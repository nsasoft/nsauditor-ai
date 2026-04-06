// plugin_manager.mjs
// Backward-compatible PluginManager with:
// - static create(dir) for CLI compatibility
// - runStrategy "single" (run once)
// - robust Result Concluder invocation (supports both signatures)
// - duplicate result coalescing by plugin id
// - optional verbose logs via NSA_VERBOSE=1|true|yes
// - Orchestrated execution with priority + requirements gating,
//   shared context (hostUp, tcpOpen, udpOpen), per-port runs,
//   and support for requirements.host === 'up' | 'down' | omitted.
// - Injects shared OUI helpers (lookupVendor, probableOsFromVendor) from utils/oui.mjs
//   into every plugin's opts.context so plugins can use vendor/OS heuristics without
//   importing the OUI DB themselves.
// - **FIX**: OS Detector (id "013") is invoked with prior plugin `outputs` via opts.results.

import fs from "fs";
import fsp from "fs/promises";
import path from "path";
import { pathToFileURL, fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);

const VERBOSE = /^(1|true|yes|on)$/i.test(String(process.env.NSA_VERBOSE || ''));
const PLUGIN_TIMEOUT_MS = Number(process.env.PLUGIN_TIMEOUT_MS || 30000);
const PREFIX = '[nsauditor]';
const vlog   = VERBOSE ? (...a) => console.log(PREFIX, ...a) : () => {};
const vwarn  = VERBOSE ? (...a) => console.warn(PREFIX, ...a) : () => {};
const verror = (...a) => console.error(PREFIX, ...a); // never silenced

vlog(`PluginManager module loaded, __filename: ${__filename}`);

// ---- OUI helpers (shared to all plugins via context) ----
let BASE_CTX = {};
try {
  const oui = await import("./utils/oui.mjs");
  await oui.initOui(); // Explicitly initialize
  const lookupVendor = typeof oui.lookupVendor === "function" ? oui.lookupVendor : null;
  const probableOsFromVendor = typeof oui.probableOsFromVendor === "function" ? oui.probableOsFromVendor : null;
  BASE_CTX = {
    ...(lookupVendor ? { lookupVendor } : {}),
    ...(probableOsFromVendor ? { probableOsFromVendor } : {}),
  };
  const size = Object.keys(BASE_CTX).length;
  if (size) {
    vlog("OUI helpers available in plugin context:", Object.keys(BASE_CTX));
  } else {
    vlog("OUI helpers not available (utils/oui.mjs missing or partial).");
  }
} catch (e) {
  vlog("Could not load utils/oui.mjs:", e?.message || e);
}

function isConcluder(p) {
  return p?.id === "008" || /result\s*concluder/i.test(p?.name || "");
}
function jclone(x) { return JSON.parse(JSON.stringify(x ?? {})); }

// Merge multiple wrapped results (same plugin) into one
function mergeResultObjects(plugin, arr) {
  const merged = {
    id: plugin.id,
    name: plugin.name,
    result: {
      up: arr.some((r) => r?.result?.up === true),
      program: arr.find((r) => r?.result?.program)?.result?.program || "Unknown",
      version: arr.find((r) => r?.result?.version)?.result?.version || "Unknown",
      os: arr.find((r) => r?.result?.os)?.result?.os || null,
      type: arr.find((r) => r?.result?.type)?.result?.type || null,
      data: [],
    },
  };
  for (const r of arr) {
    if (Array.isArray(r?.result?.data)) merged.result.data.push(...r.result.data);
  }
  return merged;
}

/* ----------------------------- helpers ----------------------------- */

function getPriority(p) {
  const n = Number(p?.priority);
  return Number.isFinite(n) ? n : 100;
}
function safeLower(x) { return String(x || "").toLowerCase(); }
function arrayify(x) { return Array.isArray(x) ? x : x != null ? [x] : []; }

// requirements gating
function shouldRunPlugin(mod, ctx) {
  const req = mod?.requirements || {};

  // host requirement
  if (req.host === "up" && !ctx.hostUp) return false;
  if (req.host === "down" && ctx.hostUp === true) return false;

  // tcp_open gating
  if (Array.isArray(req.tcp_open) && req.tcp_open.length) {
    const any = req.tcp_open.some((p) => ctx.tcpOpen.has(p));
    if (!any) return false;
  }

  // udp_open gating
  if (Array.isArray(req.udp_open) && req.udp_open.length) {
    const any = req.udp_open.some((p) => ctx.udpOpen.has(p));
    if (!any) return false;
  }

  // Optional: only_if_os_unknown gating (e.g., ARP Scanner)
  if (req.only_if_os_unknown) {
    const known = !!ctx.os || !!ctx.guessedOs || !!ctx.pingOs || !!ctx.arpOs;
    if (known) return false;
  }

  return true;
}

// Merge the manager's orchestration context with the shared OUI helpers
function withBaseContext(ctxLike) {
  const base = BASE_CTX;
  const live = ctxLike || {};
  return { ...base, ...live };
}

async function callPlugin(mod, host, ctx, priorOutputs = null) {
  // Decide if we run once per matching open port, or once total.
  const req = mod?.requirements || {};
  const runs = [];

  const perTcp = Array.isArray(req.tcp_open) && req.tcp_open.length
    ? req.tcp_open.filter((p) => ctx.tcpOpen.has(p))
    : [];

  const perUdp = Array.isArray(req.udp_open) && req.udp_open.length
    ? req.udp_open.filter((p) => ctx.udpOpen.has(p))
    : [];

  // Special-case OS Detector: pass prior plugin outputs so it can reason over them
  const isOsDetector = (mod?.id === "013") || /os\s*detector/i.test(String(mod?.name || ""));

  const runWithCtx = (port) => {
    const extra = isOsDetector && Array.isArray(priorOutputs) ? { results: priorOutputs } : {};
    const pluginPromise = mod.run(host, port, { context: withBaseContext(ctx), ...extra });

    const timeoutMs = PLUGIN_TIMEOUT_MS;
    let timer;
    const timeoutPromise = new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error(`Plugin "${mod.name}" timed out after ${timeoutMs}ms`)), timeoutMs);
    });

    return Promise.race([pluginPromise, timeoutPromise]).finally(() => clearTimeout(timer));
  };

  // If plugin explicitly asked to run once per required port, do so
  for (const port of perTcp) runs.push(runWithCtx(port));
  for (const port of perUdp) runs.push(runWithCtx(port));

  // Otherwise, use legacy semantics: run across plugin.ports unless "single"
  if (!runs.length) {
    const ports =
      mod.runStrategy === "single"
        ? [0]
        : mod.ports?.length
        ? mod.ports
        : [0];

    for (const port of ports) runs.push(runWithCtx(port));
  }

  const arr = await Promise.allSettled(runs);
  const results = arr.map((pr) => pr.status === "fulfilled"
    ? { ok: true, value: pr.value }
    : { ok: false, error: pr.reason });

  return results.map((r) => {
    if (!r.ok) {
      const isTimeout = r.error?.message?.includes('timed out') || false;
      if (isTimeout) {
        vlog(`Plugin "${mod.name}" timed out after ${PLUGIN_TIMEOUT_MS}ms — skipping`);
      }
      return {
        id: String(mod.id || ""),
        name: mod.name || "Plugin",
        result: { up: false, error: String(r.error?.message || r.error), data: [], timedOut: isTimeout },
      };
    }
    const raw = r.value;
    // Normalize to wrapped envelope if needed
    if (raw && raw.id && raw.result) return raw;
    return { id: String(mod.id || ""), name: mod.name || "Plugin", result: jclone(raw) || { up: false, data: [] } };
  });
}

// Heuristics to update context from any plugin's result
function updateContextFromResult(mod, result, ctx) {
  try {
    const id = String(mod?.id || "");
    const name = safeLower(mod?.name);

    // If plugin itself says up => trust
    if (result?.up === true) ctx.hostUp = true;

    // Capture OS hints for gating (so ARP can skip)
    if (result?.os) {
      const label = String(result.os || "").trim();
      if (label && label.toLowerCase() !== "unknown") {
        ctx.os = ctx.os || label;
        if (/ping/i.test(name)) ctx.pingOs = label;
        if (/arp/i.test(name)) ctx.arpOs = label;
        ctx.guessedOs = ctx.guessedOs || label;
      }
    }

    // Scan data rows for signals
    const rows = Array.isArray(result?.data) ? result.data : [];
    for (const d of rows) {
      const info = safeLower(d?.probe_info);
      const proto = (d?.probe_protocol || "").toLowerCase();
      const port = Number.isFinite(d?.probe_port) ? Number(d.probe_port) : null;

      if (/host .*up|ping .*success|success/.test(info)) {
        ctx.hostUp = true;
      }

      // --- NEW: extract target MAC from ARP (or any row that exposes a MAC) ---
      try {
        // prefer explicit d.mac, otherwise parse any MAC from response_banner or probe_info
        const macCandidate =
          (typeof d.mac === "string" && d.mac) ||
          (typeof d.response_banner === "string" && d.response_banner.match(/([0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}/)?.[0]) ||
          (typeof d.probe_info === "string" && d.probe_info.match(/([0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}/)?.[0]) ||
          null;

        if (macCandidate && !ctx.arpMac) {
          // normalize to AA:BB:CC:DD:EE:FF
          const flat = macCandidate.replace(/[^0-9A-Fa-f]/g, "").toUpperCase();
          if (flat.length === 12) {
            ctx.arpMac = flat.match(/.{2}/g).join(":");
            // optional: log when verbose
            vlog("Captured target MAC from results:", ctx.arpMac);
          }
        }
      } catch {}

      // TCP open/closed hints
      if (proto === "tcp" && Number.isFinite(port)) {
        if (/connect success|connection successful|banner received|http\/1|ssh-2\.0|^220 /.test(safeLower(d?.probe_info || "") + " " + safeLower(d?.response_banner || ""))) {
          ctx.tcpOpen.add(port);
        } else if (/refused/.test(info)) {
          // explicitly closed; don't add to open set
        } else if (/timeout|filtered|unreachable/.test(info)) {
          // filtered/unknown; do nothing
        }
      }

      // UDP hints (rare)
      if (proto === "udp" && Number.isFinite(port)) {
        if (/udp response|snmp response|sysdescr|pdu/.test(info)) {
          ctx.udpOpen.add(port);
        }
      }
    }

    // Port Scanner result has explicit fields
    if (id === "003" || name.includes("port scanner")) {
      for (const p of arrayify(result?.tcpOpen)) ctx.tcpOpen.add(Number(p));
      for (const p of arrayify(result?.udpOpen)) ctx.udpOpen.add(Number(p));
    }

    // Service-specific implicit opens
    if (id === "006" || name.includes("http probe")) {
      const first = rows[0];
      const proto = first?.probe_protocol;
      const port = first?.probe_port;
      if ((proto === "http" || proto === "https") && result?.up === true && Number.isFinite(port)) {
        ctx.tcpOpen.add(Number(port));
      }
    }
    if (id === "004" || name.includes("ftp")) {
      const first = rows[0];
      if (result?.up === true && Number.isFinite(first?.probe_port)) {
        if (first?.response_banner) ctx.tcpOpen.add(Number(first.probe_port));
      }
    }
    if (id === "002" || name.includes("ssh")) {
      const first = rows[0];
      if (first?.response_banner && Number.isFinite(first?.probe_port)) {
        ctx.tcpOpen.add(Number(first.probe_port));
      }
    }
    if (id === "007" || name.includes("snmp")) {
      const first = rows[0];
      if (/snmp response/.test(safeLower(first?.probe_info || "")) && Number.isFinite(first?.probe_port)) {
        ctx.udpOpen.add(Number(first.probe_port));
      }
    }
  } catch (e) {
    vlog("Context update failed:", e?.message || e);
  }
}

/* ----------------------------- PLUGIN MANAGER ----------------------------- */

/**
 * Describe why a plugin was skipped given its requirements and the current context.
 * Exported for direct testing.
 */
export function describeSkipReason(mod, ctx) {
  const req = mod?.requirements || {};
  if (req.host === 'up' && !ctx.hostUp) return 'host not up';
  if (req.host === 'down' && ctx.hostUp) return 'host is up (requires down)';
  if (Array.isArray(req.tcp_open) && req.tcp_open.length) {
    const missing = req.tcp_open.filter(p => !ctx.tcpOpen.has(p));
    if (missing.length) return `tcp ports not open: ${missing.join(',')}`;
  }
  if (Array.isArray(req.udp_open) && req.udp_open.length) {
    const missing = req.udp_open.filter(p => !ctx.udpOpen.has(p));
    if (missing.length) return `udp ports not open: ${missing.join(',')}`;
  }
  if (req.only_if_os_unknown) {
    const known = !!ctx?.os || !!ctx?.guessedOs || !!ctx?.pingOs || !!ctx?.arpOs;
    if (known) return 'OS already determined';
  }
  return 'unknown';
}

export default class PluginManager {
  constructor(directory = "./plugins") {
    this.directory = directory;
    this.plugins = [];
  }

  // ---- Backward-compatible factory ----
  static async create(directory = "./plugins") {
    vlog(`Initializing PluginManager with directory: ${directory}`);
    const mgr = new PluginManager(directory);
    await mgr.loadPlugins();
    vlog("PluginManager initialized successfully");
    return mgr;
  }

  // Optional new-style init() if you prefer ctor + init
  async init() {
    vlog(`Initializing PluginManager with directory: ${this.directory}`);
    await this.loadPlugins();
    vlog("PluginManager initialized successfully");
  }

  async loadPlugins() {
    vlog(`Loading plugins from directory: ${this.directory}`);
    const resolvedDir = this.directory;

    // Access check
    try {
      await fsp.access(resolvedDir, fs.constants.R_OK | fs.constants.W_OK);
      vlog(`Plugin directory is accessible (read/write): ${resolvedDir}`);
    } catch (e) {
      throw new Error(`Plugin directory not accessible: ${resolvedDir} -> ${e.message}`);
    }

    vlog(`Checking directory contents for ${resolvedDir}`);
    const entries = await fsp.readdir(resolvedDir);
    const files = entries.filter((f) => f.endsWith(".mjs"));
    vlog(`Found files in plugin directory: ${files.join(", ")}`);

    const loaded = [];
    for (const file of files) {
      const full = path.join(resolvedDir, file);
      vlog(`Processing file: ${full}`);
      try {
        await fsp.access(full, fs.constants.R_OK);
        const preview = (await fsp.readFile(full, "utf8")).slice(0, 50).replace(/\r?\n/g, " ");
        vlog(`File is accessible: ${full}\nFile content preview (first 50 chars): ${preview}`);
      } catch (e) {
        console.warn(`Cannot read file ${full}: ${e.message}`);
        continue;
      }

      try {
        const url = pathToFileURL(full).href;
        vlog(`Attempting to load plugin: ${full} (${url})`);
        const mod = await import(url);
        const plugin = mod.default || mod;
        const keys = Object.keys(plugin || {});
        vlog(`Plugin module loaded: ${file}, keys: ${keys.join(", ")}`);

        if (!plugin || typeof plugin.run !== "function" || !plugin.id || !plugin.name) {
          console.warn(`Skipping ${file}: missing id/name/run`);
          continue;
        }

        // normalize optional fields
        plugin.protocols = Array.isArray(plugin.protocols) ? plugin.protocols : [];
        plugin.ports = Array.isArray(plugin.ports) ? plugin.ports : [];
        if (plugin.runStrategy && String(plugin.runStrategy).toLowerCase() !== "single") {
          plugin.runStrategy = undefined;
        }
        if (String(plugin.runStrategy).toLowerCase() === "single") {
          plugin.runStrategy = "single";
        }
        if (!Array.isArray(plugin.dependencies)) {
          if (plugin.dependencies != null) {
            plugin.dependencies = [plugin.dependencies].filter(Boolean);
          } else {
            plugin.dependencies = [];
          }
        }
        loaded.push(plugin);
        vlog(`Loaded plugin: ${plugin.name} (${plugin.id})`);
      } catch (e) {
        console.error(`Failed to load ${file}: ${e.stack || e}`);
      }
    }

    this.plugins = loaded;
    const meta = this.describePlugins(false);
    vlog("All Plugins Metadata:", JSON.stringify(meta, null, 2));
  }

  // legacy name used by CLI/output; keep it
  describePlugins(logOut = true) {
    const meta = this.plugins.map((p) => {
      const out = {
        id: p.id,
        name: p.name,
        description: p.description,
        protocols: p.protocols || [],
        ports: p.ports || [],
      };
      if (p.runStrategy) out.runStrategy = p.runStrategy;
      if (p.dependencies?.length) out.dependencies = p.dependencies;
      if (p.priority != null) out.priority = p.priority;
      if (p.requirements != null) out.requirements = p.requirements;
      return out;
    });
    if (logOut) vlog("All Plugins Metadata:", JSON.stringify(meta, null, 2));
    return meta;
  }

  getAllPluginsMetadata() { return this.describePlugins(false); }

  findPlugin(nameOrId) {
    if (!nameOrId) return null;
    const needle = String(nameOrId).toLowerCase();
    return (
      this.plugins.find((p) => String(p.id).toLowerCase() === needle) ||
      this.plugins.find((p) => String(p.name).toLowerCase() === needle) ||
      null
    );
  }

  async _runOne(plugin, host, port, opts = {}) {
    const timeoutMs = parseInt(process.env.PLUGIN_TIMEOUT_MS, 10) || PLUGIN_TIMEOUT_MS;
    let timer;
    const timeoutPromise = new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error(`Plugin ${plugin.name || plugin.id} timed out after ${timeoutMs}ms`)), timeoutMs);
    });
    try {
      vlog(`Running ${plugin.name} on ${host}:${port}`);
      // Ensure every run gets the BASE_CTX helpers merged into opts.context
      const mergedOpts = { ...opts, context: withBaseContext(opts?.context || {}) };
      const raw = await Promise.race([
        plugin.run(host, port, mergedOpts),
        timeoutPromise,
      ]);
      clearTimeout(timer);

      // If plugin returned wrapped shape already, keep it
      if (raw && raw.id && raw.result) {
        vlog(`${plugin.name} Result:`, JSON.stringify(raw, null, 2));
        return raw;
      }

      // Otherwise wrap to a normalized envelope
      const wrapped = { id: plugin.id, name: plugin.name, result: jclone(raw) };
      if (!wrapped.result) wrapped.result = {};
      if (!Array.isArray(wrapped.result.data)) wrapped.result.data = [];
      vlog(`${plugin.name} Result:`, JSON.stringify(wrapped, null, 2));
      return wrapped;
    } catch (err) {
      clearTimeout(timer);
      const isTimeout = err?.message?.includes('timed out') || false;
      if (isTimeout) {
        vlog(`Plugin "${plugin.name}" timed out after ${timeoutMs}ms — skipping`);
      }
      verror(`Error running ${plugin.name} on ${host}:${port}`, err?.message || err);
      return {
        id: plugin.id,
        name: plugin.name,
        result: { up: false, error: String(err?.message || err), data: [], timedOut: isTimeout },
      };
    }
  }

  async _runAcrossPorts(plugin, host, opts = {}) {
    const ports =
      plugin.runStrategy === "single"
        ? [0]
        : plugin.ports?.length
        ? plugin.ports
        : [0];

    const out = [];
    for (const port of ports) {
      const r = await this._runOne(plugin, host, port, opts);
      out.push(r);
    }
    return out;
  }

  async runByName(nameOrId, host, opts = {}) {
    vlog(`Running plugin by name: ${nameOrId}`);
    const plugin = this.findPlugin(nameOrId);
    if (!plugin) {
      const msg = `Plugin not found: ${nameOrId}`;
      console.error(msg);
      return { error: msg };
    }

    if (isConcluder(plugin)) {
      // Accept results from multiple places to avoid "undefined" issues
      const resultsArg =
        (Array.isArray(opts?.results) && opts.results) ||
        (Array.isArray(host?.results) && host.results) ||
        (Array.isArray(host) && host) ||
        null;

      if (!resultsArg) {
        console.warn("Result Concluder called without a results array; ignoring.");
        return { id: plugin.id, name: plugin.name, error: "Result Concluder requires plugin results array" };
      }
      return await this.runConcluder(resultsArg);
    }

    const arr = await this._runAcrossPorts(plugin, host, opts);
    const filtered = arr.filter(Boolean);
    if (filtered.length === 0) return { id: plugin.id, name: plugin.name, result: { up: false, data: [] } };
    if (filtered.length === 1) return filtered[0];
    return mergeResultObjects(plugin, filtered);
  }

  async runConcluder(resultsArray) {
    const concluder =
      this.plugins.find((p) => p.id === "008") ||
      this.plugins.find((p) => /result\s*concluder/i.test(p.name || ""));

    if (!concluder) return null;
    if (!Array.isArray(resultsArray)) {
      console.warn("runConcluder called without an array; returning error object.");
      return { id: concluder.id, name: concluder.name, error: "Expected an array of plugin results" };
    }

    try {
      // Support both signatures:
      //  1) run(pluginResults)
      //  2) run(host, port, { results })
      let conclusion;
      if (concluder.run.length >= 3) {
        vlog("Running Result Concluder with plugin results (opts.results signature):", JSON.stringify(resultsArray, null, 2));
        conclusion = await concluder.run(null, 0, { results: resultsArray, context: withBaseContext({}) });
      } else {
        vlog("Running Result Concluder with plugin results (single-arg signature):", JSON.stringify(resultsArray, null, 2));
        conclusion = await concluder.run(resultsArray);
      }

      vlog("Result Concluder raw output:", JSON.stringify(conclusion, null, 2));

      // Wrap conclusion if plugin returned a bare result object
      let wrapped;
      if (conclusion && conclusion.id && conclusion.result) {
        wrapped = { id: concluder.id, name: concluder.name, ...conclusion };
      } else {
        wrapped = { id: concluder.id, name: concluder.name, result: conclusion };
      }

      vlog("Result Concluder Result:", JSON.stringify(wrapped, null, 2));
      return wrapped;
    } catch (err) {
      console.error("Error running Result Concluder:", err?.stack || err);
      return { id: concluder.id, name: concluder.name, error: String(err?.message || err) };
    }
  }

  _resolveSelection(spec) {
    if (!spec || spec === "all") return this.plugins.slice();
    if (Array.isArray(spec)) {
      const out = [];
      for (const x of spec) {
        const p = this.findPlugin(x);
        if (p) out.push(p);
      }
      return out;
    }
    const parts = String(spec).split(",").map((s) => s.trim()).filter(Boolean);
    return this._resolveSelection(parts);
  }

  /* -------------------- Orchestrated execution path -------------------- */
  async _runOrchestrated(host, selection, opts = {}) {
    // Shared context flows through all plugins (+ OUI helpers injected)
    const ctx = withBaseContext({
      host,
      hostUp: false,
      tcpOpen: new Set(),
      udpOpen: new Set(),
      // guessedOs / pingOs / arpOs will be filled as plugins run
    });

    // Sort by priority (stable)
    const toRun = selection
      .filter((p) => !isConcluder(p))
      .sort((a, b) => getPriority(a) - getPriority(b));

    const outputs = [];
    const manifest = [];

    for (const mod of toRun) {
      if (!shouldRunPlugin(mod, ctx)) {
        vlog(`Skipping ${mod.name} (priority ${getPriority(mod)}) due to unmet requirements.`);
        manifest.push({
          id: String(mod.id || ''),
          name: mod.name || 'Plugin',
          status: 'skipped',
          reason: describeSkipReason(mod, ctx),
          duration_ms: 0,
        });
        continue;
      }

      vlog(`Running ${mod.name} (priority ${getPriority(mod)}) on ${host}`);
      // **FIX**: pass prior outputs into OS Detector via callPlugin(..., priorOutputs)
      const startMs = Date.now();
      const wrappedRuns = await callPlugin(mod, host, ctx, outputs);
      const duration_ms = Date.now() - startMs;

      // Determine manifest status from the plugin results
      let status = 'ran';
      let reason = null;
      for (const wrapped of wrappedRuns) {
        if (wrapped.result?.timedOut) {
          status = 'timeout';
          reason = wrapped.result.error || `timed out after ${PLUGIN_TIMEOUT_MS}ms`;
        } else if (wrapped.result?.error && status !== 'timeout') {
          status = 'error';
          reason = wrapped.result.error;
        }
      }

      manifest.push({
        id: String(mod.id || ''),
        name: mod.name || 'Plugin',
        status,
        reason,
        duration_ms,
      });

      for (const wrapped of wrappedRuns) {
        vlog(`${mod.name} Result:`, JSON.stringify(wrapped, null, 2));
        outputs.push(wrapped);
        try {
          updateContextFromResult(mod, wrapped.result, ctx);
        } catch (e) {
          vlog(`Context update failed for ${mod.name}:`, e?.message || e);
        }
      }
    }

    return { ctx, results: outputs, manifest };
  }

  /**
   * Backward-compat run signatures:
   *  A) run(host, spec='all', opts={})
   *  B) run(host, { plugins:'all', orchestrate?, ...opts })
   *
   * Default: if any selected plugin exports priority/requirements,
   * we use the orchestrated path unless opts.orchestrate === false.
   */
  async run(host, specOrOptions = "all", maybeOpts = {}) {
    let selection;
    let opts;

    if (specOrOptions && typeof specOrOptions === "object" && !Array.isArray(specOrOptions)) {
      const { plugins = "all", ...rest } = specOrOptions;
      selection = this._resolveSelection(plugins);
      opts = rest;
    } else {
      selection = this._resolveSelection(specOrOptions);
      opts = maybeOpts || {};
    }

    // Decide execution mode
    const anyOrchestratedSignals = selection.some((p) => p?.priority != null || p?.requirements != null);
    const orchestrate = opts.orchestrate !== false && anyOrchestratedSignals;

    let results = [];
    let manifest = [];
    if (orchestrate) {
      const orch = await this._runOrchestrated(host, selection, opts);
      results = orch.results;
      manifest = orch.manifest;
    } else {
      // Legacy path: simple run across ports for each plugin (except concluder)
      const toRun = selection.filter((p) => !isConcluder(p));
      for (const plugin of toRun) {
        const startMs = Date.now();
        // Ensure legacy path also gets OUI helpers
        const arr = await this._runAcrossPorts(plugin, host, { ...opts, context: withBaseContext(opts?.context || {}) });
        const duration_ms = Date.now() - startMs;
        let status = 'ran';
        let reason = null;
        for (const r of arr) {
          results.push(r);
          if (r.result?.timedOut) {
            status = 'timeout';
            reason = r.result.error || 'timed out';
          } else if (r.result?.error && status !== 'timeout') {
            status = 'error';
            reason = r.result.error;
          }
        }
        manifest.push({
          id: String(plugin.id || ''),
          name: plugin.name || 'Plugin',
          status,
          reason,
          duration_ms,
        });
      }
    }

    const coalesceSamePlugin = false;
    let resultsForConcluder = results;

    if (coalesceSamePlugin) {
      const byId = new Map();
      for (const r of results) {
        const key = r.id;
        if (!byId.has(key)) byId.set(key, []);
        byId.get(key).push(r);
      }
      resultsForConcluder = [...byId.values()].map((arr) => {
        return arr.length === 1
          ? arr[0]
          : mergeResultObjects({ id: arr[0].id, name: arr[0].name }, arr);
      });
    }

    const conclusion = await this.runConcluder(resultsForConcluder);

    return {
      host,
      results,
      conclusion,
      manifest,
      ai: null,
      ai_meta: null,
      ai_error: null,
      ai_out_path: null,
    };
  }
}
