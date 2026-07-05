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
import { discoverPlugins } from './utils/plugin_discovery.mjs';
import { getTierFromEnv } from './utils/license.mjs';
import { resolveCapabilities } from './utils/capabilities.mjs';
import { scopeSelectionForHost, scopeSelectionForProviders, excludeMismatchedCloudPlugins, isCloudSentinelHost } from './utils/sentinel_scope.mjs';
import { mapLimit } from './utils/concurrency.mjs';

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

async function callPlugin(mod, host, ctx, priorOutputs = null, cliOpts = {}) {
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
    // Forward CLI-derived opts (ports, etc.) so plugins can honor flags like --ports.
    // CLI opts come last so they don't override critical orchestration fields like
    // `context` if the CLI ever accidentally collides on those names.
    // Promise.resolve().then(...) so a plugin that throws SYNCHRONOUSLY (before its
    // first await) becomes a rejected promise the race below catches, instead of
    // propagating out of callPlugin and aborting the whole (sequential or parallel) batch.
    const pluginPromise = Promise.resolve().then(() => mod.run(host, port, { ...cliOpts, context: withBaseContext(ctx), ...extra }));

    // Honor a per-run timeout (cloud path) but clamp to a positive number; an
    // undefined (network path) or non-positive value falls back to PLUGIN_TIMEOUT_MS.
    const reqTimeout = Number(cliOpts && cliOpts.timeoutMs);
    const timeoutMs = Number.isFinite(reqTimeout) && reqTimeout > 0 ? reqTimeout : PLUGIN_TIMEOUT_MS;
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

export class PluginManager {
  constructor(directory = "./plugins") {
    this.directory = directory;
    this.plugins = [];
    this._resolvedCapabilities = resolveCapabilities(getTierFromEnv());
  }

  // ---- Backward-compatible factory ----
  // Accepts:
  //   - a directory string (legacy CLI path)
  //   - an options object { plugins: [...] }  ← test injection (Task 2.3)
  //   - an options object { baseDir: '...' }  ← explicit base dir for discovery
  //   - no args → uses process.cwd() for discovery
  static async create(dirOrOpts = {}) {
    // Test injection path: pass plugins array directly, skip discovery
    if (dirOrOpts && typeof dirOrOpts === 'object' && !Array.isArray(dirOrOpts) && dirOrOpts.plugins) {
      const mgr = new PluginManager('/nonexistent');
      mgr.plugins = dirOrOpts.plugins;
      // Allow callers to explicitly set tier for isolation; default to env tier.
      const tier = dirOrOpts.tier ?? getTierFromEnv();
      mgr._resolvedCapabilities = resolveCapabilities(tier);
      vlog("PluginManager initialized with injected plugins");
      return mgr;
    }

    // Resolve baseDir from string arg or options object
    const baseDir = typeof dirOrOpts === 'string'
      ? path.resolve(dirOrOpts, '..')   // legacy: dir was './plugins', baseDir is parent
      : (dirOrOpts?.baseDir ?? process.cwd());

    vlog(`Initializing PluginManager via discoverPlugins, baseDir: ${baseDir}`);
    const rawPlugins = await discoverPlugins(baseDir);

    // Normalize plugin fields (same as loadPlugins() did inline)
    for (const plugin of rawPlugins) {
      plugin.protocols = Array.isArray(plugin.protocols) ? plugin.protocols : [];
      plugin.ports = Array.isArray(plugin.ports) ? plugin.ports : [];
      if (plugin.runStrategy && String(plugin.runStrategy).toLowerCase() !== 'single') {
        plugin.runStrategy = undefined;
      }
      if (String(plugin.runStrategy).toLowerCase() === 'single') {
        plugin.runStrategy = 'single';
      }
      if (!Array.isArray(plugin.dependencies)) {
        plugin.dependencies = plugin.dependencies != null
          ? [plugin.dependencies].filter(Boolean)
          : [];
      }
    }

    const mgr = new PluginManager(baseDir);
    mgr.plugins = rawPlugins;
    // Resolve capabilities from env tier at load time — prevents permissive fallback.
    // TODO: replace getTierFromEnv() with loadLicense() result here.
    mgr._resolvedCapabilities = resolveCapabilities(getTierFromEnv());
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

    // BUG2(b): runByName (a public PluginManager entry) honors the same
    // cloud-intent contract as run() — a cloud auditor runs ONLY on its own
    // sentinel host — and threads opts.hostKind. Defense-in-depth for direct
    // library consumers; the LIVE MCP single-plugin route (probe_service →
    // _runOne) is guarded at its own call site in mcp_server.handleProbeService.
    const rb = excludeMismatchedCloudPlugins([plugin], host);
    if (rb.skipped.length) {
      const need = plugin.cloudProvider;
      console.error(
        `Plugin ${plugin.id} (${plugin.name}) is a ${need} cloud auditor — it runs only on --host ${need} ` +
        `(host '${host}' is ${rb.sentinel ? `the '${rb.sentinel}' cloud` : 'a network target'}). Skipping.`,
      );
      return { id: plugin.id, name: plugin.name, result: { up: false, skipped: true, data: [] } };
    }
    const rbOpts = {
      ...opts,
      hostKind: isCloudSentinelHost(host) ? `cloud:${String(host).trim().toLowerCase()}` : 'network',
    };
    const arr = await this._runAcrossPorts(plugin, host, rbOpts);
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

  _hasCapabilities(plugin, capabilities) {
    if (!plugin.requiredCapabilities?.length) return true;
    // Fall back to capabilities resolved at load time — never "allow all".
    // Capabilities resolved at load time — updated when license validation lands.
    const caps = capabilities ?? this._resolvedCapabilities ?? {};
    return plugin.requiredCapabilities.every(cap => Boolean(caps[cap]));
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

      if (!this._hasCapabilities(mod, opts?.capabilities)) {
        vlog(`Skipping ${mod.name} (priority ${getPriority(mod)}) due to missing capabilities: ${mod.requiredCapabilities?.join(',')}`);
        manifest.push({
          id: String(mod.id || ''),
          name: mod.name || 'Plugin',
          status: 'skipped',
          reason: `missing capabilities: ${(mod.requiredCapabilities || []).join(',')}`,
          duration_ms: 0,
        });
        continue;
      }

      vlog(`Running ${mod.name} (priority ${getPriority(mod)}) on ${host}`);
      // **FIX**: pass prior outputs into OS Detector via callPlugin(..., priorOutputs)
      // **N.27 FIX**: forward CLI-derived opts (ports, etc.) so plugins can honor CLI flags
      const startMs = Date.now();
      const wrappedRuns = await callPlugin(mod, host, ctx, outputs, opts);
      const duration_ms = Date.now() - startMs;

      // Determine manifest status from the plugin results. A gate-skip envelope
      // ({ up:false, skipped:true, ... }) carries neither `timedOut` nor `error`,
      // so classify it as 'skipped' (not 'ran') iff nothing actually ran and there
      // was no timeout/error — otherwise a self-skipped plugin would be miscounted
      // as audited. Timeout/error still win over a skip; a skip+real-run mix is 'ran'.
      let status = 'ran';
      let reason = null;
      let sawRealRun = false;
      let skipReason = null;
      for (const wrapped of wrappedRuns) {
        if (wrapped.result?.timedOut) {
          status = 'timeout';
          reason = wrapped.result.error || `timed out after ${PLUGIN_TIMEOUT_MS}ms`;
        } else if (wrapped.result?.error && status !== 'timeout') {
          status = 'error';
          reason = wrapped.result.error;
        } else if (wrapped.result?.skipped === true) {
          skipReason = wrapped.result.reason || wrapped.result.skipReason || 'skipped by plugin gate';
        } else {
          sawRealRun = true;
        }
      }
      if (status === 'ran' && skipReason != null && !sawRealRun) {
        status = 'skipped';
        reason = skipReason;
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

    let rawSpec;
    if (specOrOptions && typeof specOrOptions === "object" && !Array.isArray(specOrOptions)) {
      const { plugins = "all", ...rest } = specOrOptions;
      rawSpec = plugins;
      selection = this._resolveSelection(plugins);
      opts = rest;
    } else {
      rawSpec = specOrOptions;
      selection = this._resolveSelection(specOrOptions);
      opts = maybeOpts || {};
    }

    // BUG2(b): tag the host kind so plugins + the EE cloud gate can honor the
    // "--host is the sole cloud-intent signal" contract as defense-in-depth
    // (alongside the network-host exclusion below). Cloned so the caller's opts
    // object — shared across concurrent hosts in the CLI multi-host path — is
    // never mutated; hostKind stays a scalar string so the shallow opts spread
    // in callPlugin (:152) / _runOne (:517) forwards it verbatim to every plugin.
    opts = {
      ...opts,
      hostKind: isCloudSentinelHost(host) ? `cloud:${String(host).trim().toLowerCase()}` : 'network',
    };

    // Sentinel-host scoping: on --host aws|gcp|azure with the implicit `all`,
    // run only that cloud's plugins; skip other clouds + non-cloud plugins.
    const scope = scopeSelectionForHost(selection, host, rawSpec);
    if (scope.scoped) {
      selection = scope.selected;
      if (scope.selected.length === 0) {
        console.error(
          `WARNING: --host '${scope.provider}' matched 0 ${scope.provider.toUpperCase()} plugins — ` +
          `NOTHING was audited. Ensure the ${scope.provider.toUpperCase()} plugins are installed and ` +
          `licensed (an empty result is NOT a clean pass).`,
        );
      } else if (scope.skipped.length) {
        console.error(
          `Cloud host '${scope.provider}' → running ${scope.selected.length} ` +
          `${scope.provider.toUpperCase()} plugin(s); skipping ${scope.skipped.length} ` +
          `non-${scope.provider} plugin(s) not applicable to this host ` +
          `(other-cloud plugins run on their own --host pass; non-cloud plugins need a network host/CIDR).`,
        );
      }
    }

    // BUG2(b): a cloud auditor (any plugin with a `cloudProvider` tag) runs IFF
    // the host is ITS sentinel — the symmetric inverse of the sentinel scoping
    // above. Fires for the implicit `all` AND an explicit `--plugins 1020`
    // selection: a network scan must NEVER audit a cloud estate (even with cloud
    // creds in the env), and a `--host gcp` scan must not run an explicitly-listed
    // AWS auditor. '--host' is the sole cloud-intent signal — no escape hatch.
    const netScope = excludeMismatchedCloudPlugins(selection, host);
    // review fold R-5: excluded cloud plugins are removed from `selection` before
    // dispatch, so without a manifest entry they leave no machine-readable trace
    // in pm.run()'s result. (The requirements/capability skip classes DO push a
    // manifest entry; the sentinel-scope skip at :812 does not — a separate
    // pre-existing gap, not addressed here.) A `skipped` entry surfaces the
    // exclusion to MCP scan_host responses + pm.run() library consumers (the CLI
    // does not currently render the manifest). One entry per excluded plugin.
    const cloudSkipManifest = netScope.skipped.map((p) => ({
      id: String(p?.id || ''),
      name: p?.name || 'Plugin',
      status: 'skipped',
      reason: `${p?.cloudProvider || 'cloud'} cloud auditor requires --host ${p?.cloudProvider || 'aws|gcp|azure'} ` +
        `(host '${host}' is ${netScope.sentinel ? `the '${netScope.sentinel}' cloud` : 'a network target'})`,
      duration_ms: 0,
    }));
    if (netScope.excludedCloud && netScope.skipped.length) {
      selection = netScope.selected;
      const ids = netScope.skipped.map((p) => p?.id ?? '?').join(', ');
      if (netScope.sentinel) {
        // foreign-cloud plugin explicitly selected on a mismatched sentinel host
        const foreign = [...new Set(netScope.skipped.map((p) => p?.cloudProvider).filter(Boolean))].join('/');
        console.error(
          `Host '${host}' is the '${netScope.sentinel}' cloud → skipping ${netScope.skipped.length} ` +
          `non-${netScope.sentinel} cloud auditor(s) [${ids}] (${foreign} auditors require --host ${foreign}). ` +
          `A cloud auditor runs only on its own sentinel host — '--host' is the sole cloud-scan trigger.`,
        );
      } else {
        console.error(
          `Host '${host}' is a network target → skipping ${netScope.skipped.length} cloud auditor(s) ` +
          `[${ids}]: cloud plugins require a cloud sentinel host (--host aws|gcp|azure). ` +
          `Credentials in the environment are a capability, not an intent signal — '--host' is the ` +
          `sole cloud-scan trigger. (To audit a cloud, run e.g. \`--host aws\`.)`,
        );
      }
      // review fold 4: if the exclusion emptied the selection, say so loudly — an
      // empty result is NOT a clean pass (mirrors the sentinel zero-match warning).
      if (selection.length === 0) {
        console.error(
          `WARNING: after excluding cloud auditors for host '${host}', ZERO plugins remain — ` +
          `NOTHING was audited (an empty result is NOT a clean pass). To audit a cloud, use --host aws|gcp|azure.`,
        );
      }
    }

    // Decide execution mode
    const anyOrchestratedSignals = selection.some((p) => p?.priority != null || p?.requirements != null);
    const orchestrate = opts.orchestrate !== false && anyOrchestratedSignals;

    let results = [];
    let manifest = [];
    // R-5: surface excluded cloud auditors as skipped manifest entries (before
    // the dispatched plugins), so the exclusion is machine-visible, not stderr-only.
    if (cloudSkipManifest.length) manifest.push(...cloudSkipManifest);
    if (orchestrate) {
      const orch = await this._runOrchestrated(host, selection, opts);
      results = orch.results;
      manifest = manifest.concat(orch.manifest);
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

  /**
   * Concurrent executor for cloud plugins. Mirrors _runOrchestrated's per-plugin
   * logic (requirements + capability skip checks, callPlugin, manifest status)
   * but runs with bounded parallelism and a per-run timeout — cloud plugins are
   * independent (no sequential context chain), so each gets its OWN base ctx and
   * there is no shared-mutation race. Returns { results, manifest } in plugin order.
   */
  async _runCloudPluginsParallel(selected, host, opts = {}) {
    const concurrency = Number(process.env.CLOUD_SCAN_CONCURRENCY) || 20;
    const rawTimeout = Number(process.env.CLOUD_PLUGIN_TIMEOUT_MS);
    const timeoutMs = Number.isFinite(rawTimeout) && rawTimeout > 0 ? rawTimeout : 25000;
    const toRun = selected.filter((p) => !isConcluder(p));

    const entries = await mapLimit(toRun, concurrency, async (mod) => {
      try {
        const ctx = withBaseContext({ host, hostUp: false, tcpOpen: new Set(), udpOpen: new Set() });
        if (!shouldRunPlugin(mod, ctx)) {
          return { manifest: { id: String(mod.id || ''), name: mod.name || 'Plugin', status: 'skipped', reason: describeSkipReason(mod, ctx), duration_ms: 0 }, outputs: [] };
        }
        if (!this._hasCapabilities(mod, opts?.capabilities)) {
          return { manifest: { id: String(mod.id || ''), name: mod.name || 'Plugin', status: 'skipped', reason: `missing capabilities: ${(mod.requiredCapabilities || []).join(',')}`, duration_ms: 0 }, outputs: [] };
        }
        const startMs = Date.now();
        // BUG2(b) fold B: thread hostKind on the MCP/cloud-parallel path too, so
        // the defense-in-depth signal is present on EVERY cloud dispatch route
        // (selection here is already scoped to each plugin's cloudProvider).
        const cloudHostKind = mod.cloudProvider ? `cloud:${mod.cloudProvider}` : opts.hostKind;
        const wrappedRuns = await callPlugin(mod, host, ctx, [], { ...opts, timeoutMs, hostKind: cloudHostKind });
        const duration_ms = Date.now() - startMs;
        // Same classifier as _runOrchestrated: a gate-skip envelope
        // ({ up:false, skipped:true, ... }) → 'skipped' (not 'ran') iff nothing ran
        // and there was no timeout/error, so a self-skipped cloud is not counted as
        // audited (auditedProviders derives from status==='ran' at :1034).
        let status = 'ran';
        let reason = null;
        let sawRealRun = false;
        let skipReason = null;
        for (const w of wrappedRuns) {
          if (w.result?.timedOut) { status = 'timeout'; reason = w.result.error || `timed out after ${timeoutMs}ms`; }
          else if (w.result?.error && status !== 'timeout') { status = 'error'; reason = w.result.error; }
          else if (w.result?.skipped === true) { skipReason = w.result.reason || w.result.skipReason || 'skipped by plugin gate'; }
          else { sawRealRun = true; }
        }
        if (status === 'ran' && skipReason != null && !sawRealRun) { status = 'skipped'; reason = skipReason; }
        return { manifest: { id: String(mod.id || ''), name: mod.name || 'Plugin', status, reason, duration_ms }, outputs: wrappedRuns };
      } catch (err) {
        return { manifest: { id: String(mod.id || ''), name: mod.name || 'Plugin', status: 'error', reason: String(err?.message || err), duration_ms: 0 }, outputs: [] };
      }
    });

    return { results: entries.flatMap((e) => e.outputs), manifest: entries.map((e) => e.manifest) };
  }

  /**
   * Cloud-account audit: scope the plugin run to the union of the given cloud
   * providers (by each plugin's `cloudProvider` field), with no network host.
   * Sibling of run() that scopes by provider-set instead of by sentinel host,
   * then reuses the same orchestrate + conclude path. Returns the run()-shaped
   * output. The cloud plugins ignore `host`; the synthetic label just identifies
   * the report. An empty selection returns an empty result (surfaced as a note
   * by the caller) rather than a silent clean.
   *
   * @param {string[]} providers  e.g. ['aws'] or ['aws','azure']
   * @param {object} [opts]
   */
  async runCloud(providers, opts = {}) {
    const reqProviders = (providers || []).map((p) => String(p).trim().toLowerCase());
    const host = `cloud:${reqProviders.join('+') || 'none'}`;
    const all = this.plugins.slice();
    const { selected } = scopeSelectionForProviders(all, reqProviders);

    // Seed per-provider accounting for EVERY requested provider, so a provider
    // with zero plugins is visible (available:0), not just silently absent.
    const providerStatus = {};
    for (const p of reqProviders) providerStatus[p] = { available: 0, ran: 0, skipped: 0, errored: 0 };

    if (selected.length === 0) {
      // Parity with the sentinel-host path in run(): an empty scope is NOT a clean pass.
      console.error(
        `WARNING: scan_cloud scope [${reqProviders.join(', ') || '(none)'}] matched 0 cloud plugins — ` +
        `NOTHING was audited (an empty result is NOT a clean pass).`,
      );
      return { host, results: [], conclusion: null, manifest: [], providerStatus, auditedProviders: [],
               ai: null, ai_meta: null, ai_error: null, ai_out_path: null };
    }

    const orch = await this._runCloudPluginsParallel(selected, host, opts);
    const conclusion = await this.runConcluder(orch.results);

    // Per-provider effectiveness from the manifest (ids match the selected set).
    const manifestById = new Map((orch.manifest || []).map((m) => [String(m.id), m]));
    for (const p of selected) {
      const prov = p.cloudProvider;
      if (!providerStatus[prov]) providerStatus[prov] = { available: 0, ran: 0, skipped: 0, errored: 0 };
      providerStatus[prov].available++;
      const m = manifestById.get(String(p.id));
      if (m && m.status === 'ran') providerStatus[prov].ran++;
      else if (m && m.status === 'skipped') providerStatus[prov].skipped++;
      else providerStatus[prov].errored++;
    }
    const auditedProviders = Object.keys(providerStatus).filter((p) => providerStatus[p].ran > 0);

    return { host, results: orch.results, conclusion, manifest: orch.manifest, providerStatus, auditedProviders,
             ai: null, ai_meta: null, ai_error: null, ai_out_path: null };
  }
}

export default PluginManager;
