// plugins/port_scanner.mjs
// Fast TCP/UDP port sampler with banner sniffing and clear CLOSED/FILTERED mapping.
// Output shape matches earlier examples (tcpOpen/tcpClosed/tcpFiltered, etc.).

import net from "node:net";
import dgram from "node:dgram";
import fsp from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { mapLimit } from "../utils/concurrency.mjs";

/* ------------------------------ helpers ------------------------------ */

const toInt = (v, d) => {
  const n = Number(v);
  return Number.isFinite(n) && n >= 0 ? n : d;
};

function uniqInts(arr = []) {
  return [...new Set((arr || []).map((x) => Number(x)).filter(Number.isFinite))];
}

/**
 * Parse a CLI-style ports spec string into TCP/UDP port arrays.
 *
 * Accepted formats (entries comma-separated, whitespace tolerated):
 *   "8090"                   → { tcp: [8090],          udp: [] }
 *   "8090,9090"              → { tcp: [8090, 9090],    udp: [] }
 *   "8090/tcp"               → { tcp: [8090],          udp: [] }
 *   "8090/udp"               → { tcp: [],              udp: [8090] }
 *   "8090,9090/udp"          → { tcp: [8090],          udp: [9090] }
 *   "8090/tcp,9090/udp"      → { tcp: [8090],          udp: [9090] }
 *
 * Default protocol when not specified: TCP.
 *
 * Malformed entries (non-numeric, out-of-range 1–65535, empty, unknown
 * protocol suffix) are silently skipped — defensive for sloppy CLI input.
 *
 * @param {string} spec
 * @returns {{ tcp: number[], udp: number[] }}
 */
export function parsePortsSpec(spec) {
  const out = { tcp: [], udp: [] };
  if (typeof spec !== 'string') return out;
  const entries = spec.split(',').map(s => s.trim()).filter(Boolean);
  for (const entry of entries) {
    // Reject entries with more than one '/' separator (e.g. "8090/tcp/extra")
    const parts = entry.split('/');
    if (parts.length > 2) continue;
    const portStr = parts[0];
    const proto   = (parts[1] || 'tcp').toLowerCase();
    if (proto !== 'tcp' && proto !== 'udp') continue;
    const port = Number(portStr);
    if (!Number.isInteger(port) || port < 1 || port > 65535) continue;
    out[proto].push(port);
  }
  out.tcp = uniqInts(out.tcp);
  out.udp = uniqInts(out.udp);
  return out;
}

/**
 * ⚠️ THE PACKAGE'S OWN DATA IS FOUND RELATIVE TO THE PACKAGE, NOT TO THE CALLER.
 *
 * This used to default to `process.cwd()` alone, with the `catch` below swallowing the miss.
 * A globally installed CLI runs from wherever the OPERATOR happens to be, so unless that
 * directory contained a `config/services.json`, the default port list came back EMPTY, the
 * early return in `run()` fired, and the scan reported `up:false` with every bucket empty —
 * in about a millisecond, having probed nothing. Measured 2026-08-10 on the installed build:
 * cwd=/private/tmp gave 0 rows, cwd=<package> gave 50 rows and tcpOpen [80,21,53,443,…].
 *
 * That is a FALSE CLEAN shipped to every npm customer: an empty sweep is indistinguishable
 * from a host with nothing listening, and downstream every plugin gated on `tcp_open` is then
 * skipped silently. cwd is still tried FIRST so an operator can override the port set by
 * placing their own `config/services.json` beside them — the documented behaviour — but the
 * package copy is the floor, and a scan can no longer fall through to nothing.
 */
const PKG_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

/** Parse ONE services.json into a port set. Never throws; an unusable file yields nothing. */
async function readPortSet(fp) {
  const out = { tcp: [], udp: [] };
  try {
    const cfg = JSON.parse(await fsp.readFile(fp, "utf8"));
    if (Array.isArray(cfg?.services)) {
      for (const s of cfg.services) {
        const p = Number(s?.port);
        const proto = String(s?.protocol || "").toLowerCase();
        if (!Number.isFinite(p)) continue;
        if (proto === "udp") out.udp.push(p);
        else out.tcp.push(p); // default to TCP when not specified
      }
    } else {
      if (Array.isArray(cfg?.tcp)) out.tcp.push(...cfg.tcp);
      if (Array.isArray(cfg?.udp)) out.udp.push(...cfg.udp);
    }
  } catch { /* unreadable or unparseable — yields nothing, and the caller falls through */ }
  out.tcp = uniqInts(out.tcp);
  out.udp = uniqInts(out.udp);
  return out;
}

/**
 * The default port set: the caller's override if it YIELDS PORTS, otherwise the package's own.
 *
 * ⚠️ THE RULE IS *YIELD*, NOT *READ*, AND A REVIEW CAUGHT THE DIFFERENCE. An earlier fix tried
 * cwd then the package and committed to the first file that READ successfully. But
 * `config/services.json` is a common filename: a FOREIGN one in the caller's directory —
 * another application's, or an empty/typo'd nsauditor one (`{}`, `{"services":[]}`) — parses
 * fine, populates nothing, and the package floor was then never consulted. The scan probed
 * ZERO ports and reported `up:false`: the same false clean as before, re-gated on a filename
 * collision instead of a missing file. Committing on read also made that fix's own comment
 * ("a scan can no longer fall through to nothing") untrue.
 *
 * A non-empty override REPLACES rather than merges — an operator narrowing the sweep on
 * purpose must not silently get the full set back.
 */
async function loadConfigPortsFromServicesJson(cwd = process.cwd()) {
  const override = await readPortSet(path.join(cwd, "config", "services.json"));
  if (override.tcp.length || override.udp.length) return override;
  return readPortSet(path.join(PKG_ROOT, "config", "services.json"));
}

function classifyTcpError(err) {
  const code = err?.code || "";
  const msg = err?.message || String(err) || "";
  // Treat ANY "refused" (code OR message) as closed, and ensure info contains 'refused'
  if (code === "ECONNREFUSED" || /ECONNREFUSED|refused/i.test(msg)) {
    const suffix = code ? ` (${code})` : "";
    return { status: "closed", info: `Connect refused${suffix}` };
  }
  if (code === "ETIMEDOUT" || /timed?\s*out/i.test(msg)) return { status: "filtered", info: "Timeout" };
  if (code === "EHOSTUNREACH" || code === "ENETUNREACH") return { status: "filtered", info: "Unreachable" };
  return { status: "filtered", info: code || "Socket error" };
}

/* ------------------------------ TCP scan ------------------------------ */

async function scanTcpPort(host, port, { timeoutMs, bannerTimeoutMs, maxBannerBytes }) {
  return new Promise((resolve) => {
    const started = Date.now();
    const socket = new net.Socket();
    let banner = Buffer.alloc(0);
    let done = false;
    let bannerTimer = null;

    const finish = (status, info, extra = {}) => {
      if (done) return;
      done = true;
      clearTimeout(bannerTimer);
      try { socket.destroy(); } catch {}
      resolve({
        probe_protocol: "tcp",
        probe_port: port,
        status,
        probe_info: info || null,
        response_banner: banner.length ? banner.toString("utf8", 0, Math.min(maxBannerBytes, banner.length)).trim() : null,
        rtt_ms: Date.now() - started,
        error: extra.error || null,
      });
    };

    socket.setTimeout(timeoutMs);
    socket.setNoDelay?.(true);

    socket.once("connect", () => {
      // Give services a short opportunity to greet with a banner.
      bannerTimer = setTimeout(() => finish("open", "TCP connect success (peer closed)"), bannerTimeoutMs);
    });

    socket.on("data", (chunk) => {
      banner = Buffer.concat([banner, chunk]);
      if (banner.length >= maxBannerBytes) {
        finish("open", "TCP connect success (banner captured)");
      }
    });

    socket.once("timeout", () => finish("filtered", "Timeout"));

    socket.once("error", (e) => {
      const cls = classifyTcpError(e);
      finish(cls.status, cls.info, { error: e?.code || String(e) });
    });

    try {
      socket.connect(port, host);
    } catch (e) {
      const cls = classifyTcpError(e);
      finish(cls.status, cls.info, { error: e?.code || String(e) });
    }
  });
}

/* ------------------------------ UDP scan ------------------------------ */

async function scanUdpPort(host, port, { timeoutMs, udpPayload }) {
  return new Promise((resolve) => {
    const started = Date.now();
    const sock = dgram.createSocket("udp4");
    let done = false;

    const finish = (status, info) => {
      if (done) return;
      done = true;
      try { sock.close(); } catch {}
      resolve({
        probe_protocol: "udp",
        probe_port: port,
        status,
        probe_info: info || null,
        response_banner: null,
        rtt_ms: Date.now() - started,
      });
    };

    const t = setTimeout(() => finish("no-response", "No UDP response"), timeoutMs);

    sock.once("error", () => {
      clearTimeout(t);
      finish("no-response", "UDP error/no response"); // conservative default for generic UDP ping
    });

    sock.once("message", () => {
      clearTimeout(t);
      finish("open", "UDP response");
    });

    try {
      sock.send(udpPayload, port, host);
    } catch {
      clearTimeout(t);
      finish("no-response", "UDP send error");
    }
  });
}

/* ------------------------------- runner ------------------------------- */

export default {
  id: "003",
  name: "Port Scanner",
  description: "Lightweight TCP/UDP sampler with banner sniffing. Classifies ECONNREFUSED as closed.",
  priority: 30,
  protocols: ["tcp", "udp"],
  ports: [],
  requirements: { host: "up" },

  // run(host, _portIgnored, opts)
  async run(host, _port = 0, opts = {}) {
    const timeoutMs       = toInt(opts.timeoutMs ?? process.env.TCP_CONNECT_TIMEOUT_MS, 1200);
    const bannerTimeoutMs = toInt(opts.bannerTimeoutMs ?? process.env.TCP_BANNER_TIMEOUT_MS, 250);
    const maxBannerBytes  = toInt(process.env.TCP_BANNER_MAX_BYTES, 350);
    const udpPayload      = Buffer.from("hi");

    // Port sources, in priority order:
    //   1. Explicit opts.tcpPorts / opts.udpPorts arrays (tests, programmatic API)
    //   2. config/services.json (default well-known port set)
    //   3. Empty
    // Then ADDITIVELY merge opts.ports (CLI --ports flag, comma-separated string with
    // optional /tcp /udp suffix). Additive semantics so that --ports adds extras to the
    // default scan rather than silently replacing it (Task N.27, fixed in v0.1.22).
    let tcpPorts = Array.isArray(opts.tcpPorts) ? uniqInts(opts.tcpPorts) : [];
    let udpPorts = Array.isArray(opts.udpPorts) ? uniqInts(opts.udpPorts) : [];

    if (!tcpPorts.length && !udpPorts.length) {
      const cfg = await loadConfigPortsFromServicesJson();
      tcpPorts = cfg.tcp;
      udpPorts = cfg.udp;
    }

    // Additive merge of CLI --ports flag (string spec)
    if (typeof opts.ports === 'string' && opts.ports.trim()) {
      const extra = parsePortsSpec(opts.ports);
      tcpPorts = uniqInts([...tcpPorts, ...extra.tcp]);
      udpPorts = uniqInts([...udpPorts, ...extra.udp]);
    }

    // If still nothing, just return empty structure
    if (!tcpPorts.length && !udpPorts.length) {
      return {
        up: false,
        program: "Unknown",
        version: "Unknown",
        os: null,
        type: "port-scan",
        tcpOpen: [],
        tcpClosed: [],
        tcpFiltered: [],
        udpOpen: [],
        udpClosed: [],
        udpNoResponse: [],
        data: [],
      };
    }

    const data = [];

    // ⚠️ BOUNDED CONCURRENCY, NOT A SEQUENTIAL LOOP — and the reason is a measured false clean.
    // These two loops used to `await` one port at a time. A filtered or silent port costs the
    // FULL per-port timeout, so the shipped 50-port sweep (43 TCP + 7 UDP) took 40,977 ms
    // against a real router on 2026-08-10 — past the 30,000 ms `PLUGIN_TIMEOUT_MS` the plugin
    // manager races every run against. The orchestrator therefore DISCARDED a correct result
    // (`up:true`, `tcpOpen:[80,21,53,443,...]`) that arrived eleven seconds later, and
    // substituted an empty one.
    //
    // That is not slowness, it is a FALSE CLEAN: with `ctx.tcpOpen` empty, every plugin gated
    // on `tcp_open` is skipped by `plugin_manager.mjs` with a bare `return false` — no finding,
    // no evidence gap — so `HTTP Probe` and `Webapp Detector` never ran, and the compliance
    // layer reported PASS controls off a scan that never probed HTTP.
    //
    // `mapLimit` returns results IN INPUT ORDER, so the evidence rows stay deterministic; the
    // cap is deliberately modest because a port sweep is latency-bound, not CPU-bound, and a
    // scanner that floods a small target is its own kind of defect.
    const SWEEP_CONCURRENCY = toInt(process.env.PORT_SCAN_CONCURRENCY, 12);

    // TCP scans
    data.push(...await mapLimit(tcpPorts, SWEEP_CONCURRENCY, (p) =>
      scanTcpPort(host, p, { timeoutMs, bannerTimeoutMs, maxBannerBytes })));

    // UDP scans
    data.push(...await mapLimit(udpPorts, SWEEP_CONCURRENCY, (p) =>
      scanUdpPort(host, p, { timeoutMs, udpPayload })));

    // Buckets
    const tcpOpen      = data.filter(d => d.probe_protocol === "tcp" && d.status === "open").map(d => d.probe_port);
    const tcpClosed    = data.filter(d => d.probe_protocol === "tcp" && d.status === "closed").map(d => d.probe_port);
    const tcpFiltered  = data.filter(d => d.probe_protocol === "tcp" && d.status === "filtered").map(d => d.probe_port);

    const udpOpen       = data.filter(d => d.probe_protocol === "udp" && d.status === "open").map(d => d.probe_port);
    const udpClosed     = data.filter(d => d.probe_protocol === "udp" && d.status === "closed").map(d => d.probe_port); // typically empty
    const udpNoResponse = data.filter(d => d.probe_protocol === "udp" && d.status === "no-response").map(d => d.probe_port);

    // Consider host "up" if we saw any TCP evidence (open/closed/filtered) OR any UDP open.
    const anyTcpEvidence = tcpOpen.length > 0 || tcpClosed.length > 0 || tcpFiltered.length > 0;
    const anyUdpOpen     = udpOpen.length > 0;

    return {
      up: anyTcpEvidence || anyUdpOpen,
      program: "Unknown",
      version: "Unknown",
      os: null,
      type: "port-scan",
      tcpOpen,
      tcpClosed,
      tcpFiltered,
      udpOpen,
      udpClosed,
      udpNoResponse,
      data,
    };
  },
};

/* --------------------------- conclude adapter --------------------------- */

/**
 * services[] enumerates services FOUND, so only an OPEN port becomes a record.
 * A refusal (RST) or a timeout is the absence of a service, and neither is lost:
 * both stay in the conclusion's evidence[] stream and in this scan's own
 * tcpClosed / tcpFiltered / udpNoResponse buckets.
 *
 * Measured, on a default sweep of localhost (50 ports from config/services.json):
 * 41 refusals, 1 listener. Materializing refusals would put 42 rows into
 * services[] to carry one bit of signal — and every consumer renders services
 * unfiltered (report_md's table, export_csv's row-per-service, SARIF results,
 * attack_map, and the scan_history baseline that deltas compare against).
 */
const MATERIALIZED_STATUSES = new Set(["open"]);

/**
 * Without this adapter, result_concluder falls through to fallbackRecord(),
 * which keeps only `rows.find(Boolean)` — ONE record for the whole sweep. Since
 * this plugin emits one row PER scanned port, that collapsed N open ports into
 * the first-SCANNED port and dropped the rest before any consumer (CE reports,
 * EE analysis agents) ever saw them. It also derived that survivor's status from
 * the host-level `result.up`, so a filtered port was reported `open` whenever any
 * other port on the host was open.
 *
 * `service` is deliberately the not-fingerprinted label, NOT a well-known-port
 * name: a TCP connect proves a port answers, not which protocol speaks on it.
 * Consumers that infer a protocol from the port number must do so themselves, at
 * their own (lower) confidence tier — the EE crypto_agent, for one, rates a
 * label-derived cleartext finding HIGH with certainty prose and a port-inferred
 * one MEDIUM with an explicit "UNCONFIRMED" caveat. Emitting `'ftp'` for port 21
 * here would silently promote every unfingerprinted listener into the confident
 * tier. Identification is the job of the protocol probes, which are authoritative
 * for their ports and overwrite these records on merge.
 *
 * @param {{host?: string, result?: object}} args
 * @returns {Promise<object[]>} one ServiceRecord per affirmatively-observed port
 */
export async function conclude({ result } = {}) {
  const rows = Array.isArray(result?.data) ? result.data : [];
  const items = [];

  for (const row of rows) {
    const port = Number(row?.probe_port);
    if (!Number.isInteger(port) || port <= 0) continue;

    const status = String(row?.status || "");
    if (!MATERIALIZED_STATUSES.has(status)) continue;

    items.push({
      port,
      protocol: String(row?.probe_protocol || "tcp").toLowerCase(),
      service: "unknown",
      program: result?.program || "Unknown",
      version: result?.version || "Unknown",
      // From the ROW, never from the host-level result.up.
      status,
      info: row?.probe_info || null,
      banner: row?.response_banner || null,
      source: "port_scanner",
      // The record's OWN probe row. The full sweep is already pushed to the
      // conclusion's top-level evidence[]; repeating it on every record would be
      // O(n^2) duplication of the same rows.
      evidence: [row],
      // A connect scan never outranks a protocol probe for the same port.
      authoritative: false,
    });
  }

  return items;
}
