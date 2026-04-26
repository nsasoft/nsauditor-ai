// plugins/port_scanner.mjs
// Fast TCP/UDP port sampler with banner sniffing and clear CLOSED/FILTERED mapping.
// Output shape matches earlier examples (tcpOpen/tcpClosed/tcpFiltered, etc.).

import net from "node:net";
import dgram from "node:dgram";
import fsp from "node:fs/promises";
import path from "node:path";

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

async function loadConfigPortsFromServicesJson(cwd = process.cwd()) {
  // Supports the "array schema" used by tests:
  // { "services": [ { port, protocol }, ... ] }
  // and a fallback object schema: { tcp: [...], udp: [...] }
  const out = { tcp: [], udp: [] };
  try {
    const fp = path.join(cwd, "config", "services.json");
    const raw = await fsp.readFile(fp, "utf8");
    const cfg = JSON.parse(raw);

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
  } catch {
    // no config, ignore
  }
  out.tcp = uniqInts(out.tcp);
  out.udp = uniqInts(out.udp);
  return out;
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

    // TCP scans
    for (const p of tcpPorts) {
      data.push(await scanTcpPort(host, p, { timeoutMs, bannerTimeoutMs, maxBannerBytes }));
    }

    // UDP scans
    for (const p of udpPorts) {
      data.push(await scanUdpPort(host, p, { timeoutMs, udpPayload }));
    }

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
