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

    // Port sources: opts first, else config/services.json, else empty (tests supply what they need)
    let tcpPorts = Array.isArray(opts.tcpPorts) ? uniqInts(opts.tcpPorts) : [];
    let udpPorts = Array.isArray(opts.udpPorts) ? uniqInts(opts.udpPorts) : [];

    if (!tcpPorts.length && !udpPorts.length) {
      const cfg = await loadConfigPortsFromServicesJson();
      tcpPorts = cfg.tcp;
      udpPorts = cfg.udp;
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
