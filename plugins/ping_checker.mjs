// plugins/ping_checker.mjs
// Ping Checker — ICMP ping, TTL-based OS guess, ARP assist for local targets,
// and ICMP/TCP fallback probes when Echo Request gets no reply.
// Uses ONLY ctx.lookupVendor / ctx.probableOsFromVendor (if provided).

import { promisify } from "node:util";
import { execFile } from "node:child_process";
import net from "node:net";

const execFileP = promisify(execFile);
const isWin = process.platform === "win32";
const DEBUG = /^(1|true|yes|on)$/i.test(String(process.env.DEBUG_MODE || process.env.PING_DEBUG || ""));
const FALLBACK_ENABLED = !/^(0|false|no|off)$/i.test(String(process.env.PING_FALLBACK ?? "true"));
const FALLBACK_TIMEOUT = Number(process.env.PING_FALLBACK_TIMEOUT) || 3000;

function dlog(...a) { if (DEBUG) console.log("[ping-checker]", ...a); }

/** Validate host string to prevent command injection. */
function isValidHost(h) {
  if (!h || typeof h !== "string") return false;
  // Allow IPv4, IPv6, and hostnames only — no shell metacharacters
  return /^[a-zA-Z0-9.:_\-\[\]%]+$/.test(h);
}

/**
 * Try ICMP Timestamp Request (Type 13) via nping or hping3.
 * Returns true if the host responded, false otherwise.
 */
async function tryIcmpTimestamp(host, timeoutMs) {
  if (!isValidHost(host)) return { alive: false, info: "Invalid host" };

  // Try nping first (from nmap suite)
  try {
    const { stdout } = await execFileP(
      "nping",
      ["--icmp", "--icmp-type", "timestamp", "-c", "1", "--delay", "0", host],
      { windowsHide: true, timeout: timeoutMs + 500 }
    );
    dlog("nping timestamp output:", stdout);
    const ok = /RCVD|completed/i.test(stdout) && !/0 received/i.test(stdout);
    if (ok) return { alive: true, info: "ICMP Timestamp reply via nping" };
    return { alive: false, info: "ICMP Timestamp — no reply (nping)" };
  } catch {
    dlog("nping not available or failed");
  }

  // Try hping3 as second option
  try {
    const { stdout } = await execFileP(
      "hping3",
      ["-1", "--icmptype", "13", "-c", "1", host],
      { windowsHide: true, timeout: timeoutMs + 500 }
    );
    dlog("hping3 timestamp output:", stdout);
    const ok = /flags=/.test(stdout) || /len=/.test(stdout);
    if (ok) return { alive: true, info: "ICMP Timestamp reply via hping3" };
    return { alive: false, info: "ICMP Timestamp — no reply (hping3)" };
  } catch {
    dlog("hping3 not available or failed");
  }

  return { alive: false, info: "ICMP Timestamp — nping/hping3 not available" };
}

/**
 * TCP ACK probe on common ports (80, 443).
 * A successful connect OR ECONNREFUSED (RST) both mean the host is up.
 * Returns { alive, port, info }.
 */
function tryTcpAckProbe(host, port, timeoutMs) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    socket.setTimeout(timeoutMs);

    const cleanup = () => { try { socket.destroy(); } catch {} };

    socket.on("connect", () => {
      cleanup();
      resolve({ alive: true, port, info: `TCP connect to port ${port} — host up` });
    });

    socket.on("error", (err) => {
      cleanup();
      if (err.code === "ECONNREFUSED") {
        // RST received — host is alive
        resolve({ alive: true, port, info: `TCP RST on port ${port} — host up` });
      } else {
        resolve({ alive: false, port, info: `TCP probe port ${port} — ${err.code || err.message}` });
      }
    });

    socket.on("timeout", () => {
      cleanup();
      resolve({ alive: false, port, info: `TCP probe port ${port} — timeout` });
    });

    socket.connect(port, host);
  });
}

function isPrivateLike(ip) {
  if (!ip) return false;
  if (/^(10)\./.test(ip)) return true;
  if (/^(192\.168)\./.test(ip)) return true;
  if (/^(172\.(1[6-9]|2\d|3[0-1]))\./.test(ip)) return true;
  if (/^(169\.254)\./.test(ip)) return true;
  return false;
}

async function getMacViaArp(ip, iface = null) {
  const cmd = "arp";
  const args = isWin ? ["-a", ip] : ["-n", ip];
  if (iface && !isWin) {
    args.push("-i", iface);
  }
  try {
    const { stdout } = await execFileP(cmd, args, { windowsHide: true, timeout: 5000 });
    // Log raw output for debugging
    dlog("Raw ARP output:", stdout);
    // Compact regex: catches colon or dash formats, 1 or 2 hex digits
    const macRe = /([0-9a-f]{1,2}(?:[:-][0-9a-f]{1,2}){5})/i;
    const line = stdout.split(/\r?\n/).find(l => l.includes(ip) || l.includes(`(${ip})`));
    const m = (line && line.match(macRe)) || stdout.match(macRe);
    if (m) {
      let mac = m[1].replace(/-/g, ":").toUpperCase();
      mac = mac.split(":").map(part => part.padStart(2, "0")).join(":");
      dlog(`Parsed MAC for IP ${ip}: ${mac}`);
      return mac;
    }
    dlog("No MAC found in output");
    return null;
  } catch (e) {
    dlog("arp exec failed:", e?.message || e);
    return null;
  }
}

function osFromTtl(initial) {
  if (!initial) return null;
  if (initial >= 61 && initial <= 64) return "Linux/Unix/macOS or RTOS";
  if (initial >= 125 && initial <= 128) return "Windows";
  if (initial >= 254 && initial <= 255) return "Cisco/Solaris or RTOS/IoT";
  if (initial >= 30 && initial <= 32) return "Older system or custom embedded";
  return `Custom/Proprietary (TTL=${initial})`;
}

export default {
  id: "001",
  name: "Ping Checker",
  description: "Checks ICMP reachability, infers OS from TTL, and leverages ARP (local only) with vendor hints from ctx.",
  priority: 10,
  requirements: {},
  protocols: ["icmp"],
  ports: [],
  dependencies: [],

  async run(host, _port, opts = {}) {
    if (!isValidHost(host)) {
      return { up: false, os: null, probeMethod: "none", data: [{ probe_protocol: "icmp", probe_port: 0, probe_info: "Invalid host", response_banner: null }] };
    }
    const timeoutMs = Number(opts.timeoutMs ?? process.env.NSA_PING_TIMEOUT_MS ?? 5000);
    const fallbackEnabled = opts.fallback ?? FALLBACK_ENABLED;
    const fallbackTimeout = Number(opts.fallbackTimeout ?? FALLBACK_TIMEOUT);
    const cmd = "ping";
    const args = isWin
      ? ["-n", "1", "-w", String(timeoutMs), host]
      : ["-c", "1", "-W", String(Math.ceil(timeoutMs / 1000)), host];

    const data = [];
    let up = false;
    let os = null;
    let probeMethod = "none";

    // 1) ICMP Echo Request (Type 8)
    try {
      const { stdout } = await execFileP(cmd, args, { windowsHide: true, timeout: timeoutMs + 1000 });
      dlog("Raw ping output:", stdout);
      const ok = /ttl=|TTL=|bytes from|time=|Antwort von|Reply from/i.test(stdout);
      const ttlMatch = stdout.match(/ttl=(\d+)|TTL=(\d+)/i);
      const ttl = ttlMatch ? parseInt(ttlMatch[1] || ttlMatch[2], 10) : null;
      const initialTTL = ttl ? ttl + 1 : null;
      const icmpOs = osFromTtl(initialTTL);

      data.push({
        probe_protocol: "icmp",
        probe_port: 0,
        probe_info: ok
          ? `Ping OK — ttl=${ttl ?? "N/A"} (inferred base ${initialTTL ?? "N/A"})`
          : "Ping did not confirm host up",
        response_banner: ttl ? `ttl=${ttl}` : null
      });

      if (ok) {
        up = true;
        probeMethod = "echo";
        if (icmpOs) os = icmpOs;
      }
    } catch (e) {
      dlog("ICMP probe error:", e?.message || e);
      data.push({ probe_protocol: "icmp", probe_port: 0, probe_info: "Ping failed", response_banner: null });
    }

    // 2) Fallback probes — only when echo failed and fallback is enabled
    if (!up && fallbackEnabled) {
      dlog("Echo failed, attempting fallback probes");

      // Fallback 1: ICMP Timestamp Request (Type 13)
      const tsResult = await tryIcmpTimestamp(host, fallbackTimeout);
      data.push({
        probe_protocol: "icmp-timestamp",
        probe_port: 0,
        probe_info: tsResult.info,
        response_banner: null
      });

      if (tsResult.alive) {
        up = true;
        probeMethod = "timestamp";
      }

      // Fallback 2: TCP ACK probe on ports 80 and 443
      if (!up) {
        const tcpPorts = [80, 443];
        for (const port of tcpPorts) {
          const tcpResult = await tryTcpAckProbe(host, port, fallbackTimeout);
          data.push({
            probe_protocol: "tcp-ack",
            probe_port: port,
            probe_info: tcpResult.info,
            response_banner: null
          });

          if (tcpResult.alive) {
            up = true;
            probeMethod = "tcp-ack";
            // Propagate confirmed port to shared context so downstream
            // plugins gated on tcp_open (HTTP Probe, Webapp Detector, etc.)
            // can run without waiting for a full port scan.
            const ctx = opts?.context;
            if (ctx?.tcpOpen && typeof ctx.tcpOpen.add === "function") {
              ctx.tcpOpen.add(port);
            }
            break; // No need to probe further
          }
        }
      }
    }

    // 3) ARP (local only)
    if (isPrivateLike(host)) {
      const interfaces = isWin ? [null] : [null, "en0"];
      let mac = null;
      for (const iface of interfaces) {
        mac = await getMacViaArp(host, iface);
        if (mac) break;
      }

      if (mac) {
        up = true; // ARP reachability implies L2 presence

        // Only use ctx helpers (no OUI loading here)
        const ctx = opts?.context || {};
        const vendorRaw = typeof ctx.lookupVendor === "function" ? (ctx.lookupVendor(mac) || null) : null;
        const vendor = vendorRaw ? vendorRaw.replace(/[\r\n]+/g, ' ').trim() : null;
        const info = vendor ? `ARP entry found — vendor: ${vendor}` : "ARP entry found";

        // If OS not set from TTL, try ctx vendor heuristic
        if (!os && typeof ctx.probableOsFromVendor === "function") {
          const guess = ctx.probableOsFromVendor(vendor);
          if (guess && guess !== "Unknown") os = guess;
        }

        data.push({ probe_protocol: "arp", probe_port: 0, probe_info: info, response_banner: mac });
      }
    }

    return { up, os, probeMethod, data };
  }
};