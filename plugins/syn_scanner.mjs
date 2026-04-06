// plugins/syn_scanner.mjs
// TCP SYN Scanner — optional Nmap wrapper for SYN (-sS) scanning.
// Gated by ENABLE_SYN_SCAN env var (default: false).
// Requires nmap to be installed; falls back gracefully when missing.

import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileP = promisify(execFile);

/* ------------------------------ helpers ------------------------------ */

const HOST_RE = /^[a-zA-Z0-9._:-]+$/;

function isValidHost(host) {
  if (!host || typeof host !== "string") return false;
  if (host.length > 253) return false;
  return HOST_RE.test(host);
}

/**
 * Parse Nmap XML output (from -oX -) using regex.
 * Returns { hosts: [{ ip, status, ports: [{ port, protocol, state, service, version }], os }] }
 */
export function parseNmapXml(xml) {
  const result = { hosts: [] };
  if (!xml || typeof xml !== "string") return result;

  // Match each <host>...</host> block
  const hostBlocks = xml.match(/<host[\s>][\s\S]*?<\/host>/gi);
  if (!hostBlocks) return result;

  for (const block of hostBlocks) {
    const host = { ip: null, status: null, ports: [], os: null };

    // Extract address
    const addrMatch = block.match(/<address\s+addr="([^"]+)"/i);
    if (addrMatch) host.ip = addrMatch[1];

    // Extract status
    const statusMatch = block.match(/<status\s+state="([^"]+)"/i);
    if (statusMatch) host.status = statusMatch[1];

    // Extract ports
    const portMatches = block.match(/<port[\s>][\s\S]*?<\/port>/gi);
    if (portMatches) {
      for (const portBlock of portMatches) {
        const portInfo = {};

        const protoMatch = portBlock.match(/protocol="([^"]+)"/i);
        portInfo.protocol = protoMatch ? protoMatch[1] : "tcp";

        const portIdMatch = portBlock.match(/portid="([^"]+)"/i);
        portInfo.port = portIdMatch ? Number(portIdMatch[1]) : 0;

        const stateMatch = portBlock.match(/<state\s+state="([^"]+)"/i);
        portInfo.state = stateMatch ? stateMatch[1] : "unknown";

        const svcNameMatch = portBlock.match(/<service\s+name="([^"]+)"/i);
        portInfo.service = svcNameMatch ? svcNameMatch[1] : null;

        // Extract product and version from service tag attributes
        const productMatch = portBlock.match(/product="([^"]+)"/i);
        const versionMatch = portBlock.match(/version="([^"]+)"/i);
        portInfo.version = null;
        if (productMatch && versionMatch) {
          portInfo.version = `${productMatch[1]} ${versionMatch[1]}`;
        } else if (productMatch) {
          portInfo.version = productMatch[1];
        } else if (versionMatch) {
          portInfo.version = versionMatch[1];
        }

        host.ports.push(portInfo);
      }
    }

    // Extract OS match
    const osMatch = block.match(/<osmatch\s+name="([^"]+)"/i);
    if (osMatch) host.os = osMatch[1];

    result.hosts.push(host);
  }

  return result;
}

/**
 * Build the nmap argument list.
 */
function buildNmapArgs(host) {
  const args = ["-sS", "-Pn", "-T4", "--min-rate", "100", "-oX", "-"];

  const portRange = process.env.SYN_SCAN_PORTS;
  const PORT_RANGE_RE = /^[\dT:U:,\-\s]+$/;
  if (portRange && typeof portRange === "string" && portRange.trim() && PORT_RANGE_RE.test(portRange.trim())) {
    args.push("-p", portRange.trim());
  }

  args.push(host);
  return args;
}

/**
 * Check if nmap is available on the system.
 */
async function isNmapAvailable() {
  try {
    // Use 'command -v' on Unix-like, 'where' on Windows
    const cmd = process.platform === "win32" ? "where" : "command";
    const cmdArgs = process.platform === "win32" ? ["nmap"] : ["-v", "nmap"];
    await execFileP(cmd, cmdArgs, { timeout: 5000 });
    return true;
  } catch {
    return false;
  }
}

/**
 * Check if SYN scanning is enabled via env var.
 */
function isSynScanEnabled() {
  const v = String(process.env.ENABLE_SYN_SCAN || "").toLowerCase();
  return v === "1" || v === "true" || v === "yes" || v === "on";
}

/* ------------------------------ plugin ------------------------------ */

export default {
  id: "024",
  name: "TCP SYN Scanner (Nmap)",
  description:
    "SYN scan via Nmap wrapper. Requires nmap installed and ENABLE_SYN_SCAN=1. Falls back gracefully when unavailable.",
  priority: 12,
  protocols: ["tcp"],
  ports: [],
  requirements: {},

  async run(host, _port = 0, opts = {}) {
    // Gate: must be explicitly enabled
    if (!isSynScanEnabled()) {
      return {
        up: false,
        program: "Unknown",
        version: "Unknown",
        os: null,
        type: "syn-scan",
        tcpOpen: [],
        data: [{ probe_info: "SYN scan disabled (set ENABLE_SYN_SCAN=1 to enable)" }],
      };
    }

    // Validate host to prevent command injection
    if (!isValidHost(host)) {
      return {
        up: false,
        program: "Unknown",
        version: "Unknown",
        os: null,
        type: "syn-scan",
        tcpOpen: [],
        data: [{ probe_info: `Invalid host: ${String(host).slice(0, 50)}` }],
      };
    }

    // Check nmap availability
    const nmapFound = await isNmapAvailable();
    if (!nmapFound) {
      return {
        up: false,
        program: "Unknown",
        version: "Unknown",
        os: null,
        type: "syn-scan",
        tcpOpen: [],
        data: [{ probe_info: "nmap not found, falling back to TCP connect scan" }],
      };
    }

    // Run nmap SYN scan
    const timeoutMs = Number(process.env.SYN_SCAN_TIMEOUT) || 30000;
    const args = buildNmapArgs(host);

    let stdout, stderr;
    try {
      const result = await execFileP("nmap", args, {
        timeout: timeoutMs,
        maxBuffer: 10 * 1024 * 1024,
      });
      stdout = result.stdout || "";
      stderr = result.stderr || "";
    } catch (err) {
      const msg = String(err?.stderr || err?.message || err);

      // Detect permission issues (SYN scan requires root/sudo)
      if (/permission|operation not permitted|requires root|raw socket|not authorized/i.test(msg)) {
        return {
          up: false,
          program: "Unknown",
          version: "Unknown",
          os: null,
          type: "syn-scan",
          tcpOpen: [],
          data: [
            {
              probe_info:
                "SYN scan requires root/sudo privileges. Run with sudo or use the TCP connect scanner instead.",
            },
          ],
        };
      }

      return {
        up: false,
        program: "Unknown",
        version: "Unknown",
        os: null,
        type: "syn-scan",
        tcpOpen: [],
        data: [{ probe_info: `nmap error: ${msg.slice(0, 200)}` }],
      };
    }

    // Parse XML output
    const parsed = parseNmapXml(stdout);

    const data = [];
    const tcpOpen = [];
    let hostUp = false;
    let detectedOs = null;

    for (const h of parsed.hosts) {
      if (h.status === "up") hostUp = true;
      if (h.os) detectedOs = h.os;

      for (const p of h.ports) {
        const row = {
          probe_protocol: p.protocol || "tcp",
          probe_port: p.port,
          status: p.state,
          probe_info: `SYN scan: ${p.state}${p.service ? ` (${p.service})` : ""}`,
          response_banner: p.version || null,
          service: p.service || null,
        };
        data.push(row);

        if (p.state === "open" && (p.protocol || "tcp") === "tcp") {
          tcpOpen.push(p.port);
        }
      }
    }

    // Update context if provided
    const ctx = opts?.context;
    if (ctx) {
      if (hostUp) ctx.hostUp = true;
      if (ctx.tcpOpen && typeof ctx.tcpOpen.add === "function") {
        for (const p of tcpOpen) ctx.tcpOpen.add(p);
      }
      if (detectedOs && !ctx.os) {
        ctx.os = detectedOs;
        ctx.guessedOs = detectedOs;
      }
    }

    return {
      up: hostUp || tcpOpen.length > 0,
      program: "nmap",
      version: "Unknown",
      os: detectedOs,
      type: "syn-scan",
      tcpOpen,
      data,
    };
  },
};

/* ------------------------------ conclude adapter ------------------------------ */

import { statusFrom } from "../utils/conclusion_utils.mjs";

export async function conclude({ host, result }) {
  const rows = Array.isArray(result?.data) ? result.data : [];
  const items = [];

  for (const r of rows) {
    const proto = r?.probe_protocol || "tcp";
    const port = Number(r?.probe_port ?? 0);
    if (!port) continue;

    const state = r?.status || "unknown";
    let status;
    if (state === "open") status = "open";
    else if (state === "closed") status = "closed";
    else if (state === "filtered") status = "filtered";
    else status = statusFrom({ info: r?.probe_info, banner: r?.response_banner, fallbackUp: result?.up });

    items.push({
      port,
      protocol: proto,
      service: r?.service || "unknown",
      program: result?.program || "nmap",
      version: r?.response_banner || "Unknown",
      status,
      info: r?.probe_info || null,
      banner: r?.response_banner || null,
      source: "syn_scanner",
      evidence: rows,
      authoritative: false,
    });
  }

  return items;
}
