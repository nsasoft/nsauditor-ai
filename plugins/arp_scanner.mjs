// plugins/arp_scanner.mjs
// ARP Scanner — infers vendor/OS hints from ARP (local targets only) via ctx helpers.
// Short-circuits if a prior plugin already inferred OS (e.g., Ping Checker or others).

import { promisify } from "node:util";
import { execFile } from "node:child_process";

const execFileP = promisify(execFile);

const DEBUG = /^(1|true|yes|on)$/i.test(String(process.env.DEBUG_MODE || process.env.ARP_DEBUG || ""));
const ONLY_IF_OS_UNKNOWN = !/^(0|false|no|off)$/i.test(String(process.env.ARP_RUN_ONLY_IF_OS_UNKNOWN ?? "1"));

function dlog(...a) { if (DEBUG) console.log("[arp-scanner]", ...a); }

function isPrivateLike(ip) {
  if (!ip) return false;
  if (/^(10)\./.test(ip)) return true;
  if (/^(192\.168)\./.test(ip)) return true;
  if (/^(172\.(1[6-9]|2\d|3[0-1]))\./.test(ip)) return true;
  if (/^(169\.254)\./.test(ip)) return true;
  return false;
}

// --- Exported: tests expect a STRING MAC (or null) ---
export function parseArpOutput(out, ip) {
  if (!out) return null;

  // Normalize MAC patterns (colon or dash, 1 or 2 hex digits per octet)
  const macRe = /([0-9a-f]{1,2}(?:[:-][0-9a-f]{1,2}){5})/i;

  // Log raw output for debugging
  dlog("Raw ARP output:", out);

  // Prefer a line with the specific IP if provided (macOS/Linux: IP in parentheses or first column; Windows: "Internet Address")
  if (ip) {
    const ipLine = out
      .split(/\r?\n/)
      .find((l) => l.includes(ip) || l.includes(`(${ip})`));
    if (ipLine) {
      const m = ipLine.match(macRe);
      if (m) {
        let mac = m[1].replace(/-/g, ":").toUpperCase();
        // Normalize to two digits per octet
        mac = mac.split(":").map(part => part.padStart(2, "0")).join(":");
        dlog(`Parsed MAC for IP ${ip}: ${mac}`);
        return mac;
      }
    }
  }

  // Fallback: first MAC in the whole output
  const m2 = out.match(macRe);
  if (m2) {
    let mac = m2[1].replace(/-/g, ":").toUpperCase();
    mac = mac.split(":").map(part => part.padStart(2, "0")).join(":");
    dlog(`Parsed fallback MAC: ${mac}`);
    return mac;
  }

  dlog("No MAC found in output");
  return null;
}

async function getMacViaArp(ip, iface = null) {
  const cmd = "arp";
  const args = process.platform === "win32" ? ["-a", ip] : ["-n", ip];
  // Add interface specification for macOS/Linux if provided
  if (iface && process.platform !== "win32") {
    args.push("-i", iface);
  }

  try {
    const { stdout } = await execFileP(cmd, args, { windowsHide: true, timeout: 5000 });
    return parseArpOutput(stdout, ip);
  } catch (e) {
    dlog("arp exec failed:", e?.message || e);
    return null;
  }
}

export default {
  id: "026",
  name: "ARP Scanner",
  description: "Infers vendor/OS hints from ARP (local targets only) via ctx helpers.",
  priority: 25,
  requirements: {},
  protocols: ["arp"],
  ports: [],

  async run(host, _port, opts = {}) {
    const data = [];
    let up = false;
    let os = null;

    // ----- Short-circuit logic (no manager changes required) -----
    const ctx = opts?.context || {};
    const osKnown = !!ctx.os || !!ctx.arpOs || !!ctx.pingOs;
    if (ONLY_IF_OS_UNKNOWN && osKnown) {
      dlog("Skipping ARP scan — OS already known by prior probe");
      data.push({
        probe_protocol: "arp",
        probe_port: 0,
        probe_info: "Skipped: OS already known from prior plugin",
        response_banner: null
      });
      return { up: false, os: null, data };
    }
    // -------------------------------------------------------------

    // Only meaningful on local subnets
    if (!isPrivateLike(host)) {
      dlog("Target not in private/local range; ARP not attempted.");
      data.push({
        probe_protocol: "arp",
        probe_port: 0,
        probe_info: "Non-local target — ARP not attempted",
        response_banner: null
      });
      return { up: false, os: null, data };
    }

    // Try with interface 'en0' for macOS, fallback to no interface
    const interfaces = process.platform === "win32" ? [null] : [null, "en0"];
    let mac = null;
    for (const iface of interfaces) {
      mac = await getMacViaArp(host, iface);
      if (mac) break;
    }

    if (!mac) {
      data.push({
        probe_protocol: "arp",
        probe_port: 0,
        probe_info: "No ARP entry",
        response_banner: null,
        mac: null
      });
      return { up: false, os: null, data };
    }

    up = true; // ARP implies L2 presence

    // Use ctx helpers only (no internal OUI loading)
    const vendorRaw = typeof ctx.lookupVendor === "function" ? (ctx.lookupVendor(mac) || null) : null;
    const vendor = vendorRaw ? vendorRaw.replace(/[\r\n]+/g, ' ').trim() : null;
    const info = vendor ? `ARP entry found — vendor: ${vendor}` : "ARP entry found";
    data.push({
      probe_protocol: "arp",
      probe_port: 0,
      probe_info: info,
      response_banner: mac,
      mac
    });

    // Vendor → OS heuristic via ctx helper (conservative)
    if (typeof ctx.probableOsFromVendor === "function") {
      const vendorOs = ctx.probableOsFromVendor(vendor);
      if (vendorOs && vendorOs !== "Unknown") os = vendorOs;
    }

    return {
      up,
      program: "ARP",
      version: "Unknown",
      os,
      type: "arp",
      data
    };
  }
};