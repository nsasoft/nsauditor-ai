// plugins/upnp_scanner.mjs
// Enhanced UPnP Scanner — discovers UPnP devices/services in the subnet with comprehensive SSDP analysis
// Performs active M-SEARCH queries, detailed header analysis, and improved error handling
// Filters results to include only devices matching the target host IP by default.
// Set UPNP_INCLUDE_NON_MATCHED=1 to keep all discovered devices.

import upnp from 'node-upnp-utils';
import { isPrivateLike } from '../utils/net_validation.mjs';

const DEBUG = /^(1|true|yes|on)$/i.test(String(process.env.DEBUG_MODE || process.env.UPNP_DEBUG || ""));
function dlog(...a) { if (DEBUG) console.log("[upnp-scanner]", ...a); }

// Active M-SEARCH targets for comprehensive discovery
const SEARCH_TARGETS = [
  'ssdp:all',
  'upnp:rootdevice',
  'urn:schemas-upnp-org:device:MediaRenderer:1',
  'urn:schemas-upnp-org:device:MediaServer:1',
  'urn:schemas-upnp-org:service:ContentDirectory:1',
  'urn:schemas-upnp-org:service:ConnectionManager:1',
  'urn:schemas-wifialliance-org:device:WFADevice:1'
];

// ⚠️ node-upnp-utils' discover() takes its window as `wait`, in WHOLE SECONDS from 1 to 120 (default 5),
// and reads no other key for it (lib/upnp-utils.js, discover: `const sec = params.wait || 5`). Through
// CE 0.2.54 this passed `timeout` in milliseconds, which the library never read: every one of the seven
// searches waited the 5 s default whatever NSA_UPNP_TIMEOUT_MS said, a scan cost ~39 s — over the 30 s
// plugin default on every network scan in the evidence — and the pack recorded a `timeout` window that
// was never applied. The fake the unit tests used accepted any key, which is how it survived.
// A window that is not a positive number falls back to the 15 s default rather than reaching the
// library as NaN, which it rejects — and a rejected search is swallowed below as zero devices.
export const DEFAULT_UPNP_WINDOW_MS = 15000;
export function perTargetWaitSec(windowMs) {
  const ms = Number.isFinite(windowMs) && windowMs > 0 ? windowMs : DEFAULT_UPNP_WINDOW_MS;
  return Math.min(120, Math.max(1, Math.round(ms / SEARCH_TARGETS.length / 1000)));
}
// The M-SEARCH MX header tells devices how long they may take to answer; the library's default is 3 s.
// An MX longer than the wait loses every device that answers after the window closes, so it sits
// INSIDE the window, leaving a second for the description fetch each answer starts.
export function perTargetMx(waitSec) {
  return Math.max(1, waitSec - 1);
}

// ⚠️ THE LIBRARY'S PACKET HANDLER CAN REJECT, AND NOTHING CATCHES IT (EE 1.1.0 build 6, Gate 2).
// node-upnp-utils 1.0.3 — the latest published — calls its async `_receivePacket` from the socket handler
// without a catch, so any rejection is unhandled and ends the WHOLE process. Two ways, both measured on the
// real library: (1) an answer whose description fetch is still in flight when the NEXT search's
// `startDiscovery()` resets the device table reads an entry that no longer exists
// (`SyntaxError: "undefined" is not valid JSON`) — the shorter per-search wait made that likely; (2) an
// answer with no LOCATION, or one that is not a URL (`TypeError: Invalid URL`) — one misbehaving device on
// the LAN, in every release. The guard catches the rejection on the module's single instance, once, and
// COUNTS it by error, and the plugin reports the count and warns. MEASURED, not assumed: the library lists a
// device the moment its answer arrives, BEFORE it fetches the description, so a caught answer is still in
// its search's result — what fails is the library's own description, which 028 does not depend on: it
// fetches the description of every device it reports itself. The original is called SYNCHRONOUSLY, so the
// device is listed exactly when it would have been; only its promise is caught.
const RECEIVE_GUARD = Symbol.for('nsauditor.upnp.receivePacketGuard');
const DROPPED = Symbol.for('nsauditor.upnp.droppedResponses');
export function guardReceivePacket(upnp) {
  if (!upnp || typeof upnp._receivePacket !== 'function' || upnp[RECEIVE_GUARD]) return upnp;
  const original = upnp._receivePacket;
  upnp[DROPPED] = {};
  const count = (err) => {
    const name = err?.name || 'Error';
    upnp[DROPPED][name] = (upnp[DROPPED][name] ?? 0) + 1;
  };
  upnp._receivePacket = function guardedReceivePacket(...args) {
    let p;
    try { p = original.apply(this, args); } catch (err) { count(err); return Promise.resolve(); }
    return Promise.resolve(p).catch(count);
  };
  upnp[RECEIVE_GUARD] = true;
  return upnp;
}
/** Library errors caught so far on this instance, by error name. */
export function droppedResponses(upnp) {
  return { ...(upnp?.[DROPPED] ?? {}) };
}
const droppedSince = (upnp, before) => {
  const now = droppedResponses(upnp); const out = {};
  for (const [k, v] of Object.entries(now)) if (v - (before[k] ?? 0) > 0) out[k] = v - (before[k] ?? 0);
  return out;
};

function ipMatches(target, address) {
  const t = String(target || "").trim();
  const a = String(address || "").trim();
  return t === a;
}

function extractOsFromServer(server) {
  if (!server) return { os: null, version: null };
  const s = String(server).toLowerCase();

  // Check for POSIX
  if (/posix/i.test(s)) {
    return { os: "POSIX", version: null };
  }

  // Check for Linux with version
  const linuxMatch = s.match(/linux\s*\/?\s*([\d.]+)\b/i);
  if (linuxMatch && linuxMatch[1]) {
    return { os: "Linux", version: linuxMatch[1] };
  }

  // Check for Windows
  const windowsMatch = s.match(/windows\s*\/?\s*([\d.]+)\b/i);
  if (windowsMatch && windowsMatch[1]) {
    return { os: "Windows", version: windowsMatch[1] };
  }

  // Check for other OS patterns
  if (/android/i.test(s)) {
    const androidMatch = s.match(/android\s*([\d.]+)/i);
    return { os: "Android", version: androidMatch?.[1] || null };
  }

  if (/darwin|macos|mac\s*os/i.test(s)) {
    const macMatch = s.match(/darwin\s*([\d.]+)|mac\s*os\s*([\d.]+)/i);
    return { os: "macOS", version: macMatch?.[1] || macMatch?.[2] || null };
  }

  return { os: null, version: null };
}

function analyzeSsdpHeaders(headers, rinfo) {
  const analysis = {
    timestamp: new Date().toISOString(),
    sourceIP: rinfo?.address,
    sourcePort: rinfo?.port,
    searchTarget: headers.ST,
    notificationType: headers.NT,
    uniqueServiceName: headers.USN,
    server: headers.SERVER,
    location: headers.LOCATION,
    cacheControl: headers['CACHE-CONTROL'],
    maxAge: null,
    bootId: headers['BOOTID.UPNP.ORG'],
    configId: headers['CONFIGID.UPNP.ORG'],
    date: headers.DATE,
    ext: headers.EXT,
    opt: headers.OPT
  };

  // Extract max-age from cache-control
  if (analysis.cacheControl) {
    const maxAgeMatch = analysis.cacheControl.match(/max-age\s*=\s*(\d+)/i);
    if (maxAgeMatch) {
      analysis.maxAge = parseInt(maxAgeMatch[1], 10);
    }
  }

  return analysis;
}

function extractDeviceInfo(device, deviceXml) {
  const info = {
    friendlyName: null,
    manufacturer: null,
    manufacturerURL: null,
    modelName: null,
    modelNumber: null,
    modelDescription: null,
    serialNumber: null,
    UDN: null,
    deviceType: null,
    services: []
  };

  // Extract from device object if available
  if (device?.description?.device) {
    const desc = device.description.device;
    info.friendlyName = desc.friendlyName;
    info.manufacturer = desc.manufacturer;
    info.manufacturerURL = desc.manufacturerURL;
    info.modelName = desc.modelName;
    info.modelNumber = desc.modelNumber;
    info.modelDescription = desc.modelDescription;
    info.serialNumber = desc.serialNumber;
    info.UDN = desc.UDN;
    info.deviceType = desc.deviceType;

    // Extract services
    if (desc.serviceList?.service) {
      const services = Array.isArray(desc.serviceList.service) ? 
        desc.serviceList.service : [desc.serviceList.service];
      info.services = services.map(svc => ({
        serviceType: svc.serviceType,
        serviceId: svc.serviceId,
        controlURL: svc.controlURL,
        eventSubURL: svc.eventSubURL,
        SCPDURL: svc.SCPDURL
      }));
    }
  }

  return info;
}

async function fetchDeviceDescription(location, timeout = 5000) {
  if (!location) return null;
  
  try {
    const { default: fetch } = await import('node-fetch');
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeout);
    
    const response = await fetch(location, { 
      signal: controller.signal,
      headers: {
        'User-Agent': 'UPnP-Scanner/1.0'
      }
    });
    
    clearTimeout(timeoutId);
    
    if (response.ok) {
      return await response.text();
    } else {
      dlog(`HTTP ${response.status} when fetching ${location}`);
      return null;
    }
  } catch (e) {
    if (e.name === 'AbortError') {
      dlog("Fetch timeout for device description:", location);
    } else {
      dlog("Failed to fetch device description:", e?.message || e);
    }
    return null;
  }
}

function deduplicateDevices(devices) {
  // Use Map to track unique devices by USN base (before ::)
  const seen = new Map();
  
  for (const device of devices) {
    const headers = device.headers || {};
    const usn = headers.USN || '';
    const baseUsn = usn.split('::')[0]; // Get base USN without service type
    const address = device.address || '';
    
    // Create unique device signature
    const signature = `${baseUsn}|${address}`;
    
    if (!seen.has(signature)) {
      // Store first occurrence
      seen.set(signature, {
        device,
        searchTargets: new Set([headers.ST].filter(Boolean))
      });
    } else {
      // Add search target to existing device
      const existing = seen.get(signature);
      if (headers.ST) {
        existing.searchTargets.add(headers.ST);
      }
      // Merge any additional device info
      if (device.description && !existing.device.description) {
        existing.device.description = device.description;
      }
      dlog(`Deduplicated device: ${signature} (ST: ${headers.ST})`);
    }
  }

  // Return deduplicated devices with aggregated search targets
  return Array.from(seen.values()).map(entry => {
    const device = {...entry.device};
    device.searchTargets = Array.from(entry.searchTargets);
    return device;
  });
}

async function runWithUpnp(targetHost, timeoutMs, opts) {
  let upnp;
  if (process.env.UPNP_TEST_FAKE && globalThis.__upnpFakeFactory) {
    upnp = globalThis.__upnpFakeFactory();
  } else {
    const { default: upnpModule } = await import('node-upnp-utils');
    upnp = guardReceivePacket(upnpModule);
  }
  const droppedBefore = droppedResponses(upnp);

  const allDevices = [];
  let matched = false;
  const includeNonMatched = /^(1|true|yes|on)$/i.test(String(process.env.UPNP_INCLUDE_NON_MATCHED || ""));

  try {
    // Perform discovery with multiple search targets
    for (const searchTarget of SEARCH_TARGETS) {
      try {
        dlog(`Searching for ${searchTarget}`);
        const wait = perTargetWaitSec(timeoutMs);
        const devices = await upnp.discover({ wait, mx: perTargetMx(wait), st: searchTarget });
        allDevices.push(...devices);
        dlog(`Found ${devices.length} devices for ${searchTarget}`);
      } catch (e) {
        dlog(`Error searching for ${searchTarget}:`, e?.message || e);
      }
    }

    // Deduplicate devices
    const uniqueDevices = deduplicateDevices(allDevices);
    dlog(`Total unique devices discovered: ${uniqueDevices.length}`);

    const rows = [];
    
    for (const device of uniqueDevices) {
      const address = device.address;
      const ipHit = ipMatches(targetHost, address);
      const keepRow = ipHit || includeNonMatched;

      if (!keepRow) continue;

      const headers = device.headers || {};
      const usn = headers.USN || 'unknown';
      const location = headers.LOCATION || '';
      const server = headers.SERVER || '';
      const st = headers.ST || 'upnp:rootdevice';
      
      // Enhanced OS detection
      const { os, version } = extractOsFromServer(server);
      
      // Enhanced SSDP analysis
      const ssdpAnalysis = analyzeSsdpHeaders(headers, { address, port: 1900 });
      
      // Fetch and parse device description if available
      let deviceXml = null;
      if (location) {
        deviceXml = await fetchDeviceDescription(location, 3000);
      }
      
      // Extract detailed device information
      const deviceInfo = extractDeviceInfo(device, deviceXml);
      
      // Build comprehensive info string
      const infoParts = [];
      infoParts.push(`type=${st}`);
      
      if (deviceInfo.friendlyName) {
        infoParts.push(`name="${deviceInfo.friendlyName}"`);
      }
      if (deviceInfo.manufacturer) {
        infoParts.push(`manufacturer="${deviceInfo.manufacturer}"`);
      }
      if (deviceInfo.modelName) {
        infoParts.push(`model="${deviceInfo.modelName}"`);
      }
      if (deviceInfo.modelNumber) {
        infoParts.push(`modelNumber="${deviceInfo.modelNumber}"`);
      }
      if (os) {
        infoParts.push(`os="${os}${version ? ` ${version}` : ''}"`);
      }
      if (ssdpAnalysis.maxAge) {
        infoParts.push(`maxAge=${ssdpAnalysis.maxAge}s`);
      }
      
      infoParts.push(`address=${address}`);
      if (location) {
        infoParts.push(`location=${location}`);
      }

      // Enhanced banner with comprehensive data
      const bannerObj = {
        address,
        headers: {
          USN: usn,
          SERVER: server,
          ST: st,
          LOCATION: location,
          'CACHE-CONTROL': headers['CACHE-CONTROL'],
          DATE: headers.DATE,
          EXT: headers.EXT
        },
        ssdpAnalysis,
        deviceInfo,
        descriptionXML: deviceXml ? deviceXml.substring(0, 2000) : null, // Limit XML size
        xmlTruncated: deviceXml && deviceXml.length > 2000
      };

      const row = {
        probe_protocol: "upnp",
        probe_port: 1900,
        probe_info: (ipHit ? "Matched host — " : "Discovered — ") + infoParts.join(" "),
        response_banner: JSON.stringify(bannerObj),
        os,
        osVersion: version,
        ssdpHeaders: ssdpAnalysis,
        deviceDetails: deviceInfo
      };
      
      rows.push(row);

      if (ipHit) {
        matched = true;
        dlog(`Match detected for host ${targetHost} with device ${address}`);
      }
    }

    return { rows, matched, dropped: droppedSince(upnp, droppedBefore) };
    
  } catch (e) {
    dlog("UPnP discovery error:", e?.message || e);
    return { rows: [], matched: false, dropped: droppedSince(upnp, droppedBefore) };
  }
}

export default {
  id: "028",
  // ── O1(b) DECLARED BUDGET (CE 0.2.55, EE 1.1.0 build 6) ──────────────────────────────────────
  // Two bases, both named. PRE-FIX: 39 320 ms measured at Gate 2 build 5 (pack
  // 192.168.1.1_20260923_182912), and a timeout at the 30 s default on every network scan in the
  // evidence since EE 0.44.0 — seven searches at the library's 5 s default, the `wait` defect above.
  // POST-FIX: seven searches at `perTargetWaitSec` (2 s at the default window) plus ~0.6 s of send
  // overhead each, ~18 s with no device to describe, and up to 3 s more per matching device's
  // description fetch; Gate 2 build 6 records the measured figure. Rule of record (architect ruling,
  // build 6): ≥ 1.5 × the measured maximum, ≤ the 120 000 ceiling — 60 000 (1.53× the pre-fix
  // maximum). A budget buys TIME, never a pass: an exceeded declared budget still fails closed to
  // not-measured, and a caller wall still binds.
  timeoutMs: 60_000,
  name: "Enhanced UPnP Scanner",
  description: "Comprehensive UPnP/SSDP discovery with active M-SEARCH probing, detailed header analysis, and enhanced device fingerprinting. Returns only instances matching the target host IP by default.",
  priority: 346,
  requirements: {},
  protocols: ["upnp", "ssdp"],
  ports: [1900],
  runStrategy: "single",

  async run(host, _port = 1900, opts = {}) {
    const timeoutMs = Number(opts.timeoutMs ?? process.env.NSA_UPNP_TIMEOUT_MS ?? DEFAULT_UPNP_WINDOW_MS);
    const data = [];

    if (!isPrivateLike(host)) {
      data.push({
        probe_protocol: "upnp",
        probe_port: 1900,
        probe_info: "Non-local target — UPnP/SSDP not attempted (requires local network)",
        response_banner: null
      });
      return {
        up: false,
        program: "UPnP/SSDP",
        version: "Unknown",
        os: null,
        type: "upnp",
        data
      };
    }

    const { rows, matched, dropped } = await runWithUpnp(host, timeoutMs, opts);
    dlog(`Discovery complete: matched=${matched}, rows.length=${rows.length}`);
    const upnpLibraryErrors = Object.values(dropped).reduce((a, b) => a + b, 0);
    if (upnpLibraryErrors > 0) {
      console.warn(`[upnp-scanner] ${upnpLibraryErrors} UPnP answer(s) failed inside the UPnP library and were caught (${Object.entries(dropped).map(([k, v]) => `${k} ×${v}`).join(', ')}); each device is still listed from its answer, and this scanner fetches the description of every device it reports itself`);
    }

    if (rows.length === 0) {
      data.push({
        probe_protocol: "upnp",
        probe_port: 1900,
        probe_info: "No UPnP/SSDP devices relevant to target IP discovered within timeout window",
        response_banner: JSON.stringify({
          searchTargets: SEARCH_TARGETS,
          timeout: timeoutMs,
          waitPerTargetSec: perTargetWaitSec(timeoutMs),
          reason: "No responses received"
        })
      });
    } else {
      // Sort rows by relevance (matched first, then by device type)
      rows.sort((a, b) => {
        if (a.probe_info.includes("Matched host") && !b.probe_info.includes("Matched host")) return -1;
        if (!a.probe_info.includes("Matched host") && b.probe_info.includes("Matched host")) return 1;
        return 0;
      });
      
      data.push(...rows);
    }

    // Add summary row for matched devices
    if (matched) {
      const matchedRows = rows.filter(r => r.probe_info.includes("Matched host"));
      const uniqueDeviceTypes = [...new Set(matchedRows.map(r => {
        const match = r.probe_info.match(/type=([^\s]+)/);
        return match ? match[1] : 'unknown';
      }))];
      
      const summaryRow = {
        probe_protocol: "upnp",
        probe_port: 1900,
        probe_info: `Host ${host} confirmed via UPnP/SSDP - ${matchedRows.length} device(s) found: ${uniqueDeviceTypes.join(', ')}`,
        response_banner: JSON.stringify({
          summary: true,
          matchedDevices: matchedRows.length,
          deviceTypes: uniqueDeviceTypes,
          discoveredAt: new Date().toISOString()
        })
      };
      
      data.unshift(summaryRow); // Add at beginning
      dlog(`Added summary row for ${matchedRows.length} matched devices`);
    }

    return {
      up: matched,
      program: "UPnP/SSDP",
      version: "1.1-Enhanced",
      os: matched ? rows.find(r => r.os)?.os || null : null,
      osVersion: matched ? rows.find(r => r.osVersion)?.osVersion || null : null,
      type: "upnp",
      deviceCount: rows.length,
      searchTargets: SEARCH_TARGETS,
      waitPerTargetSec: perTargetWaitSec(timeoutMs),
      upnpLibraryErrors,
      upnpLibraryErrorsByName: dropped,
      data
    };
  }
};