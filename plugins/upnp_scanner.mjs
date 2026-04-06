// plugins/upnp_scanner.mjs
// Enhanced UPnP Scanner — discovers UPnP devices/services in the subnet with comprehensive SSDP analysis
// Performs active M-SEARCH queries, detailed header analysis, and improved error handling
// Filters results to include only devices matching the target host IP by default.
// Set UPNP_INCLUDE_NON_MATCHED=1 to keep all discovered devices.

import upnp from 'node-upnp-utils';

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

function isPrivateLike(ip) {
  if (!ip) return false;
  if (/^(10)\./.test(ip)) return true;
  if (/^(192\.168)\./.test(ip)) return true;
  if (/^(172\.(1[6-9]|2\d|3[0-1]))\./.test(ip)) return true;
  if (/^(169\.254)\./.test(ip)) return true;
  if (/^fe80:/i.test(ip)) return true;
  if (/^::1$/.test(ip)) return true;
  return false;
}

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
    upnp = upnpModule;
  }

  const allDevices = [];
  let matched = false;
  const includeNonMatched = /^(1|true|yes|on)$/i.test(String(process.env.UPNP_INCLUDE_NON_MATCHED || ""));

  try {
    // Perform discovery with multiple search targets
    for (const searchTarget of SEARCH_TARGETS) {
      try {
        dlog(`Searching for ${searchTarget}`);
        const devices = await upnp.discover({ 
          timeout: Math.floor(timeoutMs / SEARCH_TARGETS.length),
          st: searchTarget 
        });
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

    return { rows, matched };
    
  } catch (e) {
    dlog("UPnP discovery error:", e?.message || e);
    return { rows: [], matched: false };
  }
}

export default {
  id: "028",
  name: "Enhanced UPnP Scanner",
  description: "Comprehensive UPnP/SSDP discovery with active M-SEARCH probing, detailed header analysis, and enhanced device fingerprinting. Returns only instances matching the target host IP by default.",
  priority: 346,
  requirements: {},
  protocols: ["upnp", "ssdp"],
  ports: [1900],
  runStrategy: "single",

  async run(host, _port = 1900, opts = {}) {
    const timeoutMs = Number(opts.timeoutMs ?? process.env.NSA_UPNP_TIMEOUT_MS ?? 15000); // Increased timeout
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

    const { rows, matched } = await runWithUpnp(host, timeoutMs, opts);
    dlog(`Discovery complete: matched=${matched}, rows.length=${rows.length}`);

    if (rows.length === 0) {
      data.push({
        probe_protocol: "upnp",
        probe_port: 1900,
        probe_info: "No UPnP/SSDP devices relevant to target IP discovered within timeout window",
        response_banner: JSON.stringify({
          searchTargets: SEARCH_TARGETS,
          timeout: timeoutMs,
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
      data
    };
  }
};