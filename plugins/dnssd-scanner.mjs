// plugins/dnssd-scanner.mjs

const DEBUG = /^(1|true|yes|on)$/i.test(String(process.env.DEBUG_MODE || process.env.DNSSD_DEBUG || ""));
function dlog(...a) { if (DEBUG) console.log("[dnssd-scanner]", ...a); }

// Use mock if in test mode
let dnssd;
if (process.env.DNSSD_TEST_FAKE && globalThis.__dnssdFakeFactory) {
  dnssd = globalThis.__dnssdFakeFactory();
} else {
  try {
    // Try different ways to get the browser
    const mod = await import('dnssd');
    
    // Case 1: mod exports Browser directly
    if (typeof mod.Browser === 'function') {
      dnssd = {
        createBrowser: (type) => new mod.Browser(type)
      };
    }
    // Case 2: mod.default exports Browser
    else if (mod.default && typeof mod.default.Browser === 'function') {
      dnssd = {
        createBrowser: (type) => new mod.default.Browser(type)
      };
    }
    // Case 3: mod exports createBrowser
    else if (typeof mod.createBrowser === 'function') {
      dnssd = mod;
    }
    // Case 4: mod.default exports createBrowser  
    else if (mod.default && typeof mod.default.createBrowser === 'function') {
      dnssd = mod.default;
    }
    // No valid export found
    else {
      throw new Error('Could not find Browser or createBrowser in dnssd module');
    }
  } catch (e) {
    dlog('Failed to initialize dnssd:', e);
    // Provide fallback that logs errors
    dnssd = {
      createBrowser: () => {
        throw new Error('DNS-SD browser not available: ' + e.message);
      }
    };
  }
}



// Common service types to discover
const SERVICE_TYPES = [
  '_http._tcp',
  '_https._tcp',
  '_printer._tcp',
  '_ipp._tcp',
  '_pdl-datastream._tcp',
  '_scanner._tcp',
  '_airport._tcp',
  '_airplay._tcp',
  '_raop._tcp',
  '_spotify-connect._tcp',
  '_workstation._tcp',
  '_companion-link._tcp',
  '_device-info._tcp',
  '_googlecast._tcp'
];

async function discoverServices(targetHost, timeoutMs) {
  return new Promise((resolve) => {
    const services = new Map();
    const browsers = [];
    const dataRows = [];

    for (const type of SERVICE_TYPES) {
      try {
        const browser = dnssd.createBrowser(type);

        browser.on('serviceUp', service => {
          const addresses = service.addresses || [];
          const isTargetHost = addresses.some(addr => addr === targetHost);

          services.set(`${service.name}|${service.type}`, {
            service,
            isTargetHost
          });
        });

        browser.on('serviceDown', service => {
          // Only push to dataRows, do not add to services map
          dataRows.push({
            probe_protocol: "dnssd",
            probe_port: 5353,
            probe_info: `Service "${service.name}" (${service.type}) went offline`,
            response_banner: JSON.stringify({
              name: service.name,
              type: service.type,
              addresses: service.addresses,
              offline: true,
              discoveredAt: new Date().toISOString()
            })
          });
        });

        browser.start();
        browsers.push(browser);

      } catch (e) {
        dlog(`Error creating browser for ${type}:`, e?.message || e);
      }
    }

    setTimeout(() => {
      browsers.forEach(browser => browser.stop());

      // Only process discovered services with a valid service object
      for (const entry of services.values()) {
        if (!entry.service) continue;

        const service = entry.service;
        const isTargetHost = entry.isTargetHost;

        const txtRecords = Object.entries(service.txt || {})
          .map(([key, value]) => `${key}=${value}`)
          .join('; ');

        const infoParts = [
        `name="${service.name}"`,
        // Fix type display
        `type=${service.type?.name || service.type}._${service.type?.protocol || 'tcp'}`,
        `port=${service.port}`,
        `addresses=${(service.addresses || []).join(',')}`,
        ];

        if (txtRecords) {
          infoParts.push(`txt=[${txtRecords}]`);
        }

        dataRows.push({
          probe_protocol: "dnssd",
          probe_port: 5353,
          probe_info: (isTargetHost ? "Matched host — " : "Discovered — ") + infoParts.join(" "),
          response_banner: JSON.stringify({
            name: service.name,
            type: service.type,
            port: service.port,
            addresses: service.addresses,
            txt: service.txt || {},
            discoveredAt: new Date().toISOString()
          })
        });
      }

      resolve(dataRows);
    }, timeoutMs);
  });
}

export default {
  id: "018",
  name: "DNS-SD Service Scanner",
  description: "Discovers DNS-SD/mDNS services on the network with comprehensive service type detection",
  priority: 347,
  requirements: {},
  protocols: ["dnssd", "mdns"],
  ports: [5353],
  runStrategy: "single",

  async run(host, _port = 5353, opts = {}) {
    const timeoutMs = Number(opts.timeoutMs ?? process.env.NSA_DNSSD_TIMEOUT_MS ?? 10000);
    const data = [];
    const includeNonMatched = /^(1|true|yes|on)$/i.test(String(process.env.DNSSD_INCLUDE_NON_MATCHED || ""));

    try {
        const discoveries = await discoverServices(host, timeoutMs);
        let matched = false;
        const matchedRows = [];
        const otherRows = [];

        // First pass - separate matched from non-matched
        for (const entry of discoveries) {
        const addresses = JSON.parse(entry.response_banner)?.addresses || [];
        const isMatch = addresses.includes(host);
        
        if (isMatch) {
            matched = true;
            matchedRows.push(entry);
        } else if (includeNonMatched) {
            otherRows.push(entry);
        }
        }

        // Add summary first if we have any data
        if (matchedRows.length > 0 || (includeNonMatched && otherRows.length > 0)) {
        data.push({
            probe_protocol: "dnssd",
            probe_port: 5353,
            probe_info: matched ? 
            `Host ${host} provides ${matchedRows.length} DNS-SD service(s)` :
            `No DNS-SD services found for host ${host} (${otherRows.length} other services discovered)`,
            response_banner: JSON.stringify({
            summary: true,
            servicesFound: matchedRows.length + otherRows.length,
            matchedHost: matched,
            discoveredAt: new Date().toISOString()
            })
        });
        }

        // Add matched rows first
        data.push(...matchedRows);

        // Add other rows only if includeNonMatched is true
        if (includeNonMatched) {
        data.push(...otherRows);
        }

        return {
        up: matched,
        program: "DNS-SD/mDNS",
        version: "Unknown",
        type: "dnssd",
        data
        };

    } catch (e) {
        dlog("DNS-SD discovery error:", e?.message || e);
        data.push({
        probe_protocol: "dnssd",
        probe_port: 5353,
        probe_info: `DNS-SD discovery failed: ${e?.message || 'Unknown error'}`,
        response_banner: null
        });

        return {
        up: false,
        program: "DNS-SD/mDNS",
        version: "Unknown",
        type: "dnssd",
        data
        };
    }
 }
};