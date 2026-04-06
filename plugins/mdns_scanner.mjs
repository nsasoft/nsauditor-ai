// plugins/mdns_scanner.mjs
// MDNS Scanner — discovers mDNS/Bonjour services and RETURNS ONLY records
// that are relevant to the scanned host by default.
// Relevance = (A/AAAA includes target host IP) OR (TXT contains a MAC that
// matches the target MAC). Set MDNS_INCLUDE_NON_MATCHED=1 to keep all rows.

const DEBUG = /^(1|true|yes|on)$/i.test(String(process.env.DEBUG_MODE || process.env.MDNS_DEBUG || ""));
function dlog(...a) { if (DEBUG) console.log("[mdns-scanner]", ...a); }

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

function ipMatches(target, addresses = []) {
  const t = String(target || "").trim();
  return addresses.some(a => String(a).trim() === t);
}

// --- Robust extraction for JSON, key=value, or inline arrays ---
function extractAddressesFromBanner(banner) {
  if (!banner) return [];
  const s = String(banner);

  // Try JSON first
  try {
    const obj = JSON.parse(s);
    if (Array.isArray(obj?.addresses)) return obj.addresses.map(String);
    if (Array.isArray(obj?.addrs)) return obj.addrs.map(String);
  } catch {}

  // Try "addresses=[...]" JSON-like fragment
  const mj = s.match(/"addresses"\s*:\s*\[([^\]]*)\]/i);
  if (mj) {
    return mj[1]
      .split(",")
      .map(x => x.replace(/["'\s]/g, ""))
      .filter(Boolean);
  }

  // Try key=value (legacy)
  const mkv = s.match(/addresses\s*=\s*([^\s;]+)/i);
  if (mkv) {
    return mkv[1]
      .split(/[,\s]+/)
      .map(x => x.trim())
      .filter(Boolean);
  }

  return [];
}

function normalizeMac(s) {
  if (!s) return null;
  const hex = String(s).trim().toUpperCase();
  const m = hex.match(/^([0-9A-F]{2}[:\-]){5}[0-9A-F]{2}$/) || hex.match(/^[0-9A-F]{12}$/);
  if (!m) return null;
  const flat = hex.replace(/[^0-9A-F]/g, "");
  return flat.length === 12 ? flat : null;
}

function anyMacsFromObject(obj) {
  // Extract all MAC-looking values from a TXT object (deviceid, rpBA, bs, etc.)
  const out = [];
  if (!obj || typeof obj !== "object") return out;
  for (const v of Object.values(obj)) {
    const mac = normalizeMac(v);
    if (mac) out.push(mac);
  }
  return out;
}

function macMatchesTarget(txtObj, targetMacNorm) {
  if (!targetMacNorm) return false;
  const found = anyMacsFromObject(txtObj);
  return found.some(m => m === targetMacNorm);
}

function compactTxt(obj) {
  if (!obj || typeof obj !== 'object') return { banner: null, obj: null };
  const keep = {};
  for (const [k, v] of Object.entries(obj)) {
    if (k.length <= 24 && String(v).length <= 256) keep[k] = v;
  }
  let banner = null;
  try { banner = JSON.stringify(keep); } catch {}
  return { banner, obj: keep };
}

function unescapeFullname(s) {
  // Convert DNS-SD escaped spaces \032 → ' '
  return String(s || "").replace(/\\032/g, " ");
}

// Deduplicate and merge rows based on probe_info and response_banner
function deduplicateAndMergeRows(rows) {
  const seen = new Map();
  const servicePairs = [
    ['ipp', 'ipps'],
    ['uscan', 'uscans']
  ];

  // Helper to extract service type from probe_info
  function getServiceType(probeInfo) {
    const match = probeInfo.match(/^[^—]+—\s*([^.\s]+)\./);
    return match ? match[1] : '';
  }

  // Helper to merge service types in probe_info
  function mergeProbeInfo(info1, info2, serviceType1, serviceType2) {
    const prefix = info1.match(/^[^—]+—\s*/)[0];
    const rest = info1.replace(/^[^—]+—\s*[^.\s]+\./, '');
    return `${prefix}${serviceType1}/${serviceType2}.${rest}`;
  }

  for (const row of rows) {
    const signature = `${row.probe_info}|${row.response_banner || ''}`;
    const serviceType = getServiceType(row.probe_info);

    // Check if this row can be merged with an existing one
    let merged = false;
    if (row.response_banner) {
      for (const [key, existing] of seen.entries()) {
        if (existing.response_banner === row.response_banner) {
          const existingServiceType = getServiceType(existing.probe_info);
          for (const [type1, type2] of servicePairs) {
            if (
              (serviceType === type1 && existingServiceType === type2) ||
              (serviceType === type2 && existingServiceType === type1)
            ) {
              // Merge the service types
              seen.set(key, {
                ...existing,
                probe_info: mergeProbeInfo(existing.probe_info, row.probe_info, existingServiceType, serviceType),
                probe_port: Math.min(existing.probe_port, row.probe_port) // Use the lower port if they differ
              });
              merged = true;
              break;
            }
          }
          if (merged) break;
        }
      }
    }

    // If not merged and not seen, add as new
    if (!merged && !seen.has(signature)) {
      seen.set(signature, row);
    }
  }

  return Array.from(seen.values());
}

// --------------------------- node-mdns path ---------------------------
async function runWithNodeMdns(targetHost, timeoutMs, opts) {
  const mdnsMod = await import('mdns');
  const mdns = mdnsMod.default || mdns;

  const sequence = [
    mdns.rst.DNSServiceResolve(),
    mdns.rst.DNSServiceGetAddrInfo({ families: [4, 6] }),
  ];

  const rows = [];
  let matched = false;
  const stopFns = [];
  const includeNonMatched = /^(1|true|yes|on)$/i.test(String(process.env.MDNS_INCLUDE_NON_MATCHED || ""));
  const targetMacNorm =
    normalizeMac(opts?.targetMac) ||
    normalizeMac(opts?.arpMac) ||
    normalizeMac(opts?.context?.arpMac);

  const browserAllTypes = mdns.browseThemAll();
  stopFns.push(() => { try { browserAllTypes.stop(); } catch {} });

  browserAllTypes.on('serviceUp', serviceType => {
    try {
      const t = serviceType?.type;
      if (!t) return;
      const specificBrowser = mdns.createBrowser(t, { resolverSequence: sequence });
      stopFns.push(() => { try { specificBrowser.stop(); } catch {} });

      specificBrowser.on('serviceUp', service => {
        const addresses = Array.isArray(service.addresses) ? service.addresses.slice() : [];
        const ipHit = ipMatches(targetHost, addresses);

        // Build TXT (keep an object for MAC matching + string banner for display)
        const { obj: txtObj } = compactTxt(service.txtRecord || {});
        const macHit = macMatchesTarget(txtObj, targetMacNorm);

        const keepRow = ipHit || macHit || includeNonMatched;

        const infoParts = [];
        infoParts.push(`${service.type?.name || "unknown"}.${service.type?.protocol || "tcp"}`);
        if (service.name) infoParts.push(`name="${service.name}"`);
        const model = service.txtRecord?.model || service.txtRecord?.mdl || service.txtRecord?.ty;
        if (model) infoParts.push(`model="${model}"`);
        if (service.host) infoParts.push(`host=${service.host}`);
        if (service.fullname) infoParts.push(`fullname="${unescapeFullname(service.fullname)}"`);

        if (keepRow) {
          rows.push({
            probe_protocol: "mdns",
            probe_port: Number.isFinite(service.port) ? service.port : 0,
            probe_info: ((ipHit || macHit) ? "Matched host — " : "Discovered — ") + infoParts.join(" "),
            response_banner: JSON.stringify({
              addresses: Array.isArray(service.addresses) ? service.addresses : [],
              txt: txtObj
            })
          });
        }

        if (ipHit || macHit) matched = true;
      });

      specificBrowser.on('serviceDown', () => {});
      specificBrowser.start();
    } catch (e) {
      dlog("node-mdns serviceType handler error:", e?.message || e);
    }
  });

  browserAllTypes.start();
  await new Promise(res => setTimeout(res, timeoutMs));
  for (const fn of stopFns) { try { fn(); } catch {} }
  return { rows: deduplicateAndMergeRows(rows), matched };
}

// ----------------------- multicast-dns fallback ----------------------
async function runWithMulticastDns(targetHost, timeoutMs, opts) {
  let mdns;
  if (process.env.MDNS_TEST_FAKE && globalThis.__mdnsFakeFactory) {
    mdns = globalThis.__mdnsFakeFactory();
  } else {
    const { default: MDNS } = await import('multicast-dns');
    mdns = MDNS();
  }

  const rows = [];
  let matched = false;
  const types = new Set();
  const includeNonMatched = /^(1|true|yes|on)$/i.test(String(process.env.MDNS_INCLUDE_NON_MATCHED || ""));
  const targetMacNorm =
    normalizeMac(opts?.targetMac) ||
    normalizeMac(opts?.arpMac) ||
    normalizeMac(opts?.context?.arpMac);

  function recordDirectAHits(pkt) {
    const aRecords = []
      .concat(pkt?.answers || [])
      .concat(pkt?.additionals || [])
      .filter(x => x && (x.type === 'A' || x.type === 'AAAA') && x.data);

    const addrs = aRecords.map(x => x.data);
    if (ipMatches(targetHost, addrs)) {
      matched = true;
      rows.push({
        probe_protocol: "mdns",
        probe_port: 0,
        probe_info: "Matched host — direct A/AAAA hit",
        response_banner: JSON.stringify({ addresses: addrs })
      });
    }
  }

  function parseTxtFor(serviceFqdn, res) {
    const obj = {};
    for (const t of (res.additionals || [])) {
      if (t.type === 'TXT' && t.name === serviceFqdn) {
        const frags = Array.isArray(t.data) ? t.data : [t.data];
        for (const f of frags) {
          const s = Buffer.isBuffer(f) ? f.toString('utf8') : String(f || '');
          const m = s.match(/^([^=]+)=(.*)$/);
          if (m) obj[m[1]] = m[2];
        }
      }
    }
    return compactTxt(obj); // {banner, obj}
  }

  function onResponse(res) {
    try {
      // 1) Fast path: direct A/AAAA matches
      recordDirectAHits(res);

      // 2) Learn service types from the DNS-SD registry
      for (const ans of (res?.answers || [])) {
        if (ans.type === 'PTR' && ans.name === '_services._dns-sd._udp.local') {
          if (typeof ans.data === 'string') types.add(ans.data);
        }
      }

      // 3) Parse SRV (+ TXT + A/AAAA) service instances
      for (const ans of (res?.answers || [])) {
        if (ans.type === 'SRV' && /_tcp\.local\.?$/.test(ans.name)) {
          const serviceFqdn = ans.name;
          const port = ans.data?.port || 0;
          const targetHostFqdn = ans.data?.target;

          // gather addresses for the SRV target
          const addrs = [];
          for (const a of (res.additionals || [])) {
            if ((a.type === 'A' || a.type === 'AAAA') && a.name === targetHostFqdn && a.data) {
              addrs.push(a.data);
            }
          }
          for (const a of (res.answers || [])) {
            if ((a.type === 'A' || a.type === 'AAAA') && a.name === targetHostFqdn && a.data) {
              addrs.push(a.data);
            }
          }

          const { obj: txtObj } = parseTxtFor(serviceFqdn, res);
          const ipHit = ipMatches(targetHost, addrs);
          const macHit = macMatchesTarget(txtObj, targetMacNorm);
          const keepRow = ipHit || macHit || includeNonMatched;

          const typeMatch = serviceFqdn.match(/(_[^.]+)\.(_tcp|_udp)\.local\.?$/);
          const typeStr = typeMatch ? `${typeMatch[1].slice(1)}.${typeMatch[2].slice(1)}` : 'unknown.tcp';

          const nameField = serviceFqdn.replace(/\._(tcp|udp)\.local\.?$/,'');
          if (keepRow) {
            rows.push({
              probe_protocol: "mdns",
              probe_port: Number.isFinite(port) ? port : 0,
              probe_info: ((ipHit || macHit) ? "Matched host — " : "Discovered — ") +
                `${typeStr} name="${unescapeFullname(nameField)}" host=${targetHostFqdn}`,
              response_banner: JSON.stringify({
                addresses: addrs,
                txt: txtObj,
                fullname: unescapeFullname(serviceFqdn)
              })
            });
          }
          if (ipHit || macHit) matched = true;
        }
      }
    } catch (e) {
      dlog("multicast-dns parse error:", e?.message || e);
    }
  }

  mdns.on('response', onResponse);

  // Ask for the list of service types
  mdns.query({ questions: [{ name: '_services._dns-sd._udp.local', type: 'PTR' }] });

  const interval = setInterval(() => {
    try {
      for (const t of types) mdns.query({ questions: [{ name: t, type: 'PTR' }] });
    } catch {}
  }, 700);

  await new Promise(res => setTimeout(res, timeoutMs));

  clearInterval(interval);
  try { mdns.removeListener('response', onResponse); } catch {}
  try { mdns.destroy?.(); } catch {}

  return { rows: deduplicateAndMergeRows(rows), matched };
}

// --------------------------- TR-069 Probe ---------------------------
async function probeTr069(host, timeoutMs = 5000) {
  const net = await import('net');
  return new Promise((resolve) => {
    const socket = net.createConnection(7547, host, () => {
      dlog("TR-069 connection established");
      const request = `GET / HTTP/1.1\r\nHost: ${host}:7547\r\nConnection: close\r\n\r\n`;
      socket.write(request);
    });

    let response = '';
    const MAX_TR069_RESPONSE = 32768;
    socket.setTimeout(timeoutMs);
    socket.on('data', (data) => {
      if (response.length > MAX_TR069_RESPONSE) { socket.destroy(); return; }
      response += data.toString();
    });

    socket.on('end', () => {
      dlog("TR-069 response received");
      resolve(response);
    });

    socket.on('timeout', () => {
      dlog("TR-069 probe timeout");
      socket.destroy();
      resolve(null);
    });

    socket.on('error', (e) => {
      dlog("TR-069 probe error:", e.message);
      resolve(null);
    });
  });
}

// ----------------------------- Plugin -----------------------------
export default {
  id: "027",
  name: "MDNS Scanner",
  description: "Discovers Bonjour/mDNS services and (by default) returns only instances that advertise the target host address or MAC.",
  // Runs after Ping/DNS so OS Detector can consume its rows later.
  priority: 345,
  requirements: {},
  protocols: ["mdns"],
  ports: [],
  runStrategy: "single",

  async run(host, _port = 0, opts = {}) {
    const timeoutMs = Number(opts.timeoutMs ?? process.env.NSA_MDNS_TIMEOUT_MS ?? 7000);
    const data = [];

    if (!isPrivateLike(host)) {
      data.push({
        probe_protocol: "mdns",
        probe_port: 0,
        probe_info: "Non-local target — mDNS not attempted",
        response_banner: null
      });
      return {
        up: false,
        program: "mDNS/Bonjour",
        version: "Unknown",
        os: null,
        type: "mdns",
        data
      };
    }

    let rows = [];
    let anyMatched = false;

    // allow tests/users to force multicast-dns path
    const forceFallback = /^(1|true|yes|on)$/i.test(String(process.env.MDNS_FORCE_FALLBACK || ""));

    try {
      if (!forceFallback) {
        dlog("Trying node-mdns strategy…");
        const out = await runWithNodeMdns(host, timeoutMs, opts);
        rows = out.rows;
        anyMatched = out.matched;
      } else {
        throw new Error("Forced fallback");
      }
    } catch (e) {
      dlog("node-mdns not available or forced/failure:", e?.message || e);
      try {
        dlog("Falling back to multicast-dns strategy…");
        const out2 = await runWithMulticastDns(host, timeoutMs, opts);
        rows = out2.rows;
        anyMatched = out2.matched;
      } catch (e2) {
        dlog("multicast-dns failed:", e2?.message || e2);
      }
    }

    if (rows.length === 0) {
      data.push({
        probe_protocol: "mdns",
        probe_port: 0,
        probe_info: "No mDNS records relevant to target (IP/MAC) observed in timeout window",
        response_banner: null
      });
    } else {
      data.push(...deduplicateAndMergeRows(rows));
    }

    // Re-check across aggregated rows and emit the explicit test-visible line
    try {
      const postMatch = data.some(r => {
        const addrs = extractAddressesFromBanner(r?.response_banner);
        return addrs.includes(host);
      });

      if (postMatch) {
        const matchRow = {
          probe_protocol: "mdns",
          probe_port: 5353,
          probe_info: `Matched host IP ${host} via mDNS`,
          response_banner: null
        };
        // Only add the match row if it's not already present
        if (!data.some(r => r.probe_info === matchRow.probe_info && r.response_banner === matchRow.response_banner)) {
          data.push(matchRow);
        }
        anyMatched = true; // reflect in final "up"
      }
    } catch {}

    // TR-069 Probe if mDNS matched (indicating potential router/device)
    if (anyMatched) {
      const tr069Response = await probeTr069(host, timeoutMs);
      if (tr069Response) {
        // Extract useful info, e.g., Server header for firmware/OS
        const serverMatch = tr069Response.match(/Server: ([^\r\n]+)/i);
        const info = serverMatch ? `TR-069 detected — ${serverMatch[1]}` : "TR-069 detected";
        data.push({
          probe_protocol: "tr069",
          probe_port: 7547,
          probe_info: info,
          response_banner: tr069Response.trim().slice(0, 512) // Limit banner size
        });
      } else {
        data.push({
          probe_protocol: "tr069",
          probe_port: 7547,
          probe_info: "No TR-069 response",
          response_banner: null
        });
      }
    }

    return {
      up: anyMatched,
      program: "mDNS/Bonjour",
      version: "Unknown",
      os: null,
      type: "mdns",
      data
    };
  }
};