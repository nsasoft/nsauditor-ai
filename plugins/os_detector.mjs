// plugins/os_detector.mjs
// OS Detector — infers OS from DNS/mDNS/UPnP evidence and conservatively falls back to prior plugin OS labels.
//
// Supports two invocation styles used by tests:
//   1) run(priorResultsArray)
//   2) run(host, port, { results: priorResultsArray, context })
// Returns an object suitable to be wrapped by the concluder.

const ID = "013";
const NAME = "OS Detector";

function asArray(x) {
  if (!x) return [];
  if (Array.isArray(x)) return x;
  return [x];
}

function getResultsFromArgs(a, b, c) {
  // Style 1: run([plugins])
  if (Array.isArray(a) && b === undefined && c === undefined) {
    return { prior: a, host: null, ctx: {} };
  }
  // Style 2: run(host, port, { results, context })
  const host = typeof a === "string" ? a : null;
  const opts = c || {};
  return { prior: asArray(opts.results), host, ctx: opts.context || {} };
}

function toStr(x) {
  return typeof x === "string" ? x : "";
}

function parseKeyVals(s) {
  // Parse 'k=v; k2=v2' (or comma/space separated) into map
  const out = {};
  if (!s) return out;
  const parts = String(s)
    .split(/[;,\s]\s*/)
    .map((p) => p.trim())
    .filter(Boolean);
  for (const p of parts) {
    const m = p.match(/^([^=]+)=(.+)$/);
    if (m) out[m[1].trim().toLowerCase()] = m[2].trim();
  }
  return out;
}

function extractAddresses(banner) {
  const s = String(banner || "");
  if (!s) return [];

  // JSON banner first (preferred by mdns_scanner and upnp_scanner)
  try {
    const obj = JSON.parse(s);
    // Check for address field (used by UPnP Scanner)
    if (obj?.address) return [obj.address];
    // Check for addresses or addrs arrays (used by mDNS Scanner)
    if (Array.isArray(obj?.addresses)) return obj.addresses.map(String);
    if (Array.isArray(obj?.addrs)) return obj.addrs.map(String);
  } catch {}

  // Key/val legacy: '...; addresses=ip1,ip2'
  const m = s.match(/addresses=([^\s;]+)/i);
  if (m) {
    return m[1]
      .split(/[,\s]+/)
      .map((x) => x.trim())
      .filter(Boolean);
  }

  // Inline JSON-like fragment
  const mj = s.match(/"addresses"\s*:\s*\[([^\]]*)\]/i);
  if (mj) {
    return mj[1]
      .split(",")
      .map(x => x.replace(/["'\s]/g, ""))
      .filter(Boolean);
  }

  return [];
}

function evidenceRow(info, port = null, proto = "os-detector", banner = null) {
  return {
    probe_protocol: proto,
    probe_port: port,
    probe_info: info,
    response_banner: banner
  };
}

/* ---------------- Helpers for mDNS Apple inference ---------------- */

function looksLikeAppleHost(s) {
  const host = String(s || "").toLowerCase();
  // iphone-of-alice.local, Alices-iPad.local, Alices-iMac.local, MacBook-Air.local, apple-tv.local, etc.
  return /(iphone|ipad|ipod|imac|macbook|apple.?tv)/i.test(host);
}

function unescapeFullname(s) {
  return String(s || "").replace(/\\032/g, " ");
}

function isAppleMdnsRow(r) {
  const info = toStr(r?.probe_info);
  const banner = toStr(r?.response_banner);

  // Service types associated with Apple
  const appleSvc =
    /airplay\._tcp|raop\._tcp|companion-link\._tcp|_apple|_touch-able|_sleep-proxy/i.test(info);

  // Host/fullname cues
  const infoHostMatch = info.match(/host=([^\s]+)/i);
  const hostLooksApple = infoHostMatch && looksLikeAppleHost(infoHostMatch[1]);

  // Fullname in banner JSON (from mdns_scanner fallback path)
  let fullnameLooksApple = false;
  try {
    const obj = JSON.parse(banner);
    if (obj?.fullname && looksLikeAppleHost(unescapeFullname(obj.fullname))) {
      fullnameLooksApple = true;
    }
  } catch {}

  // TXT cues: model, ty, features, srcvers, or a MAC-like deviceid
  let txtModel = null, hasAirplayish = false, hasDeviceIdMac = false;
  try {
    const obj = JSON.parse(banner);
    const txt = obj?.txt || {};
    txtModel = txt.model || txt.mdl || txt.ty || null;
    hasAirplayish = Boolean(txt.features || txt.srcvers);
    hasDeviceIdMac = /([0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}/.test(String(txt.deviceid || txt.rpBA || ""));
  } catch {
    // also try to scrape from probe_info
    const kv = parseKeyVals(info);
    txtModel = txtModel || kv.model || kv.mdl || kv.ty || null;
    hasAirplayish = hasAirplayish || Boolean(kv.features || kv.srcvers);
    hasDeviceIdMac = hasDeviceIdMac || /deviceid\s*=\s*([0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}/i.test(info);
  }

  const hasMacModelToken = /model\s*=\s*Mac/i.test(info) || /"model"\s*:\s*"?Mac/i.test(banner) || /^Mac/i.test(String(txtModel || ""));

  return appleSvc || hostLooksApple || fullnameLooksApple || hasMacModelToken || hasAirplayish || hasDeviceIdMac;
}

function refineAppleFamilyFromModel(model, info, banner) {
  const m = String(model || "");
  if (/^i(phone|pad|pod)/i.test(m)) return "iOS";
  if (/^Mac/i.test(m)) return "macOS";
  if (/apple.?tv/i.test(m)) return "tvOS";

  // Check hostname for iOS-specific patterns
  const infoHostMatch = info.match(/host=([^\s]+)/i);
  const host = infoHostMatch ? infoHostMatch[1].toLowerCase() : "";
  if (host.includes('iphone') || host.includes('ipad') || host.includes('ipod')) {
    return "iOS";
  }
  if (host.includes('imac') || host.includes('macbook')) {
    return "macOS";
  }
  if (host.includes('apple') && host.includes('tv')) {
    return "tvOS";
  }

  // Check fullname in banner
  try {
    const obj = JSON.parse(banner);
    const fullname = unescapeFullname(obj?.fullname || "").toLowerCase();
    if (looksLikeAppleHost(fullname)) {
      if (fullname.includes('iphone') || fullname.includes('ipad') || fullname.includes('ipod')) {
        return "iOS";
      }
      if (fullname.includes('imac') || fullname.includes('macbook')) {
        return "macOS";
      }
      if (fullname.includes('apple') && host.includes('tv')) {
        return "tvOS";
      }
    }
  } catch {}

  // Check service type for companion-link (macOS or iOS)
  if (info.includes('_companion-link._tcp')) {
    // If no hostname/model indicates otherwise, default to iOS for companion-link
    // as it's common on both but iOS is more likely without macOS-specific cues
    return "iOS";
  }

  return "macOS or iOS";
}

function inferFromMdns(prior, targetHost) {
  // Collect mDNS rows
  const mdnsRows = [];
  for (const p of prior) {
    const rows = asArray(p?.result?.data);
    for (const r of rows) {
      if (String(r?.probe_protocol || "").toLowerCase() === "mdns") {
        mdnsRows.push(r);
      }
    }
  }
  if (mdnsRows.length === 0) return null;

  // Require that at least one row ties to this host by addresses[]
  for (const r of mdnsRows) {
    if (!isAppleMdnsRow(r)) continue;

    const info = toStr(r?.probe_info);
    const banner = toStr(r?.response_banner);
    const addresses = extractAddresses(banner);
    const targetMatches = targetHost ? addresses.includes(targetHost) : addresses.length > 0;

    if (!targetMatches) continue;

    // Try to refine from model type if known
    let model = null;
    try {
      const obj = JSON.parse(banner);
      model = obj?.txt?.model || obj?.txt?.mdl || obj?.txt?.ty || null;
    } catch {
      const kv = parseKeyVals(info);
      model = kv.model || kv.mdl || kv.ty || null;
    }

    const osLabel = refineAppleFamilyFromModel(model, info, banner);
    const ev = `mDNS evidence: Apple (${model ? `model=${model}` : "service/hostname/TXT"}) matched; addresses includes ${targetHost ?? addresses.join(",")}`;
    return {
      os: osLabel,
      osVersion: null,
      osExtras: { mdns: true },
      rows: [evidenceRow(ev, 5353, "mdns", banner)]
    };
  }

  return null;
}

/* ---------------- DNS/BIND → Red Hat ---------------- */

function inferFromBind(prior) {
  // Look for DNS Scanner rows exposing version.bind with BIND banners that contain RedHat tokens
  for (const p of prior) {
    const rows = asArray(p?.result?.data);
    for (const r of rows) {
      const banner = toStr(r?.response_banner);
      const info = toStr(r?.probe_info);

      const isBind = /version\.bind/i.test(info) || /bind/i.test(banner);
      if (!isBind) continue;

      // Common Red Hat markers in packaged BIND strings
      // e.g. '...RedHat-9.11.4-26.P2.el7_9.16.tuxcare.els8'
      const isRedHatish =
        /redhat|\.el\d|centos|rhel/i.test(banner);
      if (!isRedHatish) continue;

      // Extract rhel major/minor from el7_9 or el7 token
      let osVersion = null;
      const em = banner.match(/\.el(\d+)(?:_(\d+))?/i);
      if (em) {
        const major = em[1];
        const minor = em[2] ? `.${em[2]}` : "";
        osVersion = `${major}${minor}`;
      }

      const tuxcare = /\.tuxcare\./i.test(banner);

      return {
        os: "Red Hat Enterprise Linux",
        osVersion,
        osExtras: { tuxcare },
        rows: [
          evidenceRow("BIND evidence: Red Hat family packaging", r?.probe_port ?? null, String(r?.probe_protocol || "dns"), banner)
        ]
      };
    }
  }
  return null;
}

/* ---------------- UPnP → OS from Server Header ---------------- */

function inferFromUpnp(prior, targetHost) {
  const upnpRows = [];
  for (const p of prior) {
    const rows = asArray(p?.result?.data);
    for (const r of rows) {
      if (String(r?.probe_protocol || "").toLowerCase() === "upnp") {
        upnpRows.push(r);
      }
    }
  }
  if (upnpRows.length === 0) return null;

  let bestMatch = null;
  for (const r of upnpRows) {
    const info = toStr(r?.probe_info);
    const banner = toStr(r?.response_banner);
    const addresses = extractAddresses(banner);
    const targetMatches = targetHost ? addresses.includes(targetHost) : addresses.length > 0;

    if (!targetMatches) continue;

    const os = r.os || null;
    const osVersion = r.osVersion || null;

    if (os) {
      const ev = `UPnP evidence: OS detected from server header; addresses includes ${targetHost ?? addresses.join(",")}`;
      const candidate = {
        os,
        osVersion,
        osExtras: { upnp: true },
        rows: [evidenceRow(ev, 1900, "upnp", banner)]
      };

      // Prioritize candidates with osVersion
      if (osVersion) {
        return candidate; // Immediately return if osVersion is present
      } else if (!bestMatch) {
        bestMatch = candidate;
      }
    }
  }
  return bestMatch;
}

/* ---------------- Fallbacks (Ping/FTP/others) ---------------- */

function fallbackFromPluginOs(prior) {
  // Prefer OS labels that came from "Ping Checker" (TTL) or explicit plugin os
  let picked = null;
  for (const p of prior) {
    const name = String(p?.name || "").toLowerCase();
    const os = p?.result?.os || null;
    if (!os) continue;

    // Ping Checker or explicit recognizable plugin OS is a good fallback
    if (name.includes("ping")) {
      picked = { os, rows: [evidenceRow("Baseline OS from Ping Checker")] };
      break;
    }
    // Otherwise remember the first OS we see (e.g., FTP Banner Check -> Linux)
    if (!picked) picked = { os, rows: [evidenceRow(`Fallback OS from ${p?.name || "previous plugin"}`)] };
  }
  return picked;
}

/* ---------------- Main ---------------- */

export default {
  id: ID,
  name: NAME,
  description: "Infers OS from DNS/mDNS/UPnP evidence and conservatively falls back to prior plugin OS labels.",
  // Runs after mDNS (345) and UPnP (346) to have their evidence.
  priority: 365,
  requirements: {},
  protocols: [],
  ports: [],

  async run(a, b, c) {
    const { prior, host } = getResultsFromArgs(a, b, c);

    // 1) UPnP → OS from server header
    const upnp = inferFromUpnp(prior, host);
    if (upnp) {
      return {
        up: true,
        program: NAME,
        version: "1",
        os: upnp.os,
        osVersion: upnp.osVersion || null,
        osExtras: upnp.osExtras || {},
        type: "os",
        data: upnp.rows
      };
    }

    // 2) DNS/BIND → Red Hat family
    const bind = inferFromBind(prior);
    if (bind) {
      return {
        up: true,
        program: NAME,
        version: "1",
        os: bind.os,
        osVersion: bind.osVersion || null,
        osExtras: bind.osExtras || {},
        type: "os",
        data: bind.rows
      };
    }

    // 3) mDNS → Apple (service/hostname/TXT evidence + address tie)
    const mdns = inferFromMdns(prior, host);
    if (mdns) {
      return {
        up: true,
        program: NAME,
        version: "1",
        os: mdns.os,
        osVersion: mdns.osVersion,
        osExtras: mdns.osExtras,
        type: "os",
        data: mdns.rows
      };
    }

    // 4) Fallback: use any plugin-provided OS labels (Ping/FTP/etc.)
    const fb = fallbackFromPluginOs(prior);
    if (fb) {
      return {
        up: true,
        program: NAME,
        version: "1",
        os: fb.os || "Unknown",
        osVersion: null,
        osExtras: {},
        type: "os",
        data: fb.rows
      };
    }

    // Nothing conclusive
    return {
      up: true,
      program: NAME,
      version: "1",
      os: "Unknown",
      osVersion: null,
      osExtras: {},
      type: "os",
      data: [evidenceRow("No decisive OS evidence")]
    };
  }
};