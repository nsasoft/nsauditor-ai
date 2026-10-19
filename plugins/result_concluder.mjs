// plugins/result_concluder.mjs — plug-and-play dispatcher with full metadata and evidence
import { readdir } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { normalizeService, upsertService, attachUnidentified, keyOf } from '../utils/conclusion_utils.mjs';

function pickResultsFromArgs(args) {
  if (Array.isArray(args[0])) return args[0];
  if (args.length >= 3 && args[2] && Array.isArray(args[2].results)) return args[2].results;
  if (args.length === 1 && args[0] && Array.isArray(args[0].results)) return args[0].results;
  return [];
}

// The second argument (or opts.adapters in the (host, port, { results }) form) may carry the PluginManager's adapter
// registry: a Map (or plain object) from plugin id to { conclude, authoritativePorts, cloudProvider }.
function pickOptsFromArgs(args) {
  if (Array.isArray(args[0]) && args[1] && typeof args[1] === 'object') return args[1];
  if (args.length >= 3 && args[2] && typeof args[2] === 'object') return args[2];
  if (args.length === 1 && args[0] && typeof args[0] === 'object' && !Array.isArray(args[0])) return args[0];
  return {};
}

// A plugin name as a label — the default `source` of an adapter record that names none. It no longer RESOLVES
// anything: until 1.3.0 the concluder imported `./<this slug>.mjs` and read only a named `conclude`, so 014 and 024
// (slug ≠ file name) and 040 / 050 / 060 (conclude on the default object) were never reached.
function nameSlug(name) {
  return String(name || 'plugin').toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_+|_+$/g, '') || 'plugin';
}

/** One adapter-registry entry from a plugin module: `conclude` named or on the default object, by plugin ID. */
function adapterEntry(mod) {
  const p = mod?.default;
  if (!p || typeof p !== 'object' || p.id == null) return null;
  const conclude = typeof mod.conclude === 'function' ? mod.conclude
    : (typeof p.conclude === 'function' ? p.conclude.bind(p) : null);
  return {
    id: String(p.id),
    name: typeof p.name === 'string' ? p.name : null,
    conclude,
    authoritativePorts: mod.authoritativePorts ?? p.authoritativePorts ?? null,
    cloudProvider: p.cloudProvider ?? null,
  };
}

// The concluder's own directory as a registry, built once — used for any id the caller's registry does not carry
// (a direct concluder.run, or a test manager with injected plugins).
const SELF = fileURLToPath(import.meta.url);
let ownRegistry = null;
function ownDirectoryAdapters() {
  ownRegistry ??= (async () => {
    const map = new Map();
    let names = [];
    try { names = (await readdir(path.dirname(SELF))).filter((f) => f.endsWith('.mjs')).sort(); } catch { return map; }
    for (const f of names) {
      if (f === path.basename(SELF)) continue;
      try {
        const e = adapterEntry(await import(pathToFileURL(path.join(path.dirname(SELF), f)).href));
        if (e && !map.has(e.id)) map.set(e.id, e);
      } catch { /* a plugin that fails to load has no adapter here */ }
    }
    return map;
  })();
  return ownRegistry;
}

/** The concluder's own adapter registry, exactly as it consults it — for the 4(b) census, which derives every adapter from it. */
export const _ownDirectoryAdapters = () => ownDirectoryAdapters();

function toRegistry(adapters) {
  if (adapters instanceof Map) return adapters;
  if (adapters && typeof adapters === 'object') return new Map(Object.entries(adapters));
  return new Map();
}

// A result with NO id (some callers pass names only) resolves by the plugin's DECLARED name — never by a file name
// derived from it, which is what left 014 / 024 unreached.
function byDeclaredName(registry) {
  const out = new Map();
  for (const e of registry.values()) {
    const n = typeof e?.name === 'string' ? e.name.trim().toLowerCase() : '';
    if (n && !out.has(n)) out.set(n, e);
  }
  return out;
}

// Adapter payloads that travel under a namespace. A record without a positive port is evidence, not a service row,
// and these ride along onto its evidence entry so moving it there loses nothing.
export const ADAPTER_PAYLOAD_KEYS = ['certAudit', 'tribeHealth', 'dnsSecurity'];

function scoreOsLabel(label) {
  const s = String(label||'').toLowerCase();
  if (!s || s === 'unknown') return 0;
  if (/red\s*hat|centos|rhel/.test(s)) return 120;
  if (/ubuntu|debian/.test(s)) return 110;
  if (/suse|opensuse|alpine/.test(s)) return 105;
  if (/freebsd|openbsd|netbsd/.test(s)) return 104;
  if (/solaris|aix|hp-ux/.test(s)) return 103;
  if (/windows/.test(s)) return 100;
  if (/macos|os\s*x|ios|apple/.test(s)) return 95;
  if (/linux/.test(s)) return 20;
  return 10;
}

function pickOs(currentOs, currentVersion, candidateOs, candidateVersion, source, curSource) {
  if (!candidateOs || candidateOs === 'Unknown') return { os: currentOs, osVersion: currentVersion, source: curSource };
  if (!currentOs || currentOs === 'Unknown') return { os: candidateOs, osVersion: candidateVersion, source };
  const cScore = scoreOsLabel(currentOs);
  const nScore = scoreOsLabel(candidateOs);
  if (nScore > cScore) return { os: candidateOs, osVersion: candidateVersion, source };
  if (nScore === cScore) {
    if (String(candidateOs).length > String(currentOs).length) return { os: candidateOs, osVersion: candidateVersion, source };
    const candIsDetector = /(^013$)|os\s*detector/i.test(String(source||''));
    const curIsDetector  = /(^013$)|os\s*detector/i.test(String(curSource||''));
    if (candIsDetector && !curIsDetector) return { os: candidateOs, osVersion: candidateVersion, source };
  }
  return { os: currentOs, osVersion: currentVersion, source: curSource };
}

// Generic fallback when a plugin provides no adapter
function fallbackRecord(pluginName, result) {
  const rows = Array.isArray(result?.data) ? result.data : [];
  const row = rows.find(Boolean) || {};
  const proto = row?.probe_protocol || result?.protocol || 'tcp';
  const port = Number(row?.probe_port ?? (
    /ftp/i.test(pluginName) ? 21 :
    /ssh/i.test(pluginName) ? 22 :
    /dns/i.test(pluginName) ? 53 :
    /snmp/i.test(pluginName) ? 161 :
    result?.port ?? 0
  ));
  let status = result?.up ? 'open' : 'unknown';

  // Re-label ECONNREFUSED as closed (requested feature)
  if (row?.probe_info && /refused|ECONNREFUSED/i.test(String(row.probe_info))) {
    status = 'closed';
  }

  return [{
    port, protocol: proto, service: (pluginName || 'unknown').toLowerCase().split(/\s+/)[0],
    program: result?.program || 'Unknown', version: result?.version || 'Unknown',
    status,
    info: row?.probe_info || null, banner: row?.response_banner || null,
    source: (pluginName || 'plugin').toLowerCase().split(/\s+/)[0],
    evidence: rows
  }];
}

function extractHostNameFromUpnp(result) {
  const rows = Array.isArray(result?.data) ? result.data : [];
  for (const row of rows) {
    const banner = row?.response_banner;
    if (banner) {
      try {
        const obj = JSON.parse(banner);
        const xml = obj?.descriptionXML || '';
        const match = xml.match(/<friendlyName>(.*?)<\/friendlyName>/);
        if (match && match[1]) {
          return match[1];
        }
      } catch {}
    }
  }
  return null;
}

function extractHostNameFromMdns(result) {
  const rows = Array.isArray(result?.data) ? result.data : [];
  for (const row of rows) {
    let name = null;
    const banner = row?.response_banner;
    if (banner) {
      try {
        const obj = JSON.parse(banner);
        // 1. Prefer txt.fn (friendly name)
        if (obj?.txt?.fn) return obj.txt.fn;
        // 2. Fallback to txt.md (model description)
        if (obj?.txt?.md) return obj.txt.md;
        // 3. Fallback to name field in banner JSON
        if (obj?.name) return obj.name;
        // 4. Fallback to fullname
        const fullname = obj?.fullname || '';
        const nameMatch = fullname.match(/[^._]+/);
        if (nameMatch && nameMatch[0]) return nameMatch[0];
      } catch (e) {
        // ignore JSON parse error
      }
    }
    // 5. Always check probe_info for name="..." if not found above
    if (row?.probe_info) {
      const m = row.probe_info.match(/name="([^"]+)"/);
      if (m && m[1]) return m[1];
    }
  }
  return null;
}

export default {
  id: "008",
  name: "Result Concluder",
  description: "Aggregates plugin results and produces a unified summary, host OS, and per-service findings.",
  priority: 100000,
  requirements: {},
  runStrategy: "single",

  async run(...args) {
    const results = pickResultsFromArgs(args);
    const supplied = toRegistry(pickOptsFromArgs(args).adapters);
    const own = await ownDirectoryAdapters();
    const pendingAttach = [];
    // ── 4(b), EE 2.0.0 / Community 1.0.0 — ON TCP, AUTHORITY NEEDS IDENTIFICATION ──────────────────────────────────────
    // An authoritative row (an adapter's authoritativePorts, or its own `authoritative: true`) says what a port IS, and its
    // `status` is the contract: 'open' means the adapter saw a protocol-specific response; every other status — closed,
    // unknown, filtered, a timeout policy's word — is NON-identification. On TCP an unidentified authoritative row used to be
    // pushed as a new service (tls_scanner's refused 465/563/993/995, OpenSearch's 5601/9200 — 492 rows across the
    // evidence tree) or to replace the identity of an open one. Now it never creates a service and never re-identifies one:
    // it is decided after every result is in, so result order does not matter — onto a service that exists it adds
    // evidence and fills blanks other than identity (attachUnidentified); where none exists it goes to EVIDENCE with its
    // reason. UDP rows are untouched, a DECLARED LIMIT: a UDP non-answer is open|filtered by the protocol, and the delta's
    // UDP measurement reads those rows (tasks/release-2.0.0/f4-phantom-rows-design.md).
    const psIndex = results.findIndex((r) => String(r?.id ?? '') === '003');
    const tcpClosed = new Set(psIndex >= 0 && Array.isArray(results[psIndex]?.result?.tcpClosed)
      ? results[psIndex].result.tcpClosed.map(Number) : []);
    const deferredUnidentified = [];
    const services = [];
    const evidence = [];
    let os = null;
    let osVersion = null;
    let osSource = null;
    let hostName = null;

    const pushEvidence = (from, rows) => {
      const max = Number(process.env.CONCLUDER_EVIDENCE_MAX || 200);
      for (const d of (Array.isArray(rows) ? rows : [])) {
        if (evidence.length >= max) break;
        const piece = {
          from: from || 'plugin',
          protocol: d?.probe_protocol ?? null,
          port: d?.probe_port ?? null,
          status: d?.status ?? null,
          info: d?.probe_info ?? null,
        };
        const banner = d?.response_banner;
        if (banner) {
          const s = String(banner);
          piece.banner = s.length > 800 ? s.slice(0, 800) + '…' : s;
        }
        evidence.push(piece);
      }
    };

    for (const [ri, r] of results.entries()) {
      const name = r?.name || r?.id || 'plugin';
      const id = String(r?.id ?? '');
      const slug = nameSlug(name);

      // Prefer OS and osVersion provided by plugins, but pick the most specific; OS Detector wins ties
      if (r?.result?.os) {
        const picked = pickOs(os, osVersion, r.result.os, r.result.osVersion, String(r?.id || r?.name), osSource);
        os = picked.os;
        osVersion = picked.osVersion;
        osSource = picked.source;
      }

      // Host names by plugin ID (they keyed on a name slug, and the UPnP one never matched: the plugin is named
      // "Enhanced UPnP Scanner").
      if (id === '028') {
        hostName = extractHostNameFromUpnp(r?.result) || hostName;
      }
      if (id === '027') {
        hostName = extractHostNameFromMdns(r?.result) || hostName;
      }

      // Resolve the adapter by ID: the caller's registry first, then this directory. A cloudProvider plugin is
      // EXEMPT — its findings travel raw (cloud_finding_summary / harvestCloudFindings), and through a service-record
      // adapter they carry no port and collapse into one fabricated row.
      const entry = id
        ? (supplied.get(id) ?? own.get(id))
        : (byDeclaredName(supplied).get(String(name).trim().toLowerCase())
          ?? byDeclaredName(own).get(String(name).trim().toLowerCase()));
      if (entry && typeof entry.conclude === 'function' && !entry.cloudProvider) {
        let recs = null;
        try {
          recs = await entry.conclude({ host: typeof args[0] === 'string' ? args[0] : undefined, result: r?.result });
        } catch {
          recs = null; // an adapter that throws falls through to the fallback record, as before
        }
        if (recs) {
          const authSet = entry.authoritativePorts instanceof Set ? entry.authoritativePorts : null;
          for (const item of recs) {
            const { attachOnly, ...rest } = item || {};
            const rec = normalizeService({ ...rest, source: rest.source || slug });
            const authoritative = (authSet && authSet.has(keyOf(rec))) || !!rest.authoritative;
            // An attach-only record (060's domain DNS-posture audit) lands only on a service a port-level probe
            // found; decided after every result is in, so result order does not matter.
            if (attachOnly) pendingAttach.push(rec);
            else if (authoritative && rec.protocol === 'tcp' && rec.status !== 'open') deferredUnidentified.push(rec);
            else if (authoritative && rec.protocol === 'tcp' && tcpClosed.has(rec.port)) {
              // IDENTIFIED on a port the port scanner measured closed (the architect seat's ruling): a protocol-specific
              // response cannot come from a closed port, and one refused connect is the weaker measurement (timing, rate
              // limiting, a service that came up between probes). It stays a SERVICE — the EE agents analyse only services,
              // so a diverted row is a row nobody analyses — and names both measurements. `resultsOrder` is the order in this
              // run's results: the plugin manager runs plugins one at a time by priority, so for a run it produced that is
              // the order of measurement; a caller-supplied array carries whatever order it was given.
              upsertService(services, { ...rec, measurementConflict: {
                portScanner: 'closed',
                adapter: 'open',
                adapterSource: rec.source,
                resultsOrder: psIndex < ri ? 'port-scanner-first' : 'adapter-first',
              } }, { authoritative });
            } else upsertService(services, rec, { authoritative });
          }
          if (r?.result?.data) pushEvidence(name, r.result.data);
          continue;
        }
      }
      for (const item of fallbackRecord(name, r?.result)) {
        const rec = normalizeService(item);
        // A fallback row identified nothing — no adapter read the plugin's result. On a TCP port the port scanner measured
        // closed it is decided with the deferred rows below: blanks other than identity on a service that exists, evidence
        // with its reason where none does. On any other port it is a non-authoritative service, as before.
        if (rec.protocol === 'tcp' && tcpClosed.has(rec.port)) deferredUnidentified.push(rec);
        else upsertService(services, rec, { authoritative: false });
      }
      if (r?.result?.data) pushEvidence(name, r.result.data);
    }

    // The deferred unidentified TCP rows — an authoritative row that did not identify its port, and a fallback row on a port
    // the port scanner measured closed: blanks other than identity on a service that exists, evidence with a reason where
    // none does.
    const notConcluded = [];
    for (const rec of deferredUnidentified) {
      if (!attachUnidentified(services, rec)) {
        notConcluded.push({ ...rec, reason: tcpClosed.has(rec.port)
          ? 'port measured closed by the port scanner (003)' : `not identified by its adapter (status ${rec.status})` });
      }
    }

    const unattached = [];
    for (const rec of pendingAttach) {
      if (services.some((s) => keyOf(s) === keyOf(rec))) upsertService(services, rec, { authoritative: false });
      else unattached.push(rec);
    }

    for (const svc of services) delete svc.__authoritative;

    services.sort((a,b)=> (a.port - b.port) || String(a.protocol).localeCompare(String(b.protocol)) );

    // Separate meta/non-service entries from real services
    const META_PROTOCOLS = new Set(['assessment', 'icmp', 'os-detector', 'arp']);
    const PORT_ZERO_META_PROTOCOLS = new Set(['api', 'tcp', 'udp']);
    const isMetaEntry = (s) => {
      // A service has a port. A record without a positive integer one (no port at all keys to `<proto>:NaN`) is
      // evidence — 040's "no TLS found", 060's per-domain findings — never a service row with port null.
      if (!(Number.isInteger(s.port) && s.port > 0)) return true;
      if (META_PROTOCOLS.has(s.protocol)) return true;
      if (s.port === 0 && PORT_ZERO_META_PROTOCOLS.has(s.protocol)) return true;
      if (s.info && /Skipped:/i.test(String(s.info))) return true;
      return false;
    };

    const metaEntries = services.filter(isMetaEntry).concat(unattached, notConcluded);
    const realServices = services.filter(s => !isMetaEntry(s));

    // Move meta entries into evidence only — with any namespaced adapter payload, so nothing is lost on the way
    for (const m of metaEntries) {
      evidence.push({
        from: m.source || 'meta',
        protocol: m.protocol,
        port: Number.isFinite(m.port) ? m.port : null,
        status: m.status,
        info: m.info,
        ...(m.banner ? { banner: m.banner } : {}),
        ...(m.reason ? { reason: m.reason } : {}),
        ...Object.fromEntries(ADAPTER_PAYLOAD_KEYS.filter((k) => m[k] != null).map((k) => [k, m[k]])),
      });
    }

    // Replace services array contents with real services only
    services.length = 0;
    services.push(...realServices);

    if (!os) {
      const banners = services.flatMap(s => [s.banner, s.info, s.program]).filter(Boolean).join(' ').toLowerCase();
      if (/vsftpd|pure-?ftpd|bftpd/.test(banners)) os = 'Linux';
      else if (/filezilla|windows/.test(banners)) os = 'Windows';
      else if (/apple|macos|mac\s*os|os\s*x/.test(banners)) os = 'macOS';
      else os = null;
    }

    const hostUp = results.some(r => r?.result?.up === true) || services.some(s => s.status === 'open');
    const open = services.filter(s => s.status === 'open');
    const parts = [];
    // Not UP means no probe got an answer — no evidence either way, never "DOWN" (1.3.0 lane 1 F).
    parts.push(hostUp ? `Host${hostName ? ` (${hostName})` : ''} is UP` : 'No evidence the host is up');
    if (os) parts.push(`OS: ${os}`);
    if (osVersion) parts.push(`Version: ${osVersion}`);
    if (open.length) {
      const top = open.slice(0, 3).map(s => `${s.service}/${s.port}`).join(', ');
      const more = open.length > 3 ? ` (+${open.length - 3} more open)` : '';
      parts.push(`Open: ${top}${more}`);
    } else {
      parts.push('No open services detected');
    }

    return {
      summary: parts.join(' — '),
      host: { up: hostUp, os, osVersion, name: hostName },
      services,
      evidence,
      source_count: results.length,
      os_source: osSource || null
    };
  }
};