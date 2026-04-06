// plugins/result_concluder.mjs — plug-and-play dispatcher with full metadata and evidence
import { normalizeService, upsertService, keyOf } from '../utils/conclusion_utils.mjs';

function pickResultsFromArgs(args) {
  if (Array.isArray(args[0])) return args[0];
  if (args.length >= 3 && args[2] && Array.isArray(args[2].results)) return args[2].results;
  if (args.length === 1 && args[0] && Array.isArray(args[0].results)) return args[0].results;
  return [];
}

// Stable slug from plugin name, falling back to IDs
function slugify(name, id) {
  const base = String(name || '').toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_+|_+$/g, '');
  if (base) return base;
  const map = { '001':'ping_checker','002':'ssh_scanner','003':'port_scanner','004':'ftp_banner_check','005':'host_up_check','006':'http_probe','007':'snmp_scanner','009':'dns_scanner','010':'webapp_detector','011':'tls_scanner','012':'opensearch_scanner','013':'os_detector','014':'netbios__smb_scanner','015':'sunrpc_scanner','020':'cloud_aws','021':'cloud_gcp','022':'cloud_azure','024':'syn_scanner','025':'db_scanner','026':'arp_scanner','027':'mdns_scanner','028':'upnp_scanner' };
  return map[String(id)] || String(id);
}

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

    for (const r of results) {
      const name = r?.name || r?.id || 'plugin';
      const slug = slugify(name, r?.id);
      const modPath = `./${slug}.mjs`;

      // Prefer OS and osVersion provided by plugins, but pick the most specific; OS Detector wins ties
      if (r?.result?.os) {
        const picked = pickOs(os, osVersion, r.result.os, r.result.osVersion, String(r?.id || r?.name), osSource);
        os = picked.os;
        osVersion = picked.osVersion;
        osSource = picked.source;
      }

      // Extract host name from UPnP Scanner if available
      if (slug === 'upnp_scanner') {
        hostName = extractHostNameFromUpnp(r?.result) || hostName;
      }

      // Extract host name from mDNS Scanner if available
      if (slug === 'mdns_scanner') {
        hostName = extractHostNameFromMdns(r?.result) || hostName;
      }

      let recs = null;
      try {
        const mod = await import(modPath);
        if (typeof mod.conclude === 'function') {
          recs = await mod.conclude({ host: typeof args[0] === 'string' ? args[0] : undefined, result: r?.result });
          const authSet = mod?.authoritativePorts instanceof Set ? mod.authoritativePorts : null;
          for (const item of (recs || [])) {
            const rec = normalizeService({ ...item, source: item.source || slug });
            const key = keyOf(rec);
            const authoritative = (authSet && authSet.has(key)) || !!item.authoritative;
            upsertService(services, rec, { authoritative });
          }
          if (r?.result?.data) pushEvidence(name, r.result.data);
          continue;
        }
      } catch {
        // no adapter -> fall through
      }
      for (const item of fallbackRecord(name, r?.result)) {
        upsertService(services, normalizeService(item), { authoritative: false });
      }
      if (r?.result?.data) pushEvidence(name, r.result.data);
    }

    for (const svc of services) delete svc.__authoritative;

    services.sort((a,b)=> (a.port - b.port) || String(a.protocol).localeCompare(String(b.protocol)) );

    // Separate meta/non-service entries from real services
    const META_PROTOCOLS = new Set(['assessment', 'icmp', 'os-detector', 'arp']);
    const PORT_ZERO_META_PROTOCOLS = new Set(['api', 'tcp', 'udp']);
    const isMetaEntry = (s) => {
      if (META_PROTOCOLS.has(s.protocol)) return true;
      if (s.port === 0 && PORT_ZERO_META_PROTOCOLS.has(s.protocol)) return true;
      if (s.info && /Skipped:/i.test(String(s.info))) return true;
      return false;
    };

    const metaEntries = services.filter(isMetaEntry);
    const realServices = services.filter(s => !isMetaEntry(s));

    // Move meta entries into evidence only
    for (const m of metaEntries) {
      evidence.push({
        from: m.source || 'meta',
        protocol: m.protocol,
        port: m.port,
        status: m.status,
        info: m.info,
        ...(m.banner ? { banner: m.banner } : {}),
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
    parts.push(hostUp ? `Host${hostName ? ` (${hostName})` : ''} is UP` : 'Host appears DOWN');
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