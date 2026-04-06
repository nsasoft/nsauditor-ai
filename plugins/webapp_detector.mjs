// plugins/webapp_detector.mjs
// New plugin: Webapp Detector
// Uses `simple-wappalyzer` to fingerprint web applications present on a host.
// Tries HTTPS first (port 443), then HTTP (port 80), and can also try custom ports via opts.ports.
// NOTE: Unlike http_probe, undici/fetch cannot ignore TLS easily per-request, so self-signed
// HTTPS will usually fail and the plugin will fall back to HTTP.
//
// Add to package.json (dependencies):
//   "simple-wappalyzer": "^1.14.0"   // or latest
//
// Example use (plugin manager):
//   webappDetector.run("192.168.1.1")
//
// Result shape example:
// {
//   up: true,
//   program: "WordPress + Nginx",
//   version: "Unknown",
//   os: null,
//   type: "webapp",
//   data: [
//     {
//       probe_protocol: "https",
//       probe_port: 443,
//       probe_info: "Detected web apps: WordPress, Nginx",
//       response_banner: "200 OK\r\nserver: nginx\r\nx-powered-by: PHP/8.2"
//     }
//   ],
//   apps: [ { name, categories, confidence, version?, slug, ... }, ... ]
// }

import wappalyzer from 'simple-wappalyzer';

const DEBUG =
  String(process.env.DEBUG_MODE || '').toLowerCase() === '1' ||
  String(process.env.DEBUG_MODE || '').toLowerCase() === 'true';

function log(...args) {
  if (DEBUG) console.log('[webapp-detector]', ...args);
}

function parseExtraHeaders() {
  try {
    if (!process.env.HTTP_EXTRA_HEADERS) return {};
    const h = JSON.parse(process.env.HTTP_EXTRA_HEADERS);
    return h && typeof h === 'object' ? h : {};
  } catch {
    return {};
  }
}

function buildBanner(statusCode, headers) {
  const lines = [];
  const statusLine = `${statusCode || 0}`;
  lines.push(statusLine + (headers['status-message'] ? ' ' + headers['status-message'] : ''));
  const pick = ['server', 'x-powered-by', 'www-authenticate', 'content-type', 'location', 'set-cookie'];
  for (const k of pick) {
    const v = headers[k];
    if (!v) continue;
    if (Array.isArray(v)) {
      for (const vv of v) lines.push(`${k}: ${vv}`);
    } else {
      lines.push(`${k}: ${v}`);
    }
  }
  return lines.join('\\r\\n');
}

function normalizeTarget(target) {
  if (!target) return null;
  if (typeof target === 'string') return target.replace(/^https?:\/\//i, '').split('/')[0];
  return (target.host || target.hostname || target.name || '').replace(/^https?:\/\//i, '').split('/')[0];
}

async function fetchOnce(url, signal) {
  const extra = parseExtraHeaders();
  const headers = {
    'User-Agent': 'Mozilla/5.0 (compatible; NetworkSecurityAuditor/1.18.0; +https://example.invalid)',
    DNT: '1',
    ...extra,
  };
  // global fetch (undici) is available in Node >=18
  const res = await fetch(url, { redirect: 'follow', headers, signal });
  const finalUrl = res.url || url;
  const statusCode = res.status;
  const rawHeaders = {};
  res.headers.forEach((v, k) => (rawHeaders[k.toLowerCase()] = v));
  const html = await res.text();
  return { url: finalUrl, statusCode, headers: rawHeaders, html };
}

async function tryDetectAt(url) {
  const ctrl = new AbortController();
  const timeoutMs = Number(process.env.WAPPALYZER_TIMEOUT_MS || 15000);
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    log('fetch start —', url);
    const { url: finalUrl, html, statusCode, headers } = await fetchOnce(url, ctrl.signal);
    log('fetch end —', finalUrl, statusCode, `html=${html?.length ?? 0}`);
    const apps = await detectFromHtml(finalUrl, html, statusCode, headers);
    return { ok: true, finalUrl, statusCode, headers, apps };
  } catch (e) {
    log('fetch error —', url, e?.message || e);
    return { ok: false, error: e };
  } finally {
    clearTimeout(t);
  }
}

/** Run wappalyzer on provided HTML/headers. */
async function detectFromHtml(url, html, statusCode, headers) {
  try {
    const result = await wappalyzer({ url, html, statusCode, headers });
    if (Array.isArray(result) && result.length) {
      log('wappalyzer apps=', result.map(a => a.name).join(', '));
    } else {
      log('wappalyzer apps=∅');
    }
    return result || [];
  } catch (e) {
    log('wappalyzer error:', e?.message || e);
    return [];
  }
}

function summarizeApps(apps) {
  if (!Array.isArray(apps) || !apps.length) return { program: null, version: 'Unknown', list: [] };
  // Sort by confidence descending then name
  const sorted = [...apps].sort((a, b) => (Number(b.confidence||0) - Number(a.confidence||0)) || String(a.name).localeCompare(String(b.name)));
  const names = sorted.map(a => a.name).filter(Boolean);
  const program = names.slice(0, 3).join(' + ') || null;
  // If exactly 1 app and it has a version, expose it
  const version = (sorted.length === 1 && sorted[0]?.version) ? String(sorted[0].version) : 'Unknown';
  return { program, version, list: names };
}

export default {
  id: '010',
  name: 'Webapp Detector',
  description: 'Identifies web applications and frameworks using simple-wappalyzer (tries HTTPS then HTTP).',
  priority: 55, // run near HTTP probe
  requirements: { host: 'up', tcp_open: [80, 443] }, // heuristic gate; still attempts both
  protocols: ['tcp'],
  ports: [80, 443],

  /**
   * @param {string} host - target hostname or IP
   * @param {number} port - optional hint (ignored; detection tries 443 then 80 unless opts.ports provided)
   * @param {object} opts - options: { ports?: number[] }
   */
  async run(host, port = 0, opts = {}) {
    const result = {
      up: false,
      program: null,
      version: 'Unknown',
      os: null,
      type: 'webapp',
      data: [],
      apps: [], // raw simple-wappalyzer results
    };

    let target = normalizeTarget(host);
    if (!target) return result;

    // Build candidate URLs
    const set = new Set();
    const addUrl = (proto, p) => {
      const defaultPort = (proto === 'https' ? 443 : 80);
      const portPart = (p && p !== defaultPort) ? `:${p}` : '';
      set.add(`${proto}://${target}${portPart}/`);
    };

    // If specific ports given, try both schemes for each; else default to 443 then 80
    const ports = Array.isArray(opts.ports) && opts.ports.length ? opts.ports : [443, 80];
    for (const p of ports) {
      if (p === 443) addUrl('https', 443);
      else if (p === 80) addUrl('http', 80);
      else { addUrl('https', p); addUrl('http', p); }
    }

    // Try in order added (prefers https:443, then http:80, then customs)
    for (const url of set) {
      const r = await tryDetectAt(url);
      if (r.ok) {
        result.up = true;
        result.apps = r.apps || [];
        const { program, version, list } = summarizeApps(result.apps);
        if (program) result.program = program;
        if (version) result.version = version;

        // Prepare a concise banner
        const proto = url.startsWith('https:') ? 'https' : 'http';
        const portFromUrl = (() => {
          try {
            const u = new URL(url);
            return Number(u.port || (u.protocol === 'https:' ? 443 : 80));
          } catch { return proto === 'https' ? 443 : 80; }
        })();

        result.data.push({
          probe_protocol: proto,
          probe_port: portFromUrl,
          probe_info: list.length ? `Detected web apps: ${list.join(', ')}` : `HTTP service detected (status ${r.statusCode})`,
          response_banner: buildBanner(r.statusCode, r.headers),
        });

        // Stop after first successful detection
        break;
      } else {
        // Log error row for visibility
        const proto = url.startsWith('https:') ? 'https' : 'http';
        const portFromUrl = (() => {
          try { const u = new URL(url); return Number(u.port || (u.protocol === 'https:' ? 443 : 80)); } catch { return proto === 'https' ? 443 : 80; }
        })();
        result.data.push({
          probe_protocol: proto,
          probe_port: portFromUrl,
          probe_info: `Webapp detect error: ${r.error?.message || String(r.error || 'unknown error')}`,
          response_banner: null,
        });
      }
    }

    return result;
  },
};

// This plugin enriches HTTP/HTTPS program names with detected apps.
// As a concluder adapter, it returns NO direct services; enrichment will be done upstream if desired.
export async function conclude({ host, result }) {
  return [];
}
