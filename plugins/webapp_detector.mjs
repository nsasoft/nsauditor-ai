// plugins/webapp_detector.mjs
// New plugin: Webapp Detector
// Uses the in-house zero-dep fingerprinter (utils/tech_fingerprint.mjs) to identify
// web applications present on a host.
// Tries https:443, then http:80, then each TCP port --ports adds (both schemes), and stops at the first that answers.
// THE REACH, stated: 010 runs only when TCP 80 or 443 is open; an added port is tried after https:443 and http:80 and
// only if neither answers (1.3.0 item 12 — the CLI's --ports string never reached this plugin before).
// NOTE: Unlike http_probe, undici/fetch cannot ignore TLS easily per-request, so self-signed
// HTTPS will usually fail and the plugin will fall back to HTTP.
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

import { fingerprint } from '../utils/tech_fingerprint.mjs';
import { canonicalIp, classifyAddress, resolveAndValidate, allowAllHosts } from '../utils/net_validation.mjs';
import { parsePortsSpec } from '../utils/ports_spec.mjs';

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

// 1.3.0 lane 2 (R2): redirects are followed HERE, one hop at a time, never by undici. The target chooses
// a hop, not the operator, and the scan-entry guard ran once, on the host the operator named — so with
// `redirect: 'follow'` a target could send the scanner to loopback or cloud metadata and have the
// answer's headers reflected into the result. A hop to the host the operator named (any port, http or
// https) was admitted at entry and is followed; any other host goes through the MCP guard's policy:
// loopback, link-local, metadata and unspecified refused in every configuration, private ranges only
// under NSA_ALLOW_ALL_HOSTS, a name refused if ANY of its answers is. Stated limit, as at entry: the
// checked name is resolved again by the request (no pin against rebinding).
const MAX_REDIRECT_HOPS = 5;

async function assertHopAllowed(next, entryHost) {
  if (next.protocol !== 'http:' && next.protocol !== 'https:') {
    throw new Error(`redirect to ${next.href} refused: only http and https hops are followed`);
  }
  const host = next.hostname.replace(/^\[|\]$/g, '');
  if (host.toLowerCase() === String(entryHost).replace(/^\[|\]$/g, '').toLowerCase()) return;
  const allowPrivate = allowAllHosts();
  if (canonicalIp(host)) {
    const cls = classifyAddress(host);
    if (cls === 'always' || (cls === 'private' && !allowPrivate)) {
      throw new Error(`redirect to ${host} refused by the SSRF guard (blocked address range)`);
    }
    return;
  }
  try {
    await resolveAndValidate(host, { allowPrivate });
  } catch (err) {
    throw new Error(`redirect to ${host} refused by the SSRF guard (${err.message})`);
  }
}

async function fetchOnce(url, signal) {
  const extra = parseExtraHeaders();
  const base = {
    'User-Agent': 'Mozilla/5.0 (compatible; NetworkSecurityAuditor/1.18.0; +https://example.invalid)',
    DNT: '1',
  };
  const entry = new URL(url);
  const entryHost = entry.hostname;
  // The operator's HTTP_EXTRA_HEADERS (where an Authorization or an API key goes) are for the origin the
  // operator named. Once a hop leaves that origin — another host, scheme or port — none of them is sent
  // again, even if the chain comes back. (undici's own follow drops only Authorization cross-origin.)
  let leftOrigin = false;
  let current = url;
  for (let hop = 0; ; hop++) {
    const headers = leftOrigin ? base : { ...base, ...extra };
    // global fetch (undici) is available in Node >=18
    const res = await fetch(current, { redirect: 'manual', headers, signal });
    const location = res.status >= 300 && res.status < 400 ? res.headers.get('location') : null;
    if (location) {
      if (hop >= MAX_REDIRECT_HOPS) {
        throw new Error(`redirect limit (${MAX_REDIRECT_HOPS} hops) reached at ${current}`);
      }
      const next = new URL(location, current);
      await assertHopAllowed(next, entryHost);
      if (next.origin !== entry.origin) leftOrigin = true;
      await res.body?.cancel?.().catch(() => {});
      current = next.href;
      continue;
    }
    const statusCode = res.status;
    const rawHeaders = {};
    res.headers.forEach((v, k) => (rawHeaders[k.toLowerCase()] = v));
    const html = await res.text();
    return { url: current, statusCode, headers: rawHeaders, html };
  }
}

/**
 * The TCP ports --ports adds, in every form a caller passes: the CLI's string ('8443,9090/udp'), an array, or
 * { tcp, udp }. One grammar with the port scanner (utils/ports_spec.mjs); a /udp entry adds no URL.
 */
export function addedTcpPorts(spec) {
  if (typeof spec === 'string') return parsePortsSpec(spec).tcp;
  if (Array.isArray(spec)) return parsePortsSpec(spec.join(',')).tcp;
  if (spec && typeof spec === 'object' && Array.isArray(spec.tcp)) return parsePortsSpec(spec.tcp.join(',')).tcp;
  return [];
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

/** Run in-house fingerprinter on provided HTML/headers. */
async function detectFromHtml(url, html, statusCode, headers) {
  try {
    const result = fingerprint({ url, html, statusCode, headers });
    if (Array.isArray(result) && result.length) {
      log('fingerprint apps=', result.map(a => a.name).join(', '));
    } else {
      log('fingerprint apps=∅');
    }
    return result || [];
  } catch (e) {
    log('fingerprint error:', e?.message || e);
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
  description: 'Identifies web applications and frameworks using the in-house fingerprinter (tries HTTPS then HTTP).',
  priority: 55, // run near HTTP probe
  requirements: { host: 'up', tcp_open: [80, 443] }, // heuristic gate; still attempts both
  protocols: ['tcp'],
  ports: [80, 443],

  /**
   * @param {string} host - target hostname or IP
   * @param {number} port - the port the manager dispatched (ignored: each run walks the whole candidate list — the double
   *   fetch when 80 and 443 are both open is boarded with the per-port dispatch)
   * @param {object} opts - options: { ports?: string | number[] | { tcp, udp } } — the CLI passes its --ports string
   */
  async run(host, port = 0, opts = {}) {
    const result = {
      up: false,
      program: null,
      version: 'Unknown',
      os: null,
      type: 'webapp',
      data: [],
      apps: [], // raw fingerprinter results
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

    // https:443 and http:80 first, then each TCP port --ports ADDS (both schemes) — never in place of the defaults.
    const ports = [443, 80, ...addedTcpPorts(opts.ports).filter((p) => p !== 443 && p !== 80)];
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

// Concluder adapter: emits detected apps as service records for result fusion.
export async function conclude({ host, result }) {
  if (!result?.up || !Array.isArray(result.apps) || result.apps.length === 0) return [];

  // Extract port from the first successful probe record
  const probeRecord = result.data?.find(d => d.probe_port && d.probe_port > 0);
  const port = probeRecord?.probe_port ?? 80;
  const protocol = probeRecord?.probe_protocol ?? 'tcp';

  // Emit one service record per detected app
  return result.apps.map(app => ({
    protocol,
    port,
    service: app.name ?? 'webapp',
    version: app.version ?? null,
    info: Array.isArray(app.categories) ? app.categories.join(', ') : 'webapp',
    authoritative: false,
  }));
}

export { detectFromHtml, summarizeApps };
