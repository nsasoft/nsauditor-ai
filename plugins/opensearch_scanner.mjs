
// plugins/opensearch_scanner.mjs
// OpenSearch Scanner — probes OpenSearch HTTP API ports and extracts version,
// plus (heuristically) Linux kernel and Node.js versions if present in banners.
//
// CHANGE: Default ports now only include 9200 (API) and 5601 (Dashboards).
// Previously 80/443 were included, which produced noisy entries in reports.
// You can still add 80/443 (or any others) via OPENSEARCH_SCANNER_PORTS.
//
// Env vars:
//   OPENSEARCH_SCANNER_TIMEOUT_MS    default 6000
//   OPENSEARCH_SCANNER_PORTS         CSV of port[:service] (default "9200:opensearch,5601:opensearch-dashboards")
//   OPENSEARCH_SCANNER_SCHEMES       CSV of schemes to try per HTTP port (default "http,https")
//   OPENSEARCH_SCANNER_INSECURE_TLS  1/true to skip TLS verification for HTTPS
//   OPENSEARCH_SCANNER_DEBUG         1/true to include extra debug info in banner
//   OPENSEARCH_SCANNER_INCLUDE_TRANSPORT 1/true to also probe 9300 (transport, not HTTP)
//
// Notes:
// - We attempt HTTP(S) GET / on HTTP ports. 9300 (transport) is not HTTP —
//   it's optional and only recorded as "transport port (not HTTP)" if enabled.
// - Version is read from JSON.version.number when available.
// - OS + Node.js versions are parsed from any banner/header that contains the
//   opensearch-js UA format.
// - We record response headers and body (truncated) for Evidence.

const DEFAULT_PORTS = {
  9200: 'opensearch',
  5601: 'opensearch-dashboards',
};

function parseCsvEnv(name, fallback) {
  const v = process.env[name];
  if (!v) return fallback;
  const arr = String(v).split(',').map(s => s.trim()).filter(Boolean);
  return arr.length ? arr : fallback;
}

function parsePortsEnv(name, fallback) {
  const v = process.env[name];
  if (!v) return fallback;
  const out = {};
  for (const tok of String(v).split(',').map(s => s.trim()).filter(Boolean)) {
    const [p, svc] = tok.split(':').map(s => s.trim());
    const n = Number(p);
    if (Number.isFinite(n)) out[n] = svc || (DEFAULT_PORTS[n] || `tcp-${n}`);
  }
  return Object.keys(out).length ? out : fallback;
}

// Use global fetch (Node 18+). If not present, dynamic import of node-fetch (only when needed).
async function getFetch() {
  if (typeof fetch === 'function') return fetch;
  const mod = await import('node-fetch');
  return mod.default || mod;
}

// Best effort: build a simple https.Agent that can ignore certs if requested.
// We avoid importing 'https' unless we need it.
async function buildAgentIfNeeded(scheme, insecure) {
  if (!insecure || scheme !== 'https') return undefined;
  const https = await import('node:https');
  return new https.Agent({ rejectUnauthorized: false });
}

function firstDefined(...xs) {
  for (const x of xs) if (x !== undefined && x !== null) return x;
  return undefined;
}

function normalizeUaBanner(str = '') {
  // Return { osKernel, nodeVersion, ua } if matches the opensearch-js UA shape
  const out = { osKernel: null, nodeVersion: null, ua: null };
  const s = String(str);
  const m = s.match(/opensearch-js\/[\d.]+\s*\(([^)]+)\)/i);
  if (!m) return out;
  out.ua = s;
  const inside = m[1]; // e.g., 'linux 6.19.14-linuxkit-x64; Node.js v20.10.0'
  const node = inside.match(/node\.js\s*v([\d.]+)/i);
  if (node) out.nodeVersion = node[1];
  const linux = inside.match(/linux\s*([^;]+)/i);
  if (linux) out.osKernel = linux[1].trim();
  return out;
}

function trunc(s, n = 1200) {
  const str = String(s || '');
  return str.length > n ? str.slice(0, n) + '…' : str;
}

export default {
  id: "012",
  name: "OpenSearch Scanner",
  description: "Detects OpenSearch and extracts version; heuristically parses Linux/Node.js versions from banners.",
  priority: 360,
  requirements: {},

  async run(host, _port, opts = {}) {
    const timeoutMs = Number(process.env.OPENSEARCH_SCANNER_TIMEOUT_MS || 6000);
    const portsMap = parsePortsEnv('OPENSEARCH_SCANNER_PORTS', { ...DEFAULT_PORTS });
    const includeTransport = /^(1|true|yes|on)$/i.test(String(process.env.OPENSEARCH_SCANNER_INCLUDE_TRANSPORT || ''));
    if (includeTransport && !('9300' in portsMap && portsMap[9300])) {
      portsMap[9300] = 'opensearch-transport';
    }
    const schemes = parseCsvEnv('OPENSEARCH_SCANNER_SCHEMES', ['http', 'https']);
    const insecure = /^(1|true|yes|on)$/i.test(String(process.env.OPENSEARCH_SCANNER_INSECURE_TLS || ''));
    const debug = /^(1|true|yes|on)$/i.test(String(process.env.OPENSEARCH_SCANNER_DEBUG || ''));
    const doFetch = await getFetch();

    const perPort = [];

    for (const [pStr, svc] of Object.entries(portsMap)) {
      const port = Number(pStr);
      if (port === 9300) {
        // Not HTTP; we just note transport port present if opted in
        perPort.push({
          port, service: svc, success: false, status: 'unknown', version: null,
          osKernel: null, nodeVersion: null, headers: {}, body: null, error: 'transport port (not HTTP)'
        });
        continue;
      }

      let success = false, pickedScheme = null, version = null, osKernel = null, nodeVersion = null;
      let headersRecord = {}, bodyStr = null, statusText = null, errMsg = null;

      for (const scheme of schemes) {
        const url = `${scheme}://${host}:${port}/`;
        try {
          const agent = await buildAgentIfNeeded(scheme, insecure);
          const ctrl = new AbortController();
          const to = setTimeout(() => ctrl.abort(), timeoutMs);
          const res = await doFetch(url, {
            method: 'GET',
            headers: {
              'User-Agent': 'opensearch-js/3.4.0 (opensearch-scanner)'
            },
            signal: ctrl.signal,
            agent
          }).catch(e => { throw e; });
          clearTimeout(to);

          statusText = `${res.status}`;
          // Record headers into a plain object
          headersRecord = {};
          try {
            for (const [k, v] of res.headers) headersRecord[k.toLowerCase()] = String(v);
          } catch {}

          // Try JSON first
          let parsed = null;
          try {
            const ct = headersRecord['content-type'] || '';
            if (/json/i.test(ct)) {
              parsed = await res.json();
              bodyStr = trunc(JSON.stringify(parsed));
            } else {
              // fallback to text (may include hint)
              const t = await res.text();
              bodyStr = trunc(t);
              try { parsed = JSON.parse(t); } catch {}
            }
          } catch {
            // ignore parse errors
          }

          version = firstDefined(parsed?.version?.number, parsed?.version?.distribution === 'opensearch' ? parsed?.version?.number : null, null);

          // Heuristic UA extraction: look for opensearch-js UA within *any* bannerish header
          const bannerish = headersRecord['server'] || headersRecord['x-powered-by'] || headersRecord['user-agent'] || '';
          const uaBits = normalizeUaBanner(bannerish);
          osKernel = uaBits.osKernel || null;
          nodeVersion = uaBits.nodeVersion || null;

          // Some proxies echo request headers back; try to read from body if present
          if (!osKernel && bodyStr && /opensearch-js\//i.test(bodyStr)) {
            const uaBody = normalizeUaBanner(bodyStr);
            osKernel = uaBody.osKernel || osKernel;
            nodeVersion = uaBody.nodeVersion || nodeVersion;
          }

          success = !!(version || bodyStr || Object.keys(headersRecord).length);
          pickedScheme = scheme;
          break; // stop after first scheme that returns
        } catch (e) {
          errMsg = e && e.message ? String(e.message) : 'fetch error';
          // Try next scheme
        }
      }

      perPort.push({
        port,
        service: svc,
        scheme: pickedScheme,
        success,
        status: success ? 'open' : 'unknown',
        version: version || null,
        osKernel,
        nodeVersion,
        headers: headersRecord,
        body: bodyStr,
        error: success ? null : (errMsg || statusText || null)
      });
    }

    // Build data rows for evidence
    const data = perPort.map(r => {
      const bits = [];
      if (r.version) bits.push(`OpenSearch: ${r.version}`);
      if (r.osKernel) bits.push(`Linux: ${r.osKernel}`);
      if (r.nodeVersion) bits.push(`Node.js: v${r.nodeVersion}`);
      const probe_info = bits.join(' | ') || (r.error ? `No banner (${r.error})` : 'No banner');
      const bannerObj = {
        headers: r.headers,
        body: r.body,
        scheme: r.scheme,
        debug: debug ? { error: r.error } : undefined
      };
      return {
        probe_protocol: 'tcp',
        probe_port: r.port,
        probe_service: r.service,
        probe_info,
        response_banner: JSON.stringify(bannerObj)
      };
    });

    const up = perPort.some(r => r.success);

    // Prefer the clearest program/version at the root API port (9200) if present
    const root = perPort.find(r => r.port === 9200 && r.version);
    const program = root ? 'OpenSearch' : (up ? 'OpenSearch (suspected)' : 'Unknown');
    const version = root ? root.version : null;

    return {
      up,
      program,
      version,
      os: null,           // not authoritative; let concluder infer from other sources
      osVersion: null,
      data
    };
  }
};

// ---------------- Plug-and-Play concluder adapter ----------------
import { statusFrom } from '../utils/conclusion_utils.mjs';

export async function conclude({ host, result }) {
  const rows = Array.isArray(result?.data) ? result.data : [];
  const items = [];
  for (const r of rows) {
    const port = Number(r?.probe_port);
    if (!Number.isFinite(port)) continue;
    // Prefer the probe_service we set in run()
    const svc = r?.probe_service || (port === 9200 ? 'opensearch' : (port === 5601 ? 'opensearch-dashboards' : 'opensearch'));
    const info = r?.probe_info || null;
    const banner = r?.response_banner || null;
    const status = /OpenSearch:\s*\d+/.test(String(info||'')) ? 'open' : 'unknown';
    items.push({
      port,
      protocol: 'tcp',
      service: svc,
      program: 'OpenSearch',
      version: null, // per-port version is often same; leave null unless per-port differs
      status,
      info,
      banner,
      source: 'opensearch-scanner',
      evidence: rows,
      authoritative: true
    });
  }
  return items;
}

// Authoritative for standard HTTP API / dashboards ports
export const authoritativePorts = new Set(['tcp:9200','tcp:5601']);
