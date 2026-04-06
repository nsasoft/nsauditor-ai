// plugins/tls_scanner.mjs
// TLS Scanner — detects which TLS protocol versions a host supports on common TLS ports.
// Plug-and-play: includes conclude() so the Result Concluder auto-consumes it.
//
// Env vars:
//   TLS_SCANNER_TIMEOUT_MS   default 8000
//   TLS_SCANNER_VERSIONS     CSV (e.g., "TLSv1,TLSv1.1,TLSv1.2,TLSv1.3")
//   TLS_SCANNER_PORTS        CSV of ports to scan (defaults to common TLS ports below)
//   TLS_SCANNER_DEBUG        "1"/"true" to include per-version errors in data rows
//   TLS_SCANNER_SNI          optional explicit SNI/hostname for handshake
//   TLS_SCANNER_TLS_MODULE   module id/url for TLS API (for tests), default 'node:tls'
//
// Notes:
// - We do not rejectUnauthorized to allow protocol negotiation without CA trust.
// - We set minVersion==maxVersion to force a specific handshake version.
// - We capture the agreed protocol (e.g., "TLSv1.2") and a representative cipher name.

import dns from 'node:dns/promises';

// Lazy TLS import so tests can inject a stub module via TLS_SCANNER_TLS_MODULE
const TLS_MODULE_ID = process.env.TLS_SCANNER_TLS_MODULE || 'node:tls';
let __tlsMod;
async function loadTls() {
  if (!__tlsMod) {
    const m = await import(TLS_MODULE_ID);
    __tlsMod = m.default ?? m; // support default/named exports
  }
  return __tlsMod;
}

const DEFAULT_PORTS = {
  443: 'https',
  465: 'smtps',
  563: 'nntps',
  993: 'imaps',
  995: 'pop3s'
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

async function reverseHostname(ip) {
  try {
    const names = await dns.reverse(ip);
    return Array.isArray(names) && names.length ? names[0] : null;
  } catch {
    return null;
  }
}

export default {
  id: "011",
  name: "TLS Scanner",
  description: "Detects supported TLS protocol versions and ciphers on common TLS ports.",
  priority: 350,
  requirements: {},

  async run(host, _port, opts = {}) {
    const timeoutMs = Number(process.env.TLS_SCANNER_TIMEOUT_MS || 8000);
    const versions = parseCsvEnv('TLS_SCANNER_VERSIONS', ['TLSv1', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3']);
    const portsMap = parsePortsEnv('TLS_SCANNER_PORTS', { ...DEFAULT_PORTS });
    const debug = /^(1|true|yes|on)$/i.test(String(process.env.TLS_SCANNER_DEBUG || ''));
    const sni = process.env.TLS_SCANNER_SNI || null;
    const hostname = sni || (await reverseHostname(host)) || host;
    const tlsApi = await loadTls();

    async function checkOnePort(port, service) {
      const result = {
        ip: host,
        port,
        service,
        supportedVersions: [],
        ciphers: {},
        errors: [],
        isTLSService: false,
        supportsOld: false,
        hostname: hostname || null
      };

      const check = (version) => new Promise((resolve) => {
        let settled = false;
        const options = {
          host,
          port,
          servername: hostname,
          rejectUnauthorized: false,
          minVersion: version,
          maxVersion: version
        };
        const socket = tlsApi.connect(options, () => {
          if (settled) return;
          settled = true;
          const protocol = socket.getProtocol?.();
          const cipher = socket.getCipher?.();
          try { socket.end?.(); } catch {}
          resolve({ success: true, protocol, cipher: cipher ? cipher.name : 'Unknown' });
        });
        socket.setTimeout?.(timeoutMs);
        socket.on?.('timeout', () => {
          if (settled) return;
          settled = true;
          try { socket.destroy?.(); } catch {}
          resolve({ success: false, error: 'timeout' });
        });
        socket.on?.('error', (err) => {
          if (settled) return;
          settled = true;
          resolve({ success: false, error: err && err.message ? err.message : 'error' });
        });
      });

      for (const v of versions) {
        const res = await check(v);
        if (res.success) {
          const proto = res.protocol || v;
          result.supportedVersions.push(proto);
          result.ciphers[proto] = res.cipher;
        }
        if (debug) {
          result.errors.push({ version: v, success: !!res.success, error: res.success ? 'none' : res.error });
        }
      }

      result.isTLSService = result.supportedVersions.length > 0;
      result.supportsOld = result.supportedVersions.some(v => v === 'TLSv1' || v === 'TLSv1.1');

      return result;
    }

    const perPort = [];
    for (const [pStr, svc] of Object.entries(portsMap)) {
      const p = Number(pStr);
      try {
        const r = await checkOnePort(p, svc);
        perPort.push(r);
      } catch (e) {
        if (debug) perPort.push({ ip: host, port: p, service: svc, supportedVersions: [], ciphers: {}, errors: [{ error: String(e.message || e) }] });
      }
    }

    // Build raw result.data rows for Evidence + Concluder
    const data = perPort.map(r => {
      const infoBits = [];
      if (r.supportedVersions.length) infoBits.push(`TLS: ${r.supportedVersions.join(', ')}`);
      if (r.supportsOld) infoBits.push('OLD: yes');
      if (r.hostname && r.hostname !== r.ip) infoBits.push(`SNI: ${r.hostname}`);
      const probe_info = infoBits.join(' | ') || 'No TLS supported';
      const bannerObj = { ciphers: r.ciphers, debug: debug ? r.errors : undefined };
      return {
        probe_protocol: 'tcp',
        probe_port: r.port,
        probe_service: r.service,
        probe_info,
        response_banner: JSON.stringify(bannerObj)
      };
    });

    const up = perPort.some(r => r.isTLSService);

    return {
      up,
      program: 'TLS',
      version: null,
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
    const svc = r?.probe_service || ({ 443:'https', 465:'smtps', 563:'nntps', 993:'imaps', 995:'pop3s' }[port]) || 'tls';
    const info = r?.probe_info || null;
    const banner = r?.response_banner || null;
    const status = /TLS: /.test(String(info||'')) ? 'open' : 'closed';
    items.push({
      port,
      protocol: 'tcp',
      service: svc,
      program: 'TLS',
      version: null,
      status,
      info,
      banner,
      source: 'tls-scanner',
      evidence: [r],
      authoritative: true
    });
  }
  return items;
}

export const authoritativePorts = new Set(['tcp:443','tcp:465','tcp:563','tcp:993','tcp:995']);
