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

// Lazy TLS import — test injection allowed in non-production environments only.
// In production (NODE_ENV=production) only 'node:tls' is accepted.
const _rawTlsEnv = process.env.TLS_SCANNER_TLS_MODULE;
const TLS_MODULE_ID = (() => {
  if (!_rawTlsEnv) return 'node:tls';
  if (process.env.NODE_ENV === 'production') {
    console.warn('[tls_scanner] TLS_SCANNER_TLS_MODULE is ignored in production');
    return 'node:tls';
  }
  // In non-production (test/dev): allow any value for stub injection
  return _rawTlsEnv;
})();
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

// ── crypto_agent producer contract ──────────────────────────────────────────
// The EE crypto_agent (agents/crypto_agent.mjs) grades TLS quality off structured
// fields on each service record. Before this producer leg no CE plugin set them,
// so a real scan read clean over deprecated protocols / weak ciphers / expired /
// self-signed certs. We emit only public handshake facts (versions, cipher names,
// cert validity dates) — ZDE-safe, and only where a handshake was observed.
const WEAK_TLS_PROTOCOLS = new Set(['TLSv1', 'TLSv1.1', 'SSLv3', 'SSLv2']);

// Weak cipher name fragments — mirrors plugins/040_tls_cert_auditor.mjs.
const WEAK_CIPHER_FRAGMENTS = ['RC4', '3DES', 'DES', 'NULL', 'EXPORT', 'ADH', 'AECDH', 'ANON', 'SEED', 'IDEA', 'CAMELLIA128'];

// Cipher policy for the PROBE socket only (rationale at its use site in check()).
// `eNULL` (no-encryption suites) is NOT part of OpenSSL's `ALL` by convention, so it must
// be named explicitly or a server accepting NULL-SHA is undetectable. `aNULL` (anonymous,
// ADH/AECDH) IS inside `ALL` at SECLEVEL=0 — we deliberately allow it so the suite can be
// GRADED, then re-probe without it to recover certificate evidence, because an anonymous
// handshake presents no certificate.
const PROBE_CIPHERS = 'ALL:eNULL:@SECLEVEL=0';
const PROBE_CIPHERS_AUTHENTICATED = 'ALL:eNULL:!aNULL:@SECLEVEL=0';

function isWeakCipherName(name) {
  const u = String(name || '').toUpperCase();
  if (!u || u === 'UNKNOWN') return false;
  return WEAK_CIPHER_FRAGMENTS.some((f) => u.includes(f));
}

// Self-signed iff the issuer DN equals the subject DN. A real self-signed leaf also
// self-loops its issuerCertificate under getPeerCertificate(true); the DN-equality
// check is the robust, stub-friendly signal (040 remains the deep cert auditor).
// Keyed on CN|O|OU (Node omits absent DN fields) so an O-only / OU-only self-signed
// cert — appliances, IoT, internal CAs, `openssl req -subj "/O=..."` — is caught,
// not only CN-bearing DNs. Requires a non-empty DN so two empty DNs don't match.
function isSelfSignedCert(cert) {
  if (!cert || !cert.subject || !cert.issuer) return false;
  const dnKey = (x) => `${x.CN || ''}|${x.O || ''}|${x.OU || ''}`;
  const subjectDn = dnKey(cert.subject);
  return subjectDn !== '||' && subjectDn === dnKey(cert.issuer);
}

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

      const check = (version, cipherPolicy = PROBE_CIPHERS) => new Promise((resolve) => {
        let settled = false;
        const options = {
          host,
          port,
          servername: hostname,
          rejectUnauthorized: false,
          minVersion: version,
          maxVersion: version,
          // A scanner must be able to PROPOSE legacy suites, or it cannot discover them.
          // Node 20+/OpenSSL 3 refuse to offer TLSv1/TLSv1.1 at the default security level
          // and fail client-side before any packet: ERR_SSL_NO_PROTOCOLS_AVAILABLE
          // (error:0A0000BF SSL routines:tls_setup_handshake). Without this, weakProtocols
          // could NEVER populate against a real legacy server — the branch was dead in
          // production while a stubbed unit test stayed green. @SECLEVEL=0 lowers only this
          // probe's client policy (standard scanner practice — sslscan / testssl.sh do the
          // same); it sends no data and does not weaken anything the operator runs.
          // Guarded by tests/tls_scanner_real_tls_integration.test.mjs against a real server.
          ciphers: cipherPolicy
        };
        const socket = tlsApi.connect(options, () => {
          if (settled) return;
          settled = true;
          const protocol = socket.getProtocol?.();
          const cipher = socket.getCipher?.();
          let cert = null;
          try { cert = socket.getPeerCertificate?.(true) || null; } catch { cert = null; }
          try { socket.end?.(); } catch {}
          resolve({ success: true, protocol, cipher: cipher ? cipher.name : 'Unknown', cert });
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

      let leafCert = null;
      for (const v of versions) {
        const res = await check(v);
        if (res.success) {
          const proto = res.protocol || v;
          result.supportedVersions.push(proto);
          result.ciphers[proto] = res.cipher;
          // Keep the first observed leaf cert (all versions serve the same cert).
          if (!leafCert && res.cert && res.cert.subject) leafCert = res.cert;
        }
        if (debug) {
          result.errors.push({ version: v, success: !!res.success, error: res.success ? 'none' : res.error });
        }
      }

      result.isTLSService = result.supportedVersions.length > 0;
      result.supportsOld = result.supportedVersions.some(v => v === 'TLSv1' || v === 'TLSv1.1');

      // An anonymous (aNULL) suite presents NO certificate, so if the probe negotiated one
      // the cert axes would go silent on exactly the worst-configured hosts — a false-clean
      // on the two axes this producer exists to close. Re-probe ONCE excluding aNULL, purely
      // to recover cert evidence; the weak-cipher grading from the first pass is retained.
      // Costs an extra handshake only on the rare anonymous-capable server.
      if (result.isTLSService && !leafCert) {
        const known = result.supportedVersions[result.supportedVersions.length - 1];
        const again = await check(known, PROBE_CIPHERS_AUTHENTICATED);
        if (again.success && again.cert && again.cert.subject) leafCert = again.cert;
      }
      // Public cert facts only — the full cert stays in-process (ZDE).
      result.certExpiry = leafCert?.valid_to || null;
      result.certSelfSigned = isSelfSignedCert(leafCert);

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
        response_banner: JSON.stringify(bannerObj),
        // Structured evidence for the crypto_agent producer contract (see conclude()).
        tlsEvidence: {
          tls: r.isTLSService,
          supportedVersions: r.supportedVersions,
          ciphers: r.ciphers,
          certExpiry: r.certExpiry || null,
          certSelfSigned: r.certSelfSigned === true
        }
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

    // crypto_agent producer contract — attach the TLS-quality fields ONLY where a
    // handshake was observed (status === 'open'), so the consumer's "encrypted
    // wherever this fires" premise stays code-true.
    const ev = r?.tlsEvidence || {};
    let contract = {};
    if (status === 'open') {
      const supportedVersions = Array.isArray(ev.supportedVersions) ? ev.supportedVersions : [];
      const weakProtocols = supportedVersions.filter((v) => WEAK_TLS_PROTOCOLS.has(v));
      // weakCiphers reports the NEGOTIATED cipher per version (run() connects with
      // node's default, strong client cipher list), so a non-empty value is a true
      // positive but an empty value is NOT proof "no weak cipher is accepted" — the
      // server may accept RC4/3DES that a default client never proposes. A forced
      // per-cipher enumeration (like the per-version handshake) is the follow-up; the
      // consumer only raises a finding on a non-empty value, so it never over-reads [].
      const weakCiphers = [...new Set(Object.values(ev.ciphers || {}).filter(isWeakCipherName))];
      contract = {
        tls: true, // status === 'open' ⇒ a handshake was observed
        weakProtocols,
        weakCiphers,
        certSelfSigned: ev.certSelfSigned === true,
        ...(ev.certExpiry ? { certExpiry: ev.certExpiry } : {})
      };
    }

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
      authoritative: true,
      ...contract
    });
  }
  return items;
}

export const authoritativePorts = new Set(['tcp:443','tcp:465','tcp:563','tcp:993','tcp:995']);
