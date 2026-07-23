// tests/_tls_producer_stub.mjs
// Stub node:tls for the crypto_agent producer-contract test. Unlike _tls_stub.mjs
// it also implements getPeerCertificate() so the tls_scanner producer leg can
// derive certExpiry / certSelfSigned. Two scenarios, selected via
// process.env.TLS_PRODUCER_SCENARIO ('vuln' | 'clean'), read at connect() time.
import EventEmitter from 'node:events';

const SCENARIOS = {
  // A host that still speaks TLSv1/TLSv1.1, negotiates RC4 on the old version,
  // and presents an expired, self-signed certificate.
  vuln: {
    supports: () => true, // all four attempted versions succeed
    ciphers: {
      'TLSv1': 'ECDHE-RSA-RC4-SHA',            // weak (RC4)
      'TLSv1.1': 'ECDHE-RSA-AES128-SHA',
      'TLSv1.2': 'ECDHE-RSA-AES128-GCM-SHA256',
      'TLSv1.3': 'TLS_AES_256_GCM_SHA384',
    },
    cert: {
      subject: { CN: 'vuln.local', O: 'ACME' },
      issuer: { CN: 'vuln.local', O: 'ACME' }, // issuer == subject → self-signed
      valid_from: 'Jan  1 00:00:00 2019 GMT',
      valid_to: 'Jan  1 00:00:00 2020 GMT',    // expired
      fingerprint256: 'AA:BB:CC',
    },
  },
  // A port that speaks no TLS at all — every forced-version handshake fails.
  notls: {
    supports: () => false,
    ciphers: {},
    cert: null,
  },
  // A self-signed cert whose DN carries only an Organization (no CN) — typical of
  // appliances / IoT / internal CAs / `openssl req -subj "/O=..."`. issuer == subject.
  'selfsigned-noCN': {
    supports: (v) => v === 'TLSv1.2' || v === 'TLSv1.3',
    ciphers: { 'TLSv1.2': 'ECDHE-RSA-AES256-GCM-SHA384', 'TLSv1.3': 'TLS_AES_256_GCM_SHA384' },
    cert: {
      subject: { O: 'ACME Appliance' }, // no CN
      issuer: { O: 'ACME Appliance' },  // issuer == subject → self-signed
      valid_from: 'Jan  1 00:00:00 2024 GMT',
      valid_to: 'Jan  1 00:00:00 2999 GMT',
      fingerprint256: '11:22:33',
    },
  },
  // A correctly configured host: only TLS 1.2/1.3, strong ciphers, CA-signed cert
  // valid far into the future.
  clean: {
    supports: (v) => v === 'TLSv1.2' || v === 'TLSv1.3',
    ciphers: {
      'TLSv1.2': 'ECDHE-RSA-AES256-GCM-SHA384',
      'TLSv1.3': 'TLS_AES_256_GCM_SHA384',
    },
    cert: {
      subject: { CN: 'clean.example.com', O: 'Example Inc' },
      issuer: { CN: 'Example Root CA', O: 'Example Trust' }, // CA-signed
      valid_from: 'Jan  1 00:00:00 2024 GMT',
      valid_to: 'Jan  1 00:00:00 2999 GMT',    // far future
      fingerprint256: 'DD:EE:FF',
    },
  },
};

class FakeTLSSocket extends EventEmitter {
  constructor(opts, ok, sc) {
    super();
    this._opts = opts;
    this._ok = ok;
    this._sc = sc;
  }
  setTimeout() {}
  getProtocol() { return this._ok ? this._opts.minVersion : null; }
  getCipher() {
    if (!this._ok) return null;
    return { name: this._sc.ciphers[this._opts.minVersion] || 'TLS_FAKE_CIPHER' };
  }
  getPeerCertificate() { return this._ok ? this._sc.cert : {}; }
  end() { this.emit('end'); }
  destroy() { this.emit('close'); }
}

export function connect(options, onSecure) {
  const sc = SCENARIOS[process.env.TLS_PRODUCER_SCENARIO || 'vuln'] || SCENARIOS.vuln;
  const ok = sc.supports(String(options?.minVersion || ''));
  const sock = new FakeTLSSocket(options, ok, sc);
  queueMicrotask(() => {
    if (ok) {
      if (typeof onSecure === 'function') onSecure();
      sock.emit('secureConnect');
    } else {
      sock.emit('error', new Error('unsupported protocol version'));
    }
  });
  return sock;
}

export default { connect };
