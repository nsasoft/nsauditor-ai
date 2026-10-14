// tests/_tls_transport_stub.mjs
// Stub node:tls for tests/tls_scanner_transport_class.test.mjs: every forced-version attempt FAILS, with the error
// code its scenario names for that version — so the producer's classification of a port with no completed handshake
// can be pinned case by case, including a client-side refusal no real server can produce at @SECLEVEL=0.
// Scenario via process.env.TLS_TRANSPORT_SCENARIO, read at connect() time. `null` = an error carrying no code.
import EventEmitter from 'node:events';

const SCENARIOS = {
  // TLSv1/TLSv1.1 refused by the client before a byte is sent; the server resets TLSv1.2/TLSv1.3.
  'client-side-then-reset': { TLSv1: 'ERR_SSL_NO_PROTOCOLS_AVAILABLE', 'TLSv1.1': 'ERR_SSL_NO_PROTOCOLS_AVAILABLE', 'TLSv1.2': 'ECONNRESET', 'TLSv1.3': 'ECONNRESET' },
  // Nothing was sent on any attempt: no information either way.
  'all-client-side': { TLSv1: 'ERR_SSL_NO_PROTOCOLS_AVAILABLE', 'TLSv1.1': 'ERR_SSL_NO_PROTOCOLS_AVAILABLE', 'TLSv1.2': 'ERR_SSL_NO_PROTOCOLS_AVAILABLE', 'TLSv1.3': 'ERR_SSL_NO_PROTOCOLS_AVAILABLE' },
  // The server ANSWERED one attempt (a protocol alert) and reset the rest: an answer is a measurement.
  'answer-then-reset': { TLSv1: 'ERR_SSL_TLSV1_ALERT_PROTOCOL_VERSION', 'TLSv1.1': 'ECONNRESET', 'TLSv1.2': 'ECONNRESET', 'TLSv1.3': 'ECONNRESET' },
  // Two transport classes across versions: both are named, in the order first seen.
  'mixed-transport': { TLSv1: 'ECONNRESET', 'TLSv1.1': 'ECONNRESET', 'TLSv1.2': 'ETIMEDOUT', 'TLSv1.3': 'ETIMEDOUT' },
  // An error with no code: no class is invented.
  'codeless': { TLSv1: null, 'TLSv1.1': null, 'TLSv1.2': null, 'TLSv1.3': null },
};

class FakeTLSSocket extends EventEmitter {
  setTimeout() {}
  end() {}
  destroy() {}
}

export function connect(options) {
  const sc = SCENARIOS[process.env.TLS_TRANSPORT_SCENARIO];
  if (!sc) throw new Error(`unknown TLS_TRANSPORT_SCENARIO ${process.env.TLS_TRANSPORT_SCENARIO}`);
  const code = sc[String(options?.minVersion || '')];
  const sock = new FakeTLSSocket();
  queueMicrotask(() => {
    const err = new Error(code ? `stub ${code}` : 'stub failure without a code');
    if (code) err.code = code;
    sock.emit('error', err);
  });
  return sock;
}

export default { connect };
