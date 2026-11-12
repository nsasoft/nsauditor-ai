// Two raw clients for the real-TLS legs' counter checks (B212-C1, B212-C3). Shared by tests/helpers/tls_trust_check_case.mjs
// and the control leg's child in tests/tls_cert_trust_check_real_tls.test.mjs, so "one raw connect" means one thing in both.
// Loopback only. A `.mjs` under tests/helpers/, never `*.test.mjs`: the suite glob does not run it.
import net from 'node:net';
import tls from 'node:tls';
import { once } from 'node:events';

/** ONE TCP connect, accepted by `server`, destroyed before any ClientHello. Resolves once both ends have seen the connect. */
export async function rawConnectOnce(server, port) {
  const accepted = once(server, 'connection');
  const c = net.connect(port, '127.0.0.1');
  c.on('error', () => {});
  await Promise.all([accepted, once(c, 'connect')]);
  c.destroy();
  return null;
}

/**
 * ONE ClientHello offering only TLS 1.0, which a server at Node's default minimum (TLS 1.2) refuses with an alert: a handshake
 * that STARTED and failed. Resolves with the client's error code; throws if the handshake completes (the premise is gone).
 */
export function refusedHelloOnce(server, port) {
  const c = tls.connect({ host: '127.0.0.1', port, rejectUnauthorized: false, minVersion: 'TLSv1', maxVersion: 'TLSv1', ciphers: 'DEFAULT:@SECLEVEL=0' });
  return new Promise((resolve, reject) => {
    c.on('error', (e) => resolve(e.code || e.message));
    c.on('secureConnect', () => { c.destroy(); reject(new Error('the TLS 1.0 handshake completed — the refused-hello premise is gone')); });
  });
}
