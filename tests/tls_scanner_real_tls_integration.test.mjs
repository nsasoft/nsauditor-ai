// tests/tls_scanner_real_tls_integration.test.mjs
//
// ANTI-MOCK-MASKING GUARD for the crypto_agent producer contract.
//
// The stub-driven contract test (tls_scanner_producer_contract.test.mjs) injects a
// fake TLS module via TLS_SCANNER_TLS_MODULE, and a stub can "support" TLSv1 in a way
// the REAL node:tls client cannot. That masked a live defect: node 20+/OpenSSL 3 refuses
// to PROPOSE TLSv1/TLSv1.1 at its default security level, failing client-side with
// ERR_SSL_NO_PROTOCOLS_AVAILABLE (error:0A0000BF tls_setup_handshake) — so weakProtocols
// could never populate against a real legacy server even though the stub test was green.
//
// This file deliberately does NOT set TLS_SCANNER_TLS_MODULE, so tls_scanner loads the
// real node:tls, and probes an actual legacy-capable TLS server started in-process.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import tls from 'node:tls';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';

// NOTE: no TLS_SCANNER_TLS_MODULE here — real node:tls on purpose.
process.env.TLS_SCANNER_SNI = 'localhost'; // avoid a reverse-DNS lookup; matches the cert CN
process.env.TLS_SCANNER_VERSIONS = 'TLSv1,TLSv1.1,TLSv1.2,TLSv1.3';
process.env.TLS_SCANNER_TIMEOUT_MS = '4000';

const { default: tlsScanner } = await import('../plugins/tls_scanner.mjs');
const { default: concluder } = await import('../plugins/result_concluder.mjs');

/** Generate a throwaway self-signed cert. Returns null if openssl is unavailable. */
function makeCert() {
  try {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-tls-'));
    const key = path.join(dir, 'k.pem');
    const cert = path.join(dir, 'c.pem');
    execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-keyout', key,
      '-out', cert, '-days', '2', '-nodes', '-subj', '/CN=localhost/O=NSAuditorTest'],
      { stdio: 'ignore' });
    return { key: fs.readFileSync(key), cert: fs.readFileSync(cert), dir };
  } catch {
    return null;
  }
}

test('REAL node:tls — a legacy-capable server yields weakProtocols (no stub can mask this)', async (t) => {
  const material = makeCert();
  if (!material) {
    // The stub-driven contract suite always runs, so coverage never drops below today's;
    // this guard simply needs openssl to build a fixture server.
    t.skip('openssl unavailable — cannot build a local legacy TLS server');
    return;
  }

  // A server that genuinely offers TLSv1 .. TLSv1.2 (SECLEVEL=0 so legacy versions are allowed).
  const server = tls.createServer(
    { key: material.key, cert: material.cert, minVersion: 'TLSv1', maxVersion: 'TLSv1.2', ciphers: 'ALL:@SECLEVEL=0' },
    (s) => { try { s.end(); } catch { /* ignore */ } },
  );
  server.on('tlsClientError', () => { /* probes intentionally fail some versions */ });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const port = server.address().port;

  try {
    process.env.TLS_SCANNER_PORTS = `${port}:https`;
    const raw = await tlsScanner.run('127.0.0.1');
    const conclusion = await concluder.run({ results: [{ name: 'TLS Scanner', result: raw }] });
    const svc = conclusion.services.find((s) => s.port === port);

    assert.ok(svc, 'service record should exist for the probed port');
    assert.equal(svc.status, 'open', 'positive control: the scanner did complete a handshake');
    assert.equal(svc.tls, true);

    // THE GUARD: the server offers TLSv1 + TLSv1.1, so a correct producer must report them.
    assert.ok(Array.isArray(svc.weakProtocols), 'weakProtocols must be an array');
    assert.ok(svc.weakProtocols.includes('TLSv1'),
      `real legacy server offers TLSv1 — producer must detect it (got: [${svc.weakProtocols}])`);
    assert.ok(svc.weakProtocols.includes('TLSv1.1'),
      `real legacy server offers TLSv1.1 — producer must detect it (got: [${svc.weakProtocols}])`);

    // Real Node cert object exercises the DN-equality self-signed check end-to-end.
    assert.equal(svc.certSelfSigned, true, 'the fixture cert is self-signed (issuer == subject)');
    assert.ok(svc.certExpiry, 'certExpiry captured from the real peer certificate');
    assert.ok(new Date(svc.certExpiry) > new Date(), 'fixture cert is not yet expired');
  } finally {
    server.close();
    try { fs.rmSync(material.dir, { recursive: true, force: true }); } catch { /* ignore */ }
  }
});
