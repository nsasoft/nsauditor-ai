// tests/tls_scanner_real_tls_integration.test.mjs
//
// ANTI-MOCK-MASKING GUARD for the crypto_agent producer contract.
//
// The stub-driven contract test (tls_scanner_producer_contract.test.mjs) injects a
// fake TLS module via TLS_SCANNER_TLS_MODULE, and a stub can "support" a protocol or
// cipher the REAL node:tls client cannot. That masked a live defect: node 20+/OpenSSL 3
// refuse to PROPOSE TLSv1/TLSv1.1 at their default security level, failing client-side
// with ERR_SSL_NO_PROTOCOLS_AVAILABLE (error:0A0000BF tls_setup_handshake) — so
// weakProtocols could never populate against a real legacy server even though the stub
// test was green. Everything here therefore uses the REAL node:tls against real servers.
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

/** Start a real TLS server with the given cipher policy, scan it, return the service record. */
async function scanServer(material, { ciphers, maxVersion = 'TLSv1.2' }) {
  const server = tls.createServer(
    { key: material.key, cert: material.cert, minVersion: 'TLSv1', maxVersion, ciphers, honorCipherOrder: true },
    (s) => { try { s.end(); } catch { /* ignore */ } },
  );
  server.on('tlsClientError', () => { /* probes intentionally fail some versions */ });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const port = server.address().port;
  try {
    process.env.TLS_SCANNER_PORTS = `${port}:https`;
    const raw = await tlsScanner.run('127.0.0.1');
    const conclusion = await concluder.run({ results: [{ name: 'TLS Scanner', result: raw }] });
    return conclusion.services.find((s) => s.port === port);
  } finally {
    server.close();
  }
}

test('REAL node:tls — a legacy-capable server yields weakProtocols (no stub can mask this)', async (t) => {
  const material = makeCert();
  if (!material) { t.skip('openssl unavailable — cannot build a local TLS server'); return; }
  try {
    const svc = await scanServer(material, { ciphers: 'ALL:@SECLEVEL=0' });

    assert.ok(svc, 'service record should exist for the probed port');
    assert.equal(svc.status, 'open', 'positive control: the scanner did complete a handshake');
    assert.equal(svc.tls, true);

    // THE GUARD: the server offers TLSv1 + TLSv1.1, so a correct producer must report them.
    assert.ok(svc.weakProtocols.includes('TLSv1'),
      `real legacy server offers TLSv1 — producer must detect it (got: [${svc.weakProtocols}])`);
    assert.ok(svc.weakProtocols.includes('TLSv1.1'),
      `real legacy server offers TLSv1.1 — producer must detect it (got: [${svc.weakProtocols}])`);

    // Real Node cert object exercises the DN-equality self-signed check end-to-end.
    assert.equal(svc.certSelfSigned, true, 'the fixture cert is self-signed (issuer == subject)');
    assert.ok(svc.certExpiry, 'certExpiry captured from the real peer certificate');
  } finally {
    fs.rmSync(material.dir, { recursive: true, force: true });
  }
});

test('REAL node:tls — a weak-cipher-only server is VISIBLE and its cipher flagged', async (t) => {
  const material = makeCert();
  if (!material) { t.skip('openssl unavailable'); return; }
  try {
    // CAMELLIA128 is present in the OpenSSL build but excluded from node's DEFAULT client
    // list: before the probe carried an explicit cipher policy this handshake failed
    // outright, so such a host read as "no TLS service" and produced ZERO findings on
    // EVERY axis. Pin both that it is now seen and that the cipher is graded.
    const svc = await scanServer(material, { ciphers: 'CAMELLIA128-SHA:@SECLEVEL=0' });

    assert.ok(svc, 'service record should exist');
    assert.equal(svc.status, 'open', 'a weak-cipher-only server must not read as "no TLS service"');
    assert.ok(svc.weakCiphers.some((c) => /CAMELLIA128/i.test(c)),
      `CAMELLIA128 negotiated — weakCiphers must carry it (got: [${svc.weakCiphers}])`);
    assert.equal(svc.certSelfSigned, true, 'cert evidence is still captured on a weak-cipher host');
  } finally {
    fs.rmSync(material.dir, { recursive: true, force: true });
  }
});

test('REAL node:tls — a NULL-cipher server (no encryption at all) is detected', async (t) => {
  const material = makeCert();
  if (!material) { t.skip('openssl unavailable'); return; }
  try {
    // eNULL suites carry NO encryption. OpenSSL excludes them from `ALL` by convention, so
    // without naming eNULL explicitly in the probe policy a server accepting NULL-SHA is
    // completely undetectable — the handshake simply fails and the host reads as "no TLS".
    const svc = await scanServer(material, { ciphers: 'NULL-SHA:@SECLEVEL=0' });

    assert.ok(svc, 'service record should exist');
    assert.equal(svc.status, 'open', 'a NULL-cipher server must not read as "no TLS service"');
    assert.ok(svc.weakCiphers.some((c) => /NULL/i.test(c)),
      `a no-encryption suite was negotiated — it must be graded weak (got: [${svc.weakCiphers}])`);
    // NULL-SHA is RSA-authenticated, so the certificate is still presented.
    assert.equal(svc.certSelfSigned, true, 'cert evidence is captured on a NULL-cipher host');
  } finally {
    fs.rmSync(material.dir, { recursive: true, force: true });
  }
});

test('REAL node:tls — an ANONYMOUS-cipher server still yields cert evidence', async (t) => {
  const material = makeCert();
  if (!material) { t.skip('openssl unavailable'); return; }
  try {
    // An anonymous (aNULL) suite presents NO certificate. Proposing aNULL is what lets the
    // scanner GRADE it, but if the probe simply negotiates it, certExpiry/certSelfSigned go
    // silent on exactly the worst-configured hosts — a false-clean on the two axes this
    // producer exists to close. Both must hold: the anonymous cipher is flagged AND the
    // certificate is still recovered.
    const svc = await scanServer(material, { ciphers: 'aNULL:ALL:@SECLEVEL=0' });

    assert.ok(svc, 'service record should exist');
    assert.equal(svc.status, 'open');
    assert.ok(svc.weakCiphers.some((c) => /^(ADH|AECDH)/i.test(c)),
      `an anonymous suite was negotiated — it must be graded weak (got: [${svc.weakCiphers}])`);
    assert.equal(svc.certSelfSigned, true,
      'cert evidence must survive an anonymous negotiation (re-probe excluding aNULL)');
    assert.ok(svc.certExpiry, 'certExpiry must survive an anonymous negotiation');
  } finally {
    fs.rmSync(material.dir, { recursive: true, force: true });
  }
});
