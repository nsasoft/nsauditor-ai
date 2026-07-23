// tests/tls_scanner_producer_contract.test.mjs
//
// PRODUCER CONTRACT — the TLS Scanner must attach the structured TLS-evidence
// fields that the EE crypto_agent consumer reads off each service record:
//   svc.tls            (bool)   — a TLS handshake was observed on this service
//   svc.weakProtocols  (str[])  — negotiated deprecated versions (TLSv1/1.1/SSLv3/2)
//   svc.weakCiphers    (str[])  — negotiated weak cipher names (RC4/3DES/NULL/…)
//   svc.certExpiry     (string) — the leaf cert's notAfter (crypto_agent decides expiry)
//   svc.certSelfSigned (bool)   — issuer == subject
//
// See EE agents/crypto_agent.mjs (tlsHandshakeObserved + the weakProtocols /
// weakCiphers / certExpiry / certSelfSigned branches). Before this contract the
// consumer branches were inert: no CE producer set any of these fields, so a real
// scan read clean over deprecated TLS / weak ciphers / expired / self-signed certs.
// Mirrors the cisImageInventory producer-contract discipline.
import { test } from 'node:test';
import assert from 'node:assert/strict';

// Point the plugin at the cert-aware stub BEFORE importing it (TLS_MODULE_ID is
// resolved at module-load time).
process.env.TLS_SCANNER_TLS_MODULE = new URL('./_tls_producer_stub.mjs', import.meta.url).href;
process.env.TLS_SCANNER_PORTS = '4443:https';
process.env.TLS_SCANNER_VERSIONS = 'TLSv1,TLSv1.1,TLSv1.2,TLSv1.3';
process.env.TLS_SCANNER_TIMEOUT_MS = '1500';

const { default: tlsScanner, conclude, authoritativePorts } = await import('../plugins/tls_scanner.mjs');
const { default: concluder } = await import('../plugins/result_concluder.mjs');

async function scanTo443(scenario) {
  process.env.TLS_PRODUCER_SCENARIO = scenario;
  const raw = await tlsScanner.run('127.0.0.1');
  const conclusion = await concluder.run({ results: [{ name: 'TLS Scanner', result: raw }] });
  return conclusion.services.find((s) => s.port === 4443);
}

test('producer contract (vuln host): tls_scanner emits weakProtocols / weakCiphers / certExpiry / certSelfSigned', async () => {
  const svc = await scanTo443('vuln');

  // Positive control — the service record itself must exist and be open, so a
  // missing-field failure is distinguishable from a no-record failure.
  assert.ok(svc, 'service record for port 4443 should exist');
  assert.equal(svc.status, 'open');
  assert.equal(svc.service, 'https');

  assert.equal(svc.tls, true, 'a handshake was observed → svc.tls must be true');

  assert.ok(Array.isArray(svc.weakProtocols), 'weakProtocols must be an array');
  assert.ok(svc.weakProtocols.includes('TLSv1'), 'TLSv1 negotiated → weakProtocols');
  assert.ok(svc.weakProtocols.includes('TLSv1.1'), 'TLSv1.1 negotiated → weakProtocols');
  assert.ok(!svc.weakProtocols.includes('TLSv1.2'), 'TLSv1.2 is not weak');

  assert.ok(Array.isArray(svc.weakCiphers), 'weakCiphers must be an array');
  assert.ok(svc.weakCiphers.includes('ECDHE-RSA-RC4-SHA'), 'RC4 cipher → weakCiphers');

  assert.equal(svc.certExpiry, 'Jan  1 00:00:00 2020 GMT', 'certExpiry = leaf notAfter');
  assert.ok(new Date(svc.certExpiry) < new Date(), 'the fixture cert is expired');

  assert.equal(svc.certSelfSigned, true, 'issuer == subject → self-signed');
});

test('producer contract (clean host): handshake marked, nothing spuriously flagged', async () => {
  const svc = await scanTo443('clean');

  assert.ok(svc, 'service record for port 4443 should exist');
  assert.equal(svc.status, 'open');

  // tls:true is the cleartext-gate closer — a genuinely encrypted service must
  // never be re-reported as "no transport encryption".
  assert.equal(svc.tls, true);

  assert.deepEqual(svc.weakProtocols, [], 'TLS 1.2/1.3 only → no weak protocols');
  assert.deepEqual(svc.weakCiphers, [], 'strong ciphers only → no weak ciphers');
  assert.equal(svc.certSelfSigned, false, 'CA-signed cert → not self-signed');
  assert.ok(new Date(svc.certExpiry) > new Date(), 'the fixture cert is valid');
});

test('producer contract: an O-only (no-CN) self-signed cert is still detected', async () => {
  // Regression for the review finding: a self-signed leaf whose DN carries only an
  // Organization (no CN) — appliances / IoT / internal CAs — must not slip past the
  // self-signed check just because it lacks a CN.
  const svc = await scanTo443('selfsigned-noCN');
  assert.ok(svc, 'service record for port 4443 should exist');
  assert.equal(svc.certSelfSigned, true,
    'issuer == subject with only an O (no CN) is self-signed — must not be missed');
});

test('producer contract: the record is AUTHORITATIVE (the 040-merge-trap defense)', async () => {
  // upsertService drops a NON-authoritative record's custom fields when an authoritative
  // record already owns the key. The contract fields therefore only survive because
  // tls_scanner emits them authoritatively. If that flag is ever flipped, every contract
  // field silently vanishes behind an authoritative sibling — pin it.
  process.env.TLS_PRODUCER_SCENARIO = 'vuln';
  const raw = await tlsScanner.run('127.0.0.1');
  const items = await conclude({ host: '127.0.0.1', result: raw });
  const item = items.find((i) => i.port === 4443);
  assert.ok(item, 'conclude() should emit the port 4443 record');
  assert.equal(item.authoritative, true,
    'the TLS-evidence fields survive the concluder merge ONLY on an authoritative record');
  assert.ok(authoritativePorts instanceof Set, 'authoritativePorts must remain a Set');
});

test('producer contract: a port with NO handshake carries none of the contract fields', async () => {
  // The consumer premise is "encrypted wherever this fires". Contract fields must be
  // attached ONLY where a handshake was observed — the direction that keeps that true.
  const svc = await scanTo443('notls');
  assert.ok(svc, 'a closed/no-TLS record should still exist');
  assert.notEqual(svc.status, 'open', 'positive control: no handshake was observed here');
  for (const field of ['tls', 'weakProtocols', 'weakCiphers', 'certExpiry', 'certSelfSigned']) {
    assert.equal(svc[field], undefined,
      `${field} must NOT be attached where no TLS handshake was observed`);
  }
});

test('producer contract: field shapes match what crypto_agent reads', async () => {
  const svc = await scanTo443('vuln');
  // The consumer guards are Array.isArray(...)/=== true/new Date(...); assert the
  // producer honors those exact shapes.
  assert.equal(typeof svc.tls, 'boolean');
  assert.ok(Array.isArray(svc.weakProtocols));
  assert.ok(Array.isArray(svc.weakCiphers));
  assert.equal(typeof svc.certExpiry, 'string');
  assert.equal(typeof svc.certSelfSigned, 'boolean');
});
