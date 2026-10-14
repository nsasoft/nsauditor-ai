// tests/tls_scanner_transport_class.test.mjs
//
// The classification table for a port where NO version completed a handshake, pinned case by case through a stub
// (the real-socket legs in tls_scanner_real_tls_integration.test.mjs pin the real codes; this file pins the cases a
// real server cannot produce — a client-side refusal — and the mixed ones). The row leads with the transport class
// ONLY when every attempt that reached the wire failed in transport; one server answer anywhere is a measurement.
import { test } from 'node:test';
import assert from 'node:assert/strict';

process.env.TLS_SCANNER_TLS_MODULE = new URL('./_tls_transport_stub.mjs', import.meta.url).href;
process.env.TLS_SCANNER_PORTS = '4443:tls-x';
process.env.TLS_SCANNER_VERSIONS = 'TLSv1,TLSv1.1,TLSv1.2,TLSv1.3';
process.env.TLS_SCANNER_SNI = '127.0.0.1'; // equal to the IP: no SNI suffix in probe_info

const { default: tlsScanner } = await import('../plugins/tls_scanner.mjs');

async function infoFor(scenario) {
  process.env.TLS_TRANSPORT_SCENARIO = scenario;
  const raw = await tlsScanner.run('127.0.0.1');
  assert.equal(raw.up, false, 'no attempt completed a handshake');
  return raw.data.find((d) => d.probe_port === 4443)?.probe_info;
}

test('a server ANSWER on one attempt is a measurement, whatever the others did → "No TLS supported"', async () => {
  assert.equal(await infoFor('answer-then-reset'), 'No TLS supported');
});

test('client-side refusals carry no information; the transport failures on the wire decide → ECONNRESET', async () => {
  assert.equal(await infoFor('client-side-then-reset'), 'ECONNRESET');
});

test('every attempt refused client-side → nothing reached the wire, no class is invented → "No TLS supported"', async () => {
  assert.equal(await infoFor('all-client-side'), 'No TLS supported');
});

test('two transport classes across versions → both, in the order first seen', async () => {
  assert.equal(await infoFor('mixed-transport'), 'ECONNRESET, ETIMEDOUT');
});

test('an error with no code → no class is invented → "No TLS supported"', async () => {
  assert.equal(await infoFor('codeless'), 'No TLS supported');
});
