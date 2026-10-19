// tests/concluder_fallback_closed_port.test.mjs
// ─────────────────────────────────────────────────────────────────────────────
// A FALLBACK ROW ON A TCP PORT THE PORT SCANNER MEASURED CLOSED IS EVIDENCE WITH ITS REASON, NEVER A SERVICE.
//
// A probe with no concluder adapter reaches the conclusion through the concluder's fallback: one non-authoritative row
// named after the plugin, its status `open` when the plugin's result was up and `unknown` otherwise. Since Community 1.0.0
// an authoritative adapter row that did not identify its TCP port is never a service — onto a service that exists it
// fills blanks other than identity, where none exists it goes to `evidence` with its reason — but the fallback was outside
// that rule, the 1.0.0 entry's second stated limit: the SUN RPC plugin (015) listed port 111 as `sun`, status `unknown`,
// on a port the port scanner (003) measured closed. A fallback row on a 003-closed TCP port now takes the same path.
//
// FOURTH QUADRANT FIRST: a fallback row on a port 003 measured open, or never measured, is still a service — or the rule
// could pass by dropping every fallback row.
// ─────────────────────────────────────────────────────────────────────────────
import './helpers/no_operator_home.mjs';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import concluder from '../plugins/result_concluder.mjs';

const ps = ({ open = [], closed = [] } = {}) => ({ id: '003', name: 'Port Scanner',
  result: { up: true, type: 'port-scanner', tcpOpen: open, tcpClosed: closed, tcpFiltered: [], udpOpen: [], udpClosed: [],
    udpNoResponse: [], data: [] } });
// 015 has no concluder adapter: its row reaches the conclusion through the fallback.
const sunrpc = ({ up = false, protocol = 'tcp' } = {}) => ({ id: '015', name: 'SUN RPC Scanner',
  result: { up, program: 'Unknown', version: 'Unknown', type: 'sunrpc',
    data: [{ probe_protocol: protocol, probe_port: 111, probe_info: 'No RPC response', response_banner: null }] } });
const at = (c, port, protocol = 'tcp') => (c.result ?? c).services.filter((s) => s.port === port && s.protocol === protocol);
const evidenceAt = (c, port) => (c.result ?? c).evidence.filter((e) => e.port === port && e.reason);

// ── FOURTH QUADRANT FIRST ─────────────────────────────────────────────────────────────────────────────────────────────
test('(first) a fallback row on a port the port scanner measured OPEN is still a service', async () => {
  const c = await concluder.run([ps({ open: [111] }), sunrpc({ up: true })]);
  assert.deepEqual(at(c, 111).map((s) => `${s.service}/${s.status}`), ['sun/open']);
});
test('(first) a fallback row on a port the port scanner did not measure is still a service — as before', async () => {
  for (const results of [[sunrpc()], [ps({ open: [22] }), sunrpc()]]) {
    const c = await concluder.run(results);
    assert.deepEqual(at(c, 111).map((s) => `${s.service}/${s.status}`), ['sun/unknown'], results.map((r) => r.id).join(','));
    assert.deepEqual(evidenceAt(c, 111), []);
  }
});

// ── ON A PORT THE PORT SCANNER MEASURED CLOSED ─────────────────────────────────────────────────────────────────────────
test('a fallback row on a 003-closed TCP port is not a service: it is evidence, with its reason and its plugin', async () => {
  const c = await concluder.run([ps({ open: [22], closed: [111] }), sunrpc()]);
  assert.deepEqual(at(c, 111), []);
  assert.deepEqual(evidenceAt(c, 111).map((e) => `${e.from}/${e.protocol}/${e.status}/${e.reason}`),
    ['sun/tcp/unknown/port measured closed by the port scanner (003)']);
});
test('the order of the results does not matter — the port scanner after the fallback plugin decides the same', async () => {
  const c = await concluder.run([sunrpc(), ps({ open: [22], closed: [111] })]);
  assert.deepEqual(at(c, 111), []);
  assert.equal(evidenceAt(c, 111).length, 1);
});
test('a fallback row whose plugin read itself up is still evidence on a 003-closed port — the fallback identified nothing', async () => {
  const c = await concluder.run([ps({ closed: [111] }), sunrpc({ up: true })]);
  assert.deepEqual(at(c, 111), []);
  assert.deepEqual(evidenceAt(c, 111).map((e) => e.status), ['open']);
});
test('beside an IDENTIFIED service on that port, the fallback row never replaces its identity or adds a second row', async () => {
  const adapters = { T9: { conclude: () => [{ port: 111, protocol: 'tcp', service: 'rpcbind', program: 'rpcbind', version: '2',
    status: 'open', authoritative: true }] } };
  const c = await concluder.run([ps({ closed: [111] }), { id: 'T9', name: 'RPC Identifier', result: { up: true } }, sunrpc()],
    { adapters });
  assert.deepEqual(at(c, 111).map((s) => `${s.service}/${s.program}/${s.status}`), ['rpcbind/rpcbind/open']);
});

// ── THE DECLARED LIMIT: UDP ────────────────────────────────────────────────────────────────────────────────────────────
test('a UDP fallback row is untouched by a TCP close of the same port number', async () => {
  const c = await concluder.run([ps({ closed: [111] }), sunrpc({ protocol: 'udp' })]);
  assert.deepEqual(at(c, 111, 'udp').map((s) => s.service), ['sun']);
});
