import './helpers/no_operator_dotenv.mjs';
import './helpers/no_operator_keychain.mjs';   // FIRST: this file imports cli.mjs
// tests/scan_pin_wiring.test.mjs
// ─────────────────────────────────────────────────────────────────────────────
// THE PIN IS WIRED WHERE A SCAN STARTS (EE 2.0.0, R1b): the MCP scan_host and probe_service handlers and the CLI's
// scanSingleHost run their plugins inside the pin, seeded from their own host check. utils/scan_pin.mjs being correct
// proves nothing about a handler that never calls it.
//
// DRIVEN, OFFLINE: one RFC 6761 name is answered by a stub on the object the check resolves through. The check sees
// CHECKED; the plugin manager stand-in then REBINDS the name (the attacker's TTL-0 flip) and asks the resolver again, the
// way a plugin's connect would, and records the answer. Pinned, it is the address the check looked at.
//
// FOURTH QUADRANT FIRST: unpinned, the in-scan lookup returns the REBOUND answer — or the pinned legs prove nothing.
// ─────────────────────────────────────────────────────────────────────────────
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import dnsPromises from 'node:dns/promises';
import { scanSingleHost } from '../cli.mjs';
import { handleScanHost, handleProbeService, _setPluginManager, _setValidateHost } from '../mcp_server.mjs';

const NAME = 'rebind.test';
const REBOUND = '127.0.0.1';
let answer = null;
const orig = dnsPromises.lookup;
dnsPromises.lookup = async function stub(h, o) {
  if (String(h).toLowerCase() !== NAME) return orig.call(dnsPromises, h, o);
  const list = [].concat(answer).map((address) => ({ address, family: address.includes(':') ? 6 : 4 }));
  return o?.all ? list : list[0];
};
const savedAllowAll = process.env.NSA_ALLOW_ALL_HOSTS;
after(() => {
  dnsPromises.lookup = orig; _setPluginManager(null); _setValidateHost(null);
  if (savedAllowAll === undefined) delete process.env.NSA_ALLOW_ALL_HOSTS; else process.env.NSA_ALLOW_ALL_HOSTS = savedAllowAll;
});

const STOP = /stop: the scan body ran/;
/** A plugin manager whose scan rebinds the name, then records what an in-scan lookup answers, then stops the handler. */
function recordingPm(seen, { all = false } = {}) {
  const scan = async (host) => {
    answer = REBOUND;
    seen.push(all ? (await dnsPromises.lookup(host, { all: true })).map((a) => a.address) : (await dnsPromises.lookup(host, { family: 4 })).address);
    throw new Error('stop: the scan body ran');
  };
  return { run: scan, _runOne: (plugin, host) => scan(host), findPlugin: () => ({ id: '999', name: 'stand-in network plugin' }) };
}
const checkSees = (address) => { answer = address; delete process.env.NSA_ALLOW_ALL_HOSTS; };

test('(w1, first) UNPINNED — a handler given the bare name — the in-scan lookup follows the REBOUND answer', async () => {
  checkSees('203.0.113.10');
  const seen = [];
  _setPluginManager(recordingPm(seen));
  _setValidateHost(async (h) => h);   // the pre-2.0.0 contract: the check hands on the NAME
  await assert.rejects(handleScanHost({ host: NAME }), STOP);
  assert.deepEqual(seen, [REBOUND], 'positive control: the stand-in did not observe the rebinding — this fixture measures nothing');
});

test('(w2) MCP scan_host connects where its check looked', async () => {
  checkSees('203.0.113.10');
  const seen = [];
  _setPluginManager(recordingPm(seen));
  _setValidateHost(null);
  await assert.rejects(handleScanHost({ host: NAME }), STOP);
  assert.deepEqual(seen, ['203.0.113.10']);
});

test('(w3) MCP probe_service connects where its check looked', async () => {
  checkSees('203.0.113.10');
  const seen = [];
  _setPluginManager(recordingPm(seen));
  _setValidateHost(null);
  await assert.rejects(handleProbeService({ host: NAME, port: 80, pluginName: 'stand-in' }), STOP);
  assert.deepEqual(seen, ['203.0.113.10']);
});

test('(w4) the CLI connects where its check looked', async () => {
  checkSees('203.0.113.10');
  const seen = [];
  await assert.rejects(scanSingleHost(recordingPm(seen), NAME, 'all', {}, false), STOP);
  assert.deepEqual(seen, ['203.0.113.10']);
});

test('(w5) under NSA_ALLOW_ALL_HOSTS the CLI admits a PRIVATE answer and still pins it — the variable relaxes WHICH, never WHEN', async () => {
  checkSees('10.0.0.5');
  process.env.NSA_ALLOW_ALL_HOSTS = '1';
  const seen = [];
  await assert.rejects(scanSingleHost(recordingPm(seen), NAME, 'all', {}, false), STOP);
  assert.deepEqual(seen, ['10.0.0.5']);
});

test('(w6) the WHOLE checked answer set is pinned, in resolver order — not only the first answer', async () => {
  checkSees(['203.0.113.10', '2606:4700:4700::1111']);
  const seen = [];
  _setPluginManager(recordingPm(seen, { all: true }));
  _setValidateHost(null);
  await assert.rejects(handleScanHost({ host: NAME }), STOP);
  assert.deepEqual(seen, [['203.0.113.10', '2606:4700:4700::1111']]);
});
