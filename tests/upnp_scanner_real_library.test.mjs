// 028 THROUGH THE REAL node-upnp-utils — the call shape, driven on the dependency, not on a fake.
//
// Through CE 0.2.54 the plugin called `discover({ timeout: ms / 7, st })`. The library's discover()
// reads its window from `wait`, in whole seconds (default 5), and never reads `timeout` — so every
// search waited 5 s, a scan cost ~39 s, NSA_UPNP_TIMEOUT_MS never bound, and the pack recorded a window
// that was never applied. The unit tests' fake took `({ timeout })` and slept on it, so the suite agreed
// with the plugin and not with the library: a wrong-shaped mock on a library call.
//
// This file drives the REAL module's discover(), recording only its three side-effecting seams —
// startDiscovery (the socket and M-SEARCH send), wait (the timer), stopDiscovery — so no packet leaves
// the machine and no test waits, while the parameter handling under test is the library's own code.
import test from 'node:test';
import assert from 'node:assert/strict';
import upnp from 'node-upnp-utils';
import upnpScanner, { perTargetWaitSec } from '../plugins/upnp_scanner.mjs';

const SEAMS = ['startDiscovery', 'wait', 'stopDiscovery', 'getActiveDeviceList'];

function recordSeams(t) {
  const calls = { start: [], wait: [] };
  for (const k of SEAMS) assert.equal(Object.hasOwn(upnp, k), false, `${k} is already shadowed — a previous test did not restore it`);
  upnp.startDiscovery = async (params) => { calls.start.push(params); };
  upnp.wait = async (msec) => { calls.wait.push(msec); };
  upnp.stopDiscovery = async () => {};
  upnp.getActiveDeviceList = () => [];
  t.after(() => { for (const k of SEAMS) delete upnp[k]; });
  return calls;
}

test('the real discover() reads `wait` and ignores `timeout` — the premise, driven on the library', async (t) => {
  const calls = recordSeams(t);
  await upnp.discover({ timeout: 2142, st: 'upnp:rootdevice' });
  await upnp.discover({ wait: 2, st: 'upnp:rootdevice' });
  assert.deepEqual(calls.wait, [5000, 2000], 'a `timeout` key must fall to the 5 s default; `wait: 2` must wait 2000 ms');
  await assert.rejects(upnp.discover({ wait: 0.5 }), /wait/, 'the library rejects a non-integer `wait`');
});

test('028 at the DEFAULT window gives the library seven 2 s waits, not seven 5 s ones', async (t) => {
  const prior = process.env.NSA_UPNP_TIMEOUT_MS;
  delete process.env.NSA_UPNP_TIMEOUT_MS;
  t.after(() => { if (prior === undefined) delete process.env.NSA_UPNP_TIMEOUT_MS; else process.env.NSA_UPNP_TIMEOUT_MS = prior; });
  const calls = recordSeams(t);
  const out = await upnpScanner.run('192.168.1.1', 1900, {});
  assert.equal(calls.start.length, 7, 'one discovery per search target');
  assert.deepEqual(calls.wait, Array(7).fill(2000), '15 s across 7 targets rounds to 2 s each');
  assert.ok(calls.start.every((p) => p.wait === 2 && !('timeout' in p)), 'the call carries `wait`, never `timeout`');
  assert.equal(out.waitPerTargetSec, 2, 'the result records the wait the library was actually given');
  const banner = JSON.parse(out.data.find((r) => /No UPnP\/SSDP devices/.test(r.probe_info)).response_banner);
  assert.deepEqual([banner.timeout, banner.waitPerTargetSec], [15000, 2], 'the no-response row names the requested window AND the wait applied');
});

test('an operator window reaches the library: 70 s across 7 targets is 10 s each', async (t) => {
  const calls = recordSeams(t);
  await upnpScanner.run('192.168.1.1', 1900, { timeoutMs: 70000 });
  assert.deepEqual(calls.wait, Array(7).fill(10000));
});

test('the per-target wait stays inside the library\'s 1..120 s contract, and a non-number falls back to the default', () => {
  assert.equal(perTargetWaitSec(200), 1, 'a window under a second per target still waits the minimum 1 s');
  assert.equal(perTargetWaitSec(10_000_000), 120, 'the library refuses anything over 120 s');
  assert.equal(perTargetWaitSec(15000), 2);
  for (const bad of [NaN, 0, -5, undefined, 'abc']) {
    assert.equal(perTargetWaitSec(bad), 2, `${String(bad)} must fall back to the 15 s default, never reach the library as NaN`);
  }
});
