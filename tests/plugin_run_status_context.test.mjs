// ITEM 4 — A LATE PLUGIN MUST BE ABLE TO TELL "SCANNED, NOTHING OPEN" FROM "NOT SCANNED".
//
// ⚠️ WHY THIS EXISTS, measured on a live run. Under a short budget the port scanner (003) timed
// out; EE plugin 1023 computes its verdict from `openPorts.length`, RAN SUCCESSFULLY over the
// resulting empty set, and emitted `Good segmentation — minimal port exposure`. The cross-run
// delta then reported the real `9 open ports detected — moderate exposure` as RESOLVED. Nothing
// was fixed.
//
// ⚠️ AND THE PRODUCER WAS NOT UNAWARE — IT MITIGATED THE CASE FOUR WAYS AND NONE WAS ROUTABLE:
// a `noPortData` flag, `confidence: 'low'`, the score capped at 50 under its own comment
// "can't confirm posture without evidence", and a recommendation string. Every one of those sits
// in a channel the consumer cannot read. EMPTINESS OF `tcpOpen` IS NOT A SIGNAL — it is the same
// value for "scanned, none open" and "never scanned", which is exactly why a fifth caveat would
// not have helped. The signal has to be the upstream's STATUS.
//
// The map is general rather than port-scanner-shaped because the same three states govern the
// CPE mapper's discovery inputs, and a one-consumer field would be copied rather than reused.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import PluginManager from '../plugin_manager.mjs';

const mk = (id, name, run, over = {}) => ({ id, name, run, runStrategy: 'single', ...over });

// ⚠️ ASSERTED IN THE CONSUMER'S FRAME, NOT THE PRODUCER'S. My first draft read
// `pm.run(...).ctx` — and `run()` takes `orch.results` and `orch.manifest` and DISCARDS the
// context, so every leg failed while the channel itself was fine. The consumer is a LATE PLUGIN
// reading its own `opts.context`; that is the only frame in which this feature is either true or
// false, so that is where the observation is made.
const spy = (seen) => mk('999', 'Late Consumer', async (_h, _p, opts) => {
  const m = opts?.context?.pluginRunStatus;
  seen.map = m instanceof Map ? new Map(m) : null;
  return { up: true, data: [] };
}, { priority: 9999 });

// ── FOURTH QUADRANT FIRST: the state that must keep behaving exactly as today ────────────────
// The defect is "a timed-out upstream reads as an empty one", so the leg that rots is the one
// asserting a GENUINE empty result is still genuine. Every incident-born fixture exercises the
// timeout; if `ran` stopped being distinguishable the defect would invert and a clean estate
// would report an evidence gap on every scan.
test('ACCEPT — an upstream that RAN reads `ran`, so a genuinely empty result stays genuine', async () => {
  const seen = {};
  const pm = await PluginManager.create({ plugins: [
    mk('003', 'Port Scanner', async () => ({ up: true, data: [] })), spy(seen),
  ] });
  await pm.run('10.0.0.1', 'all', {});
  assert.equal(seen.map?.get('003'), 'ran',
    'an upstream that ran and found nothing must be distinguishable from one that never ran');
});

test('an upstream that TIMED OUT reads `timeout`, not merely absent', async () => {
  const seen = {};
  const slow = mk('003', 'Port Scanner',
    () => new Promise((r) => setTimeout(() => r({ up: true, data: [] }), 3000)), { timeoutMs: 120 });
  const pm = await PluginManager.create({ plugins: [slow, spy(seen)] });
  await pm.run('10.0.0.1', 'all', {});
  assert.equal(seen.map?.get('003'), 'timeout',
    'the consumer must see WHY the surface is empty, not just that it is');
});

test('an upstream that ERRORED reads `error`', async () => {
  const seen = {};
  const pm = await PluginManager.create({ plugins: [
    mk('003', 'Port Scanner', async () => { throw new Error('socket exploded'); }), spy(seen),
  ] });
  await pm.run('10.0.0.1', 'all', {});
  assert.equal(seen.map?.get('003'), 'error');
});

test('an upstream NOT REQUESTED has NO entry — absence is the third state, not a fourth', async () => {
  // "Never requested here" must be distinguishable from "requested and failed": the first is not
  // an evidence gap, because the surface was never in scope. The cross-run case is already
  // `plugin-not-run` in the delta.
  const seen = {};
  const pm = await PluginManager.create({ plugins: [
    mk('010', 'Something Else', async () => ({ up: true, data: [] })), spy(seen),
  ] });
  await pm.run('10.0.0.1', 'all', {});
  assert.equal(seen.map?.has('003'), false, 'a plugin nobody asked for must not appear as a failure');
  assert.equal(seen.map?.get('010'), 'ran');
});

test('the channel EXISTS for the first plugin to run — no null-check required of a consumer', async () => {
  const seen = {};
  const pm = await PluginManager.create({ plugins: [spy(seen)] });
  await pm.run('10.0.0.1', 'all', {});
  assert.ok(seen.map instanceof Map, 'the channel is part of the context contract, not a late arrival');
});
