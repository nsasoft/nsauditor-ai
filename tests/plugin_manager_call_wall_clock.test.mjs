// tests/plugin_manager_call_wall_clock.test.mjs
// ─────────────────────────────────────────────────────────────────────────────
// B213 (the architect's ruling "B213 fix shape", architect-verdict-discharge-cd8bd08.md): ONE CLOCK DECIDES THE START GATE.
//
// _runOrchestrated shrinks a running plugin's wall to what is left of the call's deadline, and that wall is a timer on libuv's
// loop clock. The start gate for the NEXT plugin read `deadline - Date.now() > 0`. A timer that fires while Date.now() still
// reads a millisecond before the deadline let the loop start the next plugin, which the wall then cut at once: recorded as
// `{ cutShort: ['A','B'], notStarted: [] }` where `{ cutShort: ['A'], notStarted: ['B'] }` was expected. The fix: when the
// call's wall timer fires, the manager sets a flag, and the gate reads `fired || deadline - now() <= 0`.
//
// THE INJECTED CLOCK: Date.now() is capped at deadline − 1 for the whole call, so A's deadline timer always fires while the
// clock reads deadline − 1 — the recorded race, made deterministic.
//
// FOURTH QUADRANT FIRST: the flag must be the DEADLINE's timer, not any timeout. A plugin that times out on its own shorter
// budget, or that reports `timedOut` itself, leaves the deadline unreached, and the next plugin must start.
// ─────────────────────────────────────────────────────────────────────────────
import './helpers/no_operator_home.mjs';
import { test, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import PluginManager, { CALL_DEADLINE_KEY, PLUGIN_WALL_KEY, SCAN_HOST_NOT_STARTED_REASON } from '../plugin_manager.mjs';

const realNow = Date.now;
afterEach(() => { Date.now = realNow; });
let capEngaged = false;
/** Cap the clock at deadline − 1 for the rest of the test; returns the deadline. `capEngaged` records a read made once the
 *  real clock had reached deadline − 1 — the moment the cap, not the real clock, answered. */
function cappedClock(ms) {
  const deadline = realNow() + ms;
  capEngaged = false;
  Date.now = () => { const r = realNow(); if (r >= deadline - 1) capEngaged = true; return Math.min(r, deadline - 1); };
  return deadline;
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const plugin = (id, priority, run, extra = {}) => ({ id, name: `Plugin ${id}`, priority, requirements: {}, runStrategy: 'single', run, ...extra });
const slow = (ms) => async () => { await sleep(ms); return { up: true, data: [] }; };
const rows = (orch, ids) => Object.fromEntries(ids.map((id) => [id, orch.ctx.pluginRunStatus.get(id)]));

test('(first) a plugin that times out on its OWN shorter budget leaves the deadline unreached: the next plugin starts', async () => {
  const pm = await PluginManager.create({ plugins: [plugin('A', 10, slow(400), { timeoutMs: 20 }), plugin('B', 20, slow(10))], tier: 'ce' });
  const deadline = cappedClock(1500);
  const orch = await pm._runOrchestrated('lan-host', pm.plugins, { [CALL_DEADLINE_KEY]: deadline });
  assert.deepEqual(rows(orch, ['A', 'B']), { A: 'timeout', B: 'ran' }, 'A timed out on its own 20 ms; B ran');
  assert.deepEqual(orch.callWall, { notStarted: [], cutShort: [] });
});

test('(first) a plugin stopped by the CALLER\'s shorter wall (the MCP shape: pluginWallMs on every plugin) leaves the deadline unreached: the next plugin starts', async () => {
  const pm = await PluginManager.create({ plugins: [plugin('A', 10, slow(400)), plugin('B', 20, slow(10))], tier: 'ce' });
  const deadline = cappedClock(1500);
  const orch = await pm._runOrchestrated('lan-host', pm.plugins, { [CALL_DEADLINE_KEY]: deadline, [PLUGIN_WALL_KEY]: 20 });
  assert.deepEqual(rows(orch, ['A', 'B']), { A: 'timeout', B: 'ran' }, 'A timed out on the caller\'s 20 ms wall; B ran');
  assert.deepEqual(orch.callWall, { notStarted: [], cutShort: [] });
});

test('(first) a plugin that REPORTS timedOut itself, under the deadline\'s wall, leaves the deadline unreached: the next plugin starts', async () => {
  const selfTimed = async () => ({ up: false, data: [], timedOut: true, error: 'its own probe timed out' });
  const pm = await PluginManager.create({ plugins: [plugin('A', 10, selfTimed), plugin('B', 20, slow(10))], tier: 'ce' });
  const deadline = cappedClock(1500);
  const orch = await pm._runOrchestrated('lan-host', pm.plugins, { [CALL_DEADLINE_KEY]: deadline });
  assert.deepEqual(rows(orch, ['A', 'B']), { A: 'timeout', B: 'ran' }, 'A reported its own timeout at once; the deadline timer never fired');
  assert.deepEqual(orch.callWall.notStarted, []);
});

test('the deadline timer fires while the clock reads deadline − 1: the next plugin is NOT STARTED, not started and cut', async () => {
  const pm = await PluginManager.create({ plugins: [plugin('A', 10, slow(400)), plugin('B', 20, slow(10))], tier: 'ce' });
  const deadline = cappedClock(60);
  const orch = await pm._runOrchestrated('lan-host', pm.plugins, { [CALL_DEADLINE_KEY]: deadline });
  assert.equal(capEngaged, true, 'the premise: the gate read the clock after the real clock reached deadline − 1, and got deadline − 1');
  assert.deepEqual(orch.callWall, { notStarted: ['B'], cutShort: ['A'] });
  const b = orch.manifest.find((m) => m.id === 'B');
  assert.deepEqual({ status: b.status, reason: b.reason, duration_ms: b.duration_ms }, { status: 'timeout', reason: SCAN_HOST_NOT_STARTED_REASON, duration_ms: 0 });
});
