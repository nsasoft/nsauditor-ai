import './helpers/no_operator_home.mjs';   // FIRST: the MCP call log is computed from homedir() at load
// scan_host STOPS AT A TOTAL TIME LIMIT AND SAYS SO, INSTEAD OF BEING CUT BY THE CLIENT WITH NOTHING RETURNED.
//
// scan_host runs a host's plugins one after another, each bounded only by its own budget, so the call takes about the
// sum of their times. A client that ends a tool call at a fixed limit (Claude Desktop at about 60 s) then returns
// nothing at all. SCAN_HOST_WALL_MS bounds the CALL (default 50 000, 0 = off): the deadline starts when the handler is
// entered, a reserve is kept for the concluder and the response, a running plugin's own wall shrinks to what is left,
// and a plugin reached after the deadline is not started. Each of those reads `timeout` in the manifest — requested and
// not measured, which is the truth — and `callWall`, a constant note and the head of the markdown name them, in the
// order they would have run.
//
// FOURTH QUADRANT FIRST: under the limit, and with the limit off, the scan is the scan it always was.
import { test, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import PluginManager, { CALL_DEADLINE_KEY, SCAN_HOST_NOT_STARTED_REASON } from '../plugin_manager.mjs';
import { handleScanHost, _setPluginManager, _setValidateHost, SCAN_HOST_WALL_DEFAULT_MS, SCAN_HOST_CALL_RESERVE_MS }
  from '../mcp_server.mjs';
import { SCAN_HOST_WALL_NOTE } from '../utils/report_md.mjs';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const seenOpts = [];
/** A network plugin that takes `ms` and records the opts it was handed. */
const plugin = (id, priority, ms) => ({
  id, name: `Plugin ${id}`, priority, requirements: {}, runStrategy: 'single',
  run: async (_host, _port, opts) => { seenOpts.push({ id, keys: Object.keys(opts || {}) }); await sleep(ms); return { up: true, data: [] }; },
});
const concluder = { id: '008', name: 'Result Concluder', run: async () => ({ host: {}, services: [], summary: '' }) };

async function scan(plugins, { wall, pm } = {}) {
  if (wall === undefined) delete process.env.SCAN_HOST_WALL_MS; else process.env.SCAN_HOST_WALL_MS = String(wall);
  _setPluginManager(pm || await PluginManager.create({ plugins: [...plugins, concluder], tier: 'ce' }));
  const t0 = Date.now();
  const out = await handleScanHost({ host: 'lan-host' });
  return { out, elapsed: Date.now() - t0 };
}
const rows = (out) => out.manifest.map((m) => ({ id: m.id, status: m.status, reason: m.reason }));

beforeEach(() => { seenOpts.length = 0; _setValidateHost(async (raw) => raw); });
afterEach(() => { _setValidateHost(null); _setPluginManager(null); delete process.env.SCAN_HOST_WALL_MS; });

test('(first) under the limit: every plugin runs, nothing is stopped, and the run equals the run with the limit off', async () => {
  const set = () => [plugin('A', 10, 20), plugin('B', 20, 20), plugin('C', 30, 20)];
  const { out } = await scan(set());
  assert.equal(SCAN_HOST_WALL_DEFAULT_MS, 50000);
  assert.deepEqual(out.callWall, { limitMs: 50000, reached: false, notStarted: [], cutShort: [] });
  assert.equal(out.note, undefined);
  assert.doesNotMatch(out.markdown, /time limit/);
  const off = (await scan(set(), { wall: 0 })).out;
  assert.deepEqual(rows(out), rows(off), 'the manifest is the one the unbounded call gives');
  assert.deepEqual(out.conclusion, off.conclusion);
  assert.ok(rows(out).every((r) => r.status === 'ran'));
});

test('(first) SCAN_HOST_WALL_MS=0 turns the limit off: a run longer than any small limit completes in full', async () => {
  const { out, elapsed } = await scan([plugin('A', 10, 400), plugin('B', 20, 400), plugin('C', 30, 400)], { wall: 0 });
  assert.ok(elapsed >= 1150, `the plugins really ran for their time (${elapsed} ms)`);
  assert.ok(rows(out).every((r) => r.status === 'ran'));
  assert.deepEqual(out.callWall, { limitMs: 0, reached: false, notStarted: [], cutShort: [] });
});

test('the limit reached mid-run: the running plugin is cut short, the rest are not started, in priority order', async () => {
  const wall = SCAN_HOST_CALL_RESERVE_MS + 1000;   // 1 s for the plugins
  const { out } = await scan([plugin('E', 50, 50), plugin('A', 10, 300), plugin('D', 40, 50), plugin('B', 20, 300),
    plugin('C', 30, 5000)], { wall });
  assert.deepEqual(rows(out).map((r) => [r.id, r.status]),
    [['A', 'ran'], ['B', 'ran'], ['C', 'timeout'], ['D', 'timeout'], ['E', 'timeout']], 'every row kept, in priority order');
  const c = out.manifest.find((m) => m.id === 'C');
  assert.match(c.reason, /timed out after (\d+)ms/);
  assert.ok(Number(/after (\d+)ms/.exec(c.reason)[1]) < 1000, 'C was given what was left of the limit, not its own wall');
  for (const id of ['D', 'E']) assert.equal(out.manifest.find((m) => m.id === id).reason, SCAN_HOST_NOT_STARTED_REASON);
  assert.deepEqual(out.callWall, { limitMs: wall, reached: true, notStarted: ['D', 'E'], cutShort: ['C'] });
  assert.equal(out.note, SCAN_HOST_WALL_NOTE);
  assert.ok(!seenOpts.some((s) => s.id === 'D' || s.id === 'E'), 'a plugin not started was never called');
});

test('the deadline starts when the handler is ENTERED: time spent before the plugins counts against it', async () => {
  const wall = SCAN_HOST_CALL_RESERVE_MS + 1000;
  const slowStart = await PluginManager.create({ plugins: [plugin('X', 10, 10000), concluder], tier: 'ce' });
  const run = slowStart.run.bind(slowStart);
  slowStart.run = async (...a) => { await sleep(600); return run(...a); };   // work before the plugins
  const { out, elapsed } = await scan([], { wall, pm: slowStart });
  assert.ok(elapsed < 1300, `the call ended by its limit less the reserve, counted from entry (${elapsed} ms)`);
  assert.deepEqual(out.callWall.cutShort, ['X']);
});

test('the markdown OPENS with the stop: the note, then the two lists, equal to callWall in order', async () => {
  const wall = SCAN_HOST_CALL_RESERVE_MS + 800;
  const { out } = await scan([plugin('A', 10, 100), plugin('B', 20, 5000), plugin('C', 30, 10), plugin('D', 40, 10)], { wall });
  const md = out.markdown;
  const head = md.slice(0, md.indexOf('## Summary'));
  assert.ok(head.includes(SCAN_HOST_WALL_NOTE), 'above the summary and the service table');
  const listed = (label) => (new RegExp(`^> - ${label}: (.*)$`, 'm').exec(head)?.[1] ?? '').split(', ').filter(Boolean)
    .map((s) => s.split(' — ')[0]);
  assert.deepEqual(listed('Not started'), out.callWall.notStarted);
  assert.deepEqual(listed('Stopped at the limit'), out.callWall.cutShort);
  assert.match(head, /C — Plugin C, D — Plugin D/);
});

test('no plugin ever receives the deadline, nor the wall', async () => {
  await scan([plugin('A', 10, 10), plugin('B', 20, 10)]);
  assert.ok(seenOpts.length === 2);
  for (const s of seenOpts) {
    assert.ok(!s.keys.includes(CALL_DEADLINE_KEY), `${s.id} was handed the deadline`);
    assert.ok(!s.keys.includes('pluginWallMs'), `${s.id} was handed the wall`);
  }
});

test('the CLI path, with no deadline, is unchanged: no callWall, and a long run completes', async () => {
  const pm = await PluginManager.create({ plugins: [plugin('A', 10, 300), plugin('B', 20, 300), concluder], tier: 'ce' });
  const out = await pm.run('lan-host', 'all', {});
  assert.equal(out.callWall, undefined);
  assert.ok(out.manifest.every((m) => m.status === 'ran'));
});

test('a plugin not started reads `timeout` in the run status too, so nothing reads it as never requested', async () => {
  const pm = await PluginManager.create({ plugins: [plugin('A', 10, 5000), plugin('B', 20, 10)], tier: 'ce' });
  const orch = await pm._runOrchestrated('lan-host', pm.plugins, { [CALL_DEADLINE_KEY]: Date.now() + 300 });
  assert.equal(orch.ctx.pluginRunStatus.get('A'), 'timeout');
  assert.equal(orch.ctx.pluginRunStatus.get('B'), 'timeout');
  assert.deepEqual(orch.callWall, { notStarted: ['B'], cutShort: ['A'] });
});

test('the note and the reason are statements a reader can use, and name the setting', () => {
  assert.match(SCAN_HOST_WALL_NOTE, /SCAN_HOST_WALL_MS/);
  assert.match(SCAN_HOST_WALL_NOTE, /not a clean result/);
  assert.match(SCAN_HOST_NOT_STARTED_REASON, /^not started/);
});
