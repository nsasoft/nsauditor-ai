// A PLUGIN READS THE BUDGET THE MANAGER ENFORCES — `context.effectiveTimeoutMs` (EE 1.1.0 build 8).
//
// EE plugin 1040 declares a 60 s budget (build 6) and aborts itself at a soft budget of 0.8 × its OWN
// guess at the wall, read from the environment: 0.8 × 30 000 = 24 000 ms. The manager allowed it 60 s. On
// build 7's Gate-2 run, over a slow link, 1040 aborted its CIS v2 audit at 24 s and fell back to a name
// heuristic, with 36 s of its budget unused. The plugin could not know what the manager allowed: the
// caller's wall is stripped before a plugin's opts are built (by design), and the declaration's effect
// is decided in the manager. So the manager now hands every plugin the number it RACES AGAINST.
//
// Driven on the REAL manager, on every path that runs a plugin. The last legs read the number the plugin
// was given AND the number the manager timed it out on, and require them to be the same number.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import PluginManager, { PLUGIN_TIMEOUT_MS, PLUGIN_TIMEOUT_CEILING_MS, PLUGIN_WALL_KEY } from '../plugin_manager.mjs';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const HOST = '10.0.0.1';
const recorder = (id, seen, over = {}, sleepMs = 0) => ({
  id, name: `Budget ${id}`, runStrategy: 'single', priority: 50, requirements: {},
  run: async (_h, _p, opts) => { seen.push(opts?.context?.effectiveTimeoutMs); if (sleepMs) await sleep(sleepMs); return { up: true, data: [] }; },
  ...over,
});
const timedOutAfter = (text) => Number((/timed out after (\d+)ms/.exec(String(text ?? '')) ?? [])[1]);

// ── FOURTH QUADRANT FIRST: a plugin that declares nothing sees exactly the global it always had ──────────
test('an UNDECLARED plugin, no wall (the CLI): it is given PLUGIN_TIMEOUT_MS', async () => {
  const seen = [];
  const pm = await PluginManager.create({ plugins: [recorder('9301', seen)] });
  await pm.run(HOST, 'all', {});
  assert.deepEqual(seen, [PLUGIN_TIMEOUT_MS]);
});

test('a DECLARED plugin, no wall (the CLI): it is given its declaration', async () => {
  const seen = [];
  const pm = await PluginManager.create({ plugins: [recorder('9302', seen, { timeoutMs: 45_000 })] });
  await pm.run(HOST, 'all', {});
  assert.deepEqual(seen, [45_000]);
});

test('a declaration above the ceiling is given the ceiling', async () => {
  const seen = [];
  const pm = await PluginManager.create({ plugins: [recorder('9303', seen, { timeoutMs: PLUGIN_TIMEOUT_CEILING_MS + 60_000 })] });
  await pm.run(HOST, 'all', {});
  assert.deepEqual(seen, [PLUGIN_TIMEOUT_CEILING_MS]);
});

test('under a caller WALL (scan_host / probe_service): min(declaration, wall), and the wall for an undeclared plugin', async () => {
  const seen = [];
  const pm = await PluginManager.create({ plugins: [recorder('9304', seen, { timeoutMs: 45_000 }), recorder('9305', seen)] });
  await pm.run(HOST, 'all', { [PLUGIN_WALL_KEY]: 1_500 });
  assert.deepEqual(seen, [1_500, 1_500]);
  const loose = [];
  const pm2 = await PluginManager.create({ plugins: [recorder('9306', loose, { timeoutMs: 800 })] });
  await pm2.run(HOST, 'all', { [PLUGIN_WALL_KEY]: 1_500 });
  assert.deepEqual(loose, [800], 'a declaration UNDER the wall is not raised to it');
});

test('the single-plugin path (_runOne): the budget it races, and a caller\'s context cannot name another', async () => {
  const seen = [];
  const p = recorder('9307', seen, { timeoutMs: 45_000 });
  const pm = await PluginManager.create({ plugins: [p] });
  await pm._runOne(p, HOST, 0, { [PLUGIN_WALL_KEY]: 2_000, context: { effectiveTimeoutMs: 999_999 } });
  assert.deepEqual(seen, [2_000]);
});

test('the cloud path (runCloud): its 25 s default wall binds a larger declaration', async () => {
  const seen = [];
  const pm = await PluginManager.create({ plugins: [recorder('9308', seen, { cloudProvider: 'aws', timeoutMs: 60_000 })], tier: 'enterprise' });
  await pm.runCloud(['aws']);
  const wall = Number(process.env.CLOUD_PLUGIN_TIMEOUT_MS) > 0 ? Number(process.env.CLOUD_PLUGIN_TIMEOUT_MS) : 25_000;
  assert.deepEqual(seen, [Math.min(60_000, wall)]);
});

// ── THE NUMBER GIVEN IS THE NUMBER ENFORCED: a plugin that sleeps past it, both read ─────────────────────
test('orchestrated: the plugin is timed out after EXACTLY the budget it was given', async () => {
  const seen = [];
  const pm = await PluginManager.create({ plugins: [recorder('9309', seen, { timeoutMs: 120 }, 400)] });
  const out = await pm.run(HOST, 'all', {});
  const m = out.manifest.find((x) => x.id === '9309');
  assert.equal(m.status, 'timeout');
  assert.equal(timedOutAfter(m.reason), seen[0]);
  assert.equal(seen[0], 120);
});

test('single-plugin: timed out after exactly the budget it was given', async () => {
  const seen = [];
  const p = recorder('9310', seen, { timeoutMs: 120 }, 400);
  const pm = await PluginManager.create({ plugins: [p] });
  const out = await pm._runOne(p, HOST, 0, {});
  assert.equal(timedOutAfter(out?.result?.error), seen[0]);
  assert.equal(seen[0], 120);
});

test('cloud: timed out after exactly the budget it was given', async () => {
  const seen = [];
  const pm = await PluginManager.create({ plugins: [recorder('9311', seen, { cloudProvider: 'aws', timeoutMs: 150 }, 400)], tier: 'enterprise' });
  const out = await pm.runCloud(['aws']);
  const m = out.manifest.find((x) => x.id === '9311');
  assert.equal(m.status, 'timeout');
  assert.equal(timedOutAfter(m.reason), seen[0]);
  assert.equal(seen[0], 150);
});
