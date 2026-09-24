// A CALLER'S WALL TRAVELS ON `pluginWallMs`, AND NO PLUGIN EVER RECEIVES IT (EE 1.1.0 build 6).
//
// Twelve network plugins read `opts.timeoutMs` as their OWN discovery window or per-probe timeout
// (port_scanner, ping_checker, 028, 070 …), and the manager forwards the caller's opts into every run.
// Through 0.2.54 the manager ALSO read that key as the caller's wall, so one name meant two things:
// the cloud path injected its 25 s wall there — harmless only because no cloud plugin reads it — and a
// wall carried that way on the network path would have become port_scanner's per-probe timeout.
// Build 6 needed a wall on `scan_host` (plugins now DECLARE budgets that outrank PLUGIN_TIMEOUT_MS, and
// Desktop kills a call at ~60 s), so the wall moved to its own key, read by the manager and stripped
// before any plugin's opts are built.
//
// Also here, because the same change removed it: `scan_host` advertised a `timeout` input its handler
// never read. The derived leg at the bottom holds every MCP tool to "an advertised input is read".
import { test } from 'node:test';
import assert from 'node:assert/strict';
import PluginManager, { PLUGIN_TIMEOUT_MS, PLUGIN_WALL_KEY } from '../plugin_manager.mjs';
import { TOOLS, toolHandlers, handleScanHost, handleProbeService, _setPluginManager, _setValidateHost } from '../mcp_server.mjs';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const mk = (id, name, run, over = {}) => ({ id, name, run, runStrategy: 'single', priority: 50, requirements: {}, ...over });
const HOST = '10.0.0.1';

// ── FOURTH QUADRANT FIRST: a plugin under the wall completes exactly as it would with none ───────
test('a plugin UNDER the wall completes unchanged — status, result and data', async () => {
  const quick = mk('9201', 'Quick', async () => { await sleep(5); return { up: true, data: [{ probe_info: 'kept' }] }; });
  const pm = await PluginManager.create({ plugins: [quick] });
  const out = await pm.run(HOST, 'all', { [PLUGIN_WALL_KEY]: 2000 });
  const m = out.manifest.find((x) => x.id === '9201');
  assert.equal(m.status, 'ran');
  assert.equal(m.reason, null);
  const r = out.results.find((x) => x.id === '9201');
  assert.deepEqual(r.result.data, [{ probe_info: 'kept' }]);
});

// ── NO PLUGIN RECEIVES THE CARRIER, ON ANY PATH THAT RUNS ONE ─────────────────────────────────────
const probe = (id, seen, over = {}) => mk(id, `Probe ${id}`, async (_h, _p, opts) => {
  seen.push(Object.keys(opts ?? {}).sort());
  return { up: true, data: [] };
}, over);

test('the orchestrated path (pm.run): the plugin sees the caller\'s keys, never the wall', async () => {
  const seen = [];
  const pm = await PluginManager.create({ plugins: [probe('9202', seen)] });
  await pm.run(HOST, 'all', { [PLUGIN_WALL_KEY]: 1000, timeoutMs: 7, marker: 'x' });
  assert.equal(seen.length, 1, 'precondition: the probe ran');
  assert.ok(!seen[0].includes(PLUGIN_WALL_KEY), `the wall reached a plugin: ${seen[0]}`);
  assert.ok(seen[0].includes('marker') && seen[0].includes('timeoutMs'), 'the caller\'s own keys are still forwarded');
});

test('the single-plugin path (_runOne, which probe_service uses): never the wall', async () => {
  const seen = [];
  const p = probe('9203', seen);
  const pm = await PluginManager.create({ plugins: [p] });
  await pm._runOne(p, HOST, 0, { [PLUGIN_WALL_KEY]: 1000, timeoutMs: 7 });
  assert.equal(seen.length, 1);
  assert.ok(!seen[0].includes(PLUGIN_WALL_KEY));
  assert.ok(seen[0].includes('timeoutMs'));
});

test('the cloud-parallel path (runCloud): neither the wall NOR an injected `timeoutMs` reaches the plugin', async () => {
  const seen = [];
  const pm = await PluginManager.create({ plugins: [probe('9204', seen, { cloudProvider: 'aws' })], tier: 'enterprise' });
  await pm.runCloud(['aws']);
  assert.equal(seen.length, 1, 'precondition: the cloud probe ran');
  assert.ok(!seen[0].includes(PLUGIN_WALL_KEY));
  assert.ok(!seen[0].includes('timeoutMs'), `the cloud wall is still injected as the plugins' own key: ${seen[0]}`);
});

// ── `opts.timeoutMs` IS THE PLUGINS' KEY NOW, AND NOT A WALL ──────────────────────────────────────
test('a caller\'s `opts.timeoutMs` no longer walls a plugin: the plugin reads it, the manager does not', async () => {
  const got = {};
  const slowish = mk('9205', 'Slowish', async (_h, _p, opts) => { got.timeoutMs = opts?.timeoutMs; await sleep(150); return { up: true, data: [] }; });
  const pm = await PluginManager.create({ plugins: [slowish] });
  const out = await pm.run(HOST, 'all', { timeoutMs: 20 });
  assert.equal(out.manifest.find((x) => x.id === '9205').status, 'ran', 'a 20 ms `timeoutMs` must not have timed the plugin out');
  assert.equal(got.timeoutMs, 20, 'the plugin still receives its own key');
});

// ── THE WALL BINDS A DECLARED PLUGIN, AND THE REASON NAMES THE BUDGET IT HAD ──────────────────────
test('the wall binds OVER a declaration on the orchestrated path, and the manifest says so', async () => {
  const declared = mk('9206', 'Declared', async () => { await sleep(300); return { up: true, data: [] }; }, { timeoutMs: 5000 });
  const pm = await PluginManager.create({ plugins: [declared] });
  const out = await pm.run(HOST, 'all', { [PLUGIN_WALL_KEY]: 60 });
  const m = out.manifest.find((x) => x.id === '9206');
  assert.equal(m.status, 'timeout');
  assert.match(m.reason, /60\s*ms/, `the reason must name the wall the plugin actually had: ${m.reason}`);
});

test('the wall binds on _runOne too', async () => {
  const declared = mk('9207', 'Declared', async () => { await sleep(300); return { up: true, data: [] }; }, { timeoutMs: 5000 });
  const pm = await PluginManager.create({ plugins: [declared] });
  const r = await pm._runOne(declared, HOST, 0, { [PLUGIN_WALL_KEY]: 60 });
  assert.equal(r.result.timedOut, true);
});

test('the cloud wall (CLOUD_PLUGIN_TIMEOUT_MS) still binds a declared cloud plugin, now on the carrier', async (t) => {
  const prior = process.env.CLOUD_PLUGIN_TIMEOUT_MS;
  process.env.CLOUD_PLUGIN_TIMEOUT_MS = '60';
  t.after(() => { if (prior === undefined) delete process.env.CLOUD_PLUGIN_TIMEOUT_MS; else process.env.CLOUD_PLUGIN_TIMEOUT_MS = prior; });
  const slow = mk('9208', 'Slow Cloud', async () => { await sleep(300); return { up: true, findings: [], data: [] }; }, { cloudProvider: 'aws', timeoutMs: 5000 });
  const pm = await PluginManager.create({ plugins: [slow], tier: 'enterprise' });
  const out = await pm.runCloud(['aws']);
  assert.equal(out.manifest[0].status, 'timeout');
  assert.match(out.manifest[0].reason, /60\s*ms/);
});

// ── THE MCP TOOLS PASS THE OPERATOR'S OWN BUDGET AS THE WALL ─────────────────────────────────────
test('scan_host passes the effective PLUGIN_TIMEOUT_MS on the carrier — so a declaration never outruns it on Desktop', async (t) => {
  const got = {};
  _setValidateHost(async (h) => h);
  _setPluginManager({ run: async (host, spec, opts) => { got.opts = opts; return { host, conclusion: null, manifest: [], results: [] }; } });
  t.after(() => { _setPluginManager(null); _setValidateHost(null); });
  await handleScanHost({ host: HOST });
  assert.equal(got.opts?.[PLUGIN_WALL_KEY], PLUGIN_TIMEOUT_MS);
  assert.ok(Number.isFinite(PLUGIN_TIMEOUT_MS) && PLUGIN_TIMEOUT_MS > 0);
});

test('probe_service passes the same wall to its single plugin', async (t) => {
  const got = {};
  const plugin = { id: '9209', name: 'Probed', run: async () => ({}) };
  _setValidateHost(async (h) => h);
  _setPluginManager({ findPlugin: () => plugin, _runOne: async (p, h, port, opts) => { got.opts = opts; return { id: p.id, result: {} }; } });
  t.after(() => { _setPluginManager(null); _setValidateHost(null); });
  await handleProbeService({ host: HOST, port: 80, pluginName: 'Probed' });
  assert.equal(got.opts?.[PLUGIN_WALL_KEY], PLUGIN_TIMEOUT_MS);
  assert.equal(got.opts?.hostKind, 'network');
});

// ── DERIVED: EVERY INPUT AN MCP TOOL ADVERTISES IS READ BY ITS HANDLER ────────────────────────────
// A property in an inputSchema is a promise to the model calling the tool; one the handler never
// reads is a knob that does nothing (`scan_host.timeout` was one, advertising a default of 30000).
function unreadInputs(tools, handlers) {
  const out = [];
  for (const t of tools) {
    const h = handlers[t.name];
    if (typeof h !== 'function') { out.push(`${t.name}: no handler`); continue; }
    const src = h.toString();
    for (const prop of Object.keys(t.inputSchema?.properties ?? {})) {
      const read = new RegExp(`\\bargs\\??\\.${prop}\\b`).test(src)
        || new RegExp(`\\{[^}]*\\b${prop}\\b[^}]*\\}\\s*=\\s*args\\b`).test(src);
      if (!read) out.push(`${t.name}.${prop}`);
    }
  }
  return out;
}

test('FIXTURE — an advertised input no handler reads is named; one that is read passes', () => {
  const tools = [
    { name: 'a', inputSchema: { properties: { host: {}, timeout: {} } } },
    { name: 'b', inputSchema: { properties: { depth: {} } } },
  ];
  const handlers = {
    a: async function (args) { return args.host; },
    b: async function (args) { const { depth } = args; return depth; },
  };
  assert.deepEqual(unreadInputs(tools, handlers), ['a.timeout']);
  assert.deepEqual(unreadInputs([{ name: 'c', inputSchema: { properties: {} } }], {}), ['c: no handler']);
});

test('every MCP tool\'s advertised inputs are read by its handler — no phantom knobs', () => {
  assert.ok(TOOLS.length > 0);
  const advertised = TOOLS.reduce((n, t) => n + Object.keys(t.inputSchema?.properties ?? {}).length, 0);
  assert.ok(advertised > 0, 'no tool advertises any input — this leg would be vacuous');
  assert.deepEqual(unreadInputs(TOOLS, toolHandlers), []);
});
