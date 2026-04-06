import { test } from 'node:test';
import assert from 'node:assert/strict';
import { describeSkipReason } from '../plugin_manager.mjs';

/* ------------------------------------------------------------------ */
/*  Unit tests for describeSkipReason                                  */
/* ------------------------------------------------------------------ */

test('describeSkipReason: host up requirement + host not up', () => {
  const mod = { requirements: { host: 'up' } };
  const ctx = { hostUp: false, tcpOpen: new Set(), udpOpen: new Set() };
  assert.equal(describeSkipReason(mod, ctx), 'host not up');
});

test('describeSkipReason: host down requirement + host is up', () => {
  const mod = { requirements: { host: 'down' } };
  const ctx = { hostUp: true, tcpOpen: new Set(), udpOpen: new Set() };
  assert.equal(describeSkipReason(mod, ctx), 'host is up (requires down)');
});

test('describeSkipReason: tcp_open requirement with missing ports', () => {
  const mod = { requirements: { tcp_open: [22] } };
  const ctx = { hostUp: true, tcpOpen: new Set(), udpOpen: new Set() };
  assert.equal(describeSkipReason(mod, ctx), 'tcp ports not open: 22');
});

test('describeSkipReason: tcp_open requirement with multiple missing ports', () => {
  const mod = { requirements: { tcp_open: [22, 80, 443] } };
  const ctx = { hostUp: true, tcpOpen: new Set(), udpOpen: new Set() };
  assert.equal(describeSkipReason(mod, ctx), 'tcp ports not open: 22,80,443');
});

test('describeSkipReason: udp_open requirement with missing ports', () => {
  const mod = { requirements: { udp_open: [161] } };
  const ctx = { hostUp: true, tcpOpen: new Set(), udpOpen: new Set() };
  assert.equal(describeSkipReason(mod, ctx), 'udp ports not open: 161');
});

test('describeSkipReason: only_if_os_unknown when OS is known', () => {
  const mod = { requirements: { only_if_os_unknown: true } };
  const ctx = { hostUp: true, tcpOpen: new Set(), udpOpen: new Set(), os: 'Linux' };
  assert.equal(describeSkipReason(mod, ctx), 'OS already determined');
});

test('describeSkipReason: no matching reason returns unknown', () => {
  const mod = { requirements: {} };
  const ctx = { hostUp: true, tcpOpen: new Set(), udpOpen: new Set() };
  assert.equal(describeSkipReason(mod, ctx), 'unknown');
});

test('describeSkipReason: null mod returns unknown', () => {
  assert.equal(describeSkipReason(null, { hostUp: true, tcpOpen: new Set(), udpOpen: new Set() }), 'unknown');
});

/* ------------------------------------------------------------------ */
/*  Integration-style tests using _runOrchestrated directly            */
/* ------------------------------------------------------------------ */

test('Manifest includes ran plugins with timing', async () => {
  // Dynamically import to get a fresh PluginManager class
  const { default: PluginManager } = await import('../plugin_manager.mjs');
  const mgr = new PluginManager('/nonexistent');
  // Bypass loadPlugins — inject a fast fake plugin directly
  mgr.plugins = [
    {
      id: '900',
      name: 'Fast Fake Plugin',
      priority: 1,
      requirements: {},
      ports: [0],
      runStrategy: 'single',
      run: async () => ({ up: true, data: [] }),
    },
  ];

  const { manifest } = await mgr._runOrchestrated('127.0.0.1', mgr.plugins);
  assert.equal(manifest.length, 1);
  assert.equal(manifest[0].id, '900');
  assert.equal(manifest[0].name, 'Fast Fake Plugin');
  assert.equal(manifest[0].status, 'ran');
  assert.equal(manifest[0].reason, null);
  assert.equal(typeof manifest[0].duration_ms, 'number');
  assert.ok(manifest[0].duration_ms >= 0);
});

test('Manifest includes skipped plugins', async () => {
  const { default: PluginManager } = await import('../plugin_manager.mjs');
  const mgr = new PluginManager('/nonexistent');
  mgr.plugins = [
    {
      id: '901',
      name: 'Needs Port 80',
      priority: 1,
      requirements: { tcp_open: [80] },
      ports: [80],
      runStrategy: 'single',
      run: async () => ({ up: true, data: [] }),
    },
  ];

  const { manifest } = await mgr._runOrchestrated('127.0.0.1', mgr.plugins);
  assert.equal(manifest.length, 1);
  assert.equal(manifest[0].id, '901');
  assert.equal(manifest[0].status, 'skipped');
  assert.ok(manifest[0].reason.includes('80'), `reason should mention port 80, got: ${manifest[0].reason}`);
  assert.equal(manifest[0].duration_ms, 0);
});

test('Manifest includes timed out plugins', async () => {
  // Simulate a timeout by having the plugin throw an error containing "timed out",
  // which is how callPlugin detects and flags timeouts (timedOut: true in result).
  const { default: PluginManager } = await import('../plugin_manager.mjs');
  const mgr = new PluginManager('/nonexistent');
  mgr.plugins = [
    {
      id: '902',
      name: 'Timeout Plugin',
      priority: 1,
      requirements: {},
      ports: [0],
      runStrategy: 'single',
      run: async () => { throw new Error('Plugin "Timeout Plugin" timed out after 100ms'); },
    },
  ];

  const { manifest } = await mgr._runOrchestrated('127.0.0.1', mgr.plugins);
  assert.equal(manifest.length, 1);
  assert.equal(manifest[0].id, '902');
  assert.equal(manifest[0].status, 'timeout');
  assert.ok(manifest[0].reason.includes('timed out'));
});

test('Manifest includes error plugins', async () => {
  const { default: PluginManager } = await import('../plugin_manager.mjs');
  const mgr = new PluginManager('/nonexistent');
  mgr.plugins = [
    {
      id: '903',
      name: 'Error Plugin',
      priority: 1,
      requirements: {},
      ports: [0],
      runStrategy: 'single',
      run: async () => { throw new Error('intentional test error'); },
    },
  ];

  const { manifest } = await mgr._runOrchestrated('127.0.0.1', mgr.plugins);
  assert.equal(manifest.length, 1);
  assert.equal(manifest[0].id, '903');
  assert.equal(manifest[0].status, 'error');
  assert.ok(manifest[0].reason.includes('intentional test error'));
});

test('run() returns manifest in output', async () => {
  const { default: PluginManager } = await import('../plugin_manager.mjs');
  const mgr = new PluginManager('/nonexistent');
  mgr.plugins = [
    {
      id: '904',
      name: 'Simple Plugin',
      priority: 1,
      requirements: {},
      ports: [0],
      runStrategy: 'single',
      run: async () => ({ up: true, data: [] }),
    },
    {
      id: '008',
      name: 'Result Concluder',
      run: async (_h, _p, opts) => {
        const results = opts?.results || [];
        return { summary: `Processed ${results.length} results` };
      },
    },
  ];

  const output = await mgr.run('127.0.0.1');
  assert.ok(Array.isArray(output.manifest), 'manifest should be an array');
  assert.ok(output.manifest.length > 0, 'manifest should have entries');
  assert.ok(output.host, 'host should be present');
  assert.ok(output.results, 'results should be present');
  // manifest should not include the concluder
  const ids = output.manifest.map(m => m.id);
  assert.ok(!ids.includes('008'), 'manifest should not include concluder');
});

test('Manifest mixed: ran + skipped plugins in single run', async () => {
  const { default: PluginManager } = await import('../plugin_manager.mjs');
  const mgr = new PluginManager('/nonexistent');
  mgr.plugins = [
    {
      id: '905',
      name: 'Runs First',
      priority: 1,
      requirements: {},
      ports: [0],
      runStrategy: 'single',
      run: async () => ({ up: true, data: [] }),
    },
    {
      id: '906',
      name: 'Needs TCP 443',
      priority: 2,
      requirements: { tcp_open: [443] },
      ports: [443],
      runStrategy: 'single',
      run: async () => ({ up: true, data: [] }),
    },
  ];

  const { manifest } = await mgr._runOrchestrated('127.0.0.1', mgr.plugins);
  assert.equal(manifest.length, 2);
  assert.equal(manifest[0].status, 'ran');
  assert.equal(manifest[1].status, 'skipped');
  assert.ok(manifest[1].reason.includes('443'));
});
