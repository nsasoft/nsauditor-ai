import { test } from 'node:test';
import assert from 'node:assert/strict';

// Helper to build a minimal plugin
function makePlugin(overrides = {}) {
  return {
    id: '099',
    name: 'Test Plugin',
    priority: 50,
    requirements: {},
    async run() { return { up: true, data: [] }; },
    ...overrides,
  };
}

const ceCapabilities = {
  coreScanning: true, basicMCP: true, findingQueue: true,
  intelligenceEngine: false, cloudScanners: false,
};

test('plugin without requiredCapabilities always runs in CE', async () => {
  let ran = false;
  const plugin = makePlugin({
    id: '099',
    async run() { ran = true; return { up: true, data: [] }; },
  });
  // Dynamically import PluginManager to get fresh instance
  const { PluginManager } = await import('../plugin_manager.mjs');
  const pm = await PluginManager.create({ plugins: [plugin] });
  await pm.run('127.0.0.1', ['099'], { capabilities: ceCapabilities });
  assert.ok(ran, 'CE plugin with no requiredCapabilities should run');
});

test('plugin with satisfied requiredCapabilities runs', async () => {
  let ran = false;
  const plugin = makePlugin({
    id: '098',
    requiredCapabilities: ['coreScanning'],
    async run() { ran = true; return { up: true, data: [] }; },
  });
  const { PluginManager } = await import('../plugin_manager.mjs');
  const pm = await PluginManager.create({ plugins: [plugin] });
  await pm.run('127.0.0.1', ['098'], { capabilities: ceCapabilities });
  assert.ok(ran, 'plugin with satisfied capability should run');
});

test('plugin with unsatisfied requiredCapabilities is skipped', async () => {
  let ran = false;
  const plugin = makePlugin({
    id: '097',
    requiredCapabilities: ['cloudScanners'],
    async run() { ran = true; return { up: true, data: [] }; },
  });
  const { PluginManager } = await import('../plugin_manager.mjs');
  const pm = await PluginManager.create({ plugins: [plugin] });
  await pm.run('127.0.0.1', ['097'], { capabilities: ceCapabilities });
  assert.ok(!ran, 'EE plugin should be skipped when capability not available');
});
