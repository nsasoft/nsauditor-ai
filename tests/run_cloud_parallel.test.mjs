import { test } from 'node:test';
import assert from 'node:assert/strict';
import { PluginManager } from '../plugin_manager.mjs';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function makeCounter() { return { inFlight: 0, max: 0 }; }
function mockPlugin(id, counter, sleepMs = 30) {
  return {
    id, name: `mock-${id}`, cloudProvider: 'aws', priority: 50, runStrategy: 'single',
    async run() {
      counter.inFlight++; counter.max = Math.max(counter.max, counter.inFlight);
      await sleep(sleepMs);
      counter.inFlight--;
      return { up: true, data: [{ severity: 'info', title: `ok:${id}` }] };
    },
  };
}

async function pmWith(plugins) {
  return PluginManager.create({ plugins, tier: 'enterprise' });
}

test('runs cloud plugins concurrently (max in-flight == count) by default', async () => {
  const c = makeCounter();
  const plugins = ['9001', '9002', '9003', '9004', '9005', '9006'].map((id) => mockPlugin(id, c));
  const pm = await pmWith(plugins);
  const { manifest } = await pm._runCloudPluginsParallel(plugins, 'cloud:aws', {});
  assert.equal(c.max, 6, 'all 6 should have been in flight at once');
  assert.deepEqual(manifest.map((m) => m.status), ['ran', 'ran', 'ran', 'ran', 'ran', 'ran']);
});

test('CLOUD_SCAN_CONCURRENCY=1 forces serial (max in-flight 1)', async () => {
  const c = makeCounter();
  const plugins = ['9001', '9002', '9003'].map((id) => mockPlugin(id, c, 10));
  const pm = await pmWith(plugins);
  const saved = process.env.CLOUD_SCAN_CONCURRENCY;
  process.env.CLOUD_SCAN_CONCURRENCY = '1';
  try {
    await pm._runCloudPluginsParallel(plugins, 'cloud:aws', {});
    assert.equal(c.max, 1);
  } finally {
    if (saved === undefined) delete process.env.CLOUD_SCAN_CONCURRENCY; else process.env.CLOUD_SCAN_CONCURRENCY = saved;
  }
});

test('honors a per-run timeout via CLOUD_PLUGIN_TIMEOUT_MS', async () => {
  const c = makeCounter();
  const slow = mockPlugin('9001', c, 120);
  const pm = await pmWith([slow]);
  const saved = process.env.CLOUD_PLUGIN_TIMEOUT_MS;
  process.env.CLOUD_PLUGIN_TIMEOUT_MS = '30';
  try {
    const { manifest } = await pm._runCloudPluginsParallel([slow], 'cloud:aws', {});
    assert.equal(manifest[0].status, 'timeout');
  } finally {
    if (saved === undefined) delete process.env.CLOUD_PLUGIN_TIMEOUT_MS; else process.env.CLOUD_PLUGIN_TIMEOUT_MS = saved;
  }
});

test('anti-false-clean preserved: a timed-out provider is NOT audited', async () => {
  const c = makeCounter();
  const slow = mockPlugin('9001', c, 120);
  const pm = await pmWith([slow]);
  const saved = process.env.CLOUD_PLUGIN_TIMEOUT_MS;
  process.env.CLOUD_PLUGIN_TIMEOUT_MS = '30';
  try {
    const out = await pm.runCloud(['aws']);
    assert.deepEqual(out.auditedProviders, []);
    assert.equal(out.providerStatus.aws.ran, 0);
    assert.equal(out.providerStatus.aws.errored, 1);
  } finally {
    if (saved === undefined) delete process.env.CLOUD_PLUGIN_TIMEOUT_MS; else process.env.CLOUD_PLUGIN_TIMEOUT_MS = saved;
  }
});

test('runCloud returns the same shape via the parallel path', async () => {
  const c = makeCounter();
  const plugins = ['9001', '9002'].map((id) => mockPlugin(id, c));
  const pm = await pmWith(plugins);
  const out = await pm.runCloud(['aws']);
  assert.equal(out.host, 'cloud:aws');
  assert.deepEqual(out.auditedProviders, ['aws']);
  assert.equal(out.providerStatus.aws.ran, 2);
  assert.equal(out.manifest.length, 2);
});
