import { test } from 'node:test';
import assert from 'node:assert/strict';
import { PluginManager } from '../plugin_manager.mjs';

function mock(id, provider) {
  return { id, name: `mock-${provider}`, cloudProvider: provider, priority: 50 };
}

async function makePM() {
  const pm = await PluginManager.create({
    plugins: [mock('9001', 'aws'), mock('9002', 'gcp'), mock('9003', 'azure')],
    tier: 'enterprise',
  });
  // Stub orchestration so this test isolates runCloud's scoping (orchestration
  // is already tested via run()). Echo the scoped selection into manifest/results.
  pm._runOrchestrated = async (host, selection) => ({
    ctx: {},
    results: selection.map((p) => ({ id: p.id, name: p.name, result: { up: true, data: [] } })),
    manifest: selection.map((p) => ({ id: p.id, name: p.name, status: 'ran', duration_ms: 0 })),
  });
  return pm;
}

test('runCloud(["aws"]) runs only AWS plugins', async () => {
  const pm = await makePM();
  const out = await pm.runCloud(['aws']);
  assert.deepEqual(out.manifest.map((m) => m.id), ['9001']);
  assert.equal(out.host, 'cloud:aws');
});

test('runCloud(["aws","azure"]) runs the union', async () => {
  const pm = await makePM();
  const out = await pm.runCloud(['aws', 'azure']);
  assert.deepEqual(out.manifest.map((m) => m.id).sort(), ['9001', '9003']);
  assert.equal(out.host, 'cloud:aws+azure');
});

test('runCloud(all three) runs all cloud plugins', async () => {
  const pm = await makePM();
  const out = await pm.runCloud(['aws', 'gcp', 'azure']);
  assert.deepEqual(out.manifest.map((m) => m.id).sort(), ['9001', '9002', '9003']);
});

test('runCloud([]) runs nothing (empty selection → empty output, no orchestration)', async () => {
  const pm = await makePM();
  const out = await pm.runCloud([]);
  assert.deepEqual(out.manifest, []);
  assert.deepEqual(out.results, []);
  assert.equal(out.conclusion, null);
  assert.equal(out.host, 'cloud:none');
});

test('runCloud reports auditedProviders + providerStatus (ran counts)', async () => {
  const pm = await makePM();
  const out = await pm.runCloud(['aws', 'azure']);
  assert.deepEqual(out.auditedProviders.sort(), ['aws', 'azure']);
  assert.equal(out.providerStatus.aws.ran, 1);
  assert.equal(out.providerStatus.azure.ran, 1);
});

test('runCloud([]) reports no audited providers', async () => {
  const pm = await makePM();
  const out = await pm.runCloud([]);
  assert.deepEqual(out.auditedProviders, []);
});
