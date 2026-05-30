import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  handleScanCloud,
  toolHandlers,
  _setPluginManager,
  _setTier,
  _requireEnterpriseCapability,
} from '../mcp_server.mjs';

function mockPM({ providers = ['aws', 'gcp', 'azure'] } = {}) {
  return {
    plugins: providers.map((p, i) => ({ id: `90${i}`, name: `mock-${p}`, cloudProvider: p })),
    runCloud: async (reqProviders) => ({
      host: `cloud:${reqProviders.join('+')}`,
      results: reqProviders.map((p) => ({ id: 'r' + p, result: { up: true, data: [{ title: `finding:${p}` }] } })),
      conclusion: null,
      manifest: reqProviders.map((p) => ({ id: 'r' + p, name: `mock-${p}`, status: 'ran' })),
    }),
  };
}

test('defaults to all three providers', async () => {
  _setPluginManager(mockPM());
  const out = await handleScanCloud({});
  assert.deepEqual(out.providers, ['aws', 'gcp', 'azure']);
  assert.equal(out.pluginsRan, 3);
});

test('scopes to requested providers', async () => {
  _setPluginManager(mockPM());
  const out = await handleScanCloud({ providers: ['aws', 'azure'] });
  assert.deepEqual(out.providers, ['aws', 'azure']);
  assert.equal(out.pluginsRan, 2);
});

test('rejects an unknown provider', async () => {
  _setPluginManager(mockPM());
  await assert.rejects(() => handleScanCloud({ providers: ['aws', 'oracle'] }), /unknown provider 'oracle'/);
});

test('saves + restores CLOUD_PROVIDER around the run', async () => {
  const saved = process.env.CLOUD_PROVIDER;
  process.env.CLOUD_PROVIDER = 'preexisting';
  let sawDuringRun = null;
  _setPluginManager({
    plugins: [{ id: '1', cloudProvider: 'aws' }],
    runCloud: async () => { sawDuringRun = process.env.CLOUD_PROVIDER; return { host: 'cloud:aws', results: [], conclusion: null, manifest: [] }; },
  });
  await handleScanCloud({ providers: ['aws'] });
  assert.equal(sawDuringRun, 'aws');
  assert.equal(process.env.CLOUD_PROVIDER, 'preexisting');
  if (saved === undefined) delete process.env.CLOUD_PROVIDER; else process.env.CLOUD_PROVIDER = saved;
});

test('notes a requested provider that has no plugins', async () => {
  _setPluginManager(mockPM({ providers: ['aws'] }));
  const out = await handleScanCloud({ providers: ['aws', 'azure'] });
  assert.ok((out.notes || []).some((n) => n.includes('azure: no cloud plugins available')));
});

test('Enterprise gate denies below enterprise, allows at enterprise', () => {
  _setTier('pro');
  const denied = _requireEnterpriseCapability('scan_cloud');
  assert.ok(denied && denied.isError);
  assert.match(denied.content[0].text, /requires an Enterprise license/);
  _setTier('enterprise');
  assert.equal(_requireEnterpriseCapability('scan_cloud'), null);
  _setTier();
});

test('scan_cloud is registered as a tool handler', () => {
  assert.equal(typeof toolHandlers.scan_cloud, 'function');
});
