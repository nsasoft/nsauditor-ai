import { test } from 'node:test';
import assert from 'node:assert/strict';
import { isCloudSentinelHost, scopeSelectionForHost } from '../utils/sentinel_scope.mjs';
import PluginManager from '../plugin_manager.mjs';

function stubPlugin(id, cloudProvider) {
  return {
    id, name: `stub-${id}`, cloudProvider,
    priority: 50,                    // triggers the orchestrated path
    run: async () => ({ findings: [{ id, severity: 'info', title: `ran ${id}` }] }),
  };
}

const PLUGINS = [
  { id: '1020', name: 'AWS S3', cloudProvider: 'aws' },
  { id: '1170', name: 'AWS SG', cloudProvider: 'aws' },
  { id: '1021', name: 'GCP', cloudProvider: 'gcp' },
  { id: '1022', name: 'Azure', cloudProvider: 'azure' },
  { id: '004', name: 'Port Scan' },              // non-cloud (no cloudProvider)
];

test('isCloudSentinelHost recognizes aws/gcp/azure case-insensitively', () => {
  assert.equal(isCloudSentinelHost('aws'), true);
  assert.equal(isCloudSentinelHost('AZURE'), true);
  assert.equal(isCloudSentinelHost('10.0.0.1'), false);
  assert.equal(isCloudSentinelHost(undefined), false);
});

test('host=aws + spec=all → only AWS plugins selected; rest skipped', () => {
  const r = scopeSelectionForHost(PLUGINS, 'aws', 'all');
  assert.equal(r.scoped, true);
  assert.equal(r.provider, 'aws');
  assert.deepEqual(r.selected.map((p) => p.id), ['1020', '1170']);
  assert.deepEqual(r.skipped.map((p) => p.id), ['1021', '1022', '004']);
});

test('host=gcp + spec=all → only GCP plugin', () => {
  const r = scopeSelectionForHost(PLUGINS, 'gcp', 'all');
  assert.deepEqual(r.selected.map((p) => p.id), ['1021']);
});

test('explicit spec (array) on sentinel host → no scoping, returned as-is', () => {
  const r = scopeSelectionForHost(PLUGINS, 'aws', ['1020', '1021']);
  assert.equal(r.scoped, false);
  assert.equal(r.selected.length, PLUGINS.length);
});

test('explicit spec (CSV string) on sentinel host → no scoping', () => {
  const r = scopeSelectionForHost(PLUGINS, 'aws', '1020,1021');
  assert.equal(r.scoped, false);
});

test('non-sentinel host + spec=all → no scoping', () => {
  const r = scopeSelectionForHost(PLUGINS, '10.0.0.1', 'all');
  assert.equal(r.scoped, false);
  assert.equal(r.selected.length, PLUGINS.length);
});

test('PluginManager.run(host=aws, all) executes only AWS-tagged plugins', async () => {
  const plugins = [
    stubPlugin('1020', 'aws'),
    stubPlugin('1021', 'gcp'),
    stubPlugin('1022', 'azure'),
    { id: '004', name: 'port-scan', priority: 10, run: async () => ({ findings: [] }) }, // non-cloud
  ];
  const pm = await PluginManager.create({ plugins });
  const { manifest } = await pm.run('aws', 'all', {});
  const ran = manifest.filter((m) => m.status === 'ran').map((m) => m.id);
  assert.deepEqual(ran, ['1020'], `only AWS plugin should run, got: ${ran}`);
});

test('PluginManager.run(host=aws, explicit list) runs exactly the requested plugins', async () => {
  const plugins = [stubPlugin('1020', 'aws'), stubPlugin('1021', 'gcp')];
  const pm = await PluginManager.create({ plugins });
  const { manifest } = await pm.run('aws', ['1020', '1021'], {});
  const ran = manifest.filter((m) => m.status === 'ran').map((m) => m.id).sort();
  assert.deepEqual(ran, ['1020', '1021']);
});
