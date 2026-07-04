// tests/network_host_cloud_exclusion.test.mjs
//
// BUG2(b) (operator report 2026-07-03): cloud auditor plugins ran during a
// `--host 192.168.1.1` NETWORK scan (three cloud estates audited + folded into
// the host's conclusion). Operator-confirmed contract: cloud auditors run IF AND
// ONLY IF their cloud's sentinel (aws/gcp/azure) is in `--host`. A network host
// must NEVER trigger cloud plugins — not via `--plugins all`, not via ambient
// credentials, and not even via explicit `--plugins 1020`. `--host` is the sole
// cloud-intent signal; credentials-in-env are a capability, not intent.
//
// Fix: plugin_manager.run() excludes every `cloudProvider`-tagged plugin on a
// network host (symmetric with the existing sentinel scoping, which selects TO
// cloudProvider), and threads opts.hostKind so plugins + the EE gate can enforce
// the contract as defense-in-depth.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { excludeMismatchedCloudPlugins } from '../utils/sentinel_scope.mjs';
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
  { id: '1021', name: 'GCP', cloudProvider: 'gcp' },
  { id: '1022', name: 'Azure', cloudProvider: 'azure' },
  { id: '004', name: 'Port Scan' },              // non-cloud (no cloudProvider)
  { id: '1023', name: 'Zero Trust' },            // non-cloud EE plugin (no cloudProvider)
];

// ─── unit: excludeMismatchedCloudPlugins ─────────────────────────────────────

test('excludeMismatchedCloudPlugins on a network host strips ALL cloudProvider-tagged plugins', () => {
  const r = excludeMismatchedCloudPlugins(PLUGINS, '192.168.1.1');
  assert.equal(r.excludedCloud, true);
  assert.equal(r.sentinel, null, 'a network host has no sentinel');
  assert.deepEqual(r.selected.map((p) => p.id), ['004', '1023'], 'only non-cloud plugins survive');
  assert.deepEqual(r.skipped.map((p) => p.id), ['1020', '1021', '1022'], 'all cloud plugins skipped');
});

test('excludeMismatchedCloudPlugins on --host aws keeps aws + non-cloud, strips OTHER clouds (foreign-cloud fold A)', () => {
  const r = excludeMismatchedCloudPlugins(PLUGINS, 'aws');
  assert.equal(r.sentinel, 'aws');
  assert.deepEqual(r.selected.map((p) => p.id), ['1020', '004', '1023'], 'aws + non-cloud survive');
  assert.deepEqual(r.skipped.map((p) => p.id), ['1021', '1022'], 'gcp + azure auditors stripped on --host aws');
});

test('excludeMismatchedCloudPlugins is case-insensitive on the sentinel', () => {
  const r = excludeMismatchedCloudPlugins(PLUGINS, 'GCP');
  assert.deepEqual(r.selected.map((p) => p.id), ['1021', '004', '1023']);
});

test('excludeMismatchedCloudPlugins keeps non-cloud plugins on a hostname target', () => {
  const r = excludeMismatchedCloudPlugins(PLUGINS, 'scanme.example.com');
  assert.deepEqual(r.selected.map((p) => p.id), ['004', '1023']);
});

// ─── integration: pm.run must not dispatch cloud plugins on a network host ────

test('pm.run(network host, all) runs ONLY non-cloud plugins — cloud auditors excluded', async () => {
  const plugins = [
    stubPlugin('1020', 'aws'),
    stubPlugin('1021', 'gcp'),
    stubPlugin('1022', 'azure'),
    { id: '004', name: 'port-scan', priority: 10, run: async () => ({ findings: [] }) },
  ];
  const pm = await PluginManager.create({ plugins });
  const { manifest } = await pm.run('192.168.1.1', 'all', {});
  const ran = manifest.filter((m) => m.status === 'ran').map((m) => m.id);
  assert.deepEqual(ran, ['004'], `only the non-cloud plugin should run on a network host, got: ${ran}`);
});

test('pm.run(network host, EXPLICIT cloud plugin) still SKIPS it — creds/selection are not intent', async () => {
  const plugins = [stubPlugin('1020', 'aws'), { id: '004', name: 'port-scan', priority: 10, run: async () => ({ findings: [] }) }];
  const pm = await PluginManager.create({ plugins });
  const { manifest } = await pm.run('10.0.0.5', ['1020', '004'], {});
  const ran = manifest.filter((m) => m.status === 'ran').map((m) => m.id);
  assert.equal(ran.includes('1020'), false, 'explicit --plugins 1020 on a network host must NOT run the cloud auditor');
  assert.deepEqual(ran, ['004'], 'only the non-cloud plugin runs');
});

test('excluded cloud plugins appear as SKIPPED manifest entries — machine-visible (fold R-5)', async () => {
  const plugins = [stubPlugin('1020', 'aws'), { id: '004', name: 'net', priority: 10, run: async () => ({ findings: [] }) }];
  const pm = await PluginManager.create({ plugins });
  const { manifest } = await pm.run('192.168.1.1', 'all', {});
  const entry = manifest.find((m) => m.id === '1020');
  assert.ok(entry, 'the excluded cloud plugin has a manifest entry (not silently dropped)');
  assert.equal(entry.status, 'skipped');
  assert.match(entry.reason, /cloud auditor|--host aws/i, 'the skip reason names the required sentinel');
  // the non-cloud plugin still ran
  assert.equal(manifest.find((m) => m.id === '004')?.status, 'ran');
});

test('pm.run(host=aws, all) is UNCHANGED — cloud plugins still run on their sentinel', async () => {
  const plugins = [
    stubPlugin('1020', 'aws'),
    stubPlugin('1021', 'gcp'),
    { id: '004', name: 'port-scan', priority: 10, run: async () => ({ findings: [] }) },
  ];
  const pm = await PluginManager.create({ plugins });
  const { manifest } = await pm.run('aws', 'all', {});
  const ran = manifest.filter((m) => m.status === 'ran').map((m) => m.id);
  assert.deepEqual(ran, ['1020'], 'the sentinel path is not regressed by the network exclusion');
});

test('pm.run(host=gcp, EXPLICIT aws plugin) SKIPS the foreign AWS auditor (fold A — no cross-cloud escape hatch)', async () => {
  const plugins = [stubPlugin('1020', 'aws'), stubPlugin('1021', 'gcp')];
  const pm = await PluginManager.create({ plugins });
  const { manifest } = await pm.run('gcp', ['1020', '1021'], {});
  const ran = manifest.filter((m) => m.status === 'ran').map((m) => m.id);
  assert.equal(ran.includes('1020'), false, 'the AWS auditor must NOT run on --host gcp even when explicitly selected');
  assert.deepEqual(ran, ['1021'], 'only the gcp auditor (matching the sentinel) runs');
});

// ─── hostKind threading (defense-in-depth signal to plugins / EE gate) ────────

// ─── fold B: runByName (single-plugin) honors the same contract + threads hostKind ─

test('pm.runByName(cloud plugin, network host) SKIPS it — no single-plugin bypass (fold B)', async () => {
  const pm = await PluginManager.create({ plugins: [stubPlugin('1020', 'aws')] });
  const r = await pm.runByName('1020', '192.168.1.1', {});
  assert.equal(r?.result?.skipped, true, 'the cloud plugin must be skipped on a network host even via runByName');
});

test('pm.runByName(cloud plugin, its sentinel) RUNS it and threads hostKind=cloud:<provider> (fold B)', async () => {
  let seenHostKind = 'UNSET';
  const spy = { id: '1020', name: 'aws', cloudProvider: 'aws',
    run: async (h, p, opts) => { seenHostKind = opts?.hostKind; return { findings: [] }; } };
  const pm = await PluginManager.create({ plugins: [spy] });
  await pm.runByName('1020', 'aws', {});
  assert.equal(seenHostKind, 'cloud:aws', 'runByName threads hostKind=cloud:aws on the sentinel host');
});

test('pm.run threads opts.hostKind = "network" | "cloud:<provider>" to plugins', async () => {
  const seen = {};
  const spy = (id, cloudProvider) => ({
    id, name: `spy-${id}`, cloudProvider, priority: 50,
    run: async (host, port, opts) => { seen[id] = opts?.hostKind; return { findings: [] }; },
  });
  // network host → the surviving non-cloud plugin sees hostKind='network'
  const pmNet = await PluginManager.create({ plugins: [spy('004', undefined)] });
  await pmNet.run('192.168.1.1', 'all', {});
  assert.equal(seen['004'], 'network', 'non-cloud plugin sees hostKind=network on a network host');

  // sentinel host → the AWS plugin sees hostKind='cloud:aws'
  const pmAws = await PluginManager.create({ plugins: [spy('1020', 'aws')] });
  await pmAws.run('aws', 'all', {});
  assert.equal(seen['1020'], 'cloud:aws', 'aws plugin sees hostKind=cloud:aws on --host aws');
});
