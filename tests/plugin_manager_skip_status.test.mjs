// Move 2.8 (cheap half) — a plugin that self-skips via a gate returns a skip
// envelope { up:false, skipped:true, findings:[], data:[] } that carries NEITHER
// `timedOut` NOR `error`. Before this fix both manifest classifiers
// (plugin_manager _runOrchestrated + _runCloudPluginsParallel) left such a plugin
// at status 'ran', so a gate-skipped cloud counted toward auditedProviders → an
// "audited, 0 findings" report over a cloud that made ZERO API calls (the CSV /
// --aws-profile / --host-file false-clean the CLOUD_PROVIDER gate widened; see
// tasks/todo.md Move 2.2/2.7/2.8). A skip must classify as 'skipped', not 'ran'.
//
// NB: the STRICT-gate envelope { up:false, data:[evidence('Skipped…')] } (no
// `skipped` flag, returned by 1021/1022) + threading the gate REASON string are
// the non-cheap remainder of Move 2.8 — planned in todo.md, not covered here.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { PluginManager } from '../plugin_manager.mjs';

const SKIP_ENVELOPE = { up: false, skipped: true, findings: [], data: [] };

// ── run() path (_runOrchestrated, network host) ────────────────────────────

test('_runOrchestrated: a { skipped:true } envelope → manifest status "skipped", not "ran"', async () => {
  const { default: PM } = await import('../plugin_manager.mjs');
  const mgr = new PM('/nonexistent');
  mgr.plugins = [{
    id: '950', name: 'Self-Skipping Plugin', priority: 1, requirements: {},
    ports: [0], runStrategy: 'single',
    run: async () => ({ ...SKIP_ENVELOPE }),
  }];
  const { manifest } = await mgr._runOrchestrated('127.0.0.1', mgr.plugins);
  assert.equal(manifest.length, 1);
  assert.equal(manifest[0].status, 'skipped');
});

test('_runOrchestrated: a normal { up:true } run is still "ran" (no false skip)', async () => {
  const { default: PM } = await import('../plugin_manager.mjs');
  const mgr = new PM('/nonexistent');
  mgr.plugins = [{
    id: '951', name: 'Normal Plugin', priority: 1, requirements: {},
    ports: [0], runStrategy: 'single',
    run: async () => ({ up: true, data: [] }),
  }];
  const { manifest } = await mgr._runOrchestrated('127.0.0.1', mgr.plugins);
  assert.equal(manifest[0].status, 'ran');
});

// Pins the `!sawRealRun` guard: a multi-port (per-port) plugin whose run() SKIPS on
// one port but really RUNS on another produces wrappedRuns=[skip, real]. A real audit
// happened, so the manifest must read 'ran', NOT 'skipped' (else a partially-audited
// resource would drop out of auditedProviders — an under-claim). Mutation-proven: flip
// `!sawRealRun`→`true` in the classifier and this assertion goes RED.
test('_runOrchestrated: a skip+real-run MIX (per-port) is "ran", not "skipped"', async () => {
  const { default: PM } = await import('../plugin_manager.mjs');
  const mgr = new PM('/nonexistent');
  mgr.plugins = [{
    id: '952', name: 'Mixed Skip+Run', priority: 1, requirements: {},
    ports: [80, 443], // non-'single' → one run per port
    run: async (_host, port) => (port === 80
      ? { up: false, skipped: true, findings: [], data: [] }
      : { up: true, findings: [], data: [{ evidence: 'real-audit-on-443' }] }),
  }];
  const { manifest } = await mgr._runOrchestrated('127.0.0.1', mgr.plugins);
  assert.equal(manifest.length, 1);
  assert.equal(manifest[0].status, 'ran', 'a real run on any port must keep the plugin "ran"');
  assert.equal(manifest[0].reason, null);
});

// ── cloud path (runCloud → _runCloudPluginsParallel → auditedProviders) ─────

test('runCloud: a self-skipping cloud plugin is NOT counted as audited (the false-clean)', async () => {
  const pm = await PluginManager.create({
    plugins: [{
      id: '9101', name: 'gcp-self-skip', cloudProvider: 'gcp', priority: 50,
      requirements: {}, runStrategy: 'single',
      run: async () => ({ ...SKIP_ENVELOPE }),
    }],
    tier: 'enterprise',
  });
  const out = await pm.runCloud(['gcp']);
  assert.equal(out.manifest[0].status, 'skipped', 'manifest must classify the gate-skip as skipped');
  assert.equal(out.providerStatus.gcp.skipped, 1);
  assert.equal(out.providerStatus.gcp.ran, 0);
  assert.deepEqual(out.auditedProviders, [], 'a skipped provider must NOT appear as audited');
});

test('runCloud: a cloud plugin that actually runs still counts as audited (control)', async () => {
  const pm = await PluginManager.create({
    plugins: [{
      id: '9102', name: 'aws-runs', cloudProvider: 'aws', priority: 50,
      requirements: {}, runStrategy: 'single',
      run: async () => ({ up: true, findings: [], data: [] }),
    }],
    tier: 'enterprise',
  });
  const out = await pm.runCloud(['aws']);
  assert.equal(out.manifest[0].status, 'ran');
  assert.equal(out.providerStatus.aws.ran, 1);
  assert.deepEqual(out.auditedProviders, ['aws']);
});
