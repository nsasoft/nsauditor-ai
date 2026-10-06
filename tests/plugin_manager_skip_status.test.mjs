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

// ── B6-4c (1.2.1): "No UDP response" IS NOT A UDP-OPEN PORT ────────────────────────────────────────────────────────────
// The context update read UDP-open from probe_info text with an UNANCHORED pattern, so the port scanner's own NEGATIVE
// row ("No UDP response", status no-response) matched `udp response`, and the SNMP scanner's "No SNMP response for
// community …" matched `snmp response` — at both sites, the generic UDP hint and 007's own branch. A plugin gated on
// `udp_open` then read 'ran' over a silent port. The harmless direction (an extra run, never a false clean), but the
// run status is a claim about the port. A row's own `status` decides when it carries one; otherwise only POSITIVE text.
const UDP_GATED = (id) => ({ id, name: `UDP-gated ${id}`, priority: 50, requirements: { udp_open: [161] },
  ports: [161], runStrategy: 'single', run: async () => ({ up: true, data: [] }) });
async function gatedStatus(emitter) {
  const { default: PM } = await import('../plugin_manager.mjs');
  const mgr = new PM('/nonexistent');
  mgr.plugins = [{ priority: 10, requirements: {}, ports: [0], runStrategy: 'single', ...emitter }, UDP_GATED('955')];
  const { manifest } = await mgr._runOrchestrated('127.0.0.1', mgr.plugins);
  return manifest.find((m) => m.id === '955')?.status;
}
const row = (probe_info, extra = {}) => ({ probe_protocol: 'udp', probe_port: 161, probe_info, response_banner: null, ...extra });
const emits = (id, name, rows, extra = {}) => ({ id, name, run: async () => ({ up: true, data: rows, ...extra }) });

test('(B6-4c, fourth quadrant first) a UDP row that ANSWERED opens the port: the gated plugin runs', async () => {
  assert.equal(await gatedStatus(emits('952', 'Generic UDP Probe', [row('UDP response', { status: 'open' })])), 'ran');
});

test('(B6-4c, fourth quadrant) the port scanner\'s explicit udpOpen still opens it, and 007\'s POSITIVE SNMP answer does too', async () => {
  assert.equal(await gatedStatus(emits('003', 'Port Scanner', [], { udpOpen: [161] })), 'ran');
  assert.equal(await gatedStatus(emits('007', 'SNMP Scanner', [row('SNMP response received: Net-SNMP 5.9 (Type: snmp)')])), 'ran');
});

for (const [label, emitter] of [
  ['the port scanner\'s "No UDP response" (status no-response)', emits('952', 'Generic UDP Probe', [row('No UDP response', { status: 'no-response' })])],
  ['a generic row "No SNMP response for community \\"public\\""', emits('952', 'Generic UDP Probe', [row('No SNMP response for community "public"')])],
  ['007\'s own "No SNMP response for community \\"public\\"" (its branch)', emits('007', 'SNMP Scanner', [row('No SNMP response for community "public"')])],
]) {
  test(`(B6-4c) ${label} does NOT open the port: the gated plugin is skipped, not run`, async () => {
    assert.equal(await gatedStatus(emitter), 'skipped');
  });
}

test('(B6-4c) a row\'s own STATUS decides over its text, in both directions — the structured field is the answer', async () => {
  // Every real negative row is negative in its text too, so without this leg the status branch is decoration: a row
  // reporting `open` with no recognised phrase opens the port, and one reporting `no-response` beside a positive-looking
  // phrase does not.
  assert.equal(await gatedStatus(emits('952', 'Generic UDP Probe', [row('DNS answer received', { status: 'open' })])), 'ran');
  assert.equal(await gatedStatus(emits('952', 'Generic UDP Probe', [row('UDP response (truncated)', { status: 'no-response' })])), 'skipped');
});
