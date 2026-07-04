// tests/mcp_probe_service_cloud_gate.test.mjs
//
// M-1 (Mythos review of CE 7000863, ship-blocker): the MCP `probe_service` Pro
// tool dispatches a single plugin via pm._runOne(), which the BUG2(b) fix did
// NOT guard — so a cloud auditor could still audit a cloud estate from a NETWORK
// host via the MCP surface (the exact BUG2(b) class, on the one live route the
// fix missed; the guarded pm.runByName path has zero production callers).
//
// handleProbeService must apply the same cloud-intent contract as run()/runByName:
// a cloud auditor runs IFF the host is its sentinel.

import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { handleProbeService, validateHost, _setPluginManager, _setValidateHost } from '../mcp_server.mjs';

// A mock plugin manager whose _runOne records that it actually dispatched a
// plugin (so the test proves NON-execution by behavior, not by log text).
function makeSpyPm(plugins) {
  const calls = [];
  return {
    calls,
    plugins,
    findPlugin: (nameOrId) => {
      const n = String(nameOrId).toLowerCase();
      return plugins.find((p) => String(p.id).toLowerCase() === n) ||
             plugins.find((p) => String(p.name).toLowerCase() === n) || null;
    },
    _runOne: async (plugin, host, port, opts = {}) => {
      calls.push({ id: plugin.id, host, port, hostKind: opts?.hostKind });
      return { id: plugin.id, name: plugin.name, result: { up: true, data: [] } };
    },
  };
}

const CLOUD_PLUGIN = { id: '1020', name: 'AWS S3 Auditor', cloudProvider: 'aws' };
const NET_PLUGIN = { id: '002', name: 'SSH Scanner' };

// Review re-fold: the M-1 ALLOW path (a cloud plugin on its sentinel via
// probe_service) is only reachable if validateHost lets the bare sentinel name
// through — otherwise the SSRF DNS check rejects 'aws' (ENOTFOUND) before the
// gate. This proves the whitelist with the REAL validateHost (no stub).
describe('validateHost passes cloud sentinels (M-1 ALLOW path reachable in prod)', () => {
  it('returns the sentinel token without DNS resolution', async () => {
    for (const h of ['aws', 'GCP', 'azure']) {
      assert.equal(await validateHost(h), h.toLowerCase(), `${h} must not be rejected as an unresolvable host`);
    }
  });
});

describe('M-1: MCP probe_service honors the cloud-intent contract', () => {
  let pm;
  beforeEach(() => {
    pm = makeSpyPm([CLOUD_PLUGIN, NET_PLUGIN]);
    _setPluginManager(pm);
    _setValidateHost(async (h) => String(h).trim().toLowerCase()); // bypass SSRF guard in tests
  });
  afterEach(() => {
    _setPluginManager(null);
    _setValidateHost(null);
  });

  it('does NOT execute a cloud auditor on a NETWORK host — and rejects loudly', async () => {
    await assert.rejects(
      () => handleProbeService({ host: '192.168.1.1', port: 443, pluginName: '1020' }),
      (err) => /cloud auditor|--host aws|sentinel/i.test(err.message),
      'probe_service must reject a cloud plugin on a network host',
    );
    assert.equal(pm.calls.length, 0, 'the cloud plugin must NOT be dispatched (no _runOne call)');
  });

  it('does NOT execute an AWS auditor on the WRONG cloud sentinel (--host gcp)', async () => {
    await assert.rejects(
      () => handleProbeService({ host: 'gcp', port: 443, pluginName: '1020' }),
      (err) => /cloud auditor|--host aws|aws/i.test(err.message),
    );
    assert.equal(pm.calls.length, 0);
  });

  it('DOES execute a cloud auditor on its OWN sentinel host + threads hostKind', async () => {
    await handleProbeService({ host: 'aws', port: 443, pluginName: '1020' });
    assert.equal(pm.calls.length, 1, 'the AWS plugin runs on --host aws');
    assert.equal(pm.calls[0].id, '1020');
    assert.equal(pm.calls[0].hostKind, 'cloud:aws', 'hostKind threaded into _runOne on the sentinel path');
  });

  it('DOES execute a NON-cloud plugin on a network host (unchanged) + threads hostKind=network', async () => {
    await handleProbeService({ host: '10.0.0.5', port: 22, pluginName: '002' });
    assert.equal(pm.calls.length, 1, 'a network plugin still runs on a network host');
    assert.equal(pm.calls[0].id, '002');
    assert.equal(pm.calls[0].hostKind, 'network');
  });
});
