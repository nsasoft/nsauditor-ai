import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  _setTier,
  _putCloudScan,
  _getCloudScan,
  _resetCloudScanCache,
  requireEnterpriseCapability,
  handleScanCloud,
  _setPluginManager,
} from '../mcp_server.mjs';

test('get_findings denies CE tier even when an Enterprise scan populated the cache (gate before cache read)', () => {
  _resetCloudScanCache();
  _setTier('enterprise');
  // simulate a scan that already passed the Enterprise gate populating the cache
  _putCloudScan('aws', { scanId: 'scan-1', ts: 1, args: {}, results: [{ id: '1150', result: { findings: [{ severity: 'MEDIUM', details: { category: 'x' } }] } }] });
  _setTier('ce');
  const denied = requireEnterpriseCapability('get_findings');
  assert.ok(denied, 'CE tier must get an enterprise denial for get_findings');
  assert.ok(denied.isError, 'denial is isError:true');
  _setTier();
});

test('a multi-provider scan writes every scanned provider slot under ONE scanId', async () => {
  _resetCloudScanCache();
  _setTier('enterprise');
  _setPluginManager({
    plugins: [
      { id: 'p-aws', cloudProvider: 'aws' },
      { id: 'p-az', cloudProvider: 'azure' },
    ],
    runCloud: async (reqProviders) => {
      const providerStatus = {};
      for (const p of reqProviders) {
        providerStatus[p] = { available: 1, ran: 1, skipped: 0, errored: 0 };
      }
      return {
        host: `cloud:${reqProviders.join('+')}`,
        results: [
          { id: 'p-aws', result: { findings: [{ severity: 'MEDIUM', details: { category: 'a' } }] } },
          { id: 'p-az',  result: { findings: [{ severity: 'HIGH',   details: { category: 'b' } }] } },
        ],
        conclusion: null,
        manifest: [
          { id: 'p-aws', name: 'mock-aws', status: 'ran' },
          { id: 'p-az',  name: 'mock-azure', status: 'ran' },
        ],
        providerStatus,
        auditedProviders: reqProviders,
      };
    },
  });
  const res = await handleScanCloud({ providers: ['aws', 'azure'] });
  assert.ok(res.scanId, 'scan_cloud return carries a scanId');
  assert.equal(_getCloudScan('aws').scanId, res.scanId);
  assert.equal(_getCloudScan('azure').scanId, res.scanId);   // one-to-many: same id on both slots
  assert.equal(_getCloudScan('aws').results.length, 1);      // aws slot holds only aws results
  _setTier();
});
