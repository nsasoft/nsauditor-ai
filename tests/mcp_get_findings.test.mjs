import { test } from 'node:test';
import assert from 'node:assert/strict';
import { _setTier, _putCloudScan, _resetCloudScanCache, requireEnterpriseCapability } from '../mcp_server.mjs';

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
