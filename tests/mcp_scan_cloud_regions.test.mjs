import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildScanCloudRegionIntent } from '../mcp_server.mjs';

test('regions ["all"] → kind all', () => {
  assert.deepEqual(buildScanCloudRegionIntent(['all']), { kind: 'all', explicit: true });
});
test('regions list → kind list', () => {
  assert.deepEqual(buildScanCloudRegionIntent(['us-east-1', 'eu-west-1']),
    { kind: 'list', regions: ['us-east-1', 'eu-west-1'], explicit: true });
});
test('omitted regions → null (divergent default: env-or-single, NOT all)', () => {
  assert.equal(buildScanCloudRegionIntent(undefined), null);
});
test('unknown region rejected', () => {
  assert.throws(() => buildScanCloudRegionIntent(['eu-wist-1']), /unknown AWS region/);
});
