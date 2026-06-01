import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildRegionIntent } from '../utils/region_intent.mjs';

test('"all" → kind all, explicit', () => {
  assert.deepEqual(buildRegionIntent('all'), { kind: 'all', explicit: true });
});
test('csv → kind list with trimmed regions, explicit', () => {
  assert.deepEqual(buildRegionIntent('us-east-1, eu-west-1'),
    { kind: 'list', regions: ['us-east-1', 'eu-west-1'], explicit: true });
});
test('absent (undefined) → null intent (resolver falls back to env/implicit)', () => {
  assert.equal(buildRegionIntent(undefined), null);
});
test('unknown region throws with the valid list', () => {
  assert.throws(() => buildRegionIntent('eu-wist-1'), /unknown AWS region 'eu-wist-1'/);
});
test('unknown region allowed when bypass env set', () => {
  process.env.NSA_AWS_REGION_ALLOW_UNKNOWN = '1';
  try {
    assert.deepEqual(buildRegionIntent('eu-wist-1'),
      { kind: 'list', regions: ['eu-wist-1'], explicit: true });
  } finally { delete process.env.NSA_AWS_REGION_ALLOW_UNKNOWN; }
});
test('value-less flag (true) throws a usage error', () => {
  assert.throws(() => buildRegionIntent(true), /--aws-region requires a value/);
});
