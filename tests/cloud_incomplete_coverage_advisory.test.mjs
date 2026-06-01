import { test } from 'node:test';
import assert from 'node:assert/strict';
import { incompleteCoverageAdvisory } from '../utils/cloud_finding_summary.mjs';

const scope = (over) => ({ source: 'implicit-default', regionsScanned: ['us-east-1'], regionsKnownButNotScanned: ['eu-west-1', 'ap-south-1'], ...over });

test('implicit-default + unscanned enabled regions → advisory fires', () => {
  const a = incompleteCoverageAdvisory(scope());
  assert.ok(a && /2 enabled region/.test(a.text));
  assert.match(a.text, /--aws-region all/);
});
test('explicit flag-list → NO advisory (quiet)', () => {
  assert.equal(incompleteCoverageAdvisory(scope({ source: 'flag-list' })), null);
});
test('env → NO advisory (deliberate)', () => {
  assert.equal(incompleteCoverageAdvisory(scope({ source: 'env' })), null);
});
test('flag-all → NO advisory (full coverage)', () => {
  assert.equal(incompleteCoverageAdvisory(scope({ source: 'flag-all', regionsKnownButNotScanned: [] })), null);
});
test('implicit + DescribeRegions denied (indeterminate) → softer advisory', () => {
  const a = incompleteCoverageAdvisory(scope({ regionsKnownButNotScanned: [], resolveError: 'AccessDenied' }));
  assert.ok(a && /could not be performed|coverage NOT verified/i.test(a.text));
});
