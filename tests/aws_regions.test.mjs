import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  CANONICAL_REGIONS_BY_PARTITION, CANONICAL_REGION_LIST_VERSION,
  detectPartition, isKnownRegion, regionsForPartition,
} from '../utils/aws_regions.mjs';

test('detectPartition keys off the region prefix', () => {
  assert.equal(detectPartition('us-east-1'), 'aws');
  assert.equal(detectPartition('eu-west-2'), 'aws');
  assert.equal(detectPartition('cn-north-1'), 'aws-cn');
  assert.equal(detectPartition('us-gov-west-1'), 'aws-us-gov');
  assert.equal(detectPartition(''), 'aws');
  assert.equal(detectPartition(undefined), 'aws');
});

test('isKnownRegion is true for canonical regions, false for typos', () => {
  assert.equal(isKnownRegion('eu-west-1'), true);
  assert.equal(isKnownRegion('us-gov-east-1'), true);
  assert.equal(isKnownRegion('eu-wist-1'), false);
  assert.equal(isKnownRegion('US-EAST-1'), true); // normalized
});

test('regionsForPartition returns the frozen list', () => {
  assert.ok(regionsForPartition('aws').includes('us-east-1'));
  assert.equal(regionsForPartition('aws-cn').length, 2);
  assert.equal(regionsForPartition('bogus').length, 0);
  assert.ok(Object.isFrozen(regionsForPartition('bogus')));
});

test('version stamp present', () => {
  assert.match(CANONICAL_REGION_LIST_VERSION, /^\d{4}-\d{2}$/);
  assert.ok(Object.isFrozen(CANONICAL_REGIONS_BY_PARTITION));
});
