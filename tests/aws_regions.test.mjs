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

// ── ISO partitions: an unrecognised region must not read as COMMERCIAL ───────
// Found in the EE F3 GovCloud/partition lane (2026-08-27) and boarded for this
// paired-trio CE visit. `detectPartition` tested only `cn-` and `us-gov-` and
// then fell through to `return 'aws'`, so every ISO-partition region resolved to
// the commercial partition. The consequence is not cosmetic: plugin 1040 does
// `CANONICAL_REGIONS_BY_PARTITION[partition] || …aws`, so an ISO account's static
// region fallback became the 32 COMMERCIAL regions, and `regionsTotal` in the
// scanScope DISCLOSURE reported a region count that is wrong for that account —
// a disclosure asserting the wrong denominator is worse than none.
//
// ⚠️ WHAT THIS FIX DELIBERATELY DOES NOT DO: enumerate ISO regions. Their ids are
// a datum this repo holds no authority for, and guessing them would put a wrong
// scan SCOPE into the fallback — the silent direction. `regionsForPartition`
// already returns a frozen empty list for an unknown key, so an ISO account gets
// an EMPTY static fallback and the live `DescribeRegions` path (which is correct
// in any partition) remains its only source of truth. Incompleteness costs an
// empty scope and a visible disclosure, never a wrong one.
test('detectPartition: ISO-partition regions are NOT commercial', () => {
  for (const region of ['us-iso-east-1', 'us-iso-west-1', 'us-isob-east-1',
                        'us-isof-south-1', 'eu-isoe-west-1']) {
    const p = detectPartition(region);
    assert.notEqual(p, 'aws', `${region} resolved to the COMMERCIAL partition`);
    assert.equal(regionsForPartition(p).length, 0,
      `${p} must carry an EMPTY static fallback — this repo has no authority for ISO region ids`);
  }
});

test('detectPartition: the partitions it DOES know are unchanged', () => {
  // The fourth quadrant. A prefix rule widened carelessly could reclassify a
  // commercial region, which would break every commercial scan's fallback.
  assert.equal(detectPartition('us-east-1'), 'aws');
  assert.equal(detectPartition('us-west-2'), 'aws');
  assert.equal(detectPartition('eu-west-1'), 'aws');
  assert.equal(detectPartition('us-gov-west-1'), 'aws-us-gov');
  assert.equal(detectPartition('cn-north-1'), 'aws-cn');
  assert.equal(detectPartition(''), 'aws');
  assert.equal(detectPartition(undefined), 'aws');
  // …and a commercial region that merely CONTAINS "iso" is still commercial.
  assert.equal(detectPartition('us-isolated-1'), 'aws');
  assert.equal(regionsForPartition('aws').length > 0, true);
});

test('detectPartition: the European Sovereign Cloud is not commercial either', () => {
  // Third `aws-eusc` recurrence across the F3 lane pair, and the same shape each
  // time: a partition absent from a vocabulary. Here it re-entered the defect the
  // ISO fix had just closed — by MISdetection rather than by fallback, which also
  // bypasses the EE-side repair (plugin 1040 sees partition 'aws', not an unknown
  // one, so its no-cross-partition-fallback guard never engages).
  //
  // Structural like the ISO rule, and derivable: @aws-sdk/util-endpoints'
  // partitions.json gives aws-eusc the regionRegex ^eusc\-(de)\-\w+\-\d+$.
  // regionsForPartition('aws-eusc') already returns the frozen empty list, so the
  // empty-static-fallback discipline is inherited without enumerating a region id.
  assert.equal(detectPartition('eusc-de-east-1'), 'aws-eusc');
  assert.equal(regionsForPartition('aws-eusc').length, 0);
  // Q4: a commercial region that merely starts with "eu" is untouched.
  assert.equal(detectPartition('eu-west-1'), 'aws');
  assert.equal(detectPartition('eu-central-1'), 'aws');
});
