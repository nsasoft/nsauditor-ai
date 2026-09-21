// E1(e1) — ONE CANONICAL `resource`, SHARED BY BOTH COMPARISON CHANNELS.
//
// Two channels identify "the same finding across runs" and they must not derive the noun two
// different ways — that is the C10 defect over again, one noun down:
//   · CE's cross-run delta  (`report --since`) keys on the loader's `resource`
//   · EE's SLA/MTTR tracker (`--compliance-history`) keys on `findingFingerprint`'s `resource`
// An assessor who reads both must not be shown one report calling a finding resolved and another
// calling it unchanged.
//
// What it canonicalises, and ONLY this — the ruled pair, no invented third rule:
//   (1) a trailing ` [<region>]` equal to the finding's OWN region is DECORATION → stripped.
//       `utils/aws_region_scan.mjs::_stampRegion` appended it to every resource that did not
//       already contain the region, so a baseline written by published CE 0.2.54 and a current
//       1.1.0 run must compute the SAME key for the same object.
//   (2) a resource EQUAL to the region is not an object identity at all → null. The same
//       function manufactured this for any finding that omitted a resource, which is how 52
//       findings in one measured run claimed a REGION as the thing they were about.
//
// ⚠️ THE FOURTH-QUADRANT LEGS COME FIRST AND THEY ARE THE ONES THAT ROT. Every fixture born from
// the defect exercises the STRIP, so the leg that could be silently deleted is the one saying
// what must survive untouched — and over-stripping is the worse direction here: it COLLAPSES two
// distinct objects into one key, which is the masking this whole identity lane exists to close.
import test from 'node:test';
import assert from 'node:assert/strict';
import { canonicaliseResource } from '../utils/finding_identity.mjs';

// ── FOURTH QUADRANT: what must survive untouched ────────────────────────────────────────────
test('a plain resource is returned unchanged — the leg that rots if the strip is written wide', () => {
  assert.equal(canonicaliseResource('sg-0def2fbb3db67eae5', 'us-east-1'), 'sg-0def2fbb3db67eae5');
  assert.equal(canonicaliseResource('arn:aws:sqs:us-east-1:1234:q', 'us-east-1'),
    'arn:aws:sqs:us-east-1:1234:q', 'an ARN CONTAINS the region and is still the object id');
});

test('the region appearing INSIDE the name is not decoration', () => {
  // Only a trailing bracketed suffix was ever written by the stamper. A substring rule would
  // mutilate every legitimately region-named bucket.
  assert.equal(canonicaliseResource('my-bucket-us-east-1-logs', 'us-east-1'), 'my-bucket-us-east-1-logs');
  assert.equal(canonicaliseResource('us-east-1-audit-trail', 'us-east-1'), 'us-east-1-audit-trail');
});

test("a suffix naming a DIFFERENT region is not this finding's decoration", () => {
  // The rule is scoped to the finding's OWN region, so a bracketed token that happens to look
  // like a region is left alone unless it is the one this finding was stamped with.
  assert.equal(canonicaliseResource('bucket [eu-west-2]', 'us-east-1'), 'bucket [eu-west-2]');
});

test('a region-QUALIFIED scope literal survives — it is the producer\'s own id, not decoration', () => {
  // E1(c) has the per-region scope findings emit `backup:account:us-east-1` themselves, so that
  // de-suffixing does not collapse one-per-region findings into one. Stripping this would undo
  // the producer-side fix from the consumer side.
  assert.equal(canonicaliseResource('backup:account:us-east-1', 'us-east-1'), 'backup:account:us-east-1');
});

// ⚠️ SUPERSEDED BY MEASUREMENT, AND KEPT AS A RECORD RATHER THAN DELETED. This leg asserted
// "no region means nothing can be decoration", which is what the ruled rule implies — and it was
// written before anyone measured the side that needs the rule most. EE's MTTR tracker rebuilds
// PRIOR fingerprints from stored `scan_compliance_*.json` violations, and that shape has NO
// `region` (3735 violations in the 1.1.0 tree, zero with the field). Under the assertion below
// as originally written, every decorated prior stayed decorated, never matched its clean
// current, and the tracker reported mass remediation that never happened — the exact defect the
// canonicaliser was built to prevent. The region-unknown mode is the repair; what survives of
// the original leg is everything that is NOT region-shaped.
test('no region: only a strict REGION-SHAPED suffix is decoration, nothing else', () => {
  assert.equal(canonicaliseResource('bucket [us-east-1]', null), 'bucket',
    'region-shaped: decoration, because the prior side can never supply a region to compare');
  assert.equal(canonicaliseResource('bucket [us-east-1]', undefined), 'bucket');
  assert.equal(canonicaliseResource('bucket [target-1]', null), 'bucket [target-1]',
    'not region-shaped: identity, and it occurs 32 times in the real records');
});

// ── THE TWO RULED RULES ─────────────────────────────────────────────────────────────────────
test('rule 1 — a trailing ` [region]` equal to the finding\'s own region is stripped', () => {
  assert.equal(canonicaliseResource('sg-0def2fbb3db67eae5 [us-east-1]', 'us-east-1'), 'sg-0def2fbb3db67eae5');
  assert.equal(canonicaliseResource('backup:account [us-east-1]', 'us-east-1'), 'backup:account');
});

test('rule 2 — a resource EQUAL to the region is not an object identity', () => {
  assert.equal(canonicaliseResource('us-east-1', 'us-east-1'), null);
  assert.equal(canonicaliseResource('eu-west-2', 'eu-west-2'), null);
});

test('absent stays absent, and no third rule is invented', () => {
  assert.equal(canonicaliseResource(null, 'us-east-1'), null);
  assert.equal(canonicaliseResource(undefined, 'us-east-1'), null);
  // An EMPTY string is deliberately NOT mapped to null: that is a third rule nobody ruled, over a
  // population nobody measured, and it would move keys for findings this change is not about.
  assert.equal(canonicaliseResource('', 'us-east-1'), '');
  assert.equal(canonicaliseResource(42, 'us-east-1'), null, 'a non-string is not an identity');
});

// ── THE PROPERTY THAT IS THE WHOLE POINT ────────────────────────────────────────────────────
test('IDEMPOTENT, and the 0.2.54 baseline agrees with the 1.1.0 current', () => {
  // The upgrade case stated as an equality: what the PUBLISHED stamper wrote and what the fixed
  // producer writes must canonicalise to the same key, or every de-suffixed finding reads as
  // removed+added on the first post-upgrade delta — a fabricated churn on the headline feature.
  const before = 'sg-0def2fbb3db67eae5 [us-east-1]';   // written by published CE 0.2.54
  const after = 'sg-0def2fbb3db67eae5';                // written after E1(a)
  assert.equal(canonicaliseResource(before, 'us-east-1'), canonicaliseResource(after, 'us-east-1'));
  const once = canonicaliseResource(before, 'us-east-1');
  assert.equal(canonicaliseResource(once, 'us-east-1'), once, 'applying it twice changes nothing');
});

// ── THE REGION-UNKNOWN MODE, AND WHY IT HAD TO EXIST ────────────────────────────────────────
//
// ⚠️ THE RULED RULE — "strip a trailing ` [<r>]` equal to the finding's OWN region" — CANNOT BE
// APPLIED ON THE SIDE THAT NEEDS IT MOST, and that was found by measurement, not by reading.
// EE's MTTR tracker fingerprints PRIOR scans by re-deriving them from each prior scan's stored
// `scan_compliance_*.json` `report.controls[].violations[]`. Measured over the 1.1.0 evidence
// tree: 3735 stored violations, ALL carrying `resource`, and **ZERO carrying `region`** — the
// field is not in that shape. So on the prior side the finding's own region is unknowable, the
// exact rule returns the resource untouched, and a decorated prior (`sg-abc [us-east-1]`,
// written by the published build) never matches a clean current (`sg-abc`). That is the mass
// fabricated-remediation defect the canonicaliser exists to PREVENT, reintroduced by the
// canonicaliser itself.
//
// So when the region is unknown, a trailing bracketed token of strict REGION SHAPE is treated as
// decoration. The shape is tight because the alphabet was DERIVED, not imagined: bracketed
// suffixes in the real records are `[us-east-1]` ×286 — and also `[target-1]` ×32, `[1022]`,
// `[1021]`, `[1030]`, `[1020]` and `[ERROR]`, none of which is region decoration and every one of
// which a loose "strip any trailing bracket" rule would have eaten.
import { canonicaliseResource as canon } from '../utils/finding_identity.mjs';

test('region-unknown: a strict region-shaped suffix is decoration', () => {
  assert.equal(canon('sg-0def2fbb3db67eae5 [us-east-1]', null), 'sg-0def2fbb3db67eae5');
  assert.equal(canon('backup:account [eu-west-2]', null), 'backup:account');
  assert.equal(canon('x [us-gov-west-1]', null), 'x', 'GovCloud is a real region spelling');
});

test('region-unknown: every OTHER bracketed suffix measured in the real records survives', () => {
  // Each of these occurs in the 1.1.0 evidence tree. A loose rule would have destroyed identity
  // for all of them — `[target-1]` alone is 32 findings.
  for (const tok of ['target-1', 'target-2', '1022', '1021', '1030', '1020', 'ERROR']) {
    assert.equal(canon(`res [${tok}]`, null), `res [${tok}]`, `[${tok}] is not region decoration`);
  }
});

test('region-unknown: the UPGRADE EQUALITY holds — this is the whole reason for the mode', () => {
  // Prior side: a violation stored by the published build, no region recorded anywhere.
  // Current side: the same object after E1 stopped the stamper, region known.
  assert.equal(canon('sg-abc [us-east-1]', null), canon('sg-abc', 'us-east-1'));
  assert.equal(canon('backup:account [us-east-1]', null), canon('backup:account', 'us-east-1'));
});

test('region-unknown does NOT resurrect rule 2 — a bare region cannot be judged without one', () => {
  // With no region to compare against, `us-east-1` as a resource is indistinguishable from an
  // object legitimately so named. Refusing to guess is the safe direction: it leaves identity
  // alone rather than nulling it, and the exact rule still fires wherever the region IS known.
  assert.equal(canon('us-east-1', null), 'us-east-1');
});
