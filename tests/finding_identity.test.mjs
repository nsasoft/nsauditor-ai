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

// ── `regionOf` — ONE DERIVATION, APPLIED IDENTICALLY ON BOTH SIDES OF BOTH CHANNELS ─────────
//
// ⚠️ WHAT MAKES A COMPOSITE CHANGE FREE IS NOT THAT A FIELD EXISTS ON BOTH SIDES — it is that
// the SAME function derives the component from whatever each side actually stores. The two sides
// of a comparison are different shapes: the delta compares two loader-shaped runs (both carry
// `region`), while the MTTR tracker compares a raw current finding against a STORED violation,
// and that stored shape has no region at all (3735 violations measured, zero with the field).
// A field present on one side is not a key.
//
// The derivation, in order, and each step's occupancy MEASURED over the 1.1.0 evidence tree's
// 1786 stored violation resources:
//   1. the stored/stamped `region` field        — the steady state
//   2. recovered from a trailing ` [<region>]`  — 124, everything the old stamper decorated
//   3. a STRUCTURED parse (ARN field position)  — 0 occupants today; kept narrow and
//      fixture-proven, never corpus-proven
//   4. null
//
// ⚠️ STEP 3 IS A STRUCTURED PARSE AND NEVER A SCAN, and that is a measurement not a preference.
// A free "find a region-shaped token anywhere in the string" scan matches **562 of the 1786**
// stored resources — `s3:bucket:s3-violator-bucket-522412052794` contains `ator-bucket-52` — and
// every one of those would attribute a fabricated region to a finding, desynchronising the very
// sides this function exists to synchronise.
import { regionOf } from '../utils/finding_identity.mjs';

test('regionOf is the STAMPED FIELD and nothing cleverer', () => {
  assert.equal(regionOf({ region: 'us-east-1', resource: 'x' }), 'us-east-1');
  assert.equal(regionOf({ resource: 'x' }), null);
  assert.equal(regionOf({ region: '', resource: 'x' }), null);
  assert.equal(regionOf(null), null);
});

test('WITHDRAWN BY MEASUREMENT — regionOf must NOT recover a region from a stored violation', () => {
  // ⚠️ THIS LEG ASSERTS AN ABSENCE, and it exists because two richer versions of `regionOf` were
  // specified and both were withdrawn — a recovery from the ` [<region>]` decoration, and a
  // structured parse of an ARN's region field. Measured over all 69,792 stored violations:
  // ZERO carry a region field, ZERO embed a region token (so the ARN parse had no occupant at
  // all), 2,873 carry a suffix, 5,950 are a bare region, and **60,959 can yield no region by any
  // means**. Any composite that carries region on the current side while the prior yields null
  // resets those sixty thousand lifecycles at the upgrade boundary — the repair would have
  // caused a larger instance of the defect it was written to prevent.
  //
  // Region reaches MTTR identity through COMPOSITION NEGOTIATION instead. If someone later
  // "improves" this function to recover a region, that negotiation silently stops being
  // commensurable, so the absence is pinned here rather than left as a comment.
  assert.equal(regionOf({ resource: 'sg-abc [us-east-1]' }), null,
    'recovering from the decoration is WITHDRAWN — the suffix is stripped from the RESOURCE, '
    + 'which is what keeps an old prior equal to a clean current; it is not a region source');
  assert.equal(regionOf({ resource: 'arn:aws:sqs:us-east-1:123456789012:q' }), null,
    'the ARN parse is WITHDRAWN — zero occupants in 69,792 stored violations');
  assert.equal(regionOf({ resource: 's3:bucket:s3-violator-bucket-522412052794' }), null);
  assert.equal(regionOf({ resource: 'us-east-1' }), null,
    'a bare region is the basis-bumped producers\' population, declared and not guessed');
});

// ── THE BOUNDARY, AS TWO-REGION SYNTHETIC PAIRS ─────────────────────────────────────────────
//
// ⚠️ THE CORPUS CANNOT ADJUDICATE THIS AND SAYING SO IS PART OF THE EVIDENCE. The Gate-2 records
// are SINGLE-REGION, so no live artifact can exhibit a cross-region collapse — "0 collapses"
// there is a corpus that cannot fail. Every case below is therefore a synthetic prior/current
// pair asserting BOTH directions at once: equal ACROSS the upgrade boundary (or the repair is a
// mass fabricated remediation) and distinct ACROSS regions (or a per-region scope literal
// collapses and N-1 regions read as removed).
// The two negotiated compositions, modelled here exactly as `mttr_engine` computes them: v1 is
// today's identity and carries NO region; v2 adds it. The composition for a (prior, current)
// pair is chosen by what the PRIOR scan stores, so the sides are commensurable by construction.
const v1 = (v) => `${canonicaliseResource(v.resource ?? null, regionOf(v)) ?? '-'}`;
const v2 = (v) => `${v1(v)}|${regionOf(v) ?? '-'}`;

test('BOUNDARY — an OLD-shaped prior meets a new current under v1: equal, zero churn', () => {
  // The prior stores no region, so the pair is compared under v1 — today's identity exactly.
  // What makes them equal is the suffix STRIP, not any region rescue.
  const priorEast = { resource: 'lambda:function:f [us-east-1]' };          // stored by 0.2.54
  const currEast = { resource: 'lambda:function:f', region: 'us-east-1' };  // emitted after E1
  assert.equal(v1(priorEast), v1(currEast), 'the upgrade must not churn it');
  assert.equal(v1({ resource: 'lambda:function:f [eu-west-2]' }),
    v1({ resource: 'lambda:function:f', region: 'eu-west-2' }));
});

test('BOUNDARY — a NEW prior meets a new current under v2: distinct across regions', () => {
  // Once violations record the field, the pair negotiates v2 and per-region findings separate.
  const currEast = { resource: 'lambda:function:f', region: 'us-east-1' };
  const currWest = { resource: 'lambda:function:f', region: 'eu-west-2' };
  assert.equal(v2(currEast), v2({ resource: 'lambda:function:f', region: 'us-east-1' }));
  assert.notEqual(v2(currEast), v2(currWest), 'two regions stay two findings under v2');
});

test('BOUNDARY — a per-region SCOPE LITERAL across both eras, with the v1 limit stated', () => {
  // `kms:account` is emitted once per region and names no object. Under v1 its regions compare
  // ACCOUNT-WIDE — which is exactly what happens today, so it is a stated limit and not a new
  // defect; the run prints it. Under v2 they separate, from the first scan whose prior records
  // the field, without touching a single one of the ~66 emission sites.
  const pE = { resource: 'kms:account [us-east-1]' }, cE = { resource: 'kms:account', region: 'us-east-1' };
  const cW = { resource: 'kms:account', region: 'eu-west-2' };
  assert.equal(v1(pE), v1(cE), 'old prior vs new current: no churn');
  assert.equal(v1(cE), v1(cW), 'v1 LIMIT: per-region scope findings compare account-wide');
  assert.notEqual(v2(cE), v2(cW), 'v2: a scope literal does NOT collapse per region');
});

test('BOUNDARY — the 60,959: a prior with no region at all is equal under v1 and NOT reset', () => {
  // This is the population the withdrawn ruling would have broken. Under v1 the region is not a
  // component at all, so a prior that can yield none is commensurable by construction.
  assert.equal(v1({ resource: 'iam:user:u' }), v1({ resource: 'iam:user:u', region: 'us-east-1' }));
  assert.equal(v1({ resource: 'arn:aws:sqs:us-east-1:123456789012:q' }),
    v1({ resource: 'arn:aws:sqs:us-east-1:123456789012:q', region: 'us-east-1' }),
    'an embedded region is not decoration and is not stripped — identity is the ARN itself');
});

test('BOUNDARY — GovCloud and EUSC suffixes strip; `[target-1]` is never touched', () => {
  // ⚠️ `eusc-de-east-1` (European Sovereign Cloud) is why the token needed widening — the first
  // shape was derived from a single-region corpus and missed it, which is the same
  // corpus-cannot-fail limit this block opens with, one level down.
  assert.equal(v1({ resource: 'x [us-gov-west-1]' }), 'x');
  assert.equal(v1({ resource: 'sg-abc [eusc-de-east-1]' }), 'sg-abc');
  assert.equal(v1({ resource: 'y [ap-southeast-2]' }), 'y');
  assert.equal(v1({ resource: 'z [cn-north-1]' }), 'z');
  assert.equal(v1({ resource: 'res [target-1]' }), 'res [target-1]',
    'not a region: identity is left whole');
});

// ── THE SECOND PLACE THE DECORATION LIVED ───────────────────────────────────────────────────
import { shapeFinding } from '../utils/report_inputs.mjs';

test('the TITLE is derived from the canonical resource — canonicalising the field is not enough', () => {
  // ⚠️ FOUND BY RENDERING A ROW AND READING IT, not by reasoning about the field. `shapeFinding`
  // canonicalises `resource`, but the title is produced by `describeFinding`, which renders the
  // resource INTO the title string. Fed the raw finding, a pre-E1 baseline titled a finding
  // `backup:account [eu-west-2] — …` while a post-E1 run titles the same finding
  // `backup:account — …`.
  //
  // `title` is a component of BOTH the delta's identity key and the finding `id` hash, so the
  // pair read as resolved + new across the upgrade — the exact fabricated churn the
  // canonicaliser exists to prevent, surviving in the one field nobody had looked at. A repair
  // that moves a value has to be checked everywhere that value is REACHABLE, not only where it
  // is stored.
  const pre = shapeFinding('aws', { issues: ['Backup vault policy not enforced'],
    resource: 'backup:account [eu-west-2]', region: 'eu-west-2', severity: 'MEDIUM' }, 1130, 'b');
  const post = shapeFinding('aws', { issues: ['Backup vault policy not enforced'],
    resource: 'backup:account', region: 'eu-west-2', severity: 'MEDIUM' }, 1130, 'b');

  assert.equal(pre.resource, post.resource, 'the field');
  assert.equal(pre.title, post.title, 'and the TITLE, which identity also keys on');
  assert.equal(pre.id, post.id, 'and therefore the id hashed over it');
  assert.ok(!pre.title.includes('[eu-west-2]'), 'no decoration survives into the title');
});

test('a region that is NOT decoration still reaches the title — the strip must not overreach', () => {
  // Fourth quadrant: an ARN embeds its region legitimately and the old stamper never touched it.
  // Stripping it from the title would rename a real object.
  const shaped = shapeFinding('aws', { issues: ['Queue is unencrypted'],
    resource: 'arn:aws:sqs:us-east-1:123456789012:q', region: 'us-east-1', severity: 'HIGH' }, 1150, 'b');
  assert.ok(shaped.title.includes('us-east-1'), 'the ARN keeps its region');
  assert.equal(shaped.resource, 'arn:aws:sqs:us-east-1:123456789012:q');
});
