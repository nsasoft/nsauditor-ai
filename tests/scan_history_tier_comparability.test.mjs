// E9 — THE TIER THAT PRODUCED A HISTORY LINE IS PART OF WHAT THE LINE MEANS.
//
// `scan_history.jsonl` is a COMPARISON channel: `computeDiff` subtracts two lines and
// `delta_reporter` webhooks the result. Nothing on the line said which TIER produced it, and the
// tiers do not count the same things — Enterprise writes a finding QUEUE that Community never
// produces, and `findingsCount` is derived from the report loader's shaping, which includes it.
//
// So a Community → Pro upgrade reports "+N new findings" on the free webhook the day the queue
// first appears: no estate changed, the COUNTER changed. That is the C10 defect one field over,
// and it is the same shape contract-v1 §5.3 already rules on — a key that keeps its name and
// changes its meaning is DECLARED not comparable, never subtracted.
//
// ⚠️ THE FOURTH-QUADRANT LEGS ARE FIRST AND THEY ARE THE ONES THAT ROT. The defect this guard
// was built from is a tier CHANGE, so the veto leg is exercised by every incident-born fixture
// and the POSITIVE scope — "the same tier still compares", "two tierless lines still compare" —
// is the leg that could be deleted while every other fixture stayed green. A refusal that
// refuses everything is not a guard, it is an outage in the comparison channel.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { recordScan, computeDiff, getLastScan, NOT_COMPARABLE_REASONS } from '../utils/scan_history.mjs';

const line = (over = {}) => ({
  timestamp: '2026-09-21T00:00:00.000Z', host: 'h', servicesCount: 0, openPorts: [], os: null,
  findingsCount: 5, findingsCountBasis: 'loader-shaped-v1', tier: 'enterprise',
  cloudFindingsCount: 0, services: [], ...over,
});

// ── FOURTH QUADRANT, WRITTEN FIRST ──────────────────────────────────────────────────────────
test('SAME tier still compares — the leg that rots if the refusal is written too wide', () => {
  const d = computeDiff(line({ findingsCount: 8 }), line({ findingsCount: 5 }));
  assert.equal(d.findingsNotComparable, false, 'two enterprise lines are commensurable');
  assert.equal(d.newFindings, 3, 'and the delta must still be computed, not refused');
  assert.equal(d.findingsNotComparableReason, null);
});

test('two TIERLESS lines still compare — a customer who has not rescanned keeps a working diff', () => {
  // The same carve-out `findingsCountBasis` already makes for pre-1.1.0 lines: refusing here
  // would break a comparison that works today, for no gain — neither line has the queue.
  const a = line({ findingsCount: 8 }); const b = line({ findingsCount: 5 });
  delete a.tier; delete b.tier;
  const d = computeDiff(a, b);
  assert.equal(d.findingsNotComparable, false);
  assert.equal(d.newFindings, 3);
  // ⚠️ AND THE REASON, which is where a mutant survived: test 1 asserts the reason but drives
  // EQUAL tiers, so it never reaches the both-absent branch. Dropping the carve-out therefore
  // left this diff saying `notComparable: false` and `reason: 'tier-unknown'` together, and
  // every leg stayed green. Each fixture covered half the pair.
  assert.equal(d.findingsNotComparableReason, null);
});

test('INVARIANT: a reason is present exactly when the comparison was refused', () => {
  // The pair above stated as a rule over a driven matrix, so no future branch can desynchronise
  // them in one direction while some fixture covers only the other.
  const tiers = ['enterprise', 'ce', undefined];
  const bases = ['loader-shaped-v1', null];
  for (const ct of tiers) for (const pt of tiers) for (const cb of bases) for (const pb of bases) {
    const cur = line({ findingsCountBasis: cb }); const prev = line({ findingsCountBasis: pb });
    if (ct === undefined) delete cur.tier; else cur.tier = ct;
    if (pt === undefined) delete prev.tier; else prev.tier = pt;
    const d = computeDiff(cur, prev);
    assert.equal(d.findingsNotComparable, d.findingsNotComparableReason !== null,
      `verdict ${d.findingsNotComparable} disagrees with reason ${JSON.stringify(d.findingsNotComparableReason)} `
      + `for tiers ${ct}→${ct} / ${pt} and bases ${cb} / ${pb}`);
    assert.equal(d.findingsNotComparable, d.newFindings === null,
      'and a refused comparison must carry a null delta, never a number');
  }
});

// ── THE VETO ────────────────────────────────────────────────────────────────────────────────
test('a tier CHANGE refuses the subtraction and NAMES why', () => {
  const d = computeDiff(line({ tier: 'enterprise', findingsCount: 52 }),
                        line({ tier: 'ce', findingsCount: 0 }));
  assert.equal(d.findingsNotComparable, true);
  assert.equal(d.newFindings, null, 'null, never 0 — 0 is a claim that nothing changed');
  assert.equal(d.findingsNotComparableReason, 'tier-changed');
  assert.match(d.summary, /not comparable/i);
  assert.match(d.summary, /ce/);
  assert.match(d.summary, /enterprise/);
  assert.doesNotMatch(d.summary, /\+52/, 'the fabricated alarm must not appear anywhere');
});

test('ABSENT-vs-PRESENT tier refuses too — an upgrade is exactly this shape', () => {
  const prev = line({ findingsCount: 0 }); delete prev.tier;
  const d = computeDiff(line({ tier: 'enterprise', findingsCount: 52 }), prev);
  assert.equal(d.findingsNotComparable, true);
  assert.equal(d.newFindings, null);
  assert.equal(d.findingsNotComparableReason, 'tier-unknown');
});

test('a BASIS change still reports as a basis change, not swallowed by the tier leg', () => {
  const d = computeDiff(line({ findingsCountBasis: 'loader-shaped-v1' }),
                        line({ findingsCountBasis: null }));
  assert.equal(d.findingsNotComparable, true);
  assert.equal(d.findingsNotComparableReason, 'basis-changed');
});

test('when BOTH differ the reason is deterministic and both facts are stated', () => {
  const d = computeDiff(line({ tier: 'enterprise', findingsCountBasis: 'loader-shaped-v1' }),
                        line({ tier: 'ce', findingsCountBasis: null }));
  assert.equal(d.findingsNotComparable, true);
  assert.equal(d.findingsNotComparableReason, 'basis-changed', 'basis is the older, wider boundary');
  assert.match(d.summary, /basis/i);
  assert.match(d.summary, /tier/i, 'the tier fact must not be silently dropped');
});

// ── THE RECORDED LINE ───────────────────────────────────────────────────────────────────────
test('recordScan PERSISTS the tier — without it every leg above is unreachable in production', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'e9-'));
  try {
    await recordScan(dir, { host: 'h', findingsCount: 5, findingsCountBasis: 'loader-shaped-v1',
      tier: 'enterprise' });
    const last = await getLastScan(dir, 'h');
    assert.equal(last.tier, 'enterprise');
    await recordScan(dir, { host: 'h2', findingsCount: 1 });
    assert.equal((await getLastScan(dir, 'h2')).tier, null, 'absent tier records null, not undefined');
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

// ── THE DECLARED SET ────────────────────────────────────────────────────────────────────────
test('the reason vocabulary is DECLARED and every member is REACHABLE by driving it', () => {
  // ⚠️ THIS ORACLE IS DRIVEN, NOT A SOURCE REGEX, AND THE FIRST DRAFT WAS THE REGEX. It matched
  // `findingsNotComparableReason = '<literal>'`, which does not describe the code that shipped —
  // the value comes off a ternary chain, so the census saw ONE of three reasons and the leg went
  // red over correct code. Loosening it to "a quoted string near the name" would have been worse:
  // a COMMENT satisfies that, which is the decoration shape this repo keeps finding.
  //
  // So each declared reason must carry an input pair that PRODUCES it. Both directions are fatal
  // and they catch different things: a reason declared with no row is UNREACHABLE vocabulary
  // (nothing can ever emit it, so no consumer's branch for it is live), and a produced reason
  // outside the set is undeclared vocabulary a consumer cannot switch on.
  const REACHES = {
    'basis-changed': [line({ findingsCountBasis: 'loader-shaped-v1' }), line({ findingsCountBasis: null })],
    'tier-changed': [line({ tier: 'enterprise' }), line({ tier: 'ce' })],
    'tier-unknown': [line({ tier: 'enterprise' }), (() => { const p = line(); delete p.tier; return p; })()],
  };
  assert.deepEqual(Object.keys(REACHES).sort(), [...NOT_COMPARABLE_REASONS].sort(),
    'every declared reason needs a row that reaches it, and every row a declaration');
  for (const [reason, [cur, prev]] of Object.entries(REACHES)) {
    const got = computeDiff(cur, prev).findingsNotComparableReason;
    assert.equal(got, reason, `the pair declared for ${reason} produced ${got}`);
    assert.ok(NOT_COMPARABLE_REASONS.includes(got), `${got} is produced but undeclared`);
  }
  // And the comparable path must produce null rather than a string nobody declared.
  assert.equal(computeDiff(line(), line()).findingsNotComparableReason, null);
});

// ── THE REPORTER CARRIES THE DECLARATION OUTWARD ────────────────────────────────────────────
test('a tier refusal REACHES the operator — the webhook fires and the text names the tier', async () => {
  // ⚠️ DRIVEN, not read. The reporter gates on `findingsNotComparable`, and it would be easy to
  // confirm by inspection that the tier refusal sets it — but the whole point of this field is
  // that a refusal must not read as "no change since last scan", and only driving the two gates
  // shows that. `newFindings` is null here, which is FALSY: without the explicit
  // `findingsNotComparable` arm in both gates the diff drops out of each and the operator hears
  // nothing at all. That is the C10 false clean one layer out, now reachable by the tier too.
  const { formatDeltaSummary, hasSignificantChanges } = await import('../utils/delta_reporter.mjs');
  const diff = computeDiff(line({ tier: 'enterprise', findingsCount: 52 }),
                           line({ tier: 'ce', findingsCount: 0 }));
  const report = { newHosts: [], removedHosts: [], hostDiffs: new Map([['h', diff]]) };

  assert.equal(hasSignificantChanges(report), true,
    'a comparison we cannot make is news — it is what tells an operator to rescan');
  const text = formatDeltaSummary(report);
  assert.doesNotMatch(text, /No significant changes detected/,
    'the refusal must never be rendered as "no change", which is the false clean this guards');
  assert.match(diff.summary, /tier/i, 'and the reason must be legible, not just a boolean');
});
