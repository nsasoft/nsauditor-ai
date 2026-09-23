// P2 — cross-run delta ("what changed since the last scan"), Pro/Enterprise.
//
// ⚠️ THIS IS NOT `utils/delta_reporter.mjs`. That module is the FREE CE last-vs-current
// alerting delta on the webhook path (cli.mjs:3000) and stays free and untouched. This is a
// second, finding-level engine across two ARBITRARY run records.
//
// ⚠️ "RESOLVED" IS THE DANGEROUS VERDICT, NOT "NEW". A finding that vanished for any reason
// OTHER than being fixed reads as remediation to a buyer and to an assessor. The whole design
// is the refusal: a finding may be called resolved only if its host, plugin, scope and
// framework enumeration were in scope in BOTH runs — otherwise it goes to NOT-COMPARABLE with
// its reason, never into `resolved` and never silently dropped.
//
// The FOURTH-QUADRANT case is written first, deliberately: the defect this engine exists to
// prevent is the false RESOLVED, so the leg that rots into decoration is the one that keeps a
// non-remediated disappearance OUT of the resolved bucket.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { buildScanDelta } from '../utils/scan_delta.mjs';

const run = (id, over = {}) => ({
  schema: 1, runId: id, startedAt: `2026-09-1${id.length}T00:00:00Z`, finishedAt: `2026-09-1${id.length}T01:00:00Z`,
  hostsRequested: ['10.0.0.1'], hostsWritten: [{ host: '10.0.0.1', dir: 'h1' }],
  pluginsRequested: ['aws-iam'], portsRequested: null,
  tier: 'pro', ceVersion: '0.2.54', eeVersion: '1.0.0',
  kevLoaded: false, kevSnapshot: null, epssLoaded: false, epssSnapshot: null, ...over,
});
const finding = (over = {}) => ({ host: '10.0.0.1', plugin: 'aws-iam', title: 'Root account has no MFA', severity: 'critical', ...over });

// ⚠️ THE GAP RIDES ON A FINDING, AS THE SHIPPED PATH EMITS IT. This fixture used to pass a
// `side.evidenceGaps` array, and that array was NEVER POPULATED BY ANY SHIPPED CALLER — the leg
// it fed was dead from the day it was written, and the fall-through from a dead leg is
// `resolved`. The fixture was the only thing that made the leg look alive, which is precisely the
// class this file's own boundary guard exists for: a fix verified only against fixtures the
// author constructs is verified against the author's idea of the input.
test('a finding that vanished because the scanner LOST PERMISSION is NOT reported resolved', () => {
  const delta = buildScanDelta({
    baseline: { record: run('A'), findings: [finding()], pluginStatus: [] },
    current: {
      record: run('B'),
      findings: [finding({ title: 'Evidence gap: AccessDenied on iam:GetAccountSummary',
        severity: 'info', evidenceGap: true })],
      pluginStatus: [],
    },
  });

  assert.deepEqual(delta.resolved, [],
    'a finding absent only because the current run could not read the resource is NOT remediation');
  assert.equal(delta.notComparable.length, 1, 'it must be reported, never silently dropped');
  assert.equal(delta.notComparable[0].reason, 'evidence-gap');
  assert.match(delta.notComparable[0].detail, /AccessDenied/);
  assert.equal(delta.notComparable[0].title, 'Root account has no MFA');
  // The gap record is SCOPE. It explains the row above; it is not itself a new exposure.
  assert.deepEqual(delta.newFindings, [], 'the gap record must never be bucketed as a finding');
  assert.deepEqual(delta.coverage.gapsInCurrent,
    [{ host: '10.0.0.1', plugin: 'aws-iam', kind: 'recorded-gap',
      reason: 'Evidence gap: AccessDenied on iam:GetAccountSummary' }],
    'and it must be NAMED under coverage, so a reader can find out which surface was unreadable — '
    + 'with its KIND, because a producer declaring a gap and a plugin crashing are different events');
});

test('ACCEPT CASE — a genuinely fixed finding, fully in scope in both runs, IS reported resolved', () => {
  const delta = buildScanDelta({
    baseline: { record: run('A'), findings: [finding()] },
    current: { record: run('B'), findings: [], pluginStatus: [] },
  });

  assert.equal(delta.resolved.length, 1, 'the rule must not be satisfiable by refusing everything');
  assert.equal(delta.resolved[0].title, 'Root account has no MFA');
  assert.deepEqual(delta.notComparable, []);
});

test('a finding on a host that was not scanned this run is NOT resolved', () => {
  const d = buildScanDelta({
    baseline: { record: run('A'), findings: [finding()] },
    current: { record: run('B', { hostsRequested: ['10.0.0.9'], hostsWritten: [{ host: '10.0.0.9', dir: 'h9' }] }), findings: [] },
  });
  assert.deepEqual(d.resolved, []);
  assert.equal(d.notComparable[0].reason, 'host-not-scanned');
});

test('a finding whose plugin did not run this time is NOT resolved', () => {
  const d = buildScanDelta({
    baseline: { record: run('A'), findings: [finding()] },
    current: { record: run('B', { pluginsRequested: ['aws-s3'] }), findings: [] },
  });
  assert.deepEqual(d.resolved, []);
  assert.equal(d.notComparable[0].reason, 'plugin-not-run');
});

test('a control that left the framework ENUMERATION is not a posture change', () => {
  const d = buildScanDelta({
    baseline: { record: run('A'), findings: [finding({ control: '11.5.2' })], frameworkEnumeration: ['11.5.2'] },
    current: { record: run('B'), findings: [], frameworkEnumeration: [] },
  });
  assert.deepEqual(d.resolved, []);
  assert.equal(d.notComparable[0].reason, 'framework-enumeration-changed');
});

test('REFUSES a comparison across the contract-v1 §5.3 findingCount boundary', () => {
  const d = buildScanDelta({
    baseline: { record: run('A', { eeVersion: '0.46.0' }), findings: [finding()] },
    current: { record: run('B', { eeVersion: '1.0.0' }), findings: [] },
  });
  assert.equal(d.comparable, false);
  assert.equal(d.refusal.reason, 'finding-count-semantics-boundary');
  assert.deepEqual(d.resolved, [], 'a refused comparison reports NOTHING as remediated');
  assert.match(d.refusal.detail, /ISSUE count/);
});

test('REFUSES when the baseline chain is broken — an altered baseline makes every verdict unsound', () => {
  const d = buildScanDelta({
    baseline: { record: run('A'), findings: [finding()], integrity: 'chain-broken' },
    current: { record: run('B'), findings: [] },
  });
  assert.equal(d.comparable, false);
  assert.equal(d.refusal.reason, 'baseline-chain-broken');
  assert.deepEqual(d.resolved, []);
});

test('chain-absent still compares, but SAYS SO in the output — not only in the docs', () => {
  const d = buildScanDelta({
    baseline: { record: run('A'), findings: [finding()], integrity: 'chain-absent' },
    current: { record: run('B'), findings: [] },
  });
  assert.equal(d.comparable, true);
  assert.equal(d.resolved.length, 1);
  assert.ok(d.limits.some((l) => /no integrity digest/.test(l)), 'the gap must ride in the report');
});

test('every delta states what its integrity assurance is NOT', () => {
  const d = buildScanDelta({ baseline: { record: run('A'), findings: [] }, current: { record: run('B'), findings: [] } });
  assert.ok(d.limits.some((l) => /NOT tamper-proof/.test(l) && /not non-repudiation/.test(l)));
});

test('a finding that APPEARED only because its plugin is newly in scope is new COVERAGE, not a new exposure', () => {
  const d = buildScanDelta({
    baseline: { record: run('A', { pluginsRequested: ['aws-s3'] }), findings: [] },
    current: { record: run('B'), findings: [finding()] },
  });
  assert.deepEqual(d.newFindings, []);
  assert.equal(d.notComparable[0].reason, 'plugin-not-run');
  assert.equal(d.notComparable[0].direction, 'appeared');
});

test('REFUSES when baseline integrity COULD NOT BE MEASURED — could-not-measure is never a pass', () => {
  const d = buildScanDelta({
    baseline: { record: run('A'), findings: [finding()], integrity: 'chain-unreadable' },
    current: { record: run('B'), findings: [] },
  });
  assert.equal(d.comparable, false, 'an unmeasurable baseline must not silently compare');
  assert.equal(d.refusal.reason, 'baseline-integrity-unmeasurable');
  assert.deepEqual(d.resolved, []);
});

// ⚠️ THE FIXTURE POPULATION WAS THE BLIND SPOT, NOT THE VERIFICATION. Every test above uses ONE
// title — 'Root account has no MFA' — which is the single most singleton finding on the AWS
// surface: one root account per account, the one title that CANNOT collide. Uniqueness was a
// premise every fixture and therefore every mutant shared, so no mutation could reach this class.
// Real cloud findings are inherently multi-resource: the S3 auditor's issue strings carry the
// DEFECT and not the bucket ("No public access block configured…"), and resource identity lives
// in `finding.resource` per contract-v1 §1.1. Found by an independent seat reading the fixtures
// rather than the code.
const s3 = (resource, over = {}) => ({ host: '10.0.0.1', plugin: 'aws-s3', resource, title: 'No public access block configured', severity: 'high', ...over });

test('a NEW exposure on a different resource, sharing a title with a fixed one, is NOT masked', () => {
  const d = buildScanDelta({
    baseline: { record: run('A', { pluginsRequested: ['aws-s3'] }), findings: [s3('bucket-a'), s3('bucket-b'), s3('bucket-c')] },
    current: { record: run('B', { pluginsRequested: ['aws-s3'] }), findings: [s3('bucket-a'), s3('bucket-b'), s3('bucket-d')] },
  });
  assert.equal(d.newFindings.length, 1, 'bucket-d is a new exposure and must be reported');
  assert.equal(d.newFindings[0].resource, 'bucket-d');
  assert.equal(d.resolved.length, 1, 'bucket-c was genuinely fixed');
  assert.equal(d.resolved[0].resource, 'bucket-c');
  assert.equal(d.unchanged.length, 2);
});

test('an ESCALATION between matched findings is reported as CHANGED, not as unchanged', () => {
  const d = buildScanDelta({
    baseline: { record: run('A', { pluginsRequested: ['aws-s3'] }), findings: [s3('bucket-a', { severity: 'medium' })] },
    current: { record: run('B', { pluginsRequested: ['aws-s3'] }), findings: [s3('bucket-a', { severity: 'critical' })] },
  });
  assert.equal(d.changed.length, 1, '"this got worse" is the deliverable of a trend report');
  assert.equal(d.changed[0].from, 'medium');
  assert.equal(d.changed[0].to, 'critical');
  assert.deepEqual(d.resolved, [], 'an escalation is never a resolution plus a new finding');
  assert.deepEqual(d.newFindings, []);
  assert.equal(d.unchanged.length, 0);
});

test('when two findings DO collapse to one identity, the run says a new finding may be MASKED', () => {
  // The collision survives the resource fix: a plugin can emit two issues for ONE resource with
  // the same title and port. Rarer than before, not gone — and a limit nothing drives is a claim
  // about the code that nothing checks. This fixture exists because silencing the limit survived
  // the mutation battery; it was the one probe-bounded survivor of fifteen.
  const dup = () => s3('bucket-a');
  const d = buildScanDelta({
    baseline: { record: run('A', { pluginsRequested: ['aws-s3'] }), findings: [dup(), dup()] },
    current: { record: run('B', { pluginsRequested: ['aws-s3'] }), findings: [dup(), dup()] },
  });
  const masked = d.limits.filter((l) => /MASKED/.test(l));
  assert.equal(masked.length, 1, 'the collapse must be declared, and declared in the dangerous direction');
  assert.match(masked[0], /collapsed to one identity/);
});

// ⚠️ F5 — A LEG THAT CANNOT FIRE IS WORSE THAN AN ABSENT ONE, because it makes the
// five-asymmetry claim FALSE while reading as complete. The framework-enumeration leg was
// guarded by `mine.frameworks && theirs.frameworks && f.control` — all three absent through the
// shipped path (CE ships no compliance data at all: data/compliance is empty, `control` appears
// zero times in report_inputs.mjs, and the view never passed frameworkEnumeration). So the guard
// SHORT-CIRCUITED TO null and the finding fell through to `resolved`.
//
// That direction is the opposite of the `plugin` gap and it is the dangerous one: `plugin`
// missing failed SAFE (a wall of NOT-COMPARABLE, useless but never wrong), while this failed
// OPEN — a finding whose control stopped being enumerated between two runs was reported as
// REMEDIATED in a client-facing artifact. PCI moved 19/9/39 → 19/9/44 in one cycle, so the
// trigger is real and recent. The repo's own answer to an absent oracle is gate:cascade's
// LEG (ii): print NOT EVALUATED, never pass silently.
test('with no framework data, the delta SAYS movement was not evaluated — it never passes silently', () => {
  const d = buildScanDelta({
    baseline: { record: run('A'), findings: [finding()] },
    current: { record: run('B'), findings: [] },
  });
  const note = d.limits.filter((l) => /not evaluated/i.test(l));
  assert.equal(note.length, 1, 'an absent oracle must be declared, not short-circuited');
  assert.match(note[0], /may appear as resolved/i,
    'and it must name the CONSEQUENCE — a reader cannot infer the risk from "not evaluated"');
});

test('when BOTH runs carry framework data the leg still fires — the disclosure did not replace it', () => {
  const d = buildScanDelta({
    baseline: { record: run('A'), findings: [finding({ control: '11.5.2' })], frameworkEnumeration: ['11.5.2'] },
    current: { record: run('B'), findings: [], frameworkEnumeration: [] },
  });
  assert.equal(d.notComparable[0].reason, 'framework-enumeration-changed');
  assert.equal(d.limits.filter((l) => /not evaluated/i.test(l)).length, 0);
});

// ── THE NULL-PRODUCER LEG (T1/G2). Before the loader stamped all five containers, a finding with
// no producer identity fell through `theirs.plugins.has(undefined)` into `plugin-not-run` and
// reported "plugin undefined did not run in the other run" — a sentence that is FALSE about the
// run, attached to a finding whose comparability was never established. The direction was safe;
// the sentence was not, and it reaches the client's report through the basis cell.
//
// ⚠️ THE FOURTH-QUADRANT LEG IS WRITTEN FIRST, below: a finding that DOES carry a producer must
// still reach `resolved`. A veto that fires on everything is not a guard, and the defect this
// rule was born from cannot exercise that direction.
test('a finding with NO producer identity is refused by name, never called plugin-not-run', () => {
  const delta = buildScanDelta({
    baseline: { record: run('A'), findings: [finding({ plugin: null, pluginName: null })] },
    current: { record: run('B'), findings: [] },
  });

  assert.deepEqual(delta.resolved, [], 'comparability was never established, so nothing was remediated');
  assert.equal(delta.notComparable.length, 1);
  assert.equal(delta.notComparable[0].reason, 'producer-unknown',
    'the bucket must name what is missing — `plugin-not-run` asserts something about a run that was never measured');
  assert.doesNotMatch(delta.notComparable[0].detail, /\bnull\b|\bundefined\b/,
    'the detail is rendered into the CLIENT report; it must never print a JavaScript null');
});

test('a finding that DOES carry a producer still reaches resolved — the null leg is not a blanket veto', () => {
  const delta = buildScanDelta({
    baseline: { record: run('A'), findings: [finding()] },
    current: { record: run('B'), findings: [] },
  });
  assert.equal(delta.resolved.length, 1, 'a genuinely fixed finding whose plugin ran in both runs is still resolved');
  assert.equal(delta.notComparable.length, 0);
});

// The producer is rendered into the client's report, so the DETAIL must read as prose while the
// IDENTITY stays the token the run record can be checked against. Both, when they differ.
test('the plugin-not-run detail names the plugin readably AND by the id the record is keyed on', () => {
  const delta = buildScanDelta({
    baseline: { record: run('A', { pluginsRequested: ['003'] }), findings: [finding({ plugin: '003', pluginName: 'Port Scanner' })] },
    current: { record: run('B', { pluginsRequested: ['005'] }), findings: [] },
  });
  assert.equal(delta.notComparable.length, 1);
  assert.equal(delta.notComparable[0].reason, 'plugin-not-run');
  assert.match(delta.notComparable[0].detail, /Port Scanner/, 'a client reads the name, not the id');
  assert.match(delta.notComparable[0].detail, /\(003\)/,
    'and the id travels with it, because the baseline scope line prints `pluginsRequested` — ids');
});

// ── THE OUTCOME VOCABULARY, DECLARED AND DERIVED ────────────────────────────────────────────
// Two surfaces downstream are WRITTEN FROM this vocabulary rather than counted by hand: the CE
// CHANGELOG's "N ways a finding can vanish without being fixed" sentence and SKILL.md's item (2),
// both of which have already shipped a count that disagreed with the code. A constant nobody
// re-derives is prose, so this leg derives the produced set from the module's own source and holds
// it in EQUALITY with the declaration — a new code that forgets the constant fails, and a code
// deleted from the constant while still produced fails too.
test('the declared outcome vocabulary is exactly what the module produces — it cannot rot', async () => {
  const mod = await import('../utils/scan_delta.mjs');
  const { NOT_COMPARABLE_REASONS, REFUSAL_REASONS } = mod;
  const src = fs.readFileSync(new URL('../utils/scan_delta.mjs', import.meta.url), 'utf8');
  // A reason is emitted either as a literal or as a NAMED EXPORT (`reason: IDENTITY_BASIS_CHANGED_REASON`,
  // exported so Enterprise's MTTR engine uses the same value instead of typing it). A named reason
  // is resolved through the module itself — and an identifier that resolves to no string FAILS,
  // because a census that cannot read the source reports on its own blind spot, not on the code.
  const literal = [...src.matchAll(/reason: '([a-z][a-z0-9-]*)'/g)].map((m) => m[1]);
  const named = [...src.matchAll(/reason: ([A-Z][A-Z0-9_]*)\b/g)].map((m) => m[1]);
  const unresolved = named.filter((id) => typeof mod[id] !== 'string');
  assert.deepEqual(unresolved, [], `reason identifiers that resolve to no exported string: ${unresolved.join(', ')}`);
  const produced = [...literal, ...named.map((id) => mod[id])];
  const refusals = [...src.matchAll(/refuse\('([a-z][a-z0-9-]*)'/g)].map((m) => m[1]);

  assert.deepEqual([...new Set(produced)].sort(), [...NOT_COMPARABLE_REASONS].sort(),
    'NOT_COMPARABLE_REASONS no longer matches the reasons this module emits');
  assert.deepEqual([...new Set(refusals)].sort(), [...REFUSAL_REASONS].sort(),
    'REFUSAL_REASONS no longer matches the refusals this module returns');
  // Fourth quadrant: a derivation that finds nothing would satisfy both assertions against empty
  // declarations, and a vocabulary guard over an empty corpus guards nothing.
  assert.ok(produced.length >= 5 && refusals.length >= 4,
    `the derivation found ${produced.length} reasons and ${refusals.length} refusals — too few to be believable; the patterns have drifted from the source`);
});

// ── THE PLUGIN-STATUS VOCABULARY IS CLOSED ──────────────────────────────────────────────────
// The delta treats every status outside NOT_MEASURED_STATUSES as measured, and Enterprise's MTTR
// engine treats one outside MEASURED_STATUS ∪ NOT_MEASURED_STATUSES as UNKNOWN (never closed). Both
// are only safe while the plugin manager assigns no fifth status — so the set it assigns is DERIVED
// from its source and held inside the exported vocabulary, and a new status fails here before
// either consumer silently files it.
test('every status the plugin manager assigns is in the exported vocabulary', async () => {
  const { MEASURED_STATUS, NOT_MEASURED_STATUSES } = await import('../utils/scan_delta.mjs');
  const src = fs.readFileSync(new URL('../plugin_manager.mjs', import.meta.url), 'utf8');
  const assigned = new Set([...src.matchAll(/\bstatus(?: =|:) '([a-z]+)'/g)].map((m) => m[1]));
  const known = new Set([MEASURED_STATUS, ...NOT_MEASURED_STATUSES]);
  assert.deepEqual([...assigned].filter((s) => !known.has(s)), [],
    'the plugin manager assigns a status no consumer knows — add it to the vocabulary and decide what it means');
  // Fourth quadrant: a derivation that finds nothing is vacuously inside any vocabulary.
  assert.deepEqual([...assigned].sort(), [...known].sort(),
    'the derivation no longer finds every status in the vocabulary — the pattern has drifted from the source');
  assert.ok(Object.isFrozen(NOT_MEASURED_STATUSES), 'a shared vocabulary must not be mutable by an importer');
});

// The same discipline for the VIEW's own refusals, added with C9. `VIEW_REFUSAL_REASONS` exists
// so the equality above can stay EXACT rather than being relaxed to a subset check — but a second
// constant is a second thing that can rot, so it gets its own derivation rather than a promise.
test('VIEW_REFUSAL_REASONS is exactly what the VIEW raises and buildScanDelta does not', async () => {
  const { REFUSAL_REASONS, VIEW_REFUSAL_REASONS } = await import('../utils/scan_delta.mjs');
  const view = fs.readFileSync(new URL('../utils/scan_delta_view.mjs', import.meta.url), 'utf8');

  // Every code the view hands to `refusedComparison`, including the ones chosen by a ternary in
  // the argument list — a pattern anchored on `refusedComparison(out, err, '<literal>'` would
  // silently miss those two and report a clean derivation over half the call sites.
  // ⚠️ COMPARISON OPERANDS ARE STRIPPED FIRST, and the first draft of this guard FABRICATED a
  // finding for want of it: site 95 chooses its code with
  // `chain.status === 'chain-broken' ? 'baseline-chain-broken' : …`, so a naive scan of the call
  // text reported the view as raising `chain-broken` — a status value, never a refusal code.
  // A string being COMPARED is not a code being RAISED.
  const calls = [...view.matchAll(/refusedComparison\(([\s\S]*?)\);/g)]
    .map((m) => m[1].replace(/[=!]==\s*'[^']*'/g, ''));
  const raised = new Set(calls.flatMap((c) => [...c.matchAll(/'([a-z][a-z0-9-]*-[a-z0-9-]*)'/g)].map((m) => m[1])));
  assert.ok(raised.size >= 3,
    `the derivation found ${raised.size} view refusals — too few to be believable; the pattern has drifted`);

  const declared = new Set([...REFUSAL_REASONS, ...VIEW_REFUSAL_REASONS]);
  for (const code of raised) {
    assert.ok(declared.has(code), `the view raises "${code}", which neither constant declares`);
  }
  for (const code of VIEW_REFUSAL_REASONS) {
    assert.ok(raised.has(code), `VIEW_REFUSAL_REASONS declares "${code}", which the view never raises`);
    assert.ok(!REFUSAL_REASONS.includes(code),
      `"${code}" is in BOTH constants. The split exists so each derivation can stay exact; a code `
      + 'in both makes the buildScanDelta equality above pass over a refusal that module never returns.');
  }
});
