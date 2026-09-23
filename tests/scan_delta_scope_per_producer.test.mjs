// SITE (iii) — THE RUN-LEVEL REGION SET IS A UNION, AND A UNION IS NOT A PER-PRODUCER STATEMENT.
//
// ⚠️ WHAT THE EXISTING RULE CANNOT SEE. `scopeScanned.aws.scanned` is the union of every region
// ANY plugin resolved in that run (`reportResolvedRegionScope` unions `_resolvedSets`). So a run
// whose record says `['us-east-1','eu-west-1']` may contain a producer that only ever looked at
// `us-east-1` — 1200 resolves regions ONLY under `opts.awsRegionIntent`, and several plugins
// iterate no regions at all. The run-level check then answers "eu-west-1 WAS covered", the
// finding is differenced, and a surface that producer never examined reads as REMEDIATED.
// That is the same defect `scope-not-scanned` was built for, one level of granularity down:
// the union is true about the RUN and false about the PRODUCER.
//
// ⚠️ THE CONSUMER IS BUILT AGAINST A CONTRACT, NOT AGAINST A PRODUCER. `byPlugin` is
// `{ <pluginId>: [regions] }` on the provider's scope entry. How it is POPULATED is a separate
// decision (the id travelling as an explicit resolver argument vs injected at the manager waist);
// this file pins what the delta does with it either way, and every leg builds the record by hand
// so it cannot drift into testing the producer.
import test from 'node:test';
import assert from 'node:assert/strict';
import { buildScanDelta } from '../utils/scan_delta.mjs';

const run = (id, over = {}) => ({
  schema: 1, runId: id, startedAt: '2026-09-21T00:00:00Z', finishedAt: '2026-09-21T01:00:00Z',
  hostsRequested: ['aws'], hostsWritten: [{ host: 'aws', dir: 'd' }],
  pluginsRequested: ['1200', '1020'], portsRequested: null,
  tier: 'enterprise', ceVersion: '0.2.55', eeVersion: '1.1.0',
  kevLoaded: false, kevSnapshot: null, epssLoaded: false, epssSnapshot: null, ...over,
});
/** The provider entry, with an optional per-producer refinement. */
const aws = (regions, byPlugin = undefined) => ({
  aws: { unit: 'region', scanned: regions, ...(byPlugin ? { byPlugin } : {}) },
});
const f = (over = {}) => ({ host: 'aws', plugin: '1200', title: 'GuardDuty is NOT ENABLED',
  severity: 'high', resource: 'guardduty:account', ...over });
const delta = (baseScope, baseFindings, curScope, curFindings) => buildScanDelta({
  baseline: { record: run('A', { scopeScanned: baseScope }), findings: baseFindings, pluginStatus: [] },
  current: { record: run('B', { scopeScanned: curScope }), findings: curFindings, pluginStatus: [] },
});

const BOTH = ['us-east-1', 'eu-west-1'];

// ── FOURTH QUADRANT FIRST ───────────────────────────────────────────────────────────────────
// The defect is "a producer that never looked there reads as remediation", so every
// incident-born fixture has the region ABSENT from the producer's entry. The legs that rot are
// the ones asserting a PRESENT entry still compares — delete the containment check and they are
// the only ones that fail.

test('ACCEPT — the producer DID cover the region: remediation is still reported', () => {
  const d = delta(
    aws(BOTH, { 1200: BOTH }), [f({ region: 'eu-west-1' })],
    aws(BOTH, { 1200: BOTH }), []);
  assert.equal(d.resolved.length, 1,
    'the producing plugin looked at eu-west-1 in BOTH runs, so the finding going away IS a fix — '
    + 'a rule that refused here would make every regional delta silent and the feature pointless');
  assert.deepEqual(d.notComparable, []);
});

test('ACCEPT — NO byPlugin at all (every record written before this shipped) is unchanged', () => {
  // Backward compatibility is not a nicety here: every archived record predates the field, and a
  // rule that treated its absence as "the producer covered nothing" would refuse every historical
  // comparison at once.
  const d = delta(aws(BOTH), [f({ region: 'eu-west-1' })], aws(BOTH), []);
  assert.equal(d.resolved.length, 1, 'absent refinement must fall back to the run-level union');
  assert.deepEqual(d.notComparable, []);
});

test('ACCEPT — byPlugin present for ANOTHER producer, none for this one: falls back, does not refuse', () => {
  // This is the BACKSTOP's territory (a producer that earns no entry because it resolves no
  // regions at all), ruled separately. This rule must not pre-empt it by reading a missing entry
  // as a negative — "I have no statement about this producer" is not "it covered nothing".
  const d = delta(
    aws(BOTH, { 1020: BOTH }), [f({ region: 'eu-west-1' })],
    aws(BOTH, { 1020: BOTH }), []);
  assert.equal(d.resolved.length, 1,
    'an entry for a DIFFERENT plugin says nothing about this one; refusing here would make the '
    + 'rule fire on the absence of information rather than on information');
  assert.deepEqual(d.notComparable, []);
});

// ⚠️ THE MIXED RECORD IS THE ACTUAL UPGRADE SHAPE, and neither leg above is it. Both of those
// have the SAME map-presence on both sides. The first comparison anyone runs across this release
// has a baseline written BEFORE the field existed against a current written after — so the
// fallback has to hold ASYMMETRICALLY, per side, or (iii) declares every regional finding
// not-comparable across the 1.1.0 boundary. That would be the identity declaration's blast radius
// repeated one release later, for a field that is only a REFINEMENT.
test('ACCEPT — pre-(iii) baseline vs post-(iii) current: falls back per side, still comparable', () => {
  const d = delta(
    aws(BOTH), [f({ region: 'eu-west-1' })],          // baseline: no byPlugin, as every 1.0.0 record
    aws(BOTH, { 1200: BOTH }), []);                   // current: refined, and it DID cover the region
  assert.equal(d.resolved.length, 1,
    'the current run\'s producer covered eu-west-1, so the finding going away is a fix; the '
    + 'baseline having no refinement to offer must not make the pair incomparable');
  assert.deepEqual(d.notComparable, []);
});

test('ACCEPT — and the OTHER asymmetry: refined baseline, pre-(iii) current', () => {
  const d = delta(
    aws(BOTH, { 1200: BOTH }), [f({ region: 'eu-west-1' })],
    aws(BOTH), []);                                   // current: no map, so no statement to make
  assert.equal(d.resolved.length, 1,
    'the check reads the OTHER side\'s map, and that side has none — falling back to the '
    + 'run-level union is the only honest reading');
  assert.deepEqual(d.notComparable, []);
});

test('the mixed record still REFUSES when the side that speaks says the producer missed it', () => {
  // The compatibility fallback must not become a blanket exemption: where the other side DOES
  // carry an entry and it lacks the region, the refusal stands regardless of what this side has.
  const d = delta(
    aws(BOTH), [f({ region: 'eu-west-1' })],          // baseline: no map
    aws(BOTH, { 1200: ['us-east-1'] }), []);          // current: speaks, and says it missed it
  assert.equal(d.resolved.length, 0,
    'a fallback keyed on THIS side\'s silence would swallow the other side\'s statement');
  assert.equal(d.notComparable.length, 1);
  assert.match(d.notComparable[0].detail, /1200/);
});

// ── THE DEFECT ──────────────────────────────────────────────────────────────────────────────

test('the OTHER run covered the region, but THIS PRODUCER did not look there', () => {
  // The live shape: 1200 resolves regions only under an explicit intent, so a second pass without
  // one leaves its own coverage at us-east-1 while another plugin still pushes eu-west-1 into the
  // run-level union.
  const d = delta(
    aws(BOTH, { 1200: BOTH }), [f({ region: 'eu-west-1' })],
    aws(BOTH, { 1200: ['us-east-1'] }), []);
  assert.equal(d.resolved.length, 0,
    'the producer never examined eu-west-1 in the other run, so its finding going away is not a '
    + 'fix — this is the union-is-not-a-per-producer-statement defect');
  assert.equal(d.notComparable.length, 1, 'and it must be REPORTED, never silently dropped');
  const [row] = d.notComparable;
  assert.equal(row.reason, 'scope-not-scanned',
    `expected the scope reason; got ${row.reason}`);
  assert.match(row.detail, /eu-west-1/, 'the reason must name the region a reader can act on');
  assert.match(row.detail, /1200/,
    'and the PRODUCER, because the run-level scope says the opposite and a reader comparing the '
    + 'two needs to know which statement this row rests on');
});

test('the same refinement in the OTHER direction — a new finding is not a new exposure', () => {
  const d = delta(
    aws(BOTH, { 1200: ['us-east-1'] }), [],
    aws(BOTH, { 1200: BOTH }), [f({ region: 'eu-west-1' })]);
  assert.equal(d.newFindings.length, 0,
    'the baseline producer never looked at eu-west-1, so a finding appearing there is not new — '
    + 'the symmetric half, and the one an incident fixture never exercises');
  assert.equal(d.notComparable.length, 1);
});

// ── THE CROSS-REPO COUPLING, PINNED ON THE SIDE THAT COULD BREAK IT ─────────────────────────
//
// ⚠️ EE's multi-provider merge (`index.mjs`:370-374) DROPS `byPlugin` when two providers report
// inside one host's scan, keeping only `unit` / `scanned` / `disagreed: true`. That field loss is
// harmless ONLY because this consumer checks `disagreed` BEFORE it reads `byPlugin`, so the
// dropped data is never consulted. A coupling that keeps a field loss harmless has to be pinned
// on the side that could break it: if this ORDER ever moves, a record with no `byPlugin` would be
// read as "no statement about this producer" and every such finding would silently start
// comparing again. EE pins the other half (the merge carries `disagreed: true`); this is the half
// that lives here, and if either moves the failure names the other.
test('COUPLING — `disagreed` is checked BEFORE `byPlugin`, so a dropped map cannot start comparing', () => {
  const d = delta(
    { aws: { unit: 'region', scanned: BOTH, disagreed: true } }, [f({ region: 'eu-west-1' })],
    { aws: { unit: 'region', scanned: BOTH, disagreed: true } }, []);
  assert.equal(d.resolved.length, 0, 'a run that disagreed with itself has no usable scope');
  assert.equal(d.notComparable.length, 1);
  assert.match(d.notComparable[0].detail, /disagreed with itself/i,
    'and the reason must be the DISAGREEMENT, not a per-producer verdict derived from a map that '
    + 'the multi-provider merge did not carry');
});

test('COUPLING FOURTH QUADRANT — without `disagreed` the same record DOES reach the per-producer rule', () => {
  // The control: if this leg ever passes for the same reason as the one above, the order is no
  // longer what makes the first one true and the pin has stopped measuring anything.
  const d = delta(
    aws(BOTH, { 1200: BOTH }), [f({ region: 'eu-west-1' })],
    aws(BOTH, { 1200: ['us-east-1'] }), []);
  assert.equal(d.notComparable.length, 1);
  assert.match(d.notComparable[0].detail, /1200/,
    'the per-producer reason, reached only because `disagreed` was absent');
});

// ── "COVERED NOTHING" IS A STATEMENT, AND IT IS NOT A MISSING ENTRY (EE 1.1.0 build 5, F3) ─────
// Enterprise's 1040 and 1210 now declare the regions they COMPLETED, and when nothing completed they
// declare an EMPTY list: `byPlugin[id] = []`. That must read as "this producer covered no region" —
// refusing every regional row it made — and NOT as the missing entry above, which is "no statement"
// and defers to the run-level union. The two silences look alike and mean opposite things.
test('COVERED NONE — byPlugin[id] = [] refuses that producer\'s regional rows; a MISSING entry still defers', () => {
  const none = delta(aws(BOTH, { 1200: BOTH }), [f({ region: 'eu-west-1' })], aws(BOTH, { 1200: [] }), []);
  assert.equal(none.resolved.length, 0, 'a producer that covered nothing cannot have fixed anything');
  assert.deepEqual(none.notComparable.map((x) => x.reason), ['scope-not-scanned']);
  const missing = delta(aws(BOTH, { 1200: BOTH }), [f({ region: 'eu-west-1' })], aws(BOTH, { 1020: BOTH }), []);
  assert.equal(missing.resolved.length, 1, 'no entry is no statement — the run-level union decides, and it covered eu-west-1');
});

test('COVERED NONE survives the run record\'s persistence — the empty array is written and read back', async () => {
  const fs = await import('node:fs');
  const os = await import('node:os');
  const path = await import('node:path');
  const { writeRunStart, appendHostWritten, readRunRecord, newRunId } = await import('../utils/run_record.mjs');
  const outRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-empty-scope-'));
  try {
    const runId = newRunId();
    await writeRunStart(outRoot, { runId, startedAt: '2026-09-23T00:00:00.000Z', hostsRequested: ['aws'], pluginsRequested: ['1040'] });
    const scope = { unit: 'region', scanned: ['us-east-1'], byPlugin: { 1040: [], 1200: ['us-east-1'] } };
    assert.equal(await appendHostWritten(outRoot, runId, { host: 'aws', dir: 'aws_1', scopeScanned: scope }), true);
    const back = await readRunRecord(outRoot, runId);
    assert.ok(Object.hasOwn(back.scopeScanned.aws.byPlugin, '1040'), 'the empty entry vanished on persistence — it would read as no statement');
    assert.deepEqual(back.scopeScanned.aws.byPlugin['1040'], []);
  } finally { fs.rmSync(outRoot, { recursive: true, force: true }); }
});
