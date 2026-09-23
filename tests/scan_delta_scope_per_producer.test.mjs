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
