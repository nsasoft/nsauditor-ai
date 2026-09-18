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
import { buildScanDelta } from '../utils/scan_delta.mjs';

const run = (id, over = {}) => ({
  schema: 1, runId: id, startedAt: `2026-09-1${id.length}T00:00:00Z`, finishedAt: `2026-09-1${id.length}T01:00:00Z`,
  hostsRequested: ['10.0.0.1'], hostsWritten: [{ host: '10.0.0.1', dir: 'h1' }],
  pluginsRequested: ['aws-iam'], portsRequested: null,
  tier: 'pro', ceVersion: '0.2.54', eeVersion: '1.0.0',
  kevLoaded: false, kevSnapshot: null, epssLoaded: false, epssSnapshot: null, ...over,
});
const finding = (over = {}) => ({ host: '10.0.0.1', plugin: 'aws-iam', title: 'Root account has no MFA', severity: 'critical', ...over });

test('a finding that vanished because the scanner LOST PERMISSION is NOT reported resolved', () => {
  const delta = buildScanDelta({
    baseline: { record: run('A'), findings: [finding()] },
    current: { record: run('B'), findings: [], evidenceGaps: [{ host: '10.0.0.1', plugin: 'aws-iam', reason: 'AccessDenied' }] },
  });

  assert.deepEqual(delta.resolved, [],
    'a finding absent only because the current run could not read the resource is NOT remediation');
  assert.equal(delta.notComparable.length, 1, 'it must be reported, never silently dropped');
  assert.equal(delta.notComparable[0].reason, 'evidence-gap');
  assert.match(delta.notComparable[0].detail, /AccessDenied/);
  assert.equal(delta.notComparable[0].title, 'Root account has no MFA');
});

test('ACCEPT CASE — a genuinely fixed finding, fully in scope in both runs, IS reported resolved', () => {
  const delta = buildScanDelta({
    baseline: { record: run('A'), findings: [finding()] },
    current: { record: run('B'), findings: [], evidenceGaps: [] },
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
