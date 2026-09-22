// SCOPE-NOT-SCANNED — a finding outside the OTHER run's recorded coverage is not comparable.
//
// ⚠️ THIS EXISTS BECAUSE THE DELTA CALLED A REAL, UNREMEDIATED GAP "RESOLVED" ON A LIVE RUN.
// Measured 2026-09-21 over two full AWS passes differing ONLY in `--aws-region`
// (`us-east-1,eu-west-1` then `us-east-1`): `1 new · 9 resolved · …`, and EIGHT of the nine
// resolved rows named `eu-west-1` explicitly — `AWS GuardDuty is NOT ENABLED in region
// 'eu-west-1'`, `Inspector2 is DISABLED …`, `EC2 account default EBS encryption is DISABLED in
// eu-west-1`, two SES rows. **Nothing was remediated. The scan stopped looking.** A client-facing
// delta asserted that GuardDuty had been switched on.
//
// ⚠️ AND IT NEEDS NO FAULT AT ALL, which is what makes it worse than the timeout case: narrowing
// a follow-up scan's region is a NORMAL, documented operator action. The run record carried no
// scope field and `NOT_COMPARABLE_REASONS` had no scope reason, so nothing in the chain could
// tell "we fixed it" from "we did not look".
//
// The unit is per PROVIDER, because each provider resolves a different coverage unit: AWS a set
// of REGIONS (carried per finding as `f.region`), Azure a SUBSCRIPTION and GCP a PROJECT (carried
// by the host as a whole, so they govern every finding of that host).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildScanDelta } from '../utils/scan_delta.mjs';

const run = (id, over = {}) => ({
  schema: 1, runId: id, startedAt: '2026-09-21T00:00:00Z', finishedAt: '2026-09-21T01:00:00Z',
  hostsRequested: ['aws'], hostsWritten: [{ host: 'aws', dir: 'd' }],
  pluginsRequested: ['1200'], portsRequested: null,
  tier: 'enterprise', ceVersion: '0.2.55', eeVersion: '1.1.0',
  kevLoaded: false, kevSnapshot: null, epssLoaded: false, epssSnapshot: null, ...over,
});
const aws = (regions) => ({ aws: { unit: 'region', scanned: regions } });
const f = (over = {}) => ({ host: 'aws', plugin: '1200', title: 'GuardDuty is NOT ENABLED',
  severity: 'high', resource: 'guardduty:account', ...over });

// ── FOURTH QUADRANT FIRST: the cases the new reason must NEVER touch ────────────────────────
// Written before the defect legs deliberately. The defect is "a narrowed scope reads as
// remediation", so the leg that rots into decoration is the one asserting that an UNCHANGED
// scope still compares normally — every incident-born fixture satisfies the defect leg, and a
// rule that fires on identical scopes would make every honest delta not-comparable.

test('ACCEPT — IDENTICAL recorded scopes compare exactly as before: a real fix is still resolved', () => {
  const d = buildScanDelta({
    baseline: { record: run('A', { scopeScanned: aws(['us-east-1', 'eu-west-1']) }),
      findings: [f({ region: 'eu-west-1' })], pluginStatus: [] },
    current: { record: run('B', { scopeScanned: aws(['us-east-1', 'eu-west-1']) }),
      findings: [], pluginStatus: [] },
  });
  assert.equal(d.resolved.length, 1, 'the region WAS scanned in both runs, so this is remediation');
  assert.deepEqual(d.notComparable, [], 'an unchanged scope must produce no scope row at all');
});

test('ACCEPT — a finding INSIDE both scopes that persists is unchanged, not not-comparable', () => {
  const d = buildScanDelta({
    baseline: { record: run('A', { scopeScanned: aws(['us-east-1']) }),
      findings: [f({ region: 'us-east-1' })], pluginStatus: [] },
    current: { record: run('B', { scopeScanned: aws(['us-east-1']) }),
      findings: [f({ region: 'us-east-1' })], pluginStatus: [] },
  });
  assert.equal(d.unchanged.length, 1);
  assert.deepEqual(d.notComparable, []);
});

test('ACCEPT — NEITHER record carries the field: the rule does not fire (two pre-fix records)', () => {
  // Every record written before this change lacks the field. The rule must be silent there, or
  // the first delta after upgrading turns every historical comparison into a wall of rows.
  const d = buildScanDelta({
    baseline: { record: run('A'), findings: [f({ region: 'eu-west-1' })], pluginStatus: [] },
    current: { record: run('B'), findings: [], pluginStatus: [] },
  });
  assert.equal(d.notComparable.filter((r) => r.reason === 'scope-not-scanned').length, 0,
    'absent on BOTH sides is not evidence of a scope change');
});

// ── THE DEFECT LEGS — the live rows, in both directions ─────────────────────────────────────

test('a NARROWED scope never yields `resolved` — the eu-west-1 row from the live pair', () => {
  const d = buildScanDelta({
    baseline: { record: run('A', { scopeScanned: aws(['us-east-1', 'eu-west-1']) }),
      findings: [f({ region: 'eu-west-1' })], pluginStatus: [] },
    current: { record: run('B', { scopeScanned: aws(['us-east-1']) }),
      findings: [], pluginStatus: [] },
  });
  assert.deepEqual(d.resolved, [], 'GuardDuty was not switched on; the scan stopped looking');
  assert.equal(d.notComparable.length, 1);
  assert.equal(d.notComparable[0].reason, 'scope-not-scanned');
  assert.match(d.notComparable[0].detail, /eu-west-1/, 'the detail must name the UNIT, not just the provider');
});

test('a WIDENED scope never yields `new` — the same rule, other direction', () => {
  const d = buildScanDelta({
    baseline: { record: run('A', { scopeScanned: aws(['us-east-1']) }), findings: [], pluginStatus: [] },
    current: { record: run('B', { scopeScanned: aws(['us-east-1', 'eu-west-1']) }),
      findings: [f({ region: 'eu-west-1' })], pluginStatus: [] },
  });
  assert.deepEqual(d.newFindings, [], 'a region we simply had not looked at is not a NEW exposure');
  assert.equal(d.notComparable.length, 1);
  assert.equal(d.notComparable[0].reason, 'scope-not-scanned');
});

test('a baseline with NO field and a current WITH one fails CLOSED for findings carrying the unit', () => {
  // The one-time cost of the upgrade, stated rather than hidden: the first delta across it cannot
  // know what the old run covered, so a regional finding cannot be called resolved.
  const d = buildScanDelta({
    baseline: { record: run('A'), findings: [f({ region: 'eu-west-1' })], pluginStatus: [] },
    current: { record: run('B', { scopeScanned: aws(['us-east-1']) }), findings: [], pluginStatus: [] },
  });
  assert.deepEqual(d.resolved, [], 'an unknown baseline scope cannot support a remediation verdict');
  assert.equal(d.notComparable[0].reason, 'scope-not-scanned');
});

test('a CURRENT-side finding against a baseline with NO field is not `new` — the other quadrant', () => {
  // ⚠️ THIS LEG EXISTS BECAUSE A MUTANT SURVIVED THE ONE THAT NAMES THIS BRANCH. Deleting the
  // `!theirEntry` fail-closed branch left all nine legs green: the leg titled "a baseline with NO
  // field … fails CLOSED" puts its finding on the BASELINE side, so `theirs` is the CURRENT run,
  // which HAS the field — the row goes not-comparable through the covered-set MISMATCH and the
  // branch in the title is never reached. The branch's real quadrant is the mirror: a finding on
  // the CURRENT side, with the BASELINE lacking the field. Was its region covered back then?
  // Unknown — so it must not be reported as a new exposure.
  const d = buildScanDelta({
    baseline: { record: run('A'), findings: [], pluginStatus: [] },
    current: { record: run('B', { scopeScanned: aws(['us-east-1', 'eu-west-1']) }),
      findings: [f({ region: 'eu-west-1' })], pluginStatus: [] },
  });
  assert.deepEqual(d.newFindings, [],
    'the baseline scope is unknown, so this cannot be called a NEW exposure');
  assert.equal(d.notComparable[0].reason, 'scope-not-scanned');
});

test('a HOST-CARRIED unit is read from the finding\'s OWN side, never borrowed from the other', () => {
  // ⚠️ A REAL DEFECT, found by an independent seat probing the code rather than the fixtures.
  // For azure/gcp the unit is not on the finding, so it was taken as
  // `mineEntry?.scanned?.[0] ?? theirEntry?.scanned?.[0]` — and when the finding's OWN run
  // recorded no scope, the OTHER run's subscription was borrowed as this finding's unit, making
  // `covered.has(value)` true BY CONSTRUCTION. Measured: a baseline azure finding whose record
  // lacks the field, against a current scoped to `sub-BBB`, read `resolved = 1`. That is exactly
  // the first delta after upgrading, and the baseline may have been a different subscription
  // entirely.
  const azureRun = (id, over = {}) => run(id, { hostsRequested: ['azure'],
    hostsWritten: [{ host: 'azure', dir: 'd' }], pluginsRequested: ['1220'], ...over });
  const d = buildScanDelta({
    baseline: { record: azureRun('A'),
      findings: [f({ host: 'azure', plugin: '1220', region: null, title: 'Storage allows Shared Key auth' })],
      pluginStatus: [] },
    current: { record: azureRun('B', { scopeScanned: { azure: { unit: 'subscription', scanned: ['sub-BBB'] } } }),
      findings: [], pluginStatus: [] },
  });
  assert.deepEqual(d.resolved, [],
    'the baseline recorded no subscription, so this finding cannot be matched against sub-BBB');
  assert.equal(d.notComparable[0].reason, 'scope-not-scanned');
  assert.match(d.notComparable[0].detail, /no subscription scope|not known/,
    'the detail must say the finding\'s OWN side did not record the unit');
});

test('a finding with NO unit is untouched by the rule even when scopes differ', () => {
  // Account-wide findings (`resource: iam:account`, no region) are not regional; the rule must not
  // sweep them in, or a narrowed scope makes the whole account not-comparable.
  const d = buildScanDelta({
    baseline: { record: run('A', { scopeScanned: aws(['us-east-1', 'eu-west-1']) }),
      findings: [f({ region: null, resource: 'iam:account', title: 'Root has no MFA' })], pluginStatus: [] },
    current: { record: run('B', { scopeScanned: aws(['us-east-1']) }), findings: [], pluginStatus: [] },
  });
  assert.equal(d.notComparable.filter((r) => r.reason === 'scope-not-scanned').length, 0,
    'a finding that names no region is not scoped by region');
  assert.equal(d.resolved.length, 1, 'and it is still a genuine remediation');
});

test('AZURE/GCP: the unit governs the whole host, so a different subscription is not comparable', () => {
  const d = buildScanDelta({
    baseline: { record: run('A', { hostsRequested: ['azure'], hostsWritten: [{ host: 'azure', dir: 'd' }],
      scopeScanned: { azure: { unit: 'subscription', scanned: ['sub-AAA'] } } }),
      findings: [f({ host: 'azure', region: null, title: 'Storage account allows Shared Key auth' })], pluginStatus: [] },
    current: { record: run('B', { hostsRequested: ['azure'], hostsWritten: [{ host: 'azure', dir: 'd' }],
      scopeScanned: { azure: { unit: 'subscription', scanned: ['sub-BBB'] } } }),
      findings: [], pluginStatus: [] },
  });
  assert.deepEqual(d.resolved, [], 'a different subscription is a different estate, not a fixed one');
  assert.equal(d.notComparable[0].reason, 'scope-not-scanned');
  assert.match(d.notComparable[0].detail, /sub-AAA|subscription/);
});

test('a DISAGREED scope is an UNKNOWN scope — it fails closed rather than comparing', () => {
  // The resolver memo is keyed on the credential fingerprint; if two keys resolved DIFFERENT sets
  // inside one host's scan, the run has no single coverage and must not be differenced.
  const d = buildScanDelta({
    baseline: { record: run('A', { scopeScanned: { aws: { unit: 'region', scanned: ['us-east-1'], disagreed: true } } }),
      findings: [f({ region: 'us-east-1' })], pluginStatus: [] },
    current: { record: run('B', { scopeScanned: aws(['us-east-1']) }), findings: [], pluginStatus: [] },
  });
  assert.deepEqual(d.resolved, [], 'a run that disagreed with itself about its coverage cannot ground a verdict');
  assert.equal(d.notComparable[0].reason, 'scope-not-scanned');
});
