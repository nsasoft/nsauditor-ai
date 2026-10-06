// tests/watch_cycle.test.mjs
// 1.2.1 lane 4, items 4 + 11 — what one --watch cycle reports on stdout and whom it alerts, driven through the REAL
// producer: Community's PluginManager with stub plugins that carry the real SSH and FTP modules (their adapters
// included), the real concluder, and the real scanSingleHost writing into a scratch output root.
//
// THE DEFECT: the watch loop handed buildDeltaReport each host's scanSingleHost output, which carries no services,
// finding count or tier, so every cycle compared two empty summaries — stdout read "No significant changes detected."
// and the webhook gate never opened on a service, version or finding change. scanSingleHost already built the right
// summary for [ScanHistory]; it returns it now, and the cycle compares those.
//
// RULED (Q1–Q5): ONE per-host predicate, hostChanged, for stdout and the webhook; a host whose scan FAILED is reported on
// stdout, counts as changed and does not alert in this release; by default the first cycle establishes the baseline and
// does not alert, while --alert-every-cycle alerts every host with a finding at or above the alert severity on every
// cycle, the first included. A missing summary is NEVER read as an empty one: the naive fix's "N service(s) removed" and
// today's "No changes" are the same false reading in two directions.
//
// Harness: tests/helpers/watch_scan.mjs (the dotenv neutraliser first, a dummy licence key, a scratch output root, a
// documentation-range target, Enterprise held out).
import './helpers/no_operator_dotenv.mjs';
import { watchScan } from './helpers/watch_scan.mjs';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { watchCycle, WATCH_NOT_COMPARABLE } from '../utils/watch_cycle.mjs';
import { severityRank } from '../utils/service_flags.mjs';

const { scan } = await watchScan();
const HIGH = severityRank('High');
const cycle = (...pairs) => new Map(pairs);
const alerted = (r) => r.alerts.map((a) => a.host).sort();

// ── FOURTH QUADRANT FIRST: a cycle where nothing moved stays quiet ─────────────────────────────────────────────────────
test('(fourth quadrant, first) two identical cycles: "No significant changes detected." and nobody is alerted', async () => {
  const h = '203.0.113.10';
  const before = await scan(h, { ftp: true });
  const after = await scan(h, { ftp: true });
  assert.equal(after.scanSummary?.services?.length, 2, 'positive control: the output carries its summary, both services');
  const r = watchCycle(cycle([h, after]), cycle([h, before]), { alertRank: HIGH });
  assert.match(r.text, /No significant changes detected\./);
  assert.match(r.text, new RegExp(`${h}: No changes detected since last scan\\.`));
  assert.deepEqual(r.alerts, [], 'an unchanged host does not alert by default, flagged or not');
});

// ── THE DEFECT ────────────────────────────────────────────────────────────────────────────────────────────────────
test('a version change and a new service are REPORTED — stdout names them, never "No significant changes"', async () => {
  const h = '203.0.113.11';
  const before = await scan(h, { ssh: '8.0' });
  const after = await scan(h, { ssh: '8.9', ftp: false });
  const r = watchCycle(cycle([h, after]), cycle([h, before]), { alertRank: HIGH });
  assert.match(r.text, /1 new service\(s\) detected/);
  assert.match(r.text, /1 service\(s\) changed/);
  assert.doesNotMatch(r.text, /No significant changes detected/);
});

test('a scan that FAILED this cycle is said so and not compared — never "No changes", never "removed"; it does not alert', async () => {
  const h = '203.0.113.12';
  const before = await scan(h, { ftp: true });
  const r = watchCycle(cycle([h, { error: 'connect ETIMEDOUT' }]), cycle([h, before]), { alertRank: HIGH, everyCycle: true });
  assert.match(r.text, new RegExp(`${h}: scan failed this cycle — not compared \\(connect ETIMEDOUT\\)`));
  assert.doesNotMatch(r.text, /No changes detected|No significant changes|removed/);
  assert.equal(r.delta.hostDiffs.get(h).notCompared, 'scan-failed');
  assert.deepEqual(r.alerts, [], 'a failed scan has no findings to send — it does not alert in this release');
});

test('a FAILED baseline: the next good scan is not compared against it', async () => {
  const h = '203.0.113.13';
  const after = await scan(h, { ftp: false });
  const r = watchCycle(cycle([h, after]), cycle([h, { error: 'down' }]), { alertRank: HIGH });
  assert.equal(r.delta.hostDiffs.get(h).notCompared, 'baseline-scan-failed');
  assert.match(r.text, /the previous cycle's scan failed — not compared/);
  assert.doesNotMatch(r.text, /new service\(s\)|No significant changes/);
});

test('a MISSING summary is never read as an empty one — on either side, and with the key absent altogether', async () => {
  const h = '203.0.113.14';
  const good = await scan(h, { ftp: false });
  const nulled = { ...good, scanSummary: null };
  const { scanSummary, ...keyless } = good;
  assert.ok(scanSummary, 'positive control: the real output carried a summary');
  for (const [cur, prev, reason] of [[nulled, good, 'no-summary'], [keyless, good, 'no-summary'], [good, nulled, 'baseline-no-summary']]) {
    const r = watchCycle(cycle([h, cur]), cycle([h, prev]), { alertRank: HIGH });
    assert.equal(r.delta.hostDiffs.get(h).notCompared, reason);
    assert.doesNotMatch(r.text, /removed|No changes detected|No significant changes/, `${reason}: a missing summary read as data`);
  }
});

// ── WHOM IT ALERTS (R4: changed hosts by default, every cycle on request) ─────────────────────────────────────────────
test('by default only a host that CHANGED and has a finding at or above the severity alerts; --alert-every-cycle alerts both', async () => {
  const a = '203.0.113.20';
  const b = '203.0.113.21';
  const prev = cycle([a, await scan(a, { ssh: '8.0', ftp: true })], [b, await scan(b, { ssh: '8.0', ftp: true })]);
  const cur = cycle([a, await scan(a, { ssh: '8.9', ftp: true })], [b, await scan(b, { ssh: '8.0', ftp: true })]);
  const byDefault = watchCycle(cur, prev, { alertRank: HIGH });
  assert.deepEqual(alerted(byDefault), [a]);
  assert.ok(byDefault.alerts[0].findings.some((f) => f.description === 'FTP anonymous login enabled' && f.severity === 'critical'),
    JSON.stringify(byDefault.alerts[0].findings));
  assert.deepEqual(alerted(watchCycle(cur, prev, { alertRank: HIGH, everyCycle: true })), [a, b]);
});

test('a host that changed with a finding only BELOW the severity does not alert at that severity — and does at its own', async () => {
  const h = '203.0.113.22';
  const cur = cycle([h, await scan(h, { ssh: '8.9', weakSsh: true })]);
  const prev = cycle([h, await scan(h, { ssh: '8.0', weakSsh: true })]);
  const r = watchCycle(cur, prev, { alertRank: HIGH });
  assert.match(r.text, /1 service\(s\) changed/, 'positive control: the host did change');
  assert.deepEqual(r.alerts, [], 'a Medium finding does not reach a High threshold');
  const atMedium = watchCycle(cur, prev, { alertRank: severityRank('Medium') });
  assert.deepEqual(atMedium.alerts.map((a) => a.findings.map((f) => f.severity)), [['medium']], 'positive control: the finding is there, graded Medium');
});

test('--alert-every-cycle is a CLI flag: parseArgs reads it, and it is off by default', async () => {
  const { parseArgs } = await import('../cli.mjs');
  const base = ['node', 'cli', 'scan', '--host', '203.0.113.9', '--watch'];
  assert.equal((await parseArgs(base)).alertEveryCycle, false);
  assert.equal((await parseArgs([...base, '--alert-every-cycle'])).alertEveryCycle, true);
});

test('the FIRST cycle establishes the baseline and alerts nobody by default; --alert-every-cycle alerts from the first cycle', async () => {
  const h = '203.0.113.23';
  const first = cycle([h, await scan(h, { ftp: true })]);
  const quiet = watchCycle(first, null, { alertRank: HIGH });
  assert.equal(quiet.delta, null);
  assert.deepEqual(quiet.alerts, []);
  assert.deepEqual(alerted(watchCycle(first, null, { alertRank: HIGH, everyCycle: true })), [h]);
});

test('ONE predicate: stdout and the alert agree on what changed — a not-compared host is a change on stdout too', async () => {
  const h = '203.0.113.24';
  const r = watchCycle(cycle([h, { error: 'down' }]), cycle([h, await scan(h, { ftp: true })]), { alertRank: HIGH });
  assert.doesNotMatch(r.text, /No significant changes detected/, 'a comparison that could not be made is news');
});

test('the not-compared states are a CLOSED set, held two ways against the states the cycle produces', async () => {
  const h = '203.0.113.25';
  const good = await scan(h, { ftp: false });
  const produced = new Set();
  for (const [cur, prev] of [[{ error: 'x' }, good], [good, { error: 'x' }], [{ ...good, scanSummary: null }, good], [good, { ...good, scanSummary: null }]]) {
    produced.add(watchCycle(cycle([h, cur]), cycle([h, prev]), { alertRank: HIGH }).delta.hostDiffs.get(h).notCompared);
  }
  assert.deepEqual([...produced].sort(), [...WATCH_NOT_COMPARABLE].sort());
});

// ── The audit seat's two surviving mutants, each effective by drive ────────────────────────────────────────────────────
test('a FLAG-ONLY change (same version, a weak algorithm newly observed) is a change — and alerts at that finding\'s severity', async () => {
  const { hostChanged } = await import('../utils/delta_reporter.mjs');
  const h = '203.0.113.26';
  const prev = cycle([h, await scan(h, { ssh: '8.0' })]);
  const cur = cycle([h, await scan(h, { ssh: '8.0', weakSsh: true })]);
  const r = watchCycle(cur, prev, { alertRank: severityRank('Medium') });
  const diff = r.delta.hostDiffs.get(h);
  assert.deepEqual([diff.newServices, diff.removedServices, diff.changedServices], [[], [], []], 'positive control: no service moved');
  assert.equal(hostChanged(diff), true, 'the service-check channel alone is a change');
  assert.deepEqual(r.alerts.map((a) => [a.host, a.findings.map((f) => f.severity)]), [[h, ['medium']]]);
});

test('--alert-every-cycle alerts only a host CARRYING a finding at or above the severity — never one with none', async () => {
  const a = '203.0.113.27';
  const b = '203.0.113.28';
  const prev = cycle([a, await scan(a, { ssh: '8.0' })], [b, await scan(b, { ssh: '8.0', ftp: true })]);
  const cur = cycle([a, await scan(a, { ssh: '8.9' })], [b, await scan(b, { ssh: '8.0', ftp: true })]);
  const r = watchCycle(cur, prev, { alertRank: HIGH, everyCycle: true });
  assert.match(r.text, new RegExp(`${a.replace(/\./g, '\\.')}: 1 service\\(s\\) changed`), 'positive control: A changed');
  assert.deepEqual(alerted(r), [b], 'A changed but carries no finding at or above High; B carries one');
});
