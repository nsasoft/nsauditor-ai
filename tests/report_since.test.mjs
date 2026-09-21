// `report --since` — the entry point that makes the cross-run delta REACHABLE.
//
// ⚠️ WHY THIS FILE EXISTS AT ALL: until a command a customer can run drives the engine, a
// tampered baseline produces output byte-identical to a clean one everywhere a customer can see.
// That is the Class E caveat, and an engine with no entry point is the `recurring_attestation.mjs`
// shape — zero non-test importers while a live page said "shipped".
//
// Fixtures use the REAL writers and the S3 MULTI-RESOURCE shape deliberately: issue text carries
// the DEFECT and not the bucket, which is what made the identity-key defect live rather than
// theoretical. A fixture built on a singleton finding cannot see that class.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { runReport } from '../cli.mjs';
import { resolveCapabilities } from '../utils/capabilities.mjs';
import { newRunId, writeRunStart, appendHostWritten, finalizeRunRecord, runRecordPath } from '../utils/run_record.mjs';
import { sealRunRecord, chainDigestPath } from '../utils/run_chain.mjs';

const s3 = (resource, severity = 'HIGH') => ({ severity, title: 'No public access block configured', port: 443, resource });

// `status` / `omitResult` / `queue` are the knobs the SCOPE legs need: a plugin that ERRORED on a
// host writes a `pluginStatus` row and NO `results` entry, which is exactly how a real envelope
// records "this was attempted and produced nothing".
function writeHostDir(outRoot, dir, runId, findings, { status = 'ran', omitResult = false, queue = null } = {}) {
  fs.mkdirSync(path.join(outRoot, dir), { recursive: true });
  fs.writeFileSync(path.join(outRoot, dir, 'scan_conclusion_raw.json'), JSON.stringify({
    runId, pluginStatus: [{ id: '010', name: 'aws-s3', status, reason: null }],
    results: omitResult ? [] : [{ id: '010', name: 'aws-s3', result: { up: true, findings } }],
  }), 'utf8');
  if (queue) fs.writeFileSync(path.join(outRoot, dir, 'scan_finding_queue.json'), JSON.stringify(queue), 'utf8');
}

async function mkRun(outRoot, { startedAt, findings, seal = true, prevDigest = null,
  writeHost = true, tier = 'pro', status, omitResult, queue }) {
  const runId = newRunId();
  await writeRunStart(outRoot, { runId, startedAt, hostsRequested: ['10.0.0.7'],
    // ⚠️ IDS, because that is what `cli.mjs:3109` writes (`String(p.id ?? '')`). This fixture said
    // `['aws-s3']` — the envelope's DISPLAY NAME — until 2026-09-20, and that one wrong token is
    // what kept G2 invisible: with BOTH sides spelled in the name vocabulary the plugin-scope
    // check matched, so the suite could not tell a working comparison from one that can never
    // match on a real record. A fixture describing a record the product has never written tests
    // the fixture. MEASURED: 7,962 `pluginsRequested` members across 152 real records, zero names.
    pluginsRequested: ['010'], portsRequested: '443', tier,
    ceVersion: '0.2.54', eeVersion: '1.0.0', prevDigest });
  if (writeHost) {
    writeHostDir(outRoot, `d-${runId}`, runId, findings, { status, omitResult, queue });
    await appendHostWritten(outRoot, runId, { host: '10.0.0.7', dir: `d-${runId}` });
  }
  await finalizeRunRecord(outRoot, runId, { finishedAt: startedAt });
  if (seal) await sealRunRecord(outRoot, runId);
  return runId;
}

async function twoRuns({ before, after }) {
  const outRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-since-'));
  const baseline = await mkRun(outRoot, { startedAt: '2026-09-01T10:00:00.000Z', findings: before });
  const current = await mkRun(outRoot, { startedAt: '2026-09-08T10:00:00.000Z', findings: after });
  return { outRoot, baseline, current };
}
const PRO = () => resolveCapabilities('pro');

test('a value-less --since is FATAL, refused by name — a flag that quietly does nothing is the defect', async () => {
  const { outRoot, current } = await twoRuns({ before: [s3('bucket-a')], after: [s3('bucket-a')] });
  const r = await runReport({ from: outRoot, format: 'executive', run: current, since: true }, PRO());
  assert.equal(r.code, 2);
  assert.match(r.stderr, /--since/);
});

test('--since on CE is a LOUD tier refusal — a CE user must never receive an EMPTY delta', async () => {
  const { outRoot, current } = await twoRuns({ before: [s3('bucket-a')], after: [] });
  const r = await runReport({ from: outRoot, format: 'executive', run: current, since: 'prior' }, resolveCapabilities('ce'));
  assert.equal(r.code, 2, 'an empty delta on CE would read as "no change" — a false clean from the licensing layer');
  assert.doesNotMatch(r.stdout, /resolved/i);
});

test('the exit code never encodes WHETHER ANYTHING CHANGED — 0 for no-change and 0 for a new exposure', async () => {
  const quiet = await twoRuns({ before: [s3('bucket-a')], after: [s3('bucket-a')] });
  const noChange = await runReport({ from: quiet.outRoot, format: 'executive', run: quiet.current, since: 'prior' }, PRO());
  const noisy = await twoRuns({ before: [s3('bucket-a')], after: [s3('bucket-a'), s3('bucket-d')] });
  const changed = await runReport({ from: noisy.outRoot, format: 'executive', run: noisy.current, since: 'prior' }, PRO());
  assert.equal(noChange.code, 0);
  assert.equal(changed.code, 0, 'a twelve-new-exposure delta and a quiet one both exit 0; only could-not-measure is non-zero');
});

test('the report NAMES the baseline — id, timestamp and scope — because baseline selection is itself a claim', async () => {
  const { outRoot, baseline, current } = await twoRuns({ before: [s3('bucket-a')], after: [s3('bucket-a')] });
  const r = await runReport({ from: outRoot, format: 'executive', run: current, since: 'prior' }, PRO());
  assert.equal(r.code, 0);
  assert.match(r.stdout, new RegExp(baseline), 'the baseline run id must appear');
  assert.match(r.stdout, /2026-09-01/, 'the baseline timestamp must appear');
  // The scope line prints the record's own `pluginsRequested`, which is the ID vocabulary.
  assert.match(r.stdout, /plugins 010/, 'the baseline scope must appear — a narrow baseline explains a wall of NOT-COMPARABLE');
});

test('a chain-BROKEN baseline refuses, LISTS the verified alternatives, and does NOT auto-fall-back', async () => {
  const outRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-since-'));
  const oldest = await mkRun(outRoot, { startedAt: '2026-09-01T10:00:00.000Z', findings: [s3('bucket-a')] });
  const middle = await mkRun(outRoot, { startedAt: '2026-09-05T10:00:00.000Z', findings: [s3('bucket-a')] });
  const current = await mkRun(outRoot, { startedAt: '2026-09-08T10:00:00.000Z', findings: [] });
  const f = runRecordPath(outRoot, middle);
  const before = fs.readFileSync(f, 'utf8');
  fs.writeFileSync(f, before.replace('10.0.0.7', '10.0.0.8'), 'utf8');   // length-preserving

  const r = await runReport({ from: outRoot, format: 'executive', run: current, since: 'prior' }, PRO());
  // ⚠️ `notEqual(code, 0)` ACCEPTED BOTH 1 AND 2 AND THEREFORE PROVED ONLY "something other than
  // success". runReport's contract makes 2 = REFUSED and 1 = a loadRun refusal for another
  // reason, so the loose form could not tell REFUSED from CRASHED — in a repo whose whole exit
  // doctrine is that 1 and 2 mean different things. This is the most important customer-facing
  // behaviour of the integrity design: a tampered baseline is detected AND NAMED. Detection the
  // customer cannot read is not detection.
  //
  // It survived because the three assertions around it are precise; one loose assertion among
  // tight ones is invisible, because the test reads as rigorous and IS rigorous about the rest.
  assert.equal(r.code, 2, 'a tampered baseline is a REFUSAL (2), not a loadRun failure (1) and not a crash');
  assert.match(r.stderr, /REFUSED: the baseline is chain-broken/,
    'the refusal must NAME the tamper, not merely decline to produce a report');
  assert.doesNotMatch(r.stdout, /resolved/i, 'bucket-a must NOT be reported resolved off a broken baseline');
  assert.match(r.stderr + r.stdout, new RegExp(oldest), 'the operator must be told which earlier records are chain-verified');
  assert.doesNotMatch(r.stdout, new RegExp(`baseline[^\\n]*${oldest}`, 'i'),
    'auto-falling-back to an earlier record silently changes the SUBJECT of the comparison');
});

// ⚠️ THE FIX IN scan_delta.mjs IS DEFEATED AT THE LOADER BOUNDARY UNLESS `resource` IS CARRIED.
// `report_inputs.mjs` normalises a finding to {host, port, severity, title, detail, remediation,
// cves, kev, epss, id} — no `resource`. Every finding arriving through loadRun would therefore
// key on `'-'` and twelve buckets would collapse to one again, with the engine's own identity
// test still green. A producer-frame fix that the consumer frame undoes.
test('loadRun CARRIES `resource`, so the delta can tell two buckets apart through the real loader', async () => {
  const { loadRun } = await import('../utils/report_inputs.mjs');
  const outRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-res-'));
  const runId = await mkRun(outRoot, { startedAt: '2026-09-01T10:00:00.000Z', findings: [s3('bucket-a'), s3('bucket-b')] });
  const loaded = await loadRun(outRoot, { runId, allowPartial: false }, { tier: 'pro' });
  assert.equal(loaded.ok, true, loaded.message);
  const resources = loaded.model.findings.map((f) => f.resource);
  assert.deepEqual(resources.sort(), ['bucket-a', 'bucket-b'],
    'without this the identity key sees two identical findings and a new exposure can be masked');
});

test('NOT-COMPARABLE reaches the operator WITH ITS REASON, never as a bare count', async () => {
  // The survivor that made this test necessary: replacing the per-finding NOT-COMPARABLE lines
  // with a count changed nothing any test observed. A count alone re-creates the defect the whole
  // engine exists to prevent — the reader assumes everything else was comparable, and a finding
  // that vanished because the scanner lost permission reads as remediation. The reasons must
  // travel with the verdict to the surface a human actually reads.
  const outRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-nc-'));
  const baseline = await mkRun(outRoot, { startedAt: '2026-09-01T10:00:00.000Z', findings: [s3('bucket-a')] });
  // The current run scans a DIFFERENT host, so bucket-a is not comparable — it was never looked at.
  const runId = newRunId();
  await writeRunStart(outRoot, { runId, startedAt: '2026-09-08T10:00:00.000Z', hostsRequested: ['10.0.0.9'],
    pluginsRequested: ['010'], portsRequested: '443', tier: 'pro', ceVersion: '0.2.54', eeVersion: '1.0.0' });
  writeHostDir(outRoot, `d-${runId}`, runId, []);
  await appendHostWritten(outRoot, runId, { host: '10.0.0.9', dir: `d-${runId}` });
  await finalizeRunRecord(outRoot, runId, { finishedAt: '2026-09-08T11:00:00.000Z' });
  await sealRunRecord(outRoot, runId);

  const r = await runReport({ from: outRoot, format: 'executive', run: runId, since: baseline }, PRO());
  assert.equal(r.code, 0);
  assert.match(r.stdout, /NOT COMPARABLE/, 'the bucket must be named, not counted');
  assert.match(r.stdout, /host-not-scanned/, 'and its REASON must travel with it');
  assert.doesNotMatch(r.stdout, /1 resolved/, 'it must never be counted as remediation');
});

test('END TO END — the delta reaches the CLIENT ARTIFACT, not just stdout', async () => {
  // A delta that stops at stdout is a developer feature: the paying persona is a consultant whose
  // deliverable is the report they hand their client. If this ever regresses, a release note
  // saying "delta reports" overstates what shipped.
  const outRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-e2e-'));
  const baseline = await mkRun(outRoot, { startedAt: '2026-09-01T10:00:00.000Z', findings: [s3('bucket-c')] });
  const current = await mkRun(outRoot, { startedAt: '2026-09-08T10:00:00.000Z', findings: [] });
  const outFile = path.join(outRoot, 'report.html');

  const r = await runReport({ from: outRoot, format: 'executive', run: current, since: baseline, out: outFile }, PRO());
  assert.equal(r.code, 0, r.stderr);
  const html = fs.readFileSync(outFile, 'utf8');
  assert.match(html, /id="delta"/, 'the delta section must be in the artifact the client receives');
  assert.match(html, /bucket-c/);
  assert.match(html, /chain-verified/, 'and the basis for calling it resolved travels with it');
  assert.match(html, /NOT tamper-proof/, 'and so does what the integrity claim is NOT');
});

test('loadRun CARRIES `plugin` — without it EVERY finding falls to plugin-not-run and the delta is useless', async () => {
  // The same loader-boundary class as `resource`, one field over, and found by the end-to-end
  // test rather than by any unit. Its direction is the SAFE one — nothing is ever falsely called
  // resolved — but the cost is the failure mode the review warned about: a wall of NOT-COMPARABLE
  // that an operator stops reading after the second time. A feature that is never wrong and never
  // useful is still not shipped.
  const { loadRun } = await import('../utils/report_inputs.mjs');
  const outRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-plug-'));
  const runId = await mkRun(outRoot, { startedAt: '2026-09-01T10:00:00.000Z', findings: [s3('bucket-a')] });
  const loaded = await loadRun(outRoot, { runId, allowPartial: false }, { tier: 'pro' });
  assert.equal(loaded.ok, true, loaded.message);
  assert.equal(loaded.model.findings[0].plugin, '010',
    'the producing plugin is part of a finding’s identity and of its comparability, and that identity is the '
    + 'ID — the vocabulary `pluginsRequested` is written in. This asserted the display NAME until 2026-09-20, '
    + 'which is the assertion that PINNED the defect in place: it demanded the one value that can never match.');
  assert.equal(loaded.model.findings[0].pluginName, 'aws-s3',
    'and the display name travels BESIDE it, because the delta renders the producer into the client report');
});

// ════════════════════════════════════════════════════════════════════════════════════════════
// T2 — SCOPE. Four ways a finding can vanish without being fixed that this engine could not see,
// every one of which produced a `resolved` row in the CLIENT HTML when driven. Each leg drives
// `runReport`, never `buildScanDelta`: all four live at a SEAM, and the engine's own module tests
// were green over every one of them. A module-level drive cannot see a seam.
// ════════════════════════════════════════════════════════════════════════════════════════════

const GAP = { severity: 'INFO', title: 'Evidence gap (scan time budget exceeded): 3 of 5 buckets read',
  port: null, resource: null, details: { evidenceGap: true } };

test('SCOPE — a finding that vanished behind a RECORDED EVIDENCE GAP is not resolved, and the gap is not a finding', async () => {
  const outRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-gap-'));
  const baseline = await mkRun(outRoot, { startedAt: '2026-09-01T10:00:00.000Z', findings: [s3('bucket-a')] });
  const current = await mkRun(outRoot, { startedAt: '2026-09-08T10:00:00.000Z', findings: [GAP] });
  const r = await runReport({ from: outRoot, format: 'executive', run: current, since: baseline }, PRO());

  assert.equal(r.code, 0, r.stderr);
  assert.doesNotMatch(r.stdout, /[1-9]\d* resolved/,
    'A FINDING THAT DISAPPEARED BECAUSE THE SCANNER LOST PERMISSION IS NOT FIXED');
  assert.match(r.stdout, /NOT COMPARABLE/);
  assert.match(r.stdout, /evidence-gap/, 'and the reason must travel with it');
  // ⚠️ THE GAP RECORD ITSELF IS SCOPE, NOT A FINDING. Once the loader stamps it with a producer
  // identity it becomes comparable like anything else, so without an exclusion it appears as a NEW
  // EXPOSURE — an INFO row titled "Evidence gap …" in the client's new-findings table.
  assert.doesNotMatch(r.stdout, /[1-9]\d* new/,
    'an evidence-gap record is scope; it must never be reported as a new exposure');
  // ⚠️ THE `new` ASSERTION ABOVE STOPPED DISCRIMINATING THE MOMENT THE GAPS MAP WENT LIVE, and
  // that is worth stating rather than deleting: before the map existed the gap record fell
  // through to `new` (measured — the probe scenario read `1 new · 1 resolved`), but a live map
  // always keys the gap's OWN host|plugin, so the record now catches itself and lands in
  // not-comparable instead. It is kept as the statement of intent and these two take over the
  // discrimination — without them, deleting the bucketing exclusion stays green here.
  assert.equal((r.stdout.match(/NOT COMPARABLE/g) ?? []).length, 1,
    'exactly ONE row — the baseline finding. The gap record is the REASON that row exists; listing '
    + 'it beside the row makes the scanner\'s own blind spot look like a finding it could not compare');
  // ⚠️ ANCHORED ON THE ROW'S SUBJECT, NOT ANYWHERE ON THE LINE. The first draft of this matched
  // `NOT COMPARABLE[^\n]*Evidence gap` and went RED against CORRECT output, because the gap's
  // title is quoted in the REASON of the legitimate row ("… evidence-gap: the other run recorded
  // an evidence gap on 10.0.0.7/aws-s3 (010): Evidence gap (…)"). A loose assertion that fails on
  // right answers is worse than none: the fix for it is to weaken the rule it is guarding.
  assert.doesNotMatch(r.stdout, /NOT COMPARABLE \([a-z]+\)\s+Evidence gap/,
    'a gap belongs under coverage; it must never be the SUBJECT of a findings row');
});

test('SCOPE — a plugin that ERRORED on the host did not measure it, so its baseline findings are not resolved', async () => {
  const outRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-perr-'));
  const baseline = await mkRun(outRoot, { startedAt: '2026-09-01T10:00:00.000Z', findings: [s3('bucket-a')] });
  const current = await mkRun(outRoot, { startedAt: '2026-09-08T10:00:00.000Z', findings: [],
    status: 'error', omitResult: true });
  const r = await runReport({ from: outRoot, format: 'executive', run: current, since: baseline }, PRO());

  assert.equal(r.code, 0, r.stderr);
  assert.doesNotMatch(r.stdout, /[1-9]\d* resolved/,
    'the plugin was attempted and FAILED — "requested" is not "measured", and the envelope says so on pluginStatus');
  assert.match(r.stdout, /NOT COMPARABLE/);
  // ⚠️ THE BUCKET MUST NAME THE EVENT THAT HAPPENED. A producer DECLARING a gap and a plugin
  // CRASHING both mean "not measured", but they are not the same event and the row is read by an
  // auditor. The first draft reported this one as `evidence-gap` with the detail "the other run
  // recorded an evidence gap … the plugin's status on that host was error" — the other run
  // recorded nothing of the sort.
  assert.match(r.stdout, /plugin-not-measured/,
    'a crashed plugin is not a declared evidence gap, and the client-visible reason must say which happened');
  assert.doesNotMatch(r.stdout, /recorded an evidence gap/,
    'the sentence must be true about the run it describes');
});

test('SCOPE — a host that was REQUESTED and never WRITTEN was not scanned, whatever the record requested', async () => {
  const outRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-hu-'));
  const baseline = await mkRun(outRoot, { startedAt: '2026-09-01T10:00:00.000Z', findings: [s3('bucket-a')] });
  const current = await mkRun(outRoot, { startedAt: '2026-09-08T10:00:00.000Z', findings: [], writeHost: false });
  const r = await runReport({ from: outRoot, format: 'executive', run: current, since: baseline, allowPartial: true }, PRO());

  assert.equal(r.code, 0, r.stderr);
  assert.doesNotMatch(r.stdout, /[1-9]\d* resolved/,
    'scope is what a run WROTE, never the union of what it requested with what it wrote');
  assert.match(r.stdout, /host-not-scanned/);
});

test('SCOPE — two runs at DIFFERENT TIERS are refused outright, because the producer population differs', async () => {
  // Agent-produced findings have no per-agent run record: `agents/agent_runner.mjs` derives the
  // agent set from CAPABILITIES, so the only oracle for "was this producer in scope" is the run's
  // TIER. An enterprise baseline against a pro current silently drops the exposure agent's
  // findings, and every one of them would read as remediation.
  const outRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-tier-'));
  const baseline = await mkRun(outRoot, { startedAt: '2026-09-01T10:00:00.000Z', findings: [s3('bucket-a')],
    tier: 'enterprise', queue: [{ id: 'F-1', severity: 'HIGH', title: 'Exposed management interface',
      target: { port: 8443 }, evidence: { source: 'exposure_agent' } }] });
  const current = await mkRun(outRoot, { startedAt: '2026-09-08T10:00:00.000Z', findings: [s3('bucket-a')], tier: 'pro' });
  const r = await runReport({ from: outRoot, format: 'executive', run: current, since: baseline }, PRO());

  assert.equal(r.code, 2, 'a cross-tier comparison is not a narrower comparison, it is a different population');
  assert.match(r.stderr, /tier-differs/);
  assert.match(r.stderr, /enterprise/, 'the refusal must NAME both tiers — an unnamed refusal is not actionable');
  assert.match(r.stderr, /\bpro\b/);
  assert.doesNotMatch(r.stdout, /resolved/i);
});

test('SCOPE — when a side records NO plugin status at all, non-evaluation is DECLARED, never read as "no gaps"', async () => {
  // The evaluability declaration Option B asked for, kept under A'. An absent oracle is not a
  // clean one: `gate:cascade`'s LEG (ii) is this repo's precedent — print NOT EVALUATED, never
  // pass silently. The second half is the fourth quadrant: a limit that is always on says nothing.
  const { buildScanDelta, SCOPE_NOT_EVALUATED } = await import('../utils/scan_delta.mjs');
  const rec = { schema: 1, runId: 'R', startedAt: 'x', hostsRequested: ['h'], hostsWritten: [{ host: 'h', dir: 'd' }],
    pluginsRequested: ['010'], tier: 'pro', eeVersion: '1.0.0' };
  const seeing = { record: rec, findings: [], pluginStatus: [] };

  const blind = buildScanDelta({ baseline: seeing, current: { record: { ...rec, runId: 'S' }, findings: [] } });
  assert.ok(blind.limits.includes(SCOPE_NOT_EVALUATED),
    'a side with no pluginStatus cannot be said to have had no gaps — say so in the limits');

  const both = buildScanDelta({ baseline: seeing, current: { record: { ...rec, runId: 'S' }, findings: [], pluginStatus: [] } });
  assert.ok(!both.limits.includes(SCOPE_NOT_EVALUATED),
    'and when BOTH sides carry the oracle the declaration must NOT fire');
});

test('SCOPE — at the SAME tier an agent-produced finding IS comparable, so a fixed one reads resolved', async () => {
  // ⚠️ THE FOURTH QUADRANT OF THE TIER ORACLE, and the leg the motivating defect cannot exercise.
  // An EE analysis agent appears in NO `pluginsRequested` list and never will, so adjudicating it
  // there would bucket every agent finding `plugin-not-run` for ever — never wrong, never useful,
  // which is the failure mode on the other axis. Without this leg, deleting the producer-kind
  // branch stays green and the branch is decoration.
  const outRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-agent-'));
  const baseline = await mkRun(outRoot, { startedAt: '2026-09-01T10:00:00.000Z', findings: [],
    tier: 'enterprise', queue: [{ id: 'F-1', severity: 'HIGH', title: 'Weak TLS ciphers negotiated',
      target: { port: 443 }, evidence: { source: 'crypto_agent' } }] });
  const current = await mkRun(outRoot, { startedAt: '2026-09-08T10:00:00.000Z', findings: [], tier: 'enterprise' });
  const r = await runReport({ from: outRoot, format: 'executive', run: current, since: baseline }, PRO());

  assert.equal(r.code, 0, r.stderr);
  assert.match(r.stdout, /1 resolved/,
    'the agent runs on every run at this tier, so a finding it no longer reports was genuinely fixed');
  assert.doesNotMatch(r.stdout, /plugin-not-run/,
    'adjudicating an agent against `pluginsRequested` buckets every EE finding for ever — safe and useless');
  assert.match(r.stdout, /derived from the run TIER/,
    'and the basis for that verdict must be DECLARED, because it rests on a derivation the reader cannot see');
});

// ════════════════════════════════════════════════════════════════════════════════════════════
// T4 / G7 — `linkBroken` IS COMPUTED AND NEVER READ, SO `--since prior` RE-TARGETS IN SILENCE.
//
// `verifyRunChain` already works out whether a record's `prevDigest` still names bytes that
// exist; the view reads `status` only. Delete the middle of three chained records and `prior`
// quietly resolves to the survivor — the substitution `scan_delta_view.mjs`'s own header says it
// never makes ("falling back silently changes the SUBJECT of the comparison, which is the single
// thing the delta engine exists not to do"). The verdict that vanishes with the deleted record is
// the one an operator was relying on.
// ════════════════════════════════════════════════════════════════════════════════════════════

test('G7 — with the immediate predecessor DELETED, `--since prior` refuses instead of re-targeting', async () => {
  const outRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-link-'));
  const sealed = (id) => fs.readFileSync(chainDigestPath(outRoot, id), 'utf8').trim();
  // Chained explicitly rather than by the writer's default: three runs created inside one second
  // share a runId prefix and the default picks the lexically-last sidecar, which is not
  // necessarily the one finalized last. That is a real edge (it is on the board) and it must not
  // be what this test is measuring.
  const A = await mkRun(outRoot, { startedAt: '2026-09-01T10:00:00.000Z', findings: [s3('bucket-a')], prevDigest: null });
  const B = await mkRun(outRoot, { startedAt: '2026-09-04T10:00:00.000Z', findings: [s3('bucket-a'), s3('bucket-b')], prevDigest: sealed(A) });
  const C = await mkRun(outRoot, { startedAt: '2026-09-08T10:00:00.000Z', findings: [s3('bucket-a')], prevDigest: sealed(B) });
  fs.rmSync(runRecordPath(outRoot, B));
  fs.rmSync(chainDigestPath(outRoot, B));

  const r = await runReport({ from: outRoot, format: 'executive', run: C, since: 'prior' }, PRO());

  assert.equal(r.code, 2,
    'the current record vouches for a predecessor that no longer exists; comparing against a '
    + 'DIFFERENT run and calling it `prior` answers a question nobody asked');
  assert.match(r.stderr + r.stdout, new RegExp(A),
    'and the refusal must list what IS available, so the operator can name one explicitly');
  assert.doesNotMatch(r.stdout, /resolved/i,
    'bucket-b disappeared with the deleted record; reporting it resolved would be remediation by bookkeeping');
});

test('G7 ACCEPT — an INTACT chain still resolves `prior` and compares normally', async () => {
  // The fourth quadrant: a refusal keyed on `linkBroken` must not fire on the arrangement the
  // feature exists for. Nothing about the motivating defect exercises this direction.
  const outRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-link-ok-'));
  const sealed = (id) => fs.readFileSync(chainDigestPath(outRoot, id), 'utf8').trim();
  const A = await mkRun(outRoot, { startedAt: '2026-09-01T10:00:00.000Z', findings: [s3('bucket-a')], prevDigest: null });
  const B = await mkRun(outRoot, { startedAt: '2026-09-08T10:00:00.000Z', findings: [], prevDigest: sealed(A) });

  const r = await runReport({ from: outRoot, format: 'executive', run: B, since: 'prior' }, PRO());
  assert.equal(r.code, 0, r.stderr);
  assert.match(r.stdout, /1 resolved/, 'an unbroken chain must still produce the verdict');
});

test('G7 NARROWED — an EXPLICIT `--since <runId>` over a broken link still compares, and DISCLOSES the break', async () => {
  // ⚠️ THE REFUSAL IS SCOPED TO `prior`, AND THE SCOPE IS THE POINT. `linkBroken` means the current
  // record vouches for bytes that no longer exist. Under `prior` that CHANGED THE SUBJECT — the
  // command silently picked a different baseline than the one it names. Under an explicit runId the
  // operator chose the subject themselves, so nothing was substituted and refusing would break a
  // legitimate path: deleting old records is ordinary housekeeping, and turning it into a blanket
  // refusal is the accuse-honest-evidence direction this lane keeps warning about. So: refuse the
  // substitution, disclose the integrity fact.
  const outRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-link-x-'));
  const sealed = (id) => fs.readFileSync(chainDigestPath(outRoot, id), 'utf8').trim();
  const A = await mkRun(outRoot, { startedAt: '2026-09-01T10:00:00.000Z', findings: [s3('bucket-a')], prevDigest: null });
  const B = await mkRun(outRoot, { startedAt: '2026-09-04T10:00:00.000Z', findings: [s3('bucket-a')], prevDigest: sealed(A) });
  const C = await mkRun(outRoot, { startedAt: '2026-09-08T10:00:00.000Z', findings: [], prevDigest: sealed(B) });
  fs.rmSync(runRecordPath(outRoot, B));
  fs.rmSync(chainDigestPath(outRoot, B));

  const r = await runReport({ from: outRoot, format: 'executive', run: C, since: A }, PRO());
  assert.equal(r.code, 0, `an explicitly named baseline is the operator's choice: ${r.stderr}`);
  assert.match(r.stdout, /predecessor/i,
    'but the break must be DISCLOSED — the current record vouches for bytes that are gone, and a '
    + 'reader of this comparison is entitled to know that before treating a row as remediation');
});

// ── T4 step 3(c) — THE VIEW VERIFIED THE BASELINE ONLY ──────────────────────────────────────
// `report --run <older> --since <even-older>` is a legitimate invocation: both records are
// historical, and the CURRENT one is just as alterable as the baseline. Its chain was never read.
// An edited current findings file therefore produced `new` and `resolved` rows with no mention of
// it — the same fail-open as the baseline side, on the half nobody was looking at.
test('an altered CURRENT run is refused too, naming which side — the baseline is not the only alterable one', async () => {
  const outRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-cur-'));
  const baseline = await mkRun(outRoot, { startedAt: '2026-09-01T10:00:00.000Z', findings: [s3('bucket-a'), s3('bucket-b')] });
  const current = await mkRun(outRoot, { startedAt: '2026-09-08T10:00:00.000Z', findings: [s3('bucket-a'), s3('bucket-b')] });

  const f = path.join(outRoot, `d-${current}`, 'scan_conclusion_raw.json');
  const before = fs.readFileSync(f, 'utf8');
  const after = before.replace('bucket-b', 'bucket-z');
  assert.equal(after.length, before.length, 'length-preserving, or it proves nothing');
  assert.notEqual(after, before, 'the tamper must actually land');
  fs.writeFileSync(f, after, 'utf8');

  const r = await runReport({ from: outRoot, format: 'executive', run: current, since: baseline }, PRO());
  assert.equal(r.code, 2, 'an altered current run cannot support a `new` row any more than an altered baseline supports a `resolved` one');
  assert.match(r.stderr, /current/i, 'and the refusal must name WHICH SIDE is altered — otherwise the operator checks the wrong file');
  assert.doesNotMatch(r.stdout, /1 new/);
});

test('ACCEPT — an untouched pair still compares, so the current-side check is not a blanket refusal', async () => {
  const outRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-cur-ok-'));
  const baseline = await mkRun(outRoot, { startedAt: '2026-09-01T10:00:00.000Z', findings: [s3('bucket-a')] });
  const current = await mkRun(outRoot, { startedAt: '2026-09-08T10:00:00.000Z', findings: [] });
  const r = await runReport({ from: outRoot, format: 'executive', run: current, since: baseline }, PRO());
  assert.equal(r.code, 0, r.stderr);
  assert.match(r.stdout, /1 resolved/);
});

test('ACCEPT — a LEGACY current run (no digest at all) still compares, with the gap DISCLOSED not refused', async () => {
  // ⚠️ THE OVER-REFUSAL DIRECTION, which no fixture built from the defect can reach: every fixture
  // here seals, so a current-side rule that refused anything other than `chain-verified` would pass
  // every other leg while turning every pre-1.1.0 run into a blanket refusal. Not-measured is not
  // tampering — the verdict stands and the limit says what was not covered.
  const outRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-cur-legacy-'));
  const baseline = await mkRun(outRoot, { startedAt: '2026-09-01T10:00:00.000Z', findings: [s3('bucket-a')] });
  const current = await mkRun(outRoot, { startedAt: '2026-09-08T10:00:00.000Z', findings: [] });
  const recPath = runRecordPath(outRoot, current);
  const legacy = JSON.parse(fs.readFileSync(recPath, 'utf8'));
  delete legacy.prevDigest;                              // the shape a record had before chaining
  fs.writeFileSync(recPath, JSON.stringify(legacy), 'utf8');
  fs.rmSync(chainDigestPath(outRoot, current));

  const r = await runReport({ from: outRoot, format: 'executive', run: current, since: baseline }, PRO());
  assert.equal(r.code, 0, `a legacy current run is not a tampered one: ${r.stderr}`);
  assert.match(r.stdout, /current run carries no integrity digest/,
    'but the reader must be told the run being reported was not covered');
});
