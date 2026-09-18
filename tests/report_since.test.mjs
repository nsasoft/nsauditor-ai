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

function writeHostDir(outRoot, dir, runId, findings) {
  fs.mkdirSync(path.join(outRoot, dir), { recursive: true });
  fs.writeFileSync(path.join(outRoot, dir, 'scan_conclusion_raw.json'), JSON.stringify({
    runId, pluginStatus: [{ id: '010', name: 'aws-s3', status: 'ran', reason: null }],
    results: [{ id: '010', name: 'aws-s3', result: { up: true, findings } }],
  }), 'utf8');
}

async function mkRun(outRoot, { startedAt, findings, seal = true, prevDigest = null }) {
  const runId = newRunId();
  await writeRunStart(outRoot, { runId, startedAt, hostsRequested: ['10.0.0.7'],
    pluginsRequested: ['aws-s3'], portsRequested: '443', tier: 'pro',
    ceVersion: '0.2.54', eeVersion: '1.0.0', prevDigest });
  writeHostDir(outRoot, `d-${runId}`, runId, findings);
  await appendHostWritten(outRoot, runId, { host: '10.0.0.7', dir: `d-${runId}` });
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
  assert.match(r.stdout, /aws-s3/, 'the baseline scope must appear — a narrow baseline explains a wall of NOT-COMPARABLE');
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
  assert.notEqual(r.code, 0, 'a baseline that was altered cannot support any verdict');
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
    pluginsRequested: ['aws-s3'], portsRequested: '443', tier: 'pro', ceVersion: '0.2.54', eeVersion: '1.0.0' });
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
  assert.equal(loaded.model.findings[0].plugin, 'aws-s3',
    'the producing plugin is part of a finding’s identity and of its comparability');
});
