// A REFUSED COMPARISON STILL OWES THE CLIENT AN ARTIFACT (board C9, architect-ruled).
//
// ⚠️ THE DEFECT, found by the outcome census: `buildSinceView` returned `{code: 2}` and cli.mjs
// returned before the write, so a refused comparison wrote NO file — and the `delta-refused`
// block in `executive_report.mjs`, which renders exactly the honest artifact, was unreachable.
// The consultant's workflow is `report --out client.html`. A refusal that leaves a STALE
// client.html at that path is worse than the refusal: the file they hand a client is from an
// earlier run and says nothing about it.
//
// ⚠️ THE EXIT CONTRACT NOW HAS TWO KINDS OF 2, AND THE ARTIFACT IS WHAT DISTINGUISHES THEM:
//   exit 2 WITH an artifact    — the report rendered; the requested COMPARISON was refused, and
//                                the artifact says so, carrying no verdict rows.
//   exit 2 WITHOUT an artifact — the REQUEST or the RUN ITSELF was refused; there is nothing
//                                honest to render, and any pre-existing --out file is named as
//                                stale rather than left to be mistaken for this run's output.
// Could-not-measure stays loud in both: the exit is 2, never 0.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { runReport } from '../cli.mjs';
import { resolveCapabilities } from '../utils/capabilities.mjs';
import { newRunId, writeRunStart, appendHostWritten, finalizeRunRecord, runRecordPath } from '../utils/run_record.mjs';
import { sealRunRecord, chainDigestPath } from '../utils/run_chain.mjs';

const s3 = (resource) => ({ severity: 'HIGH', title: 'No public access block configured', port: 443, resource });

async function mkRun(outRoot, { startedAt, findings = [], tier = 'pro', eeVersion = '1.1.0' } = {}) {
  const runId = newRunId();
  await writeRunStart(outRoot, { runId, startedAt, hostsRequested: ['10.0.0.7'],
    pluginsRequested: ['010'], portsRequested: '443', tier, ceVersion: '0.2.55', eeVersion });
  const dir = `d-${runId}`;
  fs.mkdirSync(path.join(outRoot, dir), { recursive: true });
  fs.writeFileSync(path.join(outRoot, dir, 'scan_conclusion_raw.json'), JSON.stringify({
    runId, pluginStatus: [{ id: '010', name: 'aws-s3', status: 'ran', reason: null }],
    results: [{ id: '010', name: 'aws-s3', result: { up: true, findings } }],
  }), 'utf8');
  await appendHostWritten(outRoot, runId, { host: '10.0.0.7', dir });
  await finalizeRunRecord(outRoot, runId, { finishedAt: startedAt });
  await sealRunRecord(outRoot, runId);
  return runId;
}

const tmp = (t) => fs.mkdtempSync(path.join(os.tmpdir(), `nsa-refuse-${t}-`));
const STALE = '<html>STALE ARTIFACT FROM AN EARLIER RUN</html>';

async function drive(outRoot, current, since, { preExisting = false } = {}) {
  const outFile = path.join(outRoot, 'client.html');
  if (preExisting) fs.writeFileSync(outFile, STALE, 'utf8');
  const r = await runReport({ from: outRoot, format: 'executive', run: current, since, out: outFile },
    resolveCapabilities('pro'));
  return { code: r.code, text: `${r.stdout ?? ''}\n${r.stderr ?? ''}`, outFile,
    html: fs.existsSync(outFile) ? fs.readFileSync(outFile, 'utf8') : null };
}

// Every assertion a COMPARISON refusal owes, in one place so no leg can drift from another.
function assertComparisonRefusal(r, reasonCode) {
  assert.equal(r.code, 2, 'could-not-measure stays loud: a refused comparison is never exit 0');
  assert.ok(r.html !== null, 'a COMPARISON refusal must still write the client artifact');
  assert.notEqual(r.html, STALE, 'the artifact must be FRESH — a stale file left in place is the defect');
  assert.match(r.html, /id="delta"/, 'the delta section must exist and speak');
  assert.match(r.html, /No comparison was made/, 'the client must be told IN THE ARTIFACT, not only on the operator\'s terminal');
  assert.ok(r.html.includes(reasonCode), `the artifact must carry the declared reason "${reasonCode}"`);
  for (const bucket of ['delta-resolved', 'delta-new', 'delta-changed']) {
    assert.ok(!r.html.includes(bucket),
      `a refused comparison names NO finding — found a ${bucket} row, which invites exactly the `
      + 'verdict the refusal exists to withhold');
  }
}

test('COMPARISON REFUSED (tier-differs) — exit 2 AND a fresh artifact that says so', async () => {
  const outRoot = tmp('tier');
  const baseline = await mkRun(outRoot, { startedAt: '2026-09-01T10:00:00.000Z', findings: [s3('bucket-a')], tier: 'pro' });
  const current = await mkRun(outRoot, { startedAt: '2026-09-08T10:00:00.000Z', findings: [], tier: 'enterprise' });
  assertComparisonRefusal(await drive(outRoot, current, baseline, { preExisting: true }), 'tier-differs');
});

test('COMPARISON REFUSED (baseline-chain-broken) — the tampered-baseline case reaches the client', async () => {
  const outRoot = tmp('chain');
  const baseline = await mkRun(outRoot, { startedAt: '2026-09-01T10:00:00.000Z', findings: [s3('bucket-a')] });
  const current = await mkRun(outRoot, { startedAt: '2026-09-08T10:00:00.000Z', findings: [] });
  const p = runRecordPath(outRoot, baseline);
  const rec = JSON.parse(fs.readFileSync(p, 'utf8'));
  rec.portsRequested = '8443';
  fs.writeFileSync(p, JSON.stringify(rec), 'utf8');
  assertComparisonRefusal(await drive(outRoot, current, baseline, { preExisting: true }), 'baseline-chain-broken');
});

test('COMPARISON REFUSED (baseline unloadable) — a baseline this build cannot read is still a refused COMPARISON', async () => {
  const outRoot = tmp('load');
  const baseline = await mkRun(outRoot, { startedAt: '2026-09-01T10:00:00.000Z', findings: [s3('bucket-a')] });
  const p = runRecordPath(outRoot, baseline);
  const rec = JSON.parse(fs.readFileSync(p, 'utf8'));
  rec.schema = 99;
  fs.writeFileSync(p, JSON.stringify(rec), 'utf8');
  await sealRunRecord(outRoot, baseline);
  const current = await mkRun(outRoot, { startedAt: '2026-09-08T10:00:00.000Z', findings: [] });
  assertComparisonRefusal(await drive(outRoot, current, baseline, { preExisting: true }), 'baseline-unloadable');
});

// ── THE OTHER KIND OF 2. Written as its own quadrant BEFORE the artifact legs were trusted:
// if every refusal wrote an artifact, the contract would be "always write", which says nothing.
test('REQUEST REFUSED (no such run record) — NO artifact, and any stale --out file is NAMED', async () => {
  const outRoot = tmp('nobase');
  const current = await mkRun(outRoot, { startedAt: '2026-09-08T10:00:00.000Z', findings: [] });
  const r = await drive(outRoot, current, '20260101T000000Z-deadbe', { preExisting: true });
  assert.equal(r.code, 2);
  assert.equal(r.html, STALE, 'the request named a run that does not exist: there is nothing honest to render');
  assert.match(r.text, /was NOT rewritten/,
    'and the operator must be TOLD the file on disk is from an earlier run — silence here is how a '
    + 'stale artifact gets handed to a client');
  assert.ok(r.text.includes(r.outFile), 'the notice must NAME the stale file, not merely mention one exists');
});

test('RUN REFUSED (the CURRENT run is chain-broken) — NO artifact: the run itself is not reportable', async () => {
  const outRoot = tmp('cur');
  const baseline = await mkRun(outRoot, { startedAt: '2026-09-01T10:00:00.000Z', findings: [s3('bucket-a')] });
  const current = await mkRun(outRoot, { startedAt: '2026-09-08T10:00:00.000Z', findings: [] });
  const p = runRecordPath(outRoot, current);
  const rec = JSON.parse(fs.readFileSync(p, 'utf8'));
  rec.portsRequested = '8443';
  fs.writeFileSync(p, JSON.stringify(rec), 'utf8');
  const r = await drive(outRoot, current, baseline, { preExisting: true });
  assert.equal(r.code, 2);
  assert.equal(r.html, STALE,
    'an altered CURRENT run cannot support a report at all, let alone a comparison — rendering one '
    + 'would put a verdict on bytes we just said we cannot trust');
  assert.match(r.text, /was NOT rewritten/);
});

test('NO --out, NO stale notice — the notice is about a FILE, not about refusing', async () => {
  // Fourth quadrant: the notice must not fire when there is nothing on disk to be mistaken for
  // this run's output. A notice that always prints teaches an operator to ignore it.
  const outRoot = tmp('noout');
  const current = await mkRun(outRoot, { startedAt: '2026-09-08T10:00:00.000Z', findings: [] });
  const r = await runReport({ from: outRoot, format: 'executive', run: current, since: '20260101T000000Z-deadbe' },
    resolveCapabilities('pro'));
  assert.equal(r.code, 2);
  assert.doesNotMatch(`${r.stdout ?? ''}\n${r.stderr ?? ''}`, /was NOT rewritten/);
});

test('A CLEAN comparison still writes its artifact and exits 0 — the accept case', async () => {
  // Without this the whole file could be satisfied by refusing everything.
  const outRoot = tmp('ok');
  const baseline = await mkRun(outRoot, { startedAt: '2026-09-01T10:00:00.000Z', findings: [s3('bucket-a')] });
  const current = await mkRun(outRoot, { startedAt: '2026-09-08T10:00:00.000Z', findings: [] });
  const r = await drive(outRoot, current, baseline, { preExisting: true });
  assert.equal(r.code, 0, r.text);
  assert.match(r.html, /delta-resolved/, 'a comparable run DOES name its findings');
  assert.doesNotMatch(r.html, /No comparison was made/);
  assert.doesNotMatch(r.text, /was NOT rewritten/);
});

test('A FORMAT THAT CANNOT STATE THE REFUSAL WRITES NOTHING — the contract must not depend on --format', async () => {
  // ⚠️ FOUND WHILE REVIEWING C9, NOT BY A FIXTURE. Only the executive report renders the delta;
  // `renderJiraCsv(model)` never receives it. Without this scope a refused comparison would write
  // a Jira CSV that says nothing about the refusal and still exit 2 — so "exit 2 WITH an
  // artifact" would mean "the artifact states the refusal" for HTML and "the artifact is silent
  // about it" for CSV. A reader cannot hold two contracts for one exit code.
  const outRoot = tmp('jira');
  const baseline = await mkRun(outRoot, { startedAt: '2026-09-01T10:00:00.000Z', findings: [s3('bucket-a')], tier: 'pro' });
  const current = await mkRun(outRoot, { startedAt: '2026-09-08T10:00:00.000Z', findings: [], tier: 'enterprise' });
  const outFile = path.join(outRoot, 'client.csv');
  fs.writeFileSync(outFile, 'STALE CSV', 'utf8');
  const r = await runReport({ from: outRoot, format: 'jira', run: current, since: baseline, out: outFile },
    resolveCapabilities('pro'));
  assert.equal(r.code, 2);
  assert.equal(fs.readFileSync(outFile, 'utf8'), 'STALE CSV',
    'a CSV cannot state the refusal, so none is written — and the stale one is NAMED rather than replaced');
  assert.match(`${r.stdout ?? ''}\n${r.stderr ?? ''}`, /was NOT rewritten/);
});
