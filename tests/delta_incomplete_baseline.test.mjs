// AN UNFINISHED BASELINE PRODUCES NEW COVERAGE, NOT NEW FINDINGS (board C5, the mirror of G4).
//
// G4 was the RESOLVED direction: a host the CURRENT run requested but never wrote counted as
// scanned, so its baseline findings read `1 resolved` — a remediation claim over a host nobody
// looked at. Closed by making scope what a run WROTE, never what it requested.
//
// ⚠️ THIS FILE IS THE OTHER DIRECTION, AND IT IS THE ONE A CUSTOMER SEES FIRST. A baseline
// interrupted under `--allow-partial` wrote host A and not host B. The next run writes both. B's
// findings exist on one side only — and calling them NEW says the estate got worse, when what
// actually happened is that the estate got MEASURED. An operator acts on "new CRITICAL on a host
// that had none"; nobody pages anyone over "we finally scanned that host".
//
// ⚠️ IT CANNOT FAIL FIRST, AND THAT IS STATED RATHER THAN HIDDEN. The behaviour was closed by T2
// before this test existed, so writing it RED was not available: a characterization test written
// after the fix proves nothing by passing. The MUTANT is the evidence — reverting scope to
// `hostsRequested ∪ hostsWritten` must turn the first leg red, and the battery beside this file
// records that it does.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { runReport } from '../cli.mjs';
import { resolveCapabilities } from '../utils/capabilities.mjs';
import { newRunId, writeRunStart, appendHostWritten, finalizeRunRecord } from '../utils/run_record.mjs';
import { sealRunRecord } from '../utils/run_chain.mjs';

const finding = (title, resource) => ({ severity: 'CRITICAL', title, port: 443, resource });

function writeHost(outRoot, dir, runId, findings) {
  fs.mkdirSync(path.join(outRoot, dir), { recursive: true });
  fs.writeFileSync(path.join(outRoot, dir, 'scan_conclusion_raw.json'), JSON.stringify({
    runId, pluginStatus: [{ id: '010', name: 'aws-s3', status: 'ran', reason: null }],
    results: [{ id: '010', name: 'aws-s3', result: { up: true, findings } }],
  }), 'utf8');
}

// `requested` is what the run ASKED for; `written` is what it actually produced. The gap between
// them is the whole subject of this file.
async function mkRun(outRoot, { startedAt, requested, written }) {
  const runId = newRunId();
  await writeRunStart(outRoot, { runId, startedAt, hostsRequested: requested,
    pluginsRequested: ['010'], portsRequested: '443', tier: 'pro',
    ceVersion: '0.2.55', eeVersion: '1.1.0' });
  for (const [host, findings] of Object.entries(written)) {
    const dir = `d-${runId}-${host.replace(/\./g, '_')}`;
    writeHost(outRoot, dir, runId, findings);
    await appendHostWritten(outRoot, runId, { host, dir });
  }
  await finalizeRunRecord(outRoot, runId, { finishedAt: startedAt });
  await sealRunRecord(outRoot, runId);
  return runId;
}

const A = '10.0.0.7';
const B = '10.0.0.9';

// The baseline was INTERRUPTED: it asked for both hosts and wrote only A.
async function interruptedBaseline() {
  const outRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-partial-'));
  const baseline = await mkRun(outRoot, {
    startedAt: '2026-09-01T10:00:00.000Z',
    requested: [A, B],
    written: { [A]: [finding('No public access block configured', 'bucket-a')] },
  });
  const current = await mkRun(outRoot, {
    startedAt: '2026-09-08T10:00:00.000Z',
    requested: [A, B],
    written: {
      [A]: [finding('No public access block configured', 'bucket-a')],
      [B]: [finding('Security group open to the world', 'sg-b')],
    },
  });
  const outFile = path.join(outRoot, 'client.html');
  const r = await runReport({ from: outRoot, format: 'executive', run: current, since: baseline,
    out: outFile, allowPartial: true }, resolveCapabilities('pro'));
  return { r, outRoot, html: fs.existsSync(outFile) ? fs.readFileSync(outFile, 'utf8') : null };
}

test('a host the BASELINE never wrote yields NOT-COMPARABLE, never `new`', async () => {
  const { r, html } = await interruptedBaseline();
  assert.equal(r.code, 0, r.stderr);
  const text = `${r.stdout}\n${r.stderr}`;

  assert.match(text, /NOT COMPARABLE[^\n]*sg-b/,
    'host B was never measured in the baseline, so nothing about it is comparable');
  assert.match(text, /sg-b[^\n]*host-not-scanned|host-not-scanned[^\n]*sg-b/,
    'and the REASON must travel with it — a bare not-comparable count re-creates the ambiguity');
  assert.doesNotMatch(text, /NEW[^\n]*sg-b/i,
    'calling it NEW says the estate got worse; what happened is the estate got MEASURED');

  // The client artifact is the surface that matters, so assert there too — the stdout-only
  // shape is one this lane has already retired once.
  assert.ok(html, 'a comparable run writes its artifact');
  assert.ok(!/<tr class="delta-new">(?:<td>[\s\S]*?<\/td>){2}<td>sg-b</.test(html),
    'no `new` ROW for sg-b in the client report');
});

test('a finding that IS new on a host BOTH runs wrote is still reported as new', async () => {
  // ⚠️ THE ACCEPT CASE, and without it the fix could be "never report anything new", which would
  // satisfy every assertion above and destroy the feature. The found defect is the veto's shape;
  // this is the leg that rots if nobody writes it.
  const outRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-partial2-'));
  const baseline = await mkRun(outRoot, { startedAt: '2026-09-01T10:00:00.000Z',
    requested: [A], written: { [A]: [finding('No public access block configured', 'bucket-a')] } });
  const current = await mkRun(outRoot, { startedAt: '2026-09-08T10:00:00.000Z',
    requested: [A], written: { [A]: [
      finding('No public access block configured', 'bucket-a'),
      finding('Bucket policy grants s3:* to *', 'bucket-z')] } });
  const outFile = path.join(outRoot, 'client.html');
  const r = await runReport({ from: outRoot, format: 'executive', run: current, since: baseline,
    out: outFile, allowPartial: true }, resolveCapabilities('pro'));
  assert.equal(r.code, 0, r.stderr);
  assert.match(`${r.stdout}`, /1 new/, 'a genuine regression on a measured host must still be called new');
  // ⚠️ THE ROW ITSELF IS IN THE ARTIFACT, NOT ON STDOUT, and that is deliberate in the view:
  // NOT-COMPARABLE rows are enumerated with their reasons because a bare count re-creates the
  // ambiguity they exist to remove, while `new` and `resolved` are counted on stdout and named
  // in the client report. Asserting `bucket-z` on stdout was MY error about the contract, not a
  // gap in it — corrected here rather than by loosening the assertion.
  const html = fs.readFileSync(outFile, 'utf8');
  assert.match(html, /<tr class="delta-new">/, 'and the row reaches the CLIENT artifact');
  assert.match(html, /bucket-z/, 'naming the resource, which is what an operator acts on');
});

test('the run DECLARES the partial baseline rather than letting the reader infer it', async () => {
  // A not-comparable row tells you about one finding. The operator also needs to know the
  // comparison itself was made against a run that did not finish — otherwise the only signal is
  // a row they may scroll past.
  const { r } = await interruptedBaseline();
  const text = `${r.stdout}\n${r.stderr}`;
  assert.match(text, /baseline: runId /, 'the baseline is named before any verdict');
  assert.match(text, /scope 1 of 2 host\(s\) written/,
    'and its scope is the hosts it WROTE, naming the shortfall: `2 host(s)` above a '
    + '`host-not-scanned` row is the line that explains the row contradicting it');
});
