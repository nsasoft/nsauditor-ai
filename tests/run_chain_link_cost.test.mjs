// `report --since` HASHES EACH RUN RECORD ONCE PER INVOCATION, NOT ONCE PER RECORD (board C4).
//
// ⚠️ THE SHAPE: `verifyRunChain` resolves `linkedTo` existentially — "does any record in this out
// root still hash to it?" — so every call does a `readdir` and hashes EVERY record. The view then
// calls it once per record in each of its two alternatives loops, on exactly the path an operator
// hits when something is already wrong. N calls × N hashes.
//
// ⚠️ NOT A CORRECTNESS BUG, and the test says so by asserting the VERDICTS are unchanged beside
// the cost. The reason it is worth closing anyway: the quadratic path is the REFUSAL path, so the
// command gets slowest precisely when a baseline is broken and an operator is waiting on it —
// the same "worst exactly when it matters" shape as gate:cascade's partial-fetch false clean.
//
// The oracle is I/O, counted through a patched `fsp.readFile`, because that is the thing that
// actually costs: an assertion on a cache's internals would pass on a cache that is populated and
// never consulted.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { writeRunStart, appendHostWritten, finalizeRunRecord, runRecordPath } from '../utils/run_record.mjs';
import { sealRunRecord, verifyRunChain, buildRunRecordDigestIndex } from '../utils/run_chain.mjs';
import { loadRun } from '../utils/report_inputs.mjs';
import { buildSinceView } from '../utils/scan_delta_view.mjs';

const N = 12;

async function mkRun(outRoot, i) {
  const runId = `20260901T1000${String(i).padStart(2, '0')}Z-${String(i).padStart(6, '0')}`;
  const startedAt = `2026-09-01T10:00:00.${String(i).padStart(3, '0')}Z`;
  await writeRunStart(outRoot, { runId, startedAt, hostsRequested: ['10.0.0.7'],
    pluginsRequested: ['010'], portsRequested: '443', tier: 'pro', ceVersion: '0.2.55', eeVersion: '1.1.0' });
  const dir = `d-${runId}`;
  fs.mkdirSync(path.join(outRoot, dir), { recursive: true });
  fs.writeFileSync(path.join(outRoot, dir, 'scan_conclusion_raw.json'), JSON.stringify({
    runId, pluginStatus: [{ id: '010', name: 'aws-s3', status: 'ran', reason: null }],
    results: [{ id: '010', name: 'aws-s3', result: { up: true, findings: [
      { severity: 'HIGH', title: 'No public access block configured', port: 443, resource: 'bucket-a' }] } }],
  }), 'utf8');
  await appendHostWritten(outRoot, runId, { host: '10.0.0.7', dir });
  await finalizeRunRecord(outRoot, runId, { finishedAt: startedAt });
  await sealRunRecord(outRoot, runId);
  return runId;
}

// The REFUSAL path, because that is where the two alternatives loops live.
async function driveRefusal() {
  const outRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-cost-'));
  const ids = [];
  for (let i = 1; i <= N; i += 1) ids.push(await mkRun(outRoot, i));
  const current = ids[ids.length - 1];
  const baseline = ids[ids.length - 2];
  // Tamper the baseline AFTER sealing: the view refuses and lists the alternatives.
  const p = runRecordPath(outRoot, baseline);
  const rec = JSON.parse(fs.readFileSync(p, 'utf8'));
  rec.portsRequested = '8443';
  fs.writeFileSync(p, JSON.stringify(rec), 'utf8');

  const loaded = await loadRun(outRoot, { runId: current, allowPartial: false }, { tier: 'pro' });
  assert.equal(loaded.ok, true, loaded.message);

  const reads = [];
  const orig = fsp.readFile;
  fsp.readFile = (...a) => { reads.push(String(a[0])); return orig(...a); };
  let view;
  try {
    view = await buildSinceView({ outRoot, model: loaded.model, since: baseline, allowPartial: false, tier: 'pro' });
  } finally {
    fsp.readFile = orig;
  }
  const recordReads = reads.filter((f) => /scan_run_[^/]*\.json$/.test(f)).length;
  return { view, recordReads, outRoot, baseline };
}

test('the refusal still REFUSES and still lists the alternatives — cost is not bought with behaviour', async () => {
  // ⚠️ FIRST, AND DELIBERATELY. A performance change that quietly drops the alternatives list, or
  // stops verifying a record, would satisfy any pure counting assertion perfectly.
  const { view, baseline } = await driveRefusal();
  assert.equal(view.code, 2);
  const err = view.err.join('\n');
  assert.match(err, /REFUSED: baseline-chain-broken/, 'the refusal must survive unchanged');
  assert.match(err, /records you can name explicitly|earlier records you can name explicitly/);
  // Every OTHER record must still be listed with a verified status — the list is the point of
  // the loop that makes this quadratic, so a cheaper loop that lists fewer records is not a fix.
  const listed = (err.match(/^\[report]\s+20260901T[^\s]+ · /gm) ?? []).length;
  assert.equal(listed, N - 2, `expected the other ${N - 2} records listed, got ${listed}`);
  assert.ok(!err.includes(`  ${baseline} ·`), 'the tampered baseline is not one of its own alternatives');
});

test('each run record is hashed ONCE per invocation — the cost is LINEAR in the record count', async () => {
  const { recordReads } = await driveRefusal();
  const quadratic = N * N;
  const linearBound = 3 * N + 6;   // own-record read per call + one shared scan + a little slack
  assert.ok(recordReads <= linearBound,
    `read ${recordReads} run records for ${N} records. A linear pass is ~${linearBound}; the `
    + `quadratic shape this closes is ~${quadratic}. Each record must be hashed once per view `
    + 'invocation, not once per verifyRunChain call.');
  // Stated separately so a future slack adjustment cannot quietly re-admit the quadratic.
  assert.ok(recordReads < quadratic / 2,
    `read ${recordReads}, which is not clearly below the quadratic ${quadratic} — at N=${N} the two `
    + 'regimes must be unmistakable, or this leg is measuring slack rather than complexity');
});

test('THE INDEXED PATH AND THE SCANNING PATH ANSWER IDENTICALLY — the comment made checkable', async () => {
  // ⚠️ `run_chain.mjs` states that the two paths "must answer identically". That was a claim about
  // the code with nothing checking it, and a mutant proved the gap: forcing `linkBroken = false`
  // on the indexed path left this file entirely green. The suite DOES catch it — the outcome
  // census and report_since's G7 legs go red — but a file whose whole subject is the index owes
  // the equivalence directly, or its own comment is decoration.
  const outRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-equiv-'));
  const a = await mkRun(outRoot, 1);
  const b = await mkRun(outRoot, 2);          // links to a
  const index = await buildRunRecordDigestIndex(outRoot);

  // LINKED: both paths must say so.
  assert.equal((await verifyRunChain(outRoot, b)).linkBroken, false);
  assert.equal((await verifyRunChain(outRoot, b, { linkIndex: index })).linkBroken, false);

  // BROKEN: delete the predecessor, rebuild the index, and both paths must say so too.
  fs.rmSync(runRecordPath(outRoot, a));
  const after = await buildRunRecordDigestIndex(outRoot);
  const scanned = await verifyRunChain(outRoot, b);
  const indexed = await verifyRunChain(outRoot, b, { linkIndex: after });
  assert.equal(scanned.linkBroken, true, 'the scanning path must see the missing predecessor');
  assert.equal(indexed.linkBroken, true,
    'and so must the indexed path — an index that always reports "linked" is a chain check that '
    + 'cannot fail, which is the cardinal defect this repo names');
  assert.equal(indexed.status, scanned.status, 'and the two must agree on the status as well');
});
