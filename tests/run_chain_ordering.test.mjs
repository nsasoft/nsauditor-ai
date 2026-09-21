// ONE ORDERING FOR THE CHAIN AND FOR `--since prior` (board C2, with C8 merged).
//
// ⚠️ THE DEFECT: `latestSealedDigest` sorted run-record FILENAMES lexically and took the last,
// while `newRunId()` is `<ISO-to-the-SECOND>-<6 random hex>`. For two records written inside the
// same second the predecessor was therefore decided by the RANDOM SUFFIX. Found when a census
// fixture chained to one record on some runs and another on others, from byte-identical code.
//
// ⚠️ WHY IT IS NOT MERELY A FLAKY FIXTURE: `--since prior` resolves its baseline through this
// chain, and `scan_delta_view.mjs` says in as many words that silently changing the subject of a
// comparison is the one thing the command does not do. A filename sort is wrong at EVERY second
// boundary even with a monotonic id, which is why the repair keys on the record's CONTENTS.
//
// The ordering is `startedAt` — the same key `listRunRecords` already sorts on — and the
// predecessor is the most recent record whose `startedAt` strictly PRECEDES this run's.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { writeRunStart, appendHostWritten, finalizeRunRecord, runRecordPath, listRunRecords } from '../utils/run_record.mjs';
import { sealRunRecord, chainDigestPath, latestSealedDigest, predecessorOf } from '../utils/run_chain.mjs';
import { resolveBaseline } from '../utils/scan_delta_view.mjs';

// ⚠️ THE SUFFIXES ARE CHOSEN SO THE OLD FILENAME SORT PICKS THE WRONG RECORD. All three ids share
// one second — which is what `newRunId()` produces for runs started together — and the record
// that started FIRST carries the lexically LARGEST suffix. Under a filename sort it wins; under
// the ordering this file pins it can never be the predecessor of a later run.
const SEC = '20260901T100000Z';
const A = { runId: `${SEC}-ffffff`, startedAt: '2026-09-01T10:00:00.100Z' };   // first, sorts LAST
const B = { runId: `${SEC}-000000`, startedAt: '2026-09-01T10:00:00.200Z' };   // second, sorts FIRST
const C = { runId: `${SEC}-888888`, startedAt: '2026-09-01T10:00:00.300Z' };   // third

async function write(outRoot, { runId, startedAt }, { seal = true, prevDigest = null } = {}) {
  await writeRunStart(outRoot, { runId, startedAt, hostsRequested: ['10.0.0.7'],
    pluginsRequested: ['010'], portsRequested: '443', tier: 'pro',
    ceVersion: '0.2.55', eeVersion: '1.1.0', prevDigest });
  const dir = `d-${runId}`;
  fs.mkdirSync(path.join(outRoot, dir), { recursive: true });
  fs.writeFileSync(path.join(outRoot, dir, 'scan_conclusion_raw.json'), JSON.stringify({
    runId, pluginStatus: [{ id: '010', name: 'aws-s3', status: 'ran', reason: null }],
    results: [{ id: '010', name: 'aws-s3', result: { up: true, findings: [] } }],
  }), 'utf8');
  await appendHostWritten(outRoot, runId, { host: '10.0.0.7', dir });
  await finalizeRunRecord(outRoot, runId, { finishedAt: startedAt });
  if (!seal) fs.rmSync(chainDigestPath(outRoot, runId), { force: true });
  return runId;
}

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-order-'));
const digestOf = (outRoot, runId) => fs.readFileSync(chainDigestPath(outRoot, runId), 'utf8').trim();

// ⚠️ WRITTEN IN SEAL ORDER B → A → C, SO "SEALED LATER" AND "STARTED EARLIER" DISAGREE. A is
// sealed AFTER B while having started BEFORE it. A predecessor chosen by seal time — or by the
// filename sort, which A also wins — would name A. Only the startedAt ordering names B.
async function threeInOneSecond(outRoot) {
  await write(outRoot, B);
  await write(outRoot, A);
  // ⚠️ C's `prevDigest` IS NOT PASSED — the writer must compute it. The first draft passed it
  // explicitly, and `writeRunStart` does `rec.prevDigest ?? await latestSealedDigest(...)`, so an
  // explicit value SHORT-CIRCUITS the call these legs exist to test. Three legs were asserting on
  // a value the fixture had handed them. Caught by a mutant that removed `startedAt` at the call
  // site and turned only ONE leg red: the one that let the writer do its own work.
  await write(outRoot, C);
  return JSON.parse(fs.readFileSync(runRecordPath(outRoot, C.runId), 'utf8')).prevDigest;
}

test('PURE ORDERING — the predecessor is the most recent record STARTED before this one', () => {
  const recs = [A, B, C];
  assert.equal(predecessorOf(recs, C.startedAt)?.runId, B.runId,
    'C follows B by startedAt, though A sorts last by filename and was sealed later');
  assert.equal(predecessorOf(recs, B.startedAt)?.runId, A.runId);
  assert.equal(predecessorOf(recs, A.startedAt), null, 'the earliest record has no predecessor');
});

test('PURE ORDERING — a SIMULTANEOUS record is not a predecessor, and ties break DETERMINISTICALLY', () => {
  // ⚠️ STRICTLY PRECEDES. Two runs that started in the same millisecond have no recoverable
  // order between them, so neither may claim the other as its predecessor — inventing one would
  // be the filename sort's defect wearing a better key.
  const twin = { runId: `${SEC}-aaaaaa`, startedAt: C.startedAt };
  assert.notEqual(predecessorOf([A, B, twin], C.startedAt)?.runId, twin.runId);
  assert.equal(predecessorOf([A, B, twin], C.startedAt)?.runId, B.runId);
  // Among records sharing the newest qualifying startedAt, the tie is broken on runId — arbitrary
  // but DETERMINISTIC, which is the whole point. Repeating with the input shuffled must not move it.
  const tieA = { runId: `${SEC}-111111`, startedAt: B.startedAt };
  const tieB = { runId: `${SEC}-222222`, startedAt: B.startedAt };
  const one = predecessorOf([tieA, tieB], C.startedAt)?.runId;
  const two = predecessorOf([tieB, tieA], C.startedAt)?.runId;
  assert.equal(one, two, 'the same input set in a different array order must give the same answer');
});

test('THE CHAIN — prevDigest names the record that STARTED before, not the one that sorts last', async () => {
  const outRoot = tmp();
  const prevForC = await threeInOneSecond(outRoot);
  assert.equal(prevForC, digestOf(outRoot, B.runId),
    'C must link to B. Linking to A is the filename sort: A started FIRST, sorts LAST, sealed LAST.');
  assert.notEqual(prevForC, digestOf(outRoot, A.runId));
});

test('THE CHAIN AND `--since prior` NAME THE SAME RECORD — one ordering, not two', async () => {
  const outRoot = tmp();
  await threeInOneSecond(outRoot);
  const prior = await resolveBaseline(outRoot, C.runId, 'prior');
  assert.equal(prior?.runId, B.runId, '`--since prior` must name the same predecessor the chain links to');
  const linked = JSON.parse(fs.readFileSync(runRecordPath(outRoot, C.runId), 'utf8')).prevDigest;
  assert.equal(linked, digestOf(outRoot, prior.runId),
    'the record `prior` resolves to must be the record prevDigest vouches for — otherwise the '
    + 'comparison is made against a run the chain does not cover');
  // And the same for B, so the leg is not satisfied by one lucky position.
  assert.equal((await resolveBaseline(outRoot, B.runId, 'prior'))?.runId, A.runId);
});

test('DETERMINISM — the same construction gives the same answer every time', async () => {
  // ⚠️ THIS IS THE LEG THE DEFECT FAILED. Under the filename sort the answer depended on
  // `newRunId()`s random suffix, so a single run proved nothing: the old code was right roughly
  // half the time. Fixed suffixes make the ordering observable; repetition makes it a measurement.
  const answers = new Set();
  for (let i = 0; i < 5; i += 1) {
    const outRoot = tmp();
    await threeInOneSecond(outRoot);
    const prior = await resolveBaseline(outRoot, C.runId, 'prior');
    answers.add(`${prior?.runId}`);
  }
  assert.deepEqual([...answers], [B.runId], `five identical constructions gave: ${[...answers].join(', ')}`);
});

test('THE CHAIN SKIPS AN UNSEALED RECORD — and `--since prior` DOES NOT, deliberately', async () => {
  // ⚠️ THE ONE PLACE THE TWO LEGITIMATELY DIVERGE, PINNED SO IT IS A DECISION AND NOT A DRIFT.
  // The chain can only link to a digest, so an unsealed record cannot be linked and is skipped.
  // `prior` must NOT skip it: skipping would silently compare against an older run — the subject
  // substitution this engine refuses — whereas comparing against an unsealed baseline is already
  // DISCLOSED as the `baseline-unchained` limit. Disclose, never substitute.
  const outRoot = tmp();
  await write(outRoot, A);
  await write(outRoot, B, { seal: false });
  const prevForC = await latestSealedDigest(outRoot, C.startedAt);
  assert.equal(prevForC, digestOf(outRoot, A.runId), 'the chain must skip the unsealed B and link to A');
  // C must EXIST for `prior` to be resolved relative to it — without it `resolveBaseline` falls
  // back to "predecessor of the newest record", which answers a different question and made the
  // first draft of this leg pass for the wrong reason.
  await write(outRoot, C, { prevDigest: prevForC });
  const prior = await resolveBaseline(outRoot, C.runId, 'prior');
  assert.equal(prior?.runId, B.runId,
    '`prior` must still name B — the run that actually preceded C. Skipping it would change the '
    + 'SUBJECT of the comparison silently; using it merely earns a disclosed limit.');
});

test('listRunRecords ALREADY sorts on this key — the repair adopts it rather than inventing one', async () => {
  const outRoot = tmp();
  await threeInOneSecond(outRoot);
  const ids = (await listRunRecords(outRoot)).map((r) => r.runId);
  assert.deepEqual(ids, [C.runId, B.runId, A.runId], 'newest startedAt first');
});

test('`--since prior` NEVER names a SIMULTANEOUS run — the leg that proves the resolveBaseline half', async () => {
  // ⚠️ WRITTEN BECAUSE THE OTHER LEGS COULD NOT SEE THIS HALF OF THE CHANGE. With distinct
  // `startedAt` values the old `all[i + 1]` — a POSITION in the sorted list — gives the same
  // answer as the ordering, so reverting `resolveBaseline` left every leg above GREEN. The
  // positive-scope leg rotting into decoration while the veto leg carries the file is the shape
  // this repo names, so here is the fixture only this half can pass.
  //
  // The defect it pins: `listRunRecords` sorts on `startedAt` and `localeCompare` returns 0 for
  // two records that share one, so ties fall through to `Array.prototype.sort`'s stability — to
  // readdir order, to the FILENAME. A run can therefore be handed a "prior" that did not precede
  // it at all but merely sorted next to it.
  const outRoot = tmp();
  const twin = { runId: `${SEC}-aaaaaa`, startedAt: C.startedAt };   // SIMULTANEOUS with C
  await write(outRoot, A);
  await write(outRoot, B);
  await write(outRoot, twin);
  await write(outRoot, C);

  const prior = await resolveBaseline(outRoot, C.runId, 'prior');
  assert.equal(prior?.runId, B.runId,
    'C\'s prior is B. `twin` started in the same millisecond as C, so it did not precede C and '
    + 'must never be its baseline — comparing a run against a simultaneous one reports drift that '
    + 'no elapsed time could have produced.');
  assert.notEqual(prior?.runId, twin.runId);

  // And the chain agrees, which is the point of having one ordering.
  const linked = JSON.parse(fs.readFileSync(runRecordPath(outRoot, C.runId), 'utf8')).prevDigest;
  assert.equal(linked, digestOf(outRoot, B.runId), 'the chain must link C to B as well');
});
