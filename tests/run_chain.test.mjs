// Tamper-EVIDENCE for run records — a hash chain, NO KEYS.
//
// ⚠️ WHAT THIS IS NOT, and the module says the same in its own output: a chain stored beside the
// records it covers is defeated by anyone who can recompute the successors. It is evidence against
// accidental corruption, partial restore and unsophisticated edits — not tamper-proofing, and not
// non-repudiation. Ed25519 + custody is the separate, heavier property.
//
// ⚠️ CLASS F (canonicalisation independence): there is NO canonicaliser here. The digest covers the
// EXACT BYTES PERSISTED, so signer and verifier cannot share a canonicalisation bug — the recorded
// failure being a hand-rolled canonicaliser that serialised `new Date()` as `{}`. The sibling
// incident is the 2026-09-14 sample pack, whose envelope digests were computed over RAW bytes while
// the archive shipped SANITIZED ones: 72 of 96 digests named bytes that were never in the archive.
// Hash what you PERSIST.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fsp from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { sealRunRecord, verifyRunChain, chainDigestPath } from '../utils/run_chain.mjs';
import { writeRunStart, appendHostWritten, finalizeRunRecord, runRecordPath, readRunRecord } from '../utils/run_record.mjs';

const tmp = async () => fsp.mkdtemp(path.join(os.tmpdir(), 'nsa-chain-'));
const mkRun = async (root, id, over = {}) => {
  await writeRunStart(root, { runId: id, startedAt: '2026-09-18T00:00:00Z', hostsRequested: ['10.0.0.1'], ...over });
  await finalizeRunRecord(root, id, { finishedAt: '2026-09-18T01:00:00Z' });
  return sealRunRecord(root, id);
};

test('a sealed run record verifies', async () => {
  const root = await tmp();
  await mkRun(root, 'R1');
  assert.equal((await verifyRunChain(root, 'R1')).status, 'chain-verified');
});

test('a ONE-BYTE, LENGTH-PRESERVING edit to a sealed record is detected', async () => {
  const root = await tmp();
  await mkRun(root, 'R1');
  const f = runRecordPath(root, 'R1');
  const before = await fsp.readFile(f, 'utf8');
  const after = before.replace('10.0.0.1', '10.0.0.2');
  assert.equal(after.length, before.length, 'the tamper must be length-preserving or it proves nothing');
  assert.notEqual(after, before, 'the mutant must actually land');
  await fsp.writeFile(f, after, 'utf8');
  const v = await verifyRunChain(root, 'R1');
  assert.equal(v.status, 'chain-broken');
});

test('a record from BEFORE chaining is chain-ABSENT, never chain-broken — nothing measured must not read as tampering', async () => {
  // ⚠️ THIS FIXTURE SAID "a record written before chaining shipped" AND WAS NOT ONE, which only
  // became visible when G6 gave the two states different verdicts. It was built by the CURRENT
  // writer, and `writeRunStart` has set `prevDigest` since `c473f3e` — so on disk it was a record
  // that had been SEALED AND THEN UNSEALED, which is the removed-sidecar case, not the legacy one.
  // A genuinely pre-chaining record has no `prevDigest` KEY at all, and that is what the rule is
  // keyed on, so the fixture has to carry the absence it is asserting about.
  //
  // The earlier note is kept, because its reasoning was right and its conclusion incomplete: the
  // fixture had to change when sealing moved inside `finalizeRunRecord`, or writing it the old way
  // would no longer produce an unsealed record at all and this leg would have gone vacuous.
  // Removing the sidecar fixed the vacuity and left the record's SHAPE modern.
  const root = await tmp();
  await writeRunStart(root, { runId: 'R0', startedAt: '2026-09-18T00:00:00Z', hostsRequested: ['10.0.0.1'] });
  await finalizeRunRecord(root, 'R0', { finishedAt: '2026-09-18T01:00:00Z' });
  const legacy = JSON.parse(await fsp.readFile(runRecordPath(root, 'R0'), 'utf8'));
  delete legacy.prevDigest;                           // the shape a record had before chaining shipped
  await fsp.writeFile(runRecordPath(root, 'R0'), JSON.stringify(legacy), 'utf8');
  await fsp.rm(chainDigestPath(root, 'R0'));
  const v = await verifyRunChain(root, 'R0');
  assert.equal(v.status, 'chain-absent', 'a record predating the chain is not an accusation');
});

test('the digest covers the EXACT PERSISTED BYTES — a re-serialisation with different whitespace does not verify', async () => {
  const root = await tmp();
  await mkRun(root, 'R1');
  const f = runRecordPath(root, 'R1');
  const obj = JSON.parse(await fsp.readFile(f, 'utf8'));
  await fsp.writeFile(f, JSON.stringify(obj), 'utf8');   // same OBJECT, different bytes
  assert.equal((await verifyRunChain(root, 'R1')).status, 'chain-broken',
    'if this passed, the verifier is re-canonicalising instead of hashing what is on disk (Class F)');
});

test('the chain LINKS: a successor carries its predecessor digest, and altering the predecessor breaks the link', async () => {
  const root = await tmp();
  await mkRun(root, 'R1');
  const first = (await verifyRunChain(root, 'R1')).digest;
  await mkRun(root, 'R2', { prevDigest: first });
  assert.equal((await verifyRunChain(root, 'R2')).status, 'chain-verified');
  assert.equal((await verifyRunChain(root, 'R2')).linkedTo, first);

  const f = runRecordPath(root, 'R1');
  const before = await fsp.readFile(f, 'utf8');
  await fsp.writeFile(f, before.replace('10.0.0.1', '10.0.0.2'), 'utf8');
  const v = await verifyRunChain(root, 'R2');
  assert.equal(v.linkBroken, true, 'R2 vouches for bytes that R1 no longer has');
});

// ⚠️ THE WRITE SIDE WAS NEVER WIRED, AND A REAL SMOKE RUN IS WHAT FOUND IT.
// `report --since` READ the chain from the day it shipped, and nothing ever WROTE one: `cli.mjs`
// called `sealRunRecord` zero times, so three real scans produced zero `.sha256` sidecars and
// `prevDigest: null` on every record. Every delta would have reported `chain-absent` forever while
// the CHANGELOG, the press release and the README all said run records ARE sealed and chained.
// Class E one layer over — the capability existed and no shipped path invoked it.
//
// The fix is placed INSIDE `finalizeRunRecord`/`writeRunStart` rather than at the call site, so it
// cannot be forgotten by the next caller. That is the defect class removed, not the instance.
test('finalizing a run SEALS it — no caller has to remember', async () => {
  const root = await tmp();
  await writeRunStart(root, { runId: 'S1', startedAt: '2026-09-18T00:00:00Z', hostsRequested: ['10.0.0.1'] });
  await finalizeRunRecord(root, 'S1', { finishedAt: '2026-09-18T01:00:00Z' });
  const v = await verifyRunChain(root, 'S1');
  assert.equal(v.status, 'chain-verified', 'a finalized run must carry its digest without an explicit seal call');
});

test('the NEXT run chains to the previous one automatically', async () => {
  const root = await tmp();
  await writeRunStart(root, { runId: 'S1', startedAt: '2026-09-18T00:00:00Z', hostsRequested: ['10.0.0.1'] });
  await finalizeRunRecord(root, 'S1', { finishedAt: '2026-09-18T01:00:00Z' });
  const first = (await verifyRunChain(root, 'S1')).digest;

  await writeRunStart(root, { runId: 'S2', startedAt: '2026-09-18T02:00:00Z', hostsRequested: ['10.0.0.1'] });
  await finalizeRunRecord(root, 'S2', { finishedAt: '2026-09-18T03:00:00Z' });
  const rec = JSON.parse(await fsp.readFile(runRecordPath(root, 'S2'), 'utf8'));
  assert.equal(rec.prevDigest, first, 'the successor must vouch for its predecessor without the caller passing it');
  assert.equal((await verifyRunChain(root, 'S2')).linkBroken, false);
});

test('an explicit prevDigest still wins — the default must not overwrite a caller', async () => {
  const root = await tmp();
  await writeRunStart(root, { runId: 'S1', startedAt: '2026-09-18T00:00:00Z', hostsRequested: ['10.0.0.1'] });
  await finalizeRunRecord(root, 'S1', { finishedAt: '2026-09-18T01:00:00Z' });
  const pinned = 'a'.repeat(64);
  await writeRunStart(root, { runId: 'S2', startedAt: '2026-09-18T02:00:00Z', hostsRequested: ['10.0.0.1'], prevDigest: pinned });
  const rec = JSON.parse(await fsp.readFile(runRecordPath(root, 'S2'), 'utf8'));
  assert.equal(rec.prevDigest, pinned);
});

// ════════════════════════════════════════════════════════════════════════════════════════════
// T3 / G5 — THE CHAIN COVERED THE INDEX AND NOT THE EVIDENCE.
//
// `sealRunRecord` digests `scan_run_<id>.json`. The delta does not READ that file's findings —
// there are none in it. It reads `scan_conclusion_raw.json` and `scan_finding_queue.json` in each
// written host's directory, and NOTHING covered them: delete a finding from a sealed baseline's
// findings file and `verifyRunChain` still said `chain-verified`, while the delta moved from
// `2 unchanged` to `1 new · 1 unchanged`. Five surfaces — the press release, the CE CHANGELOG, the
// EE README, SKILL.md item (3) and the client HTML's own per-row basis — said an altered baseline
// is detected and refused. Gate 3-B's B3 arm tampered the RECORD, so it proved the index leg only.
// ════════════════════════════════════════════════════════════════════════════════════════════

const RAW = 'scan_conclusion_raw.json';
const QUEUE = 'scan_finding_queue.json';

/** A run with one written host directory, through the real writers, sealed by finalize. */
async function mkRunWithHost(root, id, { queue = null, findings = [{ severity: 'HIGH', title: 'T' }] } = {}) {
  await writeRunStart(root, { runId: id, startedAt: '2026-09-18T00:00:00Z', hostsRequested: ['10.0.0.1'],
    pluginsRequested: ['010'], tier: 'pro' });
  await fsp.mkdir(path.join(root, 'h1'), { recursive: true });
  await fsp.writeFile(path.join(root, 'h1', RAW), JSON.stringify({
    runId: id, pluginStatus: [{ id: '010', name: 'aws-s3', status: 'ran' }],
    results: [{ id: '010', name: 'aws-s3', result: { up: true, findings } }],
  }), 'utf8');
  if (queue) await fsp.writeFile(path.join(root, 'h1', QUEUE), JSON.stringify(queue), 'utf8');
  await appendHostWritten(root, id, { host: '10.0.0.1', dir: 'h1' });
  await finalizeRunRecord(root, id, { finishedAt: '2026-09-18T01:00:00Z' });
}

test('G5 — altering a FINDINGS FILE after sealing is detected, and the refusal NAMES the file', async () => {
  const root = await tmp();
  await mkRunWithHost(root, 'R1', { findings: [{ severity: 'HIGH', title: 'A' }, { severity: 'HIGH', title: 'B' }] });
  const f = path.join(root, 'h1', RAW);
  const before = await fsp.readFile(f, 'utf8');
  const after = before.replace('"title":"B"', '"title":"C"');
  assert.equal(after.length, before.length, 'length-preserving, or it proves nothing');
  assert.notEqual(after, before, 'the tamper must actually land');
  await fsp.writeFile(f, after, 'utf8');

  const v = await verifyRunChain(root, 'R1');
  assert.equal(v.status, 'chain-broken',
    'the delta READS this file; a chain that does not cover it cannot support the claim that an altered baseline is refused');
  assert.match(v.reason, /h1\/scan_conclusion_raw\.json/,
    'and it must NAME the file — a refusal an operator cannot act on is half a refusal');
});

test('G5 ACCEPT — an untouched run with host files still verifies, digests and all', async () => {
  // The fourth quadrant. A leg that refuses everything would satisfy the test above and destroy
  // the feature; the motivating defect cannot exercise this direction.
  const root = await tmp();
  await mkRunWithHost(root, 'R1', { queue: [{ id: 'F-1', title: 'Q', severity: 'HIGH' }] });
  const v = await verifyRunChain(root, 'R1');
  assert.equal(v.status, 'chain-verified', v.reason);
  const rec = await readRunRecord(root, 'R1');
  assert.ok(rec.hostsWritten[0].digests, 'the record must carry the per-host digests it was sealed with');
  assert.match(rec.hostsWritten[0].digests[RAW], /^[0-9a-f]{64}$/);
});

test('G5 — a findings file that APPEARED after sealing is detected, not just one that changed', async () => {
  // ⚠️ THE DIRECTION THE PRESCRIPTION DID NOT NAME. Sealing only the files that existed leaves
  // ADDING one undetectable — and adding a `scan_finding_queue.json` to a sealed baseline injects
  // findings into the comparison, which moves rows out of `resolved` or into `new`. An absent file
  // is recorded as an explicit null so that its later appearance is a mismatch rather than a gap.
  const root = await tmp();
  await mkRunWithHost(root, 'R1');                       // no queue file at seal time
  const rec = await readRunRecord(root, 'R1');
  assert.equal(rec.hostsWritten[0].digests[QUEUE], null,
    'an absent file is sealed as null — never omitted, or its appearance is invisible, and never a fabricated digest');

  await fsp.writeFile(path.join(root, 'h1', QUEUE), JSON.stringify([{ id: 'F-X', title: 'injected', severity: 'CRITICAL' }]), 'utf8');
  const v = await verifyRunChain(root, 'R1');
  assert.equal(v.status, 'chain-broken');
  assert.match(v.reason, /scan_finding_queue\.json/);
});

test('G5 — a record sealed BEFORE per-host digests keeps verifying, and SAYS what it does not cover', async () => {
  // ⚠️ NOT-MEASURED MUST NOT READ AS TAMPERING — this module's own four-state rule. A record from
  // an earlier release carries no `digests`, and calling that chain-broken would accuse honest
  // evidence. But a bare `chain-verified` over it OVERSTATES: the findings files were never
  // covered. The verdict stays, the reason discloses.
  const root = await tmp();
  await mkRunWithHost(root, 'R1');
  const rec = await readRunRecord(root, 'R1');
  delete rec.hostsWritten[0].digests;                    // the pre-1.1.0 shape on disk
  await fsp.writeFile(runRecordPath(root, 'R1'), JSON.stringify(rec), 'utf8');
  await sealRunRecord(root, 'R1');                       // reseal: the RECORD is intact, just older in shape

  const v = await verifyRunChain(root, 'R1');
  assert.equal(v.status, 'chain-verified', 'an older record is not a tampered one');
  assert.match(v.reason, /findings files/i,
    'but the reason must say the findings files were not covered — otherwise the verdict claims more than it measured');
});

test('G5 — a sealed findings file that has been DELETED is chain-broken, naming it', async () => {
  const root = await tmp();
  await mkRunWithHost(root, 'R1', { queue: [{ id: 'F-1', title: 'Q', severity: 'HIGH' }] });
  await fsp.rm(path.join(root, 'h1', QUEUE));
  const v = await verifyRunChain(root, 'R1');
  assert.equal(v.status, 'chain-broken');
  assert.match(v.reason, /scan_finding_queue\.json was sealed with this record and is now missing/);
});

test('G5 — a findings file that cannot be READ is chain-UNREADABLE, never chain-broken', async () => {
  // ⚠️ THIS MODULE'S OWN FOUR-STATE RULE, applied to the new leg: ENOENT is a MEASUREMENT ("it is
  // not there") and EACCES is a FAILURE to measure. Collapsing them would report an unreadable
  // file as a deleted one — accusing honest evidence of tampering, which this module's header
  // names as the mirror-image error of the false clean. Written because I wrote that branch and
  // nothing exercised it.
  if (process.getuid?.() === 0) {
    // SKIPPED BY NAME, never silently: root reads through mode bits, so this leg cannot be made to
    // fail as root and a pass here would mean nothing. A gate that can skip itself without saying
    // so is not a gate.
    console.log('# SKIP (running as root: chmod cannot deny a read, so this leg cannot be exercised)');
    return;
  }
  const root = await tmp();
  await mkRunWithHost(root, 'R1');
  const f = path.join(root, 'h1', RAW);
  await fsp.chmod(f, 0o000);
  try {
    const v = await verifyRunChain(root, 'R1');
    assert.equal(v.status, 'chain-unreadable',
      'could-not-measure is its own verdict; it is neither verified nor broken');
    assert.match(v.reason, /could not be read/);
    assert.match(v.reason, /h1\/scan_conclusion_raw\.json/);
  } finally {
    await fsp.chmod(f, 0o600);                      // restore, or the temp dir cannot be cleaned
  }
});

// ════════════════════════════════════════════════════════════════════════════════════════════
// T4 / G6 — A DELETED SIDECAR READ AS "PREDATES CHAINING", WITH A FALSE CAUSE.
//
// `chain-absent` says "this record was written before chaining shipped, and we know that". It was
// returned for ANY missing sidecar, including one that was REMOVED — and deleting a file is the
// unsophisticated edit the label claims to catch. The two are separable deterministically: every
// record `writeRunStart` has produced since chaining carries the `prevDigest` KEY, so a record
// that has it and no sidecar was sealed and then unsealed.
// ════════════════════════════════════════════════════════════════════════════════════════════

test('G6 — a removed sidecar on a post-chaining record is chain-UNREADABLE, not chain-absent', async () => {
  const root = await tmp();
  await mkRunWithHost(root, 'R1');
  const rec = await readRunRecord(root, 'R1');
  assert.ok('prevDigest' in rec,
    'the premise: every record written since chaining carries the key, which is what separates '
    + 'removed from predates. If this fails the WRITER changed and this leg must be re-derived.');

  await fsp.rm(chainDigestPath(root, 'R1'));
  const v = await verifyRunChain(root, 'R1');
  assert.equal(v.status, 'chain-unreadable',
    'the sidecar was removed, not never written — reporting that as "predates chained run records" '
    + 'tells an operator the record is old when it has in fact been unsealed');
  assert.match(v.reason, /removed|never written/i);
});

// (The pre-chaining ACCEPT case for G6 is the corrected `a record from BEFORE chaining` leg
// above, which now carries the absence it asserts about. Two tests of one fact is one test
// and one decoration, and the decoration is the one that rots.)

test('G5 — the coverage clause names the TWO populations, because one number overstated', async () => {
  // ⚠️ THE DEFECT THIS PINS WAS FOUND ON THE FIRST REAL RECORD THE CLAUSE EVER DESCRIBED, not on a
  // fixture: a three-host cloud run sealed 3 findings files and 3 recorded ABSENCES, and the clause
  // said "6 sealed findings file(s)". A reader counts six files on disk; there are three. It is the
  // count-that-says-more-than-it-measured class, inside the sentence added to stop `chain-verified`
  // from overclaiming — so the fixture below is the real shape: one host WITH a queue file and one
  // WITHOUT, which is exactly what a cloud+network run produces.
  const root = await tmp();
  await mkRunWithHost(root, 'R1');                                   // no queue file: sealed as null
  const v = await verifyRunChain(root, 'R1');

  assert.equal(v.status, 'chain-verified', v.reason);
  assert.equal(v.filesPresent, 1, 'one findings file exists on disk');
  assert.equal(v.filesAbsent, 1, 'and one absence was recorded and re-verified as still absent');
  assert.match(v.reason, /1 findings file\(s\) verified · 1 recorded absent/);
  assert.doesNotMatch(v.reason, /2 sealed findings file\(s\)/,
    'the two populations must never be summed into a single count of files that exist');
});
