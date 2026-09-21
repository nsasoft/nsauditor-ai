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
  // ⚠️ THE FIXTURE CHANGED WHEN SEALING MOVED INSIDE `finalizeRunRecord`, and the honest shape is
  // now what a PRE-1.1.0 record looks like on disk: the record exists, its sidecar does not. Writing
  // it the old way would no longer produce an unsealed record at all, so this leg would have gone
  // vacuous — passing while testing nothing — which is worse than failing.
  const root = await tmp();
  await writeRunStart(root, { runId: 'R0', startedAt: '2026-09-18T00:00:00Z', hostsRequested: ['10.0.0.1'] });
  await finalizeRunRecord(root, 'R0', { finishedAt: '2026-09-18T01:00:00Z' });
  await fsp.rm(chainDigestPath(root, 'R0'));          // a record written before chaining shipped
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
