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
import { writeRunStart, finalizeRunRecord, runRecordPath } from '../utils/run_record.mjs';

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
