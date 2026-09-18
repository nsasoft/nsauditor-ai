// Tamper-EVIDENCE for run records: a SHA-256 chain, no keys, no egress, no new dependency.
//
// ⚠️ SAY WHAT IT IS NOT. A chain stored on the same disk as the records it covers is defeated by
// an attacker who recomputes every successor. This is evidence against accidental corruption,
// partial restore and unsophisticated edits — NOT tamper-proofing against host-level access, and
// NOT non-repudiation: nothing here is signed and nothing names an author. Ed25519 + custody is a
// separate, heavier property. The delta engine carries that sentence into its own output, because
// a limit that lives only in documentation is a limit the reader never meets.
//
// ⚠️ NO CANONICALISER, DELIBERATELY. The digest covers the EXACT BYTES ON DISK — read back, never
// re-serialised from the in-memory object. Two recorded incidents say why: a hand-rolled
// canonicaliser that serialised `new Date()` as `{}` (signer and verifier shared the bug, so it
// was invisible in both directions), and the 2026-09-14 sample pack whose envelope digests were
// computed over RAW bytes while the archive shipped SANITIZED ones — 72 of 96 digests named bytes
// that were never in the archive. Hash what you PERSIST.
import fsp from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
// ⚠️ SELF-CONTAINED BY NECESSITY: `run_record` imports the sealer from here, so importing the
// path helper back from it would be a cycle. The filename shape is one line and is pinned by
// the tests in both modules.
const runRecordPath = (outRoot, runId) => path.join(outRoot, `scan_run_${runId}.json`);

const RUN_FILE_RE = /^scan_run_(.+)\.json$/;
const sha256 = (buf) => crypto.createHash('sha256').update(buf).digest('hex');

export function chainDigestPath(outRoot, runId) {
  return path.join(outRoot, `scan_run_${runId}.sha256`);
}

// Sealed at FINALIZE and never before: the record is rewritten N+2 times per run (start, one
// append per host, finalize), so a digest taken earlier names bytes that are meant to change.
export async function sealRunRecord(outRoot, runId) {
  try {
    const digest = sha256(await fsp.readFile(runRecordPath(outRoot, runId)));
    await fsp.writeFile(chainDigestPath(outRoot, runId), `${digest}\n`, 'utf8');
    return digest;
  } catch (e) {
    console.warn(`[RunChain] could not seal run record: ${e?.message || e}`);
    return null;
  }
}

// The digest of the most recently finalized record in this out root, for the NEXT run to carry as
// its `prevDigest`. Null when there is none — a first run is not a broken chain.
export async function latestSealedDigest(outRoot) {
  let names = [];
  try { names = await fsp.readdir(outRoot); } catch { return null; }
  const runs = names.filter((n) => RUN_FILE_RE.test(n)).sort();
  for (const n of runs.reverse()) {
    const id = n.match(RUN_FILE_RE)[1];
    try { return (await fsp.readFile(chainDigestPath(outRoot, id), 'utf8')).trim() || null; } catch { /* unsealed */ }
  }
  return null;
}

/**
 * @returns {{status:'chain-verified'|'chain-broken'|'chain-absent'|'chain-unreadable', reason:string,
 *            digest?:string, linkedTo?:string|null, linkBroken?:boolean}}
 * ⚠️ FOUR STATES, NOT TWO, AND THE DISTINCTION IS THE POINT. `chain-absent` (a record written
 * before this shipped) and `chain-unreadable` (we could not measure) are NOT `chain-broken`.
 * Rendering "nothing was checked" as "tampering" accuses honest evidence; rendering it as
 * "verified" is the false clean. Both are their own verdict.
 */
export async function verifyRunChain(outRoot, runId) {
  let bytes;
  try { bytes = await fsp.readFile(runRecordPath(outRoot, runId)); }
  catch { return { status: 'chain-unreadable', reason: 'the run record itself could not be read' }; }

  let recorded;
  try { recorded = (await fsp.readFile(chainDigestPath(outRoot, runId), 'utf8')).trim(); }
  catch { return { status: 'chain-absent', reason: 'no digest sidecar — this record predates chained run records' }; }

  if (!/^[0-9a-f]{64}$/i.test(recorded)) {
    return { status: 'chain-unreadable', reason: 'the digest sidecar is present but is not a SHA-256 digest' };
  }
  const actual = sha256(bytes);
  if (actual !== recorded.toLowerCase()) {
    return { status: 'chain-broken', digest: actual, reason: 'the run record does not match the digest recorded when it was sealed' };
  }

  // The LINK. `prevDigest` names a digest, not an id, so the check is existential: does any record
  // in this out root still hash to it? If none does, this record vouches for bytes that no longer
  // exist — which is what a rewritten predecessor looks like from here.
  let linkedTo = null;
  try { linkedTo = JSON.parse(bytes.toString('utf8'))?.prevDigest ?? null; } catch { /* verified above */ }
  let linkBroken = false;
  if (linkedTo) {
    linkBroken = true;
    let names = [];
    try { names = await fsp.readdir(outRoot); } catch { /* unreadable dir */ }
    for (const n of names) {
      if (!RUN_FILE_RE.test(n)) continue;
      try {
        if (sha256(await fsp.readFile(path.join(outRoot, n))) === linkedTo) { linkBroken = false; break; }
      } catch { /* skip */ }
    }
  }
  return { status: 'chain-verified', digest: actual, linkedTo, linkBroken, reason: 'the record matches the digest recorded when it was sealed' };
}
