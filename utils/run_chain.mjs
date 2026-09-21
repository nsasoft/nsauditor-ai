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

// ⚠️ THE CHAIN COVERED THE INDEX AND NOT THE EVIDENCE, and the two are different files. The run
// record carries no findings; the delta reads THESE, in each written host's directory. Until
// 2026-09-20 nothing hashed them, so deleting a finding from a sealed baseline left the verdict at
// `chain-verified` while the comparison moved — and five published surfaces said an altered
// baseline is detected and refused. Hash what the CONSUMER reads, not merely what the writer
// indexes.
export const HOST_EVIDENCE_FILES = Object.freeze(['scan_conclusion_raw.json', 'scan_finding_queue.json']);

/**
 * Digest every evidence file of one written host directory, for sealing INTO the record.
 * ⚠️ AN ABSENT FILE IS SEALED AS AN EXPLICIT `null`, NEVER OMITTED and never a fabricated digest.
 * Omitting it would make its later APPEARANCE invisible, and adding a `scan_finding_queue.json` to
 * a sealed baseline injects findings into the comparison — which moves rows out of `resolved` or
 * into `new` just as surely as editing one does.
 * A file that exists but cannot be READ is neither: it is left out and warned, because recording
 * it as absent would accuse it of appearing later, and this module's rule is that not-measured
 * must never render as tampering.
 */
export async function digestHostEvidence(outRoot, dir) {
  const out = {};
  for (const name of HOST_EVIDENCE_FILES) {
    try {
      out[name] = sha256(await fsp.readFile(path.join(outRoot, dir, name)));
    } catch (e) {
      if (e?.code === 'ENOENT') out[name] = null;
      else console.warn(`[RunChain] could not digest ${dir}/${name}: ${e?.message || e}`);
    }
  }
  return out;
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

  // ⚠️ "PREDATES CHAINING" AND "WAS UNSEALED" ARE DIFFERENT FACTS, AND THEY ARE SEPARABLE
  // DETERMINISTICALLY. This returned `chain-absent` for ANY missing sidecar — so deleting the
  // sidecar, which is the unsophisticated edit the label claims to catch, downgraded a REFUSAL
  // into a limit with a FALSE CAUSE: it told the operator the record was old. Every record
  // `writeRunStart` has produced since chaining carries the `prevDigest` KEY, so a record that
  // has the key and no sidecar was sealed and then unsealed. The key is checked rather than the
  // sidecar's absence, so a genuinely pre-chaining record keeps its honest `chain-absent`.
  let recorded;
  try { recorded = (await fsp.readFile(chainDigestPath(outRoot, runId), 'utf8')).trim(); }
  catch {
    let parsed = null;
    try { parsed = JSON.parse(bytes.toString('utf8')); } catch { /* unparseable: treat as pre-chaining */ }
    if (parsed && typeof parsed === 'object' && 'prevDigest' in parsed) {
      return { status: 'chain-unreadable',
        reason: 'this record was written after chaining shipped (it carries a prevDigest) and its digest '
          + 'sidecar is gone — removed, or never written; alteration can neither be confirmed nor ruled out' };
    }
    return { status: 'chain-absent', reason: 'no digest sidecar — this record predates chained run records' };
  }

  if (!/^[0-9a-f]{64}$/i.test(recorded)) {
    return { status: 'chain-unreadable', reason: 'the digest sidecar is present but is not a SHA-256 digest' };
  }
  const actual = sha256(bytes);
  if (actual !== recorded.toLowerCase()) {
    return { status: 'chain-broken', digest: actual, reason: 'the run record does not match the digest recorded when it was sealed' };
  }

  // ── THE EVIDENCE, not just the index. Verified only after the record's own digest matches,
  // because the digests being checked are READ FROM that record: checking them first would be
  // trusting bytes that have not been vouched for yet.
  let parsed = null;
  try { parsed = JSON.parse(bytes.toString('utf8')); } catch { /* the digest matched, so this is a parse we can survive */ }
  const written = Array.isArray(parsed?.hostsWritten) ? parsed.hostsWritten : [];
  let filesCovered = 0;
  let hostsUncovered = 0;
  for (const h of written) {
    if (!h?.digests || typeof h.digests !== 'object') { hostsUncovered += 1; continue; }
    for (const [name, expected] of Object.entries(h.digests)) {
      const where = `${h.dir}/${name}`;
      let actual = null;
      try {
        actual = sha256(await fsp.readFile(path.join(outRoot, h.dir, name)));
      } catch (e) {
        // ⚠️ ENOENT IS A MEASUREMENT ("it is not there"); anything else is a FAILURE to measure,
        // and the two must not share a verdict. Reporting an unreadable file as missing would
        // accuse honest evidence of having been deleted.
        if (e?.code !== 'ENOENT') {
          return { status: 'chain-unreadable',
            reason: `the findings file ${where} is sealed with this record but could not be read, so alteration could neither be confirmed nor ruled out` };
        }
      }
      if (expected === null && actual !== null) {
        return { status: 'chain-broken',
          reason: `the findings file ${where} did not exist when this record was sealed and exists now — findings added to a baseline after the fact change the comparison exactly as edited ones do` };
      }
      if (expected !== null && actual === null) {
        return { status: 'chain-broken',
          reason: `the findings file ${where} was sealed with this record and is now missing` };
      }
      if (expected !== null && actual !== expected) {
        return { status: 'chain-broken', digest: actual,
          reason: `the findings file ${where} does not match the digest sealed with the record` };
      }
      filesCovered += 1;
    }
  }

  // The LINK. `prevDigest` names a digest, not an id, so the check is existential: does any record
  // in this out root still hash to it? If none does, this record vouches for bytes that no longer
  // exist — which is what a rewritten predecessor looks like from here.
  const linkedTo = parsed?.prevDigest ?? null;
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
  // ⚠️ THE REASON STATES ITS OWN COVERAGE, because `chain-verified` over a record that sealed no
  // findings files claims more than it measured — and the surfaces that quote this verdict say an
  // altered BASELINE is refused, which is a claim about the findings.
  const coverage = hostsUncovered > 0
    ? `; the findings files of ${hostsUncovered} written host(s) were NOT covered by this record `
      + '(it predates per-host sealing), so alteration of those files could not be ruled out'
    : (written.length ? `, together with ${filesCovered} sealed findings file(s) across ${written.length} written host(s)` : '');
  return {
    status: 'chain-verified',
    digest: actual,
    linkedTo,
    linkBroken,
    filesCovered,
    hostsUncovered,
    reason: `the record matches the digest recorded when it was sealed${coverage}`,
  };
}
