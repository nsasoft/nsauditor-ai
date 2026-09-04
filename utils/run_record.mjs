// The run record: one file per scan run, holding the coverage facts a report needs in order
// to state what was attempted rather than imply it.
//
// ⚠️ IT CARRIES HOSTS AND SCOPE ONLY — no credentials, no environment, NO FILESYSTEM PATHS.
// It sits in a directory a consultant zips and sends. Two shapes leak through "hosts and scope"
// if nobody stops them: `--host` accepts `user:pass@host`, so a credential arrives through the
// one field nobody classifies as a credential field; and the `--host-file` path and out root are
// environment (`/Users/<name>/…` publishes the operator's account). We hold the host LIST and
// never the path it came from.
import fsp from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
import { CE_RETENTION_MS } from './scan_history.mjs';

export const RUN_RECORD_SCHEMA = 1;
const RUN_FILE_RE = /^scan_run_(.+)\.json$/;

// ⚠️ THE INVARIANT IS "NO CREDENTIAL, EVER" — NOT "THE HOST SURVIVES". Deliberately the
// simplest rule that can hold it: decode an encoded separator, then after the LAST '@', then cut
// at the first URL delimiter. No heuristics, because every heuristic tried here bought a leak:
//   authority-first  leaked `admin:1234` from `admin:1234/56@10.0.0.7` (a numeric password with
//                    a slash reads exactly like host:port)
//   credential-first leaked `ss` from `user:p@ss/wd@host` (a '/' inside the password truncates
//                    the authority before the second '@' is seen)
// Two more findings were second CREDENTIAL SHAPES, not further heuristics:
//   query/fragment   cutting on '/' alone left `10.0.0.7?api_key=SECRET123` and
//                    `10.0.0.7#SECRET123` attached to the host, since neither has a '/' to cut
//                    on — closed by cutting on '/', '?' AND '#'.
//   percent-encoded  `user:pass%40host` has NO literal '@', so `lastIndexOf('@')` returned -1,
//   separator        took the "no userinfo" branch, and returned the WHOLE credential-bearing
//                    string unstripped — worse than any fragment leak, because nothing was
//                    stripped at all. Reachable: the record is written at scan START from
//                    `hostsRequested`, before DNS resolution, so a host that can never resolve
//                    still lands in the file. Closed by decoding `%40` to `@` before deciding.
// ACCEPTED COST, stated rather than hidden: shapes carrying a URL delimiter inside a PATH with no
// preceding userinfo — e.g. `https://user:pass@host/path@x` and `10.0.0.7/path@x` — resolve to
// the fragment after that delimiter instead of the host. A wrong host with no credential is the
// safe direction; a right host with a credential sometimes is not. None is a `--host` value
// anyone types.
//
// ⚠️ DENY-BY-DEFAULT ON THE OUTPUT, because the input side is unbounded. Five leaks in this
// function were closed by making the parse smarter, and two remained (`%2540` double-encoded,
// U+FF20 `＠` fullwidth) with a whole Unicode confusables table behind them. A host token is a
// CLOSED shape — letters, digits, dots, hyphens, underscores, an optional numeric port, or a
// bracketed IPv6 literal. Anything else is not a host, so it is not written, whatever produced
// it. This is the leg that makes the CLASS closed rather than the instance closed: a future
// input nobody imagined cannot leak, because the guard no longer depends on recognising it.
//
// ⚠️ THE ACCEPTED SHAPE NEEDS AS MUCH CARE AS THE REFUSED ONE. The first version of this took
// IPv6 only in brackets and ASCII-only labels, so `::1` and `fe80::1` — which this product scans,
// see utils/net_validation.mjs — were recorded as unparseable. That is the coverage lie: a record
// that cannot name a host that WAS scanned, which is the same class of dishonesty as a leak,
// pointed the other way. Unicode letters and digits are allowed because the confusables this guard
// exists for are PUNCTUATION look-alikes (U+FF20 '＠', U+2044 '⁄'), which \p{L}\p{N} excludes —
// a Cyrillic or German label is a host, not a credential.
const HOST_TOKEN_RE =
  /^(?:[\p{L}\p{N}._-]+|(?=[0-9A-Fa-f]*:)[0-9A-Fa-f:.]{2,}|\[[0-9A-Fa-f:.]+(?:%[A-Za-z0-9]+)?\])(?::\d+)?$/u;
export const UNPARSEABLE = '<unparseable-host>';

export function normaliseHost(raw) {
  const s0 = String(raw ?? '').trim().replace(/^[a-z][a-z0-9+.-]*:\/\//i, '');
  // A legitimate host can never contain `%40`. Only an encoded SEPARATOR or an encoded '@'
  // inside a password can, and both must be readable by the same rule — otherwise a
  // percent-encoded separator takes the "no userinfo" branch below and the entire credential
  // string is returned unstripped. Decode before deciding.
  const s = s0.replace(/%40/gi, '@');
  const at = s.lastIndexOf('@');
  const token = (at === -1 ? s : s.slice(at + 1)).split(/[/?#]/)[0];
  if (token !== '' && !HOST_TOKEN_RE.test(token)) {
    // Name the FIELD, never the value — logging the rejected string would defeat the whole
    // point of a guard that exists because the input side cannot be enumerated.
    console.warn('[RunRecord] normaliseHost: refused a non-host-shaped token');
    return UNPARSEABLE;
  }
  return token;
}

export function runRecordPath(outRoot, runId) {
  return path.join(outRoot, `scan_run_${runId}.json`);
}

// Per-RUN filename, because an out root accumulates runs and a fixed name is silently
// overwritten — which destroys the ability to re-render an earlier deliverable.
export function newRunId() {
  const t = new Date().toISOString().replace(/[-:]/g, '').replace(/\.\d+Z$/, 'Z');
  return `${t}-${crypto.randomBytes(3).toString('hex')}`;
}

// ⚠️ EVERY WRITE IS WRAPPED. A report-side fault must never fail a scan: that is the whole
// promise of reading a run directory instead of rendering inline. A failure becomes the scan's
// own warning and returns null.
//
// Write to a sibling `.tmp` and rename over the target — `rename` is atomic within a
// filesystem. This record is rewritten N+2 times per run (start, one append per host,
// finalize); a direct `writeFile` that crashes mid-write leaves truncated JSON, which
// `readRunRecord` then reports as ABSENT, and every later append or finalize call silently
// returns false against a record that never actually disappeared.
async function writeJsonSafe(file, obj, what) {
  const tmpFile = `${file}.tmp`;
  try {
    await fsp.mkdir(path.dirname(file), { recursive: true });
    await fsp.writeFile(tmpFile, JSON.stringify(obj, null, 2), 'utf8');
    await fsp.rename(tmpFile, file);
    return file;
  } catch (e) {
    // `writeFile` can succeed and the following `rename` can still fail, leaving the `.tmp`
    // behind — a stray file in the out root that a compliance evidence-pack walk will meet.
    // Best-effort cleanup; if it was never created (mkdir/writeFile itself failed), this is a
    // harmless ENOENT.
    await fsp.unlink(tmpFile).catch(() => {});
    console.warn(`[RunRecord] could not write ${what}: ${e?.message || e}`);
    return null;
  }
}

export async function writeRunStart(outRoot, rec) {
  // The whole body is wrapped, not just the fs call — `writeJsonSafe` already never throws,
  // but building `record` from caller input can: `(rec.hostsRequested ?? []).map(...)` throws
  // synchronously if a caller passes a non-array. "returns the path, or null on a wrapped
  // failure" (the interface contract) means EVERY failure, not only an fs failure.
  try {
    const record = {
      schema: RUN_RECORD_SCHEMA,
      runId: String(rec.runId),
      startedAt: rec.startedAt,
      finishedAt: null,
      hostsRequested: (rec.hostsRequested ?? []).map(normaliseHost),
      hostsWritten: [],
      pluginsRequested: rec.pluginsRequested ?? [],
      portsRequested: rec.portsRequested ?? null,
      tier: rec.tier ?? null,
      ceVersion: rec.ceVersion ?? null,
      eeVersion: rec.eeVersion ?? null,
      kevLoaded: Boolean(rec.kevLoaded),
      kevSnapshot: rec.kevSnapshot ?? null,
      epssLoaded: Boolean(rec.epssLoaded),
      epssSnapshot: rec.epssSnapshot ?? null,
    };
    return await writeJsonSafe(runRecordPath(outRoot, record.runId), record, 'run start');
  } catch (e) {
    console.warn(`[RunRecord] could not write run start: ${e?.message || e}`);
    return null;
  }
}

// ⚠️ IN-PROCESS PER-RUN LOCK. `appendHostWritten` and `finalizeRunRecord` are both a
// read-modify-write over the SAME file, and CE ships `--parallel <n>` (cli.mjs) — real runs
// finish multiple hosts at once, in one process. Without serialization, N concurrent callers
// each read the same stale `hostsWritten`, each write back their own single addition, and the
// last write wins: N appends land as 1. A run is one process, so an in-memory promise chain
// keyed by runId is sufficient — no file lock, no new dependency. A caller's own failure does
// not wedge the queue: the chain recovers from a rejection before letting the next entry run.
const runLocks = new Map();

function withRunLock(runId, fn) {
  const key = String(runId);
  // `prior` is always either `Promise.resolve()` (a fresh key) or the tail wrapper stored
  // below (which itself always resolves via its own `(() => {}, () => {})`) — it never
  // rejects, so `fn` as the SECOND argument here is unreachable by construction. Kept
  // rather than dropped: it costs nothing and stops a future edit to the tail wrapper from
  // silently making `prior` capable of rejecting without this call site being revisited.
  const prior = runLocks.get(key) ?? Promise.resolve();
  const settled = prior.then(fn, fn);
  runLocks.set(key, settled.then(() => {}, () => {}));
  return settled;
}

// ⚠️ APPEND PER HOST, and this is not a style choice — it is what makes the interrupted-run
// case REACHABLE. If `hostsWritten` were populated only at finalize, an interrupted run would
// ALWAYS carry `hostsWritten: []`, so (a) the "crash after the last directory" shape the second
// refusal exists for could never be produced by this writer, and (b) far worse, `--allow-partial`
// over an interrupted run would render ZERO hosts and put "N of N requested hosts were not
// scanned" on a client's cover — FALSE, because they WERE scanned; only the record was never
// finalized. A false "not scanned" over scanned hosts is the exact false clean this record exists
// to prevent, inverted.
export async function appendHostWritten(outRoot, runId, { host, dir }) {
  return withRunLock(runId, async () => {
    const existing = await readRunRecord(outRoot, runId);
    if (!existing) return false;
    existing.hostsWritten = [...(existing.hostsWritten ?? []),
      { host: normaliseHost(host), dir: path.basename(String(dir ?? '')) }];
    return Boolean(await writeJsonSafe(runRecordPath(outRoot, runId), existing, 'host append'));
  });
}

export async function finalizeRunRecord(outRoot, runId, opts = {}) {
  // ⚠️ REFUSE THE STRAY KEY RATHER THAN IGNORE IT. This signature NARROWED — `hostsWritten` moved
  // to appendHostWritten() — and an ignored option is a silent contract. The caller who gets burned
  // is not one of the six that were migrated; it is the seventh, written next cycle by someone
  // reading an old example, whose fixture then reads perfectly clean while recording no hosts at
  // all. Fail at the call site, where the mistake is, not in a fixture that looks green.
  if ('hostsWritten' in opts) {
    throw new TypeError('finalizeRunRecord no longer takes hostsWritten; call appendHostWritten per host');
  }
  const { finishedAt } = opts;
  return withRunLock(runId, async () => {
    const existing = await readRunRecord(outRoot, runId);
    if (!existing) return false;
    existing.finishedAt = finishedAt ?? new Date().toISOString();
    return Boolean(await writeJsonSafe(runRecordPath(outRoot, runId), existing, 'run finalize'));
  });
}

export async function readRunRecord(outRoot, runId) {
  try { return JSON.parse(await fsp.readFile(runRecordPath(outRoot, runId), 'utf8')); }
  catch { return null; }
}

export async function listRunRecords(outRoot) {
  let names = [];
  try { names = await fsp.readdir(outRoot); } catch { return []; }
  const out = [];
  for (const n of names) {
    if (!RUN_FILE_RE.test(n)) continue;
    try { out.push(JSON.parse(await fsp.readFile(path.join(outRoot, n), 'utf8'))); } catch { /* unreadable: not a run */ }
  }
  return out.sort((a, b) => String(b.startedAt ?? '').localeCompare(String(a.startedAt ?? '')));
}

// Run records fall under the SAME CE window as scan history, from the same constant — two
// retention horizons over one scan's artifacts is a discrepancy a customer would find first.
export async function pruneRunRecordsForCE(outRoot, now = Date.now()) {
  const cutoff = now - CE_RETENTION_MS;
  let removed = 0;
  for (const rec of await listRunRecords(outRoot)) {
    const t = Date.parse(rec?.startedAt ?? '');
    if (!Number.isFinite(t) || t >= cutoff) continue;
    try { await fsp.unlink(runRecordPath(outRoot, rec.runId)); removed += 1; } catch { /* already gone */ }
  }
  return removed;
}
