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

export function normaliseHost(raw) {
  let s = String(raw ?? '').trim();
  s = s.replace(/^[a-z][a-z0-9+.-]*:\/\//i, '');   // scheme
  s = s.split('/')[0];                              // path
  const at = s.lastIndexOf('@');
  if (at !== -1) s = s.slice(at + 1);               // userinfo
  return s;
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
async function writeJsonSafe(file, obj, what) {
  try {
    await fsp.mkdir(path.dirname(file), { recursive: true });
    await fsp.writeFile(file, JSON.stringify(obj, null, 2), 'utf8');
    return file;
  } catch (e) {
    console.warn(`[RunRecord] could not write ${what}: ${e?.message || e}`);
    return null;
  }
}

export async function writeRunStart(outRoot, rec) {
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
  return writeJsonSafe(runRecordPath(outRoot, record.runId), record, 'run start');
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
  const existing = await readRunRecord(outRoot, runId);
  if (!existing) return false;
  existing.hostsWritten = [...(existing.hostsWritten ?? []),
    { host: normaliseHost(host), dir: path.basename(String(dir ?? '')) }];
  return Boolean(await writeJsonSafe(runRecordPath(outRoot, runId), existing, 'host append'));
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
  const existing = await readRunRecord(outRoot, runId);
  if (!existing) return false;
  existing.finishedAt = finishedAt ?? new Date().toISOString();
  return Boolean(await writeJsonSafe(runRecordPath(outRoot, runId), existing, 'run finalize'));
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
