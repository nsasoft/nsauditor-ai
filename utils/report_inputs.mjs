// utils/report_inputs.mjs — the only module that knows the filesystem layout of a scan run.
// Turns a run directory into ONE normalised model that the executive HTML report and the Jira
// CSV export both consume. Every refusal below is written before the happy path, because a
// report that renders confidently over a partial or mismatched run is the false clean this
// feature exists to prevent: a correct report about the wrong (or incomplete) run reads
// identically to a correct one without that caveat.
import fsp from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
import {
  RUN_RECORD_SCHEMA, UNPARSEABLE, runRecordPath, listRunRecords, readRunRecord,
} from './run_record.mjs';
import { CE_RETENTION_MS } from './scan_history.mjs';

const refuse = (reason, message) => ({ ok: false, reason, message });

// Mirrors run_record.mjs's private RUN_FILE_RE. Not exported from there, so it is re-declared
// here — deliberately, and only for the narrow purpose below: telling "no run-record file
// exists" apart from "one exists but listRunRecords()/readRunRecord() could not parse it"
// (which both currently swallow as an absence — EACCES, EISDIR, or invalid JSON all read as
// null/skipped). A directory LISTING sees a file's NAME regardless of whether its CONTENTS are
// readable (readdir needs only the directory's own permission bits), so comparing "a name that
// looks like a run record exists on disk" against "listRunRecords() parsed zero of them" is a
// portable way to catch this without guessing errno codes ourselves.
const RUN_FILE_RE = /^scan_run_(.+)\.json$/;

async function listEntryNames(outRoot) {
  try { return await fsp.readdir(outRoot); } catch { return []; }
}

// Shared by both callers below: a directory LISTING sees a file's NAME regardless of whether
// its CONTENTS are readable, so this is how "present but unreadable" is told apart from
// "genuinely never written" without guessing errno codes. Pass `onlyName` to check one specific
// filename (the explicit `--run <id>` path); omit it to find any run-record-shaped name at all
// (the "pick the latest run" path, which does not know a candidate id yet).
async function findRunRecordFilenames(outRoot, onlyName = null) {
  const names = await listEntryNames(outRoot);
  if (onlyName) return names.includes(onlyName) ? [onlyName] : [];
  return names.filter((n) => RUN_FILE_RE.test(n));
}

// Walk one level of `outRoot`, read each host directory's scan_conclusion_raw.json, and report
// what a run that never wrote a run record still left behind: which directories carry a raw at
// all, whatever runId (if any) is embedded in one of them, and the newest mtime among them (used
// to decide whether the run is inside or outside the retention window).
async function probeRawDirs(outRoot) {
  let entries;
  try { entries = await fsp.readdir(outRoot, { withFileTypes: true }); }
  catch { return { dirs: [], anyRunId: null, newestMtime: 0 }; }

  const dirs = [];
  let anyRunId = null;
  let newestMtime = 0;
  for (const ent of entries) {
    if (!ent.isDirectory()) continue;
    const rawPath = path.join(outRoot, ent.name, 'scan_conclusion_raw.json');
    let raw, stat;
    try {
      raw = JSON.parse(await fsp.readFile(rawPath, 'utf8'));
      stat = await fsp.stat(rawPath);
    } catch { continue; }
    dirs.push(ent.name);
    if (raw?.runId) anyRunId = raw.runId;
    if (stat.mtimeMs > newestMtime) newestMtime = stat.mtimeMs;
  }
  return { dirs, anyRunId, newestMtime };
}

// ⚠️ UNPARSEABLE IS A SINGLE CONSTANT (utils/run_record.mjs), so two different refused `--host`
// inputs are INDISTINGUISHABLE once written into `hostsRequested`. A naive membership check
// (`hostsRequested.filter(h => !hostsWritten.some(w => w === h))`) does not CONSUME a match, so
// one written unparseable row reads as "covering" every unparseable row requested — a false
// "complete" over a host that was never scanned. This does a proper multiset diff instead: each
// written host can satisfy exactly one requested slot. A deficit on an ordinary host name is
// reported by name; a deficit on the UNPARSEABLE sentinel can never be named (we do not know
// which of the N original bad inputs it was), so it is counted and disclosed as "coverage cannot
// be established for it" rather than either silently ignored or falsely reported as a specific
// missing host.
function computeMissing(hostsRequested, writtenHosts) {
  const pool = new Map();
  for (const h of writtenHosts) pool.set(h, (pool.get(h) ?? 0) + 1);
  const missingNamed = [];
  let missingUnparseable = 0;
  for (const h of hostsRequested) {
    const remaining = pool.get(h) ?? 0;
    if (remaining > 0) {
      pool.set(h, remaining - 1);
    } else if (h === UNPARSEABLE) {
      missingUnparseable += 1;
    } else {
      missingNamed.push(h);
    }
  }
  return { missingNamed, missingUnparseable };
}

function describeMissing(missingNamed, missingUnparseable) {
  const parts = [];
  if (missingNamed.length) parts.push(missingNamed.join(', '));
  if (missingUnparseable) {
    parts.push(`${missingUnparseable} host(s) whose input could not be parsed into a name — ` +
      `coverage cannot be established for ${missingUnparseable === 1 ? 'it' : 'them'}`);
  }
  return parts.join('; ');
}

function shapeFinding(host, f) {
  const severity = f?.severity != null ? String(f.severity).toUpperCase() : 'INFO';
  const port = f?.port ?? null;
  const title = f?.title ?? null;
  const cves = Array.isArray(f?.cves) ? f.cves.map(String)
    : Array.isArray(f?.cve) ? f.cve.map(String) : [];
  // CE ships no KEV/EPSS store of its own (utils/scan_history.mjs comment at cli.mjs:2780):
  // never invent an enrichment value that was not actually carried on the finding.
  const kev = f?.kev === true;
  const epss = typeof f?.epss === 'number' && Number.isFinite(f.epss) ? f.epss : null;
  const id = crypto.createHash('sha256')
    .update(JSON.stringify([host, port, severity, title]))
    .digest('hex').slice(0, 16);
  return {
    host, port, severity, title,
    detail: f?.detail ?? f?.description ?? null,
    remediation: f?.remediation ?? null,
    cves, kev, epss, id,
  };
}

// The envelope shape is `{ id, name, result }` (plugin_manager.mjs's manifest entries pair with
// `results[]` this way); reachability and findings both live INSIDE `result`, never at the raw's
// top level. A host counts as up if ANY plugin's envelope observed it up — a host with nothing
// reporting `up: true` (including a host with zero envelopes) is not reachable.
function shapeHost(host, dir, raw) {
  const envelopes = Array.isArray(raw.results) ? raw.results : [];
  const up = envelopes.some((e) => e?.result?.up === true);
  const findings = [];
  for (const e of envelopes) {
    const rawFindings = e?.result?.findings;
    if (Array.isArray(rawFindings)) for (const f of rawFindings) findings.push(shapeFinding(host, f));
  }
  return {
    host, dir, up, findings,
    pluginStatus: Array.isArray(raw.pluginStatus) ? raw.pluginStatus : [],
  };
}

function buildModel(rec, hosts, counts) {
  const { requested, written, missingNamed, missingUnparseable, incomplete } = counts;
  const reachable = hosts.filter((h) => h.up).length;
  const findings = hosts.flatMap((h) => h.findings);

  const plugins = { ran: 0, skipped: 0, errored: 0, timedOut: 0, byHost: [] };
  for (const h of hosts) {
    // CC-2: `dir` rides alongside `host` here so the renderer can key its per-host plugin
    // status table by DIRECTORY, never by host name — `hosts` (and therefore `model.hosts`) is
    // one entry per scan directory, and two directories can legitimately share a host name
    // (`--host 10.0.0.7,10.0.0.7`, a repeated --host-file line, an overlapping range — none of
    // which utils/host_iterator.mjs de-duplicates). A name-keyed Map is last-write-wins and
    // silently drops every same-named host's own plugin table but the final one's.
    plugins.byHost.push({ host: h.host, dir: h.dir, status: h.pluginStatus });
    for (const ps of h.pluginStatus) {
      if (ps?.status === 'ran') plugins.ran += 1;
      else if (ps?.status === 'skipped') plugins.skipped += 1;
      else if (ps?.status === 'error') plugins.errored += 1;
      else if (ps?.status === 'timeout') plugins.timedOut += 1;
    }
  }

  return {
    runId: rec.runId,
    startedAt: rec.startedAt,
    finishedAt: rec.finishedAt,
    tier: rec.tier,
    ceVersion: rec.ceVersion,
    eeVersion: rec.eeVersion,
    coverage: {
      requested,
      written,
      reachable,
      missing: missingNamed,
      partial: missingNamed.length > 0 || missingUnparseable > 0,
      incomplete,
    },
    plugins,
    kev: { loaded: Boolean(rec.kevLoaded), snapshot: rec.kevSnapshot ?? null },
    epss: { loaded: Boolean(rec.epssLoaded), snapshot: rec.epssSnapshot ?? null },
    hosts: hosts.map((h) => ({ host: h.host, dir: h.dir, up: h.up, findings: h.findings })),
    findings,
  };
}

// Schema, then binding, then completeness — in that order, so a malformed record can never be
// read as a partial one: a schema this build does not understand must refuse before any attempt
// is made to interpret its host lists, and a two-way binding mismatch must refuse before
// completeness arithmetic ever looks at what that (wrongly-bound) directory contains.
async function finishLoadingRecord(outRoot, rec, allowPartial) {
  if (rec.schema !== RUN_RECORD_SCHEMA) {
    return refuse('unknown-schema',
      `The run record for \`${rec.runId}\` declares schema ${rec.schema}; this build understands ` +
      `schema ${RUN_RECORD_SCHEMA}. Refusing rather than guessing what its fields mean.`);
  }

  const hosts = [];
  for (const { host, dir } of rec.hostsWritten ?? []) {
    const rawPath = path.join(outRoot, dir, 'scan_conclusion_raw.json');
    let raw;
    try { raw = JSON.parse(await fsp.readFile(rawPath, 'utf8')); }
    catch {
      // Loose-but-honest wording matters here: this same catch fires for a MISSING file
      // (ENOENT), an UNREADABLE one (EACCES/EISDIR), and a perfectly readable file that is not
      // valid JSON — "has no readable scan_conclusion_raw.json" is false in that third case.
      return refuse('binding-mismatch',
        `The run record lists \`${dir}\`, whose scan_conclusion_raw.json could not be read or ` +
        'parsed as valid JSON.');
    }
    if (raw.runId !== rec.runId) {
      return refuse('binding-mismatch',
        `Directory \`${dir}\` names run \`${raw.runId}\`, but the record being reported is ` +
        `\`${rec.runId}\`. Refusing: a directory from another engagement cannot be reported as ` +
        'this one.');
    }
    hosts.push(shapeHost(host, dir, raw));
  }

  const requested = (rec.hostsRequested ?? []).length;
  const written = hosts.length;
  const { missingNamed, missingUnparseable } = computeMissing(rec.hostsRequested ?? [], hosts.map((h) => h.host));
  const incomplete = !rec.finishedAt;
  const anyMissing = missingNamed.length > 0 || missingUnparseable > 0;

  // ORDER MATTERS (mutant-proven — see the task report): the incomplete case is checked FIRST.
  // A crash after the LAST host directory is written leaves hostsWritten === hostsRequested with
  // no finishedAt, so `anyMissing` is false and the partial-hosts message below would be FALSE —
  // it would say nothing is missing on a run that never actually finished.
  if (incomplete && !allowPartial) {
    const completionClause = anyMissing
      ? `${written} of ${requested} requested hosts were written (missing: ` +
        `${describeMissing(missingNamed, missingUnparseable)})`
      : `All ${requested} requested hosts were written`;
    return refuse('incomplete-run',
      `Refusing to report: this run never finished. ${completionClause}, but the scan did not ` +
      'record completion, so plugins may not have run on the last host. Re-run it, or pass ' +
      '`--allow-partial` to report on what was recorded.');
  }
  if (anyMissing && !allowPartial) {
    return refuse('partial-hosts',
      `Refusing to report: this run requested ${requested} hosts and wrote ${written}. ` +
      `Missing: ${describeMissing(missingNamed, missingUnparseable)}. Re-run those hosts, or pass ` +
      '`--allow-partial` to report on what was recorded.');
  }

  return { ok: true, model: buildModel(rec, hosts, { requested, written, missingNamed, missingUnparseable, incomplete }) };
}

/**
 * Discover, validate and normalise a scan run into one model.
 * @returns {Promise<{ ok: true, model: object } | { ok: false, reason: string, message: string }>}
 */
export async function loadRun(outRoot, { runId = null, allowPartial = false } = {}, env = {}) {
  if (runId) {
    const rec = await readRunRecord(outRoot, runId);
    if (!rec) {
      // readRunRecord swallows EACCES/EISDIR as "absent" the same way listRunRecords does
      // below — tell "genuinely never written" from "present but broken" apart.
      const fname = path.basename(runRecordPath(outRoot, runId));
      if ((await findRunRecordFilenames(outRoot, fname)).length > 0) {
        return refuse('record-unreadable',
          `The run record for \`${runId}\` is present but could not be read or parsed. Refusing ` +
          'rather than reporting this run as if no record existed.');
      }
      return refuse('no-run', `No run record named \`${runId}\` is present.`);
    }
    return finishLoadingRecord(outRoot, rec, allowPartial);
  }

  const records = await listRunRecords(outRoot);

  // ⚠️ UNCONDITIONAL cross-check — NOT gated on `records.length === 0`. The single-record
  // topology (nothing parsed at all) is not the dangerous one; a MULTI-record out-root with one
  // corrupt file is. `records.length > 0` would otherwise short-circuit past this check,
  // listRunRecords()'s own `catch { /* unreadable: not a run */ }` silently drops the bad file,
  // and a DIFFERENT run — the one that happened to parse — would render under a subject line
  // naming a run the operator may not have wanted at all. That is the same "unreadable read as
  // absent" defect this module exists to close, surviving one topology over. Comparing "every
  // scan_run_*.json name on disk" against "the filename each PARSED record implies" (writeRunStart
  // always names a record after its own runId, via runRecordPath) finds a corrupt sibling
  // regardless of how many other records parsed fine — and does not try to guess which run was
  // WANTED, because it cannot know: refusing beats guessing.
  //
  // This does not apply to the explicit `--run <id>` path above: that path only ever inspects the
  // ONE filename it was asked for, so a different, unrelated corrupt file is invisible to it by
  // construction — a deliberate ruling, not an oversight (see the "explicit --run ignores an
  // unrelated corrupt sibling" fixture in the test file for the pinned behaviour).
  const onDiskRunFiles = await findRunRecordFilenames(outRoot);
  const parsedFilenames = new Set(records.map((r) => `scan_run_${r.runId}.json`));
  const unparsedRunFiles = onDiskRunFiles.filter((n) => !parsedFilenames.has(n));
  if (unparsedRunFiles.length > 0) {
    return refuse('record-unreadable',
      `${unparsedRunFiles.length} run record file(s) are present under this output directory but ` +
      `could not be read or parsed (${unparsedRunFiles.join(', ')})` +
      (records.length > 0
        ? `, though ${records.length} other run record(s) parsed successfully. Refusing rather ` +
          'than silently rendering a different run under this subject line — the intended run ' +
          'cannot be told apart from the one that happened to parse.'
        : '. Refusing rather than reporting this scan as if no record ever existed.'));
  }

  if (records.length === 0) {
    const probe = await probeRawDirs(outRoot);
    if (probe.dirs.length === 0) {
      return refuse('no-run', `No scan run was found under ${path.basename(outRoot)}.`);
    }
    if (!probe.anyRunId) {
      // ⚠️ Do not assert a single cause. A raw with no runId can be a scan from before run
      // records existed, OR a CTEM watch-mode cycle, which deliberately writes no record
      // (cli.mjs returns above the record-writing path there; CE's basicCTEM capability text
      // says the alerting loop "adds no evidence retention"). Both are real; name both.
      return refuse('older-format',
        "This scan's raw record carries no run id, so it did not write a run record. This can " +
        'mean the scan ran under a version of NSAuditor AI that predates run records, or it came ' +
        'from a CTEM watch-mode cycle, which deliberately writes no run record. Grouping by run ' +
        'is not available, and coverage cannot be stated for it.');
    }
    const insideWindow = Date.now() - probe.newestMtime < CE_RETENTION_MS;
    const id = probe.anyRunId;
    // ⚠️ CC-5: "the record was deleted or moved" used to be asserted as THE cause, but the
    // evidence on disk here (a raw host directory naming this runId, no run-record file) cannot
    // tell that apart from "the record was never successfully written in the first place" —
    // `writeRunStart`'s own failure is warned and swallowed (cli.mjs), and the scan proceeds
    // with `opts.runId` set regardless, so a disk fault at scan START leaves exactly this shape:
    // real host evidence, no run record, ever. Name both real causes rather than the one that
    // sounds most confident — same discipline `older-format` above already applies.
    const eitherCause = 'This can mean the record was deleted or moved after being written, or ' +
      'that it was never successfully written when the scan started (for example, a disk fault ' +
      'at scan time). Both are real; what is on disk now cannot tell them apart.';
    // ⚠️ CC-6: the CE_RETENTION_MS-based age check is a REAL policy only for the CE tier —
    // `pruneRunRecordsForCE` is the only place anything ever prunes on it. Gating an "older than
    // the retention window" sentence on it for a non-CE tier is what produced the prior
    // self-contradiction ("this scan is older than the retention window... retention is
    // unlimited on this tier" — both cannot be true). So the age axis is CONSULTED only when the
    // tier is actually CE; every other tier gets the same honest, age-independent disjunction a
    // CE run gets while still inside its own window.
    if (env.tier === 'ce') {
      if (insideWindow) {
        return refuse('record-absent-inside-window',
          `The run record for \`${id}\` is not present, though this scan is inside the ` +
          `retention window. ${eitherCause}`);
      }
      return refuse('record-absent-outside-window',
        `The run record for \`${id}\` is not present. Community Edition keeps run records for ` +
        '7 days; this scan is older than that window.');
    }
    return refuse('record-absent-inside-window',
      `The run record for \`${id}\` is not present. ${eitherCause}`);
  }

  const newest = records[0].startedAt;
  const tied = records.filter((r) => r.startedAt === newest);
  // A subject chosen by tie-break is a subject nobody chose.
  if (tied.length > 1) {
    return refuse('ambiguous-run',
      `Refusing to choose: ${tied.length} runs share the newest start time ${newest} — ` +
      `${tied.map((r) => r.runId).join(', ')}. Name one with \`--run <runId>\`.`);
  }
  return finishLoadingRecord(outRoot, records[0], allowPartial);
}
