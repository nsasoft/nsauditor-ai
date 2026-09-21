// utils/report_inputs.mjs — the only module that knows the filesystem layout of a scan run.
// Turns a run directory into ONE normalised model that the executive HTML report and the Jira
// CSV export both consume. Every refusal below is written before the happy path, because a
// report that renders confidently over a partial or mismatched run is the false clean this
// feature exists to prevent: a correct report about the wrong (or incomplete) run reads
// identically to a correct one without that caveat.
// ⚠️ `fs` IS IMPORTED BECAUSE IT WAS BEING USED WITHOUT BEING IMPORTED. The queue read below
// called `fs.readFileSync` while this module bound only `fsp`, so it threw
// `ReferenceError: fs is not defined` on EVERY call and the bare `catch` around it swallowed the
// throw — the primary artifact path was dead code and 100% of finding-queue entries arrived
// through the `eeEnrichment` fallback the comment there calls a legacy shim. It read clean under
// every hand probe written with `node -e`, because `node -e` exposes built-in modules as globals
// and a real module file does not: THE PROBE HABITAT, NOT THE CODE, IS WHAT WAS PASSING.
// Behaviour-preserving on the whole corpus: all 12 real `scan_finding_queue.json` files under
// audit-evidence-samples are byte-identical to their record's `eeEnrichment.queue`.
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
import { describeFinding } from './cloud_finding_summary.mjs';
import { canonicaliseResource } from './finding_identity.mjs';
import { censusFindingContainers } from './report_finding_census.mjs';
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

// An `issues[]` entry is a STRING in almost every producer, and an OBJECT
// `{severity, detail}` in 1030's five error paths. The object form carries `.detail`
// and NOT `.title` — `String(obj)` yields "[object Object]", which is what a naive
// reuse of `describeFinding` renders for that shape. Normalise before describing.
function issueText(i) {
  if (i == null) return '';
  if (typeof i === 'string') return i;
  if (typeof i === 'object') return String(i.detail ?? i.title ?? i.message ?? i.reason ?? '');
  return String(i);
}

// The envelope's plugin id, in the vocabulary `cli.mjs` writes into `pluginsRequested`
// (`String(p.id)`). MEASURED across 152 real run records: 7,962 members, not one a display name.
const envId = (e) => (e?.id != null ? String(e.id) : null);

export function shapeFinding(host, f, plugin = null, pluginName = null) {
  const severity = f?.severity != null ? String(f.severity).toUpperCase() : 'INFO';
  const port = f?.port ?? null;
  // The finding's OWN region, from its own field — never a default and never inferred. Nothing
  // can be decoration without it, and guessing one would strip a legitimately region-named
  // object. `null` for every non-regional producer, which is most of them.
  const region = typeof f?.region === 'string' && f.region.length > 0 ? f.region : null;
  // ⚠️ THE REPORT USED TO READ `f.title` ALONE, AND NO SHIPPED PLUGIN EMITS IT.
  // Measured at Gate 3-B on the installed 0.44.0 trio: 27 of 29 EE plugins carry no
  // `title:` field, no CE plugin carries one, and exactly three `findings.push` sites
  // product-wide set one — so a real 21-plugin run rendered 208 "(untitled finding)"
  // and a Jira CSV with an empty Summary on every row. Cloud findings carry their
  // content in `issues[]`.
  //
  // `describeFinding` is the SAME normaliser the MCP surface uses, so the two consumers
  // cannot drift apart on what a finding is called.
  //
  // ⚠️ IT IS CALLED ONLY WHEN CONTENT EXISTS, and that gate is load-bearing:
  // `describeFinding` never returns empty — with nothing to say it emits
  // "INFO finding (no description)". Calling it unconditionally would hand a title to a
  // finding that has none, which is fabrication, and is the one thing worse than the
  // defect being fixed. A finding with neither a title nor any issue text stays null
  // and renders "(untitled finding)".
  const issueTexts = Array.isArray(f?.issues)
    ? f.issues.map(issueText).filter((t) => t.trim().length > 0)
    : [];
  const explicitDetail = f?.detail ?? f?.description ?? null;
  // When a producer carries its content in `detail`/`description` and no `issues[]` at all
  // (1023's {severity, description}; 040's and 060's {severity, check, detail}), feed that
  // text in AS an issue rather than widening describeFinding's shared REASON_KEYS — the
  // MCP surface consumes the same helper, and a constant widened for this caller changes
  // what every other caller titles. `description` in particular is NOT in REASON_KEYS, so
  // without this a zero-trust finding titles itself "MEDIUM finding (no description)".
  const contentIssues = issueTexts.length ? issueTexts : (explicitDetail ? [String(explicitDetail)] : []);
  const title = f?.title
    ?? (contentIssues.length ? describeFinding({ ...f, issues: contentIssues }) : null);
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
    // ⚠️ CARRIED FOR IDENTITY, not for display. Cloud issue strings name the DEFECT and not the
    // resource ("No public access block configured…"), so without this every bucket on one host
    // normalises to the same {host, port, severity, title} and a cross-run delta collapses them —
    // masking a NEW exposure behind a surviving one. Dropping it here would defeat the delta's
    // identity key from outside the delta, with the delta's own tests still green.
    // ⚠️ CANONICALISED, NOT RAW (board E1). EE's `utils/aws_region_scan.mjs::_stampRegion`
    // rewrote this field on every finding routed through `forEachRegion`: a finding with no
    // resource got the REGION as its object identity, and a finding with one got ` [<region>]`
    // appended. E1 stops both at the producer, but the PUBLISHED CE 0.2.54 already wrote
    // baselines full of the decorated values and `RUN_RECORD_SCHEMA` is 1 on both sides — so
    // those baselines compare as commensurable. Canonicalising here is what makes that true:
    // the same object computes the same key whichever side of the upgrade wrote it. Shared with
    // EE's MTTR fingerprint so the two comparison channels cannot disagree about identity.
    resource: canonicaliseResource(f?.resource ?? f?.target ?? f?.details?.resource ?? null, region),
    // ⚠️ THE REGION AS ITS OWN FIELD, which it has never been on this shape. Before E1 the
    // region reached both identity and the READER only through the decoration above — this file
    // mentioned `region` zero times — so removing the suffix without adding the field would take
    // the region out of an assessor's view and out of the delta's key at the same time. It is a
    // FIELD and never a suffix: a suffix is a value change that fabricates churn across an
    // upgrade, a field is recomputed identically on both sides of any comparison.
    region,
    // ⚠️ AN EVIDENCE GAP IS SCOPE, NOT A FINDING, and the delta cannot tell them apart without
    // this. A gap record says "the scanner could not read this surface" — so a finding that
    // vanished behind one was not fixed, nobody looked. It is carried on the finding rather than
    // in a side-channel because that is where the producer already writes it (`details.evidenceGap`
    // on 7 AWS and 3 Azure findings of the real 1.1.0 run), which means the READ side needs no
    // writer change to see it.
    evidenceGap: f?.details?.evidenceGap === true,
    // ⚠️ IDENTITY MUST NEVER BE COMPUTED OVER A TRUNCATED STRING, and these two exist because it
    // was. Plugin 1170 emits no `title`, so one is synthesised from `issues` and CUT AT 160 CHARS
    // — and on a live estate three ingress rules on ONE security group (PostgreSQL 5432, SSH 22,
    // Redis 6379, every one open to 0.0.0.0/0) synthesised to the SAME 158-character string,
    // because the port list is the only token that differs and it falls just past the cut.
    // `resource` is the REGION for that plugin and `port` is null, so neither discriminated.
    // Three real CRITICAL exposures held ONE identity: remediate the SSH rule, acquire a new
    // 0.0.0.0/0 rule on the same group, and the delta reports UNCHANGED.
    //
    // `contentDigest` is taken over the UNTRUNCATED content this function already holds, so the
    // fix covers EVERY producer whose text differs only past 160 chars, not just 1170.
    contentDigest: crypto.createHash('sha256')
      .update(JSON.stringify([f?.title ?? null, contentIssues])).digest('hex').slice(0, 16),
    // And the PRODUCER-EMITTED discriminators, never ones invented here: a rule identity the
    // plugin already carries in `details`. Absent on producers that emit none, which is why the
    // key falls back rather than requiring it.
    identityQualifier: [f?.details?.groupId, f?.details?.protocol, f?.details?.fromPort, f?.details?.toPort]
      .filter((v) => v != null).join('/') || null,
    // WHICH ORACLE adjudicates this producer's scope. A plugin id is answerable from the record's
    // `pluginsRequested`; an EE analysis agent is NOT — it appears in no such list, because
    // `agents/agent_runner.mjs` derives the agent set from CAPABILITIES and the envelope persists
    // no per-agent run status. Deriving this in the delta would mean guessing from the shape of
    // the string; the loader KNOWS, because it knows which container the finding came out of.
    producerKind: (plugin ?? f?.plugin) != null ? 'plugin' : null,
    // ⚠️ CARRIED FOR COMPARABILITY, and for the same reason as `resource`. A cross-run delta can
    // only call a finding resolved if the plugin that produced it RAN in both scans; without the
    // producing plugin on the finding, every comparison falls to "plugin-not-run" — never a false
    // "resolved" (the safe direction) but a wall of NOT-COMPARABLE, which is a feature nobody reads.
    plugin: plugin ?? f?.plugin ?? null,
    // ⚠️ IDENTITY AND DISPLAY ARE TWO FIELDS, and splitting them is not tidiness. `plugin` is
    // compared against `record.pluginsRequested`, which `cli.mjs` writes as plugin IDs, so it must
    // BE an id or the comparison is false on every real record. But `scan_delta.mjs` interpolates
    // the producing plugin into its `plugin-not-run` detail and `executive_report.mjs` renders
    // that detail into the CLIENT HTML's basis cell — so stamping the id alone would put
    // "plugin 003 did not run in the other run" into a branded deliverable. One field cannot be
    // both the join key and the prose.
    pluginName: pluginName ?? f?.pluginName ?? null,
    // ALL issues, not just the lead clause the title took: a report that shows one of a
    // finding's four issues silently drops three the scan actually recorded.
    detail: explicitDetail ?? (issueTexts.length ? issueTexts.join(' · ') : null),
    remediation: f?.remediation ?? f?.details?.remediation ?? null,
    cves, kev, epss, id,
  };
}

// The envelope shape is `{ id, name, result }` (plugin_manager.mjs's manifest entries pair with
// `results[]` this way); reachability and findings both live INSIDE `result`, never at the raw's
// top level. A host counts as up if ANY plugin's envelope observed it up — a host with nothing
// reporting `up: true` (including a host with zero envelopes) is not reachable.
/**
 * The EE finding queue is a SIBLING ARTIFACT with its own vocabulary, and the mismatch is
 * Class P — not a rename. Measured on a real entry from a 192.168.1.1 run:
 *   `cves` ABSENT     -> `evidence.cve[]`      (a naive reader renders an empty CVE column)
 *   `epss` ABSENT     -> `epssScore`           (a naive reader nulls EPSS, and the report's
 *                                               own cover promises EPSS ordering)
 *   `remediation`     -> an OBJECT `{summary}` (a naive reader prints "[object Object]")
 *   `port` ABSENT     -> `target.port`
 *   `id`              -> a stable `F-…`, better than any content hash we could compute
 */
function shapeQueueEntry(host, q) {
  const ev = (q && typeof q.evidence === 'object' && q.evidence) || {};
  const rem = q?.remediation;
  return {
    host,
    port: q?.port ?? q?.target?.port ?? null,
    severity: q?.severity != null ? String(q.severity).toUpperCase() : 'INFO',
    title: q?.title ?? null,
    detail: q?.description ?? q?.detail ?? null,
    remediation: typeof rem === 'string' ? rem : (rem?.summary ?? null),
    cves: Array.isArray(ev.cve) ? ev.cve.map(String)
      : Array.isArray(q?.cves) ? q.cves.map(String) : [],
    kev: q?.kev === true,
    epss: typeof q?.epssScore === 'number' && Number.isFinite(q.epssScore) ? q.epssScore
      : (typeof q?.epss === 'number' && Number.isFinite(q.epss) ? q.epss : null),
    exploitPriority: q?.exploitPriority ?? null,
    // ⚠️ THE QUEUE IS A SIBLING ARTIFACT WITH ITS OWN PRODUCER VOCABULARY, and emitting NO
    // producer at all was the fifth instance of the loader-boundary class: every queue finding
    // reached the delta as `plugin: undefined` and bucketed `plugin-not-run` with the sentence
    // "plugin undefined did not run in the other run". Its real producer is an EE ANALYSIS AGENT,
    // not a CE plugin — measured across 350 real queue entries: intelligence_engine 302 ·
    // crypto_agent 46 · exposure_agent 2, and ZERO entries carrying anything id-shaped. So this
    // identity is NOT a member of `pluginsRequested` and never will be; deciding whether an agent
    // was in scope on the other side needs its own oracle, which is why a null producer must
    // still refuse rather than fall through. Absence here is a per-finding fact, not a class.
    plugin: q?.evidence?.source ?? null,
    pluginName: q?.evidence?.source ?? null,
    producerKind: q?.evidence?.source ? 'agent' : null,
    // A queue entry is never a gap record: gaps are emitted by plugins into the host envelope.
    evidenceGap: false,
    id: q?.id ?? null,
  };
}

/**
 * EVERY container a finding can live in, merged and de-duplicated by IDENTICAL id only.
 *
 * ⚠️ NEVER heuristic merging across producers. crypto_agent's TLS queue entries and 040's
 * per-check issues describe the same port at different granularities and BOTH belong in
 * the report, each with its own source. Collapsing them on a similarity guess would drop
 * real findings to make a tidier table — the defect this whole lane exists to remove.
 *
 * The container inventory is enforced by `utils/report_finding_census.mjs`: a container
 * carrying severity-bearing objects that is neither read here nor allowlisted there fails
 * loudly. Incompleteness costs NOISE, never SILENCE.
 */
// ⚠️ ONE DEFINITION OF A FINDING, SHARED BY BOTH COMPARISON CHANNELS (board C10).
//
// `scan_history.jsonl` used to carry a count `cli.mjs` computed for itself — service-level
// attributes plus plugin `result.findings` — while `report --since` counted whatever THIS module
// shapes. On the real estate the two disagreed completely: the 192.168.1.1 Gate-2 run recorded
// `findingsCount: 0` while its queue held 37 entries, 21 carrying CVEs. The history is a
// COMPARISON channel (`computeDiff` derives `newFindings` and `findingsDelta` from that number,
// and `delta_reporter` gates a webhook on it), so the host reported "no change" on every scan.
//
// ⚠️ AND THE FIX IS NOT A THIRD SUM. The previous repair of this same channel added
// `cloudFindingsCount` after cloud plugins recorded 0 over a 201-finding scan — a per-producer
// patch, which closes only the producers it enumerates, which is how the channel came to be
// wrong twice. Deriving the count from the shaping the delta already uses is what makes the two
// channels incapable of drifting apart: a producer this module learns to read is counted by both,
// on the same day, without anyone remembering to add it here.
//
// A GAP IS SCOPE, NOT A FINDING, and is excluded — exactly as the delta excludes gaps from its
// buckets. Counting one would make an AccessDenied look like a vulnerability appearing and a
// fixed permission look like a remediation.
export function countHostFindings(host, raw, queue = []) {
  return shapeHostFindings(host, raw, queue).filter((f) => f?.evidenceGap !== true).length;
}

// ⚠️ THE VALUE CHANGED UNDER AN UNCHANGED KEY, which contract-v1 §5.3 records as the shape that
// once reported a mass remediation that never happened. A history line written before this fix
// counted the old way; one written after counts the new way, and subtracting across them would
// report a fabricated "+N new" on the first scan after an upgrade. The basis rides the line so
// `computeDiff` can REFUSE the comparison instead of computing it.
export const FINDINGS_COUNT_BASIS = 'loader-shaped-v1';

// ⚠️ THE COUNT AND ITS BASIS COME FROM ONE CALL, DELIBERATELY. They were two statements, and a
// mutant that reverted the COUNT to the old per-producer sum kept the BASIS stamp — so the
// history line claimed to have been counted the new way while holding an old-way number, and the
// end-to-end leg could not tell. A line's basis is a claim about HOW it was produced, so only the
// thing that produces it may assert it. Returns null when the artifacts cannot be read, and the
// caller then records an UN-BASED line rather than a mislabelled one.
export async function deriveFindingsCount(outDir, host) {
  try {
    const raw = JSON.parse(await fsp.readFile(path.join(outDir, 'scan_conclusion_raw.json'), 'utf8'));
    // ⚠️ THE QUEUE IS RESOLVED EXACTLY AS `loadRun` RESOLVES IT, and the first draft of this did
    // not. `loadRun` normalises a non-array file (`{queue:[…]}` / `{findings:[…]}`) and falls back
    // to the in-envelope `eeEnrichment.queue` for a run written before the file existed. Reading
    // the same PATH is not the same as reading the same SOURCE: with a wrapped queue this counted
    // zero while the report counted every entry — "one definition" nominally, two in fact, which
    // is the whole defect C10 exists to close. Found by reading the consumer, not by a fixture.
    return { count: countHostFindings(host, raw, resolveFindingQueue(outDir, raw)),
      basis: FINDINGS_COUNT_BASIS };
  } catch {
    return null;
  }
}

// The one resolver both channels use. Kept beside `countHostFindings` so a future change to the
// queue's shape cannot reach one channel and miss the other.
export function resolveFindingQueue(dir, raw) {
  try {
    const qRaw = JSON.parse(fs.readFileSync(path.join(dir, 'scan_finding_queue.json'), 'utf8'));
    return Array.isArray(qRaw) ? qRaw : (qRaw?.queue ?? qRaw?.findings ?? []);
  } catch {
    const q = raw?.conclusion?.result?.eeEnrichment?.queue;
    return Array.isArray(q) ? q : [];
  }
}

export function shapeHostFindings(host, raw, queue = []) {
  const out = [];
  const seen = new Set();
  // ⚠️ DE-DUPLICATE ONLY ON A PRODUCER-SUPPLIED ID, NEVER ON A CONTENT HASH.
  // `shapeFinding` derives its id from [host, port, severity, title] and the title is
  // TRUNCATED at 160 chars, so distinct findings can share one. Measured on the 0.44.0
  // cloud run: plugin 1170 emits THREE separate 0.0.0.0/0 ingress findings for
  // sg-0def2fbb3db67eae5 whose titles truncate identically — a content-keyed dedup
  // silently dropped two of them and took cloud CRITICAL from 10 to 8. A hash collision is
  // evidence that the hash is coarse, never evidence that two findings are the same one.
  // The finding queue DOES carry a stable producer id (`F-…`), which is what this is for.
  const push = (f, dedupId = null) => {
    if (dedupId != null) {
      if (seen.has(dedupId)) return;
      seen.add(dedupId);
    }
    out.push(f);
  };

  for (const e of (Array.isArray(raw?.results) ? raw.results : [])) {
    const res = e?.result ?? {};
    // ⚠️ `result.data` IS NOT A FINDINGS CONTAINER AND MUST NOT BE READ HERE. I added a
    // `findings ?? data` fallback (mirroring cloud_finding_summary's findingsOf) on the
    // reasoning that a data-only producer should not be invisible — and it was WRONG,
    // measured on the 192.168.1.1 run: a network host has `findings[] = 0` and
    // `data[] = 85`, of which 84 are PROBE TELEMETRY ({probe_protocol, probe_port,
    // probe_info} — "Connect refused (ECONNREFUSED)", "No UDP response"). The fallback put
    // scan telemetry into a client deliverable, and only an accidental id collision (null
    // title, null port, INFO) collapsed 85 rows into two, which is what hid it.
    // findingsOf can use that precedence because the MCP cloud path only ever sees cloud
    // producers; the report sees BOTH paths.
    const rf = res.findings;
    if (Array.isArray(rf)) {
      for (const f of rf) push(shapeFinding(host, f, envId(e), e?.name ?? null));
    } else if (rf && typeof rf === 'object') {
      // 060 DNS Security Auditor emits a DICT OF CATEGORIES ({spf:[…], dmarc:[…]}), which
      // an `Array.isArray` guard skips in complete silence.
      for (const arr of Object.values(rf)) {
        if (Array.isArray(arr)) for (const f of arr) push(shapeFinding(host, f, envId(e), e?.name ?? null));
      }
    }
    if (res.zeroTrust && typeof res.zeroTrust === 'object') {
      for (const dim of Object.values(res.zeroTrust)) {
        if (Array.isArray(dim?.findings)) for (const f of dim.findings) push(shapeFinding(host, f, envId(e), e?.name ?? null));
      }
    }
    if (Array.isArray(res.portResults)) {
      for (const pr of res.portResults) {
        // The port result's own `severity` is a ROLL-UP of these issues, never a finding —
        // rendering both would double-count every TLS issue.
        if (Array.isArray(pr?.issues)) {
          for (const i of pr.issues) push(shapeFinding(host, { ...i, port: i?.port ?? pr?.port ?? null }, envId(e), e?.name ?? null));
        }
      }
    }
  }
  for (const q of (Array.isArray(queue) ? queue : [])) {
    const e = shapeQueueEntry(host, q);
    push(e, e.id);
  }
  return out;
}

function shapeHost(host, dir, raw) {
  const envelopes = Array.isArray(raw.results) ? raw.results : [];
  const up = envelopes.some((e) => e?.result?.up === true);
  const findings = shapeHostFindings(host, raw, raw?.__findingQueue ?? []);
  return {
    host, dir, up, findings,
    pluginStatus: Array.isArray(raw.pluginStatus) ? raw.pluginStatus : [],
    // ⚠️ THE DEFAULT ABOVE ERASES THE ONE DISTINCTION `scan_delta.mjs` INSISTS ON. Its `scopeOf`
    // says in as many words that `[]` means "measured, no gaps" while MISSING means nothing was
    // measured, and that the two must not render alike — and then reads `Array.isArray(...)` over
    // a value this loader guarantees is an array, so the question is always true and the
    // `scope-not-evaluated` disclosure could never fire. The default stays (every consumer
    // iterates it), and the answer travels BESIDE it. Same loader-boundary class as the dropped
    // `plugin` / `resource` / `control` fields: the distinction was preserved in the consumer and
    // destroyed here, before the consumer ever saw it.
    pluginStatusRecorded: Array.isArray(raw.pluginStatus),
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
    plugins.byHost.push({ host: h.host, dir: h.dir, status: h.pluginStatus,
      pluginStatusRecorded: h.pluginStatusRecorded });
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
  const unreadByHost = [];
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
    // ⚠️ THE FINDING QUEUE IS A SIBLING FILE, WHICH IS EXACTLY WHY IT WAS MISSED — nothing
    // in scan_conclusion_raw.json points at it. `scan_finding_queue.json` is the documented
    // artifact (EE writes it; `report` is Pro-gated so EE is present); the eeEnrichment
    // fallback covers a record written before the file existed. A queue that cannot be read
    // yields [] and the host simply renders its plugin findings — never an exception, and
    // never a silent substitution of one source for another.
    // ⚠️ ONE RESOLVER, SHARED WITH `deriveFindingsCount` (board C10). This logic was duplicated
    // there and the copy was already wrong — it handled only a bare array, so a wrapped queue
    // counted zero in the history channel and every entry in the report. Two copies of "what the
    // queue is" is the same defect one layer down from two copies of "what a finding is".
    const findingQueue = resolveFindingQueue(path.join(outRoot, dir), raw);
    // ⚠️ THE CENSUS RUNS ON EVERY REAL RUN, NOT ONLY IN TESTS — this is what makes it a
    // guard rather than a fixture. Its reconcile leg's corpus is synthetic, and the two real
    // runs were reconciled BY HAND; a new plugin inventing a new container would be silent
    // again until somebody wrote its fixture. Running it here means the next unread
    // container announces itself on the first render, which is how all three of the doors
    // found tonight SHOULD have been found.
    const census = censusFindingContainers(raw, findingQueue);
    // ⚠️ `premiseFailures` TRAVELS WITH THE COUNTS, because the two reasons a container is
    // unread need DIFFERENT sentences. A container nobody wrote a reader for is genuinely NOT
    // IN the report; a carve-out whose premise BROKE has most of its objects rendered and only
    // the break unread. Handing the consumer one number and no reason is what let the report
    // tell a client that 17 objects were missing from a document containing 16 of them.
    if (Object.keys(census.unread).length) {
      unreadByHost.push({ host, unread: census.unread, premiseFailures: census.premiseFailures });
    }
    hosts.push(shapeHost(host, dir, { ...raw, __findingQueue: findingQueue }));
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

  const model = buildModel(rec, hosts, { requested, written, missingNamed, missingUnparseable, incomplete });
  // Carried on the model so the RENDERER can disclose it to the reader. A warning on stderr
  // is seen by whoever ran the command; the report is what reaches the customer, and the
  // artifact is the surface that has to state its own blind spot.
  if (unreadByHost.length) model.unreadContainers = unreadByHost;
  return { ok: true, model };
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
