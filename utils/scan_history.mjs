// utils/scan_history.mjs
// Scan history persistence and comparison utilities.
// Uses JSONL (one JSON object per line) for append-friendly storage.

import fsp from 'node:fs/promises';
import path from 'node:path';

export const HISTORY_FILE = 'scan_history.jsonl';

/**
 * Build a service key for comparison (port + protocol).
 * @param {object} svc
 * @returns {string}
 */
function serviceKey(svc) {
  return `${svc.port ?? ''}/${svc.protocol ?? 'tcp'}`;
}

/**
 * Append a scan summary as a single JSON line to scan_history.jsonl.
 * @param {string} outputDir - root output directory
 * @param {object} summary  - scan summary object
 * @returns {Promise<string>} path to the history file
 */
export async function recordScan(outputDir, summary) {
  const filePath = path.join(outputDir, HISTORY_FILE);
  const entry = {
    timestamp: summary.timestamp ?? new Date().toISOString(),
    host: summary.host ?? null,
    servicesCount: summary.servicesCount ?? 0,
    openPorts: Array.isArray(summary.openPorts) ? summary.openPorts : [],
    os: summary.os ?? null,
    findingsCount: summary.findingsCount ?? 0,
    // ⚠️ WHAT THAT NUMBER MEANS, carried on the line itself (board C10). `findingsCount` kept its
    // name and changed its value: it used to be service attributes plus plugin `result.findings`,
    // and is now what the report loader shapes — which includes the finding QUEUE, where a
    // network host's findings actually live. Lines written before the change have no basis, and
    // `computeDiff` refuses to subtract across that boundary rather than reporting a fabricated
    // "+N new" on the first scan after an upgrade.
    findingsCountBasis: summary.findingsCountBasis ?? null,
    // ⚠️ WHICH TIER COUNTED IT (board E9). The tiers do not count the same things: Enterprise
    // writes a finding QUEUE that Community never produces, and `findingsCount` is shaped by the
    // report loader, which reads it. So a Community → Pro upgrade would otherwise report "+N new
    // findings" on the free webhook the day the queue first appears — no estate changed, the
    // COUNTER changed. `computeDiff` refuses across a tier boundary for the same reason it
    // refuses across a basis boundary, and this field is what makes that refusal possible.
    tier: summary.tier ?? null,
    // review re-fold R-1: persist the cloud/service split so a cloud (--host aws)
    // scan's findings are machine-visible in history (findingsCount already
    // includes them; this surfaces how many came from cloud auditors).
    cloudFindingsCount: summary.cloudFindingsCount ?? 0,
    services: Array.isArray(summary.services) ? summary.services.map((s) => ({
      port: s.port ?? null,
      protocol: s.protocol ?? 'tcp',
      service: s.service ?? null,
      version: s.version ?? null,
    })) : [],
  };
  const line = JSON.stringify(entry) + '\n';
  await fsp.mkdir(outputDir, { recursive: true });
  await fsp.appendFile(filePath, line, 'utf8');
  return filePath;
}

/**
 * Read scan_history.jsonl and return the most recent entry for the given host.
 * @param {string} outputDir
 * @param {string} host
 * @returns {Promise<object|null>}
 */
export async function getLastScan(outputDir, host) {
  const filePath = path.join(outputDir, HISTORY_FILE);
  let content;
  try {
    content = await fsp.readFile(filePath, 'utf8');
  } catch (err) {
    if (err.code === 'ENOENT') return null;
    throw err;
  }

  const lines = content.trim().split('\n').filter(Boolean);
  let latest = null;

  for (const line of lines) {
    try {
      const entry = JSON.parse(line);
      if (entry.host === host) {
        if (!latest || entry.timestamp > latest.timestamp) {
          latest = entry;
        }
      }
    } catch {
      // skip malformed lines
    }
  }

  return latest;
}

/**
 * Compare two scan summaries and return a structured diff.
 * @param {object} current  - current scan summary
 * @param {object|null} previous - previous scan summary (null for first scan)
 * @returns {object} diff object
 */
/**
 * Why `computeDiff` refused to subtract two lines. DECLARED, because a reason string invented at
 * a call site is one no consumer can switch on; held in two-way equality with what the function
 * actually emits by `tests/scan_history_tier_comparability.test.mjs`, so a new reason must join
 * the set and a retired one must leave it.
 */
export const NOT_COMPARABLE_REASONS = ['basis-changed', 'tier-changed', 'tier-unknown'];

export function computeDiff(current, previous) {
  if (!previous) {
    return {
      newServices: [],
      removedServices: [],
      changedServices: [],
      newFindings: current?.findingsCount ?? 0,
      findingsNotComparable: false,
      findingsNotComparableReason: null,
      summary: 'No previous scan for comparison.',
    };
  }

  const currentServices = Array.isArray(current?.services) ? current.services : [];
  const previousServices = Array.isArray(previous?.services) ? previous.services : [];

  const prevMap = new Map();
  for (const svc of previousServices) {
    prevMap.set(serviceKey(svc), svc);
  }

  const currMap = new Map();
  for (const svc of currentServices) {
    currMap.set(serviceKey(svc), svc);
  }

  const newServices = [];
  const changedServices = [];

  for (const [key, svc] of currMap) {
    const prev = prevMap.get(key);
    if (!prev) {
      newServices.push(svc);
    } else if (prev.service !== svc.service || prev.version !== svc.version) {
      changedServices.push({
        port: svc.port,
        protocol: svc.protocol,
        previousService: prev.service,
        previousVersion: prev.version,
        currentService: svc.service,
        currentVersion: svc.version,
      });
    }
  }

  const removedServices = [];
  for (const [key, svc] of prevMap) {
    if (!currMap.has(key)) {
      removedServices.push(svc);
    }
  }

  // ⚠️ `findingsCount` KEPT ITS NAME AND CHANGED ITS VALUE (board C10), so two lines are only
  // subtractable when they were counted the same way. A line written before the fix summed
  // service attributes plus plugin `result.findings`; one written after counts what the loader
  // shapes, which includes the finding QUEUE. Subtracting across that boundary reports a
  // fabricated "+N new" on the first scan after an upgrade — an alarm produced by our own
  // correction, on an estate where nothing changed.
  //
  // contract-v1 §5.3 records the same shape for `findingCount` in the archived packs, and the
  // answer there was to REFUSE the comparison rather than compute it. Two OLD lines still
  // compare with each other: they are commensurable, and refusing would break a working
  // comparison for a customer who has not rescanned yet.
  const basisOf = (rec) => rec?.findingsCountBasis ?? null;
  const basisChanged = basisOf(current) !== basisOf(previous);

  // ⚠️ THE TIER BOUNDARY (board E9), and its carve-out mirrors the basis one deliberately: two
  // lines that BOTH lack a tier still compare. Neither of them can have carried a queue, so they
  // are commensurable, and refusing would break a working comparison for a customer who has not
  // rescanned since the field landed — the same judgement made for pre-1.1.0 lines above.
  // ABSENT-vs-PRESENT is refused, because that is exactly the shape an upgrade takes.
  const tierOf = (rec) => rec?.tier ?? null;
  const tierChanged = tierOf(current) !== tierOf(previous);
  // ⚠️ NO `tierChanged &&` HERE, and its deletion is a MEASUREMENT rather than a tidy-up. With
  // the verdict gate below, this value is only ever read when the comparison was already refused,
  // so in the branch that reads it `tierChanged` is necessarily true — the conjunct was dead. It
  // and the gate each made the other unfalsifiable: BOTH mutants survived, each masked by its
  // twin, which is the pair-masking shape this repo has recorded before. One mechanism is kept
  // (the gate, because it holds the invariant by construction for every future branch) and the
  // redundant one is removed, so the kept one is mutant-provable.
  const tierUnknown = tierOf(current) === null || tierOf(previous) === null;

  const findingsComparable = !basisChanged && !tierChanged;
  // Precedence is deterministic and the WIDER boundary wins: a basis change is the older and
  // more fundamental incommensurability, so it names the refusal when both apply. The tier fact
  // is still stated in the summary rather than dropped — a reader needs both.
  // ⚠️ THE REASON IS GATED ON THE VERDICT, so "non-null reason ⟺ refused" holds BY CONSTRUCTION
  // rather than by three branches agreeing. Found by a surviving mutant: with the reason computed
  // independently, dropping the both-absent carve-out left `findingsNotComparable: false` sitting
  // beside `reason: 'tier-unknown'` — a diff that says it compared AND says why it could not, and
  // a consumer switching on the reason would refuse a comparison the verdict allowed.
  const findingsNotComparableReason = findingsComparable ? null
    : basisChanged ? 'basis-changed'
      : tierUnknown ? 'tier-unknown'
        : tierChanged ? 'tier-changed'
          : null;
  const findingsDelta = findingsComparable
    ? (current?.findingsCount ?? 0) - (previous?.findingsCount ?? 0)
    : null;

  // Build human-readable summary
  const parts = [];
  if (newServices.length) {
    parts.push(`${newServices.length} new service(s) detected`);
  }
  if (removedServices.length) {
    parts.push(`${removedServices.length} service(s) removed`);
  }
  if (changedServices.length) {
    parts.push(`${changedServices.length} service(s) changed`);
  }
  if (!findingsComparable) {
    // Said out loud, not omitted. A missing findings clause reads as "no findings changed".
    // BOTH facts when both apply: the reason names one boundary, the sentence states every one
    // that was crossed, because a reader who is told only about the basis will rescan and be
    // surprised again by the tier.
    const why = [];
    if (basisChanged) {
      why.push('counted findings on a different basis '
        + `(${basisOf(previous) ?? 'pre-1.1.0'} → ${basisOf(current) ?? 'pre-1.1.0'})`);
    }
    if (tierChanged) {
      why.push(`ran at a different licence tier (${tierOf(previous) ?? 'unrecorded'} → `
        + `${tierOf(current) ?? 'unrecorded'}), which counts a different set of findings`);
    }
    parts.push(`findings not comparable: the two scans ${why.join(', and ')}; rescan to compare`);
  } else if (findingsDelta !== 0) {
    const sign = findingsDelta > 0 ? '+' : '';
    parts.push(`findings delta: ${sign}${findingsDelta}`);
  }

  const summary = parts.length > 0
    ? parts.join(', ') + '.'
    : 'No changes detected since last scan.';

  return {
    newServices,
    removedServices,
    changedServices,
    // `null`, never 0, when the bases differ: 0 is a CLAIM that nothing changed, and this
    // function does not know that. `delta_reporter` gates its webhook on this value, so a number
    // here would send the fabricated alarm and a 0 would suppress a real one.
    newFindings: findingsDelta,
    findingsNotComparable: !findingsComparable,
    findingsNotComparableReason,
    summary,
  };
}

export const CE_RETENTION_MS = 7 * 24 * 60 * 60 * 1000; // 7 days

/**
 * Remove JSONL entries older than 7 days from the given history file.
 * CE-only — call after each scan for CE tier. Pro/Enterprise: unlimited retention.
 * Unparseable lines are preserved to avoid data loss.
 *
 * @param {string} filePath - absolute path to the JSONL history file
 * @returns {Promise<void>}
 */
export async function pruneForCE(filePath) {
  let raw;
  try {
    raw = await fsp.readFile(filePath, 'utf8');
  } catch {
    return; // file doesn't exist yet — nothing to prune
  }
  const cutoff = Date.now() - CE_RETENTION_MS;
  const kept = raw.split('\n').filter(line => {
    if (!line.trim()) return false;
    try {
      const entry = JSON.parse(line);
      const rawTs = entry.timestamp;
      if (rawTs == null || rawTs === '') return true; // missing/null timestamp — preserve
      const ts = new Date(rawTs).getTime();
      if (isNaN(ts)) return true; // non-parseable string — preserve to avoid data loss
      return ts >= cutoff;
    } catch {
      return true; // keep unparseable lines rather than lose data
    }
  });
  await fsp.writeFile(filePath, kept.join('\n') + (kept.length ? '\n' : ''));
}

/**
 * Format a diff object into markdown-like text lines.
 * @param {object} diff - output from computeDiff()
 * @returns {string}
 */
export function formatDiffReport(diff) {
  if (!diff) return '';

  const lines = [];
  lines.push('## Scan Comparison');
  lines.push('');
  lines.push(diff.summary);
  lines.push('');

  if (diff.newServices.length) {
    lines.push('### New Services');
    for (const svc of diff.newServices) {
      lines.push(`- ${svc.port}/${svc.protocol}: ${svc.service ?? 'unknown'} (${svc.version ?? 'unknown'})`);
    }
    lines.push('');
  }

  if (diff.removedServices.length) {
    lines.push('### Removed Services');
    for (const svc of diff.removedServices) {
      lines.push(`- ${svc.port}/${svc.protocol}: ${svc.service ?? 'unknown'} (${svc.version ?? 'unknown'})`);
    }
    lines.push('');
  }

  if (diff.changedServices.length) {
    lines.push('### Changed Services');
    for (const ch of diff.changedServices) {
      lines.push(`- ${ch.port}/${ch.protocol}: ${ch.previousService ?? 'unknown'} ${ch.previousVersion ?? ''} -> ${ch.currentService ?? 'unknown'} ${ch.currentVersion ?? ''}`);
    }
    lines.push('');
  }

  if (diff.newFindings !== 0) {
    const sign = diff.newFindings > 0 ? '+' : '';
    lines.push(`**Findings delta:** ${sign}${diff.newFindings}`);
    lines.push('');
  }

  return lines.join('\n');
}
