// utils/delta_reporter.mjs
// Delta reporting: compare two full scan cycles across multiple hosts.

import { computeDiff, flagsChanged } from './scan_history.mjs';

// 1.3.0 lane 4, items 4 + 11. The watch loop hands this module each host's scanSingleHost OUTPUT, which carries no
// services, finding count or tier — so every cycle compared two empty summaries, stdout read "No significant changes
// detected." and the webhook gate never opened on a change. The output now carries the summary [ScanHistory] records
// (`scanSummary`), and the cycle compares those. A host whose summary is MISSING is never read as an empty one: that
// would print "N service(s) removed" for a scan that failed (the naive fix) or "No changes" (the shipped defect).

/** The per-host states in which two cycles are NOT compared — a closed set, held two ways by its test. */
export const WATCH_NOT_COMPARABLE = Object.freeze(['scan-failed', 'baseline-scan-failed', 'no-summary', 'baseline-no-summary']);

const NOT_COMPARED_TEXT = {
  'scan-failed': (detail) => `scan failed this cycle — not compared${detail ? ` (${detail})` : ''}`,
  'baseline-scan-failed': () => "the previous cycle's scan failed — not compared",
  'no-summary': () => 'no scan summary was recorded this cycle — not compared',
  'baseline-no-summary': () => 'no scan summary was recorded for the previous cycle — not compared',
};

/**
 * What one host's cycle value offers the comparison: `{ summary }`, or `{ failed: detail }` for the scheduler's
 * `{ error }`, or `{ missing: true }` when no summary is there to read.
 */
export function deltaInputOf(value) {
  if (value && typeof value === 'object') {
    if (value.error != null && !('scanSummary' in value) && !Array.isArray(value.services)) return { failed: String(value.error) };
    if ('scanSummary' in value) return value.scanSummary && typeof value.scanSummary === 'object' ? { summary: value.scanSummary } : { missing: true };
    if (Array.isArray(value.services)) return { summary: value };
  }
  return { missing: true };
}

function notComparedDiff(reason, detail) {
  return {
    newServices: [], removedServices: [], changedServices: [],
    newFindings: null, findingsNotComparable: false, findingsNotComparableReason: null,
    changedFlags: [], flagsNotComparable: false, flagsNotComparableReason: null,
    notCompared: reason,
    summary: NOT_COMPARED_TEXT[reason](detail),
  };
}

/** Compare one host's two cycle values. */
function hostDiff(current, previous) {
  const cur = deltaInputOf(current);
  if (cur.failed !== undefined) return notComparedDiff('scan-failed', cur.failed);
  if (cur.missing) return notComparedDiff('no-summary');
  if (previous == null) return computeDiff(cur.summary, null);
  const prev = deltaInputOf(previous);
  if (prev.failed !== undefined) return notComparedDiff('baseline-scan-failed');
  if (prev.missing) return notComparedDiff('baseline-no-summary');
  return computeDiff(cur.summary, prev.summary);
}

/**
 * THE one per-host change predicate (ruled): stdout and the webhook read the same definition. A service appeared,
 * went or changed; the finding count moved, or could not be compared; a service check appeared, cleared or could not
 * be compared; or the two cycles could not be compared at all.
 */
export function hostChanged(diff) {
  if (!diff) return false;
  return Boolean(diff.notCompared || diff.newServices?.length || diff.removedServices?.length || diff.changedServices?.length
    || diff.newFindings || diff.findingsNotComparable || flagsChanged(diff));
}

/**
 * Compare two full scan cycle results and produce a delta report.
 * @param {Map<string, object>|object} currentResults  - host → scan result (Map or plain object)
 * @param {Map<string, object>|object|null} previousResults - host → scan result from prior cycle
 * @returns {{ newHosts: string[], removedHosts: string[], hostDiffs: Map<string, object> }}
 */
export function buildDeltaReport(currentResults, previousResults) {
  const currMap = currentResults instanceof Map
    ? currentResults
    : new Map(Object.entries(currentResults || {}));
  const prevMap = previousResults instanceof Map
    ? previousResults
    : new Map(Object.entries(previousResults || {}));

  const currentHosts = new Set(currMap.keys());
  const previousHosts = new Set(prevMap.keys());

  const newHosts = [];
  for (const h of currentHosts) {
    if (!previousHosts.has(h)) newHosts.push(h);
  }

  const removedHosts = [];
  for (const h of previousHosts) {
    if (!currentHosts.has(h)) removedHosts.push(h);
  }

  const hostDiffs = new Map();
  for (const h of currentHosts) {
    hostDiffs.set(h, hostDiff(currMap.get(h), prevMap.has(h) ? prevMap.get(h) : null));
  }

  return { newHosts, removedHosts, hostDiffs };
}

/**
 * Format a delta report into a human-readable summary string.
 * @param {{ newHosts: string[], removedHosts: string[], hostDiffs: Map<string, object> }} deltaReport
 * @returns {string}
 */
export function formatDeltaSummary(deltaReport) {
  if (!deltaReport) return '';

  const lines = [];
  lines.push('=== Delta Report ===');
  lines.push('');

  if (deltaReport.newHosts.length) {
    lines.push(`New hosts (${deltaReport.newHosts.length}): ${deltaReport.newHosts.join(', ')}`);
  }
  if (deltaReport.removedHosts.length) {
    lines.push(`Removed hosts (${deltaReport.removedHosts.length}): ${deltaReport.removedHosts.join(', ')}`);
  }

  if (deltaReport.hostDiffs && deltaReport.hostDiffs.size > 0) {
    lines.push('');
    lines.push('Per-host changes:');
    for (const [host, diff] of deltaReport.hostDiffs) {
      lines.push(`  ${host}: ${diff.summary}`);
    }
  }

  if (!deltaReport.newHosts.length && !deltaReport.removedHosts.length) {
    let anyChange = false;
    if (deltaReport.hostDiffs) {
      // ⚠️ A comparison that could not be made COUNTS AS A CHANGE (board C10; 1.3.0 items 4 + 11): `newFindings` is null
      // when the two scans counted on a different basis, and a host whose scan failed has nothing to compare — without
      // this the operator hears NOTHING, which reads as "no change since last scan". A comparison we cannot make is
      // news: it is what tells an operator to rescan. hostChanged is the one predicate the webhook reads too.
      anyChange = [...deltaReport.hostDiffs.values()].some(hostChanged);
    }
    if (!anyChange) {
      lines.push('No significant changes detected.');
    }
  }

  return lines.join('\n');
}

/**
 * Determine whether a delta report contains significant changes.
 * Returns true if any new/removed hosts exist, or if any host has service changes.
 * @param {{ newHosts: string[], removedHosts: string[], hostDiffs: Map<string, object> }} deltaReport
 * @returns {boolean}
 */
export function hasSignificantChanges(deltaReport) {
  if (!deltaReport) return false;

  if (deltaReport.newHosts.length > 0) return true;
  if (deltaReport.removedHosts.length > 0) return true;

  if (deltaReport.hostDiffs && [...deltaReport.hostDiffs.values()].some(hostChanged)) return true;

  return false;
}
