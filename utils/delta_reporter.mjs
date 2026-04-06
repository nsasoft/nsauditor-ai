// utils/delta_reporter.mjs
// Delta reporting: compare two full scan cycles across multiple hosts.

import { computeDiff } from './scan_history.mjs';

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
    const curr = currMap.get(h);
    const prev = prevMap.has(h) ? prevMap.get(h) : null;
    hostDiffs.set(h, computeDiff(curr, prev));
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
      for (const diff of deltaReport.hostDiffs.values()) {
        if (diff.newServices?.length || diff.removedServices?.length || diff.changedServices?.length || diff.newFindings) {
          anyChange = true;
          break;
        }
      }
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

  if (deltaReport.hostDiffs) {
    for (const diff of deltaReport.hostDiffs.values()) {
      if (diff.newServices?.length > 0) return true;
      if (diff.removedServices?.length > 0) return true;
      if (diff.changedServices?.length > 0) return true;
      if (diff.newFindings && diff.newFindings !== 0) return true;
    }
  }

  return false;
}
