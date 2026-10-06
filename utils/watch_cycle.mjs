// utils/watch_cycle.mjs
// One --watch cycle: what stdout says and which hosts the webhook alerts (1.2.1 lane 4, items 4 + 11). The CLI's
// onCycleComplete prints `text` and sends `alerts`; nothing else decides either.
//
// RULED (R4 + Q1–Q5): by DEFAULT a host alerts when its own scan CHANGED since the previous cycle — hostChanged, the ONE
// predicate stdout uses too — and it has at least one finding at or above the alert severity. The first cycle
// establishes the baseline and alerts nobody, whatever it finds. With `everyCycle` (--alert-every-cycle) every host with
// such a finding alerts on every cycle, the first included. A host whose scan FAILED is reported on stdout and counts as
// changed, but it does not alert in this release: it has no findings, and the payload is findings-shaped.

import { buildDeltaReport, formatDeltaSummary, hostChanged, WATCH_NOT_COMPARABLE } from './delta_reporter.mjs';
import { conclusionFindings, severityRank } from './service_flags.mjs';

export { WATCH_NOT_COMPARABLE };

/**
 * @param {Map<string, object>} current   host → this cycle's scanSingleHost output (or the scheduler's `{ error }`)
 * @param {Map<string, object>|null} previous  the previous cycle's map, null on the first cycle
 * @param {{ alertRank: number, everyCycle?: boolean }} opts  alertRank on the shared table's scale (severityRank)
 * @returns {{ delta: object|null, text: string|null, alerts: { host: string, findings: object[] }[] }}
 */
export function watchCycle(current, previous, { alertRank, everyCycle = false } = {}) {
  const delta = previous ? buildDeltaReport(current, previous) : null;
  const text = delta ? formatDeltaSummary(delta) : null;
  const alerts = [];
  for (const [host, out] of current) {
    if (!out?.conclusion) continue; // a failed scan: on stdout, never alerted in this release
    if (!everyCycle && !(delta && hostChanged(delta.hostDiffs.get(host)))) continue;
    // One detail per FINDING at or above the alert severity, each with its own grade — the shared service-flag table
    // (1.2.1 (s1)), so the alert names what --fail-on and the reports name.
    const findings = conclusionFindings(out.conclusion, host)
      .filter((f) => severityRank(f.severity) >= alertRank)
      .map((f) => ({ port: f.port, protocol: f.protocol, service: f.service, description: f.title, severity: f.severity.toLowerCase() }));
    if (findings.length > 0) alerts.push({ host, findings });
  }
  return { delta, text, alerts };
}
