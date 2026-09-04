// utils/report_finding_census.mjs
//
// WHICH CONTAINERS IN A SCAN RECORD CAN HOLD A FINDING, AND DOES THE REPORT READ THEM?
//
// Built after Gate 3-B drove the `report` subcommand over a real 192.168.1.1 run and the
// client deliverable said, over sixteen known CVEs:
//
//     "No findings were recorded in this run."
//     CRITICAL 0 · HIGH 0 · MEDIUM 0 · LOW 0 · INFO 0 · PASS 0 · OTHER 0
//
// `shapeHost` read exactly one container — `result.findings[]` as an ARRAY — and on a
// network host that container is EMPTY. Measured on that run: 47 severity-bearing rows
// live in four other places, and none of them was opened.
//
// ⚠️ WHY THIS IS A CENSUS AND NOT FIVE MORE READERS. The defect was never "we forgot the
// queue". It was that nothing in the product could answer "is there a finding we are not
// rendering?" — so each door had to be found by a human reading raw JSON. A census keyed
// on CONTAINERS answers that question by construction: every container carrying a
// severity-bearing object is either READ or explicitly ALLOWLISTED with a written reason,
// and one that is NEITHER fails loudly. Incompleteness costs NOISE, never SILENCE — the
// inverse of the shape that produced the false clean.
//
// ⚠️ AND THE FIXTURE LESSON THAT MADE IT NECESSARY: the fleet fixture written one round
// earlier proves `shapeFinding` over every finding SHAPE, and it could not see this,
// because the network path's failure is a SOURCE the consumer never opens. A fixture
// drawn from a producer's field names cannot catch a producer whose output lives in a
// different artifact.

/** Containers the report READS. Adding a reader means adding its key here. */
export const READ_CONTAINERS = Object.freeze([
  'result.findings[]',                  // array-shaped plugin findings (the cloud shape)
  'result.findings.<category>[]',       // dict-of-categories (060 DNS Security Auditor)
  'result.zeroTrust.<dim>.findings[]',  // 1023 Zero Trust Assessment
  'result.portResults[].issues[]',      // 040 TLS Certificate & Cipher Auditor
  'findingQueue[]',                     // the EE finding queue (intelligence_engine, crypto_agent)
]);

/**
 * Containers that carry a `severity` but are NOT findings. Each needs a written reason —
 * an allowlist entry with no reason is how a real door gets closed by accident.
 */
export const ALLOWLISTED_CONTAINERS = Object.freeze({
  'result.portResults[]':
    'A per-port ROLL-UP, not a finding: its severity summarises the port\'s own '
    + '`issues[]`, which ARE read. Rendering both would double-count every TLS issue.',
  'result.summary.cisAlarmCoverage.uncovered[]':
    'A 1:1 SUMMARY MIRROR of 1040\'s own alarm-coverage findings, not a second source. '
    + 'Adjudicated on the 0.44.0 cloud run: 13 uncovered classes, 13 "alarm missing" '
    + 'findings, and the set difference of their cis-N.N ids is EMPTY. If that ever stops '
    + 'holding the mirror has broken and this entry is wrong — re-derive, do not re-assert.',
  'result.findings[].policyAnalyses[].issues[]':
    'Per-statement EVIDENCE nested inside a finding that IS rendered — e.g. "Full admin '
    + 'grant: Action \'*\' in policy X" backing a parent whose own issues[] already say '
    + '"SHADOW ADMIN: User has full wildcard (*) permissions". Not a missed finding. '
    + 'RESIDUAL, stated rather than hidden: the per-statement detail is not surfaced in the '
    + 'report at all, which is a DEPTH choice nobody has ruled on, not a coverage gap.',
  'result.data[]':
    'NOT a findings container, and the report must never read it. On a CLOUD host it '
    + 'MIRRORS result.findings (verified 0.44.0: 1150 16/16, 1170 9/9). On a NETWORK host '
    + 'it is PROBE TELEMETRY — measured on the 192.168.1.1 run, findings[]=0 while '
    + 'data[]=85, 84 of them {probe_protocol, probe_port, probe_info} ("Connect refused '
    + '(ECONNREFUSED)", "No UDP response"). ⚠️ A `findings ?? data` fallback was written '
    + 'here and REVERTED: it put scan telemetry into a client deliverable, hidden because '
    + 'the telemetry rows collided on one content hash and collapsed to two. '
    + 'cloud_finding_summary\'s findingsOf may use that precedence — it only ever sees '
    + 'cloud producers; this consumer sees both paths.',
});

const QUEUE_CONTAINER = 'findingQueue[]';

/**
 * Classify where a severity-bearing object lives. Path is the dotted walk from `result`.
 * @returns {string} a container key
 */
function containerOf(path) {
  if (/^\.findings\[\d+\]$/.test(path)) return 'result.findings[]';
  if (/^\.findings\.[A-Za-z0-9_]+\[\d+\]$/.test(path)) return 'result.findings.<category>[]';
  if (/zeroTrust\..*\.findings\[\d+\]$/.test(path)) return 'result.zeroTrust.<dim>.findings[]';
  if (/^\.portResults\[\d+\]\.issues\[\d+\]$/.test(path)) return 'result.portResults[].issues[]';
  if (/^\.portResults\[\d+\]$/.test(path)) return 'result.portResults[]';
  if (/^\.summary\.cisAlarmCoverage\.uncovered\[\d+\]$/.test(path)) return 'result.summary.cisAlarmCoverage.uncovered[]';
  if (/^\.findings\[\d+\]\.policyAnalyses\[\d+\]\.issues\[\d+\]$/.test(path)) return 'result.findings[].policyAnalyses[].issues[]';
  if (/^\.data\[\d+\]$/.test(path)) return 'result.data[]';
  // An UNRECOGNISED container is reported under its own generalised path rather than
  // bucketed into "other" — a census that collapses the unknown into one bucket tells you
  // that something is missing without telling you what.
  return `UNCLASSIFIED:${path.replace(/\[\d+\]/g, '[]')}`;
}

function* severityObjects(node, path = '') {
  if (Array.isArray(node)) {
    for (let i = 0; i < node.length; i += 1) yield* severityObjects(node[i], `${path}[${i}]`);
  } else if (node && typeof node === 'object') {
    if (typeof node.severity === 'string') yield { path, obj: node };
    for (const [k, v] of Object.entries(node)) yield* severityObjects(v, `${path}.${k}`);
  }
}

/**
 * Census one scan record.
 * @param {object} raw   the parsed scan_conclusion_raw.json
 * @param {Array}  queue the host's finding queue (scan_finding_queue.json, or the
 *                       eeEnrichment fallback) — passed in because it is a SIBLING
 *                       artifact, not part of `raw`, which is the whole reason it was missed.
 * @returns {{byContainer: Object<string, number>, unread: Object<string, number>, total: number}}
 */
export function censusFindingContainers(raw, queue = []) {
  const byContainer = {};
  const bump = (k) => { byContainer[k] = (byContainer[k] || 0) + 1; };

  for (const e of (Array.isArray(raw?.results) ? raw.results : [])) {
    for (const { path } of severityObjects(e?.result ?? {}, '')) bump(containerOf(path));
  }
  if (Array.isArray(queue) && queue.length) byContainer[QUEUE_CONTAINER] = queue.length;

  const unread = {};
  for (const [k, n] of Object.entries(byContainer)) {
    if (READ_CONTAINERS.includes(k)) continue;
    if (Object.prototype.hasOwnProperty.call(ALLOWLISTED_CONTAINERS, k)) continue;
    unread[k] = n;
  }
  return { byContainer, unread, total: Object.values(byContainer).reduce((a, b) => a + b, 0) };
}
