// utils/report_md.mjs
// Render scan conclusion as GitHub-flavored Markdown.
//
// Used by:
//   - CLI --output-format md → writes scan_report.md alongside other formats
//   - MCP scan_host tool → returns ready-to-quote markdown block in the tool response
//
// Pure synchronous renderer — no I/O, no network. Empty-conclusion inputs produce a
// minimal report (header + "no services detected") rather than throwing, so callers
// don't need to guard before invocation.

import { conclusionFindings, conclusionNotTested, manifestNotTested, normalizeSeverity, SERVICE_FLAGS, SEVERITY_ORDER } from './service_flags.mjs';
import { shapeHostFindings, isCoverageGap, isGapOnly, coverageGapText } from './report_inputs.mjs';

const SEVERITIES = SEVERITY_ORDER;

/**
 * Escape Markdown special characters that would break table cell rendering.
 * Pipes break tables; backticks break inline code; newlines break row layout.
 */
// Every Markdown- or HTML-active character is backslash-escaped (CommonMark allows a backslash before any
// ASCII punctuation), so a value a NETWORK HOST chose — a hostname from mDNS or UPnP, an OS or program from a
// banner, the summary that embeds them — renders as text: no link, image, autolink, emphasis or raw tag.
// (1.3.0: it escaped only | and `, and the hostname and OS rows, once reachable, rendered live links,
// remote images and <img onerror> in any renderer that allows HTML.)
const MD_ACTIVE = /[\\`*_[\]<>!|~]/g;
function escapeCell(value) {
  if (value == null) return '';
  return String(value)
    .replace(/[\r\n]+/g, ' ')
    .replace(MD_ACTIVE, (c) => `\\${c}`);
}

/**
 * Trim a value for table display; '' if null/undefined/'Unknown'.
 */
function cell(value) {
  if (value == null) return '';
  const s = String(value).trim();
  if (!s || s === 'Unknown') return '';
  return escapeCell(s);
}

/**
 * The security findings a conclusion carries — every one graded by the shared service-flag table
 * (utils/service_flags.mjs, 1.3.0 (s1)), so this report, SARIF, the CSV and --fail-on count the same units.
 * `evidence` is the conclusion's evidence list: an adapter payload that landed there (a domain's DNS posture when the
 * scan found no 53/udp service) is graded too, targeting the host.
 *
 * @param {object[]} services
 * @param {string} host
 * @param {object[]} [evidence]
 * @returns {Array<{ severity: string, title: string, target: string, evidence: string|null }>}
 */
function extractFindings(services, host, evidence = []) {
  return conclusionFindings({ services, evidence }, host)
    .map((f) => ({ severity: f.severity, title: f.title, target: f.target, evidence: f.evidence }));
}

function severityRank(sev) {
  // Lower index → higher priority for sorting
  const idx = SEVERITIES.indexOf(sev);
  return idx === -1 ? SEVERITIES.length : idx;
}

/**
 * Compute a fenced-code-block delimiter that's guaranteed not to be closed
 * prematurely by backtick runs inside the content. Per CommonMark §4.5, the
 * closing fence must contain at least as many backticks as the opening fence,
 * so we pick (longest internal run + 1), with a floor of 3 (the standard).
 *
 * Defensive against Markdown injection when evidence contains user-supplied
 * data (banner snippets, probe responses) that may include literal ``` runs.
 *
 * @param {*} content - The content that will be wrapped in the fenced block.
 * @returns {string} Backtick string of appropriate length (length >= 3).
 */
function safeFenceFor(content) {
  const matches = String(content ?? '').match(/`+/g) || [];
  let longestRun = 0;
  for (const m of matches) {
    if (m.length > longestRun) longestRun = m.length;
  }
  const fenceLen = Math.max(3, longestRun + 1);
  return '`'.repeat(fenceLen);
}

/**
 * Build a GitHub-flavored Markdown scan report.
 *
 * @param {object} scanData
 * @param {string} scanData.host - Target host (IP or hostname)
 * @param {object} scanData.conclusion - Concluder output: { result: { services }, summary, host }
 * @param {string} [scanData.aiAnalysis] - Optional AI-generated analysis text (Markdown or plain)
 * @param {string} [scanData.toolVersion] - Tool version string (e.g. "0.1.15")
 * @param {string|Date} [scanData.scanTime] - Scan timestamp (defaults to now in ISO format)
 * @param {object[]} [scanData.results] - The plugin results ({id, name, result}); the coverage gaps are read from them.
 *   ABSENT IS NOT EMPTY: without them the report says the gaps were not evaluated.
 * @returns {string} Markdown report
 */
/** scan_host stopped at its total time limit: the note the response and the head of the markdown both carry. */
export const SCAN_HOST_WALL_NOTE =
  'This scan stopped at its total time limit (SCAN_HOST_WALL_MS), so it is a partial result, not a clean result: the '
  + 'plugins it did not start, or stopped at the limit, did not measure their surfaces. Raise SCAN_HOST_WALL_MS, or run '
  + 'the CLI, for a complete scan.';
export function buildMarkdownReport(scanData) {
  if (!scanData || typeof scanData !== 'object') {
    throw new TypeError('scanData required');
  }

  const host = scanData.host ?? '(unknown host)';
  const conclusion = scanData.conclusion ?? {};
  const services = conclusion?.result?.services ?? [];
  // runConcluder's callers receive {id, name, result: <conclusion>}; a legacy flat shape is still read.
  const hostInfo = conclusion?.result?.host ?? conclusion?.host ?? {};
  const summaryText = conclusion?.result?.summary ?? conclusion?.summary ?? '';
  const toolVersion = scanData.toolVersion ?? '';
  const scanTime = scanData.scanTime instanceof Date
    ? scanData.scanTime.toISOString()
    : (scanData.scanTime ?? new Date().toISOString());

  const lines = [];

  // ---- Header ----
  lines.push(`# NSAuditor AI Scan Report`);
  lines.push('');
  // scan_host stopped at its total time limit: said FIRST, above the summary and the service table, so a reader who
  // stops early still sees that this is a partial — with the plugins it did not start, and those it stopped at the
  // limit, in the order they would have run (the same lists as the response's callWall).
  const wall = scanData.callWall;
  if (wall && wall.reached) {
    const nameOf = new Map((Array.isArray(scanData.manifest) ? scanData.manifest : []).map((m) => [String(m?.id), m?.name || 'Plugin']));
    const named = (ids) => ids.map((id) => `${id} — ${nameOf.get(String(id)) ?? 'Plugin'}`).join(', ');
    lines.push(`> **${SCAN_HOST_WALL_NOTE}**`);
    lines.push('>');
    if (wall.notStarted.length) lines.push(`> - Not started: ${named(wall.notStarted)}`);
    if (wall.cutShort.length) lines.push(`> - Stopped at the limit: ${named(wall.cutShort)}`);
    lines.push('');
  }
  const headerRows = [
    ['Host', host],
    ['Scan time', scanTime],
  ];
  if (toolVersion) headerRows.push(['Tool version', toolVersion]);
  if (hostInfo.os) headerRows.push(['OS', `${hostInfo.os}${hostInfo.osVersion ? ' ' + hostInfo.osVersion : ''}`]);
  if (hostInfo.name && hostInfo.name !== host) headerRows.push(['Hostname', hostInfo.name]);
  for (const [k, v] of headerRows) {
    lines.push(`- **${k}:** ${escapeCell(v)}`);
  }
  lines.push('');

  // ---- Summary ----
  lines.push(`## Summary`);
  lines.push('');
  if (summaryText) {
    lines.push(escapeCell(summaryText));
    lines.push('');
  }
  lines.push(`- **Services detected:** ${services.length}`);

  const findings = extractFindings(services, host, conclusion?.result?.evidence ?? conclusion?.evidence ?? []);
  if (findings.length > 0) {
    const counts = {};
    for (const sev of SEVERITIES) counts[sev] = 0;
    for (const f of findings) counts[f.severity] = (counts[f.severity] || 0) + 1;
    const sevSummary = SEVERITIES
      .filter((s) => counts[s] > 0)
      .map((s) => `${s}: ${counts[s]}`)
      .join(', ');
    lines.push(`- **Security findings:** ${findings.length} (${sevSummary})`);
  } else {
    lines.push(`- **Security findings:** 0`);
  }
  // G-72 (v394 Q2, VERDICT-v395 §4): the rows that carry the COVERAGE-GAP marker, shaped by the report loader's own
  // shapeHostFindings over the plugin results and picked by its own isCoverageGap, so this report and the executive html
  // read one set with one shaping code. The headline above counts the concluder's SERVICE checks and never a loader row, so
  // this report can call no gap row "counted"; it marks each row by its producer's declaration instead (isGapOnly). Only a
  // declared row is called a surface the scanner could not read. ABSENT IS NOT EMPTY: a caller that hands no results gets a line saying the gaps were not evaluated, never a
  // silence that reads as "no gaps". Results with no gap row print nothing, so that report is byte-identical to before.
  // Stated limit: this report reads no EE finding queue, so a run whose only gaps are Enterprise analysis-agent (queue)
  // gaps prints no Coverage gaps section; the section says in itself that those are not listed.
  const gaps = Array.isArray(scanData.results)
    ? shapeHostFindings(host, { results: scanData.results }).filter(isCoverageGap)
    : null;
  if (gaps === null) {
    lines.push('- **Coverage gaps:** not evaluated — this report was built without the plugin results, so a surface the '
      + 'scanner could not read is not listed here.');
  } else if (gaps.length) {
    lines.push(`- **Coverage gaps:** ${gaps.length} ${gaps.length === 1 ? 'row' : 'rows'}, listed under Coverage gaps below `
      + '(Security findings counts service checks only, so no coverage-gap row is part of it)');
  }
  // 1.3.0 (a4) + (s3): a check that did not run, or ran and could not complete, is said to be NOT TESTED with its reason —
  // never "none" and never "refused". One line per check and reason, from the shared table, with every target it covers.
  // Build 4 (Gate 3-A F-1): a host-level audit that did not run — the DNS-security audit (060) declines an IP-address
  // target — is read from the run's MANIFEST, which both callers hand in; without one nothing is inferred from absence.
  const notTested = new Map();
  for (const n of [...conclusionNotTested(conclusion), ...manifestNotTested(scanData.manifest, host)]) {
    const k = `${n.check}\u0000${n.reason}`;
    if (!notTested.has(k)) notTested.set(k, { ...n, targets: [] });
    notTested.get(k).targets.push(n.target);
  }
  for (const n of notTested.values()) {
    lines.push(`- **${n.check} not tested:** ${n.targets.map((t) => escapeCell(t)).join(', ')} — ${escapeCell(n.reason)}`);
  }
  // 1.2.0 build 3: without this line "Security findings: 0" read as a clean verdict over a host whose CLI run carried 16
  // CVEs (the Gate 3-A preparation's P8). Since 1.3.0 (s1) the counted list is DERIVED from the shared service-flag table's
  // labels, so it names exactly what is graded — it cannot run ahead of the table or fall behind it.
  const counted = [...new Set(SERVICE_FLAGS.map((r) => r.label).filter(Boolean))];
  lines.push(`- **Scope:** counts only these service-check findings: ${counted.join(', ')}. `
    + 'The opt-in checks are off by default. '
    + 'It does not look up CVEs, and does not include Enterprise analysis-agent findings or exploit intelligence (a CLI scan '
    + 'with the Enterprise package and a Pro or Enterprise licence records CVE and agent findings in scan_finding_queue.json, '
    + 'when there are any).');
  lines.push('');

  // ---- Services table ----
  lines.push(`## Services`);
  lines.push('');
  if (services.length === 0) {
    lines.push('_No services detected._');
    lines.push('');
  } else {
    lines.push('| Port | Protocol | Service | Program | Version | Status |');
    lines.push('|------|----------|---------|---------|---------|--------|');
    for (const svc of services) {
      lines.push([
        '',
        cell(svc.port),
        cell(svc.protocol || 'tcp'),
        cell(svc.service),
        cell(svc.program),
        cell(svc.version),
        cell(svc.status),
        '',
      ].join(' | ').trim());
    }
    lines.push('');
  }

  // ---- Findings ----
  lines.push(`## Findings`);
  lines.push('');
  if (findings.length === 0) {
    // v394 Q2 c: on a gap-only run this sentence names the gap count, or "found anything" beside a gap reads as clean.
    // "Not a clean result" holds for ANY gap row, declared or not; what the row records is said in its own section.
    lines.push(gaps?.length
      ? `_None of the counted service checks found anything, and ${gaps.length} coverage-gap `
        + `${gaps.length === 1 ? 'row was' : 'rows were'} recorded, listed under Coverage gaps below. This is not a clean `
        + 'result. Nor is it a statement '
        + 'that the host has no known vulnerabilities — CVE lookups and analysis-agent findings are not part of this '
        + 'count (see Scope above), and anonymous FTP login, zone transfer and the SMB null session are tested only '
        + 'when enabled._'
      : '_None of the counted service checks found anything. This is not a statement that the host has no known '
        + 'vulnerabilities — CVE lookups and analysis-agent findings are not part of this count (see Scope above), and '
        + 'anonymous FTP login, zone transfer and the SMB null session are tested only when enabled._');
    lines.push('');
  } else {
    findings.sort((a, b) => severityRank(a.severity) - severityRank(b.severity));
    for (const f of findings) {
      // The title is escaped as a WHOLE: a CVE title interpolates the service's program and version, which a host
      // chooses (the HTTP probe's program is the raw Server header).
      lines.push(`### [${f.severity}] ${escapeCell(f.title)}`);
      lines.push('');
      lines.push(`- **Target:** ${escapeCell(f.target)}`);
      if (f.evidence) {
        lines.push('- **Evidence:**');
        lines.push('');
        const fence = safeFenceFor(f.evidence);
        lines.push('  ' + fence);
        lines.push('  ' + String(f.evidence).split(/\r?\n/).join('\n  '));
        lines.push('  ' + fence);
      }
      lines.push('');
    }
  }

  // ---- Coverage gaps (G-72) ----
  // One line per gap row, after the findings, marked by its producer's declaration (m-7). Each intro sentence speaks only of
  // the rows its mark names. Every value goes through escapeCell: a gap's text can carry a name or a code a host chose
  // (v394 Q2 d). A null port prints no ":null"; a cut title shows the whole text it was cut from where it can (Q1).
  if (gaps?.length) {
    const DECLARED = '**gap only:**';
    const UNDECLARED = '**may also state a finding (not declared gap-only by its producer):**';
    let intro = 'Rows that carry a coverage-gap marker on this host. Security findings above counts service checks only, so '
      + 'none of these rows is part of it.';
    if (gaps.some(isGapOnly)) {
      intro += ' A row marked **gap only** is declared by its producer to record only a surface the scanner could not read; a '
        + 'check that could not read a surface did not pass there.';
    }
    if (gaps.some((f) => !isGapOnly(f))) {
      intro += ' A row marked **may also state a finding (not declared gap-only by its producer)** carries the marker without '
        + 'that declaration: read its text as a possible finding as well as a gap.';
    }
    lines.push('## Coverage gaps');
    lines.push('');
    lines.push(`${intro} Enterprise analysis-agent gaps are not listed in this report.`);
    lines.push('');
    for (const f of gaps) {
      lines.push(`- ${escapeCell(f.host)}${f.port != null ? `:${escapeCell(f.port)}` : ''} — `
        + `${isGapOnly(f) ? DECLARED : UNDECLARED} ${escapeCell(coverageGapText(f))}`);
    }
    lines.push('');
  }

  // ---- AI Analysis (optional) ----
  if (scanData.aiAnalysis && String(scanData.aiAnalysis).trim()) {
    lines.push(`## AI Analysis`);
    lines.push('');
    lines.push(String(scanData.aiAnalysis).trim());
    lines.push('');
  }

  return lines.join('\n');
}

// Internal helpers exported for testing.
export const _internals = {
  extractFindings,
  normalizeSeverity,
  severityRank,
  escapeCell,
  safeFenceFor,
};
