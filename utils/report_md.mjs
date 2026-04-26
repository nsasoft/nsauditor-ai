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

const SEVERITIES = ['Critical', 'High', 'Medium', 'Low', 'Info'];

/**
 * Escape Markdown special characters that would break table cell rendering.
 * Pipes break tables; backticks break inline code; newlines break row layout.
 */
function escapeCell(value) {
  if (value == null) return '';
  return String(value)
    .replace(/\|/g, '\\|')
    .replace(/`/g, '\\`')
    .replace(/[\r\n]+/g, ' ');
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
 * Extract security findings from per-service fields.
 * Mirrors the per-service finding extraction used by sarif.mjs and export_csv.mjs:
 * findings are derived from service flags (anonymousLogin, weakAlgorithms, cves, etc.),
 * not from a separate findings array on the conclusion (which doesn't exist today).
 *
 * @param {object[]} services
 * @param {string} host
 * @returns {Array<{ severity: string, title: string, target: string, evidence: string|null }>}
 */
function extractFindings(services, host) {
  const findings = [];

  for (const svc of services) {
    const target = `${host}:${svc.port}/${svc.protocol || 'tcp'}`;

    if (svc.anonymousLogin === true) {
      findings.push({
        severity: 'Critical',
        title: 'FTP anonymous login enabled',
        target,
        evidence: `${svc.service || 'ftp'} on ${target} accepts anonymous authentication.`,
      });
    }

    if (svc.axfrAllowed === true) {
      findings.push({
        severity: 'Critical',
        title: 'DNS zone transfer (AXFR) allowed',
        target,
        evidence: `Zone transfer permitted on ${target}; entire zone may be enumerated.`,
      });
    }

    if (svc.community && (svc.community === 'public' || svc.community === 'private')) {
      findings.push({
        severity: 'High',
        title: `SNMP default community string: ${svc.community}`,
        target,
        evidence: `SNMP responds to community "${svc.community}" on ${target}.`,
      });
    }

    if (Array.isArray(svc.weakAlgorithms) && svc.weakAlgorithms.length > 0) {
      const algos = svc.weakAlgorithms
        .map((a) => (typeof a === 'string' ? a : a?.algorithm || a?.name || ''))
        .filter(Boolean);
      findings.push({
        severity: 'Medium',
        title: `Weak algorithm(s) supported: ${algos.join(', ')}`,
        target,
        evidence: null,
      });
    }

    if (Array.isArray(svc.weakProtocols) && svc.weakProtocols.length > 0) {
      findings.push({
        severity: 'Medium',
        title: `Weak protocol(s) enabled: ${svc.weakProtocols.join(', ')}`,
        target,
        evidence: null,
      });
    }

    if (Array.isArray(svc.weakCiphers) && svc.weakCiphers.length > 0) {
      findings.push({
        severity: 'Medium',
        title: `Weak cipher(s) supported: ${svc.weakCiphers.length} cipher(s)`,
        target,
        evidence: svc.weakCiphers.slice(0, 5).join(', '),
      });
    }

    if (Array.isArray(svc.dangerousMethods) && svc.dangerousMethods.length > 0) {
      findings.push({
        severity: 'Medium',
        title: `Dangerous HTTP method(s) allowed: ${svc.dangerousMethods.join(', ')}`,
        target,
        evidence: null,
      });
    }

    const cves = svc.cves || svc.cve || [];
    if (Array.isArray(cves)) {
      for (const cve of cves) {
        const cveId = typeof cve === 'string' ? cve : (cve?.id || cve?.cveId || '');
        if (!cveId) continue;
        const sev = (typeof cve === 'object' && cve?.severity) ? String(cve.severity) : 'High';
        findings.push({
          severity: normalizeSeverity(sev),
          title: `${cveId} — ${svc.program || svc.service || 'service'}${svc.version && svc.version !== 'Unknown' ? ' ' + svc.version : ''}`,
          target,
          evidence: `See https://nvd.nist.gov/vuln/detail/${cveId}`,
        });
      }
    }
  }

  return findings;
}

function normalizeSeverity(sev) {
  if (!sev) return 'Info';
  const s = String(sev).trim().toLowerCase();
  if (s.startsWith('crit')) return 'Critical';
  if (s.startsWith('hi'))   return 'High';
  if (s.startsWith('med'))  return 'Medium';
  if (s.startsWith('lo'))   return 'Low';
  return 'Info';
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
 * @returns {string} Markdown report
 */
export function buildMarkdownReport(scanData) {
  if (!scanData || typeof scanData !== 'object') {
    throw new TypeError('scanData required');
  }

  const host = scanData.host ?? '(unknown host)';
  const conclusion = scanData.conclusion ?? {};
  const services = conclusion?.result?.services ?? [];
  const hostInfo = conclusion?.host ?? {};
  const summaryText = conclusion?.summary ?? '';
  const toolVersion = scanData.toolVersion ?? '';
  const scanTime = scanData.scanTime instanceof Date
    ? scanData.scanTime.toISOString()
    : (scanData.scanTime ?? new Date().toISOString());

  const lines = [];

  // ---- Header ----
  lines.push(`# NSAuditor AI Scan Report`);
  lines.push('');
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

  const findings = extractFindings(services, host);
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
    lines.push('_No security findings._');
    lines.push('');
  } else {
    findings.sort((a, b) => severityRank(a.severity) - severityRank(b.severity));
    for (const f of findings) {
      lines.push(`### [${f.severity}] ${f.title}`);
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
