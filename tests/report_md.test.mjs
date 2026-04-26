import test from 'node:test';
import assert from 'node:assert/strict';

import { buildMarkdownReport, _internals } from '../utils/report_md.mjs';

const { extractFindings, normalizeSeverity, severityRank, escapeCell, safeFenceFor } = _internals;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const minimalConclusion = {
  result: { services: [] },
  summary: 'Host is up. 0 services detected.',
  host: { up: true, os: 'Linux', osVersion: '6.5', name: 'gateway.example.com' },
};

const conclusionWithServices = {
  result: {
    services: [
      { port: 22, protocol: 'tcp', service: 'ssh', program: 'OpenSSH', version: '8.2p1', status: 'open' },
      { port: 443, protocol: 'tcp', service: 'https', program: 'nginx', version: '1.24.0', status: 'open' },
      { port: 53, protocol: 'udp', service: 'dns', program: 'BIND', version: '9.16', status: 'open' },
    ],
  },
  summary: 'Host is up. 3 services detected.',
  host: { up: true, os: 'Ubuntu', osVersion: '22.04' },
};

const conclusionWithFindings = {
  result: {
    services: [
      { port: 21, protocol: 'tcp', service: 'ftp', anonymousLogin: true },
      { port: 53, protocol: 'tcp', service: 'dns', axfrAllowed: true },
      { port: 161, protocol: 'udp', service: 'snmp', community: 'public' },
      { port: 443, protocol: 'tcp', service: 'https', weakProtocols: ['TLSv1.0', 'TLSv1.1'] },
      { port: 80, protocol: 'tcp', service: 'http', dangerousMethods: ['PUT', 'DELETE'] },
      { port: 22, protocol: 'tcp', service: 'ssh', program: 'OpenSSH', version: '8.2p1', cves: ['CVE-2023-38408'] },
    ],
  },
};

// ---------------------------------------------------------------------------
// buildMarkdownReport — structural assertions
// ---------------------------------------------------------------------------

test('buildMarkdownReport: required sections present in minimal report', () => {
  const md = buildMarkdownReport({ host: '10.0.0.1', conclusion: minimalConclusion });
  assert.match(md, /^# NSAuditor AI Scan Report/m, 'must have H1 header');
  assert.match(md, /^## Summary$/m, 'must have Summary section');
  assert.match(md, /^## Services$/m, 'must have Services section');
  assert.match(md, /^## Findings$/m, 'must have Findings section');
});

test('buildMarkdownReport: header includes host, scan time, OS info', () => {
  const md = buildMarkdownReport({
    host: '10.0.0.1',
    conclusion: minimalConclusion,
    toolVersion: '0.1.15',
    scanTime: '2026-04-26T12:00:00Z',
  });
  assert.match(md, /\*\*Host:\*\* 10\.0\.0\.1/);
  assert.match(md, /\*\*Scan time:\*\* 2026-04-26T12:00:00Z/);
  assert.match(md, /\*\*Tool version:\*\* 0\.1\.15/);
  assert.match(md, /\*\*OS:\*\* Linux 6\.5/);
  assert.match(md, /\*\*Hostname:\*\* gateway\.example\.com/);
});

test('buildMarkdownReport: scanTime accepts Date object and emits ISO string', () => {
  const fixed = new Date('2026-04-26T12:34:56Z');
  const md = buildMarkdownReport({ host: 'h', conclusion: minimalConclusion, scanTime: fixed });
  assert.match(md, /2026-04-26T12:34:56\.000Z/);
});

test('buildMarkdownReport: scanTime defaults to now when omitted', () => {
  const md = buildMarkdownReport({ host: 'h', conclusion: minimalConclusion });
  // Just confirm an ISO-shaped timestamp is present
  assert.match(md, /\*\*Scan time:\*\* \d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/);
});

test('buildMarkdownReport: services table has correct header row and one row per service', () => {
  const md = buildMarkdownReport({ host: '10.0.0.1', conclusion: conclusionWithServices });
  assert.match(md, /^\| Port \| Protocol \| Service \| Program \| Version \| Status \|$/m);
  assert.match(md, /\| 22 \| tcp \| ssh \| OpenSSH \| 8\.2p1 \| open \|/);
  assert.match(md, /\| 443 \| tcp \| https \| nginx \| 1\.24\.0 \| open \|/);
  assert.match(md, /\| 53 \| udp \| dns \| BIND \| 9\.16 \| open \|/);
});

test('buildMarkdownReport: empty services renders italicized placeholder', () => {
  const md = buildMarkdownReport({ host: 'h', conclusion: minimalConclusion });
  assert.match(md, /_No services detected\._/);
});

test('buildMarkdownReport: services count appears in Summary', () => {
  const md = buildMarkdownReport({ host: 'h', conclusion: conclusionWithServices });
  assert.match(md, /\*\*Services detected:\*\* 3/);
});

// ---------------------------------------------------------------------------
// Findings extraction and rendering
// ---------------------------------------------------------------------------

test('buildMarkdownReport: Findings section enumerates security flags', () => {
  const md = buildMarkdownReport({ host: '10.0.0.5', conclusion: conclusionWithFindings });
  assert.match(md, /FTP anonymous login enabled/);
  assert.match(md, /DNS zone transfer \(AXFR\) allowed/);
  assert.match(md, /SNMP default community string: public/);
  assert.match(md, /Weak protocol\(s\) enabled: TLSv1\.0, TLSv1\.1/);
  assert.match(md, /Dangerous HTTP method\(s\) allowed: PUT, DELETE/);
  assert.match(md, /CVE-2023-38408 — OpenSSH 8\.2p1/);
});

test('buildMarkdownReport: findings sorted descending by severity (Critical first)', () => {
  const md = buildMarkdownReport({ host: '10.0.0.5', conclusion: conclusionWithFindings });
  const criticalIdx = md.indexOf('[Critical]');
  const highIdx = md.indexOf('[High]');
  const mediumIdx = md.indexOf('[Medium]');
  assert.ok(criticalIdx > -1 && highIdx > -1 && mediumIdx > -1);
  assert.ok(criticalIdx < highIdx, 'Critical must come before High');
  assert.ok(highIdx < mediumIdx, 'High must come before Medium');
});

test('buildMarkdownReport: no findings renders italicized placeholder', () => {
  const md = buildMarkdownReport({ host: 'h', conclusion: conclusionWithServices });
  assert.match(md, /_No security findings\._/);
  assert.match(md, /\*\*Security findings:\*\* 0/);
});

test('buildMarkdownReport: severity counts in Summary line', () => {
  const md = buildMarkdownReport({ host: 'h', conclusion: conclusionWithFindings });
  assert.match(md, /\*\*Security findings:\*\* \d+ \(Critical: \d+, High: \d+, Medium: \d+\)/);
});

test('buildMarkdownReport: CVE finding evidence includes NVD link', () => {
  const md = buildMarkdownReport({ host: 'h', conclusion: conclusionWithFindings });
  assert.match(md, /https:\/\/nvd\.nist\.gov\/vuln\/detail\/CVE-2023-38408/);
});

test('buildMarkdownReport: CVE finding renders inside fenced code block', () => {
  const md = buildMarkdownReport({ host: 'h', conclusion: conclusionWithFindings });
  // Look for the evidence block — three backticks before/after the URL
  assert.match(md, /```[\s\S]*nvd\.nist\.gov\/vuln\/detail\/CVE-2023-38408[\s\S]*```/);
});

// ---------------------------------------------------------------------------
// AI Analysis section
// ---------------------------------------------------------------------------

test('buildMarkdownReport: AI Analysis section appears when aiAnalysis is provided', () => {
  const md = buildMarkdownReport({
    host: 'h',
    conclusion: minimalConclusion,
    aiAnalysis: 'The host is exposed via SSH and HTTPS. No critical issues found.',
  });
  assert.match(md, /^## AI Analysis$/m);
  assert.match(md, /No critical issues found\./);
});

test('buildMarkdownReport: AI Analysis section omitted when aiAnalysis is empty/missing', () => {
  const md1 = buildMarkdownReport({ host: 'h', conclusion: minimalConclusion });
  const md2 = buildMarkdownReport({ host: 'h', conclusion: minimalConclusion, aiAnalysis: '' });
  const md3 = buildMarkdownReport({ host: 'h', conclusion: minimalConclusion, aiAnalysis: '   ' });
  for (const md of [md1, md2, md3]) {
    assert.doesNotMatch(md, /## AI Analysis/);
  }
});

// ---------------------------------------------------------------------------
// Defensive / edge cases
// ---------------------------------------------------------------------------

test('buildMarkdownReport: throws on missing scanData', () => {
  assert.throws(() => buildMarkdownReport(null), TypeError);
  assert.throws(() => buildMarkdownReport(undefined), TypeError);
});

test('buildMarkdownReport: tolerates conclusion with no result/services key', () => {
  const md = buildMarkdownReport({ host: 'h', conclusion: {} });
  assert.match(md, /\*\*Services detected:\*\* 0/);
  assert.match(md, /_No services detected\._/);
  assert.match(md, /_No security findings\._/);
});

test('buildMarkdownReport: tolerates entirely missing conclusion', () => {
  const md = buildMarkdownReport({ host: 'h' });
  assert.match(md, /\*\*Services detected:\*\* 0/);
});

test('buildMarkdownReport: escapes pipe characters in service fields (table-safe)', () => {
  const conclusion = {
    result: {
      services: [
        { port: 80, protocol: 'tcp', service: 'http', banner: 'a|b|c', program: 'srv|name', version: '1.0' },
      ],
    },
  };
  const md = buildMarkdownReport({ host: 'h', conclusion });
  // Pipes inside cells should be backslash-escaped
  assert.match(md, /srv\\\|name/, `pipes in program must be escaped, got:\n${md}`);
});

test('buildMarkdownReport: collapses newlines in service fields (table-safe)', () => {
  const conclusion = {
    result: { services: [{ port: 80, service: 'http', program: 'multi\nline\rtext' }] },
  };
  const md = buildMarkdownReport({ host: 'h', conclusion });
  assert.match(md, /\| multi line text \|/);
});

test('buildMarkdownReport: "Unknown" program/version values render as empty cell', () => {
  const conclusion = {
    result: { services: [{ port: 22, service: 'ssh', program: 'Unknown', version: 'Unknown' }] },
  };
  const md = buildMarkdownReport({ host: 'h', conclusion });
  // The row should not include literal 'Unknown' in the program/version cells
  assert.doesNotMatch(md, /\| Unknown \|/);
});

// ---------------------------------------------------------------------------
// Internal helpers (sanity coverage)
// ---------------------------------------------------------------------------

test('extractFindings: returns empty array for no services', () => {
  assert.deepEqual(extractFindings([], 'h'), []);
});

test('extractFindings: assigns Critical to anonymousLogin and AXFR', () => {
  const findings = extractFindings(
    [
      { port: 21, service: 'ftp', anonymousLogin: true },
      { port: 53, service: 'dns', axfrAllowed: true },
    ],
    'h'
  );
  assert.equal(findings.length, 2);
  assert.ok(findings.every((f) => f.severity === 'Critical'));
});

test('normalizeSeverity: maps known severities case-insensitively', () => {
  assert.equal(normalizeSeverity('CRITICAL'), 'Critical');
  assert.equal(normalizeSeverity('high'), 'High');
  assert.equal(normalizeSeverity('Medium'), 'Medium');
  assert.equal(normalizeSeverity('lo'), 'Low');
});

test('normalizeSeverity: unknown / null falls back to Info', () => {
  assert.equal(normalizeSeverity(null), 'Info');
  assert.equal(normalizeSeverity(''), 'Info');
  assert.equal(normalizeSeverity('whatever'), 'Info');
});

test('severityRank: orders Critical < High < Medium < Low < Info', () => {
  assert.ok(severityRank('Critical') < severityRank('High'));
  assert.ok(severityRank('High')     < severityRank('Medium'));
  assert.ok(severityRank('Medium')   < severityRank('Low'));
  assert.ok(severityRank('Low')      < severityRank('Info'));
  assert.ok(severityRank('unknown')  >= severityRank('Info'));
});

test('escapeCell: nullish becomes empty string', () => {
  assert.equal(escapeCell(null), '');
  assert.equal(escapeCell(undefined), '');
});

test('escapeCell: backticks are escaped', () => {
  assert.equal(escapeCell('foo`bar'), 'foo\\`bar');
});

// ---------------------------------------------------------------------------
// safeFenceFor — Markdown injection defense (N.16)
// ---------------------------------------------------------------------------

test('safeFenceFor: empty / null content uses standard 3-tick fence', () => {
  assert.equal(safeFenceFor(''), '```');
  assert.equal(safeFenceFor(null), '```');
  assert.equal(safeFenceFor(undefined), '```');
});

test('safeFenceFor: content with no backticks uses 3-tick fence', () => {
  assert.equal(safeFenceFor('plain text with no backticks'), '```');
  assert.equal(safeFenceFor('https://example.com/foo?bar=baz'), '```');
});

test('safeFenceFor: content with single backticks still uses 3-tick fence', () => {
  // A single backtick run of length 1 needs fence > 1 → 3 (the minimum) is fine
  assert.equal(safeFenceFor('use `npm install`'), '```');
  assert.equal(safeFenceFor('``two``'), '```');
});

test('safeFenceFor: content with 3 consecutive backticks bumps fence to 4', () => {
  assert.equal(safeFenceFor('embedded ``` block'), '````');
});

test('safeFenceFor: content with 4 consecutive backticks bumps fence to 5', () => {
  assert.equal(safeFenceFor('embedded ```` block'), '`````');
});

test('safeFenceFor: pathological 10-backtick run → 11-tick fence', () => {
  const content = 'before ' + '`'.repeat(10) + ' after';
  assert.equal(safeFenceFor(content), '`'.repeat(11));
});

test('safeFenceFor: longest run wins when multiple runs are present', () => {
  // Mixed: a single, a triple, a double — the triple wins → fence = 4
  assert.equal(safeFenceFor('` then ``` then ``'), '````');
});

test('safeFenceFor: non-string input is coerced safely', () => {
  assert.equal(safeFenceFor(42), '```');
  assert.equal(safeFenceFor({ toString: () => '```inside```' }), '````');
});

// ---------------------------------------------------------------------------
// Rendering integration — fenced blocks survive backtick-bearing evidence
// ---------------------------------------------------------------------------

test('buildMarkdownReport: evidence with no backticks uses 3-tick fence (no over-escaping)', () => {
  // The CVE finding (which produces evidence "See https://...") has no backticks.
  const conclusion = {
    result: { services: [{ port: 22, service: 'ssh', cves: ['CVE-2023-38408'] }] },
  };
  const md = buildMarkdownReport({ host: 'h', conclusion });
  // Standard 3-tick fence should appear
  assert.match(md, /\n  ```\n[\s\S]*nvd\.nist\.gov[\s\S]*\n  ```\n/);
});

test('buildMarkdownReport: evidence containing ``` survives — fences upgrade to 4 ticks', () => {
  // Force a finding whose evidence contains a literal triple-backtick.
  // We use a CVE with a fabricated evidence string; the simplest path is to
  // mutate the conclusion to inject evidence via the existing finding pipeline.
  // Since extractFindings derives evidence internally, we test buildMarkdownReport
  // by constructing a service whose CVE name itself does NOT contain backticks but
  // whose existing evidence path is augmented. Easier path: test the renderer with
  // a finding directly via the public path — but findings are derived inside the
  // renderer. So we exercise this through a conclusion shape that produces such
  // evidence: a CVE id in canonical form whose evidence URL is fixed.
  //
  // Direct approach: write a fixture where weakCiphers contains a 3-backtick
  // string; the Medium-severity finding's evidence is built from `weakCiphers.slice(0, 5).join(', ')`.
  const conclusion = {
    result: {
      services: [
        { port: 443, service: 'https', weakCiphers: ['cipher-A', '```injected```'] },
      ],
    },
  };
  const md = buildMarkdownReport({ host: 'h', conclusion });
  // The 4-tick fence must wrap the evidence so the embedded triple-backtick doesn't escape
  assert.match(md, /  ````\n[\s\S]*```injected```[\s\S]*\n  ````\n/);
  // And 3-tick fence must NOT be the wrapper around this evidence
  assert.doesNotMatch(md, /  ```\n  cipher-A, ```injected```/);
});

test('buildMarkdownReport: evidence containing 4 backticks → 5-tick fence', () => {
  const conclusion = {
    result: {
      services: [
        { port: 443, service: 'https', weakCiphers: ['````four-tick````'] },
      ],
    },
  };
  const md = buildMarkdownReport({ host: 'h', conclusion });
  // Must use a 5-tick fence to safely contain 4-tick run
  assert.match(md, /  `````\n[\s\S]*````four-tick````[\s\S]*\n  `````\n/);
});

test('buildMarkdownReport: closing fence always matches opening fence length', () => {
  // Property test: for any backtick-bearing evidence, the opening and closing fences
  // wrapping that evidence must have identical length
  const conclusion = {
    result: {
      services: [
        { port: 80, service: 'http', weakCiphers: ['short ` here', 'longer ``` there'] },
      ],
    },
  };
  const md = buildMarkdownReport({ host: 'h', conclusion });
  // Find every fence pair and confirm matched lengths
  const fences = md.match(/^  (`{3,})$/gm) || [];
  // Should appear in pairs
  assert.equal(fences.length % 2, 0, `fence count must be even, got ${fences.length}`);
  for (let i = 0; i < fences.length; i += 2) {
    assert.equal(fences[i], fences[i + 1], `fence pair mismatch at index ${i}`);
  }
});
