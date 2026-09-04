import test from 'node:test';
import assert from 'node:assert/strict';
import { renderExecutiveReport, egressViolations } from '../utils/executive_report.mjs';

// A literal, not a fixture builder — a shape change in Task 4's model must be visible here,
// not absorbed by a helper that quietly adapts to whatever report_inputs.mjs now emits.
const MODEL = {
  runId: 'run_20260826T091400Z_ab12cd',
  startedAt: '2026-08-26T09:14:00Z',
  finishedAt: '2026-08-26T10:02:11Z',
  tier: 'pro',
  ceVersion: '0.2.50',
  eeVersion: null,
  coverage: {
    requested: 14,
    written: 14,
    reachable: 12,
    missing: [],
    partial: false,
    incomplete: false,
  },
  plugins: {
    ran: 26,
    skipped: 3,
    errored: 1,
    timedOut: 0,
    // `dir` mirrors the matching entry in `hosts:` below (report_inputs.mjs threads them
    // through together — see CC-2) — the renderer keys its per-host plugin table by `dir`,
    // never by `host` name, precisely because two directories can share a host name.
    byHost: [
      { host: '10.0.0.1', dir: '10.0.0.1_20260826T091400Z', status: [
        { id: '003', name: 'Port Scanner', status: 'ran', reason: null },
        { id: '010', name: 'TLS Auditor', status: 'ran', reason: null },
      ] },
      { host: '10.0.0.2', dir: '10.0.0.2_20260826T091405Z', status: [
        { id: '003', name: 'Port Scanner', status: 'ran', reason: null },
        { id: '020', name: 'HTTP Auditor', status: 'skipped', reason: 'no HTTP service detected' },
      ] },
      { host: '10.0.0.3', dir: '10.0.0.3_20260826T091410Z', status: [
        { id: '003', name: 'Port Scanner', status: 'error', reason: 'connection refused' },
      ] },
    ],
  },
  kev: { loaded: true, snapshot: '2026-08-20' },
  epss: { loaded: true, snapshot: '2026-08-20' },
  hosts: [
    {
      host: '10.0.0.1',
      dir: '10.0.0.1_20260826T091400Z',
      up: true,
      findings: [
        {
          host: '10.0.0.1', port: 443, severity: 'CRITICAL',
          title: 'OpenSSL Heartbleed exposure',
          detail: 'The TLS service responds to a malformed heartbeat request with out-of-bounds memory.',
          remediation: 'Patch OpenSSL to a version that includes the Heartbleed fix.',
          cves: ['CVE-2014-0160'], kev: true, epss: 0.94, id: 'f1',
        },
        {
          host: '10.0.0.1', port: 22, severity: 'HIGH',
          title: 'Weak SSH key exchange algorithms enabled',
          detail: 'diffie-hellman-group1-sha1 is offered by the SSH server.',
          remediation: 'Disable weak KEX algorithms in sshd_config.',
          cves: [], kev: false, epss: 0.12, id: 'f2',
        },
      ],
    },
    {
      host: '10.0.0.2',
      dir: '10.0.0.2_20260826T091405Z',
      up: true,
      findings: [
        {
          host: '10.0.0.2', port: 80, severity: 'MEDIUM',
          title: 'Directory listing enabled',
          detail: 'The web server returns a directory index for /uploads/.',
          remediation: 'Disable autoindex on the web server.',
          cves: [], kev: false, epss: null, id: 'f3',
        },
        {
          host: '10.0.0.2', port: 8080, severity: 'LOW',
          title: 'Server banner discloses software version',
          detail: 'The HTTP response includes a Server header with a version string.',
          remediation: 'Suppress or generalise the Server header.',
          cves: [], kev: false, epss: null, id: 'f4',
        },
        {
          host: '10.0.0.2', port: 443, severity: 'INFO',
          title: 'TLS 1.2 supported alongside TLS 1.3',
          detail: 'Both protocol versions are negotiable.',
          remediation: null,
          cves: [], kev: false, epss: null, id: 'f5',
        },
      ],
    },
    {
      host: '10.0.0.3',
      dir: '10.0.0.3_20260826T091410Z',
      up: false,
      findings: [],
    },
  ],
  findings: [
    {
      host: '10.0.0.1', port: 443, severity: 'CRITICAL',
      title: 'OpenSSL Heartbleed exposure',
      detail: 'The TLS service responds to a malformed heartbeat request with out-of-bounds memory.',
      remediation: 'Patch OpenSSL to a version that includes the Heartbleed fix.',
      cves: ['CVE-2014-0160'], kev: true, epss: 0.94, id: 'f1',
    },
    {
      host: '10.0.0.1', port: 22, severity: 'HIGH',
      title: 'Weak SSH key exchange algorithms enabled',
      detail: 'diffie-hellman-group1-sha1 is offered by the SSH server.',
      remediation: 'Disable weak KEX algorithms in sshd_config.',
      cves: [], kev: false, epss: 0.12, id: 'f2',
    },
    {
      host: '10.0.0.2', port: 80, severity: 'MEDIUM',
      title: 'Directory listing enabled',
      detail: 'The web server returns a directory index for /uploads/.',
      remediation: 'Disable autoindex on the web server.',
      cves: [], kev: false, epss: null, id: 'f3',
    },
    {
      host: '10.0.0.2', port: 8080, severity: 'LOW',
      title: 'Server banner discloses software version',
      detail: 'The HTTP response includes a Server header with a version string.',
      remediation: 'Suppress or generalise the Server header.',
      cves: [], kev: false, epss: null, id: 'f4',
    },
    {
      host: '10.0.0.2', port: 443, severity: 'INFO',
      title: 'TLS 1.2 supported alongside TLS 1.3',
      detail: 'Both protocol versions are negotiable.',
      remediation: null,
      cves: [], kev: false, epss: null, id: 'f5',
    },
  ],
};

const BRAND = {
  title: 'Q3 External Perimeter Review',
  companyName: 'Acme Manufacturing GmbH',
  preparedBy: 'J. Rivera, Security Consulting LLC',
  contact: 'security@example.test',
  logoDataUri: null,
};

// ── Step 1: the GREEN legs of the invariant, first ───────────────────────────────────────────

test('a legitimate CVE anchor and a mailto are NOT violations', () => {
  const html = '<a href="https://nvd.nist.gov/vuln/detail/CVE-2026-1" rel="noopener noreferrer">CVE-2026-1</a>' +
               '<a href="mailto:security@example.test">contact</a><a href="#findings">jump</a>';
  assert.deepEqual(egressViolations(html), [],
    'the rule must not be satisfiable by forbidding everything');
});

// ── Step 3: the EIGHT planted classes, each RED alone ───────────────────────────────────────

test('every planted egress class is a violation on its own', () => {
  const planted = {
    'remote img':      '<img src="https://tracker.example.test/p.gif">',
    'stylesheet link': '<link rel="stylesheet" href="https://cdn.example.test/a.css">',
    'css url()':       '<style>body{background:url(https://cdn.example.test/b.png)}</style>',
    'script element':  '<script>fetch("https://x.example.test")</script>',
    'svg image href':  '<svg><image href="https://tracker.example.test/p.png"/></svg>',
    'on* handler':     '<img src="data:image/png;base64,iVBORw0KGgo=" onerror="fetch(\'https://x.example.test\')">',
    'javascript: anchor': '<a href="javascript:fetch(\'https://x.example.test\')">click</a>',
    'meta refresh':    '<meta http-equiv="refresh" content="0;url=https://x.example.test">',
  };
  for (const [name, frag] of Object.entries(planted)) {
    const v = egressViolations(`<html><body>${frag}</body></html>`);
    assert.ok(v.length > 0, `planted class went undetected: ${name}`);
  }
});

// ── Step 4b: the twelve EVASION classes (the predicate's fourth quadrant) ───────────────────

test('every evasion class is a violation on its own', () => {
  const evasions = {
    'protocol-relative': '<img src="//tracker.example.test/p.gif">',
    'unquoted src':      '<img src=https://tracker.example.test/p.gif>',
    'entity-encoded js': '<a href="java&#115;cript:fetch(1)">c</a>',
    'colon entity':      '<a href="javascript&colon;fetch(1)">c</a>',
    'tab in scheme':     '<a href="java\tscript:fetch(1)">c</a>',
    'srcdoc document':   '<iframe srcdoc="&lt;script&gt;x&lt;/script&gt;"></iframe>',
    'css @import':       '<style>@import "//cdn.example.test/a.css";</style>',
    'srcset':            '<img srcset="https://tracker.example.test/2x.png 2x">',
    'base href':         '<base href="https://tracker.example.test/">',
    'form action':       '<form action="https://tracker.example.test/x"></form>',
    'object data':       '<object data="https://tracker.example.test/x"></object>',
    'inline style url':  '<div style="background:url(https://tracker.example.test/b.png)"></div>',
    'space after javascript:': '<a href="javascript: alert(1)">c</a>',
    'entity space':            '<a href="javascript:&#32;fetch(1)">c</a>',
    'mixed case and space':    '<a href="JavaScript: alert(1)">c</a>',
    'vbscript with space':     '<a href="vbscript: msgbox">c</a>',
    'data:text/html document': '<a href="data:text/html,<b>x</b>">c</a>',
    // ── two more, found in this implementer's own adversarial pass (not in the brief's list):
    // xlink:href is the pre-HTML5 SVG namespaced attribute, still emitted by some authoring
    // tools and still executable/loadable in every real renderer; a check keyed on the bare
    // attribute name "href" would miss it.
    'svg xlink:href':          '<svg><image xlink:href="https://tracker.example.test/p.png"/></svg>',
    // <a ping> fires a background beacon POST on click, independent of the navigation the
    // href performs — a hidden second egress channel on an otherwise-honest hyperlink.
    'anchor ping beacon':      '<a href="#findings" ping="https://tracker.example.test/beacon">jump</a>',
  };
  for (const [name, frag] of Object.entries(evasions)) {
    assert.ok(egressViolations(`<html><body>${frag}</body></html>`).length > 0,
      `evasion went undetected: ${name}`);
  }
});

test('honest constructs stay GREEN — the rule must not forbid everything', () => {
  const honest = [
    '<a href="https://nvd.nist.gov/vuln/detail/CVE-2026-1" rel="noopener noreferrer">CVE-2026-1</a>',
    '<a href="mailto:security@example.test">contact</a>',
    '<a href="#findings">jump</a>',
    '<img src="data:image/png;base64,iVBORw0KGgo=" alt="logo">',
    '<div style="color:#333;border:1px solid #ccc"></div>',
    '<style>.l{background:url(data:image/png;base64,iVBORw0KGgo=)}</style>',
    '<style>.x::after{content:"a:b"}</style>',
    '<meta charset="utf-8">',
    '<p>See https://nvd.nist.gov for detail.</p>',
    '<time datetime="2026-09-03T11:02:00Z">Sep 3</time>',
    '<rect data-severity="HIGH" data-count="3" fill="#c00"></rect>',
    "<a href='https://x.example.test' title='x'>c</a>",
    '<img src="data:image/png;base64,iVBORw0KGgo=" alt="Note: the logo">',
    '<td title="SSL: weak cipher suite">SSL: weak cipher suite</td>',
    '<img src="data:image/jpeg;base64,/9j/4AAQ" alt="logo">',
    '<td title="Ratio 3:1">3:1</td>',
    '<td title="TLS 1.0: deprecated">TLS 1.0</td>',
  ];
  for (const frag of honest) {
    assert.deepEqual(egressViolations(`<html><body>${frag}</body></html>`), [],
      `an honest construct was called a violation: ${frag}`);
  }
});

// ── Step 6: cover-vocabulary and render tests ────────────────────────────────────────────────

test('the cover carries both dates, coverage, and the ordering rule for TOP RISKS', () => {
  const html = renderExecutiveReport(MODEL, BRAND, { renderedAt: new Date('2026-09-03T11:02:00Z') });
  assert.match(html, /Scan of \d+ hosts started/);
  assert.match(html, /Report rendered/);
  assert.match(html, /hosts requested/);
  assert.match(html, /ordered by known-exploited first, then EPSS probability, then severity/);
});

// TEST-QUALITY FIX 1: no test previously asserted the KEV/EPSS *loaded* sentence — only the
// loaded:false branch was pinned. A mutant dropping the snapshot date, or always printing
// "unknown", would pass the whole suite for the one sentence `aggregateStoreLoad` and the
// `dataAsOf` plumbing exist to produce.
test('a loaded KEV/EPSS feed states its OWN snapshot date, not a placeholder', () => {
  const html = renderExecutiveReport(MODEL, BRAND, {});
  assert.match(html,
    /Known-exploited status evaluated against the CISA KEV snapshot dated 2026-08-20\./,
    'the KEV loaded sentence must carry the real snapshot date from the model');
  assert.match(html,
    /Exploitation probability from the FIRST EPSS snapshot dated 2026-08-20\./,
    'the EPSS loaded sentence must carry the real snapshot date from the model');
  assert.ok(!html.includes('snapshot dated unknown'),
    'a real snapshot date must never be replaced by the "unknown" fallback');
});

test('the COVER never uses the forbidden vocabulary', () => {
  const html = renderExecutiveReport(MODEL, BRAND, {});
  const cover = html.match(/<section id="cover"[\s\S]*?<\/section>/)?.[0];
  assert.ok(cover, 'the renderer must emit <section id="cover"> for this assertion to bind');
  for (const word of [/\bPDF\b/i, /\bassessment\b/i, /\baudit\b/i, /\bcertification\b/i,
                      /\battestation\b/i, /\bcompliance\b/i, /\bclean\b/i, /\bsecure\b/i,
                      /\bpassed\b/i, /\bverified\b/i, /\bair-?gapped\b/i, /zero.?exfiltration/i]) {
    assert.ok(!word.test(cover), `forbidden vocabulary reached the cover: ${word}`);
  }
  assert.match(html, /Generated by NSAuditor AI (ce|pro|enterprise) \d+\.\d+\.\d+/,
    'the footer is the ONLY product sentence the report carries');
});

// ── Footer version selection — fourth quadrant first. The CE-only case (no eeVersion on the
// record) is the one that already worked under the FIRST landed version of this file — a tier
// check that happened to coincide with the record's own fields on every fixture this file ever
// exercised (MODEL.eeVersion was null throughout the whole test file) — so it is the case most
// likely to rot silently if the append logic below it breaks. Written before the EE-present
// case for that reason, not because it is the more interesting branch.

test('the footer names the CE version even when the record carries none from EE', () => {
  const html = renderExecutiveReport({ ...MODEL, eeVersion: null }, BRAND, {});
  assert.match(html, /Generated by NSAuditor AI pro 0\.2\.50<\/footer>/,
    'the CE version alone must appear, with no dangling EE suffix');
});

test('the footer APPENDS the EE version when the record carries one — it never replaces CE', () => {
  const html = renderExecutiveReport({ ...MODEL, eeVersion: '0.43.0' }, BRAND, {});
  assert.match(html, /Generated by NSAuditor AI pro 0\.2\.50 \+ EE 0\.43\.0<\/footer>/,
    'both the CE version (which rendered the document) and the EE version (whose enrichment '
    + 'shaped the findings) must appear — the record is the source for both, never the tier');
});

test('a company name containing markup renders literally in the finished report', () => {
  const html = renderExecutiveReport(MODEL, { ...BRAND, companyName: '<img src=x onerror=alert(1)>' }, {});
  assert.ok(html.includes('&lt;img src=x onerror=alert(1)&gt;'));
  assert.deepEqual(egressViolations(html), [], 'operator input defeated the invariant');
});

test('zero findings is a RENDER, and never says clean/secure/passed', () => {
  const model = { ...MODEL, findings: [] };
  const html = renderExecutiveReport(model, BRAND, {});
  assert.match(html, /No findings were recorded for the \d+ hosts scanned in this run\./);
});

test('an unloaded KEV feed says so rather than showing a silent zero', () => {
  // Genuinely nothing evaluated: kev.loaded is false AND no finding on the page carries a real
  // KEV result — the flat denial is TRUE here, unlike the CC-1 fixtures below.
  const model = {
    ...MODEL,
    kev: { loaded: false, snapshot: null },
    findings: MODEL.findings.map((f) => ({ ...f, kev: false })),
  };
  const html = renderExecutiveReport(model, BRAND, {});
  assert.match(html, /Known-exploited status NOT evaluated — no CISA KEV feed was loaded for this scan\./);
});

// ── CC-1: the cover's KEV/EPSS sentence must never deny a check whose results are on the page ──

test('CC-1: a real "Yes" finding survives an unfinalized (kevLoaded:false) run — the cover no longer flatly denies it', () => {
  // Reachable shape: an interrupted run reported with --allow-partial. Finalize never ran, so
  // kevLoaded stands at writeRunStart's pessimistic `false` default, while findings still carry
  // real KEV marks from before the interruption (MODEL.findings already has f1.kev === true).
  const model = { ...MODEL, kev: { loaded: false, snapshot: null } };
  const html = renderExecutiveReport(model, BRAND, {});
  assert.ok(!/Known-exploited status NOT evaluated/.test(html),
    'the cover flatly denied KEV evaluation while a finding on the same page is marked "Yes"');
  assert.match(html, /evaluated for some but not all hosts/,
    'the cover must state the partial truth instead of a flat denial');
  // The per-finding "Yes" must still be present and must not have been reconciled by SUPPRESSING
  // the true positive — the safe direction is never to deny a check whose results are on the page.
  const topRisksSection = html.match(/<section id="top-risks"[\s\S]*?<\/section>/)?.[0];
  assert.match(topRisksSection, /<td>Yes<\/td>/, 'the real KEV "Yes" must still render');
});

test('CC-1: the cover and the per-finding column can never both appear on the page in direct contradiction', () => {
  const model = { ...MODEL, kev: { loaded: false, snapshot: null } };
  const html = renderExecutiveReport(model, BRAND, {});
  const cover = html.match(/<section id="cover"[\s\S]*?<\/section>/)?.[0];
  const deniesEvaluation = /Known-exploited status NOT evaluated/.test(cover);
  const hasAYes = /<td>Yes<\/td>/.test(html);
  assert.ok(!(deniesEvaluation && hasAYes),
    'the document contained both an outright KEV denial and a finding marked Yes');
});

test('CC-1: with no KEV signal anywhere, an unfinalized run still gets the flat, honest denial', () => {
  const model = {
    ...MODEL,
    kev: { loaded: false, snapshot: null },
    findings: MODEL.findings.map((f) => ({ ...f, kev: false })),
  };
  const html = renderExecutiveReport(model, BRAND, {});
  assert.match(html, /Known-exploited status NOT evaluated — no CISA KEV feed was loaded for this scan\./,
    'a genuinely-nothing-evaluated run must still say so plainly — the fix must not overclaim either');
});

test('--allow-partial moves the disclosure to the cover; it never removes it', () => {
  const model = { ...MODEL, coverage: { ...MODEL.coverage, partial: true, requested: 14,
    written: 12, missing: ['10.0.0.7', '10.0.0.9'] } };
  const html = renderExecutiveReport(model, BRAND, {});
  assert.match(html, /2 of 14 requested hosts were not scanned: 10\.0\.0\.7, 10\.0\.0\.9\./);
});

// CC-3: reproduced exactly as the review found it — 5 requested / 2 written / 2 reachable. The
// three hosts that were never even WRITTEN must not ALSO be reported as an affirmative
// "not reachable" (a probe that ran and failed) — those are two incompatible statuses for the
// same three hosts on the same page.
test('CC-3: "N not reachable" counts only hosts that were WRITTEN, never merely REQUESTED', () => {
  const dirs = ['10.0.0.1_ts1', '10.0.0.2_ts2'];
  const model = {
    ...MODEL,
    coverage: { requested: 5, written: 2, reachable: 2,
      missing: ['10.0.0.4', '10.0.0.5', '10.0.0.6'], partial: true, incomplete: false },
    hosts: [
      { host: '10.0.0.1', dir: dirs[0], up: true, findings: [] },
      { host: '10.0.0.2', dir: dirs[1], up: true, findings: [] },
    ],
    findings: [],
    plugins: { ran: 0, skipped: 0, errored: 0, timedOut: 0, byHost: [
      { host: '10.0.0.1', dir: dirs[0], status: [] },
      { host: '10.0.0.2', dir: dirs[1], status: [] },
    ] },
  };
  const html = renderExecutiveReport(model, BRAND, {});
  assert.match(html, /5 hosts requested · 2 reachable · 0 not reachable\./,
    'a host that was never written cannot be reported as an affirmative "not reachable" result');
  assert.match(html, /3 of 5 requested hosts were not scanned: 10\.0\.0\.4, 10\.0\.0\.5, 10\.0\.0\.6\./,
    'the genuine gap is still disclosed — just not double-counted as "not reachable" too');
});

test('--allow-partial over an INCOMPLETE run renders its own caveat, not the partial-hosts one', () => {
  const model = { ...MODEL, coverage: { ...MODEL.coverage, incomplete: true, partial: false,
    missing: [] } };
  const html = renderExecutiveReport(model, BRAND, {});
  assert.match(html, /This run did not record completion; it may be missing results the scan had not yet written\./);
});

test('brand.contact renders as TEXT, never as an href', () => {
  const html = renderExecutiveReport(MODEL, { ...BRAND, contact: 'javascript:fetch(1)' }, {});
  assert.deepEqual(egressViolations(html), [],
    'brand.contact reached an href and became an execution vector');
  assert.ok(html.includes('javascript:fetch(1)'), 'the contact must still be SHOWN, as text');
});

test('the plain default render (no malicious input at all) carries zero egress violations', () => {
  // The other egressViolations([]) checks below all exercise a HOSTILE override (markup in
  // companyName, javascript: in contact). This is the ordinary path — a real CVE citation, a
  // real brand block, real coverage/plugin prose — and it must be just as clean; a renderer
  // that only passes under adversarial fixtures because they happen to short-circuit earlier
  // rendering logic would be a false clean of its own.
  const html = renderExecutiveReport(MODEL, BRAND, { renderedAt: new Date('2026-09-03T11:02:00Z') });
  assert.deepEqual(egressViolations(html), []);
  assert.match(html, /href="https:\/\/nvd\.nist\.gov\/vuln\/detail\/CVE-2014-0160"/,
    'a well-formed CVE must still become a real citation link');
});

test('the severity chart agrees with its own table', () => {
  const html = renderExecutiveReport(MODEL, BRAND, {});
  const rects = [...html.matchAll(/<rect[^>]*data-severity="([A-Z]+)"[^>]*data-count="(\d+)"/g)]
    .map(([, sev, n]) => [sev, Number(n)]);
  const rows  = [...html.matchAll(/<tr[^>]*data-row-severity="([A-Z]+)"/g)].map((m) => m[1]);
  for (const [sev, n] of rects) {
    assert.equal(rows.filter((r) => r === sev).length, n,
      `chart and table disagree for ${sev} — both must derive from the same model`);
  }
});

// CC-2: colliding host NAMES (`--host 10.0.0.7,10.0.0.7`, a repeated --host-file line, an
// overlapping range — utils/host_iterator.mjs de-duplicates none of these) must not double a
// finding across two same-named host sections, and must not let a Map's last-write-wins silently
// drop one directory's own plugin-status table. Deliberately uses DISTINCT host names nowhere —
// this is the exact fixture the existing 'severity chart agrees with its own table' test above
// cannot catch, because every one of its fixtures uses distinct host names.
test('CC-2: colliding host names do not double findings or delete a plugin-status table', () => {
  const dirA = 'dup.example.test_20260826T091400Z';
  const dirB = 'dup.example.test_20260826T091405Z';
  const findingA = { host: 'dup.example.test', port: 22, severity: 'HIGH',
    title: 'First directory finding', detail: null, remediation: null,
    cves: [], kev: false, epss: null, id: 'dupA1' };
  const findingB = { host: 'dup.example.test', port: 80, severity: 'MEDIUM',
    title: 'Second directory finding', detail: null, remediation: null,
    cves: [], kev: false, epss: null, id: 'dupB1' };
  const collidingModel = {
    ...MODEL,
    coverage: { requested: 2, written: 2, reachable: 2, missing: [], partial: false, incomplete: false },
    plugins: {
      ran: 2, skipped: 0, errored: 0, timedOut: 0,
      byHost: [
        { host: 'dup.example.test', dir: dirA,
          status: [{ id: '900', name: 'Plugin One', status: 'ran', reason: null }] },
        { host: 'dup.example.test', dir: dirB,
          status: [{ id: '901', name: 'Plugin Two', status: 'ran', reason: null }] },
      ],
    },
    hosts: [
      { host: 'dup.example.test', dir: dirA, up: true, findings: [findingA] },
      { host: 'dup.example.test', dir: dirB, up: true, findings: [findingB] },
    ],
    findings: [findingA, findingB],
  };
  const html = renderExecutiveReport(collidingModel, BRAND, {});
  const chartTotal = [...html.matchAll(/<rect[^>]*data-count="(\d+)"/g)]
    .reduce((sum, [, n]) => sum + Number(n), 0);
  assert.equal(chartTotal, 2, 'the chart must count each finding exactly once');
  // NOT a non-greedy `[\s\S]*?<\/section>` — the appendix section NESTS a `<section class="host">`
  // per host, so a non-greedy match stops at the FIRST nested closing tag and silently truncates
  // to just the first host, which is exactly the kind of false clean this test exists to avoid.
  // The appendix is the last section before the footer, so slicing to end of string is exact.
  const appendixStart = html.indexOf('<section id="appendix">');
  assert.ok(appendixStart !== -1, 'the rendered document has no appendix section');
  const appendix = html.slice(appendixStart);
  const appendixRows = [...appendix.matchAll(/<tr data-row-severity="[A-Z]+">/g)].length;
  assert.equal(appendixRows, 2,
    'the appendix must not double a finding across two same-named host sections');
  assert.ok(appendix.includes('Plugin One'),
    'the FIRST directory\'s plugin-status table must survive a same-named sibling');
  assert.ok(appendix.includes('Plugin Two'),
    'the SECOND directory\'s plugin-status table must also render, not be Map-overwritten');
  const hostSections = [...appendix.matchAll(/<section class="host">/g)];
  assert.equal(hostSections.length, 2, 'both directories must render their own section');
});

// ── Adversarial pass: what the brief's planted-violation list does not name ────────────────
//
// The model's own data — finding titles, host names, plugin names, remediation text — reaches
// this page, and none of it is trustworthy just because report_inputs.mjs is expected to
// constrain its shape. These prove the renderer, not just the predicate, holds the invariant
// under hostile model data, and that a severity value outside the five-member vocabulary is
// never silently dropped from the visual summary.

test('malicious finding/host/plugin data cannot defeat the invariant, and renders literally', () => {
  const maliciousHost = '10.0.0.1"><script>alert(1)</script>';
  const model = {
    ...MODEL,
    hosts: [{
      host: maliciousHost,
      dir: '10.0.0.1_ts"><script>alert(2)</script>',
      up: true,
      findings: [],
    }],
    findings: [{
      host: maliciousHost,
      port: 443,
      severity: 'CRITICAL"><script>alert(3)</script>',
      title: '<img src=x onerror=alert(4)>',
      detail: '"><svg onload=alert(5)>',
      remediation: 'javascript:alert(6)',
      cves: ['CVE-2026-9999"><script>alert(7)</script>'],
      kev: true,
      epss: 0.5,
      id: 'malicious1',
    }],
    plugins: {
      ran: 1, skipped: 0, errored: 0, timedOut: 0,
      byHost: [{
        host: maliciousHost,
        // Must match hosts[0].dir above — the renderer keys the plugin-status lookup by dir.
        dir: '10.0.0.1_ts"><script>alert(2)</script>',
        status: [{ id: '999', name: '<script>alert(8)</script>', status: 'error', reason: '"><script>alert(9)</script>' }],
      }],
    },
  };
  const html = renderExecutiveReport(model, BRAND, {});
  assert.deepEqual(egressViolations(html), [], 'malicious model data defeated the no-egress invariant');
  assert.ok(!/<script[\s>]/i.test(html), 'a literal <script> tag reached the rendered output');
  assert.ok(html.includes('&lt;script&gt;alert(1)&lt;/script&gt;'), 'the malicious host must render literally escaped');
  assert.ok(html.includes('&lt;img src=x onerror=alert(4)&gt;'), 'the malicious title must render literally escaped');
  assert.ok(html.includes('&lt;script&gt;alert(8)&lt;/script&gt;'), 'the malicious plugin name must render literally escaped');
  // the malformed "CVE" must never become a link — it fails the strict CVE shape check
  assert.ok(!html.includes('href="https://nvd.nist.gov/vuln/detail/CVE-2026-9999'),
    'a CVE-shaped-but-hostile string became a live link');
});

test('an out-of-vocabulary severity is normalised into a visible OTHER bucket, never silently dropped', () => {
  const model = { ...MODEL, findings: [...MODEL.findings, {
    host: '10.0.0.1', port: 1, severity: 'WEIRD', title: 'an oddity', detail: null,
    remediation: null, cves: [], kev: false, epss: null, id: 'weird1',
  }] };
  const html = renderExecutiveReport(model, BRAND, {});
  const rects = [...html.matchAll(/<rect[^>]*data-severity="([A-Z]+)"[^>]*data-count="(\d+)"/g)]
    .map(([, , n]) => Number(n));
  const totalCharted = rects.reduce((sum, n) => sum + n, 0);
  assert.equal(totalCharted, model.findings.length,
    'a finding vanished from the chart because its severity was outside the fixed vocabulary');
});
