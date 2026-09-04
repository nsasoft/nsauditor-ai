import test from 'node:test';
import assert from 'node:assert/strict';
import { renderJiraCsv, JIRA_COLUMNS, PRIORITY_BY_SEVERITY } from '../utils/jira_export.mjs';

// A literal, not a fixture builder — a shape change in Task 4's model must be visible here, not
// absorbed by a helper that quietly adapts to whatever report_inputs.mjs now emits. Copied from
// tests/executive_report.test.mjs's MODEL so both consumers of Task 4's model are tested against
// the same shape.
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
    byHost: [
      { host: '10.0.0.1', status: [
        { id: '003', name: 'Port Scanner', status: 'ran', reason: null },
        { id: '010', name: 'TLS Auditor', status: 'ran', reason: null },
      ] },
      { host: '10.0.0.2', status: [
        { id: '003', name: 'Port Scanner', status: 'ran', reason: null },
        { id: '020', name: 'HTTP Auditor', status: 'skipped', reason: 'no HTTP service detected' },
      ] },
      { host: '10.0.0.3', status: [
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

// ── Task brief's six pinned tests (Step 1) ──────────────────────────────────────────────────

test('the header row is pinned', () => {
  const csv = renderJiraCsv(MODEL);
  assert.equal(csv.split('\n')[0], 'Summary,Description,Priority,Labels,External ID');
});

test('the priority mapping is pinned — an unstated mapping is a claim nobody can check', () => {
  assert.deepEqual(PRIORITY_BY_SEVERITY, {
    CRITICAL: 'Highest', HIGH: 'High', MEDIUM: 'Medium', LOW: 'Low', INFO: 'Lowest' });
});

test('a row carries the SCAN timestamp and host, never a render date', () => {
  const csv = renderJiraCsv(MODEL);
  assert.ok(csv.includes(MODEL.startedAt), 'the scan date must appear');
  assert.ok(!csv.includes(new Date().getFullYear() + '-' + String(new Date().getMonth() + 1).padStart(2, '0') + '-' + String(new Date().getDate()).padStart(2, '0') + 'T'),
    'a render timestamp leaked into the CSV');
});

test('a field containing a comma, a quote or a newline is quoted and escaped', () => {
  const model = { ...MODEL, findings: [{ ...MODEL.findings[0],
    title: 'Weak TLS, "legacy" cipher', detail: 'line one\nline two' }] };
  const csv = renderJiraCsv(model);
  assert.ok(csv.includes('"Weak TLS, ""legacy"" cipher'), 'RFC4180 quoting is wrong');
  assert.equal(csv.split('\n')[0], JIRA_COLUMNS.join(','), 'the header must stay one line');
});

// The brief's own quoting fixture bundles a comma AND a quote in the same title, so a mutant
// that drops ONLY the comma from the trigger set is a NO-OP against it (the quote alone still
// forces quoting, producing byte-identical output for that fixture) — measured, not assumed:
// the mutant that removes `,` from `csvField`'s trigger regex passed all fourteen tests here
// until this one was added. This isolates the comma-only case.
test('a field containing ONLY a comma (no quote, no newline) is still quoted', () => {
  const model = { ...MODEL, findings: [{ ...MODEL.findings[0], title: 'Weak cipher, legacy' }] };
  const csv = renderJiraCsv(model);
  const rows = csv.split('\n').slice(1).filter(Boolean);
  assert.equal(rows.length, 1);
  assert.ok(rows[0].startsWith('"Weak cipher, legacy"'),
    'a comma-only field must be wrapped in quotes even without an accompanying quote character');
});

test('a KEV finding is labelled, and every CVE becomes its own label', () => {
  const model = { ...MODEL, findings: [{ ...MODEL.findings[0], kev: true,
    cves: ['CVE-2026-1', 'CVE-2026-2'] }] };
  const csv = renderJiraCsv(model);
  assert.match(csv, /nsauditor/); assert.match(csv, /\bkev\b/);
  assert.match(csv, /cve-2026-1/); assert.match(csv, /cve-2026-2/);
});

test('External ID is stable across two renders of the same model', () => {
  const a = renderJiraCsv(MODEL), b = renderJiraCsv(MODEL);
  assert.equal(a, b, 'External ID must be derived, not generated per render');
});

test('External ID is UNIQUE within one CSV — two findings sharing host+port+title must differ', () => {
  // hash(host+port+title) COLLIDES for two weak ciphers reported under one title on one port.
  // An importer keyed on External ID then updates one over the other and a finding is SILENTLY
  // DROPPED from the client's board — a false clean produced by the export, not by the scan.
  const model = { ...MODEL, findings: [
    { host: '10.0.0.7', port: 443, severity: 'HIGH', title: 'Weak cipher suite',
      detail: 'TLS_RSA_WITH_3DES_EDE_CBC_SHA', cves: [], kev: false, epss: null },
    { host: '10.0.0.7', port: 443, severity: 'HIGH', title: 'Weak cipher suite',
      detail: 'TLS_RSA_WITH_RC4_128_SHA', cves: [], kev: false, epss: null },
  ] };
  const rows = renderJiraCsv(model).split('\n').slice(1).filter(Boolean);
  assert.equal(rows.length, 2, 'both findings must produce a row');
  const ids = rows.map((r) => r.split(',').pop());
  assert.notEqual(ids[0], ids[1], 'two distinct findings share an External ID');
});

// ── Additional coverage: findings identical in ALL FOUR key fields (host+port+title+detail) ──
// The brief's own uniqueness test differs by `detail`, so the hash alone already disambiguates
// it — it never reaches the ordinal fallback. This is the case that DOES: two findings with
// nothing to hash apart, which must still get distinct, stable External IDs.

test('External ID disambiguates two findings identical in host+port+title+detail, by ordinal', () => {
  const dup = { host: '10.0.0.9', port: 8443, severity: 'MEDIUM', title: 'Self-signed certificate',
    detail: 'The presented certificate is not signed by a trusted CA.', cves: [], kev: false, epss: null };
  const model = { ...MODEL, findings: [dup, { ...dup }] };
  const csvA = renderJiraCsv(model);
  const rowsA = csvA.split('\n').slice(1).filter(Boolean);
  assert.equal(rowsA.length, 2);
  const idsA = rowsA.map((r) => r.split(',').pop());
  assert.notEqual(idsA[0], idsA[1], 'two truly-identical findings must still get distinct External IDs');

  // Stability: the SAME model, re-rendered, must assign the SAME ids in the SAME order — the
  // disambiguation must come from the findings array's own (model-determined) order, not from
  // anything that varies between renders (e.g. object identity, a Map's insertion order under
  // a different runtime, Math.random).
  const csvB = renderJiraCsv(model);
  assert.equal(csvA, csvB, 'ordinal-disambiguated ids must also be stable across renders');
});

// ── Adversarial pass: hostile / awkward MODEL DATA landing in cells a spreadsheet reads ──────

test('a field beginning with =, +, - or @ does not execute as a formula when opened in a spreadsheet', () => {
  const rows = [
    { ...MODEL.findings[0], title: '=cmd|\'/c calc\'!A1' },
    { ...MODEL.findings[0], title: '+1+1' },
    { ...MODEL.findings[0], title: '-1+1' },
    { ...MODEL.findings[0], title: '@SUM(1,1)' },
  ];
  for (const f of rows) {
    const csv = renderJiraCsv({ ...MODEL, findings: [f] });
    const summary = csv.split('\n')[1].split(',')[0];
    // RFC4180-quoted because the neutralising prefix itself introduces no comma/quote/newline
    // here, so the raw cell content is what a formula-injection defence must have altered.
    assert.ok(!/^[=+\-@]/.test(summary.replace(/^"/, '')),
      `formula-triggering leading character survived neutralisation: ${summary}`);
  }
});

test('a lone \\r inside a field does not corrupt the row structure', () => {
  const model = { ...MODEL, findings: [{ ...MODEL.findings[0], detail: 'before\rafter' }] };
  const csv = renderJiraCsv(model);
  const dataRows = csv.split('\n').slice(1).filter(Boolean);
  assert.equal(dataRows.length, 1, 'a lone CR must not be read as a row separator');
  assert.ok(csv.includes('before\rafter'), 'the CR-bearing content must still be present, unmangled');
});

test('a very long field is preserved in full, never silently truncated', () => {
  const long = 'A'.repeat(50000);
  const model = { ...MODEL, findings: [{ ...MODEL.findings[0], detail: long }] };
  const csv = renderJiraCsv(model);
  assert.ok(csv.includes(long), 'a long finding detail must not be truncated on the way to CSV');
});

test('null/undefined finding fields render without crashing or emitting the literal string "undefined"', () => {
  const model = { ...MODEL, findings: [
    { host: '10.0.0.5', port: null, severity: undefined, title: null, detail: undefined,
      remediation: undefined, cves: undefined, kev: undefined, epss: undefined },
  ] };
  let csv;
  assert.doesNotThrow(() => { csv = renderJiraCsv(model); });
  const row = csv.split('\n')[1];
  assert.ok(!/undefined/.test(row), `a null/undefined model field leaked as the literal word: ${row}`);
  assert.equal(row.split(',')[2], PRIORITY_BY_SEVERITY.MEDIUM,
    'an unrecognised/missing severity must fall back to a safe default Priority, not blank/undefined');
});

test('a non-ASCII field round-trips without corruption', () => {
  const model = { ...MODEL, findings: [{ ...MODEL.findings[0],
    title: 'Bâd cönfig — 日本語 — emoji 🔥', detail: 'ütf-8 detail: ñ, ç, 中文' }] };
  const csv = renderJiraCsv(model);
  assert.ok(csv.includes('Bâd cönfig — 日本語 — emoji 🔥'));
  assert.ok(csv.includes('ütf-8 detail: ñ, ç, 中文'));
});

test('an empty findings array renders just the header', () => {
  const model = { ...MODEL, findings: [] };
  const csv = renderJiraCsv(model);
  assert.equal(csv.split('\n').filter(Boolean).length, 1);
  assert.equal(csv.split('\n')[0], JIRA_COLUMNS.join(','));
});
