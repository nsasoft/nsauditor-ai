// scan_host AND ITS MARKDOWN SAY WHAT THEY DO NOT LOOK AT (1.2.0 build 3 — the Gate 3-A preparation's P8 finding, the
// operator's ruling "fix it now").
//
// MEASURED on build 2's bytes: `scan_host` runs the plugins and the concluder only — never Enterprise's enrichment (the
// CVE mapper, the analysis agents, exploit intelligence), which is CLI-only. Rendering the router's conclusion through
// `buildMarkdownReport` gave "Security findings: 0" and "_No security findings._" over a host whose CLI run carries 16
// CVEs and 5 analysis-agent findings, while the tool's description promised "service detection, OS fingerprinting, and
// security findings". A published instruction that cannot succeed: a Desktop reply that relays it calls the router clean.
// The renderer's findings come from the service-check FLAGS alone (anonymous login, zone transfer, SNMP community, weak
// protocols / ciphers / algorithms, dangerous HTTP methods); nothing on the scan path fills a service's `cves`.
//
// The CLI's `--output-format md` report uses the same renderer, so the wording is true on both paths.
//
// FOURTH QUADRANT FIRST: what scan_host DOES do stays said, and a real service-check finding still renders.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { TOOLS } from '../mcp_server.mjs';
import { buildMarkdownReport } from '../utils/report_md.mjs';

const scanHost = () => {
  const t = TOOLS.find((x) => x?.name === 'scan_host');
  assert.ok(t, 'scan_host is registered');
  return t.description;
};
const services = { result: { services: [
  { port: 53, protocol: 'udp', service: 'dns', program: 'dnsmasq', version: '2.78', status: 'open' },
  { port: 21, protocol: 'tcp', service: 'ftp', program: 'bftpd', version: '1.6.6', status: 'open' },
] } };
const flagged = { result: { services: [{ port: 21, protocol: 'tcp', service: 'ftp', anonymousLogin: true }] } };

// ── FOURTH QUADRANT ──────────────────────────────────────────────────────────────────────────────
test('(q) the description still says what scan_host DOES: service detection and OS fingerprinting', () => {
  assert.match(scanHost(), /service detection/i);
  assert.match(scanHost(), /OS fingerprinting/i);
});

test('(q) a real service-check finding still renders, with its count', () => {
  const md = buildMarkdownReport({ host: 'h', conclusion: flagged });
  assert.match(md, /\*\*Security findings:\*\* 1 \(/);
  assert.match(md, /Anonymous FTP|anonymous/i);
});

// ── THE DEFECT ───────────────────────────────────────────────────────────────────────────────────
test('the description no longer promises unqualified "security findings", and says it does NOT look CVEs up', () => {
  const d = scanHost();
  assert.doesNotMatch(d, /OS fingerprinting, and security findings\.?$/, 'the build-2 promise, verbatim, is gone');
  assert.match(d, /does NOT look up CVEs/);
  assert.match(d, /analysis agents/);
  assert.match(d, /NOT a statement that the host has no known vulnerabilities/);
  assert.match(d, /get_vulnerabilities/, 'it names the route that DOES look CVEs up');
  // Build-3 review: scan_host RAN 040 / 050 / 060 but the concluder never reached their adapters, so the description said
  // so and routed to probe_service. Since 1.2.1 lane 3 they are carried (and 006's methods too), so nothing is left to
  // route: the probe_service sentence is retired, and the carried-fields leg below pins each of them to behaviour.
  assert.match(d, /040/); assert.match(d, /060/); assert.match(d, /050/);
  assert.match(d, /MCP server checks/, 'the flags 070 DOES set are named as returned');
});

test('zero findings: the markdown says its SCOPE and that zero is not "no known vulnerabilities"', () => {
  const md = buildMarkdownReport({ host: 'h', conclusion: services });
  assert.doesNotMatch(md, /_No security findings\._/, 'the build-2 placeholder, which read as a clean verdict, is gone');
  // Nor may it say the service checks found NOTHING: 040 / 060 did find things on the router, and they are dropped.
  assert.doesNotMatch(md, /No findings from the service checks/);
  assert.match(md, /_None of the counted service checks found anything\./);
  assert.match(md, /not a statement that the host has no known vulnerabilities/);
  assert.match(md, /\*\*Scope:\*\* counts only these service-check findings/);
  assert.match(md, /does not look up CVEs/);
  assert.match(md, /TLS-certificate/); assert.match(md, /DNS-security/); assert.match(md, /MCP server checks/);
});

test('with findings too: the scope line is there, because the limit holds whatever the count', () => {
  const md = buildMarkdownReport({ host: 'h', conclusion: flagged });
  assert.match(md, /\*\*Scope:\*\* counts only these service-check findings/);
  assert.match(md, /does not look up CVEs/);
});

// ── SECOND REVIEW ROUND: what the conclusion does NOT carry, and the two checks that are OFF by default ────────────
// tests/concluder_reaches_every_adapter.test.mjs pins what the conclusion carries and drops; tests/fail_on_scope_honesty.test.mjs the gate.
// What the records CARRY is the part before "It does NOT look up CVEs". Since 1.2.1 (a4) nothing a scan_host plugin produces
// is left un-returned, so there is no "does NOT return" clause; the HTTP probe's methods are carried, and NOT TESTED is
// said for what it is.
const carriedPart = (d) => d.slice(0, d.search(/It does NOT look up/));

test('the description lists the HTTP probe\'s methods among what the records carry, and says not tested is not "none"', () => {
  const d = scanHost();
  assert.match(carriedPart(d), /\(006\b[^)]*dangerousMethods[^)]*methodsTested/, '006 is named with its two fields');
  assert.match(carriedPart(d), /not tested, never "none"/);
  assert.doesNotMatch(d, /does NOT return/, 'no plugin result is left un-returned');
  for (const re of [/014/, /1023/, /FTP_CHECK_ANON/, /DNS_CHECK_AXFR/, /off by default/, /self-signed/, /cpe is null/]) assert.match(d, re);
});

// 1.2.1 (s1): the counted list is DERIVED from the shared service-flag table's labels, so it names exactly what is
// graded; each opt-in check is named with its switch.
test('the Scope line\'s COUNTED list names what the table grades, each opt-in check with its switch', () => {
  const md = buildMarkdownReport({ host: 'h', conclusion: services });
  const counted = /counts only these service-check findings:([^.]*)\./.exec(md)?.[1];
  assert.ok(counted, 'the Scope line has its counted list');
  assert.match(counted, /dangerous HTTP methods/, 'counted since 1.2.1 (a4) — the conclusion carries them');
  assert.match(counted, /Allow header/, 'and only where an Allow header was read');
  for (const sw of [/FTP_CHECK_ANON/, /DNS_CHECK_AXFR/, /SMB_NULL_SESSION/]) assert.match(counted, sw);
  for (const re of [/self-signed/, /SMB null session/, /MCP server checks/, /TLS-certificate audit/, /debug-endpoint audit/,
    /DNS-security audit/]) assert.match(counted, re, `counted since 1.2.1 (s1): ${re}`);
});

// 1.2.1 lane 3: the concluder REACHES 006 / 014 / 040 / 050 / 060 now, so the description names them among what the records
// carry — and this leg ties each name to a field the concluder actually lands, so the sentence cannot run ahead of the
// code (or fall behind it).
test('the description names what the conclusion carries (006, 014, 040, 050, 060), each tied to a field that lands', async () => {
  const d = scanHost();
  const carried = carriedPart(d);
  for (const [id, field] of [['006', 'dangerousMethods'], ['014', 'nullSessionAllowed'], ['040', 'certAudit'],
    ['050', 'tribeHealth'], ['060', 'dnsSecurity']]) {
    assert.match(carried, new RegExp(`\\(${id}\\b[^)]*${field}`), `${id} is named with ${field} among what the records carry`);
  }
  // 1023 is reached through the manager's registry and lands as ONE evidence line (Enterprise's
  // tests/zero_trust_adapter_reached.test.mjs measures it) — so the description says exactly that.
  assert.match(d, /\(1023\) reaches the conclusion only as one score line in its evidence/);
  const { default: concluder } = await import('../plugins/result_concluder.mjs');
  const c = await concluder.run([
    { id: '006', name: 'HTTP Probe', result: { up: true, program: 'nginx', methodsTested: true, allowedMethods: ['PUT'],
      dangerousMethods: ['PUT'], data: [{ probe_protocol: 'http', probe_port: 80, probe_info: 'Server: nginx' }] } },
    { id: '014', name: 'NetBIOS/SMB Scanner', result: { up: true, nullSessionAllowed: true, data: [{ probe_port: 445, probe_protocol: 'tcp', probe_info: 'SMB2' }] } },
    { id: '050', name: 'TRIBE', result: { up: true, overallSeverity: 'high', summary: { critical: 0, high: 1, medium: 0 }, serverInfo: {},
      findings: { debug: [{ severity: 'high', check: 'debug_endpoint', detail: 'x' }] } } },
    { id: '060', name: 'DNS', result: { up: true, overallSeverity: 'high', summary: { actionable: 1 },
      details: { spfRecord: null, dmarcRecord: null, dkimSelectors: [], dnssec: { hasDNSKEY: false } },
      findings: { spf: [{ severity: 'high', check: 'missing_spf', detail: 'x' }] } } },
  ]);
  const has = (field) => c.services.some((s) => s[field] != null) || c.evidence.some((e) => e[field] != null);
  for (const field of ['dangerousMethods', 'nullSessionAllowed', 'tribeHealth', 'dnsSecurity']) assert.ok(has(field), `the concluder lands ${field}`);
});
