// tests/service_flag_table.test.mjs
// 1.2.1 lane 3, (s1) — ONE table grades every service-check flag, and every reader reads it.
//
// Six readers each kept their own list of the flags a service record can carry — the Markdown report, SARIF, the CSV,
// `--fail-on` (maxSeverityInConclusion), the scan-history fallback count and the `--watch` webhook filter — and the lists
// disagreed: the CSV printed any SNMP community, `--fail-on` did not read weak TLS or SNMP at all, and none of them read
// the MCP flags, a self-signed or expired certificate, an SMB null session, or the TLS-certificate, debug-endpoint and
// DNS-security audits (040 / 050 / 060) that the concluder carries since 1.2.1. A producer added a flag and no reader
// followed, five times. `utils/service_flags.mjs` is now the only place a flag is graded.
//
// FOURTH QUADRANT FIRST: a clean, fully-tested record is graded NOTHING by the table and by every reader.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import * as T from '../utils/service_flags.mjs';
import { buildMarkdownReport } from '../utils/report_md.mjs';
import { buildSarifLog, severityToLevel } from '../utils/sarif.mjs';
import { buildCsv } from '../utils/export_csv.mjs';
import { maxSeverityInConclusion } from '../cli.mjs';
import concluder, { ADAPTER_PAYLOAD_KEYS } from '../plugins/result_concluder.mjs';
import { IDENTITY_FIELDS } from '../utils/conclusion_utils.mjs';
import { _internals as mcpInternals, MCP_FLAG_SEVERITY } from '../plugins/mcp_scanner.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const PLUGINS = path.join(ROOT, 'plugins');
const RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
const PAST = '2001-01-01T00:00:00Z';
const FUTURE = '2099-01-01T00:00:00Z';
const rec = (fields) => ({ port: 443, protocol: 'tcp', service: 'https', program: 'nginx', version: '1.18.0', status: 'open', ...fields });
const graded = (fields) => T.flagFindings(rec(fields), { target: 'h:443/tcp' });
const conclusionOf = (services, evidence = []) => ({ id: '100000', name: 'Result Concluder', result: { services, evidence } });

// ── THE ORACLE — DECLARED, never computed from the table ─────────────────────────────────────────────────────────
// key → the record fields that make it fire → [severity, item] per finding → the CSV token it prints.
const FIRES = {
  anonymousLogin: [{ anonymousLogin: true }, [['Critical', null]], 'anonymous_login'],
  axfrAllowed: [{ axfrAllowed: true }, [['Critical', null]], 'axfr_allowed'],
  community: [{ community: 'public' }, [['High', 'public']], 'default_community:public'],
  weakAlgorithms: [{ weakAlgorithms: ['ssh-dss', { algorithm: 'diffie-hellman-group1-sha1' }] },
    [['Medium', 'ssh-dss'], ['Medium', 'diffie-hellman-group1-sha1']], 'weak_algorithms:ssh-dss;diffie-hellman-group1-sha1'],
  weakProtocols: [{ weakProtocols: ['TLSv1', 'TLSv1.1'] }, [['Medium', 'TLSv1'], ['Medium', 'TLSv1.1']], 'weak_protocols:TLSv1;TLSv1.1'],
  weakCiphers: [{ weakCiphers: ['RC4-SHA'] }, [['Medium', 'RC4-SHA']], 'weak_ciphers:RC4-SHA'],
  dangerousMethods: [{ methodsTested: true, allowedMethods: ['GET', 'PUT', 'DELETE'], dangerousMethods: ['PUT', 'DELETE'] },
    [['Medium', 'PUT'], ['Medium', 'DELETE']], 'dangerous_methods:PUT;DELETE'],
  certSelfSigned: [{ certSelfSigned: true }, [['Medium', null]], 'cert_self_signed'],
  certExpiry: [{ certExpiry: PAST }, [['High', null]], 'cert_expired'],
  nullSessionAllowed: [{ nullSessionAllowed: true, shares: ['C$'] }, [['High', null]], 'null_session'],
  mcpAnonymousAccess: [{ mcpAnonymousAccess: true }, [['Critical', null]], 'mcp_anonymous_access'],
  mcpAnonymousToolList: [{ mcpAnonymousToolList: ['exec'] }, [['Critical', null]], 'mcp_anonymous_tool_list'],
  mcpCleartextTransport: [{ mcpCleartextTransport: true }, [['High', null]], 'mcp_cleartext_transport'],
  mcpDeprecatedProtocol: [{ mcpDeprecatedProtocol: '2024-11-05' }, [['High', '2024-11-05']], 'mcp_deprecated_protocol:2024-11-05'],
  mcpInspectorExposed: [{ mcpInspectorExposed: true }, [['Medium', null]], 'mcp_inspector_exposed'],
  cves: [{ cves: ['CVE-2001-0001', { id: 'CVE-2001-0002', severity: 'critical' }] },
    [['High', 'CVE-2001-0001'], ['Critical', 'CVE-2001-0002']], 'cves:CVE-2001-0001;CVE-2001-0002'],
  certAudit: [{ certAudit: { severity: 'critical', issues: [{ severity: 'critical', check: 'cert_expired', detail: 'Certificate expired' },
    { severity: 'medium', check: 'cert_expiring_soon', detail: 'Expires in 20 days' }] } },
  [['Critical', 'cert_expired'], ['Medium', 'cert_expiring_soon']], 'tls_certificate_issues:cert_expired;cert_expiring_soon'],
  tribeHealth: [{ tribeHealth: { state: 'up', severity: 'critical', findings: [{ severity: 'critical', category: 'auth', check: 'no_auth', detail: 'No auth' }] } },
    [['Critical', 'auth/no_auth']], 'debug_endpoint_findings:auth/no_auth'],
  dnsSecurity: [{ dnsSecurity: { severity: 'high', findings: [{ severity: 'high', category: 'spf', check: 'missing_spf', detail: 'No SPF record' }] } },
    [['High', 'missing_spf']], 'dns_security_findings:missing_spf'],
};
// key → record fields that carry the key and are NOT a finding (each must grade nothing).
const QUIET = {
  anonymousLogin: [{ anonymousLogin: false }],
  axfrAllowed: [{ axfrAllowed: false }, { axfrAllowed: null }],
  community: [{ community: null }, { community: 'Public' }, { community: 'custom', communityCustom: true }],
  weakAlgorithms: [{ weakAlgorithms: [] }, { weakAlgorithms: null }],
  weakProtocols: [{ weakProtocols: [] }],
  weakCiphers: [{ weakCiphers: [] }],
  dangerousMethods: [{ methodsTested: true, allowedMethods: ['GET'], dangerousMethods: [] },
    { methodsTested: false, allowedMethods: null, dangerousMethods: null }],
  certSelfSigned: [{ certSelfSigned: false }],
  certExpiry: [{ certExpiry: FUTURE }, { certExpiry: 'not a date' }],
  nullSessionAllowed: [{ nullSessionAllowed: false }],
  mcpAnonymousAccess: [{ mcpAnonymousAccess: false }],
  mcpAnonymousToolList: [{ mcpAnonymousToolList: [] }],
  mcpCleartextTransport: [{ mcpCleartextTransport: false }],
  mcpDeprecatedProtocol: [{ mcpDeprecatedProtocol: '' }, { mcpDeprecatedProtocol: null }],
  mcpInspectorExposed: [{ mcpInspectorExposed: false }],
  cves: [{ cves: [] }],
  certAudit: [{ certAudit: { severity: null, issues: [] } }],
  tribeHealth: [{ tribeHealth: { state: 'down', severity: 'info', error: 'ECONNREFUSED', findings: [] } }],
  dnsSecurity: [{ dnsSecurity: { severity: 'pass', findings: [{ severity: 'pass', category: 'mx', check: 'mx_ok', detail: 'fine' }] } }],
};

// ── FOURTH QUADRANT ──────────────────────────────────────────────────────────────────────────────────────────────
test('(fourth quadrant, first) a clean, fully-tested record is graded NOTHING — by the table and by every reader', () => {
  const clean = rec({ weakAlgorithms: [], weakProtocols: [], weakCiphers: [], tls: true, certSelfSigned: false,
    methodsTested: true, allowedMethods: ['GET', 'HEAD'], dangerousMethods: [], anonymousLogin: false, axfrAllowed: false });
  assert.deepEqual(T.flagFindings(clean), []);
  const c = conclusionOf([clean]);
  assert.deepEqual(T.conclusionFindings(c, 'h'), []);
  assert.match(buildMarkdownReport({ host: 'h', conclusion: c }), /\*\*Security findings:\*\* 0/);
  const sarif = buildSarifLog({ host: 'h', conclusion: c });
  assert.equal(sarif.runs[0].results.length, 1, 'only the service-detected result');
  assert.equal(buildCsv({ host: 'h', conclusion: c }).trim().split('\n')[1].split(',').at(-1), '');
  assert.equal(maxSeverityInConclusion(c), RANK.info);
});

// ── THE TABLE ────────────────────────────────────────────────────────────────────────────────────────────────────
test('the table has a row for every key in the oracle and no other — a row without a declared grade cannot land', () => {
  assert.deepEqual([...T.FLAG_KEYS].sort(), Object.keys(FIRES).sort());
  assert.deepEqual(Object.keys(QUIET).sort(), Object.keys(FIRES).sort());
});

test('each key grades its declared severity, ONE finding per item', () => {
  for (const [key, [fields, expected]] of Object.entries(FIRES)) {
    const got = graded(fields);
    assert.deepEqual(got.map((f) => [f.key, f.severity, f.item]), expected.map(([s, i]) => [key, s, i]), key);
    for (const f of got) assert.ok(f.title && f.ruleId, `${key} carries a title and a rule id`);
  }
});

test('a field that is present but is not a finding grades nothing — false, empty, null, a custom community, a future date', () => {
  for (const [key, cases] of Object.entries(QUIET)) {
    for (const fields of cases) assert.deepEqual(graded(fields), [], `${key} ${JSON.stringify(fields)}`);
  }
});

test('only a DEFAULT community is a finding — the list is the SNMP plugin\'s own', async () => {
  const { DEFAULT_COMMUNITIES } = await import('../plugins/snmp_scanner.mjs');
  for (const c of DEFAULT_COMMUNITIES) assert.equal(graded({ community: c }).length, 1, c);
  assert.deepEqual(graded({ community: 'zq7-not-a-default' }), []);
});

test('the MCP grades are the scanner\'s own declaration, and every flag it SETS has one — read from its source', () => {
  const src = fs.readFileSync(path.join(PLUGINS, 'mcp_scanner.mjs'), 'utf8').replace(/\/\/.*$/gm, '');
  const set = [...src.matchAll(/\bflags\.(\w+)\s*=/g)].map((m) => m[1]);
  assert.ok(set.length >= 5, 'positive control: the flags are found');
  assert.deepEqual([...new Set(set)].sort(), Object.keys(MCP_FLAG_SEVERITY).sort());
  for (const [k, sev] of Object.entries(MCP_FLAG_SEVERITY)) assert.equal(FIRES[k][1][0][0], sev, `${k}: the oracle agrees with the declaration`);
});

test('a certificate is graded ONCE: 011\'s two flags only where no 040 audit landed on the record', () => {
  // (fourth quadrant) 011 alone: both of its certificate flags are graded.
  assert.deepEqual(graded({ certSelfSigned: true, certExpiry: PAST }).map((f) => f.key).sort(), ['certExpiry', 'certSelfSigned']);
  // 011 + 040 on one port: 040 is the certificate's authority, so the same certificate is not graded twice.
  const both = graded({ certSelfSigned: true, certExpiry: PAST, certAudit: { severity: 'critical', issues: [
    { severity: 'critical', check: 'cert_expired', detail: 'expired' }, { severity: 'high', check: 'self_signed', detail: 'self-signed' }] } });
  assert.deepEqual(both.map((f) => [f.key, f.item]), [['certAudit', 'cert_expired'], ['certAudit', 'self_signed']]);
});

test('a 040 roll-up is DERIVED from the issues it carries, never copied — its adapter computes it', async () => {
  const { default: p040 } = await import('../plugins/040_tls_cert_auditor.mjs');
  const cert = { expired: false, daysToExpiry: 90, selfSigned: true, hostnameValid: true, subject: 'CN=x', issuer: 'CN=x',
    names: [], validFrom: '', validTo: '', signatureAlgorithm: 'sha256', keyType: 'RSA', keyBits: 2048 };
  const out = p040.conclude({ result: { portResults: [{ port: 443, service: 'https', severity: 'critical', certificate: cert,
    negotiation: { protocol: 'TLSv1.3', cipher: 'X', forwardSecrecy: true }, chain: { depth: 0 }, authorized: false,
    issues: [{ severity: 'high', check: 'self_signed', detail: 'self-signed' }, { severity: 'info', check: 'not_tls13', detail: 'x' }] }] } });
  assert.deepEqual(out[0].certAudit.issues, [{ severity: 'high', check: 'self_signed', detail: 'self-signed' }]);
  assert.equal(out[0].certAudit.severity, 'high', 'the port\'s raw roll-up said critical; the audit carries high, the max of what it carries');
  const none = p040.conclude({ result: { portResults: [{ port: 443, service: 'https', severity: 'info', certificate: cert,
    negotiation: { protocol: 'TLSv1.3', cipher: 'X', forwardSecrecy: true }, chain: { depth: 0 }, authorized: true, issues: [] }] } });
  assert.equal(none[0].certAudit.severity, null, 'nothing actionable: no roll-up, not "info"');
});

// ── THE READERS — each one, against the table ───────────────────────────────────────────────────────────────────
test('every reader grades every key: --fail-on, the CSV token, the Markdown finding and the SARIF result', () => {
  for (const [key, [fields, expected, token]] of Object.entries(FIRES)) {
    const c = conclusionOf([rec(fields)]);
    const max = Math.max(...expected.map(([s]) => RANK[s.toLowerCase()]));
    assert.equal(maxSeverityInConclusion(c), max, `--fail-on ${key}`);
    assert.equal(buildCsv({ host: 'h', conclusion: c }).trim().split('\n')[1].split(',').at(-1).replace(/^"|"$/g, ''), token, `csv ${key}`);
    const md = buildMarkdownReport({ host: 'h', conclusion: c });
    assert.match(md, new RegExp(`\\*\\*Security findings:\\*\\* ${expected.length} `), `md count ${key}`);
    const sarif = buildSarifLog({ host: 'h', conclusion: c }).runs[0].results.slice(1);
    assert.deepEqual(sarif.map((r) => r.level), expected.map(([s]) => severityToLevel(s)), `sarif ${key}`);
  }
});

test('the Markdown finding set and the SARIF result set ARE the table\'s, for a record carrying every key at once', () => {
  const all = rec(Object.assign({}, ...Object.entries(FIRES).filter(([k]) => k !== 'certAudit').map(([, [f]]) => f)));
  const c = conclusionOf([all]);
  const table = T.conclusionFindings(c, 'h');
  assert.equal(table.length, Object.entries(FIRES).filter(([k]) => k !== 'certAudit').reduce((n, [, [, e]]) => n + e.length, 0));
  const md = buildMarkdownReport({ host: 'h', conclusion: c });
  const heads = [...md.matchAll(/^### \[(\w+)\] (.*)$/gm)].map((m) => `${m[1]} ${m[2].replace(/\\(.)/g, '$1')}`).sort();
  assert.deepEqual(heads, table.map((f) => `${f.severity} ${f.title}`).sort());
  const sarif = buildSarifLog({ host: 'h', conclusion: c }).runs[0].results.slice(1);
  assert.deepEqual(sarif.map((r) => `${r.ruleId} ${r.level}`).sort(), table.map((f) => `${f.ruleId} ${severityToLevel(f.severity)}`).sort());
});

test('the SARIF rule ids the GitHub alerts are keyed on do not move for the four flags SARIF already graded', () => {
  const ids = (fields) => graded(fields).map((f) => f.ruleId);
  assert.deepEqual(ids({ anonymousLogin: true }), ['ftp-anonymous-login']);
  assert.deepEqual(ids({ axfrAllowed: true }), ['dns-zone-transfer']);
  assert.deepEqual(ids({ weakAlgorithms: ['ssh-dss'] }), ['weak-algorithm-ssh-dss']);
  assert.deepEqual(ids({ methodsTested: true, dangerousMethods: ['PUT'] }), ['http-dangerous-method-put']);
  assert.deepEqual(ids({ cves: ['CVE-2001-0001'] }), ['CVE-2001-0001']);
});

// ── Q-B: a payload is graded WHERE IT LANDS ─────────────────────────────────────────────────────────────────────
const DNSSEC = { up: true, overallSeverity: 'high', summary: { actionable: 2 },
  details: { spfRecord: null, dmarcRecord: null, dkimSelectors: [], dnssec: { hasDNSKEY: false } },
  findings: { spf: [{ severity: 'high', check: 'missing_spf', detail: 'No SPF record' }],
    dmarc: [{ severity: 'medium', check: 'missing_dmarc', detail: 'No DMARC record' }] } };
const DNS_009 = { id: '009', name: 'dns_scanner', result: { up: true, program: 'BIND', version: '9.18',
  data: [{ probe_port: 53, probe_protocol: 'udp', probe_info: 'version.bind' }] } };

test('a domain\'s DNS posture grades the same with or without a 53/udp record — only the target differs', async () => {
  const wrap = async (results) => ({ result: await concluder.run(results) });
  const onRecord = await wrap([DNS_009, { id: '060', name: 'DNS Security Auditor', result: DNSSEC }]);
  const onEvidence = await wrap([{ id: '060', name: 'DNS Security Auditor', result: DNSSEC }]);
  assert.ok(onRecord.result.services.some((s) => s.dnsSecurity), 'positive control: attached to 53/udp');
  assert.ok(onEvidence.result.evidence.some((e) => e.dnsSecurity), 'positive control: landed in evidence');
  const shape = (c) => T.conclusionFindings(c, 'h').map((f) => `${f.key} ${f.item} ${f.severity} ${f.title}`).sort();
  assert.deepEqual(shape(onEvidence), shape(onRecord));
  assert.equal(shape(onRecord).length, 2);
  assert.equal(maxSeverityInConclusion(onEvidence), maxSeverityInConclusion(onRecord));
  assert.equal(maxSeverityInConclusion(onEvidence), RANK.high);
  assert.match(buildMarkdownReport({ host: 'h', conclusion: onEvidence }), /\*\*Security findings:\*\* 2 /);
  assert.equal(buildSarifLog({ host: 'h', conclusion: onEvidence }).runs[0].results.length, 2, 'both, located at the host');
  assert.match(buildCsv({ host: 'h', conclusion: onEvidence }), /dns_security_findings:missing_spf;missing_dmarc/);
});

test('the payload keys the readers grade on evidence are the CONCLUDER\'s, imported, never re-listed', () => {
  assert.deepEqual([...T.PAYLOAD_KEYS].sort(), [...ADAPTER_PAYLOAD_KEYS].sort());
  const src = fs.readFileSync(path.join(ROOT, 'utils/service_flags.mjs'), 'utf8');
  assert.match(src, /import \{[^}]*ADAPTER_PAYLOAD_KEYS[^}]*\} from '\.\.\/plugins\/result_concluder\.mjs'/);
  // The DEFINITION is what must derive from it — an import beside a re-listed literal passes the line above (a battery
  // mutant did exactly that), so the right-hand side is read: it names the concluder's set and carries no literal.
  const def = /export const PAYLOAD_KEYS = ([^;]*);/.exec(src)?.[1];
  assert.ok(def, 'the PAYLOAD_KEYS definition is found');
  assert.match(def, /ADAPTER_PAYLOAD_KEYS/);
  assert.doesNotMatch(def, /['"`]/, 'no key is spelled out in the definition');
});

// ── NO READER GRADES A FLAG ITSELF ───────────────────────────────────────────────────────────────────────────────
// Comments and string literals are blanked first (a Scope sentence NAMES the checks; that is not a read).
function code(src) {
  let out = ''; let i = 0;
  while (i < src.length) {
    const c = src[i]; const n = src[i + 1];
    if (c === '/' && n === '/') { while (i < src.length && src[i] !== '\n') { out += ' '; i++; } continue; }
    if (c === '/' && n === '*') { const e = src.indexOf('*/', i + 2); const end = e < 0 ? src.length : e + 2;
      out += src.slice(i, end).replace(/[^\n]/g, ' '); i = end; continue; }
    if (c === '"' || c === "'" || c === '`') {
      out += ' '; i++;
      while (i < src.length && src[i] !== c) { if (src[i] === '\\') { out += '  '; i += 2; continue; } out += src[i] === '\n' ? '\n' : ' '; i++; }
      out += ' '; i++; continue;
    }
    out += c; i++;
  }
  return out;
}
const READERS = ['utils/report_md.mjs', 'utils/sarif.mjs', 'utils/export_csv.mjs', 'cli.mjs'];

test('no reader reads a graded key itself — every grade comes from the table', () => {
  const offenders = [];
  for (const rel of READERS) {
    const src = code(fs.readFileSync(path.join(ROOT, rel), 'utf8'));
    for (const key of T.FLAG_KEYS) {
      for (const m of src.matchAll(new RegExp(`\\.${key}\\b`, 'g'))) offenders.push(`${rel}: .${key} at ${src.slice(0, m.index).split('\n').length}`);
    }
  }
  assert.deepEqual(offenders, []);
  // positive control: the census does see a read when one is there
  assert.equal([...code('const x = svc.anonymousLogin; // svc.axfrAllowed\nconst y = "svc.community";').matchAll(/\.(anonymousLogin|axfrAllowed|community)\b/g)].length, 1);
});

test('the history fallback count and the webhook filter are computed from the table', () => {
  const cli = code(fs.readFileSync(path.join(ROOT, 'cli.mjs'), 'utf8'));
  assert.match(cli, /serviceFindingsCount\s*=\s*conclusionFindings\(/);
  assert.match(cli, /conclusionFindings\(scanOut\.conclusion/);
});

// ── THE CENSUS — every key an adapter lands is graded or declared, and every graded key has an emitter ───────────
// Each adapter-bearing plugin is DRIVEN through the real concluder with a result that reaches its flag-bearing branch.
// The set of drivers is held equal to the set of plugins that carry an adapter, so a new adapter joins by failing here.
// LIMIT, stated: a key an adapter sets only on a branch no driver below reaches is invisible to the forward leg.
const mcpFlags = mcpInternals.buildFindings({ host: '203.0.113.7', port: 6274,
  detection: { authRequired: false, tools: ['exec'], scheme: 'http', protocolVersion: '2024-01-01' } });
const auditCert = { expired: true, daysToExpiry: -3, selfSigned: true, hostnameValid: false, subject: 'CN=x', issuer: 'CN=x',
  names: [], validFrom: '', validTo: '', signatureAlgorithm: 'sha256', keyType: 'RSA', keyBits: 2048 };
const DRIVERS = {
  '002': [{ up: true, program: 'OpenSSH', version: '7.2', algorithms: { kex: ['diffie-hellman-group1-sha1'] }, weakAlgorithms: ['diffie-hellman-group1-sha1'],
    data: [{ probe_protocol: 'tcp', probe_port: 22, probe_info: 'SSH-2.0-OpenSSH_7.2', response_banner: 'SSH-2.0-OpenSSH_7.2' }] }],
  '003': [{ up: true, data: [{ probe_protocol: 'tcp', probe_port: 22, status: 'open', probe_info: 'open' }] }],
  '004': [{ up: true, program: 'vsftpd', version: '3.0.3', anonymousLogin: true,
    data: [{ probe_protocol: 'tcp', probe_port: 21, probe_info: '220 vsFTPd', response_banner: '220 (vsFTPd 3.0.3)' }] }],
  '006': [{ up: true, program: 'nginx', version: '1.18.0', methodsTested: true, allowedMethods: ['GET', 'PUT'], dangerousMethods: ['PUT'],
    data: [{ probe_protocol: 'http', probe_port: 80, probe_info: 'Server: nginx' }] }],
  '007': [{ up: true, program: 'Linux', version: '5.10', community: 'public', communitiesTried: ['public'],
    data: [{ probe_protocol: 'udp', probe_port: 161, probe_info: 'SNMP response', response_banner: 'Linux' }] },
  { up: true, program: 'Linux', version: '5.10', community: null, communityCustom: true, communitiesTried: ['custom'],
    data: [{ probe_protocol: 'udp', probe_port: 161, probe_info: 'SNMP response', response_banner: 'Linux' }] }],
  '009': [{ up: true, program: 'BIND', version: '9.18', axfrAllowed: true, data: [{ probe_port: 53, probe_protocol: 'tcp', probe_info: 'AXFR allowed' }] }],
  '010': [{ up: true, apps: [{ name: 'WordPress', version: '6.0', categories: ['CMS'] }], data: [{ probe_port: 80, probe_protocol: 'tcp' }] }],
  '011': [{ up: true, data: [{ probe_port: 443, probe_info: 'TLS: TLSv1.3', tlsEvidence: { supportedVersions: ['TLSv1', 'TLSv1.3'],
    ciphers: { TLSv1: 'ECDHE-RSA-RC4-SHA' }, certSelfSigned: true, certExpiry: PAST } }] }],
  '012': [{ up: true, program: 'opensearch', version: '2.13.0', data: [{ probe_port: 9200, probe_protocol: 'tcp', probe_info: 'OpenSearch 2.13.0' }] }],
  '014': [{ up: true, nullSessionAllowed: true, shares: ['C$'], users: ['guest'], data: [{ probe_port: 445, probe_protocol: 'tcp', probe_info: 'SMB2' }] }],
  '024': [{ up: true, data: [{ probe_port: 2222, probe_protocol: 'tcp', status: 'open', service: 'ssh', response_banner: null }] }],
  '025': [{ up: true, program: 'PostgreSQL', version: '15', data: [{ probe_port: 5432, probe_protocol: 'tcp', probe_info: 'PostgreSQL' }] }],
  '040': [{ up: true, portResults: [{ port: 8443, service: 'https', severity: 'critical', certificate: auditCert,
    negotiation: { protocol: 'TLSv1.2', cipher: 'X', forwardSecrecy: false }, chain: { depth: 1 }, authorized: false,
    issues: [{ severity: 'critical', check: 'cert_expired', detail: 'expired' }, { severity: 'info', check: 'not_tls13', detail: 'x' }] }] }],
  '050': [{ up: true, overallSeverity: 'critical', summary: { critical: 1, high: 0, medium: 0 }, serverInfo: { name: 't' },
    findings: { auth: [{ severity: 'critical', check: 'no_auth', detail: 'No auth' }] } }, { up: false, error: 'ECONNREFUSED' }],
  '060': [DNSSEC],
  '070': [{ up: true, mcpDetections: [{ port: 6274, ...mcpFlags,
    detection: { protocolVersion: '2024-01-01', scheme: 'http', serverInfo: {}, path: '/mcp', authRequired: false, ssePresent: false, tools: ['exec'] } }] }],
};
// Keys the concluder itself writes onto every record or evidence entry — not an adapter's emission.
const CONCLUDER_KEYS = new Set(['cpe', 'from']);

async function adapterPlugins() {
  const out = new Map();
  for (const f of fs.readdirSync(PLUGINS).filter((x) => x.endsWith('.mjs') && x !== 'result_concluder.mjs').sort()) {
    const m = await import(pathToFileURL(path.join(PLUGINS, f)).href);
    if (typeof m.conclude === 'function' || typeof m.default?.conclude === 'function') out.set(String(m.default?.id), m.default?.name);
  }
  return out;
}
async function emitted() {
  const plugins = await adapterPlugins();
  const keys = new Map(); // key → Set of plugin ids that landed it
  const note = (k, id) => { if (!keys.has(k)) keys.set(k, new Set()); keys.get(k).add(id); };
  for (const [id, results] of Object.entries(DRIVERS)) {
    for (const result of results) {
      const c = await concluder.run([...(id === '060' ? [DNS_009] : []), { id, name: plugins.get(id), result }]);
      for (const s of c.services) if (id !== '060' || s.dnsSecurity) for (const k of Object.keys(s)) note(k, id);
      for (const e of c.evidence) for (const k of Object.keys(e)) if (ADAPTER_PAYLOAD_KEYS.includes(k)) note(k, id);
    }
  }
  return { plugins, keys };
}

test('(census) a driver for EVERY plugin that carries an adapter — derived from the plugin directory', async () => {
  const { plugins } = await emitted();
  assert.ok(plugins.size >= 16, `positive control: ${plugins.size} adapters found`);
  assert.deepEqual(Object.keys(DRIVERS).sort(), [...plugins.keys()].sort());
});

test('(census) every key an adapter lands is identity, graded by the table, or declared not-a-finding WITH a reason', async () => {
  const { keys } = await emitted();
  const unknown = [...keys.keys()].filter((k) => !IDENTITY_FIELDS.has(k) && !CONCLUDER_KEYS.has(k)
    && !T.FLAG_KEYS.includes(k) && !(k in T.DECLARED_NON_FINDING_KEYS));
  assert.deepEqual(unknown, [], `landed by ${unknown.map((k) => `${k}←${[...keys.get(k)]}`).join(', ')}`);
  for (const [k, why] of Object.entries(T.DECLARED_NON_FINDING_KEYS)) assert.ok(String(why).length > 20, `${k} says why`);
});

test('(census, reverse) every graded key and every declared non-finding key is landed by some adapter — none is a phantom', async () => {
  const { keys } = await emitted();
  const phantoms = [...T.FLAG_KEYS, ...Object.keys(T.DECLARED_NON_FINDING_KEYS)]
    .filter((k) => !keys.has(k) && !(k in T.UNEMITTED_FLAG_KEYS));
  assert.deepEqual(phantoms, []);
  // The declared exception is still unemitted — if a producer starts filling it, the exception goes.
  for (const k of Object.keys(T.UNEMITTED_FLAG_KEYS)) assert.equal(keys.has(k), false, `${k} is landed now — retire its exception`);
});
