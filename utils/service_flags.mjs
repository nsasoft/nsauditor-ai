// utils/service_flags.mjs
// THE SERVICE-FLAG TABLE (1.3.0 (s1)) — the ONLY place a flag a service check leaves on a record is graded.
//
// Six readers used to keep their own lists — the Markdown report, SARIF, the CSV, `--fail-on`, the scan-history fallback
// count and the `--watch` webhook filter — and the lists disagreed: the CSV printed any SNMP community, `--fail-on` read
// neither weak TLS nor SNMP, and none of them read the MCP flags, a certificate flag, an SMB null session or the
// 040 / 050 / 060 audits the concluder carries since 1.3.0. A producer added a flag and no reader followed. Every reader
// now asks this table, `tests/service_flag_table.test.mjs` holds every reader to it, and its census drives every adapter
// so a key an adapter lands is either graded here or declared not-a-finding below, with the reason.
//
// Pure: no I/O. `now` is injectable for the one clock-dependent row (an expired certificate).

import { DEFAULT_COMMUNITIES } from '../plugins/snmp_scanner.mjs';
import { MCP_FLAG_SEVERITY } from '../plugins/mcp_scanner.mjs';
import { ADAPTER_PAYLOAD_KEYS } from '../plugins/result_concluder.mjs';

export const SEVERITY_ORDER = Object.freeze(['Critical', 'High', 'Medium', 'Low', 'Info']);
/** 'critical' | 'CRIT' | 'High' … → 'Critical' | 'High' | 'Medium' | 'Low' | 'Info'. */
export function normalizeSeverity(sev) {
  const s = String(sev ?? '').trim().toLowerCase();
  if (s.startsWith('crit')) return 'Critical';
  if (s.startsWith('hi')) return 'High';
  if (s.startsWith('med')) return 'Medium';
  if (s.startsWith('lo')) return 'Low';
  return 'Info';
}
/** Info 0 … Critical 4 — the scale `--fail-on` and the webhook compare on. */
export const severityRank = (sev) => SEVERITY_ORDER.length - 1 - SEVERITY_ORDER.indexOf(normalizeSeverity(sev));

/**
 * The grade of an OPEN SERVICE that carries no finding (1.3.0 (s2)): an open port is inventory, not a finding. SARIF's
 * "service detected" result and --fail-on's open-service baseline both read this — SARIF graded every open service
 * Medium, a code-scanning warning per open port, while --fail-on graded the same service info.
 */
export const OPEN_SERVICE_SEVERITY = 'Info';

/** The payloads the concluder carries under a namespace — on a service record, or on an evidence entry when no port. */
export const PAYLOAD_KEYS = Object.freeze([...ADAPTER_PAYLOAD_KEYS]);

const list = (v) => (Array.isArray(v) ? v : []);
const nameOf = (a) => (typeof a === 'string' ? a : (a?.algorithm || a?.name || String(a)));
const ruleSafe = (s) => String(s).replace(/[^a-zA-Z0-9._-]/g, '-');
const finding = (severity, title, ruleId, evidence = null, item = null) => ({ item, severity, title, ruleId, evidence });
const once = (cond, f) => (cond ? [f()] : []);
// An entry a payload carries is a finding unless its producer graded it PASS or INFO (the adapters drop those already).
const actionable = (e) => e && !/^(pass|info)$/i.test(String(e.severity ?? ''));
const fired = (v) => v === true || (Array.isArray(v) && v.length > 0) || (typeof v === 'string' && v.trim() !== '');

const MCP_TITLES = {
  mcpAnonymousAccess: 'MCP server reachable without authentication',
  mcpAnonymousToolList: 'MCP server lists its tools without authentication',
  mcpCleartextTransport: 'MCP server served over cleartext HTTP',
  mcpDeprecatedProtocol: 'MCP server speaks a deprecated protocol version',
  mcpInspectorExposed: 'MCP Inspector exposed on a non-loopback address',
};

/**
 * One row per key. `label` names the check in the Markdown Scope line, `token` is its CSV token, and `grade(record, ctx)`
 * returns that key's findings — ONE PER ITEM where the key holds a list (a method, an algorithm, a protocol, a cipher, an
 * audit entry), so every reader counts the same units.
 */
const GRADED = [
  { key: 'anonymousLogin', label: 'anonymous FTP login (tested only when FTP_CHECK_ANON is set)', token: 'anonymous_login',
    grade: (s, { target }) => once(s.anonymousLogin === true, () => finding('Critical', 'FTP anonymous login enabled', 'ftp-anonymous-login',
      `${s.service || 'ftp'} on ${target} accepts anonymous authentication.`)) },
  { key: 'axfrAllowed', label: 'DNS zone transfer (tested only when DNS_CHECK_AXFR and DNS_AXFR_DOMAIN are set)', token: 'axfr_allowed',
    grade: (s, { target }) => once(s.axfrAllowed === true, () => finding('Critical', 'DNS zone transfer (AXFR) allowed', 'dns-zone-transfer',
      `Zone transfer permitted on ${target}; the entire zone may be enumerated.`)) },
  { key: 'community', label: 'an SNMP default community', token: 'default_community',
    grade: (s, { target }) => once(DEFAULT_COMMUNITIES.includes(s.community), () => finding('High',
      `SNMP default community string: ${s.community}`, 'snmp-default-community', `SNMP responds to community "${s.community}" on ${target}.`, s.community)) },
  { key: 'weakAlgorithms', label: 'weak SSH algorithms', token: 'weak_algorithms',
    grade: (s) => list(s.weakAlgorithms).map(nameOf).filter(Boolean).map((a) => finding('Medium', `Weak SSH algorithm supported: ${a}`,
      `weak-algorithm-${ruleSafe(a)}`, null, a)) },
  { key: 'weakProtocols', label: 'weak TLS protocols', token: 'weak_protocols',
    grade: (s) => list(s.weakProtocols).map(String).map((p) => finding('Medium', `Weak TLS protocol enabled: ${p}`,
      `tls-weak-protocol-${ruleSafe(p)}`, null, p)) },
  { key: 'weakCiphers', label: 'weak TLS ciphers (the cipher each version negotiated)', token: 'weak_ciphers',
    grade: (s) => list(s.weakCiphers).map(String).map((c) => finding('Medium', `Weak TLS cipher negotiated: ${c}`,
      `tls-weak-cipher-${ruleSafe(c)}`, null, c)) },
  { key: 'dangerousMethods', label: 'dangerous HTTP methods (only where an Allow header was read)', token: 'dangerous_methods',
    grade: (s) => list(s.dangerousMethods).map(String).map((m) => finding('Medium', `Dangerous HTTP method allowed: ${m}`,
      `http-dangerous-method-${m.toLowerCase()}`, null, m)) },
  // 011's two certificate flags are graded only where NO 040 audit landed on the record: 040 is the certificate's
  // authority on that port and grades the same certificate itself (cert_expired, self_signed), so grading both would count
  // one certificate twice. The severities derive from Enterprise's crypto_agent grading of these same two flags.
  { key: 'certSelfSigned', label: 'a self-signed certificate', token: 'cert_self_signed',
    grade: (s) => once(s.certSelfSigned === true && s.certAudit == null, () => finding('Medium', 'Self-signed TLS certificate',
      'tls-self-signed-certificate')) },
  { key: 'certExpiry', label: 'an expired certificate', token: 'cert_expired',
    grade: (s, { now }) => once(Boolean(s.certExpiry) && s.certAudit == null && new Date(s.certExpiry) < now,
      () => finding('High', 'Expired TLS certificate', 'tls-expired-certificate', `The certificate expired ${s.certExpiry}.`)) },
  // provisional — operator ruling pending: High is this product's rung for anonymous ENUMERATION, one below anonymous access.
  { key: 'nullSessionAllowed', label: 'an SMB null session (tested only when SMB_NULL_SESSION is set)', token: 'null_session',
    grade: (s, { target }) => once(s.nullSessionAllowed === true, () => finding('High', 'SMB null session allowed', 'smb-null-session',
      `An anonymous (null) session was accepted on ${target}${list(s.shares).length ? `; ${list(s.shares).length} share(s) listed` : ''}.`)) },
  ...Object.entries(MCP_FLAG_SEVERITY).map(([key, severity]) => ({
    key, label: 'the MCP server checks', token: key.replace(/[A-Z]/g, (c) => `_${c.toLowerCase()}`),
    grade: (s) => once(fired(s[key]), () => finding(severity,
      typeof s[key] === 'string' ? `${MCP_TITLES[key] ?? key}: ${s[key]}` : (MCP_TITLES[key] ?? key),
      key.replace(/[A-Z]/g, (c) => `-${c.toLowerCase()}`), Array.isArray(s[key]) ? `Tools: ${s[key].join(', ')}` : null,
      typeof s[key] === 'string' ? s[key] : null)),
  })),
  // No shipped producer fills a record's CVEs (Enterprise's CVE mapper writes the finding queue); a conclusion built by
  // another tool may, so the row stays — declared in UNEMITTED_FLAG_KEYS, which the census holds to "still unemitted".
  { key: 'cves', label: null, token: 'cves',
    grade: (s) => list(s.cves ?? s.cve).map((c) => {
      const id = typeof c === 'string' ? c : (c?.id || c?.cveId || '');
      if (!id) return null;
      return finding(normalizeSeverity(typeof c === 'object' && c?.severity ? c.severity : 'High'),
        `${id} — ${s.program || s.service || 'service'}${s.version && s.version !== 'Unknown' ? ` ${s.version}` : ''}`, id,
        `See https://nvd.nist.gov/vuln/detail/${id}`, id);
    }).filter(Boolean) },
  { key: 'certAudit', label: 'the TLS-certificate audit (040)', token: 'tls_certificate_issues',
    grade: (s) => list(s.certAudit?.issues).filter(actionable).map((i) => finding(normalizeSeverity(i.severity),
      `TLS certificate: ${i.detail || i.check}`, `tls-cert-${ruleSafe(i.check)}`, null, String(i.check))) },
  { key: 'tribeHealth', label: 'the debug-endpoint audit (050)', token: 'debug_endpoint_findings',
    grade: (s) => list(s.tribeHealth?.findings).filter(actionable).map((f) => finding(normalizeSeverity(f.severity),
      `Debug endpoint: ${f.detail || f.check}`, `debug-endpoint-${ruleSafe(f.category)}-${ruleSafe(f.check)}`, null, `${f.category}/${f.check}`)) },
  { key: 'dnsSecurity', label: 'the DNS-security audit of the domain (060)', token: 'dns_security_findings',
    grade: (s) => list(s.dnsSecurity?.findings).filter(actionable).map((f) => finding(normalizeSeverity(f.severity),
      `DNS security: ${f.detail || f.check}`, `dns-security-${ruleSafe(f.check)}`, null, String(f.check))) },
];

// ── (s1) B — WHAT THE COMPARISON CHANNEL COMPARES ──────────────────────────────────────────────────────────────────
// Each row also declares how a scan-to-scan comparison reads it:
//   producer — the plugin that writes the row's fields: its record `source`, and a `marker` field its adapter always
//              writes (so a payload merged onto another producer's record is still recognised). `applies` keys on this,
//              never on a service LABEL.
//   cid      — the comparison identity of one item. One declared form per row; two rows that see the SAME fact share a
//              cid (011's and 040's expired certificate are both `certificate:expired`), so the dedupe that decides
//              which producer GRADES it can never make the identity switch between runs.
//   owns     — which cids the row can produce.
//   measured — read from RECORD STATE only, never from configuration: true, a reason code from NOT_COMPARED_REASONS,
//              or `{ tried: [...] }` where measurement is per item (an SNMP default community is measured only if tried).
//   scope    — 'host' for a fact about the host's domain, compared at host level wherever the concluder put it.
// A row whose absence proves nothing (`absenceProves: false`) is never CLEARED.
const fromState = (state) => (state in NOT_TESTED_CODES ? state : 'not-recorded');
const NOT_TESTED_CODES = { 'opt-in-off': 1, 'no-domain': 1, 'no-answer': 1 };
const optInMeasured = (key, stateKey) => (s) => (s[key] === true || s[key] === false ? true : fromState(s[stateKey]));
const sameAs = (c) => (cid) => cid === c;
const prefixed = (p) => (cid) => cid.startsWith(`${p}:`);
const tlsMeasured = (s) => (s.tls === true ? true : 'no-handshake');
const TLS_011 = { id: '011', source: 'tls-scanner', marker: 'tls' };
const CERT_CID = { cert_expired: 'certificate:expired', self_signed: 'certificate:self_signed' };
const COMPARISON = {
  anonymousLogin: { producer: { id: '004', source: 'ftp', marker: 'anonymousLogin' }, cid: () => 'anonymousLogin',
    owns: sameAs('anonymousLogin'), measured: optInMeasured('anonymousLogin', 'anonymousLoginTested') },
  axfrAllowed: { producer: { id: '009', source: 'dns', marker: 'axfrAllowed' }, cid: () => 'axfrAllowed',
    owns: sameAs('axfrAllowed'), measured: optInMeasured('axfrAllowed', 'axfrTested') },
  community: { producer: { id: '007', source: 'snmp', marker: 'community' }, cid: (i) => `community:${i}`, owns: prefixed('community'),
    measured: (s) => (Array.isArray(s.communitiesTried) ? { tried: [...s.communitiesTried] } : 'not-recorded') },
  weakAlgorithms: { producer: { id: '002', source: 'ssh', marker: 'weakAlgorithms' }, cid: (i) => `weakAlgorithms:${i}`,
    owns: prefixed('weakAlgorithms'), measured: (s) => (s.algorithms != null ? true : 'no-algorithms') },
  weakProtocols: { producer: TLS_011, cid: (i) => `weakProtocols:${i}`, owns: prefixed('weakProtocols'), measured: tlsMeasured },
  weakCiphers: { producer: TLS_011, cid: (i) => `weakCiphers:${i}`, owns: prefixed('weakCiphers'), measured: tlsMeasured,
    absenceProves: false },
  dangerousMethods: { producer: { id: '006', source: 'http', marker: 'methodsTested' }, cid: (i) => `dangerousMethods:${i}`,
    owns: prefixed('dangerousMethods'), measured: (s) => (s.methodsTested === true ? true : 'no-allow-header') },
  certSelfSigned: { producer: TLS_011, cid: () => CERT_CID.self_signed, owns: sameAs(CERT_CID.self_signed), measured: tlsMeasured },
  certExpiry: { producer: TLS_011, cid: () => CERT_CID.cert_expired, owns: sameAs(CERT_CID.cert_expired), measured: tlsMeasured },
  nullSessionAllowed: { producer: { id: '014', source: 'netbios', marker: 'nullSessionAllowed' }, cid: () => 'nullSessionAllowed',
    owns: sameAs('nullSessionAllowed'), measured: optInMeasured('nullSessionAllowed', 'nullSessionTested') },
  // A CVE on a record is a LOOKUP outcome, not an estate fact: an empty list after a lookup that failed, or after the
  // vulnerability data moved, is not a fix. Until a producer records the lookup's outcome (F1's scope — it must flip this
  // rule to read it), an absence is NOT COMPARED and an appearance is FIRST OBSERVED.
  cves: { producer: { id: null, source: null, marker: 'cves' }, cid: (i) => `cve:${i}`, owns: prefixed('cve'),
    measured: () => 'lookup-not-recorded' },
  certAudit: { producer: { id: '040', source: 'tls-cert-auditor', marker: 'certAudit' }, cid: (i) => CERT_CID[i] ?? `certificate:${i}`,
    owns: prefixed('certificate'), measured: (s) => (s.certAudit != null ? true : 'producer-not-run') },
  tribeHealth: { producer: { id: '050', source: 'tribe-health', marker: 'tribeHealth' }, cid: (i) => `tribeHealth:${i}`,
    owns: prefixed('tribeHealth'), measured: (s) => (s.tribeHealth?.state === 'up' ? true : 'payload-down') },
  dnsSecurity: { producer: { id: '060', source: 'dns-sec-auditor', marker: 'dnsSecurity' }, cid: (i) => `dnsSecurity:${i}`,
    owns: prefixed('dnsSecurity'), measured: () => true, scope: 'host' },
};
const MCP_COMPARISON = (key) => ({ producer: { id: '070', source: 'mcp', marker: null }, cid: () => `mcp:${key}`,
  owns: sameAs(`mcp:${key}`), measured: () => true });

export const SERVICE_FLAGS = Object.freeze(GRADED.map((row) => {
  const cmp = COMPARISON[row.key] ?? (row.key in MCP_FLAG_SEVERITY ? MCP_COMPARISON(row.key) : null);
  if (!cmp) return Object.freeze({ ...row });
  const { producer } = cmp;
  return Object.freeze({ scope: 'service', absenceProves: true, ...row, ...cmp,
    applies: (rec) => Boolean(rec) && ((producer.marker != null && producer.marker in rec)
      || (producer.source != null && rec.source === producer.source)) });
}));
export const FLAG_KEYS = Object.freeze(SERVICE_FLAGS.map((r) => r.key));
export const rowOf = (key) => SERVICE_FLAGS.find((r) => r.key === key);
/** The rows that can produce a comparison identity. */
export const rowsOwning = (cid) => SERVICE_FLAGS.filter((r) => typeof r.owns === 'function' && r.owns(cid));

/** Why an item, or a row, was NOT COMPARED — a closed vocabulary, each with the sentence a reader sees. */
export const NOT_COMPARED_REASONS = Object.freeze({
  'service-not-answering': () => 'the service did not answer this run',
  'producer-not-run': () => 'the check did not run on this service this run',
  'opt-in-off': () => 'the check was off this run',
  'no-domain': () => 'no domain was given this run',
  'no-answer': () => 'the exchange did not complete this run',
  'not-recorded': () => 'the scan did not record whether the check ran',
  'no-allow-header': () => 'no Allow header was read this run',
  'no-algorithms': () => 'the SSH algorithms were not collected this run',
  'no-handshake': () => 'no TLS handshake was observed this run',
  'negotiated-only': () => 'the cipher each TLS version negotiated — an empty list is not proof that no weak cipher is accepted',
  'not-tried': (item) => `${item} was not tried this run`,
  'payload-down': () => 'the debug-endpoint probe did not complete this run',
  'lookup-not-recorded': () => 'the scan did not record whether the CVE lookup ran',
  'service-not-in-scan': () => 'the service is not in this scan',
});
/** The version of what a history line records about service checks. Absent on a line written before 1.3.0. */
export const FLAGS_BASIS = 'service-flags-v1';

// ── (s3) NOT TESTED ──────────────────────────────────────────────────────────────────────────────────────────────
// A check that did not run, or ran and could not complete, is said to be NOT TESTED with its reason — never "none", never
// "refused". The producer records the state beside the result (`axfrTested`, `anonymousLoginTested`, `nullSessionTested`:
// `true` when measured, else the reason code); the HTTP probe's is `methodsTested`. A record that carries the result as
// null and no state was written before 1.3.0, so whether the check ran was not recorded.
const REASONS = {
  'opt-in-off': (sw) => `the check is off (${sw} is unset)`,
  'no-domain': () => 'no domain was given (DNS_AXFR_DOMAIN is unset)',
  'no-answer': () => 'the exchange did not complete, so nothing was measured',
  'no-allow-header': () => 'no Allow header was read, so dangerous methods were not checked there (not "none")',
  'not-recorded': () => 'the scan that wrote this record did not record whether the check ran',
};
const optIn = (key, stateKey, check, sw) => ({ key, check, notTested: (s) => {
  if (!(key in s) || s[key] === true || s[key] === false) return null;
  const code = s[stateKey] in REASONS ? s[stateKey] : 'not-recorded';
  return REASONS[code](sw);
} });
export const NOT_TESTED_CHECKS = Object.freeze([
  optIn('axfrAllowed', 'axfrTested', 'DNS zone transfer', 'DNS_CHECK_AXFR'),
  optIn('anonymousLogin', 'anonymousLoginTested', 'Anonymous FTP login', 'FTP_CHECK_ANON'),
  optIn('nullSessionAllowed', 'nullSessionTested', 'SMB null session', 'SMB_NULL_SESSION'),
  { key: 'dangerousMethods', check: 'HTTP methods', notTested: (s) => (s.methodsTested === false ? REASONS['no-allow-header']() : null) },
]);

/** The checks a record's service did not test, each with its reason. Only an OPEN service is listed: a service that did
 * not answer had nothing for the check to run against, and the services table already says so. */
export function notTestedChecks(record) {
  if (!record || typeof record !== 'object' || record.status !== 'open') return [];
  return NOT_TESTED_CHECKS.map((c) => ({ key: c.key, check: c.check, reason: c.notTested(record) })).filter((c) => c.reason);
}

/** Every NOT TESTED check across a conclusion's services, each with the service it was not tested on. */
export function conclusionNotTested(conclusion) {
  const r = conclusion?.result ?? conclusion ?? {};
  return list(r.services).flatMap((s) => notTestedChecks(s).map((c) => ({ ...c, target: `${s.port}/${s.protocol || 'tcp'}` })));
}

// ⚠️ A HOST-LEVEL AUDIT THAT DID NOT RUN IS READ FROM ITS PLUGIN STATUS, NEVER FROM ITS PAYLOAD'S ABSENCE (1.3.0 build 4,
// Gate 3-A F-1). The DNS-security audit (060) declines an IP-address target and says why on its manifest entry; its
// payload (`dnsSecurity`) is then simply absent — and an absence where a reader expects a result reads as "no DNS
// issues". So the status decides: `ran` adds nothing (its findings are graded by the table above); `skipped`, `timeout`
// or `error` adds the audit as NOT TESTED with the manifest's own reason; and an audit ABSENT from the manifest adds
// nothing, because it was not requested, which is not a decline.
export const HOST_AUDITS = Object.freeze([{ id: '060', key: 'dnsSecurity', check: 'DNS-security audit (060)' }]);

/** The host-level audits a run's manifest says did not run, each with the host as its target and the manifest's reason. */
export function manifestNotTested(manifest, host) {
  return list(manifest).flatMap((m) => {
    const audit = HOST_AUDITS.find((a) => a.id === String(m?.id ?? ''));
    if (!audit || !m.status || m.status === 'ran') return [];
    return [{ key: audit.key, check: audit.check, target: String(host ?? ''),
      reason: m.reason || `the plugin's status is ${m.status}, and it recorded no reason` }];
  });
}

/** Keys an adapter lands that are NOT findings — each with the reason, so the census cannot be satisfied silently. */
export const DECLARED_NON_FINDING_KEYS = Object.freeze({
  algorithms: 'the SSH algorithm inventory the server offered; weakAlgorithms is its graded subset',
  allowedMethods: 'the methods the Allow header listed; dangerousMethods is its graded subset',
  methodsTested: 'whether an Allow header was read — the tested state of dangerousMethods, not a finding',
  axfrTested: 'whether the zone-transfer check ran and measured — true, or the reason it did not (NOT TESTED, never "denied")',
  anonymousLoginTested: 'whether the anonymous-FTP check ran and measured — true, or the reason it did not (NOT TESTED)',
  nullSessionTested: 'whether the SMB null-session check ran and measured — true, or the reason it did not (NOT TESTED)',
  tls: 'a TLS handshake was observed on the port — the condition under which the TLS rows are measured',
  shares: 'the shares an SMB null session enumerated — evidence for nullSessionAllowed, never a separate finding',
  users: 'the users an SMB null session enumerated — evidence for nullSessionAllowed, never a separate finding',
  communityCustom: 'a custom (operator-supplied) SNMP community answered — not a finding, and the string is never recorded',
  communitiesTried: 'the SNMP communities tried, as labels (a custom string reads "custom") — what makes a default community measurable',
  headers: 'the HTTP probe\'s allowlisted response headers (strict-transport-security only), present only when an HTTPS response arrived — read by Enterprise\'s crypto agent for its Missing-HSTS check; no Community reader grades it',
});
/** Graded keys no shipped adapter lands, with the reason the row stays. */
export const UNEMITTED_FLAG_KEYS = Object.freeze({
  cves: 'no shipped producer fills a service record\'s CVEs; the row grades a conclusion another tool supplies',
});

/** The findings one record (a service record, or an evidence entry carrying a payload) carries. */
export function flagFindings(record, { target = '', now = new Date() } = {}) {
  if (!record || typeof record !== 'object') return [];
  return SERVICE_FLAGS.flatMap((row) => row.grade(record, { target, now })
    .map((f) => ({ key: row.key, ...f, cid: row.cid ? row.cid(f.item) : null })));
}

/**
 * Every finding a conclusion carries: each service record's, plus each EVIDENCE entry that carries an adapter payload —
 * a domain's DNS posture (060) lands in evidence when the scan found no 53/udp service, and its grade must not depend on
 * whether an unrelated port answered. Evidence findings target the host, with no port.
 */
export function conclusionFindings(conclusion, host, { now } = {}) {
  const r = conclusion?.result ?? conclusion ?? {};
  const out = [];
  for (const s of list(r.services)) {
    const target = `${host}:${s.port}/${s.protocol || 'tcp'}`;
    for (const f of flagFindings(s, { target, now })) out.push({ ...f, target, port: s.port, protocol: s.protocol || 'tcp', service: s.service ?? null });
  }
  for (const e of list(r.evidence)) {
    if (!PAYLOAD_KEYS.some((k) => e?.[k] != null)) continue;
    const payloadOnly = Object.fromEntries(PAYLOAD_KEYS.filter((k) => e[k] != null).map((k) => [k, e[k]]));
    for (const f of flagFindings(payloadOnly, { target: String(host), now })) {
      out.push({ ...f, target: String(host), port: null, protocol: null, service: e.from ?? null });
    }
  }
  return out;
}

/** The CSV tokens for a record: one per key that fired, its items joined by ';'. */
export function csvTokens(record, opts) {
  const byKey = new Map();
  for (const f of flagFindings(record, opts)) {
    if (!byKey.has(f.key)) byKey.set(f.key, []);
    if (f.item != null) byKey.get(f.key).push(f.item);
  }
  return [...byKey].map(([key, items]) => {
    const { token } = SERVICE_FLAGS.find((r) => r.key === key);
    return items.length ? `${token}:${items.join(';')}` : token;
  });
}

/** The highest rank among findings, or -1 when there are none. */
export const maxRank = (findings) => findings.reduce((m, f) => Math.max(m, severityRank(f.severity)), -1);

// ── (s1) B — WHAT A HISTORY LINE RECORDS ─────────────────────────────────────────────────────────────────────────
/**
 * One service's comparison state: the cids of the findings it carries, and for each row that APPLIES to it, whether that
 * row was measured. A service that did not answer measured nothing. Host-scope rows are left to hostFlagState.
 */
export function serviceFlagState(record, opts) {
  const answered = record?.status === 'open';
  const checks = {};
  for (const row of SERVICE_FLAGS) {
    if (row.scope !== 'service' || !row.applies(record)) continue;
    checks[row.key] = answered ? row.measured(record) : 'service-not-answering';
  }
  const flags = new Set(flagFindings(record, opts).filter((f) => rowOf(f.key).scope === 'service').map((f) => f.cid));
  return { flags: [...flags].sort(), checks };
}

/** The host-level comparison state: host-scope rows (a domain's DNS posture), wherever the concluder put the payload. */
export function hostFlagState(conclusion, opts) {
  const r = conclusion?.result ?? conclusion ?? {};
  const hostRows = SERVICE_FLAGS.filter((row) => row.scope === 'host');
  const flags = new Set();
  const checks = {};
  for (const rec of [...list(r.services), ...list(r.evidence)]) {
    for (const row of hostRows) {
      if (rec?.[row.producer.marker] == null) continue;
      const only = { [row.producer.marker]: rec[row.producer.marker] };
      if (checks[row.key] !== true) checks[row.key] = row.measured(only);
      for (const f of flagFindings(only, opts)) if (f.key === row.key) flags.add(f.cid);
    }
  }
  return { hostFlags: [...flags].sort(), hostChecks: checks };
}
