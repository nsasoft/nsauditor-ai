// utils/service_flags.mjs
// THE SERVICE-FLAG TABLE (1.2.1 (s1)) — the ONLY place a flag a service check leaves on a record is graded.
//
// Six readers used to keep their own lists — the Markdown report, SARIF, the CSV, `--fail-on`, the scan-history fallback
// count and the `--watch` webhook filter — and the lists disagreed: the CSV printed any SNMP community, `--fail-on` read
// neither weak TLS nor SNMP, and none of them read the MCP flags, a certificate flag, an SMB null session or the
// 040 / 050 / 060 audits the concluder carries since 1.2.1. A producer added a flag and no reader followed. Every reader
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
export const SERVICE_FLAGS = Object.freeze([
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
]);
export const FLAG_KEYS = Object.freeze(SERVICE_FLAGS.map((r) => r.key));

/** Keys an adapter lands that are NOT findings — each with the reason, so the census cannot be satisfied silently. */
export const DECLARED_NON_FINDING_KEYS = Object.freeze({
  algorithms: 'the SSH algorithm inventory the server offered; weakAlgorithms is its graded subset',
  allowedMethods: 'the methods the Allow header listed; dangerousMethods is its graded subset',
  methodsTested: 'whether an Allow header was read — the tested state of dangerousMethods, not a finding',
  tls: 'a TLS handshake was observed on the port — the condition under which the TLS rows are measured',
  shares: 'the shares an SMB null session enumerated — evidence for nullSessionAllowed, never a separate finding',
  users: 'the users an SMB null session enumerated — evidence for nullSessionAllowed, never a separate finding',
  communityCustom: 'a custom (operator-supplied) SNMP community answered — not a finding, and the string is never recorded',
});
/** Graded keys no shipped adapter lands, with the reason the row stays. */
export const UNEMITTED_FLAG_KEYS = Object.freeze({
  cves: 'no shipped producer fills a service record\'s CVEs; the row grades a conclusion another tool supplies',
});

/** The findings one record (a service record, or an evidence entry carrying a payload) carries. */
export function flagFindings(record, { target = '', now = new Date() } = {}) {
  if (!record || typeof record !== 'object') return [];
  return SERVICE_FLAGS.flatMap((row) => row.grade(record, { target, now }).map((f) => ({ key: row.key, ...f })));
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
