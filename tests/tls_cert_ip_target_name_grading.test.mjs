// THE TLS CERTIFICATE AUDIT (040) GRADES AN IP TARGET'S NAME MISMATCH BY CONTEXT (0.2.57).
//
// Scanned by address, a certificate that names only DNS names never matches the target, so `hostname_mismatch` fired
// HIGH on every IP-target scan of such a service, and from 0.2.57 — when the concluder reaches 040 and one table grades
// its findings — `--fail-on high` failed on it. Measured on the 1.3.0 Gate-1 router run: `Hostname "192.168.1.1" does
// not match certificate names: www.routerlogin.net`, High, beside the router's self-signed High. The finding is TRUE (a
// client connecting by address does see a mismatch), so it is KEPT — unlike the DNS-posture audit on an IP, which could
// measure nothing — and graded LOW in exactly that case: an IP-literal target, a certificate carrying at least one DNS
// SAN and no IP SAN at all. It stays HIGH where the name is a real misconfiguration: a DNS-name target absent from the
// certificate, a certificate naming a DIFFERENT address, or one naming nothing. LOW, never INFO: service_flags drops
// `info` and `pass` from grading, so INFO would remove the finding from every reader — a decline by another route.
//
// FOURTH QUADRANT FIRST. Every case is a REAL TLS server on an ephemeral loopback port, audited by the real plugin in a
// child process whose NODE_EXTRA_CA_CERTS trusts a throwaway CA, so the certificate's name is the only thing under test.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HELPER = fileURLToPath(new URL('./helpers/tls_cert_case.mjs', import.meta.url));
let DIR = null;
const RANK = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

// A throwaway CA and five leaves it signs. Returns null when openssl is unavailable (a hard failure in CI).
function makeFixtures() {
  try {
    const d = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-040-name-'));
    const run = (args) => execFileSync('openssl', args, { cwd: d, stdio: 'ignore' });
    run(['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'ca.key', '-out', 'ca.pem', '-days', '30', '-subj', '/CN=NSAuditor Test CA']);
    const leaf = (name, san) => {
      run(['req', '-newkey', 'rsa:2048', '-nodes', '-keyout', `${name}.key`, '-out', `${name}.csr`, '-subj', '/CN=www.routerlogin.test']);
      fs.writeFileSync(path.join(d, `${name}.ext`), san ? `subjectAltName=${san}\n` : 'basicConstraints=CA:FALSE\n');
      run(['x509', '-req', '-in', `${name}.csr`, '-CA', 'ca.pem', '-CAkey', 'ca.key', '-CAcreateserial', '-out', `${name}.pem`,
        '-days', '200', '-sha256', '-extfile', `${name}.ext`]);
    };
    leaf('dnsOnly', 'DNS:www.routerlogin.test');
    leaf('otherIp', 'DNS:www.routerlogin.test,IP:10.0.0.1');
    leaf('noSan', null);
    leaf('ownIp', 'DNS:www.routerlogin.test,IP:127.0.0.1');
    leaf('ownIp6', 'DNS:www.routerlogin.test,IP:::1');
    leaf('ipOnly', 'IP:10.0.0.1');
    run(['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'selfSigned.key', '-out', 'selfSigned.pem', '-days', '200',
      '-subj', '/CN=www.routerlogin.test', '-addext', 'subjectAltName=DNS:www.routerlogin.test']);
    return d;
  } catch { return null; }
}

before(() => { DIR = makeFixtures(); });
after(() => { if (DIR) fs.rmSync(DIR, { recursive: true, force: true }); });

function caseFor(t, name, target, { trusted = true, server = null } = {}) {
  if (!DIR) {
    if (process.env.CI) assert.fail('openssl is required for these real-TLS legs — refusing to skip in CI');
    t.skip('openssl unavailable — cannot build the TLS fixtures (would hard-fail in CI)');
    return null;
  }
  const env = { ...process.env };
  if (trusted) env.NODE_EXTRA_CA_CERTS = path.join(DIR, 'ca.pem'); else delete env.NODE_EXTRA_CA_CERTS;
  delete env.NODE_TEST_CONTEXT;
  const args = [HELPER, path.join(DIR, `${name}.key`), path.join(DIR, `${name}.pem`), target, ...(server ? [JSON.stringify(server)] : [])];
  const out = execFileSync(process.execPath, args,
    { env, encoding: 'utf8', timeout: 30000 });
  const i = out.lastIndexOf('@@RESULT@@');
  assert.ok(i >= 0, `the case printed no result: ${out.slice(-300)}`);
  return JSON.parse(out.slice(i + '@@RESULT@@'.length));
}

// ── FOURTH QUADRANT FIRST: nothing below the LOW case may move ────────────────────────────────────────────────────────
test('(q, first) a DNS-NAME target the certificate does not name: HIGH, and the sentence is unchanged — a real misconfiguration', (t) => {
  const r = caseFor(t, 'dnsOnly', 'localhost'); if (!r) return;
  assert.deepEqual(r.otherChecks, [], 'the chain is trusted and nothing else is wrong: the name is the only thing under test');
  assert.deepEqual(r.hostname.map((i) => i.severity), ['high']);
  assert.equal(r.hostname[0].detail, 'Hostname "localhost" does not match certificate names: www.routerlogin.test');
  assert.equal(r.failOnRank, RANK.high, '--fail-on high trips on it');
});

test('(q) an IP target the certificate DOES name (its IP SAN): no hostname issue at all', (t) => {
  const r = caseFor(t, 'ownIp', '127.0.0.1'); if (!r) return;
  assert.deepEqual([r.hostname, r.otherChecks], [[], []]);
});

test('(q) an IP target and a certificate naming a DIFFERENT address: HIGH — that certificate was issued for another host', (t) => {
  const r = caseFor(t, 'otherIp', '127.0.0.1'); if (!r) return;
  assert.deepEqual(r.hostname.map((i) => i.severity), ['high']);
  assert.equal(r.failOnRank, RANK.high);
});

test('(q) an IP target and a certificate with NO subjectAltName: HIGH — it names no host a client can check, and says so', (t) => {
  const r = caseFor(t, 'noSan', '127.0.0.1'); if (!r) return;
  assert.deepEqual(r.hostname.map((i) => i.severity), ['high']);
  assert.equal(r.hostname[0].detail, 'Hostname "127.0.0.1": the certificate carries no subjectAltName — modern clients '
    + 'reject it for any name (CN www.routerlogin.test is not checked)');
});

test('(q) an IP-only SAN naming a different address: HIGH, and NOT the no-SAN wording — the certificate does carry a SAN', (t) => {
  const r = caseFor(t, 'ipOnly', '127.0.0.1'); if (!r) return;
  assert.deepEqual(r.hostname.map((i) => i.severity), ['high']);
  assert.doesNotMatch(r.hostname[0].detail, /carries no subjectAltName/);
});

test('a DNS-NAME target and a certificate with NO subjectAltName: the same no-SAN wording, HIGH — not "the names differ"', (t) => {
  const r = caseFor(t, 'noSan', 'localhost'); if (!r) return;
  assert.deepEqual(r.hostname.map((i) => [i.severity, i.detail]), [['high', 'Hostname "localhost": the certificate carries no '
    + 'subjectAltName — modern clients reject it for any name (CN www.routerlogin.test is not checked)']]);
});

// ── THE CHANGE ────────────────────────────────────────────────────────────────────────────────────────────────────────
test('an IP target and a certificate naming DNS names only: the finding is KEPT and graded LOW, its detail saying why', (t) => {
  const r = caseFor(t, 'dnsOnly', '127.0.0.1'); if (!r) return;
  assert.deepEqual(r.otherChecks, [], 'the name is the only thing under test');
  assert.deepEqual(r.hostname.map((i) => i.severity), ['low']);
  assert.equal(r.hostname[0].detail, 'Hostname "127.0.0.1" does not match certificate names: www.routerlogin.test — the '
    + 'certificate names DNS names only (www.routerlogin.test); a client connecting by address sees a name mismatch, '
    + 'expected where the service is reached by name');
});

test('LOW, not INFO: the finding still reaches the graded table every reader reads, at Low', (t) => {
  const r = caseFor(t, 'dnsOnly', '127.0.0.1'); if (!r) return;
  const names = r.graded.filter((f) => /does not match certificate names/.test(f.title));
  assert.deepEqual(names.map((f) => f.severity), ['Low'], `graded: ${JSON.stringify(r.graded)}`);
});

test('--fail-on high: an IP target whose ONLY issue is the name no longer trips the gate (the gate\'s own function, over the real conclusion)', (t) => {
  const r = caseFor(t, 'dnsOnly', '127.0.0.1'); if (!r) return;
  assert.equal(r.failOnRank, RANK.low, 'the highest graded finding is the Low name mismatch');
  assert.ok(r.failOnRank < RANK.high, '--fail-on high exits 0 here; the DNS-name target above still exits 1');
});

// ── IPv6: SANs are compared as ADDRESSES ──────────────────────────────────────────────────────────────────────────────
test('an IPv6 target the certificate names: Node prints the SAN expanded, the target is compressed — they MATCH', (t) => {
  const r = caseFor(t, 'ownIp6', '::1'); if (!r) return;
  assert.deepEqual([r.hostname, r.otherChecks], [[], []]);
});

test('(q) an IPv6 target against an IPv4 SAN: no address matches — HIGH (a certificate naming a different address)', (t) => {
  const r = caseFor(t, 'ownIp', '::1'); if (!r) return;
  assert.deepEqual(r.hostname.map((i) => i.severity), ['high']);
});

// ── THE CA-TRUST LABEL (ruled into this commit): ca_not_trusted says what the CA store decided, never the name ────────
test('(q, first) an UNTRUSTED CA and the RIGHT name: ca_not_trusted stays MEDIUM — the control', (t) => {
  const r = caseFor(t, 'ownIp', '127.0.0.1', { trusted: false }); if (!r) return;
  assert.deepEqual([r.hostname, r.otherChecks], [[], ['medium:ca_not_trusted']]);
});

test('(q) an UNTRUSTED CA and a WRONG name: the chain fails first, so its own code is reported — ca_not_trusted STAYS beside the mismatch', (t) => {
  const r = caseFor(t, 'dnsOnly', 'localhost', { trusted: false }); if (!r) return;
  assert.deepEqual(r.hostname.map((i) => i.severity), ['high']);
  assert.deepEqual(r.otherChecks, ['medium:ca_not_trusted'], 'the exclusion is keyed on the exact altname code, not on "a mismatch exists"');
});

test('(q) SELF-SIGNED is unchanged: self_signed HIGH, no ca_not_trusted (skipped there already) — the router\'s shape', (t) => {
  const r = caseFor(t, 'selfSigned', '127.0.0.1', { trusted: false }); if (!r) return;
  assert.deepEqual(r.otherChecks, ['high:self_signed']);
  assert.deepEqual(r.hostname.map((i) => i.severity), ['low'], 'the IP-target name mismatch is LOW here too — the self-signed HIGH still trips --fail-on high');
  assert.equal(r.failOnRank, RANK.high);
});

test('a TRUSTED chain and a WRONG name: hostname_mismatch only — no "not trusted by system CA store" for a chain the store verified', (t) => {
  const r = caseFor(t, 'dnsOnly', '127.0.0.1'); if (!r) return;
  assert.equal(r.otherChecks.includes('medium:ca_not_trusted'), false);
  assert.deepEqual(r.otherChecks, []);
});

// ── FORWARD SECRECY (ruled into 0.2.57): judged by the PROTOCOL for TLS 1.3, by the cipher name below it ──────────────
// Every TLS 1.3 suite is ephemeral by construction, but its name (TLS_AES_256_GCM_SHA384) carries neither ECDHE nor
// DHE, so a name-only test called every TLS 1.3 server "no forward secrecy".
test('(q, first) TLS 1.2 with an RSA key exchange: no_forward_secrecy MEDIUM STAYS — the router\'s true finding is this shape', (t) => {
  const r = caseFor(t, 'ownIp', '127.0.0.1', { server: { ciphers: 'AES256-GCM-SHA384' } }); if (!r) return;
  assert.equal(r.negotiation?.protocol, 'TLSv1.2');
  assert.deepEqual(r.otherChecks, ['medium:no_forward_secrecy']);
});

test('(q) TLS 1.2 with ECDHE: no no_forward_secrecy', (t) => {
  const r = caseFor(t, 'ownIp', '127.0.0.1'); if (!r) return;
  assert.equal(r.negotiation?.protocol, 'TLSv1.2');
  assert.deepEqual(r.otherChecks, []);
});

test('a default node:tls server (TLS 1.3): no no_forward_secrecy — every TLS 1.3 suite is ephemeral', (t) => {
  const r = caseFor(t, 'ownIp', '127.0.0.1', { server: { maxVersion: 'TLSv1.3', ciphers: null, honorCipherOrder: null } }); if (!r) return;
  assert.equal(r.negotiation?.protocol, 'TLSv1.3', 'the case negotiated TLS 1.3');
  assert.match(r.negotiation?.cipher ?? '', /^TLS_/, 'a TLS 1.3 suite name, which carries no ECDHE/DHE');
  assert.equal(r.negotiation?.forwardSecrecy, true);
  assert.deepEqual(r.otherChecks, []);
});
