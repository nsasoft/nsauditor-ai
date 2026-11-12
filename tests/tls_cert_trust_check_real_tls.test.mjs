// tests/tls_cert_trust_check_real_tls.test.mjs
// ─────────────────────────────────────────────────────────────────────────────
// THE SECOND LOOK AT A REFUSAL WITH NO NAMED REASON (EE 2.0.0 / Community 1.0.0, 4(c); the architect seat's Q4, default ON).
//
// Node reports UNSPECIFIED for a verify error outside its named table. Measured on Node 24.12 over fourteen certificate
// shapes, it appears only when the chain is otherwise trusted and the one failure is the verifier's security-level policy
// (a 1024-bit leaf, a SHA-1 leaf, a SHA-1 intermediate), and each of those is authorized at OpenSSL security level 0.
// A NAMED chain problem — an untrusted root, a missing issuer, an expired certificate, an intermediate that is not a CA,
// a client-only key usage — is reported by name already at the default level, weak key or not. So 040, on an UNSPECIFIED
// refusal of a certificate carrying a graded weak key or signature, makes ONE more handshake at level 0: authorized there,
// the refusal was the weak crypto and ca_not_trusted is not raised (the weak-key / weak-signature finding is the finding);
// anything short of an authorization keeps ca_not_trusted.
//
// FOURTH QUADRANT FIRST: weak crypto must never launder an untrusted chain — a weak leaf under an UNTRUSTED CA keeps
// ca_not_trusted with its named code, and no second look runs. Then the pin: the second look is a new connect site, and it
// must reach the target through the scan's pinned address. Each case is a real TLS server on loopback, in a child whose CA
// store trusts only its own throwaway root.
//
// The `refused-at-level-0` verdict (a NAMED code at level 0 after UNSPECIFIED at the default) has NO measured occupant on
// Node 24.12 — every named problem tried wins at the default level. It is kept (the architect seat's ruling: a named
// refusal is the verifier's reason, and folding it into NOT ASSESSED discards it in the direction that hides a refusal), and
// the legs below drive it through the injected-result seam: the FIRST refusal is real, only the level-0 result is injected.
// ─────────────────────────────────────────────────────────────────────────────
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { TRUST_CHECK } from '../plugins/040_tls_cert_auditor.mjs';

const HELPER = fileURLToPath(new URL('./helpers/tls_trust_check_case.mjs', import.meta.url));
const PIN_NAME = 'trust-check.test';
let DIR = null;

function makeFixtures() {
  try {
    const d = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-040-trust-'));
    const run = (args) => execFileSync('openssl', args, { cwd: d, stdio: 'ignore' });
    const CA_EXT = ['-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign'];
    const root = (name) => run(['req', '-x509', '-newkey', 'rsa:2048', '-sha256', '-nodes', '-keyout', `${name}.key`, '-out', `${name}.pem`,
      '-days', '30', '-subj', `/CN=${name}`, ...CA_EXT]);
    const sign = (name, bits, issuer, md, ext) => {
      run(['req', '-newkey', `rsa:${bits}`, '-nodes', '-keyout', `${name}.key`, '-out', `${name}.csr`, '-subj', `/CN=${name}`]);
      fs.writeFileSync(path.join(d, `${name}.ext`), ext);
      run(['x509', '-req', '-in', `${name}.csr`, '-CA', `${issuer}.pem`, '-CAkey', `${issuer}.key`, '-CAcreateserial', '-out', `${name}.pem`,
        '-days', '200', `-${md}`, '-extfile', `${name}.ext`]);
    };
    const LEAF = `subjectAltName=DNS:localhost,DNS:${PIN_NAME},IP:127.0.0.1\n`;
    root('trusted');
    root('untrusted');
    sign('rsa1024', 1024, 'trusted', 'sha256', LEAF);
    sign('rsa1024Untrusted', 1024, 'untrusted', 'sha256', LEAF);
    sign('sha1Leaf', 2048, 'trusted', 'sha1', LEAF);
    sign('sha1LeafUntrusted', 2048, 'untrusted', 'sha1', LEAF);
    sign('strong', 2048, 'trusted', 'sha256', LEAF);
    sign('sha1Inter', 2048, 'trusted', 'sha1', 'basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n');
    sign('underSha1Inter', 2048, 'sha1Inter', 'sha256', LEAF);
    fs.writeFileSync(path.join(d, 'underSha1Inter.chain.pem'),
      fs.readFileSync(path.join(d, 'underSha1Inter.pem'), 'utf8') + fs.readFileSync(path.join(d, 'sha1Inter.pem'), 'utf8'));
    return d;
  } catch { return null; }
}
before(() => { DIR = makeFixtures(); });
after(() => { if (DIR) fs.rmSync(DIR, { recursive: true, force: true }); });

/** Run one case in a child whose CA store trusts only `trusted.pem`. */
function caseFor(t, { key, cert = key, opts = null, pin = null, mode = null }) {
  if (!DIR) {
    if (process.env.CI) assert.fail('openssl is required for these real-TLS legs — refusing to skip in CI');
    t.skip('openssl unavailable — cannot build the TLS fixtures (would hard-fail in CI)');
    return null;
  }
  const env = { ...process.env, NODE_EXTRA_CA_CERTS: path.join(DIR, 'trusted.pem') };
  delete env.NODE_TEST_CONTEXT;
  const args = [HELPER, path.join(DIR, `${key}.key`), path.join(DIR, `${cert}.pem`), opts ? JSON.stringify(opts) : '', pin ?? '', ...(mode ? [mode] : [])];
  let out;
  // A child that dies or times out (close() waiting on a lingering connection) still printed its @@ATWRITE@@ snapshot.
  try { out = execFileSync(process.execPath, args, { env, encoding: 'utf8', timeout: 30000 }); }
  catch (e) { assert.fail(`the case child failed (${e.code ?? `exit ${e.status}`}): ${String(e.stdout ?? '').slice(-600)} ${String(e.stderr ?? '').slice(-300)}`); }
  const i = out.lastIndexOf('@@RESULT@@');
  assert.ok(i >= 0, `the case printed no result: ${out.slice(-300)}`);
  return JSON.parse(out.slice(i + '@@RESULT@@'.length));
}

/**
 * B212 (ruling (d), the architect's verdict on cd8bd08). `n` looks are `n` TCP connections: a connection is accepted before any
 * handshake, so this count cannot race one. Every connection ends as exactly one server-side session or one tlsClientError,
 * so the two sum to `n`. The helper reads them after close AND after every accepted connection has reported its outcome
 * (B212-C3: a connection that ends before its handshake reports its tlsClientError only after close resolves; `settled`
 * false means one never reported). `sessionsAtWrite` (the count when 040's result was taken) is reported and never
 * asserted: it read 0 where 1 was expected once in five full runs, with no mechanism established. No retry, and never a bare 0.
 */
function assertLooks(r, n, why = '') {
  const counters = { connections: r.connections, sessionsAtWrite: r.sessionsAtWrite, sessionsAfterClose: r.sessionsAfterClose, tlsClientErrors: r.tlsClientErrors, socketErrors: r.socketErrors, settled: r.settled };
  assert.equal(r.connections, n, `${why ? why + ' — ' : ''}TCP connections ${JSON.stringify(counters)}`);
  assert.equal(r.sessionsAfterClose + r.tlsClientErrors, n, `${why ? why + ' — ' : ''}every connection ends as one session or one tlsClientError ${JSON.stringify(counters)}`);
}

// ── FOURTH QUADRANT FIRST: weak crypto never launders an untrusted chain ───────────────────────────────────────────────
test('(first) a 1024-bit leaf under an UNTRUSTED CA keeps ca_not_trusted with its NAMED code — and no second look runs', (t) => {
  const r = caseFor(t, { key: 'rsa1024Untrusted' }); if (!r) return;
  assert.ok(r.checks.includes('high:weak_rsa_key'), `the weak grade is present (${r.checks})`);
  assert.ok(r.checks.includes('medium:ca_not_trusted'), `ca_not_trusted is raised (${r.checks})`);
  assert.match(r.caTrust[0], /^Certificate not trusted by system CA store: [A-Z_]+$/);
  assert.doesNotMatch(r.caTrust[0], /UNSPECIFIED/);
  assert.equal(r.trustCheck, null, 'a named refusal needs no second look');
  assertLooks(r, 1);
});

test('(first) a SHA-1 leaf under an UNTRUSTED CA keeps ca_not_trusted with its NAMED code — and no second look runs', (t) => {
  const r = caseFor(t, { key: 'sha1LeafUntrusted' }); if (!r) return;
  assert.ok(r.checks.includes('high:weak_signature'), `the weak grade is present (${r.checks})`);
  assert.match(r.caTrust[0] ?? '', /^Certificate not trusted by system CA store: [A-Z_]+$/);
  assert.equal(r.trustCheck, null);
  assertLooks(r, 1, 'no second look');
});

test('(first) the second look never silences a refusal no graded finding stands in for: a 1024-bit leaf with the minimum lowered to 1024 keeps ca_not_trusted', (t) => {
  // TLS_AUDIT_MIN_RSA_BITS / opts.minRsaBits lowered by an operator: 040 grades no weak key, and the runtime's verifier
  // still refuses the chain (UNSPECIFIED). Dropping ca_not_trusted here would leave the refusal reported NOWHERE.
  const r = caseFor(t, { key: 'rsa1024', opts: { minRsaBits: 1024 } }); if (!r) return;
  assert.equal(r.authError, 'UNSPECIFIED');
  assert.equal(r.checks.includes('high:weak_rsa_key'), false, 'no weak grade at this minimum');
  assert.equal(r.trustCheck, null, 'no second look without a graded weak key or signature');
  assert.match(r.caTrust[0] ?? '', /^Certificate chain refused by this runtime's verifier — Node reports no named reason \(UNSPECIFIED\)$/);
  assertLooks(r, 1, 'no second look without a graded weak key or signature');
});

test('(q) a strong leaf under the trusted CA: authorized, no ca_not_trusted, no second look', (t) => {
  const r = caseFor(t, { key: 'strong' }); if (!r) return;
  assert.deepEqual(r.caTrust, []);
  assert.equal(r.trustCheck, null);
  assertLooks(r, 1);
});

// ── THE CHANGE ─────────────────────────────────────────────────────────────────────────────────────────────────────────
for (const [name, setup, grade] of [
  ['a 1024-bit leaf', { key: 'rsa1024' }, 'high:weak_rsa_key'],
  ['a SHA-1 leaf', { key: 'sha1Leaf' }, 'high:weak_signature'],
  ['a leaf under a SHA-1 intermediate', { key: 'underSha1Inter', cert: 'underSha1Inter.chain' }, 'medium:chain_weak_signature'],
]) {
  test(`${name} under the TRUSTED CA: the verifier refused it UNSPECIFIED, level 0 authorizes it — the weak grade is the finding, no ca_not_trusted`, (t) => {
    const r = caseFor(t, setup); if (!r) return;
    assert.equal(r.authError, 'UNSPECIFIED', 'the premise: the default verifier refused it with no named reason');
    assert.ok(r.checks.includes(grade), `${grade} (${r.checks})`);
    assert.deepEqual(r.caTrust, [], 'the refusal was the weak crypto, already graded');
    assert.deepEqual(r.trustCheck, { verdict: TRUST_CHECK.TRUSTED_AT_LEVEL_0 });
    assert.deepEqual(r.certAuditTrustCheck, r.trustCheck, 'the outcome rides the concluded certAudit');
    assertLooks(r, 2, 'exactly one more handshake');
  });
}

test('NOT ASSESSED: a runtime that refuses the level-0 handshake keeps ca_not_trusted with today\'s wording — only an authorization removes it', (t) => {
  const r = caseFor(t, { key: 'rsa1024', opts: { _trustCheckCiphers: 'NSA-NO-SUCH-CIPHER' } }); if (!r) return;
  assert.ok(r.checks.includes('medium:ca_not_trusted'), `${r.checks}`);
  assert.match(r.caTrust[0], /^Certificate chain refused by this runtime's verifier — Node reports no named reason \(UNSPECIFIED\); the graded weak key \/ signature on this certificate is the actionable finding$/);
  assert.equal(r.trustCheck?.verdict, TRUST_CHECK.NOT_ASSESSED);
  assert.ok(r.trustCheck.reason, 'the reason is recorded');
  // The premise, measured on the floor runtime (v24.22.3): the bogus cipher string is refused when the second look builds
  // its context, BEFORE any TCP connect, so the server sees ONE connection. A runtime that refuses it later would read
  // connections 2 with a tlsClientError and turn this red: re-measure that runtime, never loosen this to a range.
  assertLooks(r, 1, 'the second handshake never completed (refused before any TCP connect)');
});

// ── THE PIN: a new connect site, reached through the scan's pinned address ─────────────────────────────────────────────
test('the second look runs inside the scan\'s pin: a name only the pin answers reaches the server twice, and the verdict is the authorization', (t) => {
  const r = caseFor(t, { key: 'rsa1024', pin: PIN_NAME }); if (!r) return;
  assert.equal(r.up, true, `the first probe reached the server through the pin (${JSON.stringify(r.failed)})`);
  assert.deepEqual(r.trustCheck, { verdict: TRUST_CHECK.TRUSTED_AT_LEVEL_0 }, 'an unpinned second connect could not resolve the name');
  assertLooks(r, 2);
  assert.deepEqual(r.caTrust, []);
});

test('(control) the same name OUTSIDE the pin resolves nowhere: the audit never reaches the server', (t) => {
  if (!DIR) {
    if (process.env.CI) assert.fail('openssl is required for these real-TLS legs — refusing to skip in CI');
    t.skip('openssl unavailable — cannot build the TLS fixtures (would hard-fail in CI)');
    return;
  }
  const env = { ...process.env, NODE_EXTRA_CA_CERTS: path.join(DIR, 'trusted.pem') };
  delete env.NODE_TEST_CONTEXT;
  // The helper with a NAME as its target but no pin: run 040 against the name directly.
  const out = execFileSync(process.execPath, ['--input-type=module', '-e', `
    import tls from 'node:tls'; import fs from 'node:fs';
    const { default: auditor } = await import(${JSON.stringify(new URL('../plugins/040_tls_cert_auditor.mjs', import.meta.url).href)});
    const { rawConnectOnce } = await import(${JSON.stringify(new URL('./helpers/tls_case_clients.mjs', import.meta.url).href)});
    const srv = tls.createServer({ key: fs.readFileSync(process.argv[1]), cert: fs.readFileSync(process.argv[2]), ciphers: 'DEFAULT:@SECLEVEL=0' }, (s) => s.end());
    let connections = 0; srv.on('connection', () => { connections += 1; });
    await new Promise((r) => srv.listen(0, '127.0.0.1', r));
    const res = await auditor.run(${JSON.stringify(PIN_NAME)}, srv.address().port, { timeoutMs: 3000 });
    const connectionsAfterAudit = connections;
    // B212-C1: one raw TCP connect, accepted by the server, then destroyed — the counter's liveness on the same server.
    await rawConnectOnce(srv, srv.address().port);
    await new Promise((r) => srv.close(r));
    process.stdout.write(JSON.stringify({ connectionsAfterAudit, connectionsAfterProbe: connections, reached: (res.portResults ?? []).length,
      failed: (res.failedPorts ?? []).map((f) => f.error) }));
  `, path.join(DIR, 'rsa1024.key'), path.join(DIR, 'rsa1024.pem')], { env, encoding: 'utf8', timeout: 30000 });
  // B212: TCP connections, read after close — a connect that reached the server is counted even if no handshake completed.
  // B212-C1 (the architect's verdict 0395a014): the audit's 0 sits beside a 1 from the SAME counter — one raw TCP connect,
  // made after the audit returned, is counted. A counter that never fires would read 0 for both and fail on the 1.
  const r = JSON.parse(out);
  assert.deepEqual({ connectionsAfterAudit: r.connectionsAfterAudit, connectionsAfterProbe: r.connectionsAfterProbe, reached: r.reached },
    { connectionsAfterAudit: 0, connectionsAfterProbe: 1, reached: 0 });
  // The miss is the name not resolving (ENOTFOUND; EAI_* on a runner with no resolver), not 040 returning before it tried.
  assert.equal(r.failed.length, 1, `one failed port (${JSON.stringify(r.failed)})`);
  assert.match(r.failed[0], /^(ENOTFOUND|EAI_[A-Z]+)$/, 'the audit tried the name and the resolver refused it');
});

// ── THE VERDICT NO MEASURED RUNTIME REACHES, driven through the injected-result seam (`opts._trustCheckResult`) ──────────
// Each case is the real trusted 1024-bit leaf, so the default verifier's refusal is genuine (UNSPECIFIED, with a graded weak
// key); only the second handshake's result is injected, and the server sees ONE session.
test('injected: a NAMED code at level 0 → ca_not_trusted carrying that code, named by the second handshake', (t) => {
  const r = caseFor(t, { key: 'rsa1024', opts: { _trustCheckResult: { authorized: false, authError: 'CERT_REVOKED' } } }); if (!r) return;
  assert.equal(r.authError, 'UNSPECIFIED', 'the premise: the first refusal is real');
  assert.deepEqual(r.trustCheck, { verdict: TRUST_CHECK.REFUSED_AT_LEVEL_0, authError: 'CERT_REVOKED' });
  assert.deepEqual(r.caTrust, ['Certificate not trusted by system CA store: CERT_REVOKED (named by a second handshake at OpenSSL '
    + "security level 0, after this runtime's verifier refused the chain with no named reason)"]);
  assert.deepEqual(r.certAuditTrustCheck, r.trustCheck);
  assertLooks(r, 1, 'the injected result replaced the second handshake');
});

test('injected: an AUTHORIZATION at level 0 → no ca_not_trusted', (t) => {
  const r = caseFor(t, { key: 'rsa1024', opts: { _trustCheckResult: { authorized: true } } }); if (!r) return;
  assert.deepEqual(r.trustCheck, { verdict: TRUST_CHECK.TRUSTED_AT_LEVEL_0 });
  assert.deepEqual(r.caTrust, []);
  assertLooks(r, 1);
});

for (const [name, injected] of [['a THROW', { throws: 'ERR_SSL_NO_CIPHER_MATCH' }], ['UNSPECIFIED again', { authorized: false, authError: 'UNSPECIFIED' }]]) {
  test(`injected: ${name} at level 0 → NOT ASSESSED, and ca_not_trusted keeps today's wording`, (t) => {
    const r = caseFor(t, { key: 'rsa1024', opts: { _trustCheckResult: injected } }); if (!r) return;
    assert.equal(r.trustCheck?.verdict, TRUST_CHECK.NOT_ASSESSED);
    assert.ok(r.trustCheck.reason, 'the reason is recorded');
    assert.deepEqual(r.caTrust, ["Certificate chain refused by this runtime's verifier — Node reports no named reason (UNSPECIFIED); "
      + 'the graded weak key / signature on this certificate is the actionable finding']);
    assertLooks(r, 1, 'the injected result replaced the second handshake');
  });
}

// ── THE SUM'S SECOND TERM (B212-C3, the architect's verdict 0395a014) ───────────────────────────────────────────────────
// assertLooks adds tlsClientErrors to sessions. Every leg above reads that term as 0, so these legs show it counting, through
// the same server and the same counters, with no audit: the helper's modes make ONE connection that ends as a tlsClientError.
// Each states assertLooks' two lines with the terms separated, so assertLooks itself would add nothing here.
for (const [mode, how, client] of [
  ['raw-connect', 'a connection destroyed before any ClientHello', null],
  // A handshake that STARTED: the server read the ClientHello and refused it with a protocol_version alert.
  ['refused-hello', 'a ClientHello the server refuses', 'ERR_SSL_TLSV1_ALERT_PROTOCOL_VERSION'],
]) {
  test(`(sum) ${how} ends as one tlsClientError and no session`, (t) => {
    const r = caseFor(t, { key: 'strong', mode }); if (!r) return;
    assert.equal(r.mode, mode, 'the helper ran the mode, not the audit');
    assert.equal(r.client, client, 'what the client saw');
    assert.deepEqual({ connections: r.connections, sessionsAfterClose: r.sessionsAfterClose, tlsClientErrors: r.tlsClientErrors, settled: r.settled },
      { connections: 1, sessionsAfterClose: 0, tlsClientErrors: 1, settled: true }, `the term counts ${JSON.stringify(r)}`);
  });
}
