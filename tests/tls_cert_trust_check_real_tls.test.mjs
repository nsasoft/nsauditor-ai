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
// STATED LIMIT: the `refused-at-level-0` verdict (a NAMED code at level 0 after UNSPECIFIED at the default) has NO measured
// occupant on Node 24.12 — every named problem tried wins at the default level — so no leg here drives it.
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
function caseFor(t, { key, cert = key, opts = null, pin = null }) {
  if (!DIR) {
    if (process.env.CI) assert.fail('openssl is required for these real-TLS legs — refusing to skip in CI');
    t.skip('openssl unavailable — cannot build the TLS fixtures (would hard-fail in CI)');
    return null;
  }
  const env = { ...process.env, NODE_EXTRA_CA_CERTS: path.join(DIR, 'trusted.pem') };
  delete env.NODE_TEST_CONTEXT;
  const args = [HELPER, path.join(DIR, `${key}.key`), path.join(DIR, `${cert}.pem`), opts ? JSON.stringify(opts) : '', ...(pin ? [pin] : [])];
  const out = execFileSync(process.execPath, args, { env, encoding: 'utf8', timeout: 30000 });
  const i = out.lastIndexOf('@@RESULT@@');
  assert.ok(i >= 0, `the case printed no result: ${out.slice(-300)}`);
  return JSON.parse(out.slice(i + '@@RESULT@@'.length));
}

// ── FOURTH QUADRANT FIRST: weak crypto never launders an untrusted chain ───────────────────────────────────────────────
test('(first) a 1024-bit leaf under an UNTRUSTED CA keeps ca_not_trusted with its NAMED code — and no second look runs', (t) => {
  const r = caseFor(t, { key: 'rsa1024Untrusted' }); if (!r) return;
  assert.ok(r.checks.includes('high:weak_rsa_key'), `the weak grade is present (${r.checks})`);
  assert.ok(r.checks.includes('medium:ca_not_trusted'), `ca_not_trusted is raised (${r.checks})`);
  assert.match(r.caTrust[0], /^Certificate not trusted by system CA store: [A-Z_]+$/);
  assert.doesNotMatch(r.caTrust[0], /UNSPECIFIED/);
  assert.equal(r.trustCheck, null, 'a named refusal needs no second look');
  assert.equal(r.sessions, 1);
});

test('(first) a SHA-1 leaf under an UNTRUSTED CA keeps ca_not_trusted with its NAMED code — and no second look runs', (t) => {
  const r = caseFor(t, { key: 'sha1LeafUntrusted' }); if (!r) return;
  assert.ok(r.checks.includes('high:weak_signature'), `the weak grade is present (${r.checks})`);
  assert.match(r.caTrust[0] ?? '', /^Certificate not trusted by system CA store: [A-Z_]+$/);
  assert.equal(r.trustCheck, null);
});

test('(first) the second look never silences a refusal no graded finding stands in for: a 1024-bit leaf with the minimum lowered to 1024 keeps ca_not_trusted', (t) => {
  // TLS_AUDIT_MIN_RSA_BITS / opts.minRsaBits lowered by an operator: 040 grades no weak key, and the runtime's verifier
  // still refuses the chain (UNSPECIFIED). Dropping ca_not_trusted here would leave the refusal reported NOWHERE.
  const r = caseFor(t, { key: 'rsa1024', opts: { minRsaBits: 1024 } }); if (!r) return;
  assert.equal(r.authError, 'UNSPECIFIED');
  assert.equal(r.checks.includes('high:weak_rsa_key'), false, 'no weak grade at this minimum');
  assert.equal(r.trustCheck, null, 'no second look without a graded weak key or signature');
  assert.match(r.caTrust[0] ?? '', /^Certificate chain refused by this runtime's verifier — Node reports no named reason \(UNSPECIFIED\)$/);
});

test('(q) a strong leaf under the trusted CA: authorized, no ca_not_trusted, no second look', (t) => {
  const r = caseFor(t, { key: 'strong' }); if (!r) return;
  assert.deepEqual(r.caTrust, []);
  assert.equal(r.trustCheck, null);
  assert.equal(r.sessions, 1);
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
    assert.equal(r.sessions, 2, 'exactly one more handshake');
  });
}

test('NOT ASSESSED: a runtime that refuses the level-0 handshake keeps ca_not_trusted with today\'s wording — only an authorization removes it', (t) => {
  const r = caseFor(t, { key: 'rsa1024', opts: { _trustCheckCiphers: 'NSA-NO-SUCH-CIPHER' } }); if (!r) return;
  assert.ok(r.checks.includes('medium:ca_not_trusted'), `${r.checks}`);
  assert.match(r.caTrust[0], /^Certificate chain refused by this runtime's verifier — Node reports no named reason \(UNSPECIFIED\); the graded weak key \/ signature on this certificate is the actionable finding$/);
  assert.equal(r.trustCheck?.verdict, TRUST_CHECK.NOT_ASSESSED);
  assert.ok(r.trustCheck.reason, 'the reason is recorded');
  assert.equal(r.sessions, 1, 'the second handshake never completed');
});

// ── THE PIN: a new connect site, reached through the scan's pinned address ─────────────────────────────────────────────
test('the second look runs inside the scan\'s pin: a name only the pin answers reaches the server twice, and the verdict is the authorization', (t) => {
  const r = caseFor(t, { key: 'rsa1024', pin: PIN_NAME }); if (!r) return;
  assert.equal(r.up, true, `the first probe reached the server through the pin (${JSON.stringify(r.failed)})`);
  assert.deepEqual(r.trustCheck, { verdict: TRUST_CHECK.TRUSTED_AT_LEVEL_0 }, 'an unpinned second connect could not resolve the name');
  assert.equal(r.sessions, 2);
  assert.deepEqual(r.caTrust, []);
});

test('(control) the same name OUTSIDE the pin resolves nowhere: the audit never reaches the server', (t) => {
  if (!DIR) { t.skip('openssl unavailable'); return; }
  const env = { ...process.env, NODE_EXTRA_CA_CERTS: path.join(DIR, 'trusted.pem') };
  delete env.NODE_TEST_CONTEXT;
  // The helper with a NAME as its target but no pin: run 040 against the name directly.
  const out = execFileSync(process.execPath, ['--input-type=module', '-e', `
    import tls from 'node:tls'; import fs from 'node:fs';
    const { default: auditor } = await import(${JSON.stringify(new URL('../plugins/040_tls_cert_auditor.mjs', import.meta.url).href)});
    const srv = tls.createServer({ key: fs.readFileSync(process.argv[1]), cert: fs.readFileSync(process.argv[2]), ciphers: 'DEFAULT:@SECLEVEL=0' }, (s) => s.end());
    let sessions = 0; srv.on('secureConnection', () => { sessions += 1; });
    await new Promise((r) => srv.listen(0, '127.0.0.1', r));
    const res = await auditor.run(${JSON.stringify(PIN_NAME)}, srv.address().port, { timeoutMs: 3000 });
    process.stdout.write(JSON.stringify({ sessions, reached: (res.portResults ?? []).length }));
    srv.close();
  `, path.join(DIR, 'rsa1024.key'), path.join(DIR, 'rsa1024.pem')], { env, encoding: 'utf8', timeout: 30000 });
  assert.deepEqual(JSON.parse(out), { sessions: 0, reached: 0 });
});
