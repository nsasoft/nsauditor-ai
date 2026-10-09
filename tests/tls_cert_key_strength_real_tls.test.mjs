// 040's KEY-STRENGTH CHECK FIRES ON A REAL SERVER (1.3.0 build 5 — Gate 3-A finding F-3; the operator's ruling "Fix now").
//
// `analyzeKeyStrength` read the key type from `cert.pubkey?.type`. Node's `getPeerCertificate()` returns `pubkey` as a
// raw Buffer with no `.type` — an RSA key is told by its `modulus` / `exponent`, an EC key by `asn1Curve` / `nistCurve`
// (measured on Node 24.12 against loopback servers) — so the type always read "unknown" and BOTH branches were
// unreachable from `e96c8f9` (2026-04-08) on. A router serving a 1024-bit RSA key (`certAudit.details.keyBits: 1024`)
// raised nothing, and a 1024-bit and a 2048-bit key produced IDENTICAL issues. No test named `weak_rsa_key`.
//
// Now the type comes from the fields Node sets (modulus → RSA, a named curve → EC) and the size from `bits`; a key of
// neither type (Ed25519 carries none of them) records key strength NOT ASSESSED on certAudit — never silence.
//
// FOURTH QUADRANT FIRST: an EC key must never read as a weak RSA key (a type that defaulted to RSA would grade every
// P-256 server CRITICAL), and a 2048-bit RSA key raises nothing. Real TLS on loopback, a throwaway CA trusted through
// NODE_EXTRA_CA_CERTS and a leaf naming 127.0.0.1, so the KEY is the only thing under test.
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
// TLS 1.3 for the EC and Ed25519 leaves (their signatures need it); TLS 1.3 has forward secrecy by protocol since 0.2.57.
const TLS13 = { ciphers: null, maxVersion: 'TLSv1.3' };
// A 1024-bit RSA key loads only at OpenSSL security level 0; the helper's ECDHE-RSA suites are kept.
const RSA1024 = { ciphers: 'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:@SECLEVEL=0' };

function makeFixtures() {
  try {
    const d = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-040-key-'));
    const run = (args) => execFileSync('openssl', args, { cwd: d, stdio: 'ignore' });
    run(['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'ca.key', '-out', 'ca.pem', '-days', '30', '-subj', '/CN=NSAuditor Test CA']);
    const leaf = (name, newkey) => {
      run(['req', ...newkey, '-nodes', '-keyout', `${name}.key`, '-out', `${name}.csr`, '-subj', '/CN=localhost']);
      fs.writeFileSync(path.join(d, `${name}.ext`), 'subjectAltName=DNS:localhost,IP:127.0.0.1\n');
      run(['x509', '-req', '-in', `${name}.csr`, '-CA', 'ca.pem', '-CAkey', 'ca.key', '-CAcreateserial', '-out', `${name}.pem`,
        '-days', '200', '-sha256', '-extfile', `${name}.ext`]);
    };
    leaf('rsa1024', ['-newkey', 'rsa:1024']);
    leaf('rsa2048', ['-newkey', 'rsa:2048']);
    leaf('ec256', ['-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256']);
    leaf('ed25519', ['-newkey', 'ed25519']);
    return d;
  } catch { return null; }
}

before(() => { DIR = makeFixtures(); });
after(() => { if (DIR) fs.rmSync(DIR, { recursive: true, force: true }); });

function caseFor(t, name, server = null, { trusted = true } = {}) {
  if (!DIR) {
    if (process.env.CI) assert.fail('openssl is required for these real-TLS legs — refusing to skip in CI');
    t.skip('openssl unavailable — cannot build the TLS fixtures (would hard-fail in CI)');
    return null;
  }
  const env = { ...process.env, NODE_EXTRA_CA_CERTS: path.join(DIR, 'ca.pem') };
  if (!trusted) delete env.NODE_EXTRA_CA_CERTS;
  delete env.NODE_TEST_CONTEXT;
  const args = [HELPER, path.join(DIR, `${name}.key`), path.join(DIR, `${name}.pem`), '127.0.0.1', ...(server ? [JSON.stringify(server)] : [])];
  const out = execFileSync(process.execPath, args, { env, encoding: 'utf8', timeout: 30000 });
  const i = out.lastIndexOf('@@RESULT@@');
  assert.ok(i >= 0, `the case printed no result: ${out.slice(-300)}`);
  return JSON.parse(out.slice(i + '@@RESULT@@'.length));
}
const keyChecks = (r) => r.otherChecks.filter((c) => /_key$/.test(c));

/**
 * THE RUNTIME'S OWN VERIFIER, ASKED DIRECTLY — the oracle for whether `ca_not_trusted` rides beside a weak key.
 *
 * Node 24.12 refuses a 1024-bit RSA leaf even under a trusted CA (authorizationError UNSPECIFIED); Node 22.23.3 accepts
 * it (both measured 2026-10-09; both bundle OpenSSL 3.5.x, so the difference is Node's default, not OpenSSL's version).
 * CE's floor is >=24, so the pin asserts the Node 24 answer — and asks the runtime's own verifier first, the same way
 * 040's probe asks (a default client context, rejectUnauthorized:false, the CA through NODE_EXTRA_CA_CERTS, a fresh
 * child), so a red names WHICH premise moved: the verifier's verdict, or 040's reading of it.
 */
function runtimeVerifier(name, server) {
  const script = "const tls=require('node:tls'),fs=require('node:fs');const [k,c,ci]=process.argv.slice(1);"
    + "const srv=tls.createServer({key:fs.readFileSync(k),cert:fs.readFileSync(c),...(ci?{ciphers:ci}:{})},(s)=>s.end());"
    + "srv.listen(0,'127.0.0.1',()=>{const s=tls.connect({host:'127.0.0.1',port:srv.address().port,rejectUnauthorized:false},()=>{"
    + "process.stdout.write(JSON.stringify({authorized:s.authorized,error:s.authorizationError||null}));s.destroy();srv.close();});"
    + "s.on('error',(e)=>{process.stdout.write(JSON.stringify({authorized:null,error:String(e)}));srv.close();});});";
  const env = { ...process.env, NODE_EXTRA_CA_CERTS: path.join(DIR, 'ca.pem') };
  delete env.NODE_TEST_CONTEXT;
  const out = execFileSync(process.execPath, ['-e', script, path.join(DIR, `${name}.key`), path.join(DIR, `${name}.pem`), server?.ciphers || ''],
    { env, encoding: 'utf8', timeout: 15000 });
  const v = JSON.parse(out);
  assert.equal(typeof v.authorized, 'boolean', `the verifier oracle did not complete a handshake: ${out}`);
  return v;
}

// ── FOURTH QUADRANT FIRST ──────────────────────────────────────────────────────────────────────────────────────────────
test('(q, first) an EC P-256 key: recorded as EC, 256 bits, and NO key finding — an EC key never reads as a weak RSA key', (t) => {
  const r = caseFor(t, 'ec256', TLS13); if (!r) return;
  assert.equal(r.hostname.length, 0, 'positive control: the name is clean, so the key is the only thing under test');
  assert.deepEqual([r.keyInfo.keyType, r.keyInfo.keyBits], ['EC', 256]);
  assert.deepEqual(keyChecks(r), []);
  assert.deepEqual(r.otherChecks, [], 'nothing else is wrong with this certificate');
});

test('(q) a 2048-bit RSA key: recorded as RSA, 2048 bits, and NO key finding', (t) => {
  const r = caseFor(t, 'rsa2048'); if (!r) return;
  assert.deepEqual([r.keyInfo.keyType, r.keyInfo.keyBits], ['RSA', 2048]);
  assert.deepEqual(r.otherChecks, []);
});

// ── THE CHANGE ─────────────────────────────────────────────────────────────────────────────────────────────────────────
test('a 1024-bit RSA key: weak_rsa_key HIGH, graded, and it trips --fail-on high — the router\'s key, which raised nothing', (t) => {
  const r = caseFor(t, 'rsa1024', RSA1024); if (!r) return;
  assert.deepEqual([r.keyInfo.keyType, r.keyInfo.keyBits], ['RSA', 1024]);
  assert.deepEqual(keyChecks(r), ['high:weak_rsa_key']);
  // PINNED, NOT ENDORSED: Node 24's verifier refuses a 1024-bit leaf even under a trusted CA (authorizationError
  // UNSPECIFIED), so ca_not_trusted MEDIUM rides beside the weak key. A self-signed key (the router) skips that check.
  // Raised for a ruling; change this pin deliberately if ca_not_trusted's exact-code carve-out widens.
  const verifier = runtimeVerifier('rsa1024', RSA1024);
  assert.equal(verifier.authorized, false, `the premise: this runtime's verifier refuses the 1024-bit leaf (${process.version}: ${JSON.stringify(verifier)})`);
  {
    assert.deepEqual(r.otherChecks, ['high:weak_rsa_key', 'medium:ca_not_trusted'], `verifier: ${JSON.stringify(verifier)}`);
    // The architect seat's ruling on that pin: the store DOES hold the CA, so the detail must not name the CA store as the
    // cause of a refusal Node reports only as UNSPECIFIED — it states the fact, and points at the graded weak key.
    assert.equal(r.caTrust.length, 1);
    assert.doesNotMatch(r.caTrust[0], /CA store/);
    assert.match(r.caTrust[0], /^Certificate chain refused by this runtime's verifier — Node reports no named reason \(UNSPECIFIED\)/);
    assert.match(r.caTrust[0], /the graded weak key \/ signature on this certificate is the actionable finding/);
  }
  assert.ok(r.graded.some((g) => g.severity === 'High' && /RSA key is 1024 bits \(minimum recommended: 2048\)/.test(g.title)),
    `graded: ${JSON.stringify(r.graded)}`);
  assert.equal(r.failOnRank, RANK.high);
});

test('(q) a NAMED verify code keeps its wording: an untrusted CA reads "not trusted by system CA store: <code>"', (t) => {
  const r = caseFor(t, 'rsa2048', null, { trusted: false }); if (!r) return;
  assert.equal(r.caTrust.length, 1, `otherChecks: ${JSON.stringify(r.otherChecks)}`);
  assert.match(r.caTrust[0], /^Certificate not trusted by system CA store: [A-Z_]+$/);
  assert.doesNotMatch(r.caTrust[0], /UNSPECIFIED|actionable finding/, 'no weak grade here, and a named reason');
});

test('an Ed25519 key — neither RSA nor EC: key strength is NOT ASSESSED on certAudit, with no finding and never silence', (t) => {
  const r = caseFor(t, 'ed25519', TLS13); if (!r) return;
  assert.deepEqual(keyChecks(r), []);
  assert.match(String(r.certAuditKey.keyStrength), /^not assessed — /, `certAudit: ${JSON.stringify(r.certAuditKey)}`);
  assert.match(String(r.keyInfo.keyStrength), /^not assessed — /);
});

test('an assessed key says so on certAudit — the not-assessed state is a state, not an absence', (t) => {
  const r = caseFor(t, 'rsa2048'); if (!r) return;
  assert.equal(r.certAuditKey.keyStrength, 'assessed');
});

// ── THE DERIVATION, ON THE SHAPES NODE DELIVERS ────────────────────────────────────────────────────────────────────────
// The shapes below are copied from what getPeerCertificate() returned on Node 24.12 (fields only; values are those of
// the measured certificates). The weak-EC branch is driven here at unit level because no OpenSSL this suite runs on
// will serve a curve under 256 bits (P-224 fails the handshake on TLS 1.2 and 1.3 alike — measured).
test('the type comes from modulus / a named curve and the size from bits — never from pubkey', async () => {
  const { analyzeKeyStrength } = await import('../plugins/040_tls_cert_auditor.mjs');
  const cfg = { minRsaBits: 2048, minEcBits: 256 };
  const buf = Buffer.alloc(8);
  const issuesOf = (cert) => analyzeKeyStrength(cert, cfg).issues.map((i) => `${i.severity}:${i.check}`);
  assert.deepEqual(issuesOf({ bits: 256, asn1Curve: 'prime256v1', nistCurve: 'P-256', pubkey: buf }), [], '(q) P-256');
  assert.deepEqual(issuesOf({ bits: 224, asn1Curve: 'secp224r1', nistCurve: 'P-224', pubkey: buf }), ['high:weak_ec_key']);
  assert.deepEqual(issuesOf({ bits: 1024, modulus: 'AB', exponent: '0x10001', pubkey: buf }), ['high:weak_rsa_key']);
  assert.deepEqual(issuesOf({ bits: 768, modulus: 'AB', exponent: '0x10001', pubkey: buf }), ['critical:weak_rsa_key']);
  // The shape the old code expected and Node never delivers: no modulus, no curve — NOT ASSESSED, never graded.
  const stub = analyzeKeyStrength({ bits: 1024, pubkey: { type: 'RSA', size: 1024 } }, cfg);
  assert.deepEqual([stub.issues, stub.keyInfo.type], [[], 'unknown']);
  assert.match(stub.keyInfo.strength, /^not assessed — /);
});
