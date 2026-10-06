// 040's WEAK-SIGNATURE CHECKS FIRE ON A REAL SERVER (1.3.0 build 5 — Gate 3-A finding F-3b, the architect seat's ruling).
//
// `weak_signature` (the leaf) and `chain_weak_signature` (the issued certificates above it) read
// `cert.signatureAlgorithm`, a field Node's getPeerCertificate() never sets — measured on Node 24.12, whose peer
// certificate carries subject, issuer, modulus, bits, raw … and no signature algorithm — so both read "unknown" and
// neither could fire from `e96c8f9` (2026-04-08) on. The algorithm is in the DER: `new X509Certificate(raw)
// .signatureAlgorithm` reads it on Node 24, and the getter does NOT EXIST on Node 20 (CE's engines floor; measured on
// v20.19.6). So on a runtime without it 040 records the signature algorithm NOT ASSESSED on certAudit — never "unknown"
// read as a pass.
//
// Rulings carried: a SELF-SIGNED certificate's own signature is never graded — no client verifies it (an anchor, or a
// leaf that is its own anchor) — so a self-signed root raises no chain_weak_signature and a self-signed leaf no
// weak_signature; the FACT (the algorithm) is still recorded, and on a self-signed leaf the self_signed finding names it
// and says why it is not graded (option B). `ecdsa-with-SHA1` joins the weak names with its own fixture.
//
// FOURTH QUADRANT FIRST: a SHA-256 chain, and a SHA-1 ROOT above SHA-256 certificates, raise nothing; a self-signed
// SHA-1 leaf raises self_signed alone. Real TLS on loopback; each case trusts only its own throwaway CA.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HELPER = fileURLToPath(new URL('./helpers/tls_cert_case.mjs', import.meta.url));
let DIR = null;
const TLS13 = { ciphers: null, maxVersion: 'TLSv1.3' };
// OpenSSL refuses to LOAD a certificate a CA signed with SHA-1 above security level 0 ("ca md too weak", measured), so
// those servers run at level 0; the RSA cases keep the helper's ECDHE-RSA suites, the EC case allows TLS 1.3.
const SEC0_RSA = { ciphers: 'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:@SECLEVEL=0' };
const SEC0_EC = { ciphers: 'DEFAULT:@SECLEVEL=0', maxVersion: 'TLSv1.3' };

function makeFixtures() {
  try {
    const d = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-040-sig-'));
    const run = (args) => execFileSync('openssl', args, { cwd: d, stdio: 'ignore' });
    const CA_EXT = ['-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign'];
    const ca = (name, newkey, md) => run(['req', '-x509', ...newkey, `-${md}`, '-nodes', '-keyout', `${name}.key`, '-out',
      `${name}.pem`, '-days', '30', '-subj', `/CN=${name}`, ...CA_EXT]);
    const sign = (name, csrSubj, newkey, issuer, md, ext) => {
      run(['req', ...newkey, '-nodes', '-keyout', `${name}.key`, '-out', `${name}.csr`, '-subj', csrSubj]);
      fs.writeFileSync(path.join(d, `${name}.ext`), ext);
      run(['x509', '-req', '-in', `${name}.csr`, '-CA', `${issuer}.pem`, '-CAkey', `${issuer}.key`, '-CAcreateserial', '-out',
        `${name}.pem`, '-days', '200', `-${md}`, '-extfile', `${name}.ext`]);
    };
    const RSA = ['-newkey', 'rsa:2048'];
    const P256 = ['-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256'];
    const LEAF = 'subjectAltName=DNS:localhost,IP:127.0.0.1\n';
    ca('root256', RSA, 'sha256');
    ca('root1', RSA, 'sha1');
    ca('ecroot', P256, 'sha256');
    sign('inter1', '/CN=inter1', RSA, 'root256', 'sha1', 'basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n');
    sign('leaf256', '/CN=localhost', RSA, 'root256', 'sha256', LEAF);
    sign('leafUnderSha1Root', '/CN=localhost', RSA, 'root1', 'sha256', LEAF);
    sign('leafSha1', '/CN=localhost', RSA, 'root256', 'sha1', LEAF);
    sign('leafUnderSha1Inter', '/CN=localhost', RSA, 'inter1', 'sha256', LEAF);
    fs.writeFileSync(path.join(d, 'leafUnderSha1Inter.chain.pem'),
      fs.readFileSync(path.join(d, 'leafUnderSha1Inter.pem'), 'utf8') + fs.readFileSync(path.join(d, 'inter1.pem'), 'utf8'));
    sign('leafEcdsaSha1', '/CN=localhost', P256, 'ecroot', 'sha1', LEAF);
    run(['req', '-x509', ...RSA, '-sha1', '-nodes', '-keyout', 'selfSha1.key', '-out', 'selfSha1.pem', '-days', '200',
      '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1']);
    return d;
  } catch { return null; }
}

before(() => { DIR = makeFixtures(); });
after(() => { if (DIR) fs.rmSync(DIR, { recursive: true, force: true }); });

function caseFor(t, { key, cert = key, ca = null, server = null, dropGetter = false }) {
  if (!DIR) {
    if (process.env.CI) assert.fail('openssl is required for these real-TLS legs — refusing to skip in CI');
    t.skip('openssl unavailable — cannot build the TLS fixtures (would hard-fail in CI)');
    return null;
  }
  const env = { ...process.env };
  if (ca) env.NODE_EXTRA_CA_CERTS = path.join(DIR, `${ca}.pem`); else delete env.NODE_EXTRA_CA_CERTS;
  if (dropGetter) env.NSA_TEST_DROP_SIGALG_GETTER = '1'; else delete env.NSA_TEST_DROP_SIGALG_GETTER;
  delete env.NODE_TEST_CONTEXT;
  const args = [HELPER, path.join(DIR, `${key}.key`), path.join(DIR, `${cert}.pem`), '127.0.0.1', ...(server ? [JSON.stringify(server)] : [])];
  const out = execFileSync(process.execPath, args, { env, encoding: 'utf8', timeout: 30000 });
  const i = out.lastIndexOf('@@RESULT@@');
  assert.ok(i >= 0, `the case printed no result: ${out.slice(-300)}`);
  return JSON.parse(out.slice(i + '@@RESULT@@'.length));
}
const sigChecks = (r) => r.otherChecks.filter((c) => /weak_signature$/.test(c));

// ── FOURTH QUADRANT FIRST ──────────────────────────────────────────────────────────────────────────────────────────────
test('(q, first) a SHA-256 leaf under a SHA-256 root: no signature finding; the algorithms are RECORDED, not "unknown"', (t) => {
  const r = caseFor(t, { key: 'leaf256', ca: 'root256' }); if (!r) return;
  assert.deepEqual(r.otherChecks, [], 'nothing is wrong with this certificate');
  assert.deepEqual(r.chainSigs, ['0:sha256WithRSAEncryption', '1:sha256WithRSAEncryption']);
  assert.deepEqual([r.certAuditSig.signatureAlgorithm, r.certAuditSig.signatureStrength], ['sha256WithRSAEncryption', 'assessed']);
});

test('(q) a SHA-1 self-signed ROOT above SHA-256 certificates: NO chain_weak_signature — an anchor\'s own signature is never verified', (t) => {
  const r = caseFor(t, { key: 'leafUnderSha1Root', ca: 'root1' }); if (!r) return;
  assert.deepEqual(r.chainSigs, ['0:sha256WithRSAEncryption', '1:sha1WithRSAEncryption'], 'the root\'s SHA-1 is recorded');
  assert.deepEqual(sigChecks(r), []);
});

test('(q) a SELF-SIGNED SHA-1 leaf: self_signed HIGH alone, naming the algorithm and why it is not graded — no weak_signature', (t) => {
  const r = caseFor(t, { key: 'selfSha1' }); if (!r) return;
  assert.deepEqual(sigChecks(r), []);
  assert.equal(r.certAuditSig.signatureAlgorithm, 'sha1WithRSAEncryption', 'the FACT is recorded; only the finding is skipped');
  const self = r.graded.find((g) => /self-signed/.test(g.title));
  assert.ok(self && self.severity === 'High', `graded: ${JSON.stringify(r.graded)}`);
  assert.match(self.title, /signed with sha1WithRSAEncryption — not graded on a self-signed certificate, whose signature no client verifies/);
});

// ── THE CHANGE ─────────────────────────────────────────────────────────────────────────────────────────────────────────
test('a CA-ISSUED SHA-1 leaf: weak_signature HIGH', (t) => {
  const r = caseFor(t, { key: 'leafSha1', ca: 'root256', server: SEC0_RSA }); if (!r) return;
  assert.deepEqual(sigChecks(r), ['high:weak_signature']);
  assert.ok(r.graded.some((g) => g.severity === 'High' && /Weak signature algorithm: sha1WithRSAEncryption/.test(g.title)));
  // Node's verifier also refuses it (UNSPECIFIED): the detail states the fact, not a CA-store cause (the ruling).
  assert.equal(r.caTrust.length, 1);
  assert.doesNotMatch(r.caTrust[0], /CA store/);
  assert.match(r.caTrust[0], /\(UNSPECIFIED\); the graded weak key \/ signature on this certificate is the actionable finding$/);
});

test('a SHA-1 INTERMEDIATE between a SHA-256 root and a SHA-256 leaf: chain_weak_signature', (t) => {
  const r = caseFor(t, { key: 'leafUnderSha1Inter', cert: 'leafUnderSha1Inter.chain', ca: 'root256', server: SEC0_RSA }); if (!r) return;
  assert.deepEqual(r.chainSigs.slice(0, 2), ['0:sha256WithRSAEncryption', '1:sha1WithRSAEncryption']);
  assert.deepEqual(sigChecks(r), ['medium:chain_weak_signature']);
});

test('an ecdsa-with-SHA1 leaf (a CA-issued EC certificate): weak_signature HIGH — the weak names cover ECDSA too', (t) => {
  const r = caseFor(t, { key: 'leafEcdsaSha1', ca: 'ecroot', server: SEC0_EC }); if (!r) return;
  assert.equal(r.certAuditSig.signatureAlgorithm, 'ecdsa-with-SHA1');
  assert.deepEqual(sigChecks(r), ['high:weak_signature']);
});

// ── A RUNTIME THAT CANNOT SAY ──────────────────────────────────────────────────────────────────────────────────────────
test('where Node cannot report the algorithm (Node 20): NOT ASSESSED on certAudit — and a SHA-1 leaf is not read as a pass', (t) => {
  for (const [key, ca, server] of [['leaf256', 'root256', null], ['leafSha1', 'root256', SEC0_RSA]]) {
    const r = caseFor(t, { key, ca, server, dropGetter: true }); if (!r) return;
    assert.deepEqual(sigChecks(r), [], `${key}: nothing graded on an unread algorithm`);
    assert.match(String(r.certAuditSig.signatureStrength), /^not assessed — /, `${key}: ${JSON.stringify(r.certAuditSig)}`);
    assert.notEqual(r.certAuditSig.signatureAlgorithm, 'unknown', `${key}: never the old "unknown"`);
  }
});
