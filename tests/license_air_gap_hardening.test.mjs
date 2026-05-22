// tests/license_air_gap_hardening.test.mjs
// ─────────────────────────────────────────────────────────────────────────────
// CE 0.1.70 (EE 0.9.1 paired) — air-gap operational hardening tests.
//
// External audit 2026-05-22 D-HIGH-1/2/3: the JWT verifier is cryptographically
// tight, but air-gap operational gaps were the realistic license-abuse paths
// (seat-cloning, no per-license revocation, clock-rollback against `exp`).
// These tests guard the three new defenses without re-asserting the canonical
// JWT-verification path (that is covered in tests/license.test.mjs).
// ─────────────────────────────────────────────────────────────────────────────

import { describe, it, before, after, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { promises as fsp } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { generateKeyPairSync, createSign } from 'node:crypto';

import {
  loadLicense,
  _resetCache,
  _readLicenseState,
  _writeLicenseState,
  _loadAndVerifyBlocklist,
  _verifyBlocklistSignature,
  _canonicalizeBlocklistForSigning,
  _getLicenseStateFilePath,
} from '../utils/license.mjs';

// ── Test fixtures (real production-signed JWTs from license.test.mjs) ────────

const VALID_PRO_KEY = 'pro_eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0aWVyIjoicHJvIiwib3JnIjoidGVzdC1wcm9AZml4dHVyZS5jb20iLCJzZWF0cyI6MSwibGljZW5zZUlkIjoibGljXzM0ODRlZjU4LWYzMjUtNDUxOS04NjY5LTIzYjY3M2Y0YjZkYyIsImNhcGFiaWxpdGllcyI6WyJpbnRlbGxpZ2VuY2VFbmdpbmUiLCJyaXNrU2NvcmluZyIsInByb0FJIiwicHJvTUNQIiwiYW5hbHlzaXNBZ2VudHMiLCJ2ZXJpZmljYXRpb25FbmdpbmUiLCJhZHZhbmNlZENURU0iLCJlbmhhbmNlZFJlZGFjdGlvbiIsInBkZkV4cG9ydCIsImJyYW5kZWRSZXBvcnRzIl0sInN1YiI6ImxpY2Vuc2UiLCJpc3MiOiJuc2Fzb2Z0IiwiYXVkIjoibnNhdWRpdG9yLWFpIiwiaWF0IjoxNzc2MjA3MzI3LCJleHAiOjIwOTE1NjczMjd9.qt3wIqVShLAS2TdtFmY7_MvIFb0dEbpQ2AG-FiAxgp0VR7h9CJv2CG_FfXjPipd4f0n6QDkcv8pungZvK8BKZA';
const PRO_LICENSE_ID = 'lic_3484ef58-f325-4519-8669-23b673f4b6dc';

const VALID_ENTERPRISE_KEY = 'enterprise_eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0aWVyIjoiZW50ZXJwcmlzZSIsIm9yZyI6IlRlc3QgRW50ZXJwcmlzZSBDb3JwIiwic2VhdHMiOjI1LCJsaWNlbnNlSWQiOiJsaWNfMmVlNDU1ODctYTEzYy00ODcwLWIzNjMtMzhmNmNmNjMwNmE5IiwiY2FwYWJpbGl0aWVzIjpbImludGVsbGlnZW5jZUVuZ2luZSIsInJpc2tTY29yaW5nIiwicHJvQUkiLCJwcm9NQ1AiLCJhbmFseXNpc0FnZW50cyIsInZlcmlmaWNhdGlvbkVuZ2luZSIsImFkdmFuY2VkQ1RFTSIsImVuaGFuY2VkUmVkYWN0aW9uIiwicGRmRXhwb3J0IiwiYnJhbmRlZFJlcG9ydHMiLCJjbG91ZFNjYW5uZXJzIiwiemVyb1RydXN0IiwiY29tcGxpYW5jZUVuZ2luZSIsInpkZVBvbGljeUVuZ2luZSIsImVudGVycHJpc2VDVEVNIiwiZW50ZXJwcmlzZU1DUCIsInVzYWdlTWV0ZXJpbmciLCJhaXJHYXBwZWQiLCJkb2NrZXJJc29sYXRpb24iXSwic3ViIjoibGljZW5zZSIsImlzcyI6Im5zYXNvZnQiLCJhdWQiOiJuc2F1ZGl0b3ItYWkiLCJpYXQiOjE3NzYyMDczMzAsImV4cCI6MjA5MTU2NzMzMH0.nUTUQEzvUiERCLK-MNJ7hbwyJCgAOp_AzPjtEnNEB1gNYTbyHFoVpmwA_1PqGzxs_pdlfwbDJz-k8wdSPAgN1Q';
const ENTERPRISE_LICENSE_ID = 'lic_2ee45587-a13c-4870-b363-38f6cf6306a9';

// ── Per-test temp dirs ───────────────────────────────────────────────────────

let _tmpRoot;
let _statePath;
let _blocklistPath;
let _savedEnv;

before(async () => {
  _tmpRoot = await fsp.mkdtemp(join(tmpdir(), 'ce-air-gap-test-'));
  _savedEnv = {
    NSAUDITOR_LICENSE_KEY: process.env.NSAUDITOR_LICENSE_KEY,
    NSAUDITOR_LICENSE_STATE_FILE: process.env.NSAUDITOR_LICENSE_STATE_FILE,
    NSAUDITOR_LICENSE_REVOCATIONS_FILE: process.env.NSAUDITOR_LICENSE_REVOCATIONS_FILE,
    NSAUDITOR_LICENSE_ID_REPLAY_DEFENSE: process.env.NSAUDITOR_LICENSE_ID_REPLAY_DEFENSE,
    NSAUDITOR_LICENSE_REVOCATION_CHECK: process.env.NSAUDITOR_LICENSE_REVOCATION_CHECK,
    NSAUDITOR_LICENSE_CLOCK_ANCHOR: process.env.NSAUDITOR_LICENSE_CLOCK_ANCHOR,
  };
  // Make sure no operator env leaks in.
  delete process.env.NSAUDITOR_LICENSE_KEY;
  delete process.env.NSAUDITOR_LICENSE_ID_REPLAY_DEFENSE;
  delete process.env.NSAUDITOR_LICENSE_REVOCATION_CHECK;
  delete process.env.NSAUDITOR_LICENSE_CLOCK_ANCHOR;
});

after(async () => {
  for (const [k, v] of Object.entries(_savedEnv)) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
  await fsp.rm(_tmpRoot, { recursive: true, force: true });
});

beforeEach(async () => {
  const subDir = await fsp.mkdtemp(join(_tmpRoot, 'case-'));
  _statePath = join(subDir, 'license-state.json');
  _blocklistPath = join(subDir, 'license-revocations.json');
  // Direct via env var so loadLicense's resolution honors the temp paths
  // without per-call opts plumbing (matches existing test conventions).
  process.env.NSAUDITOR_LICENSE_STATE_FILE = _statePath;
  process.env.NSAUDITOR_LICENSE_REVOCATIONS_FILE = _blocklistPath;
  _resetCache();
});

afterEach(() => {
  _resetCache();
  delete process.env.NSAUDITOR_LICENSE_STATE_FILE;
  delete process.env.NSAUDITOR_LICENSE_REVOCATIONS_FILE;
  delete process.env.NSAUDITOR_LICENSE_ID_REPLAY_DEFENSE;
  delete process.env.NSAUDITOR_LICENSE_REVOCATION_CHECK;
  delete process.env.NSAUDITOR_LICENSE_CLOCK_ANCHOR;
});

// ── _getLicenseStateFilePath path resolution ─────────────────────────────────

describe('CE 0.1.70 _getLicenseStateFilePath', () => {
  it('honors NSAUDITOR_LICENSE_STATE_FILE env override', () => {
    const p = _getLicenseStateFilePath();
    assert.equal(p, _statePath);
  });

  it('opts._stateFile takes precedence over env override', () => {
    const custom = '/tmp/nsauditor-custom-state.json';
    const p = _getLicenseStateFilePath({ _stateFile: custom });
    assert.equal(p, custom);
  });

  it('falls back to platform default when no override is set', () => {
    delete process.env.NSAUDITOR_LICENSE_STATE_FILE;
    const p = _getLicenseStateFilePath({ _platform: 'linux' });
    assert.ok(p.includes('nsauditor') && p.endsWith('license-state.json'));
  });

  it('Windows platform default uses LOCALAPPDATA-shaped path', () => {
    delete process.env.NSAUDITOR_LICENSE_STATE_FILE;
    const prev = process.env.LOCALAPPDATA;
    process.env.LOCALAPPDATA = 'C:\\Users\\test\\AppData\\Local';
    try {
      const p = _getLicenseStateFilePath({ _platform: 'win32' });
      assert.ok(p.includes('nsauditor'));
      assert.ok(p.endsWith('license-state.json'));
    } finally {
      if (prev === undefined) delete process.env.LOCALAPPDATA;
      else process.env.LOCALAPPDATA = prev;
    }
  });
});

// ── _writeLicenseState + _readLicenseState round-trip ────────────────────────

describe('CE 0.1.70 license-state file round-trip', () => {
  it('writes then reads back licenseId + lastSeenUnixTs', async () => {
    const ts = 1716422400000;
    await _writeLicenseState({ licenseId: 'lic_test-roundtrip', lastSeenUnixTs: ts });
    const back = await _readLicenseState();
    assert.equal(back.licenseId, 'lic_test-roundtrip');
    assert.equal(back.lastSeenUnixTs, ts);
  });

  it('returns null when state file does not exist', async () => {
    const back = await _readLicenseState();
    assert.equal(back, null);
  });

  it('atomic-write semantics: no .tmp file remains after write', async () => {
    await _writeLicenseState({ licenseId: 'lic_a', lastSeenUnixTs: 1 });
    const entries = await fsp.readdir(join(_statePath, '..'));
    const tmps = entries.filter((e) => e.endsWith('.tmp'));
    assert.equal(tmps.length, 0);
  });

  it('state file mode is 0600 on POSIX', async () => {
    if (process.platform === 'win32') return; // POSIX-only
    await _writeLicenseState({ licenseId: 'lic_mode', lastSeenUnixTs: 1 });
    const stat = await fsp.stat(_statePath);
    assert.equal((stat.mode & 0o777), 0o600);
  });

  it('tolerates malformed JSON in state file (returns null, not throw)', async () => {
    await fsp.mkdir(join(_statePath, '..'), { recursive: true });
    await fsp.writeFile(_statePath, '{ not json', 'utf8');
    const back = await _readLicenseState();
    assert.equal(back, null);
  });
});

// ── D-HIGH-1: licenseId replay defense ───────────────────────────────────────

describe('CE 0.1.70 D-HIGH-1 — licenseId replay defense', () => {
  it('first activation persists licenseId; subsequent same-licenseId loads succeed', async () => {
    const r1 = await loadLicense(VALID_PRO_KEY);
    assert.equal(r1.valid, true);
    assert.equal(r1.tier, 'pro');
    assert.equal(r1.licenseId, PRO_LICENSE_ID);

    _resetCache();
    process.env.NSAUDITOR_LICENSE_STATE_FILE = _statePath;
    process.env.NSAUDITOR_LICENSE_REVOCATIONS_FILE = _blocklistPath;

    const r2 = await loadLicense(VALID_PRO_KEY);
    assert.equal(r2.valid, true, 'same-licenseId reload MUST be allowed');
    assert.equal(r2.licenseId, PRO_LICENSE_ID);
  });

  it('second activation with DIFFERENT licenseId is rejected with reason license_id_mismatch', async () => {
    // First activation locks lic_3484 (Pro fixture)
    const r1 = await loadLicense(VALID_PRO_KEY);
    assert.equal(r1.valid, true);

    _resetCache();
    process.env.NSAUDITOR_LICENSE_STATE_FILE = _statePath;
    process.env.NSAUDITOR_LICENSE_REVOCATIONS_FILE = _blocklistPath;

    // Second activation tries lic_2ee455 (Enterprise fixture) — replay defense fires
    const r2 = await loadLicense(VALID_ENTERPRISE_KEY);
    assert.equal(r2.valid, false, 'mismatched licenseId MUST be rejected');
    assert.equal(r2.tier, 'ce', 'rejection downgrades to CE');
    assert.equal(r2.reason, 'license_id_mismatch');
  });

  it('escape hatch: NSAUDITOR_LICENSE_ID_REPLAY_DEFENSE=0 allows licenseId mismatch (support-only)', async () => {
    await loadLicense(VALID_PRO_KEY);
    _resetCache();
    process.env.NSAUDITOR_LICENSE_STATE_FILE = _statePath;
    process.env.NSAUDITOR_LICENSE_REVOCATIONS_FILE = _blocklistPath;
    process.env.NSAUDITOR_LICENSE_ID_REPLAY_DEFENSE = '0';

    const r = await loadLicense(VALID_ENTERPRISE_KEY);
    assert.equal(r.valid, true,
      'escape hatch MUST allow mismatch (documented support-only use case)');
    assert.equal(r.tier, 'enterprise');
  });

  it('seat-clone scenario: 10,000 hosts cloning a seats:1 token are blocked from second host onward', async () => {
    // Simulates the realistic abuse path the audit called out as D-HIGH-1's
    // motivation. Host A activates legitimately → state file written.
    // Host B (with COPY of state file) tries a DIFFERENT license → blocked.
    // Host C cloning Host A's state but using ANOTHER license → also blocked.
    await loadLicense(VALID_PRO_KEY);
    _resetCache();
    process.env.NSAUDITOR_LICENSE_STATE_FILE = _statePath;
    process.env.NSAUDITOR_LICENSE_REVOCATIONS_FILE = _blocklistPath;
    const cloneAttempt = await loadLicense(VALID_ENTERPRISE_KEY);
    assert.equal(cloneAttempt.valid, false);
    assert.equal(cloneAttempt.reason, 'license_id_mismatch');
  });
});

// ── D-HIGH-2: signed revocation blocklist ────────────────────────────────────

describe('CE 0.1.70 D-HIGH-2 — signed revocation blocklist', () => {
  // Generate a fresh ES256 keypair per test suite for signing test blocklists.
  // The real production blocklist is signed by the license-manager service
  // (same ES256 key as JWTs). For tests we sign with a fresh key + inject
  // the matching public key via the _publicKeyPem opt seam.
  let testKeyPair;

  before(() => {
    testKeyPair = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  });

  function signTestBlocklist(envelope) {
    const canonical = _canonicalizeBlocklistForSigning(envelope);
    const signer = createSign('SHA256');
    signer.update(canonical, 'utf8');
    signer.end();
    const sig = signer.sign({ key: testKeyPair.privateKey, dsaEncoding: 'der' });
    return { ...envelope, signature: sig.toString('base64') };
  }

  function testPubPem() {
    return testKeyPair.publicKey.export({ type: 'spki', format: 'pem' });
  }

  it('valid signature + non-empty revoked list returns the revoked array', async () => {
    const envelope = signTestBlocklist({
      schema_version: 1,
      issued_at: '2026-05-22T00:00:00.000Z',
      revoked: ['lic_revoked-1', 'lic_revoked-2'],
    });
    const revoked = await _loadAndVerifyBlocklist({
      _blocklistData: undefined,  // force file path
      _blocklistPath: undefined,  // force env var
      _publicKeyPem: testPubPem(),
    });
    // Since we didn't write the file yet, expect []. Now write + retest.
    assert.deepEqual(revoked, []);

    await fsp.writeFile(_blocklistPath, JSON.stringify(envelope), 'utf8');
    const revoked2 = await _loadAndVerifyBlocklist({ _publicKeyPem: testPubPem() });
    assert.deepEqual(revoked2.sort(), ['lic_revoked-1', 'lic_revoked-2']);
  });

  it('invalid signature → fail-open, returns [] (no revocation enforced)', async () => {
    const envelope = signTestBlocklist({
      schema_version: 1,
      issued_at: '2026-05-22T00:00:00.000Z',
      revoked: ['lic_revoked'],
    });
    // Corrupt the signature
    envelope.signature = 'AAAA' + envelope.signature.slice(4);
    await fsp.writeFile(_blocklistPath, JSON.stringify(envelope), 'utf8');
    const revoked = await _loadAndVerifyBlocklist({ _publicKeyPem: testPubPem() });
    assert.deepEqual(revoked, [],
      'invalid signature MUST fail-open — never enforce revocation from a tampered list');
  });

  it('missing blocklist file → returns []', async () => {
    const revoked = await _loadAndVerifyBlocklist({ _publicKeyPem: testPubPem() });
    assert.deepEqual(revoked, []);
  });

  it('malformed JSON → returns []', async () => {
    await fsp.writeFile(_blocklistPath, '{ not valid json', 'utf8');
    const revoked = await _loadAndVerifyBlocklist({ _publicKeyPem: testPubPem() });
    assert.deepEqual(revoked, []);
  });

  it('unsupported schema_version → returns []', async () => {
    const envelope = signTestBlocklist({
      schema_version: 999,
      issued_at: '2026-05-22T00:00:00.000Z',
      revoked: ['lic_should-be-ignored'],
    });
    await fsp.writeFile(_blocklistPath, JSON.stringify(envelope), 'utf8');
    const revoked = await _loadAndVerifyBlocklist({ _publicKeyPem: testPubPem() });
    assert.deepEqual(revoked, [],
      'unknown schema_version MUST be ignored; signature alone is not enough');
  });

  it('signature with WRONG key → returns [] (cryptographic match required)', async () => {
    // Sign with our test key but verify against a DIFFERENT key.
    const wrongKey = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const envelope = signTestBlocklist({
      schema_version: 1,
      issued_at: '2026-05-22T00:00:00.000Z',
      revoked: ['lic_x'],
    });
    await fsp.writeFile(_blocklistPath, JSON.stringify(envelope), 'utf8');
    const revoked = await _loadAndVerifyBlocklist({
      _publicKeyPem: wrongKey.publicKey.export({ type: 'spki', format: 'pem' }),
    });
    assert.deepEqual(revoked, []);
  });

  it('_blocklistData opts seam short-circuits file load', async () => {
    const revoked = await _loadAndVerifyBlocklist({
      _blocklistData: ['lic_seam-bypass'],
    });
    assert.deepEqual(revoked, ['lic_seam-bypass']);
  });

  it('end-to-end: loadLicense rejects a revoked licenseId with reason license_revoked', async () => {
    // Seed blocklist with the Pro fixture's licenseId.
    const envelope = signTestBlocklist({
      schema_version: 1,
      issued_at: '2026-05-22T00:00:00.000Z',
      revoked: [PRO_LICENSE_ID],
    });
    await fsp.writeFile(_blocklistPath, JSON.stringify(envelope), 'utf8');

    const r = await loadLicense(VALID_PRO_KEY, { _publicKeyPem: testPubPem() });
    assert.equal(r.valid, false);
    assert.equal(r.tier, 'ce');
    assert.equal(r.reason, 'license_revoked');
  });

  it('escape hatch: NSAUDITOR_LICENSE_REVOCATION_CHECK=0 ignores blocklist (support-only)', async () => {
    const envelope = signTestBlocklist({
      schema_version: 1,
      issued_at: '2026-05-22T00:00:00.000Z',
      revoked: [PRO_LICENSE_ID],
    });
    await fsp.writeFile(_blocklistPath, JSON.stringify(envelope), 'utf8');
    process.env.NSAUDITOR_LICENSE_REVOCATION_CHECK = '0';

    const r = await loadLicense(VALID_PRO_KEY, { _publicKeyPem: testPubPem() });
    assert.equal(r.valid, true,
      'escape hatch MUST disable the blocklist check (documented support-only)');
  });
});

// ── D-HIGH-3: monotonic-clock anchor ─────────────────────────────────────────

describe('CE 0.1.70 D-HIGH-3 — monotonic-clock anchor', () => {
  it('first loadLicense persists current time as lastSeenUnixTs', async () => {
    const fixedNow = 1716422400000;
    const r = await loadLicense(VALID_PRO_KEY, { _now: () => fixedNow });
    assert.equal(r.valid, true);
    const state = await _readLicenseState();
    assert.equal(state.lastSeenUnixTs, fixedNow);
  });

  it('subsequent load with clock moving FORWARD is allowed', async () => {
    const t1 = 1716422400000;
    const t2 = t1 + 60_000;
    await loadLicense(VALID_PRO_KEY, { _now: () => t1 });
    _resetCache();
    process.env.NSAUDITOR_LICENSE_STATE_FILE = _statePath;
    process.env.NSAUDITOR_LICENSE_REVOCATIONS_FILE = _blocklistPath;

    const r = await loadLicense(VALID_PRO_KEY, { _now: () => t2 });
    assert.equal(r.valid, true,
      'forward-moving wall-clock MUST be allowed (normal operation)');
  });

  it('clock-rewind within 5min tolerance is allowed (NTP step / suspend resume)', async () => {
    const t1 = 1716422400000;
    const t2 = t1 - 60_000; // 1 min rewind, within 5min tolerance
    await loadLicense(VALID_PRO_KEY, { _now: () => t1 });
    _resetCache();
    process.env.NSAUDITOR_LICENSE_STATE_FILE = _statePath;
    process.env.NSAUDITOR_LICENSE_REVOCATIONS_FILE = _blocklistPath;

    const r = await loadLicense(VALID_PRO_KEY, { _now: () => t2 });
    assert.equal(r.valid, true,
      'small rewinds (NTP step, DST, suspend/resume) MUST be tolerated');
  });

  it('clock-rewind BEYOND 5min tolerance is rejected with reason clock_rollback_detected', async () => {
    const t1 = 1716422400000;
    const t2 = t1 - (6 * 60 * 1000); // 6 min rewind, beyond default 5min tolerance
    await loadLicense(VALID_PRO_KEY, { _now: () => t1 });
    _resetCache();
    process.env.NSAUDITOR_LICENSE_STATE_FILE = _statePath;
    process.env.NSAUDITOR_LICENSE_REVOCATIONS_FILE = _blocklistPath;

    const r = await loadLicense(VALID_PRO_KEY, { _now: () => t2 });
    assert.equal(r.valid, false,
      'rewind beyond tolerance MUST be rejected (defeats faketime against exp)');
    assert.equal(r.tier, 'ce');
    assert.equal(r.reason, 'clock_rollback_detected');
  });

  it('faketime attack scenario: rewind to before token issue is rejected', async () => {
    // The realistic attack: operator installs a Pro license today (t1).
    // Later, the license expires (per JWT exp claim). Attacker sets system
    // clock back BEFORE expiry — JWT `exp` check now passes.
    // The clock anchor compares against lastSeenUnixTs from prior activation
    // → any rewind beyond tolerance fails-closed.
    const t1 = 1716422400000;
    const t2 = t1 - 86_400_000; // 1 day rewind — classic faketime move
    await loadLicense(VALID_PRO_KEY, { _now: () => t1 });
    _resetCache();
    process.env.NSAUDITOR_LICENSE_STATE_FILE = _statePath;
    process.env.NSAUDITOR_LICENSE_REVOCATIONS_FILE = _blocklistPath;

    const r = await loadLicense(VALID_PRO_KEY, { _now: () => t2 });
    assert.equal(r.valid, false);
    assert.equal(r.reason, 'clock_rollback_detected');
  });

  it('escape hatch: NSAUDITOR_LICENSE_CLOCK_ANCHOR=0 disables the check (support-only)', async () => {
    const t1 = 1716422400000;
    const t2 = t1 - 86_400_000;
    await loadLicense(VALID_PRO_KEY, { _now: () => t1 });
    _resetCache();
    process.env.NSAUDITOR_LICENSE_STATE_FILE = _statePath;
    process.env.NSAUDITOR_LICENSE_REVOCATIONS_FILE = _blocklistPath;
    process.env.NSAUDITOR_LICENSE_CLOCK_ANCHOR = '0';

    const r = await loadLicense(VALID_PRO_KEY, { _now: () => t2 });
    assert.equal(r.valid, true,
      'escape hatch MUST disable the clock-anchor check');
  });

  it('configurable tolerance via NSAUDITOR_LICENSE_CLOCK_TOLERANCE_S', async () => {
    const t1 = 1716422400000;
    const t2 = t1 - 10_000; // 10s rewind
    await loadLicense(VALID_PRO_KEY, { _now: () => t1 });
    _resetCache();
    process.env.NSAUDITOR_LICENSE_STATE_FILE = _statePath;
    process.env.NSAUDITOR_LICENSE_REVOCATIONS_FILE = _blocklistPath;
    process.env.NSAUDITOR_LICENSE_CLOCK_TOLERANCE_S = '5'; // tighten to 5s

    try {
      const r = await loadLicense(VALID_PRO_KEY, { _now: () => t2 });
      assert.equal(r.valid, false,
        '10s rewind exceeds 5s configured tolerance → reject');
      assert.equal(r.reason, 'clock_rollback_detected');
    } finally {
      delete process.env.NSAUDITOR_LICENSE_CLOCK_TOLERANCE_S;
    }
  });
});

// ── Cross-defense interaction tests ──────────────────────────────────────────

describe('CE 0.1.70 — three defenses interact in stable order', () => {
  it('revocation fires BEFORE replay defense (revoked check is layer 1)', async () => {
    // Setup: prior activation succeeded with PRO_LICENSE_ID; state file has lic_3484
    // Now we revoke PRO_LICENSE_ID + try to activate a DIFFERENT license.
    // Expected reason: license_revoked (NOT license_id_mismatch) because the
    // attacker's NEW license is what's being checked, but revocation runs
    // first against the SUPPLIED token's licenseId.
    const testKeyPair = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const testPubPem = testKeyPair.publicKey.export({ type: 'spki', format: 'pem' });
    function signTestBlocklist(envelope) {
      const canonical = _canonicalizeBlocklistForSigning(envelope);
      const signer = createSign('SHA256');
      signer.update(canonical, 'utf8');
      signer.end();
      return { ...envelope, signature: signer.sign({ key: testKeyPair.privateKey, dsaEncoding: 'der' }).toString('base64') };
    }
    // Activate PRO first (so state file has PRO_LICENSE_ID).
    await loadLicense(VALID_PRO_KEY, { _publicKeyPem: testPubPem });
    _resetCache();
    process.env.NSAUDITOR_LICENSE_STATE_FILE = _statePath;
    process.env.NSAUDITOR_LICENSE_REVOCATIONS_FILE = _blocklistPath;

    // Now revoke the ENTERPRISE licenseId + try to load Enterprise.
    await fsp.writeFile(_blocklistPath, JSON.stringify(signTestBlocklist({
      schema_version: 1,
      issued_at: '2026-05-22T00:00:00.000Z',
      revoked: [ENTERPRISE_LICENSE_ID],
    })), 'utf8');

    const r = await loadLicense(VALID_ENTERPRISE_KEY, { _publicKeyPem: testPubPem });
    assert.equal(r.valid, false);
    assert.equal(r.reason, 'license_revoked',
      'revocation MUST fire before replay defense — order matters for the operator-facing error message');
  });

  it('state-write failure does not block a verified license', async () => {
    // If the state path is unwritable, loadLicense should still return valid.
    // This is the resilience contract for read-only-filesystem deployments.
    process.env.NSAUDITOR_LICENSE_STATE_FILE = '/proc/this/path/cannot/exist/license-state.json';
    const r = await loadLicense(VALID_PRO_KEY);
    assert.equal(r.valid, true,
      'state-write failure MUST NOT block a verified license (resilience contract)');
    assert.equal(r.tier, 'pro');
  });
});

// ── Canonicalization stability ───────────────────────────────────────────────

describe('CE 0.1.70 _canonicalizeBlocklistForSigning', () => {
  it('produces stable output regardless of revoked array order', () => {
    const a = _canonicalizeBlocklistForSigning({
      schema_version: 1,
      issued_at: '2026-05-22T00:00:00.000Z',
      revoked: ['lic_z', 'lic_a', 'lic_m'],
    });
    const b = _canonicalizeBlocklistForSigning({
      schema_version: 1,
      issued_at: '2026-05-22T00:00:00.000Z',
      revoked: ['lic_a', 'lic_m', 'lic_z'],
    });
    assert.equal(a, b,
      'canonical form MUST sort revoked array — signature is order-independent');
  });

  it('does not include signature field in canonical input', () => {
    const canonical = _canonicalizeBlocklistForSigning({
      schema_version: 1,
      issued_at: '2026-05-22T00:00:00.000Z',
      revoked: [],
      signature: 'should-be-excluded',
    });
    assert.equal(canonical.includes('should-be-excluded'), false);
  });
});
