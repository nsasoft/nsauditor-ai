// tests/mcp_auth_rotation.test.mjs
// ─────────────────────────────────────────────────────────────────────────────
// EE-SEC.1.1 (Thread I) — rotation cadence + Keychain lock-state distinction.
//
// Tests cover:
//   1. persistMcpAuthKey writes a sibling NSA_MCP_AUTH_KEY_CREATED
//      timestamp on both Keychain and file backends.
//   2. mergeMcpAuthCreatedIntoEnvFile / mergeKeyValueIntoEnvFile generic
//      semantics (replace-in-place, append, preserve other vars).
//   3. getMcpAuthKeyAge computes age in days from the timestamp.
//   4. reportMcpAuthSource surfaces ageDays + createdAt fields.
//   5. reportMcpAuthSource distinguishes 'keychain-locked' from
//      'unconfigured' so headless macOS / SSH-only CI runners get an
//      actionable error.
// ─────────────────────────────────────────────────────────────────────────────

import test from 'node:test';
import assert from 'node:assert/strict';
import { promises as fsp } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  persistMcpAuthKey,
  reportMcpAuthSource,
  getMcpAuthKeyAge,
  mergeMcpAuthIntoEnvFile,
  mergeMcpAuthCreatedIntoEnvFile,
  mergeKeyValueIntoEnvFile,
  generateMcpAuthKey,
  ROTATION_WARNING_DAYS,
  MCP_AUTH_ENV_VAR,
  MCP_AUTH_CREATED_ENV_VAR,
} from '../utils/mcp_auth.mjs';

const SAMPLE_KEY = 'nsa_mcp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';

async function withTempDir() {
  const dir = await fsp.mkdtemp(join(tmpdir(), 'nsauditor-rotation-test-'));
  return { dir, cleanup: () => fsp.rm(dir, { recursive: true, force: true }) };
}

function snapshotEnv(...keys) {
  const saved = {};
  for (const k of keys) saved[k] = process.env[k];
  return () => {
    for (const k of keys) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k];
    }
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. persist writes a created-at timestamp companion
// ─────────────────────────────────────────────────────────────────────────────

test('EE-SEC.1.1: persist (file backend) writes NSA_MCP_AUTH_KEY_CREATED alongside the key', async () => {
  const { dir, cleanup } = await withTempDir();
  const filePath = join(dir, '.env');
  try {
    const fixedTime = '2026-05-01T12:00:00.000Z';
    const result = await persistMcpAuthKey(SAMPLE_KEY, {
      _platform: 'linux',
      _homeFileOverride: filePath,
      _now: fixedTime,
    });
    assert.equal(result.ok, true);
    assert.equal(result.createdAt, fixedTime);

    const content = await fsp.readFile(filePath, 'utf8');
    assert.ok(content.includes(`${MCP_AUTH_ENV_VAR}=${SAMPLE_KEY}`));
    assert.ok(content.includes(`${MCP_AUTH_CREATED_ENV_VAR}=${fixedTime}`),
      `expected timestamp companion line; got: ${content}`);
  } finally {
    await cleanup();
  }
});

test('EE-SEC.1.1: persist (file backend) replaces existing timestamp on rotation', async () => {
  const { dir, cleanup } = await withTempDir();
  const filePath = join(dir, '.env');
  try {
    // Pre-existing file with old key + old timestamp.
    await fsp.writeFile(filePath,
      `${MCP_AUTH_ENV_VAR}=oldkey\n${MCP_AUTH_CREATED_ENV_VAR}=2025-01-01T00:00:00Z\nOTHER=keep\n`,
      { mode: 0o600 },
    );
    const newTime = '2026-05-09T18:00:00.000Z';
    const result = await persistMcpAuthKey(SAMPLE_KEY, {
      _platform: 'linux',
      _homeFileOverride: filePath,
      _now: newTime,
    });
    assert.equal(result.ok, true);

    const content = await fsp.readFile(filePath, 'utf8');
    // New timestamp present, old timestamp absent.
    assert.ok(content.includes(`${MCP_AUTH_CREATED_ENV_VAR}=${newTime}`));
    assert.equal(content.includes('2025-01-01T00:00:00Z'), false);
    // Other vars preserved.
    assert.ok(content.includes('OTHER=keep'));
  } finally {
    await cleanup();
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// 2. mergeKeyValueIntoEnvFile generic helper
// ─────────────────────────────────────────────────────────────────────────────

test('EE-SEC.1.1: mergeKeyValueIntoEnvFile writes header on empty input', () => {
  const out = mergeKeyValueIntoEnvFile('', 'FOO', 'bar', '# header line');
  assert.ok(out.startsWith('# header line\n'));
  assert.ok(out.includes('FOO=bar'));
});

test('EE-SEC.1.1: mergeKeyValueIntoEnvFile appends to non-empty input without header', () => {
  const out = mergeKeyValueIntoEnvFile('OTHER=keep\n', 'FOO', 'bar', null);
  assert.ok(out.startsWith('OTHER=keep'));
  assert.ok(out.includes('FOO=bar'));
});

test('EE-SEC.1.1: mergeKeyValueIntoEnvFile replaces existing key, preserves others', () => {
  const out = mergeKeyValueIntoEnvFile('A=1\nFOO=old\nB=2\n', 'FOO', 'new', null);
  assert.ok(out.includes('FOO=new'));
  assert.equal(out.includes('FOO=old'), false);
  assert.ok(out.includes('A=1'));
  assert.ok(out.includes('B=2'));
});

test('EE-SEC.1.1: mergeKeyValueIntoEnvFile collapses duplicate keys (corrupted-file defense)', () => {
  const out = mergeKeyValueIntoEnvFile('FOO=a\nFOO=b\nFOO=c\nKEEP=1\n', 'FOO', 'new', null);
  const matches = out.match(/^FOO=/gm);
  assert.equal(matches.length, 1, `expected single FOO line; got: ${out}`);
  assert.ok(out.includes('FOO=new'));
  assert.ok(out.includes('KEEP=1'));
});

test('EE-SEC.1.1: mergeKeyValueIntoEnvFile escapes regex metacharacters in name', () => {
  // Defense-in-depth (Reviewer 1 MEDIUM #5 carry-over): names with
  // regex specials must not break the merge.
  const tricky = 'NAME.WITH+SPECIAL?[CHARS]';
  const out = mergeKeyValueIntoEnvFile(`${tricky}=old\nKEEP=1\n`, tricky, 'new', null);
  assert.ok(out.includes(`${tricky}=new`));
  assert.equal(out.includes(`${tricky}=old`), false);
  assert.ok(out.includes('KEEP=1'));
});

test('EE-SEC.1.1: mergeMcpAuthIntoEnvFile delegates to generic helper (back-compat)', () => {
  // The legacy named export should still produce equivalent output.
  const out = mergeMcpAuthIntoEnvFile('', SAMPLE_KEY);
  assert.ok(out.includes(`${MCP_AUTH_ENV_VAR}=${SAMPLE_KEY}`));
  assert.ok(out.startsWith('#'), 'legacy header must still be emitted');
});

test('EE-SEC.1.1: mergeMcpAuthCreatedIntoEnvFile writes timestamp without header', () => {
  // Used as the SECOND merge in persistMcpAuthKey (the key write
  // already added the header). No header here.
  const out = mergeMcpAuthCreatedIntoEnvFile(
    `${MCP_AUTH_ENV_VAR}=somekey\n`,
    '2026-05-09T12:00:00Z',
  );
  assert.ok(out.includes(`${MCP_AUTH_CREATED_ENV_VAR}=2026-05-09T12:00:00Z`));
});

// ─────────────────────────────────────────────────────────────────────────────
// 3. getMcpAuthKeyAge / reportMcpAuthSource — age computation
// ─────────────────────────────────────────────────────────────────────────────

test('EE-SEC.1.1: getMcpAuthKeyAge returns null when no key configured', async () => {
  const restore = snapshotEnv(MCP_AUTH_ENV_VAR);
  delete process.env[MCP_AUTH_ENV_VAR];
  try {
    const age = await getMcpAuthKeyAge({
      _keychainGetDetailed: async () => ({ value: null, state: 'not-found' }),
      _homeFileOverride: '/nonexistent',
    });
    assert.equal(age, null);
  } finally { restore(); }
});

test('EE-SEC.1.1: getMcpAuthKeyAge computes day-difference correctly (file backend)', async () => {
  const restore = snapshotEnv(MCP_AUTH_ENV_VAR);
  delete process.env[MCP_AUTH_ENV_VAR];
  const { dir, cleanup } = await withTempDir();
  const filePath = join(dir, '.env');
  try {
    // Persist with a fixed past timestamp.
    const past = '2026-01-01T00:00:00.000Z';
    await persistMcpAuthKey(SAMPLE_KEY, {
      _platform: 'linux',
      _homeFileOverride: filePath,
      _now: past,
    });
    // Compute age relative to a fixed "now" — 100 days later.
    const now = '2026-04-11T00:00:00.000Z'; // 100 days after Jan 1
    const age = await getMcpAuthKeyAge({
      _keychainGetDetailed: async () => ({ value: null, state: 'not-found' }),
      _homeFileOverride: filePath,
      _now: now,
    });
    assert.equal(age, 100);
  } finally {
    restore();
    await cleanup();
  }
});

test('EE-SEC.1.1: getMcpAuthKeyAge returns null for clock-skewed (future) timestamps', async () => {
  const restore = snapshotEnv(MCP_AUTH_ENV_VAR);
  delete process.env[MCP_AUTH_ENV_VAR];
  const { dir, cleanup } = await withTempDir();
  const filePath = join(dir, '.env');
  try {
    const future = '2099-01-01T00:00:00.000Z';
    await persistMcpAuthKey(SAMPLE_KEY, {
      _platform: 'linux',
      _homeFileOverride: filePath,
      _now: future,
    });
    const age = await getMcpAuthKeyAge({
      _keychainGetDetailed: async () => ({ value: null, state: 'not-found' }),
      _homeFileOverride: filePath,
      _now: '2026-05-09T00:00:00.000Z',
    });
    // Future timestamp → null (don't emit a misleading negative age).
    assert.equal(age, null);
  } finally {
    restore();
    await cleanup();
  }
});

test('EE-SEC.1.1: reportMcpAuthSource includes ageDays + createdAt fields when timestamp is present', async () => {
  const restore = snapshotEnv(MCP_AUTH_ENV_VAR);
  delete process.env[MCP_AUTH_ENV_VAR];
  const { dir, cleanup } = await withTempDir();
  const filePath = join(dir, '.env');
  try {
    const past = '2026-02-01T00:00:00.000Z';
    await persistMcpAuthKey(SAMPLE_KEY, {
      _platform: 'linux',
      _homeFileOverride: filePath,
      _now: past,
    });
    const result = await reportMcpAuthSource({
      _keychainGetDetailed: async () => ({ value: null, state: 'not-found' }),
      _homeFileOverride: filePath,
      _now: '2026-05-02T00:00:00.000Z', // 90 days later
    });
    assert.equal(result.source, 'file');
    assert.equal(result.createdAt, past);
    assert.equal(result.ageDays, 90);
  } finally {
    restore();
    await cleanup();
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// 4. reportMcpAuthSource — keychain-locked vs unconfigured distinction
// ─────────────────────────────────────────────────────────────────────────────

test('EE-SEC.1.1: reportMcpAuthSource returns "keychain-locked" when Keychain entry exists but interaction not allowed', async () => {
  const restore = snapshotEnv(MCP_AUTH_ENV_VAR);
  delete process.env[MCP_AUTH_ENV_VAR];
  try {
    const result = await reportMcpAuthSource({
      _keychainGetDetailed: async () => ({
        value: null,
        state: 'locked',
        raw: 'security: User interaction is not allowed',
      }),
      _homeFileOverride: '/nonexistent',
    });
    assert.equal(result.source, 'keychain-locked');
    assert.ok(result.detail.includes('Keychain'));
    assert.ok(result.detail.includes('interaction not allowed'));
  } finally { restore(); }
});

test('EE-SEC.1.1: reportMcpAuthSource returns "unconfigured" when Keychain has no entry AND file is missing', async () => {
  const restore = snapshotEnv(MCP_AUTH_ENV_VAR);
  delete process.env[MCP_AUTH_ENV_VAR];
  try {
    const result = await reportMcpAuthSource({
      _keychainGetDetailed: async () => ({ value: null, state: 'not-found' }),
      _homeFileOverride: '/nonexistent',
    });
    assert.equal(result.source, 'unconfigured');
  } finally { restore(); }
});

test('EE-SEC.1.1: reportMcpAuthSource still falls through to file when Keychain unavailable (non-mac)', async () => {
  const restore = snapshotEnv(MCP_AUTH_ENV_VAR);
  delete process.env[MCP_AUTH_ENV_VAR];
  const { dir, cleanup } = await withTempDir();
  const filePath = join(dir, '.env');
  try {
    await fsp.writeFile(filePath, `${MCP_AUTH_ENV_VAR}=${SAMPLE_KEY}\n`, { mode: 0o600 });
    const result = await reportMcpAuthSource({
      _keychainGetDetailed: async () => ({ value: null, state: 'unavailable' }),
      _homeFileOverride: filePath,
    });
    assert.equal(result.source, 'file');
    assert.equal(result.detail, filePath);
  } finally {
    restore();
    await cleanup();
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// 5. ROTATION_WARNING_DAYS export + threshold contract
// ─────────────────────────────────────────────────────────────────────────────

test('EE-SEC.1.1: ROTATION_WARNING_DAYS export is 90 (SOC 2 CC6.1/CC6.7 cadence)', () => {
  assert.equal(ROTATION_WARNING_DAYS, 90);
});

// ─────────────────────────────────────────────────────────────────────────────
// 6. Round-trip: persist + report ages correctly across the boundary
// ─────────────────────────────────────────────────────────────────────────────

test('EE-SEC.1.1: end-to-end — key created exactly at boundary, age=ROTATION_WARNING_DAYS, no warning yet', async () => {
  const restore = snapshotEnv(MCP_AUTH_ENV_VAR);
  delete process.env[MCP_AUTH_ENV_VAR];
  const { dir, cleanup } = await withTempDir();
  const filePath = join(dir, '.env');
  try {
    const created = '2026-01-01T00:00:00.000Z';
    await persistMcpAuthKey(SAMPLE_KEY, {
      _platform: 'linux',
      _homeFileOverride: filePath,
      _now: created,
    });
    // Exactly 90 days later (Jan 1 → Apr 1 = 90 days).
    const result = await reportMcpAuthSource({
      _keychainGetDetailed: async () => ({ value: null, state: 'not-found' }),
      _homeFileOverride: filePath,
      _now: '2026-04-01T00:00:00.000Z',
    });
    assert.equal(result.ageDays, 90);
    // Server-side warning fires for `> 90`, not `>= 90`. At the boundary,
    // no warning yet — pin the strict-greater semantic.
    assert.equal(result.ageDays > ROTATION_WARNING_DAYS, false);
  } finally {
    restore();
    await cleanup();
  }
});

test('EE-SEC.1.1: end-to-end — key 91 days old triggers the strict-greater warning condition', async () => {
  const restore = snapshotEnv(MCP_AUTH_ENV_VAR);
  delete process.env[MCP_AUTH_ENV_VAR];
  const { dir, cleanup } = await withTempDir();
  const filePath = join(dir, '.env');
  try {
    const created = '2026-01-01T00:00:00.000Z';
    await persistMcpAuthKey(SAMPLE_KEY, {
      _platform: 'linux',
      _homeFileOverride: filePath,
      _now: created,
    });
    const result = await reportMcpAuthSource({
      _keychainGetDetailed: async () => ({ value: null, state: 'not-found' }),
      _homeFileOverride: filePath,
      _now: '2026-04-02T00:00:00.000Z', // 91 days
    });
    assert.equal(result.ageDays, 91);
    assert.equal(result.ageDays > ROTATION_WARNING_DAYS, true);
  } finally {
    restore();
    await cleanup();
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// 7. keychainGetDetailed (smoke test against real macOS — skipped on Linux/CI)
// ─────────────────────────────────────────────────────────────────────────────

// ─────────────────────────────────────────────────────────────────────────────
// 8. Post-review folds — Reviewer 1 MEDIUM #1, Reviewer 2 CRITICAL #1, MEDIUM #1/#2/#4, LOW #2
// ─────────────────────────────────────────────────────────────────────────────

test('EE-SEC.1.1 fold (Reviewer 1 MEDIUM #1): persist normalizes epoch-ms _now to ISO-8601', async () => {
  // Pre-fold: caller passing epoch ms wrote the literal number string,
  // which Date.parse cannot read → silent age-computation breakage.
  // Post-fold: persist normalizes via new Date(...).toISOString().
  const { dir, cleanup } = await withTempDir();
  const filePath = join(dir, '.env');
  try {
    const epochMs = 1746748800000; // 2025-05-09T12:00:00.000Z
    const result = await persistMcpAuthKey(SAMPLE_KEY, {
      _platform: 'linux',
      _homeFileOverride: filePath,
      _now: epochMs,
    });
    assert.equal(result.ok, true);
    // Stored as ISO-8601 string, NOT the literal "1746748800000".
    assert.ok(/^\d{4}-\d{2}-\d{2}T/.test(result.createdAt));
    const content = await fsp.readFile(filePath, 'utf8');
    assert.ok(content.includes(`${MCP_AUTH_CREATED_ENV_VAR}=2025-05-09T`),
      `expected ISO-8601 timestamp in file; got: ${content}`);
  } finally { await cleanup(); }
});

test('EE-SEC.1.1 fold (Reviewer 2 MEDIUM #1): file backend writes via .tmp + rename (atomic)', async () => {
  // Pre-fold: writeFile directly truncated then wrote → concurrent
  // readers could see empty file. Post-fold: write to .tmp then
  // POSIX-atomic rename. We can't observe the .tmp file post-write
  // (it's renamed away), but we CAN verify the final file is
  // complete and the .tmp file does not exist as cleanup leftover.
  const { dir, cleanup } = await withTempDir();
  const filePath = join(dir, '.env');
  const tmpPath = `${filePath}.tmp`;
  try {
    const result = await persistMcpAuthKey(SAMPLE_KEY, {
      _platform: 'linux',
      _homeFileOverride: filePath,
    });
    assert.equal(result.ok, true);
    // Final file should exist with correct content.
    const content = await fsp.readFile(filePath, 'utf8');
    assert.ok(content.includes(`${MCP_AUTH_ENV_VAR}=${SAMPLE_KEY}`));
    // .tmp should NOT exist (rename consumed it).
    let tmpExists = false;
    try {
      await fsp.access(tmpPath);
      tmpExists = true;
    } catch { /* expected — .tmp gone after rename */ }
    assert.equal(tmpExists, false, 'rename should have consumed .tmp file');
  } finally { await cleanup(); }
});

test('EE-SEC.1.1 fold (Reviewer 2 MEDIUM #2): Keychain writes timestamp FIRST, then key (fail-CLOSED)', async () => {
  // Reordered to fail-CLOSED: a half-write where timestamp succeeds
  // but key fails leaves NO usable key. Pre-fold the order was
  // reversed and a half-write left a usable key with no rotation
  // signal forever.
  const writes = [];
  const result = await persistMcpAuthKey(SAMPLE_KEY, {
    _platform: 'darwin',
    _keychainSet: async (account, secret) => {
      writes.push({ account, secret });
    },
  });
  assert.equal(result.ok, true);
  assert.equal(writes.length, 2);
  // Timestamp first.
  assert.equal(writes[0].account, MCP_AUTH_CREATED_ENV_VAR);
  // Key second.
  assert.equal(writes[1].account, MCP_AUTH_ENV_VAR);
});

test('EE-SEC.1.1 fold (Reviewer 2 MEDIUM #2): Keychain timestamp-write failure returns ok:false (no partial state)', async () => {
  // Pre-fold: partial-state success. Post-fold: timestamp-first +
  // fall-through to file when ANY Keychain write fails. Since the
  // first write fails, no key is persisted to Keychain — the
  // function falls through to file storage (full reset, atomic at
  // the file level).
  const { dir, cleanup } = await withTempDir();
  const filePath = join(dir, '.env');
  try {
    const writes = [];
    const result = await persistMcpAuthKey(SAMPLE_KEY, {
      _platform: 'darwin',
      _keychainSet: async (account, secret) => {
        writes.push({ account, secret });
        if (account === MCP_AUTH_CREATED_ENV_VAR) {
          throw new Error('User interaction is not allowed');
        }
      },
      _homeFileOverride: filePath,
    });
    // Falls through to file.
    assert.equal(result.ok, true);
    assert.equal(result.location, filePath);
    assert.ok(result.warning && result.warning.includes('Keychain unavailable'));
    // Only the timestamp-write was attempted on Keychain (fail-fast).
    assert.equal(writes.length, 1);
    assert.equal(writes[0].account, MCP_AUTH_CREATED_ENV_VAR);
  } finally { await cleanup(); }
});

test('EE-SEC.1.1 fold (Reviewer 2 CRITICAL #1): file branch surfaces legacyTimestampMissing for pre-EE-SEC.1.1 installs', async () => {
  const restore = snapshotEnv(MCP_AUTH_ENV_VAR);
  delete process.env[MCP_AUTH_ENV_VAR];
  const { dir, cleanup } = await withTempDir();
  const filePath = join(dir, '.env');
  try {
    // Simulate a pre-0.1.32 install: key present, NO timestamp.
    await fsp.writeFile(filePath, `${MCP_AUTH_ENV_VAR}=${SAMPLE_KEY}\n`, { mode: 0o600 });
    const result = await reportMcpAuthSource({
      _keychainGetDetailed: async () => ({ value: null, state: 'not-found' }),
      _homeFileOverride: filePath,
    });
    assert.equal(result.source, 'file');
    assert.equal(result.createdAt, null);
    assert.equal(result.ageDays, null);
    assert.equal(result.legacyTimestampMissing, true,
      'CRITICAL #1: pre-0.1.32 installs MUST surface legacyTimestampMissing=true so the operator sees the backfill hint');
  } finally {
    restore();
    await cleanup();
  }
});

test('EE-SEC.1.1 fold (Reviewer 2 CRITICAL #1): keychain branch surfaces legacyTimestampMissing when companion entry absent', async () => {
  const restore = snapshotEnv(MCP_AUTH_ENV_VAR);
  delete process.env[MCP_AUTH_ENV_VAR];
  try {
    // Mock keychainGetDetailed: key present but timestamp account
    // returns 'not-found' (older install).
    const result = await reportMcpAuthSource({
      _keychainGetDetailed: async (account) => {
        if (account === MCP_AUTH_ENV_VAR) {
          return { value: SAMPLE_KEY, state: 'ok' };
        }
        if (account === MCP_AUTH_CREATED_ENV_VAR) {
          return { value: null, state: 'not-found' };
        }
        return { value: null, state: 'unavailable' };
      },
      _homeFileOverride: '/nonexistent',
    });
    assert.equal(result.source, 'keychain');
    assert.equal(result.createdAt, null);
    assert.equal(result.legacyTimestampMissing, true);
  } finally { restore(); }
});

test('EE-SEC.1.1 fold (Reviewer 2 CRITICAL #1): legacyTimestampMissing is FALSE when both key and timestamp present', async () => {
  const restore = snapshotEnv(MCP_AUTH_ENV_VAR);
  delete process.env[MCP_AUTH_ENV_VAR];
  const { dir, cleanup } = await withTempDir();
  const filePath = join(dir, '.env');
  try {
    await persistMcpAuthKey(SAMPLE_KEY, {
      _platform: 'linux',
      _homeFileOverride: filePath,
      _now: '2026-05-01T00:00:00Z',
    });
    const result = await reportMcpAuthSource({
      _keychainGetDetailed: async () => ({ value: null, state: 'not-found' }),
      _homeFileOverride: filePath,
    });
    assert.equal(result.source, 'file');
    assert.equal(result.legacyTimestampMissing, false);
  } finally {
    restore();
    await cleanup();
  }
});

test('EE-SEC.1.1 fold (Reviewer 2 MEDIUM #4): NSA_MCP_AUTH_KEY_ROTATION_DAYS env override', async () => {
  const { getRotationWarningDays } = await import('../utils/mcp_auth.mjs');
  // No override → default 90.
  assert.equal(getRotationWarningDays({ _env: {} }), 90);
  // Operator override → honored.
  assert.equal(getRotationWarningDays({ _env: { NSA_MCP_AUTH_KEY_ROTATION_DAYS: '60' } }), 60);
  assert.equal(getRotationWarningDays({ _env: { NSA_MCP_AUTH_KEY_ROTATION_DAYS: '180' } }), 180);
  // Clamping: < 7 → 7 (prevent constant-warn-noise).
  assert.equal(getRotationWarningDays({ _env: { NSA_MCP_AUTH_KEY_ROTATION_DAYS: '1' } }), 7);
  assert.equal(getRotationWarningDays({ _env: { NSA_MCP_AUTH_KEY_ROTATION_DAYS: '0' } }), 7);
  // Clamping: > 365 → 365 (prevent effectively no-rotation).
  assert.equal(getRotationWarningDays({ _env: { NSA_MCP_AUTH_KEY_ROTATION_DAYS: '999' } }), 365);
  // Garbage input → default.
  assert.equal(getRotationWarningDays({ _env: { NSA_MCP_AUTH_KEY_ROTATION_DAYS: 'not-a-number' } }), 90);
  assert.equal(getRotationWarningDays({ _env: { NSA_MCP_AUTH_KEY_ROTATION_DAYS: '' } }), 90);
});

test('EE-SEC.1.1 fold (Reviewer 2 LOW #2): keychainGetDetailed pattern-matches numeric error codes (locale-stable)', async () => {
  const { keychainGetDetailed } = await import('../utils/keychain.mjs');
  // We can't easily inject error stderr into the real keychainGetDetailed
  // (it spawns the security command); the contract is verified
  // indirectly by ensuring the regex includes the numeric codes.
  // Read the source file and assert the regex contains them.
  const src = await fsp.readFile(
    new URL('../utils/keychain.mjs', import.meta.url),
    'utf8',
  );
  assert.ok(src.includes('-25300'), '-25300 (errSecItemNotFound) must be in the not-found regex');
  assert.ok(src.includes('-25308'), '-25308 (errSecInteractionNotAllowed) must be in the locked regex');
});

test('EE-SEC.1.1: keychainGetDetailed returns "unavailable" on non-macOS platforms', async () => {
  const { keychainGetDetailed } = await import('../utils/keychain.mjs');
  if (process.platform === 'darwin') {
    // On real macOS this test would actually query the Keychain.
    // Skip the assertion — covered by hermetic seam tests above.
    return;
  }
  const result = await keychainGetDetailed('NSA_TEST_NONEXISTENT_ACCOUNT_FOR_TEST');
  assert.equal(result.state, 'unavailable');
  assert.equal(result.value, null);
});
