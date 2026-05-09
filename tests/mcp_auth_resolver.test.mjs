// tests/mcp_auth_resolver.test.mjs
// ─────────────────────────────────────────────────────────────────────────────
// EE-SEC.1 — MCP auth key multi-source resolver tests.
//
// Resolution order (mirrors license-key resolver):
//   1. process.env.NSA_MCP_AUTH_KEY    (CI/CD precedence)
//   2. macOS Keychain (service=nsauditor-ai, account=NSA_MCP_AUTH_KEY)
//   3. ~/.nsauditor/.env (or $XDG_CONFIG_HOME/nsauditor/.env)
//
// Test seams (_keychainGet, _homeFileOverride) keep the suite hermetic
// — no real Keychain reads, no touching the user's home directory.
// ─────────────────────────────────────────────────────────────────────────────

import test from 'node:test';
import assert from 'node:assert/strict';
import { promises as fsp } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  resolveMcpAuthKey,
  reportMcpAuthSource,
  generateMcpAuthKey,
  validateMcpAuthKeyShape,
  MCP_AUTH_ENV_VAR,
  MCP_AUTH_KEY_PREFIX,
} from '../utils/mcp_auth.mjs';

// ── Helpers ──────────────────────────────────────────────────────────────────

async function withTempEnvFile(content, mode = 0o600) {
  const dir = await fsp.mkdtemp(join(tmpdir(), 'nsauditor-mcp-auth-test-'));
  const filePath = join(dir, '.env');
  await fsp.writeFile(filePath, content, { mode });
  return { filePath, cleanup: () => fsp.rm(dir, { recursive: true, force: true }) };
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

const SAMPLE_KEY_FROM_ENV =
  'nsa_mcp_envenvenvenvenvenvenvenvenvenvenvenvenvenvenv1';
const SAMPLE_KEY_FROM_KEYCHAIN =
  'nsa_mcp_keykeykeykeykeykeykeykeykeykeykeykeykeykeykey1';
const SAMPLE_KEY_FROM_FILE =
  'nsa_mcp_filfilfilfilfilfilfilfilfilfilfilfilfilfilfil1';

// ─────────────────────────────────────────────────────────────────────────────
// 1. env var — highest precedence
// ─────────────────────────────────────────────────────────────────────────────

test('EE-SEC.1: env var wins over Keychain + file', async () => {
  const restore = snapshotEnv(MCP_AUTH_ENV_VAR);
  process.env[MCP_AUTH_ENV_VAR] = SAMPLE_KEY_FROM_ENV;
  try {
    let kgetCalled = false;
    const result = await resolveMcpAuthKey({
      _keychainGet: async () => { kgetCalled = true; return SAMPLE_KEY_FROM_KEYCHAIN; },
      _homeFileOverride: '/nonexistent/path-should-not-be-read',
    });
    assert.equal(result, SAMPLE_KEY_FROM_ENV);
    assert.equal(kgetCalled, false, 'Keychain must not be queried when env var is set');
  } finally { restore(); }
});

// ─────────────────────────────────────────────────────────────────────────────
// 2. Keychain — second precedence
// ─────────────────────────────────────────────────────────────────────────────

test('EE-SEC.1: Keychain wins over file when env var is unset', async () => {
  const restore = snapshotEnv(MCP_AUTH_ENV_VAR);
  delete process.env[MCP_AUTH_ENV_VAR];
  const { filePath, cleanup } = await withTempEnvFile(
    `${MCP_AUTH_ENV_VAR}=${SAMPLE_KEY_FROM_FILE}\n`,
  );
  try {
    const result = await resolveMcpAuthKey({
      _keychainGet: async (account) => {
        assert.equal(account, MCP_AUTH_ENV_VAR);
        return SAMPLE_KEY_FROM_KEYCHAIN;
      },
      _homeFileOverride: filePath,
    });
    assert.equal(result, SAMPLE_KEY_FROM_KEYCHAIN);
  } finally {
    restore();
    await cleanup();
  }
});

test('EE-SEC.1: Keychain failure (throws) falls through to file silently', async () => {
  const restore = snapshotEnv(MCP_AUTH_ENV_VAR);
  delete process.env[MCP_AUTH_ENV_VAR];
  const { filePath, cleanup } = await withTempEnvFile(
    `${MCP_AUTH_ENV_VAR}=${SAMPLE_KEY_FROM_FILE}\n`,
  );
  try {
    const result = await resolveMcpAuthKey({
      _keychainGet: async () => { throw new Error('Keychain unavailable'); },
      _homeFileOverride: filePath,
    });
    assert.equal(result, SAMPLE_KEY_FROM_FILE);
  } finally {
    restore();
    await cleanup();
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// 3. File — third precedence
// ─────────────────────────────────────────────────────────────────────────────

test('EE-SEC.1: file is read when env + Keychain are empty', async () => {
  const restore = snapshotEnv(MCP_AUTH_ENV_VAR);
  delete process.env[MCP_AUTH_ENV_VAR];
  const { filePath, cleanup } = await withTempEnvFile(
    `# header\n${MCP_AUTH_ENV_VAR}=${SAMPLE_KEY_FROM_FILE}\nOTHER=value\n`,
  );
  try {
    const result = await resolveMcpAuthKey({
      _keychainGet: async () => null,
      _homeFileOverride: filePath,
    });
    assert.equal(result, SAMPLE_KEY_FROM_FILE);
  } finally {
    restore();
    await cleanup();
  }
});

test('EE-SEC.1: returns null when no source has a key', async () => {
  const restore = snapshotEnv(MCP_AUTH_ENV_VAR);
  delete process.env[MCP_AUTH_ENV_VAR];
  const { filePath, cleanup } = await withTempEnvFile('OTHER=value\n');
  try {
    const result = await resolveMcpAuthKey({
      _keychainGet: async () => null,
      _homeFileOverride: filePath,
    });
    assert.equal(result, null);
  } finally {
    restore();
    await cleanup();
  }
});

test('EE-SEC.1: returns null when file does not exist', async () => {
  const restore = snapshotEnv(MCP_AUTH_ENV_VAR);
  delete process.env[MCP_AUTH_ENV_VAR];
  try {
    const result = await resolveMcpAuthKey({
      _keychainGet: async () => null,
      _homeFileOverride: '/nonexistent/totally-not-there.env',
    });
    assert.equal(result, null);
  } finally { restore(); }
});

// ─────────────────────────────────────────────────────────────────────────────
// 4. reportMcpAuthSource — does not leak the key
// ─────────────────────────────────────────────────────────────────────────────

test('EE-SEC.1: reportMcpAuthSource returns "env" when env is set, no key value', async () => {
  const restore = snapshotEnv(MCP_AUTH_ENV_VAR);
  process.env[MCP_AUTH_ENV_VAR] = SAMPLE_KEY_FROM_ENV;
  try {
    const result = await reportMcpAuthSource({
      _keychainGet: async () => SAMPLE_KEY_FROM_KEYCHAIN,
      _homeFileOverride: '/nonexistent',
    });
    assert.equal(result.source, 'env');
    assert.equal(result.detail, MCP_AUTH_ENV_VAR);
    // Critical: the key value MUST NOT appear anywhere in the result.
    assert.equal(JSON.stringify(result).includes(SAMPLE_KEY_FROM_ENV), false);
  } finally { restore(); }
});

test('EE-SEC.1: reportMcpAuthSource returns "keychain" when only Keychain has the key', async () => {
  const restore = snapshotEnv(MCP_AUTH_ENV_VAR);
  delete process.env[MCP_AUTH_ENV_VAR];
  try {
    const result = await reportMcpAuthSource({
      _keychainGet: async () => SAMPLE_KEY_FROM_KEYCHAIN,
      _homeFileOverride: '/nonexistent',
    });
    assert.equal(result.source, 'keychain');
    assert.ok(result.detail.includes('Keychain'));
    assert.equal(JSON.stringify(result).includes(SAMPLE_KEY_FROM_KEYCHAIN), false);
  } finally { restore(); }
});

test('EE-SEC.1: reportMcpAuthSource returns "file" when only file has the key', async () => {
  const restore = snapshotEnv(MCP_AUTH_ENV_VAR);
  delete process.env[MCP_AUTH_ENV_VAR];
  const { filePath, cleanup } = await withTempEnvFile(
    `${MCP_AUTH_ENV_VAR}=${SAMPLE_KEY_FROM_FILE}\n`,
  );
  try {
    const result = await reportMcpAuthSource({
      _keychainGet: async () => null,
      _homeFileOverride: filePath,
    });
    assert.equal(result.source, 'file');
    assert.equal(result.detail, filePath);
    assert.equal(JSON.stringify(result).includes(SAMPLE_KEY_FROM_FILE), false);
  } finally {
    restore();
    await cleanup();
  }
});

test('EE-SEC.1: reportMcpAuthSource returns "unconfigured" when no source has a key', async () => {
  const restore = snapshotEnv(MCP_AUTH_ENV_VAR);
  delete process.env[MCP_AUTH_ENV_VAR];
  try {
    const result = await reportMcpAuthSource({
      _keychainGet: async () => null,
      _homeFileOverride: '/nonexistent',
    });
    assert.equal(result.source, 'unconfigured');
  } finally { restore(); }
});

// ─────────────────────────────────────────────────────────────────────────────
// 5. generateMcpAuthKey — entropy + format
// ─────────────────────────────────────────────────────────────────────────────

test('EE-SEC.1: generateMcpAuthKey produces a key with the prefix', () => {
  const k = generateMcpAuthKey();
  assert.ok(k.startsWith(MCP_AUTH_KEY_PREFIX));
});

test('EE-SEC.1: generateMcpAuthKey passes shape validation', () => {
  const k = generateMcpAuthKey();
  assert.deepEqual(validateMcpAuthKeyShape(k), { ok: true });
});

test('EE-SEC.1: two consecutive generated keys differ (entropy sanity)', () => {
  const a = generateMcpAuthKey();
  const b = generateMcpAuthKey();
  assert.notEqual(a, b);
});

test('EE-SEC.1: generated key body is base64url (no padding, no +/)', () => {
  const k = generateMcpAuthKey();
  const body = k.slice(MCP_AUTH_KEY_PREFIX.length);
  assert.ok(/^[A-Za-z0-9_-]+$/.test(body), `body "${body}" not base64url`);
});

// ─────────────────────────────────────────────────────────────────────────────
// 6. validateMcpAuthKeyShape — rejection cases
// ─────────────────────────────────────────────────────────────────────────────

test('EE-SEC.1: validateMcpAuthKeyShape rejects non-string input', () => {
  for (const bad of [null, undefined, 42, {}, []]) {
    const r = validateMcpAuthKeyShape(bad);
    assert.equal(r.ok, false);
    assert.ok(r.reason.includes('string'));
  }
});

test('EE-SEC.1: validateMcpAuthKeyShape rejects key without prefix', () => {
  const r = validateMcpAuthKeyShape('justsometextwithoutaprefix1234567890abcdef');
  assert.equal(r.ok, false);
  assert.ok(r.reason.includes(MCP_AUTH_KEY_PREFIX));
});

test('EE-SEC.1: validateMcpAuthKeyShape rejects too-short body', () => {
  const r = validateMcpAuthKeyShape('nsa_mcp_short');
  assert.equal(r.ok, false);
  assert.ok(r.reason.includes('length'));
});

test('EE-SEC.1: validateMcpAuthKeyShape rejects non-base64url chars', () => {
  // Body length is right (43) but contains a literal `=` which is not in base64url.
  const r = validateMcpAuthKeyShape(`nsa_mcp_${'a'.repeat(40)}===`);
  assert.equal(r.ok, false);
  assert.ok(r.reason.includes('base64url'));
});

test('EE-SEC.1: validateMcpAuthKeyShape accepts a freshly-generated key', () => {
  for (let i = 0; i < 20; i++) {
    const r = validateMcpAuthKeyShape(generateMcpAuthKey());
    assert.deepEqual(r, { ok: true });
  }
});
