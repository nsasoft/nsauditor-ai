// tests/mcp_auth_persist.test.mjs
// ─────────────────────────────────────────────────────────────────────────────
// EE-SEC.1 — MCP auth key persistence + cross-platform routing.
//
// Mirrors license_persist.test.mjs structure. Test seams keep the suite
// hermetic (no real Keychain writes, no touching the user's home
// directory). The merge-into-env-file helper has its own coverage so
// the multi-occurrence + CRLF + preserve-other-vars semantics are
// pinned independently.
// ─────────────────────────────────────────────────────────────────────────────

import test from 'node:test';
import assert from 'node:assert/strict';
import { promises as fsp } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  persistMcpAuthKey,
  mergeMcpAuthIntoEnvFile,
  generateMcpAuthKey,
  MCP_AUTH_ENV_VAR,
} from '../utils/mcp_auth.mjs';

// ── Helpers ──────────────────────────────────────────────────────────────────

async function withTempDir() {
  const dir = await fsp.mkdtemp(join(tmpdir(), 'nsauditor-mcp-persist-test-'));
  return { dir, cleanup: () => fsp.rm(dir, { recursive: true, force: true }) };
}

const SAMPLE_KEY = 'nsa_mcp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const SAMPLE_KEY_2 = 'nsa_mcp_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB';

// ─────────────────────────────────────────────────────────────────────────────
// 1. validation rejection
// ─────────────────────────────────────────────────────────────────────────────

test('EE-SEC.1: persistMcpAuthKey rejects malformed key with reason', async () => {
  const result = await persistMcpAuthKey('not-a-valid-key', { _platform: 'linux' });
  assert.equal(result.ok, false);
  assert.ok(result.error.includes('persistMcpAuthKey'));
});

test('EE-SEC.1: persistMcpAuthKey rejects empty string', async () => {
  const result = await persistMcpAuthKey('', { _platform: 'linux' });
  assert.equal(result.ok, false);
});

test('EE-SEC.1: persistMcpAuthKey rejects non-string', async () => {
  for (const bad of [null, undefined, 42, {}, []]) {
    const result = await persistMcpAuthKey(bad, { _platform: 'linux' });
    assert.equal(result.ok, false);
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// 2. macOS — Keychain success path
// ─────────────────────────────────────────────────────────────────────────────

test('EE-SEC.1: darwin platform writes to Keychain via _keychainSet (key + EE-SEC.1.1 timestamp companion)', async () => {
  // EE-SEC.1.1 (Thread I): persist now writes BOTH the key and a
  // sibling NSA_MCP_AUTH_KEY_CREATED timestamp for rotation cadence.
  const writes = [];
  const result = await persistMcpAuthKey(SAMPLE_KEY, {
    _platform: 'darwin',
    _keychainSet: async (account, secret) => {
      writes.push({ account, secret });
    },
  });
  assert.equal(result.ok, true);
  assert.ok(result.location.includes('Keychain'));
  // EE-SEC.1.1 MEDIUM #2 fold (post-review): timestamp written FIRST,
  // then key — half-write fails CLOSED (no usable key without timestamp).
  assert.equal(writes.length, 2, `expected 2 writes (timestamp + key), got ${writes.length}`);
  assert.equal(writes[0].account, 'NSA_MCP_AUTH_KEY_CREATED');
  assert.ok(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/.test(writes[0].secret));
  assert.equal(writes[1].account, MCP_AUTH_ENV_VAR);
  assert.equal(writes[1].secret, SAMPLE_KEY);
  assert.equal(result.createdAt, writes[0].secret);
});

// ─────────────────────────────────────────────────────────────────────────────
// 3. macOS — Keychain failure → file fallback with WARNING
// ─────────────────────────────────────────────────────────────────────────────

test('EE-SEC.1: darwin Keychain failure falls back to file with warning', async () => {
  const { dir, cleanup } = await withTempDir();
  const filePath = join(dir, '.env');
  try {
    const result = await persistMcpAuthKey(SAMPLE_KEY, {
      _platform: 'darwin',
      _keychainSet: async () => { throw new Error('security daemon unavailable'); },
      _homeFileOverride: filePath,
    });
    assert.equal(result.ok, true);
    assert.equal(result.location, filePath);
    assert.ok(result.warning, 'must surface keychain-fallback warning');
    assert.ok(result.warning.includes('Keychain unavailable'));

    const content = await fsp.readFile(filePath, 'utf8');
    assert.ok(content.includes(`${MCP_AUTH_ENV_VAR}=${SAMPLE_KEY}`));
  } finally {
    await cleanup();
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// 4. Linux — file path
// ─────────────────────────────────────────────────────────────────────────────

test('EE-SEC.1: linux platform writes to file with mode 0600', async () => {
  const { dir, cleanup } = await withTempDir();
  const filePath = join(dir, '.env');
  try {
    const result = await persistMcpAuthKey(SAMPLE_KEY, {
      _platform: 'linux',
      _homeFileOverride: filePath,
    });
    assert.equal(result.ok, true);
    assert.equal(result.location, filePath);
    assert.equal(result.warning, undefined, 'no Keychain warning on non-darwin');

    const stat = await fsp.stat(filePath);
    assert.equal(stat.mode & 0o777, 0o600, `expected mode 0600, got ${(stat.mode & 0o777).toString(8)}`);
  } finally {
    await cleanup();
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// 5. Windows — file path (no chmod attempt)
// ─────────────────────────────────────────────────────────────────────────────

test('EE-SEC.1: win32 platform writes to file without chmod', async () => {
  const { dir, cleanup } = await withTempDir();
  const filePath = join(dir, '.env');
  try {
    const result = await persistMcpAuthKey(SAMPLE_KEY, {
      _platform: 'win32',
      _homeFileOverride: filePath,
    });
    assert.equal(result.ok, true);
    assert.equal(result.location, filePath);

    const content = await fsp.readFile(filePath, 'utf8');
    assert.ok(content.includes(`${MCP_AUTH_ENV_VAR}=${SAMPLE_KEY}`));
  } finally {
    await cleanup();
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// 6. Preserves other env vars in existing file
// ─────────────────────────────────────────────────────────────────────────────

test('EE-SEC.1: persist preserves OTHER vars in existing dotenv file', async () => {
  const { dir, cleanup } = await withTempDir();
  const filePath = join(dir, '.env');
  await fsp.writeFile(filePath, `# comment\nNSAUDITOR_LICENSE_KEY=pro_eyJexisting\nOTHER=value\n`);
  try {
    const result = await persistMcpAuthKey(SAMPLE_KEY, {
      _platform: 'linux',
      _homeFileOverride: filePath,
    });
    assert.equal(result.ok, true);

    const content = await fsp.readFile(filePath, 'utf8');
    assert.ok(content.includes('NSAUDITOR_LICENSE_KEY=pro_eyJexisting'),
      'license key must be preserved');
    assert.ok(content.includes('OTHER=value'), 'other vars must be preserved');
    assert.ok(content.includes(`${MCP_AUTH_ENV_VAR}=${SAMPLE_KEY}`),
      'MCP key must be appended');
  } finally {
    await cleanup();
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// 7. Replaces existing MCP key on rotation
// ─────────────────────────────────────────────────────────────────────────────

test('EE-SEC.1: persist replaces existing MCP key (rotate-key flow)', async () => {
  const { dir, cleanup } = await withTempDir();
  const filePath = join(dir, '.env');
  await fsp.writeFile(filePath, `${MCP_AUTH_ENV_VAR}=${SAMPLE_KEY}\nOTHER=keep\n`);
  try {
    const result = await persistMcpAuthKey(SAMPLE_KEY_2, {
      _platform: 'linux',
      _homeFileOverride: filePath,
    });
    assert.equal(result.ok, true);

    const content = await fsp.readFile(filePath, 'utf8');
    assert.ok(content.includes(`${MCP_AUTH_ENV_VAR}=${SAMPLE_KEY_2}`), 'new key written');
    assert.equal(content.includes(SAMPLE_KEY), false, 'old key must be removed');
    assert.ok(content.includes('OTHER=keep'), 'other vars preserved');
  } finally {
    await cleanup();
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// 8. mergeMcpAuthIntoEnvFile — direct unit tests
// ─────────────────────────────────────────────────────────────────────────────

test('EE-SEC.1: mergeMcpAuthIntoEnvFile writes header for empty input', () => {
  const out = mergeMcpAuthIntoEnvFile('', SAMPLE_KEY);
  assert.ok(out.startsWith('#'), 'must start with header comment');
  assert.ok(out.includes(`${MCP_AUTH_ENV_VAR}=${SAMPLE_KEY}`));
  assert.ok(out.endsWith('\n'));
});

test('EE-SEC.1: mergeMcpAuthIntoEnvFile appends to non-empty input without header', () => {
  const existing = 'OTHER=value\n';
  const out = mergeMcpAuthIntoEnvFile(existing, SAMPLE_KEY);
  assert.ok(out.startsWith('OTHER=value'), 'existing content preserved verbatim');
  assert.ok(out.includes(`${MCP_AUTH_ENV_VAR}=${SAMPLE_KEY}`));
});

test('EE-SEC.1: mergeMcpAuthIntoEnvFile replaces existing key in place', () => {
  const existing = `OTHER=keep\n${MCP_AUTH_ENV_VAR}=${SAMPLE_KEY}\nMORE=data\n`;
  const out = mergeMcpAuthIntoEnvFile(existing, SAMPLE_KEY_2);
  assert.ok(out.includes(`${MCP_AUTH_ENV_VAR}=${SAMPLE_KEY_2}`));
  assert.equal(out.includes(SAMPLE_KEY), false);
  assert.ok(out.includes('OTHER=keep'));
  assert.ok(out.includes('MORE=data'));
});

test('EE-SEC.1: mergeMcpAuthIntoEnvFile collapses duplicate keys (corrupted-file defense)', () => {
  // A corrupted file with two MCP_AUTH_ENV_VAR lines — replace the
  // first, remove the rest. dotenv parses last-wins, so without this
  // mergeMcpAuthIntoEnvFile would leave the OLD key visible to
  // resolveMcpAuthKey while reporting "install succeeded."
  const existing = `${MCP_AUTH_ENV_VAR}=${SAMPLE_KEY}\nOTHER=keep\n${MCP_AUTH_ENV_VAR}=${SAMPLE_KEY}\n`;
  const out = mergeMcpAuthIntoEnvFile(existing, SAMPLE_KEY_2);
  // exactly ONE occurrence of MCP_AUTH_ENV_VAR= should remain
  const matches = out.match(new RegExp(`^${MCP_AUTH_ENV_VAR}=`, 'gm'));
  assert.equal(matches.length, 1);
  assert.ok(out.includes(`${MCP_AUTH_ENV_VAR}=${SAMPLE_KEY_2}`));
  assert.equal(out.includes(SAMPLE_KEY), false);
});

test('EE-SEC.1: mergeMcpAuthIntoEnvFile preserves CRLF line endings', () => {
  const existing = `OTHER=value\r\n${MCP_AUTH_ENV_VAR}=${SAMPLE_KEY}\r\nMORE=x\r\n`;
  const out = mergeMcpAuthIntoEnvFile(existing, SAMPLE_KEY_2);
  // OTHER and MORE lines must keep their \r\n
  assert.ok(out.includes('OTHER=value\r\n'));
  assert.ok(out.includes('MORE=x\r\n'));
  assert.ok(out.includes(`${MCP_AUTH_ENV_VAR}=${SAMPLE_KEY_2}`));
});

// ─────────────────────────────────────────────────────────────────────────────
// 9. Round-trip — persisted key resolves back via the resolver
// ─────────────────────────────────────────────────────────────────────────────

test('EE-SEC.1 fold (Reviewer 2 MEDIUM #1): parent dir is chmod 0700 even when pre-existing at 0755', async () => {
  // mkdir mode is honored only on FIRST creation; existing dirs are
  // not chmod'd by mkdir alone. This test pre-creates the parent at
  // 0755 (matching the license-key flow's behavior pre-fold) and
  // verifies that persistMcpAuthKey explicitly chmods it back to 0700.
  // Skip on win32 — Windows has no POSIX mode bits.
  if (process.platform === 'win32') return;
  const { dir, cleanup } = await withTempDir();
  const subdir = join(dir, 'preexisting');
  await fsp.mkdir(subdir, { mode: 0o755 });
  const filePath = join(subdir, '.env');
  try {
    const result = await persistMcpAuthKey(SAMPLE_KEY, {
      _platform: 'linux',
      _homeFileOverride: filePath,
    });
    assert.equal(result.ok, true);
    const dirStat = await fsp.stat(subdir);
    assert.equal(dirStat.mode & 0o777, 0o700,
      `expected parent dir mode 0700 after persist, got ${(dirStat.mode & 0o777).toString(8)}`);
  } finally {
    await cleanup();
  }
});

test('EE-SEC.1: persisted key round-trips via resolveMcpAuthKey (file path)', async () => {
  const { resolveMcpAuthKey } = await import('../utils/mcp_auth.mjs');
  const { dir, cleanup } = await withTempDir();
  const filePath = join(dir, '.env');
  // Snapshot env to ensure resolver doesn't pick up an actual env var.
  const saved = process.env[MCP_AUTH_ENV_VAR];
  delete process.env[MCP_AUTH_ENV_VAR];
  try {
    const key = generateMcpAuthKey();
    const persisted = await persistMcpAuthKey(key, {
      _platform: 'linux',
      _homeFileOverride: filePath,
    });
    assert.equal(persisted.ok, true);

    const resolved = await resolveMcpAuthKey({
      _keychainGet: async () => null,
      _homeFileOverride: filePath,
    });
    assert.equal(resolved, key);
  } finally {
    if (saved === undefined) delete process.env[MCP_AUTH_ENV_VAR];
    else process.env[MCP_AUTH_ENV_VAR] = saved;
    await cleanup();
  }
});
