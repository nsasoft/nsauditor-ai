// tests/mcp_server_auth.test.mjs
// ─────────────────────────────────────────────────────────────────────────────
// EE-SEC.1 — MCP server startup auth check tests.
//
// Tests the authorizeMcpServerStartup() function that mcp_server.mjs
// invokes BEFORE accepting any tool calls. Each test exercises the
// public API directly with hermetic test seams (no spawning real
// subprocesses, no touching real Keychain).
//
// Critical security invariants pinned here:
//   1. No configured key → REFUSE startup (with actionable error).
//   2. Configured key + no env key presented → REFUSE.
//   3. Configured key + wrong env key → REFUSE (constant-time compare).
//   4. Configured key + correct env key → ACCEPT.
//   5. NSA_MCP_AUTH_DISABLE=1 → ACCEPT with bypassed flag (caller emits warn).
//   6. Constant-time comparison: equal-length wrong key returns false.
//   7. Length-mismatched comparison returns false (no crash).
// ─────────────────────────────────────────────────────────────────────────────

import test from 'node:test';
import assert from 'node:assert/strict';
import { promises as fsp } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  authorizeMcpServerStartup,
  constantTimeMcpKeyEquals,
  generateMcpAuthKey,
  MCP_AUTH_ENV_VAR,
  MCP_AUTH_DISABLE_ENV_VAR,
} from '../utils/mcp_auth.mjs';

const SAMPLE_KEY_A = 'nsa_mcp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const SAMPLE_KEY_B = 'nsa_mcp_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB';

async function withTempEnvFile(content) {
  const dir = await fsp.mkdtemp(join(tmpdir(), 'nsauditor-server-auth-test-'));
  const filePath = join(dir, '.env');
  await fsp.writeFile(filePath, content, { mode: 0o600 });
  return { filePath, cleanup: () => fsp.rm(dir, { recursive: true, force: true }) };
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. NO key configured → REFUSE
// ─────────────────────────────────────────────────────────────────────────────

test('EE-SEC.1 server-auth: refuses startup when NO key is configured anywhere', async () => {
  const result = await authorizeMcpServerStartup({
    _env: {}, // no NSA_MCP_AUTH_KEY, no NSA_MCP_AUTH_DISABLE
    _keychainGet: async () => null,
    _homeFileOverride: '/nonexistent/no-file-here',
  });
  assert.equal(result.ok, false);
  assert.ok(result.error.includes('not configured'));
  assert.ok(result.error.includes('mcp install-key'),
    'error must point operator at the install command');
});

// ─────────────────────────────────────────────────────────────────────────────
// 2. Key in storage, NO env key presented → REFUSE
// ─────────────────────────────────────────────────────────────────────────────

test('EE-SEC.1 server-auth: refuses when storage has key but env var is unset', async () => {
  const result = await authorizeMcpServerStartup({
    _env: {}, // env var missing
    _keychainGet: async () => SAMPLE_KEY_A,
    _homeFileOverride: '/nonexistent',
  });
  assert.equal(result.ok, false);
  assert.ok(result.error.includes('env var is not set'));
  assert.ok(result.error.includes('Claude Desktop config'));
});

// ─────────────────────────────────────────────────────────────────────────────
// 3. Key in storage, WRONG env key → REFUSE
// ─────────────────────────────────────────────────────────────────────────────

test('EE-SEC.1 server-auth: refuses when env key does NOT match stored key', async () => {
  const result = await authorizeMcpServerStartup({
    _env: { [MCP_AUTH_ENV_VAR]: SAMPLE_KEY_B },
    _keychainGet: async () => SAMPLE_KEY_A,
    _homeFileOverride: '/nonexistent',
  });
  assert.equal(result.ok, false);
  assert.ok(result.error.includes('does not match'));
  assert.ok(result.error.includes('rotate-key'),
    'error must point operator at rotation as the likely cause');
});

// ─────────────────────────────────────────────────────────────────────────────
// 4. Match → ACCEPT
// ─────────────────────────────────────────────────────────────────────────────

test('EE-SEC.1 server-auth: accepts when env key matches Keychain-stored key', async () => {
  const result = await authorizeMcpServerStartup({
    _env: { [MCP_AUTH_ENV_VAR]: SAMPLE_KEY_A },
    _keychainGet: async () => SAMPLE_KEY_A,
    _homeFileOverride: '/nonexistent',
  });
  assert.deepEqual(result, { ok: true });
});

test('EE-SEC.1 server-auth: accepts when env key matches file-stored key', async () => {
  const { filePath, cleanup } = await withTempEnvFile(
    `${MCP_AUTH_ENV_VAR}=${SAMPLE_KEY_A}\n`,
  );
  try {
    const result = await authorizeMcpServerStartup({
      _env: { [MCP_AUTH_ENV_VAR]: SAMPLE_KEY_A },
      _keychainGet: async () => null, // Keychain empty
      _homeFileOverride: filePath,
    });
    assert.deepEqual(result, { ok: true });
  } finally {
    await cleanup();
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// 5. NSA_MCP_AUTH_DISABLE=1 escape hatch
// ─────────────────────────────────────────────────────────────────────────────

test('EE-SEC.1 server-auth: NSA_MCP_AUTH_DISABLE=1 bypasses check', async () => {
  const result = await authorizeMcpServerStartup({
    _env: { [MCP_AUTH_DISABLE_ENV_VAR]: '1' },
    // No env key, no keychain, no file — bypass should still succeed.
    _keychainGet: async () => null,
    _homeFileOverride: '/nonexistent',
  });
  assert.equal(result.ok, true);
  assert.equal(result.bypassed, true,
    'caller relies on bypassed flag to emit stderr warning');
});

test('EE-SEC.1 server-auth: NSA_MCP_AUTH_DISABLE=1 takes precedence over auth FAILURE', async () => {
  // Even with a configured key + wrong env key (which would normally
  // refuse), the disable flag short-circuits to ok:true. This is the
  // correct behavior for an escape hatch — operator-acknowledged risk.
  const result = await authorizeMcpServerStartup({
    _env: {
      [MCP_AUTH_DISABLE_ENV_VAR]: '1',
      [MCP_AUTH_ENV_VAR]: SAMPLE_KEY_B,
    },
    _keychainGet: async () => SAMPLE_KEY_A,
    _homeFileOverride: '/nonexistent',
  });
  assert.equal(result.ok, true);
  assert.equal(result.bypassed, true);
});

test('EE-SEC.1 server-auth: NSA_MCP_AUTH_DISABLE=other-value does NOT bypass', async () => {
  // Only the literal "1" disables; other values are ignored to prevent
  // accidental bypass from typos / logging-config files / stale envs.
  for (const val of ['0', 'true', 'yes', 'TRUE', '']) {
    const result = await authorizeMcpServerStartup({
      _env: { [MCP_AUTH_DISABLE_ENV_VAR]: val },
      _keychainGet: async () => null,
      _homeFileOverride: '/nonexistent',
    });
    assert.equal(result.ok, false, `value "${val}" must NOT bypass`);
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// 6. constantTimeMcpKeyEquals — security-critical helper
// ─────────────────────────────────────────────────────────────────────────────

test('EE-SEC.1: constantTimeMcpKeyEquals returns true for identical strings', () => {
  const k = generateMcpAuthKey();
  assert.equal(constantTimeMcpKeyEquals(k, k), true);
});

test('EE-SEC.1: constantTimeMcpKeyEquals returns false for equal-length-different strings', () => {
  // Same length, different bytes — exercises the actual timingSafeEqual path.
  assert.equal(constantTimeMcpKeyEquals(SAMPLE_KEY_A, SAMPLE_KEY_B), false);
});

test('EE-SEC.1: constantTimeMcpKeyEquals returns false for length-mismatched strings (no crash)', () => {
  assert.equal(constantTimeMcpKeyEquals('short', 'much longer than short'), false);
});

test('EE-SEC.1: constantTimeMcpKeyEquals rejects non-string args without throwing', () => {
  assert.equal(constantTimeMcpKeyEquals(null, 'x'), false);
  assert.equal(constantTimeMcpKeyEquals('x', null), false);
  assert.equal(constantTimeMcpKeyEquals(undefined, undefined), false);
  assert.equal(constantTimeMcpKeyEquals(42, 42), false);
});

test('EE-SEC.1: constantTimeMcpKeyEquals returns true for two empty strings (helper allows; server rejects empty separately)', () => {
  // Two empty strings ARE equal under timingSafeEqual semantics. The
  // helper does not special-case empty — the server's storage check
  // (authorizeMcpServerStartup) rejects when the configured key is
  // null/empty BEFORE this comparator is called, so empty/empty
  // matches at the helper level cannot lead to a real bypass.
  assert.equal(constantTimeMcpKeyEquals('', ''), true);
});

// ─────────────────────────────────────────────────────────────────────────────
// 7. Behavior under length-extension (env longer than stored)
// ─────────────────────────────────────────────────────────────────────────────

test('EE-SEC.1 server-auth: refuses when presented key is a prefix of stored key', async () => {
  // Defensive — without timingSafeEqual length-mismatch handling, a
  // truncation attack could leak byte-by-byte. Pin the negative case.
  const stored = SAMPLE_KEY_A;
  const presented = stored.slice(0, stored.length - 1); // off by one char
  const result = await authorizeMcpServerStartup({
    _env: { [MCP_AUTH_ENV_VAR]: presented },
    _keychainGet: async () => stored,
    _homeFileOverride: '/nonexistent',
  });
  assert.equal(result.ok, false);
});

test('EE-SEC.1 server-auth: refuses when presented key is longer than stored key', async () => {
  const stored = SAMPLE_KEY_A;
  const presented = stored + 'X'; // appended char
  const result = await authorizeMcpServerStartup({
    _env: { [MCP_AUTH_ENV_VAR]: presented },
    _keychainGet: async () => stored,
    _homeFileOverride: '/nonexistent',
  });
  assert.equal(result.ok, false);
});

// ─────────────────────────────────────────────────────────────────────────────
// 8. Storage precedence: Keychain wins over file for the EXPECTED key
// ─────────────────────────────────────────────────────────────────────────────

test('EE-SEC.1 server-auth: Keychain-stored key wins over file when both exist', async () => {
  const { filePath, cleanup } = await withTempEnvFile(
    `${MCP_AUTH_ENV_VAR}=${SAMPLE_KEY_B}\n`,
  );
  try {
    // Env presents Key A. Storage has Key A in Keychain + Key B in file.
    // The Keychain copy must win → match succeeds.
    const result = await authorizeMcpServerStartup({
      _env: { [MCP_AUTH_ENV_VAR]: SAMPLE_KEY_A },
      _keychainGet: async () => SAMPLE_KEY_A,
      _homeFileOverride: filePath,
    });
    assert.equal(result.ok, true);
  } finally {
    await cleanup();
  }
});

test('EE-SEC.1 server-auth: storage-source mismatch — env presents file key when Keychain has different key', async () => {
  // Env presents Key B (matches file). Storage has Key A in Keychain.
  // Keychain wins → mismatch → refuse. This is the ROTATION scenario:
  // operator rotated the Keychain key but didn't update the file or
  // the Claude Desktop config (which reads from the file via dotenv).
  const { filePath, cleanup } = await withTempEnvFile(
    `${MCP_AUTH_ENV_VAR}=${SAMPLE_KEY_B}\n`,
  );
  try {
    const result = await authorizeMcpServerStartup({
      _env: { [MCP_AUTH_ENV_VAR]: SAMPLE_KEY_B },
      _keychainGet: async () => SAMPLE_KEY_A,
      _homeFileOverride: filePath,
    });
    assert.equal(result.ok, false);
    assert.ok(result.error.includes('does not match'));
  } finally {
    await cleanup();
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// 9. Integration with the actual generated key shape
// ─────────────────────────────────────────────────────────────────────────────

test('EE-SEC.1 server-auth: round-trip with a freshly-generated key', async () => {
  const key = generateMcpAuthKey();
  const result = await authorizeMcpServerStartup({
    _env: { [MCP_AUTH_ENV_VAR]: key },
    _keychainGet: async () => key,
    _homeFileOverride: '/nonexistent',
  });
  assert.deepEqual(result, { ok: true });
});

// ─────────────────────────────────────────────────────────────────────────────
// 10. Post-review folds — bypassedReason + keychain: indirection
// ─────────────────────────────────────────────────────────────────────────────

test('EE-SEC.1 fold (Reviewer 1 CRITICAL #2): DISABLE=1 + no key → bypassedReason "unconfigured"', async () => {
  const result = await authorizeMcpServerStartup({
    _env: { [MCP_AUTH_DISABLE_ENV_VAR]: '1' },
    _keychainGet: async () => null,
    _homeFileOverride: '/nonexistent',
  });
  assert.equal(result.ok, true);
  assert.equal(result.bypassed, true);
  assert.equal(result.bypassedReason, 'unconfigured');
});

test('EE-SEC.1 fold (Reviewer 1 CRITICAL #2): DISABLE=1 + key present → bypassedReason "configured"', async () => {
  const result = await authorizeMcpServerStartup({
    _env: { [MCP_AUTH_DISABLE_ENV_VAR]: '1' },
    _keychainGet: async () => SAMPLE_KEY_A,
    _homeFileOverride: '/nonexistent',
  });
  assert.equal(result.ok, true);
  assert.equal(result.bypassed, true);
  assert.equal(result.bypassedReason, 'configured');
});

test('EE-SEC.1 fold (Reviewer 2 CRITICAL #2): keychain: indirection in env resolves via _resolveSecret seam', async () => {
  // Operator's Claude Desktop config has "NSA_MCP_AUTH_KEY":"keychain:NSA_MCP_AUTH_KEY"
  // (placeholder, not the secret). _resolveSecret seam simulates the
  // keychain.mjs:resolveSecret() lookup that pulls the actual value
  // from Keychain at server startup. Server then compares the
  // resolved value against the storage-resolved expected value.
  const result = await authorizeMcpServerStartup({
    _env: { [MCP_AUTH_ENV_VAR]: `keychain:${MCP_AUTH_ENV_VAR}` },
    _keychainGet: async () => SAMPLE_KEY_A,
    _resolveSecret: async (val) => {
      // Verify the seam was called with the placeholder string.
      assert.equal(val, `keychain:${MCP_AUTH_ENV_VAR}`);
      return SAMPLE_KEY_A;
    },
    _homeFileOverride: '/nonexistent',
  });
  assert.equal(result.ok, true);
});

test('EE-SEC.1 fold (Reviewer 2 CRITICAL #2): keychain: indirection failure produces a distinguishable error', async () => {
  // The keychain: prefix is used but the Keychain entry is missing /
  // locked / inaccessible (e.g., headless Mac without GUI prompt
  // approval). Operator must see a SPECIFIC error, not just "mismatch."
  const result = await authorizeMcpServerStartup({
    _env: { [MCP_AUTH_ENV_VAR]: `keychain:${MCP_AUTH_ENV_VAR}` },
    _keychainGet: async () => SAMPLE_KEY_A,
    _resolveSecret: async () => null, // Keychain entry missing
    _homeFileOverride: '/nonexistent',
  });
  assert.equal(result.ok, false);
  assert.ok(result.error.includes('keychain: indirection'),
    'error must explicitly mention keychain: indirection so operator can debug');
  assert.ok(result.error.includes('headless'),
    'error must mention the common headless-CI cause');
});

test('EE-SEC.1 fold (Reviewer 2 CRITICAL #2): literal env value bypasses _resolveSecret unchanged', async () => {
  // Backwards compat: operators on Linux/Windows continue using the
  // literal key in their env (no keychain: prefix). resolveSecret()
  // returns the input unchanged for non-`keychain:` strings.
  let resolveCalledWith = null;
  const result = await authorizeMcpServerStartup({
    _env: { [MCP_AUTH_ENV_VAR]: SAMPLE_KEY_A },
    _keychainGet: async () => SAMPLE_KEY_A,
    _resolveSecret: async (val) => {
      resolveCalledWith = val;
      return val; // literal pass-through
    },
    _homeFileOverride: '/nonexistent',
  });
  assert.equal(result.ok, true);
  assert.equal(resolveCalledWith, SAMPLE_KEY_A);
});

// ─────────────────────────────────────────────────────────────────────────────
// 11. SECURITY regression — error messages must NEVER echo key values
// ─────────────────────────────────────────────────────────────────────────────

test('EE-SEC.1 fold (Reviewer 2 MEDIUM #4): error message does NOT echo expected or presented key value', async () => {
  // SOC 2 evidence requires that the auth failure log line never
  // contains the secret. A future commit adding "expected ${expected},
  // got ${presented}" for "debugging" would silently break this.
  const expected = 'nsa_mcp_EXPECTEDKEYDONTLEAKDONTLEAKDONTLEAKDONTLE';
  const presented = 'nsa_mcp_PRESENTEDKEYDONTLEAKDONTLEAKDONTLEAKDONTLE';
  const result = await authorizeMcpServerStartup({
    _env: { [MCP_AUTH_ENV_VAR]: presented },
    _keychainGet: async () => expected,
    _homeFileOverride: '/nonexistent',
  });
  assert.equal(result.ok, false);
  // Pin: neither key value (or any 12+ char prefix) appears in the error.
  assert.equal(result.error.includes(expected), false,
    `error message MUST NOT contain expected key value; got: ${result.error}`);
  assert.equal(result.error.includes(presented), false,
    `error message MUST NOT contain presented key value; got: ${result.error}`);
  // Sub-prefix defense: the BODY of the keys (after the nsa_mcp_ prefix)
  // must not appear either.
  const expectedBody = expected.slice('nsa_mcp_'.length);
  const presentedBody = presented.slice('nsa_mcp_'.length);
  assert.equal(result.error.includes(expectedBody.slice(0, 12)), false);
  assert.equal(result.error.includes(presentedBody.slice(0, 12)), false);
});

test('EE-SEC.1 fold (Reviewer 2 MEDIUM #4): unconfigured error message contains no secret-shaped strings', async () => {
  const result = await authorizeMcpServerStartup({
    _env: {},
    _keychainGet: async () => null,
    _homeFileOverride: '/nonexistent',
  });
  assert.equal(result.ok, false);
  // No nsa_mcp_<...> string should appear in the unconfigured error.
  assert.equal(/nsa_mcp_[A-Za-z0-9_-]{20,}/.test(result.error), false,
    `unconfigured error MUST NOT contain a secret-shaped string; got: ${result.error}`);
});
