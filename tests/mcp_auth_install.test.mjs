// tests/mcp_auth_install.test.mjs
// ─────────────────────────────────────────────────────────────────────────────
// EE-SEC.1 — `nsauditor-ai mcp` CLI subcommand smoke tests.
//
// Spawns the actual cli.mjs subprocess to exercise the end-to-end
// command routing + output formatting. The underlying business logic
// (resolveMcpAuthKey, persistMcpAuthKey, generateMcpAuthKey,
// authorizeMcpServerStartup) is tested in dedicated unit suites with
// hermetic seams; these tests focus on the surface the operator
// actually interacts with.
//
// Each test runs in a tmp HOME so the operator's real ~/.nsauditor/.env
// is never touched. NSA_MCP_AUTH_KEY is unset to force the resolver
// to read from the tmp file.
// ─────────────────────────────────────────────────────────────────────────────

import test from 'node:test';
import assert from 'node:assert/strict';
import { promises as fsp } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const CLI_PATH = join(
  dirname(fileURLToPath(import.meta.url)),
  '..',
  'cli.mjs',
);

// Helper: run cli.mjs with isolated HOME + sanitized env.
async function runCli(args, opts = {}) {
  const tmpHome = await fsp.mkdtemp(join(tmpdir(), 'nsauditor-mcp-cli-test-'));
  const cleanup = () => fsp.rm(tmpHome, { recursive: true, force: true });

  // Clean env: drop NSA_MCP_AUTH_KEY/NSAUDITOR_LICENSE_KEY/etc. so the
  // CLI exercises the file-based fallback. Override HOME so the file
  // path resolves into the tmp dir.
  const env = {
    PATH: process.env.PATH,
    NODE_PATH: process.env.NODE_PATH ?? '',
    HOME: tmpHome,
    USERPROFILE: tmpHome, // Windows
    // explicitly unset XDG so it doesn't override HOME-based path
    ...opts.env,
  };

  const result = spawnSync(process.execPath, [CLI_PATH, ...args], {
    env,
    encoding: 'utf8',
    timeout: 10_000,
  });

  return {
    stdout: result.stdout ?? '',
    stderr: result.stderr ?? '',
    status: result.status,
    cleanup,
    tmpHome,
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. usage / help
// ─────────────────────────────────────────────────────────────────────────────

test('EE-SEC.1 CLI: `mcp` with no subcommand prints usage', async () => {
  const r = await runCli(['mcp']);
  try {
    assert.equal(r.status, 0);
    assert.ok(r.stdout.includes('install-key'), 'usage must list install-key');
    assert.ok(r.stdout.includes('rotate-key'));
    assert.ok(r.stdout.includes('print-key'));
    assert.ok(r.stdout.includes('status'));
    assert.ok(r.stdout.includes('NSA_MCP_AUTH_KEY'));
    assert.ok(r.stdout.includes('NSA_MCP_AUTH_DISABLE'));
  } finally { await r.cleanup(); }
});

// ─────────────────────────────────────────────────────────────────────────────
// 2. install-key (auto-generate)
// ─────────────────────────────────────────────────────────────────────────────

test('EE-SEC.1 CLI: `mcp install-key` (no arg) generates + persists + prints config snippet', async () => {
  const r = await runCli(['mcp', 'install-key']);
  try {
    assert.equal(r.status, 0, `expected exit 0, got ${r.status}; stderr: ${r.stderr}`);
    assert.ok(r.stdout.includes('MCP auth key generated and installed'));
    assert.ok(r.stdout.includes('Stored at:'));
    assert.ok(r.stdout.includes('Claude Desktop config'));
    assert.ok(r.stdout.includes('NSA_MCP_AUTH_KEY'));
    // The config snippet must include a key with the proper prefix.
    assert.ok(/nsa_mcp_[A-Za-z0-9_-]{40,50}/.test(r.stdout));

    // The key must actually have been written to ~/.nsauditor/.env
    // inside the tmp HOME (the platform fallback writes to file unless
    // we're on macOS with a working Keychain — which spawnSync's
    // `security` invocation may or may not exercise depending on the
    // test runner's macOS Keychain access).
    // We can't assert the exact storage location (Keychain vs file)
    // because that depends on macOS Keychain availability in the
    // test environment, but the "Stored at:" line tells us either way.
  } finally { await r.cleanup(); }
});

// ─────────────────────────────────────────────────────────────────────────────
// 3. install-key with caller-supplied invalid key
// ─────────────────────────────────────────────────────────────────────────────

test('EE-SEC.1 CLI: `mcp install-key <invalid>` rejects with shape error', async () => {
  const r = await runCli(['mcp', 'install-key', 'totally-not-valid']);
  try {
    assert.equal(r.status, 1);
    assert.ok(r.stderr.includes('Key rejected'));
    assert.ok(r.stderr.includes('nsa_mcp_'));
    assert.ok(r.stderr.includes('install-key'),
      'stderr must point at the regenerate command');
  } finally { await r.cleanup(); }
});

test('EE-SEC.1 CLI: `mcp install-key <valid>` accepts caller-supplied key', async () => {
  const validKey = 'nsa_mcp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
  const r = await runCli(['mcp', 'install-key', validKey]);
  try {
    assert.equal(r.status, 0, `expected exit 0, got ${r.status}; stderr: ${r.stderr}`);
    assert.ok(r.stdout.includes('MCP auth key installed'));
    // For caller-supplied key, "generated and " phrasing must NOT appear.
    assert.equal(r.stdout.includes('generated and installed'), false);
    // The supplied key should appear verbatim in the config snippet.
    assert.ok(r.stdout.includes(validKey));
  } finally { await r.cleanup(); }
});

// ─────────────────────────────────────────────────────────────────────────────
// 4. status — does not leak the key value
// ─────────────────────────────────────────────────────────────────────────────

test('EE-SEC.1 CLI: `mcp status` reports unconfigured when no key present', async () => {
  const r = await runCli(['mcp', 'status']);
  try {
    assert.equal(r.status, 1);
    assert.ok(r.stdout.includes('not configured'));
    assert.ok(r.stdout.includes('install-key'));
  } finally { await r.cleanup(); }
});

test('EE-SEC.1 CLI: `mcp status` after install reports source WITHOUT printing the key', async () => {
  // Install first.
  const r1 = await runCli(['mcp', 'install-key']);
  try {
    assert.equal(r1.status, 0);
    // Extract the generated key from the config snippet output.
    const m = r1.stdout.match(/nsa_mcp_[A-Za-z0-9_-]{40,50}/);
    assert.ok(m, 'install-key output must include the generated key');
    const generatedKey = m[0];

    // Now status — using the SAME tmp HOME so the file persists.
    const r2 = await runCli(['mcp', 'status'], { env: { HOME: r1.tmpHome, USERPROFILE: r1.tmpHome } });
    try {
      assert.equal(r2.status, 0);
      assert.ok(r2.stdout.includes('configured'));
      assert.ok(r2.stdout.includes('Source:'));
      // The key value MUST NOT appear in status output.
      assert.equal(r2.stdout.includes(generatedKey), false,
        'status must NOT print the key value');
    } finally { await r2.cleanup(); }
  } finally { await r1.cleanup(); }
});

// ─────────────────────────────────────────────────────────────────────────────
// 5. print-key — gated behind --confirm
// ─────────────────────────────────────────────────────────────────────────────

test('EE-SEC.1 CLI: `mcp print-key` (no --confirm) refuses', async () => {
  // Even with no key configured, the missing --confirm should block first.
  const r = await runCli(['mcp', 'print-key']);
  try {
    assert.equal(r.status, 2);
    assert.ok(r.stderr.includes('--confirm'));
    assert.ok(r.stderr.includes('shell history'));
  } finally { await r.cleanup(); }
});

test('EE-SEC.1 CLI: `mcp print-key --confirm --force` (no key) reports unconfigured + exit 1', async () => {
  // --force is required to bypass the non-TTY guard added by the
  // Reviewer 2 CRITICAL #1 fold. With --force, the key resolution
  // happens; unconfigured → exit 1.
  const r = await runCli(['mcp', 'print-key', '--confirm', '--force']);
  try {
    assert.equal(r.status, 1);
    assert.ok(r.stderr.includes('not configured') || r.stderr.includes('No MCP auth key'));
  } finally { await r.cleanup(); }
});

// ─────────────────────────────────────────────────────────────────────────────
// 6. rotate-key
// ─────────────────────────────────────────────────────────────────────────────

test('EE-SEC.1 CLI fold (Reviewer 1 MEDIUM #3): `mcp rotate-key` (no --confirm) refuses', async () => {
  // First install one key.
  const r1 = await runCli(['mcp', 'install-key']);
  try {
    assert.equal(r1.status, 0);
    // Rotate without --confirm should refuse (prevents accidental
    // Claude-disconnect during a busy audit window).
    const r2 = await runCli(['mcp', 'rotate-key'], {
      env: { HOME: r1.tmpHome, USERPROFILE: r1.tmpHome },
    });
    try {
      assert.equal(r2.status, 2);
      assert.ok(r2.stderr.includes('immediately invalidates'));
      assert.ok(r2.stderr.includes('--confirm'));
    } finally { await r2.cleanup(); }
  } finally { await r1.cleanup(); }
});

test('EE-SEC.1 CLI: `mcp rotate-key --confirm` generates fresh key + warns to update config', async () => {
  // First install one key.
  const r1 = await runCli(['mcp', 'install-key']);
  try {
    assert.equal(r1.status, 0);
    const oldKeyMatch = r1.stdout.match(/nsa_mcp_[A-Za-z0-9_-]{40,50}/);
    const oldKey = oldKeyMatch[0];

    // Now rotate using the same tmp HOME, WITH --confirm.
    const r2 = await runCli(['mcp', 'rotate-key', '--confirm'], {
      env: { HOME: r1.tmpHome, USERPROFILE: r1.tmpHome },
    });
    try {
      assert.equal(r2.status, 0);
      assert.ok(r2.stdout.includes('rotated'));
      assert.ok(r2.stdout.includes('OLD key is now invalid'));
      assert.ok(r2.stdout.includes('Update your Claude Desktop config'));
      // The new key must differ from the old.
      const newKeyMatch = r2.stdout.match(/nsa_mcp_[A-Za-z0-9_-]{40,50}/);
      assert.ok(newKeyMatch);
      assert.notEqual(newKeyMatch[0], oldKey, 'rotate must produce a new key');
    } finally { await r2.cleanup(); }
  } finally { await r1.cleanup(); }
});

test('EE-SEC.1 CLI fold (Reviewer 2 CRITICAL #1): `mcp print-key --confirm` refuses non-TTY without --force', async () => {
  // spawnSync's pipe stderr is non-TTY by definition. The check should
  // fire and refuse to print the key.
  const r1 = await runCli(['mcp', 'install-key']);
  try {
    assert.equal(r1.status, 0);
    const r2 = await runCli(['mcp', 'print-key', '--confirm'], {
      env: { HOME: r1.tmpHome, USERPROFILE: r1.tmpHome },
    });
    try {
      assert.equal(r2.status, 2);
      assert.ok(r2.stderr.includes('non-TTY'));
      assert.ok(r2.stderr.includes('--force'));
      // Critical: the key value must NOT have been printed.
      const m = r1.stdout.match(/nsa_mcp_[A-Za-z0-9_-]{40,50}/);
      const generatedKey = m[0];
      assert.equal(r2.stdout.includes(generatedKey), false);
      assert.equal(r2.stderr.includes(generatedKey), false);
    } finally { await r2.cleanup(); }
  } finally { await r1.cleanup(); }
});

test('EE-SEC.1 CLI fold (Reviewer 2 CRITICAL #2): keychain: indirection used in macOS install-key snippet', async () => {
  // On macOS where Keychain is available, the install-key output's
  // Claude Desktop config snippet uses `keychain:NSA_MCP_AUTH_KEY`
  // placeholder instead of the literal key. This test asserts the
  // platform-aware branching works — the assertion is conditional on
  // the persistence target being Keychain (which depends on whether
  // the test environment can reach `security` daemon). On Linux/CI
  // the test verifies the literal-key branch + chmod warning.
  const r = await runCli(['mcp', 'install-key']);
  try {
    assert.equal(r.status, 0);
    if (r.stdout.includes('Stored at: macOS Keychain')) {
      // Keychain branch — snippet should use indirection.
      assert.ok(r.stdout.includes(`"keychain:NSA_MCP_AUTH_KEY"`),
        'macOS install-key output must use keychain: indirection in snippet');
      assert.ok(r.stdout.includes('placeholder tells the MCP server'));
      // The literal key must NOT appear in the snippet line of the
      // config block (it appears elsewhere — e.g., for verification —
      // but the env value in the JSON must be the placeholder).
      const snippetLine = r.stdout
        .split('\n')
        .find((line) => line.includes(`"${'NSA_MCP_AUTH_KEY'}":`));
      assert.ok(snippetLine, 'snippet line must exist');
      assert.equal(snippetLine.includes(`"keychain:NSA_MCP_AUTH_KEY"`), true);
    } else {
      // File branch (Linux/Windows or macOS Keychain unavailable) —
      // literal key in snippet + chmod warning required.
      assert.ok(r.stdout.includes('literal key value is now in your Claude Desktop'),
        'file-branch output must warn about literal-key in config file');
    }
  } finally { await r.cleanup(); }
});
