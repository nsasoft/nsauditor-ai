// tests/cli_license_install.test.mjs
// ─────────────────────────────────────────────────────────────────────────────
// CE-0.1.30.4 — CLI tests for `nsauditor-ai license install <KEY>`.
//
// Subprocess-driven so we exercise the actual cli.mjs dispatch, parser,
// exit codes, and stdout/stderr separation. Tests use synthetic keys
// (which fail JWT verification, since we don't have the private key) to
// pin the verify-before-persist contract; round-trip tests with a real
// key are out of scope here (covered at the unit level in
// license_persist.test.mjs and end-to-end via the dev box smoke).
// ─────────────────────────────────────────────────────────────────────────────

import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(__dirname, '..');
const CLI_PATH = join(REPO_ROOT, 'cli.mjs');

function runCli(args, env = {}) {
  const cleanEnv = {
    ...process.env,
    // Force a non-existent XDG path so the resolver chain can't find
    // an existing license on the dev machine while these tests run.
    XDG_CONFIG_HOME: '/nonexistent-cli-license-install-test-isolation',
    ...env,
  };
  delete cleanEnv.NSAUDITOR_LICENSE_KEY;
  return spawnSync(process.execPath, [CLI_PATH, ...args], {
    cwd: REPO_ROOT,
    env: cleanEnv,
    encoding: 'utf8',
    timeout: 15000,
  });
}

// ── 1. Usage / error paths ───────────────────────────────────────────────────

test('CE-0.1.30.4: `license install` with no key prints Usage + exits 2', () => {
  const r = runCli(['license', 'install']);
  assert.equal(r.status, 2, `expected exit 2, got ${r.status}`);
  assert.match(r.stderr, /Usage: nsauditor-ai license install/);
  assert.match(r.stderr, /KEY is the JWT/);
  assert.match(r.stderr, /Storage locations/);
});

test('CE-0.1.30.4: `license install --some-flag` (next arg looks like a flag) prints Usage', () => {
  // Defends against a customer accidentally typing `license install
  // --some-other-flag` and having `--some-other-flag` mis-interpreted
  // as the key value (which would fail verification with a confusing
  // error). We treat any next-arg starting with `-` as missing-key.
  const r = runCli(['license', 'install', '--debug']);
  assert.equal(r.status, 2);
  assert.match(r.stderr, /Usage: nsauditor-ai license install/);
});

test('CE-0.1.30.4: `license install <invalid-key>` rejects + exits 1 + does NOT persist', () => {
  // Synthetic key — fails JWT verification. The install command must
  // reject (not silently persist garbage and let the next --status
  // call discover it).
  const r = runCli(['license', 'install', 'enterprise_synthetic-not-a-jwt']);
  assert.equal(r.status, 1);
  assert.match(r.stderr, /License key rejected/);
  assert.match(r.stderr, /No changes made/);
});

test('CE-0.1.30.4: `license install <wrong-prefix>` (no pro_ / enterprise_) is rejected', () => {
  const r = runCli(['license', 'install', 'random_no-prefix']);
  assert.equal(r.status, 1);
  assert.match(r.stderr, /License key rejected/);
});

test('CE-0.1.30.4: `license install <empty>` after trim is treated as missing', () => {
  // Whitespace-only argument should fall through the trim() and hit the
  // "missing key" branch, NOT the JWT-verification rejection branch.
  const r = runCli(['license', 'install', '   ']);
  assert.equal(r.status, 2);
  assert.match(r.stderr, /Usage:/);
});

// ── 2. --help integration (CLI-flag visibility rule) ─────────────────────────

test('CE-0.1.30.4: --help mentions the install subcommand', () => {
  const r = runCli(['--help']);
  assert.equal(r.status, 0);
  assert.match(r.stdout, /license install/, '--help must document the install subcommand');
  assert.match(r.stdout, /Verify and persist/, '--help should describe what install does');
});

test('CE-0.1.30.4: --help Examples block has an install line', () => {
  const r = runCli(['--help']);
  assert.match(r.stdout, /nsauditor-ai license install/, 'Examples block should show install usage');
});

test('CE-0.1.30.4: bare `license` (no subcommand) Usage line lists install', () => {
  const r = runCli(['license']);
  assert.equal(r.status, 0);
  assert.match(r.stdout, /install <KEY>/);
});

// ── 3. License-key value safety ──────────────────────────────────────────────

test('CE-0.1.30.4: install does NOT echo the key value to stdout/stderr', () => {
  // Defense against shell history / log leakage. Even on success the
  // install command should print the License ID / Org / Tier — never
  // the JWT itself. Run with a verifiably-rejected key so we can pin
  // the negative assertion (the rejection path should also not echo
  // the key).
  const SECRET = 'enterprise_eyJ-DO-NOT-LEAK-secret-marker';
  const r = runCli(['license', 'install', SECRET]);
  assert.doesNotMatch(r.stdout, /DO-NOT-LEAK/);
  assert.doesNotMatch(r.stderr, /DO-NOT-LEAK/);
});
