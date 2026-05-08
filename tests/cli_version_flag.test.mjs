// tests/cli_version_flag.test.mjs
// ─────────────────────────────────────────────────────────────────────────────
// CE-0.1.30.1 — `--version` / `-v` / `version` flag tests.
//
// Pre-fix, `nsauditor-ai --version` errored with "Fatal: --host or --host-file
// is required" because the args parser fell through to scan-mode default and
// the validator demanded a host. Same UX gap as the pre-0.1.29 `--help` flag.
// This test pins all three discovery forms to (a) exit 0 and (b) print the
// version on stdout.
// ─────────────────────────────────────────────────────────────────────────────

import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(__dirname, '..');
const CLI_PATH = join(REPO_ROOT, 'cli.mjs');
const PKG = JSON.parse(readFileSync(join(REPO_ROOT, 'package.json'), 'utf8'));

function runCli(args) {
  return spawnSync(process.execPath, [CLI_PATH, ...args], {
    cwd: REPO_ROOT,
    encoding: 'utf8',
    timeout: 15000,
  });
}

test('CE-0.1.30.1: `--version` prints "nsauditor-ai <version>" and exits 0', () => {
  const r = runCli(['--version']);
  assert.equal(r.status, 0, `expected exit 0, got ${r.status}; stderr: ${r.stderr}`);
  // The cli.mjs has top-level imports that emit chatter on stderr/stdout
  // (PluginManager loaded, oui-data loaded). The version line is the LAST
  // line of stdout. Match anywhere.
  assert.match(
    r.stdout,
    new RegExp(`nsauditor-ai ${PKG.version.replace(/\./g, '\\.')}`),
    `expected "nsauditor-ai ${PKG.version}" in stdout; got: ${r.stdout}`
  );
});

test('CE-0.1.30.1: `-v` short form prints version and exits 0', () => {
  const r = runCli(['-v']);
  assert.equal(r.status, 0, `expected exit 0, got ${r.status}; stderr: ${r.stderr}`);
  assert.match(r.stdout, new RegExp(`nsauditor-ai ${PKG.version.replace(/\./g, '\\.')}`));
});

test('CE-0.1.30.1: `version` subcommand prints version and exits 0', () => {
  const r = runCli(['version']);
  assert.equal(r.status, 0, `expected exit 0, got ${r.status}; stderr: ${r.stderr}`);
  assert.match(r.stdout, new RegExp(`nsauditor-ai ${PKG.version.replace(/\./g, '\\.')}`));
});

test('CE-0.1.30.1: version flag does NOT require a license key (parallels --help behavior)', () => {
  // Strip license-related env vars to simulate a fresh customer install.
  // The test asserts the flag works without NSAUDITOR_LICENSE_KEY set.
  const cleanEnv = Object.fromEntries(
    Object.entries(process.env).filter(([k]) =>
      !['NSAUDITOR_LICENSE_KEY', 'npm_package_version'].includes(k) &&
      !k.startsWith('npm_')
    )
  );
  const r = spawnSync(process.execPath, [CLI_PATH, '--version'], {
    cwd: REPO_ROOT,
    env: cleanEnv,
    encoding: 'utf8',
    timeout: 15000,
  });
  assert.equal(r.status, 0, `--version must work without license; exit=${r.status}, stderr=${r.stderr}`);
  assert.match(r.stdout, new RegExp(`nsauditor-ai ${PKG.version.replace(/\./g, '\\.')}`));
  // Critically, NO "Fatal: --host or --host-file is required" — that was
  // the exact pre-0.1.30.1 failure mode.
  assert.doesNotMatch(r.stderr, /Fatal: --host/);
});

test('CE-0.1.30.1: `--version` mid-args (not first) is also recognized', () => {
  // Defends against a regression where the parser only checks a[0]. The
  // implementation uses `a.includes('--version')` after the a[0] check
  // so a customer typing `nsauditor-ai scan --version` still gets the
  // version (instead of falling through to scan-with-no-host).
  const r = runCli(['scan', '--version']);
  assert.equal(r.status, 0);
  assert.match(r.stdout, new RegExp(`nsauditor-ai ${PKG.version.replace(/\./g, '\\.')}`));
});

test('CE-0.1.30.1: `--help` output documents the --version / -v flag', () => {
  // Ties the --help docs to the --version implementation so the CLI-flag
  // visibility rule (added 2026-05-08 in EE tasks/todo.md) is enforced.
  // If someone removes --version from --help text, this test fails.
  const r = runCli(['--help']);
  assert.equal(r.status, 0);
  assert.match(r.stdout, /--version|-v/, '--help must mention --version / -v flag');
  assert.match(r.stdout, /version/, '--help must mention `version` subcommand form');
});

test('CE-0.1.30.1 reviewer M1: short flag `-v` does NOT match when used as a flag VALUE (regression)', () => {
  // Pre-fix: `a.includes('-v')` would match `-v` anywhere in argv,
  // including as a value of another flag. So `nsauditor-ai --host
  // 1.1.1.1 -v` would silently fire the version handler instead of
  // running a scan. Reviewer M1 tightened `-v` to match ONLY at `a[0]`.
  // Long-flag `--version` retains anywhere-match (line 7 above).
  //
  // Note: this test runs outside the normal scan path. We assert that
  // the CLI does NOT exit 0 with version output — it should hit the
  // SSRF guard or licensing path instead, depending on credentials.
  // The cleanest signal: stdout does NOT contain "nsauditor-ai 0.1."
  // by itself on its own line.
  // Use 127.0.0.1 — fails fast on the SSRF guard ("blocked address range")
  // instead of trying to do a real network scan and timing out at 15s.
  const r = runCli(['--host', '127.0.0.1', '-v']);
  // Either fails the scan (no license / SSRF) OR scans successfully, but
  // the version line MUST NOT appear as the only/last output.
  // Strict assertion: stdout should not have a bare "nsauditor-ai <ver>"
  // line that isn't preceded by other output (which would mean version
  // handler fired). We assert the cmd fell through to scan by checking
  // that EITHER the process errored (license) OR scan output appears.
  // The key invariant is: the version handler (which exits 0 immediately
  // after one line) was NOT triggered.
  const isJustVersion = /^nsauditor-ai \d+\.\d+\.\d+\s*$/m.test(r.stdout) &&
                        r.stdout.split('\n').filter((l) => l.trim()).length < 5;
  assert.equal(
    isJustVersion, false,
    `'-v' as a flag VALUE should not trigger the version handler (stdout=${JSON.stringify(r.stdout)})`
  );
});

test('CE-0.1.30.1 reviewer M1: short flag `-h` does NOT match when used as a flag VALUE (regression)', () => {
  // Same fix mirrored to the existing --help branch (was a pre-existing
  // bug: `a.includes('-h')` matched `-h` anywhere). Now -h only matches
  // at a[0]; --help retains anywhere-match.
  const r = runCli(['--alert-severity', '-h']);
  const isJustHelp = /^Usage:/m.test(r.stdout) && r.stdout.includes('Scan options:');
  assert.equal(
    isJustHelp, false,
    `'-h' as a flag VALUE should not trigger the help handler`
  );
});
