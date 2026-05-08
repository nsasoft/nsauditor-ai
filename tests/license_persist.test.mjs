// tests/license_persist.test.mjs
// ─────────────────────────────────────────────────────────────────────────────
// CE-0.1.30.4 — persistLicenseKey() unit tests.
//
// Tests the platform-aware persister that writes a license key to:
//   - macOS: Keychain via keychainSet()
//   - Linux/Windows/macOS-fallback: ~/.nsauditor/.env (mode 0600, dir 0700)
//
// Uses test seams (_platform / _keychainSet / _homeFileOverride) to keep
// tests hermetic — no real Keychain writes, no touching the user's home.
// ─────────────────────────────────────────────────────────────────────────────

import test from 'node:test';
import assert from 'node:assert/strict';
import { promises as fsp } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  persistLicenseKey,
  mergeLicenseIntoEnvFile,
  resolveLicenseKey,
} from '../utils/license.mjs';

async function tempDir() {
  return fsp.mkdtemp(join(tmpdir(), 'nsauditor-persist-test-'));
}

// ── 1. macOS path: Keychain ──────────────────────────────────────────────────

test('CE-0.1.30.4: macOS path writes to Keychain via keychainSet', async () => {
  const calls = [];
  const result = await persistLicenseKey('enterprise_eyJ-test-key', {
    _platform: 'darwin',
    _keychainSet: async (account, secret) => {
      calls.push({ account, secret });
    },
  });
  assert.equal(result.ok, true);
  assert.match(result.location, /Keychain/);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].account, 'NSAUDITOR_LICENSE_KEY');
  assert.equal(calls[0].secret, 'enterprise_eyJ-test-key');
});

test('CE-0.1.30.4: macOS Keychain failure falls back to file storage', async () => {
  // Headless mac, denied prompt, or `security` daemon unavailable.
  const dir = await tempDir();
  const filePath = join(dir, '.env');
  try {
    const result = await persistLicenseKey('enterprise_eyJ-fallback', {
      _platform: 'darwin',
      _keychainSet: async () => { throw new Error('Keychain unavailable'); },
      _homeFileOverride: filePath,
    });
    assert.equal(result.ok, true);
    assert.equal(result.location, filePath);
    // File should exist with the key written.
    const written = await fsp.readFile(filePath, 'utf8');
    assert.match(written, /NSAUDITOR_LICENSE_KEY=enterprise_eyJ-fallback/);
  } finally {
    await fsp.rm(dir, { recursive: true, force: true });
  }
});

// ── 2. Linux / Windows path: file-based storage ──────────────────────────────

test('CE-0.1.30.4: Linux path writes to ~/.nsauditor/.env file', async () => {
  const dir = await tempDir();
  const filePath = join(dir, 'subdir', '.env');  // dir doesn't exist yet
  try {
    const result = await persistLicenseKey('enterprise_eyJ-linux', {
      _platform: 'linux',
      _homeFileOverride: filePath,
    });
    assert.equal(result.ok, true);
    assert.equal(result.location, filePath);
    const stat = await fsp.stat(filePath);
    // Mode 0600 on POSIX (drop the file-type bits via 0o777 mask)
    assert.equal((stat.mode & 0o777), 0o600, `expected mode 0600, got ${(stat.mode & 0o777).toString(8)}`);
  } finally {
    await fsp.rm(dir, { recursive: true, force: true });
  }
});

test('CE-0.1.30.4: Linux path creates parent dir with 0700 if missing', async () => {
  const dir = await tempDir();
  const subDir = join(dir, 'nested', 'nsauditor');
  const filePath = join(subDir, '.env');
  try {
    await persistLicenseKey('enterprise_eyJ-mkdir-test', {
      _platform: 'linux',
      _homeFileOverride: filePath,
    });
    const dirStat = await fsp.stat(subDir);
    // 0700 on the new dir (recursive=true only sets mode on NEW dirs)
    assert.equal(
      dirStat.mode & 0o777, 0o700,
      `expected dir mode 0700, got ${(dirStat.mode & 0o777).toString(8)}`
    );
  } finally {
    await fsp.rm(dir, { recursive: true, force: true });
  }
});

test('CE-0.1.30.4: Linux Windows-platform writes to file too', async () => {
  const dir = await tempDir();
  const filePath = join(dir, '.env');
  try {
    const result = await persistLicenseKey('pro_eyJ-win', {
      _platform: 'win32',
      _homeFileOverride: filePath,
    });
    assert.equal(result.ok, true);
    assert.equal(result.location, filePath);
    // No mode check on Windows — the platform doesn't honor POSIX mode bits.
  } finally {
    await fsp.rm(dir, { recursive: true, force: true });
  }
});

// ── 3. Existing-file preservation ────────────────────────────────────────────

test('CE-0.1.30.4: existing file with OTHER vars preserves them', async () => {
  const dir = await tempDir();
  const filePath = join(dir, '.env');
  try {
    // Pre-existing file with unrelated env vars.
    const initial = `# user notes\nOPENAI_API_KEY=sk-test-1234\nFOO=bar\n`;
    await fsp.writeFile(filePath, initial, { mode: 0o600 });
    const result = await persistLicenseKey('enterprise_eyJ-merge', {
      _platform: 'linux',
      _homeFileOverride: filePath,
    });
    assert.equal(result.ok, true);
    const after = await fsp.readFile(filePath, 'utf8');
    assert.match(after, /OPENAI_API_KEY=sk-test-1234/, 'OPENAI_API_KEY should be preserved');
    assert.match(after, /FOO=bar/, 'FOO=bar should be preserved');
    assert.match(after, /# user notes/, 'comment should be preserved');
    assert.match(after, /NSAUDITOR_LICENSE_KEY=enterprise_eyJ-merge/, 'license appended');
  } finally {
    await fsp.rm(dir, { recursive: true, force: true });
  }
});

test('CE-0.1.30.4: existing file with old NSAUDITOR_LICENSE_KEY replaces in place', async () => {
  const dir = await tempDir();
  const filePath = join(dir, '.env');
  try {
    const initial = `# header\nFOO=bar\nNSAUDITOR_LICENSE_KEY=enterprise_OLD-key\nOTHER=baz\n`;
    await fsp.writeFile(filePath, initial, { mode: 0o600 });
    await persistLicenseKey('enterprise_NEW-key', {
      _platform: 'linux',
      _homeFileOverride: filePath,
    });
    const after = await fsp.readFile(filePath, 'utf8');
    assert.match(after, /NSAUDITOR_LICENSE_KEY=enterprise_NEW-key/);
    assert.doesNotMatch(after, /enterprise_OLD-key/, 'old key should be replaced, not duplicated');
    assert.match(after, /FOO=bar/, 'FOO preserved');
    assert.match(after, /OTHER=baz/, 'OTHER preserved');
  } finally {
    await fsp.rm(dir, { recursive: true, force: true });
  }
});

test('CE-0.1.30.4: file with permissive mode is re-chmodded to 0600', async () => {
  if (process.platform === 'win32') return;
  const dir = await tempDir();
  const filePath = join(dir, '.env');
  try {
    // Pre-create with mode 0644 (permissive).
    await fsp.writeFile(filePath, 'NSAUDITOR_LICENSE_KEY=old\n', { mode: 0o644 });
    await persistLicenseKey('enterprise_chmod-test', {
      _platform: 'linux',
      _homeFileOverride: filePath,
    });
    const stat = await fsp.stat(filePath);
    assert.equal(
      stat.mode & 0o777, 0o600,
      `expected re-chmod to 0600, got ${(stat.mode & 0o777).toString(8)}`
    );
  } finally {
    await fsp.rm(dir, { recursive: true, force: true });
  }
});

// ── 4. Error / input validation ──────────────────────────────────────────────

test('CE-0.1.30.4: empty key string returns ok:false', async () => {
  const result = await persistLicenseKey('');
  assert.equal(result.ok, false);
  assert.match(result.error, /non-empty string/);
});

test('CE-0.1.30.4: non-string key (null) returns ok:false', async () => {
  const result = await persistLicenseKey(null);
  assert.equal(result.ok, false);
});

test('CE-0.1.30.4: undefined key returns ok:false', async () => {
  const result = await persistLicenseKey(undefined);
  assert.equal(result.ok, false);
});

test('CE-0.1.30.4: file-write failure (read-only dir) returns ok:false with error message', async () => {
  // Linux platform forced; point at a path we can't write to.
  const result = await persistLicenseKey('enterprise_test', {
    _platform: 'linux',
    _homeFileOverride: '/dev/null/not-a-real-path/.env',  // can't mkdir
  });
  assert.equal(result.ok, false);
  assert.ok(result.error.length > 0);
});

// ── 5. mergeLicenseIntoEnvFile (pure function) ───────────────────────────────

test('CE-0.1.30.4: mergeLicenseIntoEnvFile replaces existing key in place', () => {
  const before = `FOO=bar\nNSAUDITOR_LICENSE_KEY=old\nBAZ=qux\n`;
  const after = mergeLicenseIntoEnvFile(before, 'NEW');
  assert.match(after, /NSAUDITOR_LICENSE_KEY=NEW/);
  assert.doesNotMatch(after, /=old/);
  assert.match(after, /FOO=bar/);
  assert.match(after, /BAZ=qux/);
});

test('CE-0.1.30.4: mergeLicenseIntoEnvFile appends with newline if file missing trailing newline', () => {
  const before = `FOO=bar`;  // no trailing newline
  const after = mergeLicenseIntoEnvFile(before, 'NEW');
  assert.match(after, /FOO=bar\nNSAUDITOR_LICENSE_KEY=NEW\n/);
});

test('CE-0.1.30.4: mergeLicenseIntoEnvFile writes header for empty input', () => {
  const after = mergeLicenseIntoEnvFile('', 'NEW');
  assert.match(after, /^#/, 'should start with a comment header');
  assert.match(after, /NSAUDITOR_LICENSE_KEY=NEW/);
});

test('CE-0.1.30.4: mergeLicenseIntoEnvFile is idempotent on identical key', () => {
  const before = `NSAUDITOR_LICENSE_KEY=SAME\n`;
  const after = mergeLicenseIntoEnvFile(before, 'SAME');
  assert.equal(after, before, 'replacing a key with the same value is a no-op');
});

// ── 7. Reviewer M2 fold: corrupted file with multiple key lines ──────────────

test('CE-0.1.30.4 reviewer M2: corrupted file with TWO key lines collapses to ONE (new value)', () => {
  // Pre-fold bug: only the first occurrence was replaced. dotenv parses
  // last-wins, so `--status` after install would show the OLD key while
  // install reported success. Real-world cause: operator manually edited
  // the file twice and forgot to delete the old line.
  const before = `FOO=bar\nNSAUDITOR_LICENSE_KEY=OLD-FIRST\nBAZ=baz\nNSAUDITOR_LICENSE_KEY=OLD-SECOND\n`;
  const after = mergeLicenseIntoEnvFile(before, 'NEW');
  // Count occurrences of NSAUDITOR_LICENSE_KEY=
  const keyLineCount = (after.match(/^NSAUDITOR_LICENSE_KEY=/gm) || []).length;
  assert.equal(keyLineCount, 1, `expected exactly 1 NSAUDITOR_LICENSE_KEY line after merge; got ${keyLineCount}`);
  assert.match(after, /NSAUDITOR_LICENSE_KEY=NEW/, 'new value should be present');
  assert.doesNotMatch(after, /OLD-FIRST/, 'first old value purged');
  assert.doesNotMatch(after, /OLD-SECOND/, 'second old value purged');
  assert.match(after, /FOO=bar/, 'unrelated FOO line preserved');
  assert.match(after, /BAZ=baz/, 'unrelated BAZ line preserved');
});

test('CE-0.1.30.4 reviewer M2: corrupted file with THREE key lines collapses to ONE', () => {
  const before = `KEY1=a\nNSAUDITOR_LICENSE_KEY=A\nNSAUDITOR_LICENSE_KEY=B\nNSAUDITOR_LICENSE_KEY=C\nKEY2=b\n`;
  const after = mergeLicenseIntoEnvFile(before, 'NEW');
  const keyLineCount = (after.match(/^NSAUDITOR_LICENSE_KEY=/gm) || []).length;
  assert.equal(keyLineCount, 1);
  assert.match(after, /NSAUDITOR_LICENSE_KEY=NEW/);
  assert.match(after, /KEY1=a/);
  assert.match(after, /KEY2=b/);
});

// ── 8. Reviewer M2b fold: CRLF line ending preservation ──────────────────────

test('CE-0.1.30.4 reviewer M2b: CRLF (Windows) input preserves other lines without mangling', () => {
  // Pre-fold bug: \s* in the regex matched \r, leaving dangling carriage
  // returns at line ends after replacement. New regex uses [ \t]* and
  // [^\r\n]* anchors to keep CRLF intact.
  const before = `FOO=bar\r\nNSAUDITOR_LICENSE_KEY=OLD\r\nBAZ=q\r\n`;
  const after = mergeLicenseIntoEnvFile(before, 'NEW');
  // FOO line should still end with \r\n (or \r — depending on what
  // we preserved). Critically, FOO should NOT be merged into the
  // NSAUDITOR line via a stripped \n.
  assert.match(after, /FOO=bar/);
  assert.match(after, /BAZ=q/);
  assert.match(after, /NSAUDITOR_LICENSE_KEY=NEW/);
  // Lines should remain on separate lines — no "FOO=barNSAUDITOR" mash-up
  assert.doesNotMatch(after, /FOO=barNSAUDITOR/);
  assert.doesNotMatch(after, /NEWBAZ=q/);
});

test('CE-0.1.30.4 reviewer M2b: spaces around `=` (KEY = value form) replaces correctly', () => {
  const before = `NSAUDITOR_LICENSE_KEY = OLD-spaced\n`;
  const after = mergeLicenseIntoEnvFile(before, 'NEW');
  assert.match(after, /NSAUDITOR_LICENSE_KEY=NEW/);
  assert.doesNotMatch(after, /OLD-spaced/);
});

test('CE-0.1.30.4 reviewer M2b: commented-out key line is NOT replaced (correct behavior)', () => {
  // A line like `# NSAUDITOR_LICENSE_KEY=old-disabled` should be left
  // alone — it's a comment from the operator. Append the new key.
  const before = `# NSAUDITOR_LICENSE_KEY=old-disabled\n`;
  const after = mergeLicenseIntoEnvFile(before, 'NEW');
  assert.match(after, /# NSAUDITOR_LICENSE_KEY=old-disabled/, 'comment preserved');
  assert.match(after, /^NSAUDITOR_LICENSE_KEY=NEW$/m, 'new key appended');
});

// ── 9. Reviewer M1 fold: Keychain-fallback warning ───────────────────────────

test('CE-0.1.30.4 reviewer M1: Keychain failure on macOS surfaces a warning in result.warning', async () => {
  const dir = await tempDir();
  const filePath = join(dir, '.env');
  try {
    const result = await persistLicenseKey('enterprise_eyJ-warn-test', {
      _platform: 'darwin',
      _keychainSet: async () => { throw new Error('user denied prompt'); },
      _homeFileOverride: filePath,
    });
    assert.equal(result.ok, true);
    assert.ok(typeof result.warning === 'string', 'expected result.warning when Keychain failed');
    assert.match(result.warning, /Keychain unavailable/);
    assert.match(result.warning, /user denied prompt/, 'should include the underlying error reason');
    assert.match(result.warning, /grant(ing)?\s+Keychain\s+access/i, 'should give actionable next-step');
  } finally {
    await fsp.rm(dir, { recursive: true, force: true });
  }
});

test('CE-0.1.30.4 reviewer M1: Keychain success on macOS does NOT include result.warning', async () => {
  const result = await persistLicenseKey('enterprise_eyJ-success', {
    _platform: 'darwin',
    _keychainSet: async () => { /* succeeds */ },
  });
  assert.equal(result.ok, true);
  assert.match(result.location, /Keychain/);
  assert.equal(result.warning, undefined, 'no warning on Keychain success');
});

test('CE-0.1.30.4 reviewer M1: file-only path (Linux) does NOT include result.warning', async () => {
  const dir = await tempDir();
  try {
    const result = await persistLicenseKey('enterprise_eyJ-linux', {
      _platform: 'linux',
      _homeFileOverride: join(dir, '.env'),
    });
    assert.equal(result.ok, true);
    assert.equal(result.warning, undefined, 'no warning on Linux file-only path');
  } finally {
    await fsp.rm(dir, { recursive: true, force: true });
  }
});

// ── 6. End-to-end: persist then resolve ──────────────────────────────────────

test('CE-0.1.30.4 round-trip: persist + resolve via the file path', async () => {
  // The whole point of the install command: what install writes, the
  // resolver chain (CE-0.1.30.2) reads back. This test pins the
  // round-trip behavior — install on Linux writes to the file, and
  // resolveLicenseKey() on subsequent calls reads it.
  const dir = await tempDir();
  const filePath = join(dir, '.env');
  const restoreEnv = process.env.NSAUDITOR_LICENSE_KEY;
  delete process.env.NSAUDITOR_LICENSE_KEY;
  try {
    await persistLicenseKey('enterprise_eyJ-roundtrip', {
      _platform: 'linux',
      _homeFileOverride: filePath,
    });
    const resolved = await resolveLicenseKey({
      _keychainGet: async () => null,  // skip Keychain
      _homeFileOverride: filePath,
    });
    assert.equal(resolved, 'enterprise_eyJ-roundtrip');
  } finally {
    if (restoreEnv === undefined) delete process.env.NSAUDITOR_LICENSE_KEY;
    else process.env.NSAUDITOR_LICENSE_KEY = restoreEnv;
    await fsp.rm(dir, { recursive: true, force: true });
  }
});
