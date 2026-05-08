// tests/license_resolver.test.mjs
// ─────────────────────────────────────────────────────────────────────────────
// CE-0.1.30.2 — multi-source license-key resolver tests.
//
// Resolution order:
//   1. process.env.NSAUDITOR_LICENSE_KEY (CI/CD)
//   2. macOS Keychain (service=nsauditor-ai, account=NSAUDITOR_LICENSE_KEY)
//   3. ~/.nsauditor/.env (or $XDG_CONFIG_HOME/nsauditor/.env)
//
// Each test uses test seams (_keychainGet, _homeFileOverride) to keep the
// suite hermetic — no real Keychain reads, no touching the user's home
// directory. The default resolution path (no opts) is also exercised in
// the smoke section against process.env.
// ─────────────────────────────────────────────────────────────────────────────

import test from 'node:test';
import assert from 'node:assert/strict';
import { promises as fsp } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { resolveLicenseKey, _resetCache } from '../utils/license.mjs';

// ── Test isolation helpers ────────────────────────────────────────────────────

async function withTempEnvFile(content, mode = 0o600) {
  const dir = await fsp.mkdtemp(join(tmpdir(), 'nsauditor-license-test-'));
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

// ── 1. env var — highest precedence ──────────────────────────────────────────

test('CE-0.1.30.2: returns env-var value when set (skips Keychain + file)', async () => {
  const restore = snapshotEnv('NSAUDITOR_LICENSE_KEY');
  process.env.NSAUDITOR_LICENSE_KEY = 'enterprise_eyJ-from-env';
  try {
    let kgetCalled = false;
    const result = await resolveLicenseKey({
      _keychainGet: async () => { kgetCalled = true; return 'enterprise_eyJ-from-keychain'; },
      _homeFileOverride: '/nonexistent/path-should-not-be-read',
    });
    assert.equal(result, 'enterprise_eyJ-from-env');
    assert.equal(kgetCalled, false, 'Keychain must not be queried when env var is set');
  } finally {
    restore();
  }
});

test('CE-0.1.30.2: empty env var falls through to next source', async () => {
  const restore = snapshotEnv('NSAUDITOR_LICENSE_KEY');
  process.env.NSAUDITOR_LICENSE_KEY = '';   // explicitly empty — not set
  try {
    const result = await resolveLicenseKey({
      _keychainGet: async () => 'enterprise_from-keychain',
      _homeFileOverride: '/nonexistent',
    });
    assert.equal(result, 'enterprise_from-keychain');
  } finally {
    restore();
  }
});

// ── 2. macOS Keychain — second precedence ────────────────────────────────────

test('CE-0.1.30.2: returns Keychain value when env is unset', async () => {
  const restore = snapshotEnv('NSAUDITOR_LICENSE_KEY');
  delete process.env.NSAUDITOR_LICENSE_KEY;
  try {
    const result = await resolveLicenseKey({
      _keychainGet: async (account) => {
        assert.equal(account, 'NSAUDITOR_LICENSE_KEY', 'queries the right account name');
        return 'pro_eyJ-from-keychain';
      },
      _homeFileOverride: '/nonexistent',
    });
    assert.equal(result, 'pro_eyJ-from-keychain');
  } finally {
    restore();
  }
});

test('CE-0.1.30.2: Keychain miss (returns null) falls through to file', async () => {
  const restore = snapshotEnv('NSAUDITOR_LICENSE_KEY');
  delete process.env.NSAUDITOR_LICENSE_KEY;
  const { filePath, cleanup } = await withTempEnvFile('NSAUDITOR_LICENSE_KEY=enterprise_from-file');
  try {
    const result = await resolveLicenseKey({
      _keychainGet: async () => null,
      _homeFileOverride: filePath,
    });
    assert.equal(result, 'enterprise_from-file');
  } finally {
    restore();
    await cleanup();
  }
});

// Note: keychain.mjs returns null (not throws) on non-mac. The test below
// covers the genuine throw case (corrupt Keychain on macOS) for completeness.
test('CE-0.1.30.2: Keychain throw (corrupt Keychain on macOS) falls through cleanly to file', async () => {
  const restore = snapshotEnv('NSAUDITOR_LICENSE_KEY');
  delete process.env.NSAUDITOR_LICENSE_KEY;
  const { filePath, cleanup } = await withTempEnvFile('NSAUDITOR_LICENSE_KEY=enterprise_from-file');
  try {
    const result = await resolveLicenseKey({
      _keychainGet: async () => { throw new Error('Keychain unavailable'); },
      _homeFileOverride: filePath,
    });
    assert.equal(result, 'enterprise_from-file');
  } finally {
    restore();
    await cleanup();
  }
});

// ── 3. ~/.nsauditor/.env — third precedence ──────────────────────────────────

test('CE-0.1.30.2: parses dotenv-format file with NSAUDITOR_LICENSE_KEY', async () => {
  const restore = snapshotEnv('NSAUDITOR_LICENSE_KEY');
  delete process.env.NSAUDITOR_LICENSE_KEY;
  const { filePath, cleanup } = await withTempEnvFile(
    '# NSAuditor AI license\nNSAUDITOR_LICENSE_KEY=enterprise_eyJ-from-file\nOTHER_KEY=ignored\n'
  );
  try {
    const result = await resolveLicenseKey({
      _keychainGet: async () => null,
      _homeFileOverride: filePath,
    });
    assert.equal(result, 'enterprise_eyJ-from-file');
  } finally {
    restore();
    await cleanup();
  }
});

test('CE-0.1.30.2: missing file falls through to null (not an error)', async () => {
  const restore = snapshotEnv('NSAUDITOR_LICENSE_KEY');
  delete process.env.NSAUDITOR_LICENSE_KEY;
  try {
    const result = await resolveLicenseKey({
      _keychainGet: async () => null,
      _homeFileOverride: '/nonexistent/does/not/exist/.env',
    });
    assert.equal(result, null);
  } finally {
    restore();
  }
});

test('CE-0.1.30.2: file with no NSAUDITOR_LICENSE_KEY entry returns null', async () => {
  const restore = snapshotEnv('NSAUDITOR_LICENSE_KEY');
  delete process.env.NSAUDITOR_LICENSE_KEY;
  const { filePath, cleanup } = await withTempEnvFile('SOME_OTHER_KEY=value\n');
  try {
    const result = await resolveLicenseKey({
      _keychainGet: async () => null,
      _homeFileOverride: filePath,
    });
    assert.equal(result, null);
  } finally {
    restore();
    await cleanup();
  }
});

test('CE-0.1.30.2: empty file does not crash; returns null', async () => {
  const restore = snapshotEnv('NSAUDITOR_LICENSE_KEY');
  delete process.env.NSAUDITOR_LICENSE_KEY;
  const { filePath, cleanup } = await withTempEnvFile('');
  try {
    const result = await resolveLicenseKey({
      _keychainGet: async () => null,
      _homeFileOverride: filePath,
    });
    assert.equal(result, null);
  } finally {
    restore();
    await cleanup();
  }
});

test('CE-0.1.30.2: permissive file mode (0644) emits warning but still loads', async () => {
  // Skip on Windows — POSIX mode bits don't apply.
  if (process.platform === 'win32') return;
  const restore = snapshotEnv('NSAUDITOR_LICENSE_KEY');
  delete process.env.NSAUDITOR_LICENSE_KEY;
  const { filePath, cleanup } = await withTempEnvFile(
    'NSAUDITOR_LICENSE_KEY=enterprise_eyJ-from-permissive-file',
    0o644
  );
  // Capture console.warn output.
  const origWarn = console.warn;
  let warned = '';
  console.warn = (msg) => { warned += String(msg) + '\n'; };
  try {
    const result = await resolveLicenseKey({
      _keychainGet: async () => null,
      _homeFileOverride: filePath,
    });
    assert.equal(result, 'enterprise_eyJ-from-permissive-file');
    assert.match(warned, /permissive mode 644/, 'expected permissive-mode warning');
    assert.match(warned, /chmod 0600/, 'warning should suggest the fix');
  } finally {
    console.warn = origWarn;
    restore();
    await cleanup();
  }
});

test('CE-0.1.30.2: tight file mode (0600) does NOT trigger a warning', async () => {
  if (process.platform === 'win32') return;
  const restore = snapshotEnv('NSAUDITOR_LICENSE_KEY');
  delete process.env.NSAUDITOR_LICENSE_KEY;
  const { filePath, cleanup } = await withTempEnvFile(
    'NSAUDITOR_LICENSE_KEY=enterprise_eyJ-from-tight-file',
    0o600
  );
  const origWarn = console.warn;
  let warned = '';
  console.warn = (msg) => { warned += String(msg) + '\n'; };
  try {
    const result = await resolveLicenseKey({
      _keychainGet: async () => null,
      _homeFileOverride: filePath,
    });
    assert.equal(result, 'enterprise_eyJ-from-tight-file');
    assert.equal(warned, '', 'no warning for mode 0600');
  } finally {
    console.warn = origWarn;
    restore();
    await cleanup();
  }
});

// ── 4. All sources empty ─────────────────────────────────────────────────────

test('CE-0.1.30.2: all sources empty returns null', async () => {
  const restore = snapshotEnv('NSAUDITOR_LICENSE_KEY');
  delete process.env.NSAUDITOR_LICENSE_KEY;
  try {
    const result = await resolveLicenseKey({
      _keychainGet: async () => null,
      _homeFileOverride: '/nonexistent',
    });
    assert.equal(result, null);
  } finally {
    restore();
  }
});

// ── 5. Default path resolution (XDG_CONFIG_HOME) ─────────────────────────────

test('CE-0.1.30.2: $XDG_CONFIG_HOME is honored when set (Linux convention)', async () => {
  const restore = snapshotEnv('NSAUDITOR_LICENSE_KEY', 'XDG_CONFIG_HOME', 'HOME');
  delete process.env.NSAUDITOR_LICENSE_KEY;
  // Build an XDG-style path
  const dir = await fsp.mkdtemp(join(tmpdir(), 'nsauditor-xdg-test-'));
  const xdgNsauditor = join(dir, 'nsauditor');
  await fsp.mkdir(xdgNsauditor, { recursive: true });
  await fsp.writeFile(
    join(xdgNsauditor, '.env'),
    'NSAUDITOR_LICENSE_KEY=enterprise_eyJ-from-xdg',
    { mode: 0o600 },
  );
  process.env.XDG_CONFIG_HOME = dir;
  try {
    // No _homeFileOverride — exercise the default path resolution.
    const result = await resolveLicenseKey({
      _keychainGet: async () => null,
    });
    assert.equal(result, 'enterprise_eyJ-from-xdg');
  } finally {
    restore();
    await fsp.rm(dir, { recursive: true, force: true });
  }
});

// ── 6. loadLicense end-to-end with chained resolution ────────────────────────

test('CE-0.1.30.2: loadLicense() invokes the chain when called with no arg', async () => {
  // Smoke for the integration: loadLicense() without keyStr argument must
  // hit resolveLicenseKey(). This verifies the production wiring at
  // utils/license.mjs:loadLicense:55 (`raw = keyStr ?? (await resolveLicenseKey())`).
  // The actual JWT verify will fail on our synthetic key — we only assert
  // that the chain WAS used (i.e., the reason is "invalid license key"
  // not "no key provided", which would mean the chain returned null).
  const { loadLicense } = await import('../utils/license.mjs');
  const restore = snapshotEnv('NSAUDITOR_LICENSE_KEY');
  process.env.NSAUDITOR_LICENSE_KEY = 'enterprise_synthetic-key-not-real';
  try {
    const result = await loadLicense();    // no arg → resolver chain
    assert.equal(result.valid, false);
    assert.equal(
      result.reason, 'invalid license key',
      'chain provided a key (so reason is "invalid", not "no key provided")'
    );
  } finally {
    restore();
  }
});

// ── 7. Reviewer fold tests ───────────────────────────────────────────────────

test('CE-0.1.30.2 reviewer M10: permissive-mode warning fires only once per path per process', async () => {
  if (process.platform === 'win32') return;
  const restore = snapshotEnv('NSAUDITOR_LICENSE_KEY');
  delete process.env.NSAUDITOR_LICENSE_KEY;
  const { filePath, cleanup } = await withTempEnvFile(
    'NSAUDITOR_LICENSE_KEY=enterprise_eyJ-from-permissive-file',
    0o644
  );
  // Reset the warn-cache so the test sees a clean slate.
  _resetCache();
  const origWarn = console.warn;
  let warnCount = 0;
  console.warn = () => { warnCount += 1; };
  try {
    await resolveLicenseKey({ _keychainGet: async () => null, _homeFileOverride: filePath });
    await resolveLicenseKey({ _keychainGet: async () => null, _homeFileOverride: filePath });
    await resolveLicenseKey({ _keychainGet: async () => null, _homeFileOverride: filePath });
    assert.equal(warnCount, 1, `permissive warning should fire ONCE for repeated calls on the same path; got ${warnCount}`);
  } finally {
    console.warn = origWarn;
    restore();
    await cleanup();
  }
});

test('CE-0.1.30.2 reviewer L4: dotenv quoted-value form works', async () => {
  // Customers may write the file with quoted values:
  //   NSAUDITOR_LICENSE_KEY="enterprise_eyJ..."
  // or with spaces around `=`:
  //   NSAUDITOR_LICENSE_KEY = enterprise_eyJ
  // Both must parse correctly.
  const restore = snapshotEnv('NSAUDITOR_LICENSE_KEY');
  delete process.env.NSAUDITOR_LICENSE_KEY;
  const cases = [
    ['NSAUDITOR_LICENSE_KEY="enterprise_quoted"\n', 'enterprise_quoted'],
    ['NSAUDITOR_LICENSE_KEY = enterprise_spaced\n', 'enterprise_spaced'],
    [`NSAUDITOR_LICENSE_KEY='enterprise_singlequoted'\n`, 'enterprise_singlequoted'],
  ];
  for (const [content, expected] of cases) {
    const { filePath, cleanup } = await withTempEnvFile(content);
    try {
      const result = await resolveLicenseKey({
        _keychainGet: async () => null,
        _homeFileOverride: filePath,
      });
      assert.equal(result, expected, `expected ${expected} for content ${JSON.stringify(content)}`);
    } finally {
      await cleanup();
    }
  }
  restore();
});

test('CE-0.1.30.2: loadLicense(undefined) is equivalent to loadLicense()', async () => {
  const { loadLicense } = await import('../utils/license.mjs');
  const restore = snapshotEnv('NSAUDITOR_LICENSE_KEY');
  delete process.env.NSAUDITOR_LICENSE_KEY;
  try {
    const r1 = await loadLicense();
    const r2 = await loadLicense(undefined);
    assert.deepEqual(r1, r2);
  } finally {
    restore();
  }
});
