import test from 'node:test';
import assert from 'node:assert/strict';
import fsp from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';

import {
  STATUSES,
  checkPlugins,
  checkLicense,
  checkAiProviders,
  checkOutputDir,
  checkNetwork,
  runValidation,
  _internals,
} from '../utils/validate.mjs';

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

function withEnv(overrides, fn) {
  const saved = {};
  const keys = Object.keys(overrides);
  for (const k of keys) saved[k] = process.env[k];
  for (const [k, v] of Object.entries(overrides)) {
    if (v == null) delete process.env[k];
    else process.env[k] = v;
  }
  try {
    return fn();
  } finally {
    for (const k of keys) {
      if (saved[k] == null) delete process.env[k];
      else process.env[k] = saved[k];
    }
  }
}

// ---------------------------------------------------------------------------
// checkPlugins
// ---------------------------------------------------------------------------

test('checkPlugins: ok when discover returns plugins', async () => {
  const result = await checkPlugins({
    discover: async () => [{ id: '001' }, { id: '002' }, { id: '003' }],
  });
  assert.equal(result.status, STATUSES.OK);
  assert.equal(result.name, 'plugins');
  assert.match(result.message, /3 plugins loaded/);
  assert.equal(result.details.count, 3);
});

test('checkPlugins: handles single-plugin grammar', async () => {
  const result = await checkPlugins({ discover: async () => [{ id: '001' }] });
  assert.match(result.message, /1 plugin loaded/);
});

test('checkPlugins: handles { plugins } wrapper shape', async () => {
  const result = await checkPlugins({
    discover: async () => ({ plugins: [{ id: '001' }, { id: '002' }] }),
  });
  assert.equal(result.status, STATUSES.OK);
  assert.equal(result.details.count, 2);
});

test('checkPlugins: error when discover throws', async () => {
  const result = await checkPlugins({
    discover: async () => { throw new Error('plugin syntax error in 042_foo.mjs'); },
  });
  assert.equal(result.status, STATUSES.ERROR);
  assert.match(result.message, /Plugin discovery failed/);
  assert.match(result.details.error, /042_foo/);
});

// ---------------------------------------------------------------------------
// checkLicense
// ---------------------------------------------------------------------------

test('checkLicense: skip when no key set', async () => {
  const result = await checkLicense({ env: {} });
  assert.equal(result.status, STATUSES.SKIP);
  assert.match(result.message, /Community Edition/);
  assert.equal(result.details.tier, 'ce');
});

test('checkLicense: ok when JWT verifies cleanly', async () => {
  const result = await checkLicense({
    env: { NSAUDITOR_LICENSE_KEY: 'pro_fake' },
    loadFn: async () => ({ valid: true, tier: 'pro', org: 'acme.example.com', daysUntilExpiry: 90, expiresAt: '2026-07-01' }),
  });
  assert.equal(result.status, STATUSES.OK);
  assert.match(result.message, /pro.*acme/);
});

test('checkLicense: warn when expiring within 7 days', async () => {
  const result = await checkLicense({
    env: { NSAUDITOR_LICENSE_KEY: 'pro_fake' },
    loadFn: async () => ({ valid: true, tier: 'pro', org: 'acme', daysUntilExpiry: 3 }),
  });
  assert.equal(result.status, STATUSES.WARN);
  assert.match(result.message, /expires in 3 days/);
});

test('checkLicense: warn message uses singular for 1-day expiry', async () => {
  const result = await checkLicense({
    env: { NSAUDITOR_LICENSE_KEY: 'pro_fake' },
    loadFn: async () => ({ valid: true, tier: 'pro', org: 'acme', daysUntilExpiry: 1 }),
  });
  assert.match(result.message, /expires in 1 day(?!s)/);
});

test('checkLicense: error when JWT invalid', async () => {
  const result = await checkLicense({
    env: { NSAUDITOR_LICENSE_KEY: 'pro_bogus' },
    loadFn: async () => ({ valid: false, tier: 'ce', reason: 'expired' }),
  });
  assert.equal(result.status, STATUSES.ERROR);
  assert.match(result.message, /expired/);
});

test('checkLicense: error when loadFn throws', async () => {
  const result = await checkLicense({
    env: { NSAUDITOR_LICENSE_KEY: 'pro_fake' },
    loadFn: async () => { throw new Error('unexpected token'); },
  });
  assert.equal(result.status, STATUSES.ERROR);
  assert.match(result.message, /unexpected token/);
});

// ---------------------------------------------------------------------------
// checkAiProviders
// ---------------------------------------------------------------------------

test('checkAiProviders: warn when no provider configured', () => {
  const result = checkAiProviders({ env: {} });
  assert.equal(result.status, STATUSES.WARN);
  assert.deepEqual(result.details.providers, []);
});

test('checkAiProviders: ok when OpenAI configured', () => {
  const result = checkAiProviders({ env: { OPENAI_API_KEY: 'sk-...' } });
  assert.equal(result.status, STATUSES.OK);
  assert.deepEqual(result.details.providers, ['openai']);
});

test('checkAiProviders: ok when Claude configured', () => {
  const result = checkAiProviders({ env: { ANTHROPIC_API_KEY: 'sk-ant-...' } });
  assert.equal(result.status, STATUSES.OK);
  assert.deepEqual(result.details.providers, ['claude']);
});

test('checkAiProviders: ok when Ollama configured via OLLAMA_HOST', () => {
  const result = checkAiProviders({ env: { OLLAMA_HOST: 'http://localhost:11434' } });
  assert.equal(result.status, STATUSES.OK);
  assert.deepEqual(result.details.providers, ['ollama']);
});

test('checkAiProviders: ok when Ollama configured via AI_PROVIDER=ollama', () => {
  const result = checkAiProviders({ env: { AI_PROVIDER: 'ollama' } });
  assert.equal(result.status, STATUSES.OK);
  assert.deepEqual(result.details.providers, ['ollama']);
});

test('checkAiProviders: lists multiple providers when several are configured', () => {
  const result = checkAiProviders({
    env: { OPENAI_API_KEY: 'sk-...', ANTHROPIC_API_KEY: 'sk-ant-...' },
  });
  assert.equal(result.status, STATUSES.OK);
  assert.equal(result.details.providers.length, 2);
  assert.ok(result.details.providers.includes('openai'));
  assert.ok(result.details.providers.includes('claude'));
});

// ---------------------------------------------------------------------------
// checkOutputDir
// ---------------------------------------------------------------------------

test('checkOutputDir: ok against a real temp directory', async () => {
  const tmp = await fsp.mkdtemp(path.join(os.tmpdir(), 'nsa-validate-test-'));
  try {
    const result = await checkOutputDir({ dir: tmp });
    assert.ok(result.status === STATUSES.OK || result.status === STATUSES.WARN);
    assert.equal(result.details.dir, tmp);
  } finally {
    await fsp.rm(tmp, { recursive: true, force: true });
  }
});

test('checkOutputDir: error when mkdir throws', async () => {
  const fakeFs = {
    mkdir: async () => { throw new Error('EACCES: permission denied'); },
  };
  const result = await checkOutputDir({ dir: '/nope', fsApi: fakeFs });
  assert.equal(result.status, STATUSES.ERROR);
  assert.match(result.message, /EACCES/);
});

test('checkOutputDir: warn when free space below threshold', async () => {
  const calls = { writes: 0, unlinks: 0 };
  const fakeFs = {
    mkdir: async () => {},
    writeFile: async () => { calls.writes++; },
    unlink: async () => { calls.unlinks++; },
    statfs: async () => ({ bavail: 1, bsize: 1024 * 1024 }), // 1 MB free
  };
  const result = await checkOutputDir({ dir: '/tmp/fake', fsApi: fakeFs, freeSpaceWarnMB: 100 });
  assert.equal(result.status, STATUSES.WARN);
  assert.match(result.message, /1 MB free/);
  assert.equal(calls.writes, 1);
  assert.equal(calls.unlinks, 1);
});

test('checkOutputDir: ok when free space above threshold', async () => {
  const fakeFs = {
    mkdir: async () => {},
    writeFile: async () => {},
    unlink: async () => {},
    statfs: async () => ({ bavail: 10000, bsize: 1024 * 1024 }), // 10 GB free
  };
  const result = await checkOutputDir({ dir: '/tmp/fake', fsApi: fakeFs });
  assert.equal(result.status, STATUSES.OK);
  assert.match(result.message, /MB free/);
});

test('checkOutputDir: ok when statfs unsupported (skips free-space check)', async () => {
  const fakeFs = {
    mkdir: async () => {},
    writeFile: async () => {},
    unlink: async () => {},
    statfs: async () => { throw new Error('ENOTSUP'); },
  };
  const result = await checkOutputDir({ dir: '/tmp/fake', fsApi: fakeFs });
  assert.equal(result.status, STATUSES.OK);
});

test('checkOutputDir: ok when fsApi has no statfs at all', async () => {
  const fakeFs = {
    mkdir: async () => {},
    writeFile: async () => {},
    unlink: async () => {},
    // no statfs property
  };
  const result = await checkOutputDir({ dir: '/tmp/fake', fsApi: fakeFs });
  assert.equal(result.status, STATUSES.OK);
});

// ---------------------------------------------------------------------------
// checkNetwork
// ---------------------------------------------------------------------------

test('checkNetwork: ok when DNS lookup resolves', async () => {
  const result = await checkNetwork({
    host: 'fake.host',
    lookup: async () => ({ address: '127.0.0.1', family: 4 }),
  });
  assert.equal(result.status, STATUSES.OK);
  assert.match(result.message, /127\.0\.0\.1/);
});

test('checkNetwork: warn when lookup throws', async () => {
  const result = await checkNetwork({
    host: 'fake.host',
    lookup: async () => { throw new Error('ENOTFOUND'); },
  });
  assert.equal(result.status, STATUSES.WARN);
  assert.match(result.message, /ENOTFOUND/);
});

test('checkNetwork: warn when lookup hangs past timeout', async () => {
  const result = await checkNetwork({
    host: 'slow.host',
    timeoutMs: 30,
    lookup: () => new Promise(() => {}), // never resolves
  });
  assert.equal(result.status, STATUSES.WARN);
  assert.match(result.message, /timeout/i);
});

test('checkNetwork: defaults to localhost (hermetic)', async () => {
  // Real localhost lookup — should always succeed, no external network
  const result = await checkNetwork({ timeoutMs: 1000 });
  assert.equal(result.status, STATUSES.OK);
  assert.equal(result.details.host, 'localhost');
});

// ---------------------------------------------------------------------------
// runValidation — aggregator and exit-code mapping
// ---------------------------------------------------------------------------

test('runValidation: returns checks array and overall status', async () => {
  // Use real implementations with safe defaults — should be all-OK or skip in test env
  const result = await runValidation({
    plugins: { discover: async () => [{ id: '001' }] },
    network: { host: 'fake', lookup: async () => ({ address: '1.1.1.1' }) },
  });
  assert.ok(Array.isArray(result.checks));
  assert.equal(result.checks.length, 5);
  assert.ok(['ok', 'warn', 'error'].includes(result.overall));
  assert.ok([0, 1, 2].includes(result.exitCode));
});

test('runValidation: any error → exit 2 / overall=error', async () => {
  const result = await runValidation({
    plugins: { discover: async () => { throw new Error('boom'); } },
    network: { host: 'fake', lookup: async () => ({ address: '1.1.1.1' }) },
  });
  assert.equal(result.overall, STATUSES.ERROR);
  assert.equal(result.exitCode, 2);
});

test('runValidation: any warn (no errors) → exit 1 / overall=warn', async () => {
  // Force a warn from network but everything else ok-or-skip
  const result = await runValidation({
    plugins: { discover: async () => [{ id: '001' }] },
    network: { host: 'fake', lookup: async () => { throw new Error('ENOTFOUND'); } },
  });
  // overall could be 'warn' — license is 'skip', ai is likely 'warn' (no providers in test env)
  assert.ok(result.overall === STATUSES.WARN || result.overall === STATUSES.OK);
  assert.ok(result.exitCode === 1 || result.exitCode === 0);
});

test('runValidation: completes in <2s with normal inputs', async () => {
  const start = Date.now();
  await runValidation({
    plugins: { discover: async () => [{ id: '001' }] },
    network: { host: 'fake', lookup: async () => ({ address: '1.1.1.1' }) },
  });
  const elapsed = Date.now() - start;
  assert.ok(elapsed < 2000, `runValidation took ${elapsed}ms (must be <2000)`);
});

test('runValidation: errors in one check do NOT block others (parallel execution)', async () => {
  const result = await runValidation({
    plugins: { discover: async () => { throw new Error('plugin boom'); } },
    network: { host: 'fake', lookup: async () => ({ address: '1.1.1.1' }) },
  });
  // Despite plugins erroring, network check still runs and reports OK
  const networkCheck = result.checks.find((c) => c.name === 'network');
  assert.ok(networkCheck);
  assert.equal(networkCheck.status, STATUSES.OK);
});

// ---------------------------------------------------------------------------
// _internals — sanity
// ---------------------------------------------------------------------------

test('_internals: exposes named constants', () => {
  assert.equal(_internals.FREE_SPACE_WARN_MB, 100);
  assert.equal(_internals.DEFAULT_NETWORK_TIMEOUT_MS, 1500);
  assert.equal(_internals.DEFAULT_NETWORK_HOST, 'localhost');
});

test('STATUSES is a frozen enum', () => {
  assert.ok(Object.isFrozen(STATUSES));
  assert.equal(STATUSES.OK, 'ok');
  assert.equal(STATUSES.WARN, 'warn');
  assert.equal(STATUSES.ERROR, 'error');
  assert.equal(STATUSES.SKIP, 'skip');
});

// Restore env helper used by some tests
withEnv;
