import { test } from 'node:test';
import assert from 'node:assert/strict';
import { applyScanEnvFile } from '../utils/mcp_env_file.mjs';

function fakeFs(map) {
  return {
    fileExists: (p) => Object.prototype.hasOwnProperty.call(map, p),
    readFile: (p) => map[p],
  };
}

test('no-op when NSA_ENV_FILE unset', () => {
  const env = { FOO: 'bar' };
  const logs = [];
  const r = applyScanEnvFile({ env, ...fakeFs({}), log: (m) => logs.push(m) });
  assert.deepEqual(r, { applied: [], ignored: [], cleared: [] });
  assert.deepEqual(env, { FOO: 'bar' });
  assert.equal(logs.length, 0);
});

test('applies dotenv keys into env (file wins over ambient)', () => {
  const env = { NSA_ENV_FILE: '/e.env', CLOUD_PROVIDER: 'azure' };
  const fs = fakeFs({ '/e.env': 'CLOUD_PROVIDER=aws\nAWS_ACCESS_KEY_ID=AKIA\n' });
  const r = applyScanEnvFile({ env, ...fs, log: () => {} });
  assert.equal(env.CLOUD_PROVIDER, 'aws');
  assert.equal(env.AWS_ACCESS_KEY_ID, 'AKIA');
  assert.deepEqual(r.applied.sort(), ['AWS_ACCESS_KEY_ID', 'CLOUD_PROVIDER']);
});

test('fail-fast: missing file throws', () => {
  const env = { NSA_ENV_FILE: '/missing.env' };
  assert.throws(() => applyScanEnvFile({ env, ...fakeFs({}), log: () => {} }), /not found/);
});

test('fail-fast: INI/credentials file rejected', () => {
  const env = { NSA_ENV_FILE: '/creds' };
  const fs = fakeFs({ '/creds': '[default]\naws_access_key_id=AKIA\n' });
  assert.throws(() => applyScanEnvFile({ env, ...fs, log: () => {} }), /INI/);
});

test('security boundary: NSA_MCP_AUTH_KEY in file is ignored, inline value kept', () => {
  const env = { NSA_ENV_FILE: '/e.env', NSA_MCP_AUTH_KEY: 'INLINE' };
  const fs = fakeFs({ '/e.env': 'NSA_MCP_AUTH_KEY=FROMFILE\nCLOUD_PROVIDER=aws\n' });
  const logs = [];
  const r = applyScanEnvFile({ env, ...fs, log: (m) => logs.push(m) });
  assert.equal(env.NSA_MCP_AUTH_KEY, 'INLINE');
  assert.equal(env.CLOUD_PROVIDER, 'aws');
  assert.deepEqual(r.ignored, ['NSA_MCP_AUTH_KEY']);
  assert.ok(logs.some((m) => m.includes('ignored NSA_MCP_AUTH_KEY')));
});

test('license key in file is ignored too', () => {
  const env = { NSA_ENV_FILE: '/e.env', NSAUDITOR_LICENSE_KEY: 'ENT' };
  const fs = fakeFs({ '/e.env': 'NSAUDITOR_LICENSE_KEY=HACK\nCLOUD_PROVIDER=gcp\n' });
  const r = applyScanEnvFile({ env, ...fs, log: () => {} });
  assert.equal(env.NSAUDITOR_LICENSE_KEY, 'ENT');
  assert.deepEqual(r.ignored, ['NSAUDITOR_LICENSE_KEY']);
});

test('breadcrumb logs key NAMES only, never values', () => {
  const env = { NSA_ENV_FILE: '/e.env' };
  const fs = fakeFs({ '/e.env': 'AWS_SECRET_ACCESS_KEY=supersecret123\n' });
  const logs = [];
  applyScanEnvFile({ env, ...fs, log: (m) => logs.push(m) });
  const joined = logs.join('\n');
  assert.ok(joined.includes('AWS_SECRET_ACCESS_KEY'));
  assert.ok(!joined.includes('supersecret123'));
});

test('R-HIGH-1: clears leftover ambient AWS creds the file did not set', () => {
  const env = {
    NSA_ENV_FILE: '/e.env',
    AWS_ACCESS_KEY_ID: 'AKIA_AMBIENT_ACCOUNT_A',
    AWS_SECRET_ACCESS_KEY: 'ambient_secret',
  };
  const fs = fakeFs({ '/e.env': 'CLOUD_PROVIDER=aws\nNSA_ALLOW_ALL_HOSTS=1\n' });
  const logs = [];
  const r = applyScanEnvFile({ env, ...fs, log: (m) => logs.push(m) });
  assert.equal(env.AWS_ACCESS_KEY_ID, undefined);      // leftover cleared
  assert.equal(env.AWS_SECRET_ACCESS_KEY, undefined);  // leftover cleared
  assert.equal(env.CLOUD_PROVIDER, 'aws');
  assert.ok(r.cleared.includes('AWS_ACCESS_KEY_ID'));
  assert.ok(r.cleared.includes('AWS_SECRET_ACCESS_KEY'));
  assert.ok(logs.some((m) => m.includes('cleared ambient')));
});

test('does NOT clear creds the file DID set (file wins, no spurious clear)', () => {
  const env = { NSA_ENV_FILE: '/e.env', AWS_ACCESS_KEY_ID: 'AKIA_OLD' };
  const fs = fakeFs({ '/e.env': 'CLOUD_PROVIDER=aws\nAWS_ACCESS_KEY_ID=AKIA_NEW\nAWS_SECRET_ACCESS_KEY=newsecret\n' });
  const r = applyScanEnvFile({ env, ...fs, log: () => {} });
  assert.equal(env.AWS_ACCESS_KEY_ID, 'AKIA_NEW');     // file value wins
  assert.equal(env.AWS_SECRET_ACCESS_KEY, 'newsecret');
  assert.deepEqual(r.cleared, []);                      // nothing leftover to clear
});

test('R-MEDIUM-1: NSA_ENV_FILE set-but-empty fails fast (not a silent no-op)', () => {
  assert.throws(
    () => applyScanEnvFile({ env: { NSA_ENV_FILE: '' }, ...fakeFs({}), log: () => {} }),
    /set but empty/,
  );
});

test('truly-unset NSA_ENV_FILE is still a clean no-op (does not clear ambient creds)', () => {
  const env = { AWS_ACCESS_KEY_ID: 'AKIA_AMBIENT' }; // no NSA_ENV_FILE key at all
  const r = applyScanEnvFile({ env, ...fakeFs({}), log: () => {} });
  assert.deepEqual(r, { applied: [], ignored: [], cleared: [] });
  assert.equal(env.AWS_ACCESS_KEY_ID, 'AKIA_AMBIENT'); // untouched when feature unused
});

// ── The Azure CLOUD SELECTORS are credential-adjacent and must be cleared too ──
// Found while building the EE sovereign-cloud resolver (F3-Azure, EE 2026-08-27).
// PROVIDER_CRED_KEYS listed AZURE_CLIENT_ID / TENANT_ID / CLIENT_SECRET /
// SUBSCRIPTION_ID but not the variables that decide WHICH AZURE CLOUD is
// addressed. Its stated contract is "clear leftover ambient provider creds the
// file did NOT set", and the anti-false-clean purpose is that the env file IS the
// scan-target selector — but an ambient AZURE_ENVIRONMENT or AZURE_ARM_ENDPOINT
// survived, so the file could select one target while the ambient shell silently
// redirected the scan to another cloud's ARM. A subscription id and the cloud its
// ARM lives in are one selection, not two.
//
// AZURE_AUTHORITY_HOST matters for the same reason and is read by @azure/identity
// itself, so it can steer authentication with no code of ours involved.
test('mcp_env_file: ambient Azure CLOUD SELECTORS are cleared when the file does not set them', () => {
  const env = {
    AZURE_SUBSCRIPTION_ID: 'ambient-sub',
    AZURE_ENVIRONMENT: 'AzureUSGovernment',
    ARM_ENVIRONMENT: 'usgovernment',
    AZURE_ARM_ENDPOINT: 'https://management.usgovcloudapi.net',
    AZURE_AUTHORITY_HOST: 'https://login.microsoftonline.us',
    NSA_ENV_FILE: '/x/commercial.env',
  };
  const r = applyScanEnvFile({
    env,
    fileExists: () => true,
    readFile: () => 'AZURE_SUBSCRIPTION_ID=file-sub\n',
    log: () => {},
  });
  assert.equal(env.AZURE_SUBSCRIPTION_ID, 'file-sub', 'the file must win for what it sets');
  for (const k of ['AZURE_ENVIRONMENT', 'ARM_ENVIRONMENT', 'AZURE_ARM_ENDPOINT', 'AZURE_AUTHORITY_HOST']) {
    assert.equal(env[k], undefined, `ambient ${k} survived the env-file selection`);
    assert.ok(r.cleared.includes(k), `${k} was not reported as cleared`);
  }
});

test('mcp_env_file: a cloud selector the FILE sets is honoured, not cleared', () => {
  // The fourth quadrant: the fix must not make sovereign scanning impossible via
  // the very mechanism operators use to select a target.
  const env = { NSA_ENV_FILE: '/x/gov.env' };
  applyScanEnvFile({
    env,
    fileExists: () => true,
    readFile: () => 'AZURE_SUBSCRIPTION_ID=s\nAZURE_ENVIRONMENT=AzureUSGovernment\n',
    log: () => {},
  });
  assert.equal(env.AZURE_ENVIRONMENT, 'AzureUSGovernment');
  assert.equal(env.AZURE_SUBSCRIPTION_ID, 's');
});
