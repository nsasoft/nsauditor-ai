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
  assert.deepEqual(r, { applied: [], ignored: [] });
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
