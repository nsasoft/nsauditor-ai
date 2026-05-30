import { test } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { resolveScanEnv } from '../utils/env_loader.mjs';

// Injected fs fakes: a map of path -> contents.
function fakeFs(files) {
  return {
    fileExists: (p) => Object.prototype.hasOwnProperty.call(files, p),
    readFile: (p) => {
      if (!Object.prototype.hasOwnProperty.call(files, p)) throw new Error(`ENOENT ${p}`);
      return files[p];
    },
  };
}

test('--env valid dotenv → values land in .set (override semantics applied by caller)', () => {
  const fs = fakeFs({ '/envs/prod.env': 'CLOUD_PROVIDER=aws\nAWS_REGION=us-east-1\nAWS_PROFILE=prod\n' });
  const r = resolveScanEnv({ envPath: '/envs/prod.env', env: {}, ...fs });
  assert.equal(r.set.CLOUD_PROVIDER, 'aws');
  assert.equal(r.set.AWS_REGION, 'us-east-1');
  assert.equal(r.set.AWS_PROFILE, 'prod');
  assert.deepEqual(r.unset, []);
});

test('--env missing file → throws (fail-fast)', () => {
  const fs = fakeFs({});
  assert.throws(
    () => resolveScanEnv({ envPath: '/envs/nope.env', env: {}, ...fs }),
    /not found|fail/i,
  );
});

test('--env INI-looking file (has [section]) → throws with --aws-profile redirect', () => {
  const fs = fakeFs({ '/home/u/.aws/credentials': '[default]\naws_access_key_id = AKIA\naws_secret_access_key = x\n' });
  assert.throws(
    () => resolveScanEnv({ envPath: '/home/u/.aws/credentials', env: {}, ...fs }),
    /--aws-profile/,
  );
});

test('--env file with zero KEY=value lines → throws (INI/garbage guard)', () => {
  const fs = fakeFs({ '/envs/bad.env': '# just a comment\nnot a kv line\n' });
  assert.throws(() => resolveScanEnv({ envPath: '/envs/bad.env', env: {}, ...fs }), /--aws-profile|KEY=value/i);
});

test('no flags → empty patch, shell untouched', () => {
  const r = resolveScanEnv({ env: { EXISTING: '1' }, fileExists: () => false, readFile: () => '' });
  assert.deepEqual(r.set, {});
  assert.deepEqual(r.unset, []);
});

test('--env dotenv with only export-prefixed lines is NOT misclassified as INI', () => {
  const fs = { fileExists: (p) => p.endsWith('exp.env'), readFile: () => 'export AWS_PROFILE=prod\nexport AWS_REGION=us-east-1\n' };
  const r = resolveScanEnv({ envPath: '/envs/exp.env', env: {}, ...fs });
  assert.equal(r.set.AWS_PROFILE, 'prod');
  assert.equal(r.set.AWS_REGION, 'us-east-1');
});

// === TASK 2: --aws-profile + implied-AWS precedence ===

test('--aws-profile sets AWS_PROFILE + AWS_SDK_LOAD_CONFIG, clears explicit keys, implies CLOUD_PROVIDER=aws', () => {
  const r = resolveScanEnv({
    awsProfile: 'staging',
    env: { AWS_ACCESS_KEY_ID: 'AKIA_STALE', AWS_SECRET_ACCESS_KEY: 's' },
    fileExists: () => false,
    readFile: () => '',
  });
  assert.equal(r.set.AWS_PROFILE, 'staging');
  assert.equal(r.set.AWS_SDK_LOAD_CONFIG, '1');
  assert.equal(r.set.CLOUD_PROVIDER, 'aws');
  assert.ok(r.unset.includes('AWS_ACCESS_KEY_ID'));
  assert.ok(r.unset.includes('AWS_SECRET_ACCESS_KEY'));
  assert.ok(r.unset.includes('AWS_SESSION_TOKEN'));
});

test('--aws-profile does NOT override an already-set CLOUD_PROVIDER (contradictory gcp left as-is)', () => {
  const r = resolveScanEnv({
    awsProfile: 'staging',
    env: { CLOUD_PROVIDER: 'gcp' },
    fileExists: () => false,
    readFile: () => '',
  });
  assert.equal(r.set.CLOUD_PROVIDER, undefined); // not set → existing gcp survives
});

test('--aws-profile beats an AWS_PROFILE provided by an --env file', () => {
  const fs = {
    fileExists: (p) => p === path.resolve('/envs/dev.env'),
    readFile: () => 'AWS_PROFILE=from_file\nCLOUD_PROVIDER=aws\n',
  };
  const r = resolveScanEnv({ envPath: '/envs/dev.env', awsProfile: 'cli_wins', env: {}, ...fs });
  assert.equal(r.set.AWS_PROFILE, 'cli_wins');
});

// === TASK 3: sentinel-host implied CLOUD_PROVIDER ===

test('sentinel host gcp → implies CLOUD_PROVIDER=gcp when unset', () => {
  const r = resolveScanEnv({ host: 'gcp', env: {}, fileExists: () => false, readFile: () => '' });
  assert.equal(r.set.CLOUD_PROVIDER, 'gcp');
});

test('sentinel host AWS (mixed case) → implies aws, normalized lowercase', () => {
  const r = resolveScanEnv({ host: 'AWS', env: {}, fileExists: () => false, readFile: () => '' });
  assert.equal(r.set.CLOUD_PROVIDER, 'aws');
});

test('sentinel host does NOT override an explicit CSV CLOUD_PROVIDER', () => {
  const r = resolveScanEnv({ host: 'aws', env: { CLOUD_PROVIDER: 'aws,gcp' }, fileExists: () => false, readFile: () => '' });
  assert.equal(r.set.CLOUD_PROVIDER, undefined);
});

test('non-sentinel host (IP) → no CLOUD_PROVIDER implication', () => {
  const r = resolveScanEnv({ host: '10.0.0.1', env: {}, fileExists: () => false, readFile: () => '' });
  assert.equal(r.set.CLOUD_PROVIDER, undefined);
});

test('--env file that sets CLOUD_PROVIDER (matching host) wins over sentinel implication, no throw', () => {
  const fs = { fileExists: (p) => p === path.resolve('/envs/gcp.env'), readFile: () => 'CLOUD_PROVIDER=gcp\n' };
  const r = resolveScanEnv({ envPath: '/envs/gcp.env', host: 'gcp', env: {}, ...fs });
  assert.equal(r.set.CLOUD_PROVIDER, 'gcp'); // file value present → host does not overwrite, and matches host so no throw
});

// === FN-audit: host vs CLOUD_PROVIDER contradiction must fail loud, not silently skip everything ===

test('contradiction: --host aws with CLOUD_PROVIDER=gcp in env → throws (no silent skip)', () => {
  assert.throws(
    () => resolveScanEnv({ host: 'aws', env: { CLOUD_PROVIDER: 'gcp' }, fileExists: () => false, readFile: () => '' }),
    /CLOUD_PROVIDER.*gcp|conflict|does not match/i,
  );
});
test('contradiction: --host gcp with CLOUD_PROVIDER=aws from an --env file → throws', () => {
  const fs = { fileExists: (p) => p.endsWith('aws.env'), readFile: () => 'CLOUD_PROVIDER=aws\n' };
  assert.throws(() => resolveScanEnv({ envPath: '/x/aws.env', host: 'gcp', env: {}, ...fs }), /conflict|does not match|CLOUD_PROVIDER/i);
});
test('NO contradiction: --host aws with CLOUD_PROVIDER=aws,gcp CSV (includes aws) → does not throw', () => {
  const r = resolveScanEnv({ host: 'aws', env: { CLOUD_PROVIDER: 'aws,gcp' }, fileExists: () => false, readFile: () => '' });
  assert.equal(r.set.CLOUD_PROVIDER, undefined); // already set, host doesn't override; no throw
});
test('NO contradiction: --host aws, CLOUD_PROVIDER unset → implies aws (existing behavior preserved)', () => {
  const r = resolveScanEnv({ host: 'aws', env: {}, fileExists: () => false, readFile: () => '' });
  assert.equal(r.set.CLOUD_PROVIDER, 'aws');
});
