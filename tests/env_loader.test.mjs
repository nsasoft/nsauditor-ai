import { test } from 'node:test';
import assert from 'node:assert/strict';
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
