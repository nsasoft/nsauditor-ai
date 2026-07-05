// Move 2.7 — CSV-of-sentinels + --host-file + --aws-profile reconcile for
// resolveScanEnv. Regression guard for the multi-cloud one-liner false-clean:
// `--host aws,gcp,azure` (or a --host-file of sentinels) under a stale/implied
// CLOUD_PROVIDER must either imply the UNION of the sentinel legs (when the
// operator did not pin CLOUD_PROVIDER) or FAIL-FAST (when a pinned provider does
// not cover every leg) — never silently run a subset while reporting all legs
// "audited-clean". See tasks/todo.md Move 2.7 + tasks/pass-tier-curation notes.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { resolveScanEnv } from '../utils/env_loader.mjs';

const NOFS = { fileExists: () => false, readFile: () => '' };

// ── CSV host string (--host aws,gcp,azure) ─────────────────────────────────

test('CSV host + CLOUD_PROVIDER unset → implies the UNION of sentinel legs', () => {
  const r = resolveScanEnv({ host: 'aws,gcp,azure', env: {}, ...NOFS });
  assert.equal(r.set.CLOUD_PROVIDER, 'aws,gcp,azure');
});

test('CSV host + stale single CLOUD_PROVIDER=aws (misses gcp/azure legs) → THROWS (no silent subset)', () => {
  assert.throws(
    () => resolveScanEnv({ host: 'aws,gcp,azure', env: { CLOUD_PROVIDER: 'aws' }, ...NOFS }),
    /gcp|azure|conflict|not covered|does not/i,
  );
});

test('CSV host covered by a wider CLOUD_PROVIDER CSV → no throw, no override', () => {
  const r = resolveScanEnv({ host: 'aws,gcp', env: { CLOUD_PROVIDER: 'aws,gcp,azure' }, ...NOFS });
  assert.equal(r.set.CLOUD_PROVIDER, undefined); // already covered → operator value untouched
});

test('CSV host with one leg (azure) missing from the pinned CSV → THROWS', () => {
  assert.throws(
    () => resolveScanEnv({ host: 'aws,gcp,azure', env: { CLOUD_PROVIDER: 'aws,gcp' }, ...NOFS }),
    /azure/i,
  );
});

test('CSV host + --aws-profile, CLOUD_PROVIDER unset → UNION-MERGE (profile-implied aws does not throw)', () => {
  // The tool itself implies CLOUD_PROVIDER=aws for --aws-profile; that must NOT
  // trip the conflict check against the gcp/azure legs — it union-merges instead.
  const r = resolveScanEnv({ host: 'aws,gcp,azure', awsProfile: 'prod', env: {}, ...NOFS });
  assert.equal(r.set.CLOUD_PROVIDER, 'aws,gcp,azure');
  assert.equal(r.set.AWS_PROFILE, 'prod');
  assert.equal(r.set.AWS_SDK_LOAD_CONFIG, '1');
});

test('CSV host mixed sentinel + network IP + unset → implies only the sentinel union', () => {
  const r = resolveScanEnv({ host: 'aws,10.0.0.1', env: {}, ...NOFS });
  assert.equal(r.set.CLOUD_PROVIDER, 'aws');
});

test('CSV host with dup/mixed-case legs → deduped, lowercased, first-appearance order', () => {
  const r = resolveScanEnv({ host: 'GCP,aws,gcp', env: {}, ...NOFS });
  assert.equal(r.set.CLOUD_PROVIDER, 'gcp,aws');
});

test('CSV host + stale single CLOUD_PROVIDER=gcp that covers gcp but not aws → THROWS on aws leg', () => {
  assert.throws(
    () => resolveScanEnv({ host: 'aws,gcp', env: { CLOUD_PROVIDER: 'gcp' }, ...NOFS }),
    /aws/i,
  );
});

// ── --host-file resolved list (hosts[] array) ──────────────────────────────

test('hosts[] of sentinels + unset → implies the union (host-file path)', () => {
  const r = resolveScanEnv({ hosts: ['aws', 'gcp'], env: {}, ...NOFS });
  assert.equal(r.set.CLOUD_PROVIDER, 'aws,gcp');
});

test('hosts[] of sentinels + stale single CLOUD_PROVIDER=aws (misses gcp) → THROWS', () => {
  assert.throws(
    () => resolveScanEnv({ hosts: ['aws', 'gcp'], env: { CLOUD_PROVIDER: 'aws' }, ...NOFS }),
    /gcp|conflict|not covered/i,
  );
});

test('hosts[] of only network hosts → no implication, no throw', () => {
  const r = resolveScanEnv({ hosts: ['10.0.0.1', 'host.example'], env: {}, ...NOFS });
  assert.equal(r.set.CLOUD_PROVIDER, undefined);
});

test('hosts[] of sentinels + --aws-profile + unset → union-merge (no throw)', () => {
  const r = resolveScanEnv({ hosts: ['aws', 'gcp'], awsProfile: 'p', env: {}, ...NOFS });
  assert.equal(r.set.CLOUD_PROVIDER, 'aws,gcp');
  assert.equal(r.set.AWS_PROFILE, 'p');
});

test('hosts[] sentinels + CLOUD_PROVIDER from an --env file that covers all legs → no throw', () => {
  const fs = { fileExists: (p) => p === path.resolve('/e/all.env'), readFile: () => 'CLOUD_PROVIDER=aws,gcp,azure\n' };
  const r = resolveScanEnv({ envPath: '/e/all.env', hosts: ['aws', 'gcp'], env: {}, ...fs });
  assert.equal(r.set.CLOUD_PROVIDER, 'aws,gcp,azure'); // file value present + covers legs → untouched
});

// ── single-sentinel regressions (existing behavior must be byte-identical) ──

test('single sentinel host still implies its provider when unset (regression)', () => {
  const r = resolveScanEnv({ host: 'gcp', env: {}, ...NOFS });
  assert.equal(r.set.CLOUD_PROVIDER, 'gcp');
});

test('single sentinel host contradiction still throws (regression)', () => {
  assert.throws(
    () => resolveScanEnv({ host: 'aws', env: { CLOUD_PROVIDER: 'gcp' }, ...NOFS }),
    /gcp|conflict|does not/i,
  );
});
