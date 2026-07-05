// argv-level end-to-end for Move 2.7's --host-file reconcile wiring. The resolver
// logic (resolveScanEnv) is unit-tested in env_loader_multicloud_scope; THIS test
// proves the CLI actually threads a --host-file's resolved sentinel legs into the
// reconcile (parseHostFile → resolveScanEnv), so a stale CLOUD_PROVIDER that misses
// a leg fail-fasts (exit 1) instead of silently skipping that cloud — the third
// reachability path Move 2.7 closed. The conflict fail-fast fires in the env block
// BEFORE license/scan, so this is deterministic + fast (no creds, no network).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { writeFileSync, unlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';

const __dirname = dirname(fileURLToPath(import.meta.url));
const BIN = join(__dirname, '..', 'bin', 'nsauditor-ai.mjs');

test('--host-file of sentinels + stale CLOUD_PROVIDER=aws → CLI fail-fasts (exit 1, names uncovered legs)', () => {
  const hf = join(tmpdir(), `nsa-hostfile-reconcile-${process.pid}.txt`);
  writeFileSync(hf, 'aws\ngcp\nazure\n');
  try {
    const r = spawnSync(process.execPath, [BIN, 'scan', '--host-file', hf, '--plugins', 'all'],
      { encoding: 'utf8', env: { ...process.env, CLOUD_PROVIDER: 'aws' } });
    assert.equal(r.status, 1, `expected exit 1; stderr: ${r.stderr}`);
    assert.match(r.stderr, /conflicts with CLOUD_PROVIDER|not covered/i,
      `expected the reconcile conflict error; stderr: ${r.stderr}`);
    assert.match(r.stderr, /gcp|azure/i, `error should name the uncovered legs; stderr: ${r.stderr}`);
  } finally {
    try { unlinkSync(hf); } catch { /* best-effort cleanup */ }
  }
});
