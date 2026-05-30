import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const BIN = join(__dirname, '..', 'bin', 'nsauditor-ai.mjs');

test('bin wrapper runs main() — `--version` prints version and exits 0', () => {
  const r = spawnSync(process.execPath, [BIN, '--version'], { encoding: 'utf8' });
  assert.equal(r.status, 0, `exit code; stderr: ${r.stderr}`);
  assert.match(r.stdout, /nsauditor-ai \d+\.\d+\.\d+/, `stdout was: ${JSON.stringify(r.stdout)}`);
});

test('bin wrapper runs main() — `--help` prints usage', () => {
  const r = spawnSync(process.execPath, [BIN, '--help'], { encoding: 'utf8' });
  assert.equal(r.status, 0, `exit code; stderr: ${r.stderr}`);
  assert.match(r.stdout, /Usage:|Scan options:/);
});
