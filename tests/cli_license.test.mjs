import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const exec = promisify(execFile);
const CLI = join(dirname(fileURLToPath(import.meta.url)), '..', 'cli.mjs');

test('license --status prints CE when no key set', async () => {
  const env = { ...process.env };
  delete env.NSAUDITOR_LICENSE_KEY;
  const { stdout } = await exec('node', [CLI, 'license', '--status'], { env });
  assert.ok(
    stdout.includes('CE') || stdout.includes('Community') || stdout.includes('community'),
    `Expected CE/Community in output, got: ${stdout}`
  );
});

test('license --capabilities lists CE capabilities', async () => {
  const env = { ...process.env };
  delete env.NSAUDITOR_LICENSE_KEY;
  const { stdout } = await exec('node', [CLI, 'license', '--capabilities'], { env });
  assert.ok(stdout.includes('coreScanning'), `Missing coreScanning in: ${stdout}`);
  assert.ok(stdout.includes('basicMCP'), `Missing basicMCP in: ${stdout}`);
});
