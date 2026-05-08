import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const exec = promisify(execFile);
const CLI = join(dirname(fileURLToPath(import.meta.url)), '..', 'cli.mjs');

// CE-0.1.30.2: the license resolver is multi-source (env → Keychain → file).
// To assert "no key set" semantics we must isolate all three sources, not
// just the env var. Setting XDG_CONFIG_HOME to a non-existent path makes
// the file source return null. The macOS Keychain is not isolated here
// (would require shelling out to `security delete-generic-password` and
// restoring after); the test relies on the developer NOT having run
// `nsauditor-ai license install` (which writes to Keychain on macOS).
// CI runners on Linux have no Keychain — automatically isolated there.
function isolatedEnv() {
  const env = { ...process.env };
  delete env.NSAUDITOR_LICENSE_KEY;
  env.XDG_CONFIG_HOME = '/nonexistent-license-resolver-isolation';
  return env;
}

test('license --status prints CE when no key set', async () => {
  const env = isolatedEnv();
  const { stdout } = await exec('node', [CLI, 'license', '--status'], { env });
  assert.ok(
    stdout.includes('CE') || stdout.includes('Community') || stdout.includes('community'),
    `Expected CE/Community in output, got: ${stdout}`
  );
});

test('license --capabilities lists CE capabilities', async () => {
  const env = isolatedEnv();
  const { stdout } = await exec('node', [CLI, 'license', '--capabilities'], { env });
  assert.ok(stdout.includes('coreScanning'), `Missing coreScanning in: ${stdout}`);
  assert.ok(stdout.includes('basicMCP'), `Missing basicMCP in: ${stdout}`);
});
