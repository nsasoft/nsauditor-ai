import { withNoDotenv } from './helpers/no_operator_dotenv.mjs';
import { test } from 'node:test';
import './helpers/no_operator_keychain.mjs';   // FIRST: keeps this file off the operator's real Keychain
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

// B99 (2026-10-27): `nsauditor-ai license <unknown>` printed the usage line and exited 0, so a script or an AI agent
// that typed a subcommand wrong, or called one this release does not ship (`license status` for `license --status`),
// read the call as a success. An unknown `license` subcommand, and `license` with NO subcommand (the likeliest agent
// misspelling of `license --status`), now print the usage on stderr and exit 2, the usage exit code — as `feed` and
// `compliance` with no verb already do (the audit-review seat's ruling, 2026-10-27, Q8). The explicit ask for the usage,
// `license --help`, reaches the global help and exits 0. FOURTH QUADRANT FIRST: every shipped subcommand and `--help`
// still exit 0.

const exec = promisify(execFile);
const CLI = join(dirname(fileURLToPath(import.meta.url)), '..', 'cli.mjs');

function isolatedEnv() {
  const env = { ...process.env };
  delete env.NSAUDITOR_LICENSE_KEY;
  env.XDG_CONFIG_HOME = '/nonexistent-license-resolver-isolation';
  return env;
}

/** Run the CLI; resolve with { code, stdout, stderr } whatever the exit code. */
async function run(args) {
  try {
    const { stdout, stderr } = await exec('node', [CLI, ...args], { env: withNoDotenv(isolatedEnv()) });
    return { code: 0, stdout, stderr };
  } catch (err) {
    return { code: err.code, stdout: err.stdout ?? '', stderr: err.stderr ?? '' };
  }
}

const USAGE = /Usage: nsauditor-ai license --status \| --capabilities \| --plugins \| install <KEY> \| --reset \[--purge\]/;

test('(first) the shipped read-only subcommands still exit 0', async () => {
  for (const sub of ['--status', '--capabilities', '--plugins']) {
    const r = await run(['license', sub]);
    assert.equal(r.code, 0, `license ${sub} exited ${r.code}: ${r.stderr}`);
  }
});

test('(first) `license --help` is the explicit ask for the usage: the global help, exit 0, on stdout', async () => {
  const r = await run(['license', '--help']);
  assert.equal(r.code, 0, r.stderr);
  assert.match(r.stdout, /nsauditor-ai license <subcommand>/);
});

test('`license` with no subcommand is a failed call: the usage on stderr, exit 2', async () => {
  const r = await run(['license']);
  assert.equal(r.code, 2, `exited ${r.code}; stdout: ${r.stdout}`);
  assert.match(r.stderr, /missing license subcommand/);
  assert.match(r.stderr, USAGE);
  assert.doesNotMatch(r.stdout, USAGE, 'the usage of a failed call belongs on stderr');
});

for (const sub of ['status', 'frobnicate', '--stauts', 'activate']) {
  test(`\`license ${sub}\` is not a subcommand: the usage on stderr, exit 2`, async () => {
    const r = await run(['license', sub]);
    assert.equal(r.code, 2, `exited ${r.code}; stdout: ${r.stdout}`);
    assert.match(r.stderr, USAGE);
    assert.match(r.stderr, new RegExp(`unknown license subcommand: ${sub.replace(/[-]/g, '\\-')}`));
    assert.doesNotMatch(r.stdout, USAGE, 'the usage of a failed call belongs on stderr');
  });
}
