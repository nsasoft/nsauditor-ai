import { withNoDotenv } from './helpers/no_operator_dotenv.mjs';
import './helpers/no_operator_keychain.mjs';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const BIN = join(__dirname, '..', 'bin', 'nsauditor-ai.mjs');
const CLI = join(__dirname, '..', 'cli.mjs');

test('bin wrapper runs main() — `--version` prints version and exits 0', () => {
  const r = spawnSync(process.execPath, [BIN, '--version'], { env: withNoDotenv(), encoding: 'utf8' });
  assert.equal(r.status, 0, `exit code; stderr: ${r.stderr}`);
  assert.match(r.stdout, /nsauditor-ai \d+\.\d+\.\d+/, `stdout was: ${JSON.stringify(r.stdout)}`);
});

test('bin wrapper runs main() — `--help` prints usage', () => {
  const r = spawnSync(process.execPath, [BIN, '--help'], { env: withNoDotenv(), encoding: 'utf8' });
  assert.equal(r.status, 0, `exit code; stderr: ${r.stderr}`);
  assert.match(r.stdout, /Usage:|Scan options:/);
});

// ── A REJECTED main() THROUGH THE COMMAND npm INSTALLS ───────────────────────────────────────────────────────────────
// npm links `nsauditor-ai` to bin/nsauditor-ai.mjs, which imports main(), so for an installed user cli.mjs is never the
// process entry point. A flag refusal (EFLAGSHAPE / EFLAGVALUE) must still reach them as exit 2 and one `[ERROR]` line —
// what cli.mjs's mapping and README.md say. Exit 1 is `--fail-on`'s "findings at or above the threshold" code, so a flag
// typo that exits 1 reads as a findings verdict in CI. The mapping is ONE exported function that both entry points call;
// these legs spawn the BIN, because a leg that spawns cli.mjs proves the module and not the artifact.
//
// A REFUSED SCAN TARGET is the same class (an operator error, coded ETARGETREFUSED): it reached the operator as exit 1 and
// a stack until the next Community release after 1.0.0.
//
// FOURTH QUADRANT: a rejection that is NOT an operator error keeps exit 1 and its stack — the mapping must not widen. It
// is held at the handler (r4), because no uncoded rejection is reachable through the bin before a scan reaches the
// network: the refused target was the last one.

/** Spawn an entry point with the dotenv neutraliser, NSA_ALLOW_ALL_HOSTS unset, and a throwaway cwd. */
function spawnEntry(entry, args) {
  const cwd = fs.mkdtempSync(join(os.tmpdir(), 'nsa-bin-entry-'));
  try {
    const env = { ...process.env };
    delete env.NSA_ALLOW_ALL_HOSTS;
    const r = spawnSync(process.execPath, [entry, ...args], { cwd, env: withNoDotenv(env), encoding: 'utf8', timeout: 60_000 });
    return { status: r.status, stdout: r.stdout, stderr: r.stderr, cwd };
  } finally {
    fs.rmSync(cwd, { recursive: true, force: true });
  }
}

const FLAG_REFUSALS = [
  { code: 'EFLAGVALUE', args: ['scan', '--host', '192.0.2.1', '--notify-format', 'slack'],
    line: '[ERROR] --notify-format configure the drift notification and need --notify-webhook <url>' },
  { code: 'EFLAGSHAPE', args: ['scan', '--host=192.0.2.1'],
    line: '[ERROR] --host=192.0.2.1: the --flag=value form is not supported. Use a space: --host 192.0.2.1' },
];

test('(r1) a REFUSED scan target through the bin: exit 2, one [ERROR] line, no stack', () => {
  const out = fs.mkdtempSync(join(os.tmpdir(), 'nsa-bin-entry-out-'));
  try {
    const r = spawnEntry(BIN, ['scan', '--host', '127.0.0.1', '--out', out]);
    assert.equal(r.status, 2, `exit ${r.status}; stderr: ${r.stderr.slice(0, 400)}`);
    assert.match(r.stderr, /^\[ERROR\] Scanning blocked address range is not allowed: 127\.0\.0\.1$/m);
    assert.doesNotMatch(r.stderr, /\bat assertScanTargetAllowed\b/, 'a refused target is an operator error, not a crash');
  } finally {
    fs.rmSync(out, { recursive: true, force: true });
  }
});

for (const { code, args, line } of FLAG_REFUSALS) {
  test(`(r2) ${code} through the BIN: exit 2, one [ERROR] line, no stack`, () => {
    const r = spawnEntry(BIN, args);
    assert.equal(r.status, 2, `exit ${r.status}; stderr: ${r.stderr.slice(0, 400)}`);
    assert.equal(r.stderr.trim(), line, `stderr was: ${JSON.stringify(r.stderr.slice(0, 400))}`);
    assert.doesNotMatch(r.stderr, /\bat parseArgs\b/);
    assert.equal(r.stdout, '', 'a refusal before any scan prints nothing on stdout');
  });

  test(`(r3) ${code}: the bin and cli.mjs answer byte-for-byte alike — one mapping, two callers`, () => {
    const viaBin = spawnEntry(BIN, args);
    const viaCli = spawnEntry(CLI, args);
    assert.equal(viaCli.status, 2, `positive control: cli.mjs maps ${code} — exit ${viaCli.status}`);
    assert.deepEqual([viaBin.status, viaBin.stderr, viaBin.stdout], [viaCli.status, viaCli.stderr, viaCli.stdout]);
  });
}

test('(r4) the mapping is ONE function: the bin hands a rejection to cli.mjs\'s exported handler and maps nothing itself', async () => {
  const { exitOnMainRejection } = await import('../cli.mjs');
  assert.equal(typeof exitOnMainRejection, 'function', 'cli.mjs exports the rejection handler');
  const drive = (err) => {
    const lines = []; const exits = [];
    exitOnMainRejection(err, { error: (x) => lines.push(String(x)), exit: (c) => exits.push(c) });
    return { lines, exits };
  };
  const flag = Object.assign(new Error('--x refused'), { code: 'EFLAGVALUE' });
  assert.deepEqual(drive(flag), { lines: ['[ERROR] --x refused'], exits: [2] });
  const shape = Object.assign(new Error('--x=1 refused'), { code: 'EFLAGSHAPE' });
  assert.deepEqual(drive(shape), { lines: ['[ERROR] --x=1 refused'], exits: [2] });
  const plain = new Error('boom');
  const p = drive(plain);
  assert.deepEqual(p.exits, [1]);
  assert.equal(p.lines[0], plain.stack, 'a plain Error prints its stack');
  assert.deepEqual(drive('a thrown string'), { lines: ['a thrown string'], exits: [1] });
  const target = Object.assign(new Error('Scanning blocked address range is not allowed: 127.0.0.1'), { code: 'ETARGETREFUSED' });
  assert.deepEqual(drive(target), { lines: ['[ERROR] Scanning blocked address range is not allowed: 127.0.0.1'], exits: [2] });
  const other = Object.assign(new Error('not a flag'), { code: 'ENOENT' });
  assert.deepEqual(drive(other).exits, [1], 'another error code is not a flag refusal');
  // No second copy of the mapping (the twin-drift class). The bin names the handler and no EFLAG code or exit; cli.mjs
  // compares an error code against EFLAGVALUE in exactly one place, so its own entry block cannot carry a twin either.
  const bin = fs.readFileSync(BIN, 'utf8');
  assert.match(bin, /\bexitOnMainRejection\b/);
  assert.doesNotMatch(bin, /EFLAG|process\.exit/);
  const cli = fs.readFileSync(CLI, 'utf8');
  assert.equal((cli.match(/===\s*'EFLAGVALUE'/g) ?? []).length, 1, 'cli.mjs compares against EFLAGVALUE in more than one place');
  assert.match(cli, /main\(\)\.catch\(\(err\) => exitOnMainRejection\(err\)\)/, 'cli.mjs\'s own entry block calls the handler');
});
