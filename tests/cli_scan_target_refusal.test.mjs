// THE `scan` REQUIRED-TARGET REFUSAL, AS A VALUE — and main() still refuses through it (EE 1.1.0 build 10).
//
// A documented command that cannot run is a claim no gate could read. The scan_cloud tool description taught
// `nsauditor-ai scan --compliance <fw> --out <dir>` for releases, and run as written it exits 2 before any scan:
// the CLI requires --host or --host-file, and a positional target is silently ignored. So that a census can
// judge every DOCUMENTED command by the code that would refuse it, the two checks main() makes before it
// resolves hosts — an unknown command, then a missing target — are one exported pure function.
//
// ⚠️ TWO KINDS OF PROOF, BECAUSE EACH ALONE WAS SHOWN INSUFFICIENT (adversarial review, build 10). The spawned
// legs drive the PUBLISHED bin: same message, same exit code, same order, and the refusal still comes AFTER the
// flag/env/region checks main() makes first. But behaviour cannot tell main() refusing through this function from
// main() refusing through a COPY of its condition — a mutant that restored the old inline checks passed every
// spawned leg — so a structural leg reads cli.mjs: the two refusal messages live in code only inside
// scanTargetRefusal, and main() calls it exactly once.
import './helpers/no_operator_keychain.mjs';   // FIRST: keeps this file off the operator's real Keychain
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { parseArgs, scanTargetRefusal } from '../cli.mjs';

const HOST_REQUIRED = 'Fatal: --host or --host-file is required';

// parseArgs writes SCAN_OUT_PATH for --out; keep this process's environment as it found it.
async function parsed(...argv) {
  const saved = process.env.SCAN_OUT_PATH;
  try { return await parseArgs(['node', 'nsauditor-ai', ...argv]); } finally {
    if (saved === undefined) delete process.env.SCAN_OUT_PATH; else process.env.SCAN_OUT_PATH = saved;
  }
}
const verdict = async (...argv) => scanTargetRefusal(await parsed(...argv));

test('FOURTH QUADRANT FIRST — a scan WITH a target is not refused: a cloud sentinel, an address, a host file', async () => {
  assert.equal(await verdict('scan', '--host', 'aws', '--compliance', 'soc2', '--out', 'evidence'), null);
  assert.equal(await verdict('scan', '--host', '192.0.2.10', '--plugins', 'all'), null);
  assert.equal(await verdict('scan', '--host-file', 'targets.txt', '--plugins', 'all'), null);
  assert.equal(await verdict('scan', '--ip', 'gcp'), null, '--ip and --target are the parser\'s own aliases for --host');
});

test('a scan with NO target is refused with the CLI\'s own message and exit 2 — the documented command as it was', async () => {
  assert.deepEqual(await verdict('scan', '--compliance', 'soc2', '--out', 'evidence'), { message: HOST_REQUIRED, code: 2 });
});

test('a POSITIONAL target is not a target, and `nsauditor-ai <target>` is an unknown command', async () => {
  assert.deepEqual(await verdict('scan', '192.0.2.10', '--compliance', 'iso-27001'), { message: HOST_REQUIRED, code: 2 });
  assert.deepEqual(await verdict('192.0.2.10', '--compliance', 'soc2'), { message: 'Unknown command: 192.0.2.10', code: 2 });
});

test('the ORDER holds: an unknown command is refused as unknown even when no target is given either', async () => {
  assert.deepEqual(scanTargetRefusal({ cmd: 'report', host: undefined, hostFile: undefined }),
    { message: 'Unknown command: report', code: 2 },
    'main() refuses an unknown command before it looks for a target — the function must answer in that order');
});

test('KNOWN LIMIT, pinned and not endorsed: a value-less --host passes this check (host is `true`) and fails later', async () => {
  // parseArgs returns `true` for a flag with no value, and main() then hands `true` to parseHostArg, which throws a
  // TypeError (exit 1) — never this refusal. Changing that changes behaviour, so it is boarded for 1.1.1, not folded.
  const a = await parsed('scan', '--host', '--compliance', 'soc2');
  assert.equal(a.host, true);
  assert.equal(scanTargetRefusal(a), null);
});

// ── THE STRUCTURE — main() refuses THROUGH the function, not through a copy of it ──────────────────────────
test('STRUCTURE — the refusal messages live in code only inside scanTargetRefusal, and main() calls it once', () => {
  const src = fs.readFileSync(new URL('../cli.mjs', import.meta.url), 'utf8').split('\n');
  const isComment = (line) => /^\s*(\*|\/\/|\/\*)/.test(line);
  const fnStart = src.findIndex((l) => l.startsWith('export function scanTargetRefusal('));
  const fnEnd = src.findIndex((l, i) => i > fnStart && l === '}');
  const mainStart = src.findIndex((l) => l.startsWith('export async function main('));
  assert.ok(fnStart > 0 && fnEnd > fnStart && mainStart > 0, 'cli.mjs no longer has the shape this leg reads');
  for (const literal of ['Fatal: --host or --host-file is required', 'Unknown command: ']) {
    const sites = src.map((l, i) => (l.includes(literal) && !isComment(l) ? i : -1)).filter((i) => i >= 0);
    assert.deepEqual(sites.filter((i) => i < fnStart || i > fnEnd).map((i) => `cli.mjs:${i + 1}`), [],
      `"${literal}" is refused OUTSIDE scanTargetRefusal — main() is refusing through a copy of the condition`);
  }
  const calls = src.map((l, i) => (/\bscanTargetRefusal\(/.test(l) && !isComment(l) && i !== fnStart ? i : -1)).filter((i) => i >= 0);
  assert.equal(calls.length, 1, `scanTargetRefusal is called ${calls.length} times outside its definition`);
  assert.ok(calls[0] > mainStart, 'the one call is not inside main()');
});

// ── THROUGH THE PUBLISHED BIN ───────────────────────────────────────────────────────────────────────────
// A cwd with no .env, a non-JWT licence key (license.mjs short-circuits — no Keychain call, no state write), and
// the three variables that could refuse earlier (GRC preflight, offline posture, TSA) unset. The rest of the
// runner's environment IS inherited — this is isolation from the licence and the cwd, not a clean environment.
function runBin(argv) {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-target-refusal-'));
  const env = { ...process.env, NSAUDITOR_LICENSE_KEY: 'not-a-licence', XDG_CONFIG_HOME: path.join(tmp, 'nonexistent'),
    NSAUDITOR_LICENSE_STATE_FILE: path.join(tmp, 'lic-state.json'), NSAUDITOR_LICENSE_REVOCATIONS_FILE: path.join(tmp, 'lic-revocations.json') };
  for (const k of ['COMPLIANCE_GRC_PROVIDER', 'NSAUDITOR_OFFLINE_ONLY', 'NSAUDITOR_TSA_URL', 'SCAN_OUT_PATH']) delete env[k];
  try {
    const r = spawnSync(process.execPath, [new URL('../bin/nsauditor-ai.mjs', import.meta.url).pathname, ...argv],
      { encoding: 'utf8', env, cwd: tmp, timeout: 60_000 });
    return { code: r.status, stderr: r.stderr, wrote: fs.readdirSync(tmp).filter((f) => f !== 'nonexistent') };
  } finally { fs.rmSync(tmp, { recursive: true, force: true }); }
}

test('THROUGH THE BIN — the documented host-less command exits 2 with the message, before anything is written', () => {
  const r = runBin(['scan', '--compliance', 'soc2', '--out', 'evidence']);
  assert.equal(r.code, 2, r.stderr);
  assert.match(r.stderr, new RegExp(`^${HOST_REQUIRED}$`, 'm'));
  assert.deepEqual(r.wrote, [], 'the refusal comes before any run record or output directory');
});

test('THROUGH THE BIN — the region check still runs FIRST: an unknown region is refused as one, not as a missing target', () => {
  // Pins the call's POSITION: moved ahead of main()'s flag/env/region checks, every other leg here stays green
  // while the CLI's output changes (measured by the review with a mutant).
  const r = runBin(['scan', '--aws-region', 'mars-central-9']);
  assert.equal(r.code, 2, r.stderr);
  assert.match(r.stderr, /unknown AWS region/i);
  assert.doesNotMatch(r.stderr, new RegExp(HOST_REQUIRED));
});

test('THROUGH THE BIN — an unknown command still wins over a missing target', () => {
  const r = runBin(['report-x', '--compliance', 'soc2']);
  assert.equal(r.code, 2, r.stderr);
  assert.match(r.stderr, /^Unknown command: report-x$/m);
  assert.doesNotMatch(r.stderr, new RegExp(HOST_REQUIRED));
});
