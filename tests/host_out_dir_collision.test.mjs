// TWO SCANS OF ONE HOST IN ONE SECOND MUST NOT SHARE A DIRECTORY (1.1.1 board — found by Gate 3-B on build 12).
//
// Measured on 2026-09-28: the Gate 3-B setup loop ran three localhost scans into one `--out`; runs 2 and 3 reached
// directory creation in the SAME second. `scanSingleHost` named the directory `${safeHost(host)}_${nowStamp()}`
// (second granularity, local time) and created it with `mkdir … { recursive: true }` — no exclusive create, no
// suffix — so three runs wrote TWO directories and run 2's `scan_conclusion_raw.json` on disk hashed to run 3's sealed
// digest: run 2's evidence GONE, the colliding scan exiting 0 with no warning. 1.1.0's per-host seal detected it
// downstream and both consumers failed closed, but the evidence was already lost. Worse when the second run's finding
// queue is EMPTY: EE writes `scan_finding_queue.json` only when there is something to write, so the first run's queue
// stays in the shared directory and the second run's seal covers it as its own.
//
// The audit seat's shape: an EXCLUSIVE create, a suffix on EEXIST, a WARNING on stdout naming both directories —
// and the fourth quadrant first: when the seconds differ, the directory name is BYTE-IDENTICAL to today's, because
// every reader and every manifest keys on it.
import './helpers/no_operator_dotenv.mjs';
import './helpers/no_operator_keychain.mjs';   // FIRST: keeps this file off the operator's real Keychain
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import * as OD from '../utils/output_dir.mjs';
// A namespace import, so that before the helper exists each leg fails ON ITS OWN rather than the file failing to load.
const need = (n) => { assert.equal(typeof OD[n], 'function', `${n} is exported by utils/output_dir.mjs`); return OD[n]; };
const createHostOutDir = (...a) => need('createHostOutDir')(...a);
const nowStamp = (...a) => need('nowStamp')(...a);
const safeHost = (...a) => need('safeHost')(...a);

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-hostdir-'));
const collect = () => { const lines = []; return { lines, log: (s) => lines.push(String(s)) }; };

// ── FOURTH QUADRANT FIRST: different seconds keep today's name, byte for byte, and say nothing ─────────────
test('(q1) different seconds → the name is exactly `${safeHost(host)}_${stamp}`, as before, and nothing is printed', async () => {
  const base = tmp();
  try {
    const out = collect();
    const a = await createHostOutDir(base, '192.168.1.1', { stamp: () => '20260928_101010', log: out.log });
    const b = await createHostOutDir(base, '192.168.1.1', { stamp: () => '20260928_101011', log: out.log });
    assert.equal(a, path.join(base, '192.168.1.1_20260928_101010'));
    assert.equal(b, path.join(base, '192.168.1.1_20260928_101011'));
    assert.deepEqual(out.lines, []);
    assert.ok(fs.statSync(a).isDirectory() && fs.statSync(b).isDirectory());
  } finally { fs.rmSync(base, { recursive: true, force: true }); }
});

test('(q1) the name is built from the SAME two helpers the old inline code used — safeHost folds the same characters', async () => {
  const base = tmp();
  try {
    const host = 'aws:us-east-1/acct?x';
    const d = await createHostOutDir(base, host, { stamp: () => '20260928_101010', log: () => {} });
    assert.equal(path.basename(d), `${safeHost(host)}_20260928_101010`);
    assert.equal(safeHost(host), 'aws_us-east-1_acct_x');
  } finally { fs.rmSync(base, { recursive: true, force: true }); }
});

test('(q1) the base directory is created when absent (as the inline `mkdir(base, { recursive: true })` did)', async () => {
  const root = tmp();
  try {
    const base = path.join(root, 'nested', 'out');
    const d = await createHostOutDir(base, 'h', { stamp: () => '20260928_101010', log: () => {} });
    assert.ok(fs.statSync(d).isDirectory());
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('nowStamp keeps its shape: YYYYMMDD_HHMMSS in LOCAL time', () => {
  const d = new Date(2026, 8, 28, 7, 5, 3);   // local
  assert.equal(nowStamp(d), '20260928_070503');
  assert.match(nowStamp(), /^\d{8}_\d{6}$/);
});

// ── THE DEFECT ────────────────────────────────────────────────────────────────────────────────────────
test('(a) SAME second → the second directory is suffixed `_2`, the first is never reused, and a WARNING names both', async () => {
  const base = tmp();
  try {
    const out = collect();
    const stamp = () => '20260928_101010';
    const a = await createHostOutDir(base, '127.0.0.1', { stamp, log: out.log });
    fs.writeFileSync(path.join(a, 'scan_conclusion_raw.json'), '{"runId":"A"}');
    const b = await createHostOutDir(base, '127.0.0.1', { stamp, log: out.log });
    assert.equal(a, path.join(base, '127.0.0.1_20260928_101010'));
    assert.equal(b, path.join(base, '127.0.0.1_20260928_101010_2'));
    assert.equal(fs.readFileSync(path.join(a, 'scan_conclusion_raw.json'), 'utf8'), '{"runId":"A"}', 'run A\'s evidence is intact');
    assert.deepEqual(fs.readdirSync(b), [], 'the new directory is a FRESH one — nothing of run A\'s leaks into it');
    assert.equal(out.lines.length, 1);
    assert.match(out.lines[0], /^\[scan\] WARNING: /);
    // WHOLE TOKENS (audit seat's fold): `a` is a PREFIX of `b`, so `includes(a)` was satisfied by `b` alone and a warning
    // naming only the new directory passed. Each path is asserted in its own role.
    assert.ok(out.lines[0].includes(`${a} already exists`), `the warning names the EXISTING directory: ${out.lines[0]}`);
    assert.ok(out.lines[0].includes(`writes to ${b} instead`), `the warning names the NEW directory: ${out.lines[0]}`);
    // v77-8 (1.3.0): the directory is stamped AFTER the plugin runs, so two scans collide when their runs FINISH in the same
    // second — they may have started minutes apart. README:35 says so; the warning said "started".
    assert.doesNotMatch(out.lines[0], /started in the same second/);
    assert.match(out.lines[0], /finished[^.]* the same second/);
  } finally { fs.rmSync(base, { recursive: true, force: true }); }
});

test('(a) a third same-second scan → `_3`; each collision warns once', async () => {
  const base = tmp();
  try {
    const out = collect();
    const stamp = () => '20260928_101010';
    const dirs = [];
    for (let i = 0; i < 3; i += 1) dirs.push(await createHostOutDir(base, 'h', { stamp, log: out.log }));
    assert.deepEqual(dirs.map((d) => path.basename(d)), ['h_20260928_101010', 'h_20260928_101010_2', 'h_20260928_101010_3']);
    assert.equal(out.lines.length, 2);
  } finally { fs.rmSync(base, { recursive: true, force: true }); }
});

test('(a) the stamp is taken ONCE per call — a suffix always belongs to the stamp it collided with', async () => {
  const base = tmp();
  try {
    let calls = 0;
    const stamp = () => { calls += 1; return '20260928_101010'; };
    await createHostOutDir(base, 'h', { stamp, log: () => {} });
    await createHostOutDir(base, 'h', { stamp, log: () => {} });
    assert.equal(calls, 2);
  } finally { fs.rmSync(base, { recursive: true, force: true }); }
});

test('(a) EXHAUSTION throws — it never falls back to reusing an existing directory', async () => {
  const base = tmp();
  try {
    const stamp = () => '20260928_101010';
    await createHostOutDir(base, 'h', { stamp, log: () => {}, max: 2 });
    await createHostOutDir(base, 'h', { stamp, log: () => {}, max: 2 });
    await assert.rejects(createHostOutDir(base, 'h', { stamp, log: () => {}, max: 2 }), /could not create a fresh output directory/);
    assert.deepEqual(fs.readdirSync(base).sort(), ['h_20260928_101010', 'h_20260928_101010_2']);
  } finally { fs.rmSync(base, { recursive: true, force: true }); }
});

test('(a) a LEAF error that is NOT "already exists" is rethrown as itself, never retried under a new name', async (t) => {
  // The base exists and is not writable, so the BASE mkdir succeeds and the LEAF mkdir is the one that fails —
  // which is the catch this leg guards (a failure on the base never reaches it).
  if (process.getuid?.() === 0) { t.skip('root bypasses directory permissions'); return; }
  const base = tmp();
  try {
    fs.chmodSync(base, 0o500);
    let attempts = 0;
    const stamp = () => { attempts += 1; return '20260928_101010'; };
    await assert.rejects(createHostOutDir(base, 'h', { stamp, log: () => {} }), (e) => e.code === 'EACCES');
    assert.equal(attempts, 1);
  } finally { fs.chmodSync(base, 0o700); fs.rmSync(base, { recursive: true, force: true }); }
});

test('(a) an error creating the BASE directory is rethrown as itself', async () => {
  const root = tmp();
  try {
    const file = path.join(root, 'not-a-dir');
    fs.writeFileSync(file, 'x');
    await assert.rejects(createHostOutDir(path.join(file, 'out'), 'h', { stamp: () => '20260928_101010', log: () => {} }),
      (e) => e.code === 'ENOTDIR' || e.code === 'EEXIST');
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

// ── THROUGH THE SHIPPED SCAN PATH: two real scans, one pinned second ─────────────────────────────────────
import { main } from '../cli.mjs';
import { listRunRecords } from '../utils/run_record.mjs';
// NOT INSTALLED, described the way the product decides it (utils/ee_load.mjs): the package does not RESOLVE. A throwing
// `importEE` alone now means installed-and-broken, which the scan reports (1.1.1).
const notInstalled = () => { throw Object.assign(new Error("Cannot find package '@nsasoft/nsauditor-ai-ee'"), { code: 'ERR_MODULE_NOT_FOUND' }); };

async function scan(outRoot, hostArg, hooks = {}) {
  const savedArgv = process.argv;
  const saved = { SCAN_OUT_PATH: process.env.SCAN_OUT_PATH, OPENAI_OUT_PATH: process.env.OPENAI_OUT_PATH, NSA_ALLOW_ALL_HOSTS: process.env.NSA_ALLOW_ALL_HOSTS };
  const origLog = console.log;
  const lines = [];
  try {
    delete process.env.OPENAI_OUT_PATH;
    process.env.SCAN_OUT_PATH = outRoot;
    process.env.NSA_ALLOW_ALL_HOSTS = '1';
    process.argv = ['node', 'cli', 'scan', '--host', hostArg, '--plugins', '003', '--ports', '1-2', '--parallel', '1'];
    console.log = (...a) => { lines.push(a.map(String).join(' ')); };
    await main({ importEE: async () => { throw new Error('injected: EE not installed'); }, ...(hooks.importEE ? {} : { resolveEE: notInstalled }), ...hooks });
  } finally {
    console.log = origLog;
    process.argv = savedArgv;
    for (const [k, v] of Object.entries(saved)) { if (v == null) delete process.env[k]; else process.env[k] = v; }
  }
  return lines;
}

test('THROUGH main(): two scans of one host in one pinned second write TWO directories, both raws intact, both records distinct', async () => {
  const outRoot = tmp();
  try {
    const nowStampHook = () => '20260928_101010';
    await scan(outRoot, '127.0.0.1', { nowStamp: nowStampHook });
    await new Promise((r) => setTimeout(r, 1100));   // run ids are second-granular — this pins the DIRECTORY second only
    const lines = await scan(outRoot, '127.0.0.1', { nowStamp: nowStampHook });
    const dirs = fs.readdirSync(outRoot).filter((n) => n.startsWith('127.0.0.1_')).sort();
    assert.deepEqual(dirs, ['127.0.0.1_20260928_101010', '127.0.0.1_20260928_101010_2']);
    const raws = dirs.map((d) => JSON.parse(fs.readFileSync(path.join(outRoot, d, 'scan_conclusion_raw.json'), 'utf8')));
    assert.notEqual(raws[0].runId, raws[1].runId, 'each directory holds its OWN run');
    const recs = await listRunRecords(outRoot);
    assert.equal(recs.length, 2);
    const named = recs.flatMap((r) => r.hostsWritten.map((h) => h.dir)).sort();
    assert.deepEqual(named, dirs, 'each run record names the directory its own evidence is in');
    for (const r of recs) assert.equal(raws[dirs.indexOf(r.hostsWritten[0].dir)].runId, r.runId);
    assert.ok(lines.some((l) => /^\[scan\] WARNING: /.test(l) && l.includes('127.0.0.1_20260928_101010_2')),
      `the warning is on STDOUT: ${lines.filter((l) => /WARNING/.test(l)).join(' | ')}`);
  } finally { fs.rmSync(outRoot, { recursive: true, force: true }); }
});

test('THROUGH main(): one run naming the same host twice gets two directories, not one shared', async () => {
  const outRoot = tmp();
  try {
    await scan(outRoot, '127.0.0.1,127.0.0.1', { nowStamp: () => '20260928_101010' });
    const [rec] = await listRunRecords(outRoot);
    const named = rec.hostsWritten.map((h) => h.dir).sort();
    assert.equal(named.length, 2);
    assert.equal(new Set(named).size, 2, `two host entries must not share one directory: ${named.join(', ')}`);
  } finally { fs.rmSync(outRoot, { recursive: true, force: true }); }
});

test('THROUGH main(): an earlier run\'s finding QUEUE does not ride into a later same-second run whose queue is EMPTY', async () => {
  // The contamination shape, the second thing the exclusive create closes: Enterprise writes
  // `scan_finding_queue.json` only when its queue is non-empty, so in a SHARED directory run A's queue stayed on
  // disk under run B, and run B's seal covered it as B's evidence. A stand-in Enterprise writes a queue on the first
  // run only — the shape of a real empty second queue.
  const outRoot = tmp();
  try {
    let call = 0;
    const importEE = async () => ({
      enrichScan: async (_conclusion, { outDir }) => {
        call += 1;
        if (call === 1) fs.writeFileSync(path.join(outDir, 'scan_finding_queue.json'), JSON.stringify([{ id: 'F-A', title: 'from run A' }]));
        return null;
      },
    });
    const pinned = () => '20260928_101010';
    await scan(outRoot, '127.0.0.1', { nowStamp: pinned, importEE });
    await new Promise((r) => setTimeout(r, 1100));
    await scan(outRoot, '127.0.0.1', { nowStamp: pinned, importEE });
    assert.equal(call, 2, 'both runs reached Enterprise');
    // Each run's directory is read off ITS OWN run record — never assumed from a name, which is what made the first
    // draft of this leg pass under the defect (the suffixed directory simply did not exist, so it held no queue).
    const recs = await listRunRecords(outRoot);
    assert.equal(recs.length, 2);
    const byStart = [...recs].sort((x, y) => String(x.startedAt).localeCompare(String(y.startedAt)));
    const [dirA, dirB] = byStart.map((r) => path.join(outRoot, r.hostsWritten[0].dir));
    assert.notEqual(dirA, dirB, 'the two runs name two directories');
    assert.ok(fs.existsSync(path.join(dirA, 'scan_finding_queue.json')), 'run A keeps its own queue');
    assert.equal(fs.existsSync(path.join(dirB, 'scan_finding_queue.json')), false,
      'run B wrote no queue, so ITS directory holds none — run A\'s queue is not in it');
  } finally { fs.rmSync(outRoot, { recursive: true, force: true }); }
});

// ── THE CLI COMPOSES NO HOST DIRECTORY ITSELF (the audit seat's second fold) ─────────────────────────────────
// A caller-less fallback in maybeSendToOpenAI composed `${safeHost(host)}_${nowStamp()}` with a recursive mkdir — the
// defect's own shape, kept warm, and no leg drove it. It is deleted; this census is what keeps any composition of a
// host directory out of cli.mjs, so the exclusive create stays the only way one is made.
test('cli.mjs composes no host-directory name and calls createHostOutDir exactly once (scanSingleHost)', () => {
  const src = fs.readFileSync(new URL('../cli.mjs', import.meta.url), 'utf8')
    .replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:\\])\/\/.*$/gm, '$1');
  assert.equal((src.match(/\bcreateHostOutDir\(/g) ?? []).length, 1, 'one exclusive create, in scanSingleHost');
  // A CALL, not the seam's name: `opts.nowStamp` / `testHooks.nowStamp` carry a function in and never call it here.
  assert.equal((src.match(/(?<![.\w])nowStamp\s*\(/g) ?? []).length, 0, 'no second-granular stamp is taken in cli.mjs');
  assert.equal((src.match(/\$\{safeHost\([^)]*\)\}_/g) ?? []).length, 0, 'no `${safeHost(host)}_…` directory name is composed in cli.mjs');
  assert.match(src, /if \(!presetOutDir\) throw new Error\('maybeSendToOpenAI: outDir is required/);
});
