// tests/run_record_producer_contract.test.mjs
//
// PINS THE PRODUCER/CONSUMER CONTRACT BEFORE ANY WIRING TOUCHES IT.
//
// `PluginManager.run()` already returns a `manifest` array classifying every selected
// plugin as ran/skipped/timeout/error with a reason (plugin_manager.mjs `_runOrchestrated`).
// `cli.mjs:825` throws it away — `const { results, conclusion } = await pm.run(...)`. This
// test drives the REAL writer (no hand-written fixture) so it cannot rot the first time the
// manifest shape changes: if this test ever fails, the producer changed and the wiring in
// cli.mjs must be re-derived, not patched to match a stale assumption.
//
// Why this matters more than it looks: `results[]` alone cannot tell *skipped* from
// *ran-and-found-nothing*. Without `status`/`reason`, "no findings" over an estate whose
// cloud plugins never loaded is indistinguishable from a clean estate — the false clean
// handed to a paying client.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import PluginManager from '../plugin_manager.mjs';
import { main } from '../cli.mjs';
import { listRunRecords } from '../utils/run_record.mjs';
import { resolveBaseOutDir } from '../utils/output_dir.mjs';

// ⚠️ DEVIATION FROM THE BRIEF'S LITERAL TEXT, MEASURED BEFORE ADJUSTING.
// The brief's Step 1 snippet selects `'port_scanner'`. `PluginManager.findPlugin()` matches
// a spec against `p.id` OR `p.name`, lower-cased — the real Port Scanner plugin's id is
// `"003"` and its name is `"Port Scanner"` (a space, not an underscore); `'port_scanner'`
// matches neither. `_resolveSelection('port_scanner')` therefore returns an EMPTY selection,
// so `out.manifest` really was `[]` — not because the manifest producer regressed, but
// because the brief's fixture used an identifier that was never valid for this repo's
// naming convention. Confirmed directly (`node -e`) before editing anything: `pm.run('127.0.0.1',
// '003', { ports: '1-2' })` returns a one-entry manifest (`{ id: '003', name: 'Port Scanner',
// status: 'skipped', reason: 'host not up', duration_ms: 0 }` — a legitimate classified
// status; nothing ran ahead of it to mark the host up). Swapped the spec to `'003'`, the
// plugin's real id, and changed nothing else about the assertions.
test('PluginManager.run() surfaces a manifest with a classified status per plugin', async () => {
  const pm = await PluginManager.create(new URL('../plugins', import.meta.url).pathname);
  const out = await pm.run('127.0.0.1', '003', { ports: '1-2' });
  assert.ok(Array.isArray(out.manifest), 'run() must return a manifest array');
  assert.ok(out.manifest.length > 0, 'manifest was empty for a selected plugin');
  for (const m of out.manifest) {
    assert.ok(['ran', 'skipped', 'timeout', 'error'].includes(m.status),
      `unclassified manifest status: ${m.status}`);
    assert.equal(typeof m.id, 'string');
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// Step 6: the end-to-end leg — the REAL writer discovered by the REAL reader.
//
// Drives `main()` (cli.mjs's real entry point) against a real scan and reads back what
// it wrote, rather than asserting on any intermediate return value. `main()` reads
// `process.argv` directly and takes no parameters (confirmed by reading cli.mjs — it is
// NOT `main(argv, opts)` as an earlier sketch of this test assumed), so this test sets
// `process.argv`/`process.env` and restores both in a `finally`, following the pattern in
// `tests/output_dir.test.mjs`'s `withEnv` helper.
//
// ⚠️ SECOND DEVIATION FROM THE BRIEF'S LITERAL TEXT, MEASURED BEFORE ADJUSTING.
// `scanSingleHost`'s SSRF guard (cli.mjs) blocks loopback/RFC1918 addresses — including
// `127.0.0.1` — unless `NSA_ALLOW_ALL_HOSTS=1` is set (confirmed by reading the guard and
// cli.mjs's own `--help` text, which documents the flag). Driving `main()` with `--host
// 127.0.0.1` and no override throws `Scanning blocked address range is not allowed:
// 127.0.0.1` before any host directory is ever created. The brief's Step 6 snippet did not
// set this, and without it the test cannot reach the code this task wires — added
// `NSA_ALLOW_ALL_HOSTS: '1'` alongside `SCAN_OUT_PATH`, restored in the same `finally`.
// Also swapped `--plugins port_scanner` for `--plugins 003` for the same reason as the
// contract test above.
test('a real scan writes a run record and stamps its runId into every per-host raw', async () => {
  const outRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-e2e-'));
  const savedArgv = process.argv;
  const savedEnv = {
    SCAN_OUT_PATH: process.env.SCAN_OUT_PATH,
    NSA_ALLOW_ALL_HOSTS: process.env.NSA_ALLOW_ALL_HOSTS,
  };
  try {
    process.argv = ['node', 'cli', 'scan', '--host', '127.0.0.1', '--plugins', '003',
      '--ports', '1-2'];
    process.env.SCAN_OUT_PATH = outRoot;
    process.env.NSA_ALLOW_ALL_HOSTS = '1';
    await main();

    const records = await listRunRecords(outRoot);
    assert.equal(records.length, 1, 'exactly one run record per run');
    const rec = records[0];
    assert.ok(rec.finishedAt, 'a completed scan must record finishedAt');
    assert.equal(rec.hostsWritten.length, rec.hostsRequested.length);
    for (const { dir } of rec.hostsWritten) {
      const raw = JSON.parse(fs.readFileSync(path.join(outRoot, dir, 'scan_conclusion_raw.json'), 'utf8'));
      assert.equal(raw.runId, rec.runId, 'a per-host raw names a different run than the record');
      assert.ok(Array.isArray(raw.pluginStatus) && raw.pluginStatus.length > 0,
        'the per-host raw must carry the classified plugin manifest');
    }
  } finally {
    process.argv = savedArgv;
    for (const [k, v] of Object.entries(savedEnv)) {
      if (v == null) delete process.env[k]; else process.env[k] = v;
    }
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// The run record and the host directories it NAMES must share a root — a coordinator
// review found that they didn't, for a DOTTED `--out`.
//
// `scanSingleHost` creates every per-host directory under `resolveBaseOutDir()`
// (`utils/output_dir.mjs`). The run record was originally written against the OLDER inline
// expression `toCleanPath(...).replace(/\.[^/.]+$/, '')` (still used, unchanged, for
// `scan_history.jsonl` — a different artifact with no directory references). The two
// resolvers agree when `--out` has no dot in it, and DIVERGE when it does:
// `SCAN_OUT_PATH=/tmp/x/run.json` resolves to `/tmp/x/run` under the inline expression
// (which merely strips the trailing `.json`) but to `/tmp/x` under `resolveBaseOutDir()`
// (which correctly treats `.json` as a file extension and returns the PARENT directory —
// the same rule that fixed the `--out .../ee-0.32.8` evidence-misplacement bug its own
// header comment documents). Writing the record under one and the host directories under
// the other means `hostsWritten[].dir` names directories that do not exist relative to
// wherever the record itself is found — a coverage lie produced by a path helper, not a
// scan defect.
//
// Fixed by pointing the run record's resolver at `resolveBaseOutDir()` at all four call
// sites (`writeRunStart`/`appendHostWritten`/`finalizeRunRecord`/`pruneRunRecordsForCE`).
//
// FOURTH QUADRANT FIRST: the ordinary, undotted `--out` case already passed before this
// fix (the two resolvers happen to agree there) — written and proven green BEFORE the
// dotted case below, so a fix that hardcoded one resolver without actually unifying the
// two could not pass the new test while silently breaking this one.
async function driveScanWithOut(outFlagValue) {
  const savedArgv = process.argv;
  const savedEnv = {
    SCAN_OUT_PATH: process.env.SCAN_OUT_PATH,
    OPENAI_OUT_PATH: process.env.OPENAI_OUT_PATH,
    NSA_ALLOW_ALL_HOSTS: process.env.NSA_ALLOW_ALL_HOSTS,
  };
  try {
    delete process.env.SCAN_OUT_PATH;   // `--out` sets this during parseArgs; start clean
    delete process.env.OPENAI_OUT_PATH;
    process.env.NSA_ALLOW_ALL_HOSTS = '1';
    process.argv = ['node', 'cli', 'scan', '--host', '127.0.0.1', '--plugins', '003',
      '--ports', '1-2', '--out', outFlagValue];
    await main();
    // Independently compute where the record OUGHT to be, the same way the per-host
    // directories are created (scanSingleHost's `baseOutDir`) — NOT by trusting whatever
    // the code under test used internally.
    const root = resolveBaseOutDir();
    return { root, records: await listRunRecords(root) };
  } finally {
    process.argv = savedArgv;
    for (const [k, v] of Object.entries(savedEnv)) {
      if (v == null) delete process.env[k]; else process.env[k] = v;
    }
  }
}

function assertRecordAndDirsShareRoot(root, records) {
  assert.equal(records.length, 1,
    `exactly one run record must be found at ${root} — the SAME root resolveBaseOutDir() `
    + 'computes for the host directories');
  const rec = records[0];
  assert.ok(rec.finishedAt, 'a completed scan must record finishedAt');
  assert.ok(rec.hostsWritten.length > 0, 'at least one host directory must have landed');
  for (const { dir } of rec.hostsWritten) {
    assert.ok(fs.existsSync(path.join(root, dir)),
      `the record names host directory "${dir}" under ${root}, but no such directory exists there`);
  }
}

test('run record and host directories share a root under an ORDINARY --out (fourth-quadrant control)', async () => {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-out-plain-'));
  const outArg = path.join(base, 'scanrun'); // no dot anywhere in this path
  const { root, records } = await driveScanWithOut(outArg);
  assertRecordAndDirsShareRoot(root, records);
});

test('run record and host directories share a root under a DOTTED --out — the divergence this fix closes', async () => {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-out-dotted-'));
  const outArg = path.join(base, 'run.json'); // a real file-extension shape; measured to
  // diverge the two resolvers before this fix: inline -> `<base>/run`, resolveBaseOutDir()
  // -> `<base>` (the file's parent).
  const { root, records } = await driveScanWithOut(outArg);
  assertRecordAndDirsShareRoot(root, records);
});
