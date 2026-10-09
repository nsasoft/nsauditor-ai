// tests/ee_drift_forwarding.test.mjs
// ─────────────────────────────────────────────────────────────────────────────
// WHAT COMMUNITY TELLS ENTERPRISE SO THE DRIFT FILE CAN EXIST (EE 2.0.0, cargo 3 — D1/D2).
//
// Enterprise writes `scan_drift_<fw>.json` on the ONE-SHOT path only, comparing with the run `report --since prior`
// names. It can do that only if Community forwards three facts on the `enrichScan` call: the run's id, the root its
// run records live under (the SAME resolver `appendHostWritten` uses), and `watch: true` from the watch loop. A
// Community that stopped forwarding `watch` would make Enterprise write a drift file every watch cycle; one that
// stopped forwarding the run id would make it write none. Both legs DRIVE `main()` with an injected Enterprise module
// and read what `enrichScan` received — never a grep of the call site.
//
// FOURTH QUADRANT FIRST: the one-shot path, then the watch cycle.
// ─────────────────────────────────────────────────────────────────────────────
// ⚠️ THESE TWO FIRST, before cli.mjs is imported: without them this file loaded the operator's .env (AI sending on, real
// provider keys) and touched the operator's Keychain. Its first run sent two real AI requests and rewrote the licence
// Keychain item (2026-10-09); tests/no_operator_dotenv_census.test.mjs holds the rule.
import './helpers/no_operator_dotenv.mjs';
import './helpers/no_operator_keychain.mjs';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { main } from '../cli.mjs';
import { listRunRecords } from '../utils/run_record.mjs';

function captureEE(sink) {
  return async () => ({
    enrichScan: async (conclusion, opts) => {
      sink.push({ runId: opts.runId, runRecordRoot: opts.runRecordRoot, watch: opts.watch, host: opts.host });
      return { enrichedPrompt: null, exploitIntel: { stores: { kev: null, epss: null } } };
    },
  });
}

async function withScanEnv(fn) {
  const outRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-drift-fwd-'));
  const savedArgv = process.argv;
  const savedEnv = { SCAN_OUT_PATH: process.env.SCAN_OUT_PATH, OPENAI_OUT_PATH: process.env.OPENAI_OUT_PATH,
    NSA_ALLOW_ALL_HOSTS: process.env.NSA_ALLOW_ALL_HOSTS };
  try {
    delete process.env.OPENAI_OUT_PATH;
    process.env.SCAN_OUT_PATH = outRoot;
    process.env.NSA_ALLOW_ALL_HOSTS = '1';
    return await fn(outRoot);
  } finally {
    process.argv = savedArgv;
    for (const [k, v] of Object.entries(savedEnv)) { if (v == null) delete process.env[k]; else process.env[k] = v; }
    fs.rmSync(outRoot, { recursive: true, force: true });
  }
}

test('(first) a ONE-SHOT scan forwards its run id, the run-record root and watch: false', async () => {
  await withScanEnv(async (outRoot) => {
    const sink = [];
    process.argv = ['node', 'cli', 'scan', '--host', '127.0.0.1', '--plugins', '003', '--ports', '1-2'];
    await main({ importEE: captureEE(sink) });
    const records = await listRunRecords(outRoot);
    assert.equal(records.length, 1, 'positive control: the run wrote its record');
    assert.equal(sink.length, 1, 'enrichScan was called once');
    assert.equal(sink[0].runId, records[0].runId, 'the run id Enterprise receives is the run record\'s');
    assert.equal(path.resolve(sink[0].runRecordRoot), path.resolve(outRoot), 'the root Enterprise reads records from is the one they are written to');
    assert.equal(sink[0].watch, false);
  });
});

test('a WATCH cycle forwards watch: true and no run id — so Enterprise writes no drift file per cycle', async () => {
  await withScanEnv(async () => {
    const sink = [];
    let cycle = null;
    const before = { int: process.listeners('SIGINT').slice(), term: process.listeners('SIGTERM').slice() };
    const fakeScheduler = (cfg) => ({
      hosts: cfg.hosts, duplicatesDropped: 0,
      start() { cycle = cfg.scanFn(cfg.hosts[0]); },
      async stop() {},
    });
    process.argv = ['node', 'cli', 'scan', '--host', '127.0.0.1', '--plugins', '003', '--ports', '1-2', '--watch', '--interval', '1'];
    try {
      await main({ importEE: captureEE(sink), _createScheduler: fakeScheduler });
      assert.ok(cycle, 'positive control: the watch loop started a cycle through the scheduler');
      await cycle;
    } finally {
      for (const l of process.listeners('SIGINT')) if (!before.int.includes(l)) process.removeListener('SIGINT', l);
      for (const l of process.listeners('SIGTERM')) if (!before.term.includes(l)) process.removeListener('SIGTERM', l);
    }
    assert.equal(sink.length, 1, 'enrichScan was called once, inside the cycle');
    assert.equal(sink[0].watch, true);
    assert.equal(sink[0].runId, null, 'a watch cycle has no run record, so no run id');
  });
});
