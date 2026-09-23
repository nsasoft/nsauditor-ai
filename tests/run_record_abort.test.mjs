// AN ABORTED SCAN IS FINALISED, SEALED AND SAYS WHY — board item 2 (CE 0.2.55).
//
// Measured instance: a network scan of 192.168.1.1 that the SSRF guard correctly REFUSED threw past the
// finalize block, leaving `finishedAt: null`, no host and no sidecar — and every later report labelled
// that honest refusal `chain-unreadable`, the verdict a STRIPPED sidecar earns. The false-accusation
// direction, through the run-record chain. Now: finalised with `status: 'aborted'` and the reason,
// sealed, and the error re-thrown so the scan's exit is unchanged; `report` refuses it BY NAME
// (`aborted-run`), and `--since prior` still selects it rather than silently substituting an older run.
// ⚠️ FOURTH QUADRANT FIRST: a scan that completes is `finished`, sealed, and reportable as before.
import './helpers/no_operator_keychain.mjs';   // FIRST: keeps this file off the operator's real Keychain
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { spawnSync } from 'node:child_process';
import { main } from '../cli.mjs';
import { listRunRecords } from '../utils/run_record.mjs';
import { verifyRunChain, chainDigestPath } from '../utils/run_chain.mjs';
import { loadRun } from '../utils/report_inputs.mjs';

async function scan(outRoot, host, { allowAll, hooks = {} }) {
  const savedArgv = process.argv;
  const saved = { SCAN_OUT_PATH: process.env.SCAN_OUT_PATH, OPENAI_OUT_PATH: process.env.OPENAI_OUT_PATH, NSA_ALLOW_ALL_HOSTS: process.env.NSA_ALLOW_ALL_HOSTS };
  try {
    delete process.env.OPENAI_OUT_PATH;
    process.env.SCAN_OUT_PATH = outRoot;
    if (allowAll) process.env.NSA_ALLOW_ALL_HOSTS = '1'; else delete process.env.NSA_ALLOW_ALL_HOSTS;
    process.argv = ['node', 'cli', 'scan', '--host', host, '--plugins', '003', '--ports', '1-2'];
    let error = null;
    try { await main({ importEE: async () => { throw new Error('injected: EE not installed'); }, ...hooks }); } catch (e) { error = e; }
    return error;
  } finally {
    process.argv = savedArgv;
    for (const [k, v] of Object.entries(saved)) { if (v == null) delete process.env[k]; else process.env[k] = v; }
  }
}
const newest = async (outRoot) => (await listRunRecords(outRoot))[0];

test('FOURTH QUADRANT — a scan that COMPLETES is finished, sealed and reportable exactly as before', async () => {
  const outRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-abort-ok-'));
  try {
    assert.equal(await scan(outRoot, '127.0.0.1', { allowAll: true }), null);
    const rec = await newest(outRoot);
    assert.equal(rec.status, 'finished');
    assert.equal(rec.abortReason, null);
    assert.ok(rec.finishedAt);
    assert.ok(fs.existsSync(chainDigestPath(outRoot, rec.runId)), 'sealed');
    const loaded = await loadRun(outRoot, { runId: rec.runId, allowPartial: false }, { tier: 'enterprise' });
    assert.equal(loaded.ok, true, loaded.message);
  } finally { fs.rmSync(outRoot, { recursive: true, force: true }); }
});

test('a REFUSED scan is finalised as ABORTED with its reason, SEALED, and its error still propagates', async () => {
  const outRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-abort-'));
  try {
    const err = await scan(outRoot, '192.168.1.1', { allowAll: false });
    assert.match(String(err?.message), /blocked address range/, 'the scan still fails, with the same error');
    const rec = await newest(outRoot);
    assert.equal(rec.status, 'aborted');
    // (iv) a CODE plus the message's first line — never a stack, which carries local paths.
    assert.match(rec.abortReason, /^Error: Scanning blocked address range is not allowed: 192\.168\.1\.1$/);
    assert.doesNotMatch(rec.abortReason, /\n|\bat \S+:\d+/);
    assert.ok(rec.finishedAt, 'finalised');
    assert.deepEqual(rec.hostsWritten, []);
    assert.ok(fs.existsSync(chainDigestPath(outRoot, rec.runId)), 'sealed — an honest abort is not an unreadable record');
    const chain = await verifyRunChain(outRoot, rec.runId);
    assert.notEqual(chain.status, 'chain-unreadable', `an honest refusal was labelled ${chain.status}: ${chain.reason}`);
  } finally { fs.rmSync(outRoot, { recursive: true, force: true }); }
});

test('loadRun refuses an aborted run BY NAME with the recorded reason; --allow-partial reports what was recorded', async () => {
  const outRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-abort-load-'));
  try {
    await scan(outRoot, '192.168.1.1', { allowAll: false });
    const rec = await newest(outRoot);
    const r = await loadRun(outRoot, { runId: rec.runId, allowPartial: false }, { tier: 'enterprise' });
    assert.equal(r.ok, false);
    assert.equal(r.reason, 'aborted-run');
    assert.match(r.message, /ABORTED before it completed \(Error: Scanning blocked address range/);
    const partial = await loadRun(outRoot, { runId: rec.runId, allowPartial: true }, { tier: 'enterprise' });
    assert.equal(partial.ok, true, partial.message);
  } finally { fs.rmSync(outRoot, { recursive: true, force: true }); }
});

// ── THROUGH THE SHIPPED BINARY — the refusal reaches the exit code the switch documents ──────────
const LIC = fs.readFileSync(new URL('./license.test.mjs', import.meta.url), 'utf8');
const PRO_KEY = LIC.match(/VALID_PRO_KEY\s*=\s*'([^']+)'/)[1];
function runCli(argv) {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-cli-'));
  const env = { ...process.env, NSAUDITOR_LICENSE_KEY: PRO_KEY, XDG_CONFIG_HOME: path.join(tmp, 'nonexistent'),
    NSAUDITOR_LICENSE_STATE_FILE: path.join(tmp, 'lic-state.json'), NSAUDITOR_LICENSE_REVOCATIONS_FILE: path.join(tmp, 'lic-revocations.json'),
    NSAUDITOR_LICENSE_ID_REPLAY_DEFENSE: '0' };
  const r = spawnSync(process.execPath, [new URL('../bin/nsauditor-ai.mjs', import.meta.url).pathname, ...argv], { encoding: 'utf8', env });
  return { code: r.status, stderr: r.stderr };
}

test('THROUGH THE CLI — `report` on an aborted run exits 1 (a run problem) naming the abort, never the internal-error 2', async () => {
  const outRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-abort-cli-'));
  try {
    await scan(outRoot, '192.168.1.1', { allowAll: false });
    const rec = await newest(outRoot);
    const { code, stderr } = runCli(['report', '--from', outRoot, '--run', rec.runId, '--format', 'executive', '--out', path.join(outRoot, 'r.html')]);
    assert.equal(code, 1, stderr);
    assert.match(stderr, /ABORTED before it completed/);
    assert.doesNotMatch(stderr, /unrecognised refusal reason/);
  } finally { fs.rmSync(outRoot, { recursive: true, force: true }); }
});

test('`--since prior` after an aborted run DISCLOSES it — the aborted baseline is named, never swapped for an older run', async () => {
  const outRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-abort-since-'));
  try {
    await scan(outRoot, '127.0.0.1', { allowAll: true });            // A — finished
    await new Promise((r) => setTimeout(r, 1100));                      // run ids are second-granular
    await scan(outRoot, '192.168.1.1', { allowAll: false });          // B — aborted
    await new Promise((r) => setTimeout(r, 1100));
    await scan(outRoot, '127.0.0.1', { allowAll: true });            // C — finished
    const [c] = await listRunRecords(outRoot);
    assert.equal(c.status, 'finished');
    const { code, stderr } = runCli(['report', '--from', outRoot, '--run', c.runId, '--since', 'prior', '--format', 'executive', '--out', path.join(outRoot, 'r.html')]);
    assert.notEqual(code, 0, 'a comparison against an aborted baseline must not read as a clean delta');
    assert.match(stderr, /ABORTED/, `the abort must be disclosed: ${stderr}`);
  } finally { fs.rmSync(outRoot, { recursive: true, force: true }); }
});

test('(i) a finalize that ITSELF fails never replaces the scan\'s own error, and the record stays unsealed', async () => {
  const outRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-abort-fin-'));
  try {
    const err = await scan(outRoot, '192.168.1.1', { allowAll: false,
      hooks: { _finalizeRunRecord: async () => { throw new Error('injected: finalize failed'); } } });
    assert.match(String(err?.message), /blocked address range/, 'the ORIGINAL error propagates');
    const rec = await newest(outRoot);
    assert.equal(rec.finishedAt, null, 'nothing finalised it');
    assert.equal(fs.existsSync(chainDigestPath(outRoot, rec.runId)), false, 'nothing sealed it');
  } finally { fs.rmSync(outRoot, { recursive: true, force: true }); }
});

test('(ii) FOURTH QUADRANT — a record written before `status` existed is FINISHED, never aborted', async () => {
  const outRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-abort-legacy-'));
  try {
    await scan(outRoot, '127.0.0.1', { allowAll: true });
    const rec = await newest(outRoot);
    const file = path.join(outRoot, `scan_run_${rec.runId}.json`);
    const legacy = JSON.parse(fs.readFileSync(file, 'utf8'));
    delete legacy.status; delete legacy.abortReason;
    fs.writeFileSync(file, JSON.stringify(legacy));
    const loaded = await loadRun(outRoot, { runId: rec.runId, allowPartial: false }, { tier: 'enterprise' });
    assert.equal(loaded.ok, true, loaded.message);
  } finally { fs.rmSync(outRoot, { recursive: true, force: true }); }
});

test('(iii) the refusal names the nearest FINISHED run before the aborted one, so it can be passed explicitly', async () => {
  const outRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-abort-near-'));
  try {
    await scan(outRoot, '127.0.0.1', { allowAll: true });
    const a = await newest(outRoot);
    await new Promise((r) => setTimeout(r, 1100));
    await scan(outRoot, '192.168.1.1', { allowAll: false });
    const b = await newest(outRoot);
    assert.equal(b.status, 'aborted');
    const r = await loadRun(outRoot, { runId: b.runId, allowPartial: false }, { tier: 'enterprise' });
    assert.equal(r.reason, 'aborted-run');
    assert.ok(r.message.includes(a.runId), `the finished run ${a.runId} must be named: ${r.message}`);
    // A second abort after the first: the nearest FINISHED run is still A — never the aborted B.
    await new Promise((res) => setTimeout(res, 1100));
    await scan(outRoot, '192.168.1.1', { allowAll: false });
    const c = await newest(outRoot);
    const r3 = await loadRun(outRoot, { runId: c.runId, allowPartial: false }, { tier: 'enterprise' });
    assert.ok(r3.message.includes(a.runId) && !r3.message.includes(b.runId), `C must point past the aborted B to A: ${r3.message}`);
    // With no finished run before it, it says so.
    const lone = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-abort-lone-'));
    try {
      await scan(lone, '192.168.1.1', { allowAll: false });
      const only = await newest(lone);
      const r2 = await loadRun(lone, { runId: only.runId, allowPartial: false }, { tier: 'enterprise' });
      assert.match(r2.message, /No finished run precedes it/);
    } finally { fs.rmSync(lone, { recursive: true, force: true }); }
  } finally { fs.rmSync(outRoot, { recursive: true, force: true }); }
});
