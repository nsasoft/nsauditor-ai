// THE RUN RECORD SAYS WHICH NVD STORE AND CACHE THE RUN READ — Enterprise 1.1.0 build 5, board item 23.
//
// The CVE set a scan reports depends on the NVD store and response cache it consulted, and that was a
// hidden, cwd-relative input nothing recorded. Enterprise now reports it per host as `nvdStore`; this
// file holds the run-level record to the all-or-nothing rule the KEV/EPSS snapshots follow — a location
// true for some hosts and wrong for others is worse than none.
// ⚠️ FOURTH QUADRANT FIRST: two hosts that AGREE are recorded, with the FIRST host's vintage — the leg
// that rots if the aggregation degenerates to "always null".
import './helpers/no_operator_keychain.mjs';   // FIRST: keeps this file off the operator's real Keychain
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { main } from '../cli.mjs';
import { listRunRecords, aggregateNvdCache } from '../utils/run_record.mjs';

const LOC = (p, source = 'env:NVD_CACHE_DIR', entries = 4) => ({
  path: p, source, state: 'absent',
  responseCache: { present: true, ttlDays: 7, entries, liveEntries: entries, oldestAt: '2026-09-18T18:27:00.000Z', newestAt: '2026-09-18T18:27:00.000Z' },
});

// ── THE RULE ─────────────────────────────────────────────────────────────────────────────────
test('FOURTH QUADRANT — hosts that agree are recorded, and the vintage is the FIRST host\'s', () => {
  const r = aggregateNvdCache([LOC('/nvd', 'env:NVD_CACHE_DIR', 4), LOC('/nvd', 'env:NVD_CACHE_DIR', 6)]);
  assert.equal(r.warning, null);
  assert.deepEqual(r.value, { path: '/nvd', source: 'env:NVD_CACHE_DIR', state: 'absent', responseCache: LOC('/nvd').responseCache });
});
test('no host reported one (Community alone) → null, and NOTHING to warn about', () => {
  assert.deepEqual(aggregateNvdCache([null, null]), { value: null, warning: null });
  assert.deepEqual(aggregateNvdCache([]), { value: null, warning: null });
});
test('some hosts reported one and some did not → null, with the counts named', () => {
  const r = aggregateNvdCache([LOC('/nvd'), null]);
  assert.equal(r.value, null);
  assert.match(r.warning, /only 1 of 2/);
});
test('hosts that DISAGREE on the path or the source → null, with both named', () => {
  for (const pair of [[LOC('/a'), LOC('/b')], [LOC('/a', 'home'), LOC('/a', 'env:NVD_CACHE_DIR')]]) {
    const r = aggregateNvdCache(pair);
    assert.equal(r.value, null);
    assert.match(r.warning, /disagreed/);
  }
});

// ── THROUGH main() — the per-host capture reaches the written record ─────────────────────────
function fakeEE(perHost) {
  return async () => ({
    enrichScan: async (conclusion, opts) => ({ enrichedPrompt: null, exploitIntel: { stores: {} }, nvdStore: perHost[opts.host] ?? undefined }),
  });
}
async function drive(hosts, importEE) {
  const outRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-nvdrec-'));
  const savedArgv = process.argv;
  const saved = { SCAN_OUT_PATH: process.env.SCAN_OUT_PATH, OPENAI_OUT_PATH: process.env.OPENAI_OUT_PATH, NSA_ALLOW_ALL_HOSTS: process.env.NSA_ALLOW_ALL_HOSTS };
  try {
    delete process.env.OPENAI_OUT_PATH;
    process.env.SCAN_OUT_PATH = outRoot;
    process.env.NSA_ALLOW_ALL_HOSTS = '1';
    process.argv = ['node', 'cli', 'scan', '--host', hosts.join(','), '--plugins', '003', '--ports', '1-2', '--parallel', '1'];
    await main({ importEE });
    const records = await listRunRecords(outRoot);
    assert.equal(records.length, 1);
    return records[0];
  } finally {
    process.argv = savedArgv;
    for (const [k, v] of Object.entries(saved)) { if (v == null) delete process.env[k]; else process.env[k] = v; }
    fs.rmSync(outRoot, { recursive: true, force: true });
  }
}

test('THROUGH main() — two hosts reporting the same location put it in the run record', async () => {
  const rec = await drive(['127.0.0.1', '127.0.0.2'], fakeEE({ '127.0.0.1': LOC('/nvd'), '127.0.0.2': LOC('/nvd') }));
  assert.equal(rec.hostsWritten.length, 2);
  assert.deepEqual(rec.nvdCache, { path: '/nvd', source: 'env:NVD_CACHE_DIR', state: 'absent', responseCache: LOC('/nvd').responseCache });
});

test('THROUGH main(), FOURTH QUADRANT — without Enterprise the record says null, not a guess', async () => {
  const rec = await drive(['127.0.0.1'], async () => { throw new Error('injected: EE not installed'); });
  assert.equal(rec.nvdCache, null);
});
