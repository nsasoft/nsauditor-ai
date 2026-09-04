// tests/run_record_kev_epss.test.mjs
//
// The run record's `kevLoaded`/`kevSnapshot` (and the epss pair) are a claim about the WHOLE
// RUN: Task 4's consumer renders one sentence from them covering every finding on the page —
// "Known-exploited status evaluated against the CISA KEV snapshot dated <date>". These tests
// drive the REAL scan pipeline (`main()`, `cli.mjs`'s real entry point) with an INJECTED EE
// module (via `main(testHooks)`'s `testHooks.importEE`, mirroring the established
// `preflightNsauditorPosture({ importEE })` pattern elsewhere in this file) so the aggregation
// across hosts is exercised through the REAL `scanSingleHost` extraction and the REAL
// `main()` finalize-block wiring — not a hand-simulated copy of either.
//
// ⚠️ CORRECTED SPEC, TWICE, BEFORE THIS FILE WAS WRITTEN. The coordinator's first ruling
// ("CE loads no KEV/EPSS store, so hard-wiring false/null is honest") was itself wrong: EE's
// `enrichScan` reports a store's `dataAsOf` when one is configured, and CE's scan path calls
// it. The coordinator's first proposed multi-host rule ("take the first non-null") was ALSO
// withdrawn before being implemented: it would print "evaluated" over a host whose own
// enrichment never ran, the same false-clean this fix exists to remove, sign flipped. The
// rule actually implemented is ALL-OR-NOTHING per store (kev and epss independently):
//   - loaded:true only if EVERY WRITTEN host reported a non-null dataAsOf.
//   - any written host lacking one -> loaded:false, with a warning naming how many DID have it.
//   - all loaded but disagreeing on the date -> loaded:true, snapshot:null, with a warning.
//
// ⚠️ A THIRD MEASURED CORRECTION, made while implementing this file. EE's actual `enrichScan`
// return shape (`nsauditor-ai-ee/index.mjs`'s final `return { ... exploitIntel: ctx.exploitIntel,
// ... }`) nests the per-store date at `exploitIntel.stores.{kev,epss}.dataAsOf` — NOT at a
// top-level `exploit.kev.dataAsOf` as an earlier message described. Confirmed by reading
// `index.mjs` directly before writing `cli.mjs`'s extraction code or these fixtures; the
// injected fakes below return the MEASURED shape.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { main } from '../cli.mjs';
import { listRunRecords } from '../utils/run_record.mjs';

// A fake `@nsasoft/nsauditor-ai-ee` module whose `enrichScan` reports exploit-intel store
// state PER HOST — keyed by the real `host` value EE always receives in its own opts bag
// (`ee.enrichScan(conclusion, { host, ... })`, cli.mjs). This is what lets a SINGLE injected
// module drive genuinely different per-host outcomes within one multi-host `--parallel` run,
// without needing to export or separately drive `scanSingleHost`.
//
// `behaviors[host]`:
//   - `{ dataAsOf }`             -> that host's KEV store reports this dataAsOf
//   - `null` / undefined         -> that host's KEV store was not loaded (the honest default)
//   - `'throw'`                  -> enrichScan THROWS for this host — the reachability
//     mechanism the coordinator named: `ee.enrichScan(...)` sits inside cli.mjs's own
//     PER-HOST try/catch, so one host's enrichment failing and being caught, while another
//     host's succeeds, needs no exotic input — just this.
function fakeEEPerHost(behaviors) {
  return async () => ({
    enrichScan: async (conclusion, opts) => {
      const b = behaviors[opts.host];
      if (b === 'throw') throw new Error('injected: enrichment failed for this host');
      const dataAsOf = b?.dataAsOf ?? null;
      return {
        enrichedPrompt: null,
        exploitIntel: { stores: { kev: dataAsOf ? { dataAsOf } : null, epss: null } },
      };
    },
  });
}

// `behaviors === 'no-ee'`: the injected `importEE` hook itself THROWS — genuinely simulating
// EE not being installed at all (`ee` stays `null` inside cli.mjs). This is DELIBERATELY
// distinct from a per-host `null` behavior (EE IS present and its `enrichScan` runs, but
// reports no store) — the two must not be conflated, because relying on this MACHINE's real
// EE-import outcome (present or absent) to distinguish them would make the test's result
// depend on incidental environment state rather than on the code under test. `main()`'s own
// default (no `testHooks` at all) still falls through to a REAL `import('@nsasoft/…')`, which
// is untouched by this file and exercised by Task 3's own tests.
function driveHooks(behaviors) {
  if (behaviors === 'no-ee') {
    return { importEE: async () => { throw new Error('injected: EE not installed'); } };
  }
  return behaviors ? { importEE: fakeEEPerHost(behaviors) } : {};
}

// ⚠️ `--parallel 1`, DELIBERATELY, EVEN FOR MULTIPLE HOSTS. Measured before choosing this:
// the multi-host branch pushes each host's result onto `scanOutputs` in COMPLETION order
// (inside each `scanSingleHost(...).then(...)`), not REQUEST order — under real concurrency
// (`--parallel 2` for two near-identical local scans) that order is a genuine race with no
// inherent bias. A fixture built to catch "derive from the LAST entry" (mutant c) needs its
// array order to be the one thing under test, not a second coin flip stacked on top of it —
// `--parallel 1` still exercises the multi-host branch (any `hosts.length > 1` does), it just
// serialises it, making `scanOutputs`' order equal to `hosts`' own order, deterministically.
async function driveMultiHostScan(hosts, behaviors) {
  const outRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-kev-'));
  const savedArgv = process.argv;
  const savedEnv = {
    SCAN_OUT_PATH: process.env.SCAN_OUT_PATH,
    OPENAI_OUT_PATH: process.env.OPENAI_OUT_PATH,
    NSA_ALLOW_ALL_HOSTS: process.env.NSA_ALLOW_ALL_HOSTS,
  };
  try {
    delete process.env.OPENAI_OUT_PATH;
    process.env.SCAN_OUT_PATH = outRoot;
    process.env.NSA_ALLOW_ALL_HOSTS = '1';
    process.argv = ['node', 'cli', 'scan', '--host', hosts.join(','), '--plugins', '003',
      '--ports', '1-2', '--parallel', '1'];
    const testHooks = driveHooks(behaviors);
    await main(testHooks);
    const records = await listRunRecords(outRoot);
    assert.equal(records.length, 1, 'exactly one run record per run');
    return records[0];
  } finally {
    process.argv = savedArgv;
    for (const [k, v] of Object.entries(savedEnv)) {
      if (v == null) delete process.env[k]; else process.env[k] = v;
    }
  }
}

// ── FOURTH QUADRANT FIRST — the positive control, written before any veto case. ──────────
// This is the leg that rots if the aggregation degenerates to "always false": two hosts, both
// report a KEV store with the SAME dataAsOf.
test('KEV: two hosts agreeing on dataAsOf -> loaded true, snapshot is that date', async () => {
  const rec = await driveMultiHostScan(['127.0.0.1', '127.0.0.2'], {
    '127.0.0.1': { dataAsOf: '2026-08-01T00:00:00.000Z' },
    '127.0.0.2': { dataAsOf: '2026-08-01T00:00:00.000Z' },
  });
  assert.equal(rec.hostsWritten.length, 2, 'both hosts must have landed for this fixture to mean anything');
  assert.equal(rec.kevLoaded, true);
  assert.equal(rec.kevSnapshot, '2026-08-01T00:00:00.000Z');
});

// ── MIXED — host A has a store, host B does not. ──────────────────────────────────────────
// Ordered so a "last host wins" implementation (mutant c) would WRONGLY read this as loaded,
// since the LAST host in the array is the one WITH a store: the correct all-or-nothing rule
// must still say false, because host A's findings were never checked against a store.
test('KEV: one of two hosts lacks a store -> loaded false, not the last host\'s value', async () => {
  const rec = await driveMultiHostScan(['127.0.0.1', '127.0.0.2'], {
    '127.0.0.1': null,
    '127.0.0.2': { dataAsOf: '2026-08-01T00:00:00.000Z' },
  });
  assert.equal(rec.hostsWritten.length, 2);
  assert.equal(rec.kevLoaded, false,
    'a store present for only one of two written hosts must not read as loaded for the run');
  assert.equal(rec.kevSnapshot, null);
});

// The same shape, but via the mechanism the coordinator specifically named reachable: one
// host's real `enrichScan` THROWS (caught by cli.mjs's own per-host try/catch) while the
// other's succeeds — no exotic input, just an ordinary per-host failure.
test('KEV: one host\'s enrichment THROWS while the other succeeds -> loaded false', async () => {
  const rec = await driveMultiHostScan(['127.0.0.1', '127.0.0.2'], {
    '127.0.0.1': 'throw',
    '127.0.0.2': { dataAsOf: '2026-08-01T00:00:00.000Z' },
  });
  assert.equal(rec.hostsWritten.length, 2, 'a thrown enrichment must not stop the host from being scanned/written');
  assert.equal(rec.kevLoaded, false);
  assert.equal(rec.kevSnapshot, null);
});

// ── DISAGREE — both hosts loaded a store, but report DIFFERENT dataAsOf values. ───────────
test('KEV: two hosts both load a store but DISAGREE on dataAsOf -> loaded true, snapshot null', async () => {
  const rec = await driveMultiHostScan(['127.0.0.1', '127.0.0.2'], {
    '127.0.0.1': { dataAsOf: '2026-08-01T00:00:00.000Z' },
    '127.0.0.2': { dataAsOf: '2026-08-02T00:00:00.000Z' },
  });
  assert.equal(rec.hostsWritten.length, 2);
  assert.equal(rec.kevLoaded, true,
    'every written host DID load a store — a disagreement on the date is not the same as no store');
  assert.equal(rec.kevSnapshot, null,
    'a snapshot date true for one host and wrong for another is worse than no date at all');
});

// ── CE CONTROL — EE genuinely unavailable (a real Community install). ─────────────────────
// `'no-ee'` makes the injected hook ITSELF throw, so `ee` stays `null` inside cli.mjs —
// deterministic regardless of whether this MACHINE happens to have the real
// `@nsasoft/nsauditor-ai-ee` package resolvable (it is, in this dev checkout, via a symlink;
// relying on that would make the test's result depend on incidental environment state).
test('KEV: EE genuinely unavailable -> loaded false, snapshot null (the honest CE default)', async () => {
  const rec = await driveMultiHostScan(['127.0.0.1'], 'no-ee');
  assert.equal(rec.hostsWritten.length, 1);
  assert.equal(rec.kevLoaded, false);
  assert.equal(rec.kevSnapshot, null);
});

// ── EE PRESENT, BUT REPORTS NO STORE — the exact distinction mutant (b) is about. ─────────
// `ee` is truthy here (the fake module imports successfully) and `enrichScan` runs to
// completion; it just reports `exploitIntel.stores.kev: null` (no store configured), which is
// the ordinary, expected shape for an EE-licensed install with no KEV/EPSS files placed. A
// "kevLoaded derives from EE being importable" bug reads this as loaded; the correct code
// must read it as not loaded, because `ee` being truthy says nothing about whether a STORE
// was loaded.
test('KEV: EE importable but its enrichScan reports no store -> loaded false, not "EE is present"', async () => {
  const rec = await driveMultiHostScan(['127.0.0.1'], { '127.0.0.1': null });
  assert.equal(rec.hostsWritten.length, 1);
  assert.equal(rec.kevLoaded, false);
  assert.equal(rec.kevSnapshot, null);
});

// EPSS is independent of KEV and must be aggregated on its OWN dataAsOf, never borrowing
// KEV's. A single host reporting a KEV date but no EPSS date must show epssLoaded:false while
// kevLoaded:true, proving the two are not accidentally sharing one code path.
test('EPSS aggregates independently of KEV', async () => {
  const outRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-kev-epss-'));
  const savedArgv = process.argv;
  const savedEnv = { SCAN_OUT_PATH: process.env.SCAN_OUT_PATH, NSA_ALLOW_ALL_HOSTS: process.env.NSA_ALLOW_ALL_HOSTS };
  try {
    process.env.SCAN_OUT_PATH = outRoot;
    process.env.NSA_ALLOW_ALL_HOSTS = '1';
    process.argv = ['node', 'cli', 'scan', '--host', '127.0.0.1', '--plugins', '003', '--ports', '1-2'];
    const testHooks = {
      importEE: async () => ({
        enrichScan: async () => ({
          enrichedPrompt: null,
          exploitIntel: {
            stores: {
              kev: { dataAsOf: '2026-08-01T00:00:00.000Z' },
              epss: null,
            },
          },
        }),
      }),
    };
    await main(testHooks);
    const records = await listRunRecords(outRoot);
    assert.equal(records.length, 1);
    const rec = records[0];
    assert.equal(rec.kevLoaded, true);
    assert.equal(rec.kevSnapshot, '2026-08-01T00:00:00.000Z');
    assert.equal(rec.epssLoaded, false, 'EPSS must not inherit KEV\'s loaded state');
    assert.equal(rec.epssSnapshot, null);
  } finally {
    process.argv = savedArgv;
    for (const [k, v] of Object.entries(savedEnv)) {
      if (v == null) delete process.env[k]; else process.env[k] = v;
    }
  }
});
