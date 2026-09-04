import test, { mock } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {
  RUN_RECORD_SCHEMA, runRecordPath, newRunId, normaliseHost,
  writeRunStart, appendHostWritten, finalizeRunRecord, readRunRecord, listRunRecords,
  pruneRunRecordsForCE,
} from '../utils/run_record.mjs';

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-run-'));

test('normaliseHost leaves an ordinary host untouched', () => {
  assert.equal(normaliseHost('10.0.0.7'), '10.0.0.7');
  assert.equal(normaliseHost('db01.internal'), 'db01.internal');
  assert.equal(normaliseHost('10.0.0.7:8443'), '10.0.0.7:8443');
  assert.equal(normaliseHost('aws'), 'aws');
});

test('normaliseHost strips userinfo and scheme — a credential must never reach the record', () => {
  assert.equal(normaliseHost('user:pass@10.0.0.7'), '10.0.0.7');
  assert.equal(normaliseHost('admin@db01.internal'), 'db01.internal');
  assert.equal(normaliseHost('https://10.0.0.7/scan'), '10.0.0.7');
  assert.equal(normaliseHost('https://user:pass@db01.internal:8443/x'), 'db01.internal:8443');
  // The record is a file a consultant zips and sends. `@` must not survive at all.
  for (const raw of ['user:pass@10.0.0.7', 'https://user:pass@db01.internal:8443/x']) {
    assert.ok(!normaliseHost(raw).includes('@'), `userinfo survived: ${raw}`);
  }
});

test('normaliseHost: authority-first with a credential-shaped fallback — no single ordering satisfies all nine', async (t) => {
  // Neither "split-on-/-then-strip-@" nor "strip-on-@-then-split-on-/" is correct alone: each
  // row below falsifies at least one of the two orderings tried before this rule existed.
  // Each row is its OWN subtest — a for-loop with one `assert.equal` per row would let the
  // FIRST failing row's thrown assertion mask every later row (a loud defect hiding a silent
  // one on the same condition; this is exactly how a mutant that breaks TWO rows was first
  // seen to break only one).
  const cases = [
    ['user:pa/ss@10.0.0.7',                     '10.0.0.7',            'the original leak: a / inside the password'],
    ['https://user:pa/ss@db01.internal:8443/x', 'db01.internal:8443',  'leak + scheme + port'],
    ['https://user:pass@host/path@x',           'host',                'the regression: a second @ inside the PATH'],
    ['user:pass@10.0.0.7',                      '10.0.0.7',            'plain userinfo'],
    ['10.0.0.7/path@x',                         '10.0.0.7',            'bare-host leg of the fallback guard'],
    ['10.0.0.7',                                '10.0.0.7',            'plain host'],
    ['db01.internal:8443',                      'db01.internal:8443',  'host:port must not be mistaken for user:pass'],
    // A bare 'db01.internal:8443' (no '@' anywhere) never reaches the fallback guard at all —
    // `s.includes('@')` is false, so isHostPort/isBareHost is never even evaluated. This row
    // puts an '@' in the PATH so the guard's isHostPort leg is actually exercised.
    ['db01.internal:8443/path@x',                'db01.internal:8443', 'host:port leg of the fallback guard'],
    ['aws',                                      'aws',                'the sentinel cloud hosts must survive untouched'],
  ];
  for (const [input, expected, why] of cases) {
    await t.test(`${why} — ${input}`, () => {
      const actual = normaliseHost(input);
      assert.equal(actual, expected);
      if (input.includes('@')) {
        assert.ok(!actual.includes('@'), `userinfo survived: ${input}`);
      }
    });
  }
});

test('a started run is readable, and finalizing adds completion without losing the start fields', async () => {
  const outRoot = tmp();
  const runId = newRunId();
  await writeRunStart(outRoot, {
    runId, startedAt: '2026-08-26T09:14:00.000Z',
    hostsRequested: ['10.0.0.7', '10.0.0.9'],
    pluginsRequested: ['port_scanner', 'tls_scanner'],
    portsRequested: '1-1024', tier: 'pro',
    ceVersion: '0.2.50', eeVersion: '0.43.0',
    kevLoaded: true, kevSnapshot: '2026-08-20',
    epssLoaded: false, epssSnapshot: null,
  });
  const started = await readRunRecord(outRoot, runId);
  assert.equal(started.schema, RUN_RECORD_SCHEMA);
  assert.equal(started.finishedAt, null, 'a started run must record finishedAt as null');
  assert.deepEqual(started.hostsRequested, ['10.0.0.7', '10.0.0.9']);

  await appendHostWritten(outRoot, runId, { host: '10.0.0.7', dir: '10.0.0.7_20260826T091400' });
  await finalizeRunRecord(outRoot, runId, { finishedAt: '2026-08-26T09:31:00.000Z' });
  const done = await readRunRecord(outRoot, runId);
  assert.equal(done.finishedAt, '2026-08-26T09:31:00.000Z');
  assert.deepEqual(done.pluginsRequested, ['port_scanner', 'tls_scanner'],
    'finalize must not drop the start fields');
  assert.equal(done.hostsWritten.length, 1);
});

test('the record contains no absolute path, no userinfo and no account-shaped id', async () => {
  const outRoot = tmp();
  const runId = newRunId();
  await writeRunStart(outRoot, {
    runId, startedAt: new Date().toISOString(),
    hostsRequested: ['user:pass@10.0.0.7', 'https://db01.internal:8443/x', 'user:pa/ss@10.0.0.9',
      'https://user:pass@host/path@x'],
    pluginsRequested: ['port_scanner'], portsRequested: '443', tier: 'ce',
    ceVersion: '0.2.50', eeVersion: null,
    kevLoaded: false, kevSnapshot: null, epssLoaded: false, epssSnapshot: null,
  });
  const raw = fs.readFileSync(runRecordPath(outRoot, runId), 'utf8');
  assert.ok(!raw.includes('@'),            'userinfo or an email reached the record');
  // `!includes('@')` alone is satisfied by a leak that removes `@` along with the PATH while
  // leaving `username:password-fragment` behind (the order bug) — check the fragments by name,
  // not merely the separator.
  assert.ok(!raw.includes('user'),         'a credential fragment (username) reached the record');
  assert.ok(!raw.includes('pa'),           'a credential fragment (password prefix) reached the record');
  assert.ok(!/"\/(?:Users|home|var|etc|tmp|opt|root|Volumes)\//.test(raw), 'an absolute path reached the record');
  assert.ok(!/\bAKIA[0-9A-Z]{16}\b/.test(raw), 'an access key reached the record');
  assert.ok(!/\b\d{12}\b/.test(raw),       'a 12-digit account id reached the record');
  const rec = JSON.parse(raw);
  // The credential being GONE is only half the property; losing the HOST to the same fix is
  // the other failure this round is about. A raw substring check for "host" would be vacuous
  // here — the field names `hostsRequested`/`hostsWritten` already contain that substring — so
  // this checks the parsed VALUE instead.
  assert.ok(rec.hostsRequested.includes('host'),
    'the host itself was lost, not just the credential — https://user:pass@host/path@x');
  assert.deepEqual(rec.hostsRequested, ['10.0.0.7', 'db01.internal:8443', '10.0.0.9', 'host']);
});

test('finalizeRunRecord accepts the correct call, and REFUSES the narrowed-away key', async () => {
  // Fourth quadrant FIRST: prove the correct call still works, or "throws on everything" passes.
  const outRoot = tmp(), runId = newRunId();
  await writeRunStart(outRoot, { runId, startedAt: new Date().toISOString(), hostsRequested: ['10.0.0.1'],
    pluginsRequested: [], portsRequested: null, tier: 'ce', ceVersion: '0.2.50', eeVersion: null,
    kevLoaded: false, kevSnapshot: null, epssLoaded: false, epssSnapshot: null });
  assert.equal(await finalizeRunRecord(outRoot, runId, { finishedAt: '2026-08-26T09:31:00.000Z' }), true);
  // THEN the veto: the key this signature narrowed away must throw BY NAME, not be ignored.
  await assert.rejects(
    () => finalizeRunRecord(outRoot, runId, { hostsWritten: [{ host: 'x', dir: 'y' }], finishedAt: 'z' }),
    /hostsWritten/,
    'a stray hostsWritten was silently ignored instead of refused');
});

test('appendHostWritten accumulates across sequential calls and stores dir as a BASENAME, never a path', async () => {
  const outRoot = tmp();
  const runId = newRunId();
  await writeRunStart(outRoot, { runId, startedAt: new Date().toISOString(), hostsRequested: ['10.0.0.1', '10.0.0.2'],
    pluginsRequested: [], portsRequested: null, tier: 'ce', ceVersion: '0.2.50', eeVersion: null,
    kevLoaded: false, kevSnapshot: null, epssLoaded: false, epssSnapshot: null });

  await appendHostWritten(outRoot, runId, { host: '10.0.0.1', dir: '10.0.0.1_x' });
  // A second sequential append must ACCUMULATE, not replace — a mutant that keeps only the
  // latest entry stays green as long as every fixture in the suite appends exactly one host.
  await appendHostWritten(outRoot, runId, { host: '10.0.0.2', dir: '/Users/someone/scans/10.0.0.2_x' });

  const rec = await readRunRecord(outRoot, runId);
  assert.equal(rec.hostsWritten.length, 2, 'a second append dropped the first instead of accumulating');
  assert.deepEqual(rec.hostsWritten, [
    { host: '10.0.0.1', dir: '10.0.0.1_x' },
    { host: '10.0.0.2', dir: '10.0.0.2_x' },
  ], 'dir must be stored as a basename even when given a full path — the NAME is scope, the path to it is environment');

  const raw = fs.readFileSync(runRecordPath(outRoot, runId), 'utf8');
  assert.ok(!/"\/(?:Users|home|var|etc|tmp|opt|root|Volumes)\//.test(raw),
    'an absolute path reached the record via hostsWritten[].dir');
});

test('appendHostWritten does not lose an update to a concurrent one — CE ships --parallel <n>', async () => {
  const outRoot = tmp();
  const hosts = Array.from({ length: 8 }, (_, i) => `10.0.0.${i}`);
  const base = { pluginsRequested: [], portsRequested: null, tier: 'pro',
    ceVersion: '0.2.50', eeVersion: '0.43.0', kevLoaded: false, kevSnapshot: null,
    epssLoaded: false, epssSnapshot: null };

  // Fourth quadrant FIRST: sequential appends must all land, or "nothing is ever lost" would
  // trivially hold for the wrong reason (an always-broken writer that happens to serialize).
  const seqRunId = newRunId();
  await writeRunStart(outRoot, { ...base, runId: seqRunId, hostsRequested: hosts, startedAt: new Date().toISOString() });
  for (const host of hosts) {
    await appendHostWritten(outRoot, seqRunId, { host, dir: `${host}_x` });
  }
  const seqRec = await readRunRecord(outRoot, seqRunId);
  assert.equal(seqRec.hostsWritten.length, 8, 'sequential appends lost an entry');

  // THEN the veto: concurrent appends over a FRESH run — the --parallel shape — must all land too.
  const parRunId = newRunId();
  await writeRunStart(outRoot, { ...base, runId: parRunId, hostsRequested: hosts, startedAt: new Date().toISOString() });
  await Promise.all(hosts.map((host) => appendHostWritten(outRoot, parRunId, { host, dir: `${host}_x` })));
  const parRec = await readRunRecord(outRoot, parRunId);
  assert.equal(parRec.hostsWritten.length, 8, 'a concurrent append was lost under --parallel');
});

test('finalizeRunRecord racing concurrent appends does not lose the hosts or the completion', async () => {
  const outRoot = tmp();
  const hosts = Array.from({ length: 8 }, (_, i) => `10.0.0.${i}`);
  const base = { pluginsRequested: [], portsRequested: null, tier: 'pro',
    ceVersion: '0.2.50', eeVersion: '0.43.0', kevLoaded: false, kevSnapshot: null,
    epssLoaded: false, epssSnapshot: null };

  // Fourth quadrant FIRST: sequential append-then-finalize must still work, or "finalize
  // always wins" (racing away every append) would pass this test for the wrong reason.
  const seqRunId = newRunId();
  await writeRunStart(outRoot, { ...base, runId: seqRunId, hostsRequested: hosts, startedAt: new Date().toISOString() });
  for (const host of hosts) {
    await appendHostWritten(outRoot, seqRunId, { host, dir: `${host}_x` });
  }
  await finalizeRunRecord(outRoot, seqRunId, { finishedAt: '2026-08-26T09:31:00.000Z' });
  const seqRec = await readRunRecord(outRoot, seqRunId);
  assert.equal(seqRec.hostsWritten.length, 8, 'sequential appends before finalize were lost');
  assert.equal(seqRec.finishedAt, '2026-08-26T09:31:00.000Z', 'finalize did not record completion');

  // THEN the veto: finalize racing appends STILL IN FLIGHT must lose neither — a late append
  // reading the record before finalize wrote it would otherwise overwrite finalize's own write
  // with a stale `finishedAt: null`, the same race one function over.
  //
  // ⚠️ POSITION MATTERS HERE, not just concurrency. Every call in this array is registered onto
  // the per-run lock queue SYNCHRONOUSLY, in array order, before any of them actually run — so
  // putting `finalizeRunRecord` LAST (or first) lets the queue serialize around it BY REGISTRATION
  // ORDER ALONE, regardless of whether its own body is inside or outside the lock: queued last,
  // every append has already finished by the time it runs; queued first, nothing has started yet.
  // Neither position can distinguish "protected" from "protected-in-name-only" (this was measured:
  // finalize queued last left an M8 mutant — its body moved outside the lock — completely
  // undetected, all green). Queuing it in the MIDDLE, chained between two batches of appends,
  // is what lets its (mutant-unprotected) body actually overlap a still-in-flight append's real
  // read-modify-write on the real filesystem.
  const parRunId = newRunId();
  await writeRunStart(outRoot, { ...base, runId: parRunId, hostsRequested: hosts, startedAt: new Date().toISOString() });
  const mid = Math.floor(hosts.length / 2);
  await Promise.all([
    ...hosts.slice(0, mid).map((host) => appendHostWritten(outRoot, parRunId, { host, dir: `${host}_x` })),
    finalizeRunRecord(outRoot, parRunId, { finishedAt: '2026-08-26T09:31:00.000Z' }),
    ...hosts.slice(mid).map((host) => appendHostWritten(outRoot, parRunId, { host, dir: `${host}_x` })),
  ]);
  const parRec = await readRunRecord(outRoot, parRunId);
  assert.equal(parRec.hostsWritten.length, 8, 'a host append racing finalize was lost');
  assert.equal(parRec.finishedAt, '2026-08-26T09:31:00.000Z', 'finalize racing appends lost the completion');
});

test('appendHostWritten recovers the run queue after a caller-side throw, without wedging a later append', async () => {
  const outRoot = tmp();
  const runId = newRunId();
  await writeRunStart(outRoot, { runId, startedAt: new Date().toISOString(), hostsRequested: ['10.0.0.1', '10.0.0.2'],
    pluginsRequested: [], portsRequested: null, tier: 'ce', ceVersion: '0.2.50', eeVersion: null,
    kevLoaded: false, kevSnapshot: null, epssLoaded: false, epssSnapshot: null });

  // A caller-supplied `dir` that throws on its own String() coercion — the lock's own body
  // rejects, by design (see the report: a caller's own throw rejects to its caller, unlike an
  // fs fault). The QUEUE for this runId must still recover for the NEXT caller.
  const boomDir = { toString() { throw new Error('boom'); } };
  await assert.rejects(
    () => appendHostWritten(outRoot, runId, { host: '10.0.0.1', dir: boomDir }),
    /boom/,
    'the throwing call itself must still reject to its caller');

  // THEN the veto: a plain append on the SAME run, right after, must still settle and land.
  const result = await appendHostWritten(outRoot, runId, { host: '10.0.0.2', dir: '10.0.0.2_x' });
  assert.equal(result, true, 'the queue was wedged by the prior rejection instead of recovering');
  const rec = await readRunRecord(outRoot, runId);
  assert.equal(rec.hostsWritten.length, 1);
  assert.deepEqual(rec.hostsWritten[0], { host: '10.0.0.2', dir: '10.0.0.2_x' });
});

test("a caller-side throw with NOTHING queued after it never leaves the run queue's own continuation promise unhandled", async () => {
  // ⚠️ MEASURED: the previous test (a throw followed by a plain append on the same run) does
  // NOT discriminate the mutant this one is for — the recovery a SUBSEQUENT caller observes
  // comes from `prior.then(fn, fn)` (both handlers, unmutated) at the CONSUMING end, not from
  // whether the STORED continuation promise itself carries a rejection handler. That storage
  // promise only matters when NOTHING EVER consumes it — i.e. the throwing call is the LAST
  // operation on its run. Then, if it carries no rejection handler of its own, it is left an
  // unconsumed rejection, and Node's own unhandled-rejection tracker is the only thing that can
  // observe that (by default that would terminate the process; a temporary local listener lets
  // this test observe it instead, without crashing the whole suite).
  const outRoot = tmp();
  const runId = newRunId();
  await writeRunStart(outRoot, { runId, startedAt: new Date().toISOString(), hostsRequested: ['10.0.0.1'],
    pluginsRequested: [], portsRequested: null, tier: 'ce', ceVersion: '0.2.50', eeVersion: null,
    kevLoaded: false, kevSnapshot: null, epssLoaded: false, epssSnapshot: null });

  const boomDir = { toString() { throw new Error('boom'); } };
  let unhandled = null;
  const onUnhandledRejection = (err) => { unhandled = err; };
  process.on('unhandledRejection', onUnhandledRejection);
  try {
    await assert.rejects(
      () => appendHostWritten(outRoot, runId, { host: '10.0.0.1', dir: boomDir }),
      /boom/,
      'the throwing call itself must still reject to its caller');
    // Node defers the unhandled-rejection check by one tick past the rejection; give it room.
    await new Promise((resolve) => setTimeout(resolve, 50));
  } finally {
    process.off('unhandledRejection', onUnhandledRejection);
  }
  assert.equal(unhandled, null,
    `the run queue's own continuation promise was left an unhandled rejection: ${unhandled?.message}`);
});

test('writeRunStart never throws — a malformed field is wrapped, not propagated', async () => {
  const outRoot = tmp();
  // `.map` does not exist on a string; this is exactly the shape of caller-input failure the
  // "returns the path, or null on a wrapped failure" contract must survive.
  const result = await writeRunStart(outRoot, {
    runId: newRunId(), startedAt: new Date().toISOString(),
    hostsRequested: 'not-an-array',
    pluginsRequested: [], portsRequested: null, tier: 'ce', ceVersion: '0.2.50', eeVersion: null,
    kevLoaded: false, kevSnapshot: null, epssLoaded: false, epssSnapshot: null,
  });
  assert.equal(result, null, 'a malformed field crashed the write instead of being wrapped');
});

test('writeJsonSafe leaves no stray .tmp artifact after a normal write', async () => {
  // This confirms the rename-based write cleans up after itself on the success path. On its
  // own it does NOT exercise write-failure or crash-mid-write behavior — see the next test for
  // the property that a failed write cannot corrupt the existing record; process-level
  // crash-mid-write resilience (a kill -9 between `writeFile` and `rename`) remains the one
  // residual that stays out of reach for a deterministic unit test.
  const outRoot = tmp();
  const runId = newRunId();
  await writeRunStart(outRoot, { runId, startedAt: new Date().toISOString(), hostsRequested: ['10.0.0.1'],
    pluginsRequested: [], portsRequested: null, tier: 'ce', ceVersion: '0.2.50', eeVersion: null,
    kevLoaded: false, kevSnapshot: null, epssLoaded: false, epssSnapshot: null });
  const names = fs.readdirSync(outRoot);
  assert.ok(!names.some((n) => n.endsWith('.tmp')), 'a temp file was left behind after write');
});

test('a failed write leaves the previously-valid record untouched — the property the atomic write is for', async () => {
  const outRoot = tmp();
  const runId = newRunId();
  await writeRunStart(outRoot, { runId, startedAt: new Date().toISOString(), hostsRequested: ['10.0.0.1'],
    pluginsRequested: [], portsRequested: null, tier: 'ce', ceVersion: '0.2.50', eeVersion: null,
    kevLoaded: false, kevSnapshot: null, epssLoaded: false, epssSnapshot: null });
  const before = await readRunRecord(outRoot, runId);

  // The module holds the SAME `node:fs/promises` default object, so mocking the method here
  // reaches the production code's own `fsp.writeFile` call. Write HALF the intended bytes,
  // then fail — simulating a disk-full mid-write — and prove the TARGET is untouched because
  // the half-written bytes landed in the `.tmp` sibling, never in the file `readRunRecord` reads.
  const realWriteFile = fsp.writeFile;
  mock.method(fsp, 'writeFile', async (p, data) => {
    await realWriteFile(p, String(data).slice(0, Math.floor(String(data).length / 2)));
    throw new Error('disk full');
  });
  try {
    const result = await appendHostWritten(outRoot, runId, { host: '10.0.0.1', dir: 'x' });
    assert.equal(result, false, 'a failed write must report failure, not silently succeed');
  } finally {
    mock.restoreAll();
  }

  const after = await readRunRecord(outRoot, runId);
  assert.ok(after, 'a failed write corrupted the existing record into something unparseable');
  assert.deepEqual(after, before, 'a failed write must leave the previously-valid record untouched');
});

test('CE retention keeps a run inside the window and removes one outside it', async () => {
  const outRoot = tmp();
  const fresh = newRunId(), old = newRunId();
  const base = { pluginsRequested: [], portsRequested: null, tier: 'ce',
    ceVersion: '0.2.50', eeVersion: null, kevLoaded: false, kevSnapshot: null,
    epssLoaded: false, epssSnapshot: null, hostsRequested: ['10.0.0.1'] };
  await writeRunStart(outRoot, { ...base, runId: fresh, startedAt: new Date(Date.now() - 60_000).toISOString() });
  await writeRunStart(outRoot, { ...base, runId: old,   startedAt: new Date(Date.now() - 40 * 86_400_000).toISOString() });
  const removed = await pruneRunRecordsForCE(outRoot);
  assert.equal(removed, 1);
  assert.ok(await readRunRecord(outRoot, fresh), 'a run inside the window was deleted');
  assert.equal(await readRunRecord(outRoot, old), null, 'a run outside the window survived');
});
