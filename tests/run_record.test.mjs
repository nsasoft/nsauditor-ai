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

// ⚠️ AN ORACLE HAS A MODEL, AND A MODEL HAS A BOUNDARY. The first version of this asked only
// "did the output draw bytes from before the last '@'?" — which is blind to a SECOND credential
// shape, a token in a query string or fragment, because those bytes are AFTER the '@'
// (`10.0.0.7?api_key=SECRET123` drew nothing from before any '@' — there is none — and passed
// clean). Asserting the output is the maximal DELIMITER-FREE prefix of the post-'@' segment
// covers both: nothing from the credential side, and nothing from the query/fragment side either.
// A THIRD shape — `user:pass%40host`, a PERCENT-ENCODED '@' — showed the oracle shares the
// production rule's blind spot for the same reason: both key off a LITERAL '@'. Decoding `%40`
// here mirrors the production decode; without it, this oracle would call that row clean too.
// ⚠️ THIS IS NOW THE SAME EXPRESSION AS THE PRODUCTION RULE, so it cannot be the only guard — a
// shared expression proves CONSISTENCY, not correctness. The fixture table's explicit expected
// column remains the independent statement of truth; this oracle's job is catching a row nobody
// thought to add, not replacing the table.
function expectedHostToken(raw) {
  const s = String(raw).replace(/^[a-z][a-z0-9+.-]*:\/\//i, '').replace(/%40/gi, '@');
  const at = s.lastIndexOf('@');
  return (at === -1 ? s : s.slice(at + 1)).split(/[/?#]/)[0];
}

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

test('normaliseHost: the simplest rule that holds "no credential, ever" — last @, then cut at the first URL delimiter', async (t) => {
  // ⚠️ THE INVARIANT IS "NO CREDENTIAL, EVER" — NOT "THE HOST SURVIVES". Every heuristic tried
  // on this function bought a leak of its own: authority-first leaked `admin:1234` out of
  // `admin:1234/56@10.0.0.7` (a numeric password with a slash reads exactly like host:port);
  // credential-first leaked `ss` out of `user:p@ss/wd@host` (a '/' inside the password
  // truncates the authority before the SECOND '@' is ever seen). Two further finds were SECOND
  // and THIRD credential shapes rather than further heuristics: cutting on '/' alone left a
  // query string or fragment (`10.0.0.7?api_key=SECRET123`, `10.0.0.7#SECRET123`) attached to
  // the host, since neither has a '/' to cut on; and a percent-encoded '@' (`user:pass%40host`)
  // is not a literal '@', so `lastIndexOf('@')` returned -1, took the "no userinfo" branch, and
  // returned the WHOLE credential-bearing string unstripped — worse than any fragment leak,
  // because nothing was stripped at all. This table is the accumulated record of every shape
  // that motivated a change, kept — not trimmed — so the next maintainer can see exactly what
  // was tried and why each one failed.
  // Each row is its OWN subtest — a for-loop with one `assert.equal` per row would let the
  // FIRST failing row's thrown assertion mask every later row (a loud defect hiding a silent
  // one on the same condition; measured directly in an earlier round of this same table).
  const cases = [
    // Leaks under one or another PRIOR rule — all closed by "last @, then cut at the first
    // URL delimiter".
    ['user:pa/ss@10.0.0.7',                     '10.0.0.7',            'a / inside the password'],
    ['https://user:pa/ss@db01.internal:8443/x', 'db01.internal:8443',  'leak + scheme + port'],
    ['admin:1234/56@10.0.0.7',                  '10.0.0.7',            'numeric password + slash read as host:port (authority-first leak)'],
    ['root:0000/abc@db01.internal',             'db01.internal',       'same shape, a different credential'],
    ['user/name:pa@10.0.0.7',                   '10.0.0.7',            'a slash in the USERNAME read as a bare host (authority-first leak)'],
    ['user:p@ss/wd@host',                       'host',                'a / between two @s truncated the authority before the 2nd @ (credential-first leak)'],
    ['user:p@ssword123/junk@host',              'host',                'same shape, a longer credential fragment'],
    ['user:p@ss@10.0.0.7',                      '10.0.0.7',            'password containing @'],
    ['user:pass@10.0.0.7',                      '10.0.0.7',            'plain userinfo'],
    // A SECOND credential shape: a query string or fragment, no '/' anywhere in the string.
    ['10.0.0.7?api_key=SECRET123',              '10.0.0.7',            'query string, no userinfo — the 4th leak'],
    ['user:pass@10.0.0.7?token=SECRET123',      '10.0.0.7',            'query string AFTER userinfo — both cuts must fire'],
    ['10.0.0.7#SECRET123',                      '10.0.0.7',            'fragment, no userinfo'],
    // A THIRD credential shape: a percent-encoded separator. Reachable — the run record is
    // written at scan START from `hostsRequested`, before DNS resolution, so a host string that
    // can never resolve still lands in the file with its credential intact.
    ['user:pass%40host',                        'host',                'percent-encoded @ separator — the whole credential leaked, unstripped'],
    ['admin:s3cret%4010.0.0.7',                  '10.0.0.7',            'same shape, a different credential'],
    ['user:p%40ss@host',                         'host',                'an encoded @ INSIDE the password must still work'],
    // Edge shapes.
    [':pass@host',                              'host',                'empty username'],
    ['user:http://x@host',                      'host',                'a scheme-shaped password'],
    ['user@',                                   '',                    'userinfo with no host at all'],
    // Unchanged.
    ['10.0.0.7',                                '10.0.0.7',            'plain host'],
    ['db01.internal:8443',                      'db01.internal:8443',  'host:port, no userinfo at all'],
    ['[::1]:443',                                '[::1]:443',           'IPv6 must survive untouched'],
    ['aws',                                      'aws',                 'the sentinel cloud hosts must survive untouched'],
    ['azure',                                    'azure',               'the sentinel cloud hosts must survive untouched'],
    ['gcp',                                      'gcp',                 'the sentinel cloud hosts must survive untouched'],
    // ⚠️ ACCEPTED COST — FOUR rows, kept with their trade named rather than deleted. With NO
    // userinfo present, or with the LAST @ sitting inside a PATH, the rule reads that @ as a
    // credential separator too and returns the fragment after it — a wrong host, but zero
    // credential. Nobody types an '@'-in-a-path as a `--host` value; wrong-host-no-credential
    // is the safe direction this module's whole invariant is written around.
    ['https://user:pass@host/path@x',           'x',                   'accepted cost: 2nd @ lives in the path'],
    ['user:p@ss@host/p@x',                      'x',                   'accepted cost: password @ plus a 2nd @ in the path'],
    ['10.0.0.7/path@x',                         'x',                   'accepted cost: no userinfo, @ only in a path'],
    ['db01.internal:8443/path@x',               'x',                   'accepted cost: same trade, host:port shaped'],
  ];
  for (const [input, expected, why] of cases) {
    await t.test(`${why} — ${input}`, () => {
      const actual = normaliseHost(input);
      assert.equal(actual, expected);
      // Applied to EVERY row, not only the `@`-bearing ones — the query/fragment shapes have
      // no `@` at all, which is exactly why the prior (narrower) oracle could not have covered
      // them. This is the SAME expression as the production rule, so it proves consistency, not
      // correctness; `expected` above (the table's own explicit column) is the independent
      // statement of truth.
      assert.equal(actual, expectedHostToken(input),
        `output diverged from the maximal delimiter-free prefix: ${input} -> ${actual}`);
    });
  }
});

test('expectedHostToken is a STRUCTURAL oracle, not a stub — it flags the rules we rejected', () => {
  // Fourth quadrant: the oracle must actually DISCRIMINATE, not just agree with everything — an
  // oracle that never disagrees would pass every row in the table above for the wrong reason.
  // Drive it against a deliberately-broken normaliser: the round-3 "authority-first" rule,
  // reduced to its leaking essence (trust an authority that itself contains no '@', even when
  // that authority is really a username:password) — three lines, and it leaked three of this
  // table's rows for real.
  function r3AuthorityFirst(raw) {
    const s = String(raw ?? '').trim().replace(/^[a-z][a-z0-9+.-]*:\/\//i, '');
    const auth = s.split('/')[0];
    return auth.includes('@') ? auth.slice(auth.lastIndexOf('@') + 1) : auth;
  }
  const knownLeaks = [
    'admin:1234/56@10.0.0.7',
    'root:0000/abc@db01.internal',
    'user/name:pa@10.0.0.7',
  ];
  for (const raw of knownLeaks) {
    const broken = r3AuthorityFirst(raw);
    assert.notEqual(broken, expectedHostToken(raw),
      `the oracle failed to flag a KNOWN leak: ${raw} -> ${broken}`);
  }
  // And it must NOT false-flag the LANDED rule's own output on the same inputs.
  for (const raw of knownLeaks) {
    const correct = normaliseHost(raw);
    assert.equal(correct, expectedHostToken(raw),
      `the oracle false-flagged the correct rule's own output: ${raw} -> ${correct}`);
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
      'admin:1234/56@10.0.0.1', 'root:0000/abc@10.0.0.2', 'user/name:pa@10.0.0.3',
      'user:p@ss/wd@10.0.0.4', 'user:p@ssword123/junk@10.0.0.5',
      '10.0.0.6?api_key=SECRET123', 'user:pass@10.0.0.10?token=SECRET123', '10.0.0.11#SECRET123',
      'user:pass%40host', 'admin:s3cret%4010.0.0.12', 'user:p%40ss@10.0.0.13'],
    pluginsRequested: ['port_scanner'], portsRequested: '443', tier: 'ce',
    ceVersion: '0.2.50', eeVersion: null,
    kevLoaded: false, kevSnapshot: null, epssLoaded: false, epssSnapshot: null,
  });
  const raw = fs.readFileSync(runRecordPath(outRoot, runId), 'utf8');
  assert.ok(!raw.includes('@'),            'userinfo or an email reached the record');
  // A token list only catches the credentials someone thought to plant (measured: a token list
  // built from other fixtures missed `ssword123` entirely). Kept as a SECOND, independent check
  // — it guards the rest of the file (paths, keys, ids), while the structural oracle in the
  // table test above is what actually guards normaliseHost's own output.
  assert.ok(!raw.includes('user'),         'a credential fragment (username) reached the record');
  assert.ok(!raw.includes('pa'),           'a credential fragment (password prefix) reached the record');
  assert.ok(!raw.includes('admin'),        'a credential fragment (admin username) reached the record');
  assert.ok(!raw.includes('1234'),         'a credential fragment (numeric password) reached the record');
  assert.ok(!raw.includes('root'),         'a credential fragment (root username) reached the record');
  assert.ok(!raw.includes('0000'),         'a credential fragment (numeric password) reached the record');
  assert.ok(!raw.includes('ssword'),       'a credential fragment (password) reached the record');
  assert.ok(!raw.includes('SECRET123'),    'a query-string or fragment credential token reached the record');
  assert.ok(!raw.includes('s3cret'),       'a percent-encoded-separator credential fragment reached the record');
  assert.ok(!raw.includes('pass%40'),      'a percent-encoded separator survived unstripped — the whole credential leaked');
  // NOT checked as a raw substring: bare "ss" is a false-positive trap here — the field name
  // `epssSnapshot` (always present as a JSON key, regardless of any real leak) already contains
  // it, so `!raw.includes('ss')` would fail on every record. The exact parsed-array equality
  // below proves no `ss`-shaped fragment survived in a HOST value instead.
  assert.ok(!/"\/(?:Users|home|var|etc|tmp|opt|root|Volumes)\//.test(raw), 'an absolute path reached the record');
  assert.ok(!/\bAKIA[0-9A-Z]{16}\b/.test(raw), 'an access key reached the record');
  assert.ok(!/\b\d{12}\b/.test(raw),       'a 12-digit account id reached the record');
  const rec = JSON.parse(raw);
  assert.deepEqual(rec.hostsRequested,
    ['10.0.0.7', 'db01.internal:8443', '10.0.0.9', '10.0.0.1', '10.0.0.2', '10.0.0.3', '10.0.0.4', '10.0.0.5',
     '10.0.0.6', '10.0.0.10', '10.0.0.11', 'host', '10.0.0.12', '10.0.0.13']);
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

test('a failed rename leaves no stray .tmp behind, and writeRunStart reports null', async () => {
  // The existing `.tmp`-litter test only proves cleanup after a NORMAL write; it never
  // exercises the FAILURE path, which is the only path the `await fsp.unlink(tmpFile)` line
  // in writeJsonSafe's catch block exists for. Force `rename` itself to fail by making the
  // TARGET path a non-empty directory — `writeFile` to the `.tmp` sibling succeeds, then
  // `rename(tmpFile, target)` fails (EISDIR/ENOTEMPTY), landing in the catch.
  const outRoot = tmp();
  const runId = newRunId();
  const target = runRecordPath(outRoot, runId);
  await fsp.mkdir(target, { recursive: true });
  await fsp.writeFile(path.join(target, 'occupied.txt'), 'x');

  const result = await writeRunStart(outRoot, { runId, startedAt: new Date().toISOString(), hostsRequested: ['10.0.0.1'],
    pluginsRequested: [], portsRequested: null, tier: 'ce', ceVersion: '0.2.50', eeVersion: null,
    kevLoaded: false, kevSnapshot: null, epssLoaded: false, epssSnapshot: null });
  assert.equal(result, null, 'a failed rename must report failure, not silently succeed');
  assert.ok(!fs.existsSync(`${target}.tmp`), 'a stray .tmp survived a failed rename');
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
