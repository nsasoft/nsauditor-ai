import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
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
  // A password routinely contains `/` (base64). Userinfo must strip BEFORE the path split,
  // or the password is cut at the slash, the host is discarded with the remainder, and a
  // credential fragment lands with no host at all.
  assert.equal(normaliseHost('user:pa/ss@10.0.0.7'), '10.0.0.7');
  assert.equal(normaliseHost('https://user:pa/ss@db01.internal:8443/x'), 'db01.internal:8443');
  // The record is a file a consultant zips and sends. `@` must not survive at all.
  for (const raw of ['user:pass@10.0.0.7', 'https://user:pass@db01.internal:8443/x', 'user:pa/ss@10.0.0.7']) {
    assert.ok(!normaliseHost(raw).includes('@'), `userinfo survived: ${raw}`);
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
    hostsRequested: ['user:pass@10.0.0.7', 'https://db01.internal:8443/x', 'user:pa/ss@10.0.0.9'],
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
  assert.deepEqual(rec.hostsRequested, ['10.0.0.7', 'db01.internal:8443', '10.0.0.9']);
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
  // This confirms the rename-based write cleans up after itself on the success path; it does
  // NOT exercise crash-mid-write atomicity, which needs process-level fault injection and is
  // out of reach for a deterministic unit test.
  const outRoot = tmp();
  const runId = newRunId();
  await writeRunStart(outRoot, { runId, startedAt: new Date().toISOString(), hostsRequested: ['10.0.0.1'],
    pluginsRequested: [], portsRequested: null, tier: 'ce', ceVersion: '0.2.50', eeVersion: null,
    kevLoaded: false, kevSnapshot: null, epssLoaded: false, epssSnapshot: null });
  const names = fs.readdirSync(outRoot);
  assert.ok(!names.some((n) => n.endsWith('.tmp')), 'a temp file was left behind after write');
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
