import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { loadRun } from '../utils/report_inputs.mjs';
import {
  writeRunStart, appendHostWritten, finalizeRunRecord, newRunId, runRecordPath, UNPARSEABLE,
} from '../utils/run_record.mjs';

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-ri-'));
const BASE = { pluginsRequested: ['port_scanner'], portsRequested: '443', tier: 'pro',
  ceVersion: '0.2.50', eeVersion: '0.43.0', kevLoaded: true, kevSnapshot: '2026-08-20',
  epssLoaded: true, epssSnapshot: '2026-08-20' };

function writeHostDir(outRoot, dir, runId, { up = true, findings = [], pluginStatus = null } = {}) {
  fs.mkdirSync(path.join(outRoot, dir), { recursive: true });
  fs.writeFileSync(path.join(outRoot, dir, 'scan_conclusion_raw.json'), JSON.stringify({
    runId, pluginStatus: pluginStatus ?? [{ id: '010', name: 'port_scanner', status: 'ran', reason: null }],
    results: [{ id: '010', name: 'port_scanner', result: { up, findings } }],
  }), 'utf8');
}

// ── Step 1: the eight refusal tests, written before any happy path ─────────────────────────

test('REFUSAL: a run that requested more hosts than it wrote', async () => {
  const outRoot = tmp(), runId = newRunId();
  await writeRunStart(outRoot, { ...BASE, runId, startedAt: '2026-08-26T09:14:00.000Z',
    hostsRequested: ['10.0.0.7', '10.0.0.9'] });
  writeHostDir(outRoot, 'd7', runId);
  await appendHostWritten(outRoot, runId, { host: '10.0.0.7', dir: 'd7' });
  await finalizeRunRecord(outRoot, runId, { finishedAt: '2026-08-26T09:31:00.000Z' });
  const r = await loadRun(outRoot, {});
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'partial-hosts');
  assert.match(r.message, /Refusing to report: this run requested 2 hosts and wrote 1\. Missing: 10\.0\.0\.9\./);
  assert.match(r.message, /--allow-partial/);
});

test('REFUSAL: a run that never recorded completion, where the arithmetic looks COMPLETE', async () => {
  // The dangerous shape: a crash AFTER the last host directory is written leaves
  // hostsWritten == hostsRequested with no finishedAt, so host arithmetic reads clean and the
  // partial-hosts message above would be FALSE here.
  const outRoot = tmp(), runId = newRunId();
  await writeRunStart(outRoot, { ...BASE, runId, startedAt: '2026-08-26T09:14:00.000Z',
    hostsRequested: ['10.0.0.7'] });
  writeHostDir(outRoot, 'd7', runId);
  // PRODUCED BY THE WRITER, not patched in: append the host, then never finalize. That is
  // exactly what a crash after the last host directory leaves behind.
  await appendHostWritten(outRoot, runId, { host: '10.0.0.7', dir: 'd7' });
  const r = await loadRun(outRoot, {});
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'incomplete-run');
  assert.match(r.message, /this run never finished/);
  assert.match(r.message, /All 1 requested hosts were written/);
});

test('REFUSAL: interrupted AND missing hosts — the shape a real interruption produces most', async () => {
  // With append-per-host this is the COMMON interruption: the scan died partway, so some hosts
  // are listed and some are not, and finishedAt is null. The message must not claim all were written.
  const outRoot = tmp(), runId = newRunId();
  await writeRunStart(outRoot, { ...BASE, runId, startedAt: '2026-08-26T09:14:00.000Z',
    hostsRequested: ['10.0.0.7', '10.0.0.8', '10.0.0.9'] });
  writeHostDir(outRoot, 'd7', runId);
  await appendHostWritten(outRoot, runId, { host: '10.0.0.7', dir: 'd7' });
  const r = await loadRun(outRoot, {});
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'incomplete-run');
  assert.match(r.message, /this run never finished/);
  assert.ok(!/All 3 requested hosts were written/.test(r.message),
    'the message claimed every host was written when only one was');
  assert.match(r.message, /1 of 3/);
});

test('REFUSAL: an older-format run whose raw carries no runId', async () => {
  const outRoot = tmp();
  fs.mkdirSync(path.join(outRoot, 'legacy'), { recursive: true });
  fs.writeFileSync(path.join(outRoot, 'legacy', 'scan_conclusion_raw.json'),
    JSON.stringify({ results: [] }), 'utf8');
  const r = await loadRun(outRoot, {});
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'older-format');
  assert.match(r.message, /did not write a run record/);
  assert.match(r.message, /coverage cannot be stated for it/);
});

test('REFUSAL: record absent, raw INSIDE the retention window — deleted or moved', async () => {
  const outRoot = tmp();
  writeHostDir(outRoot, 'd7', 'run-abc');
  const r = await loadRun(outRoot, {});
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'record-absent-inside-window');
  assert.match(r.message, /the record was deleted or moved/);
});

test('REFUSAL: record absent, raw OUTSIDE the window on CE — the retention explanation', async () => {
  const outRoot = tmp();
  writeHostDir(outRoot, 'd7', 'run-abc');
  const old = new Date(Date.now() - 40 * 86_400_000);
  fs.utimesSync(path.join(outRoot, 'd7', 'scan_conclusion_raw.json'), old, old);
  const r = await loadRun(outRoot, {}, { tier: 'ce' });
  assert.equal(r.reason, 'record-absent-outside-window');
  assert.match(r.message, /Community\s*\n?\s*Edition keeps run records for 7 days|Community Edition keeps run records for 7 days/);
});

// CC-5: a `writeRunStart` failure (warned and swallowed in cli.mjs, opts.runId still set) can
// leave EXACTLY this shape — real host evidence, no run record, ever — and that is
// indistinguishable on disk from a record that WAS written and later deleted or moved. Neither
// cause may be asserted alone.
test('CC-5: record absent, raw INSIDE the window on a NON-CE tier — both real causes are named, not one asserted as fact', async () => {
  const outRoot = tmp();
  writeHostDir(outRoot, 'd7', 'run-abc');
  const r = await loadRun(outRoot, {}, { tier: 'pro' });
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'record-absent-inside-window');
  assert.match(r.message, /never successfully written when the scan started/,
    'a write failure at scan start must be named as a real possibility, not silently excluded');
  assert.match(r.message, /deleted or moved/,
    'deletion/move must still be named as a real possibility');
});

// CC-6: the CE_RETENTION_MS age check is a real POLICY only on CE (pruneRunRecordsForCE is the
// only thing that ever prunes on it) — so a non-CE tier must never be told the scan is "older
// than the retention window" while ALSO being told retention is unlimited on its tier. Both
// halves cannot be true at once; the fix removes the age-based framing entirely for non-CE.
test('CC-6: a non-CE tier, however OLD the scan, never gets the self-contradicting retention sentence', async () => {
  const outRoot = tmp();
  writeHostDir(outRoot, 'd7', 'run-abc');
  const old = new Date(Date.now() - 40 * 86_400_000); // well outside CE's 7-day window
  fs.utimesSync(path.join(outRoot, 'd7', 'scan_conclusion_raw.json'), old, old);
  const r = await loadRun(outRoot, {}, { tier: 'pro' });
  assert.equal(r.ok, false);
  assert.notEqual(r.reason, 'record-absent-outside-window',
    'a non-CE tier has no age-based retention policy to attribute the absence to');
  assert.ok(!/older than the retention window/.test(r.message),
    'a non-CE tier must never be told its scan is older than a retention window it does not have');
  assert.ok(!/retention is unlimited/i.test(r.message) || !/older than/.test(r.message),
    'retention-is-unlimited and older-than-the-window must never both appear — that is the CC-6 contradiction');
});

test('REFUSAL: two-way binding mismatch — a directory copied in from another engagement', async () => {
  const outRoot = tmp(), runId = newRunId();
  await writeRunStart(outRoot, { ...BASE, runId, startedAt: '2026-08-26T09:14:00.000Z',
    hostsRequested: ['10.0.0.7'] });
  writeHostDir(outRoot, 'd7', 'A-DIFFERENT-RUN');
  await appendHostWritten(outRoot, runId, { host: '10.0.0.7', dir: 'd7' });
  await finalizeRunRecord(outRoot, runId, { finishedAt: '2026-08-26T09:31:00.000Z' });
  const r = await loadRun(outRoot, {});
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'binding-mismatch');
});

test('REFUSAL: a tie on startedAt is refused, naming both runs', async () => {
  const outRoot = tmp(), a = newRunId(), b = newRunId();
  const at = '2026-08-26T09:14:00.000Z';
  for (const runId of [a, b]) {
    await writeRunStart(outRoot, { ...BASE, runId, startedAt: at, hostsRequested: ['10.0.0.7'] });
    writeHostDir(outRoot, `d-${runId}`, runId);
    await appendHostWritten(outRoot, runId, { host: '10.0.0.7', dir: `d-${runId}` });
    await finalizeRunRecord(outRoot, runId, { finishedAt: at });
  }
  const r = await loadRun(outRoot, {});
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'ambiguous-run');
  assert.ok(r.message.includes(a) && r.message.includes(b), 'a tie must NAME both runs');
});

test('REFUSAL: an unknown schema is refused LOUDLY, never misread', async () => {
  const outRoot = tmp(), runId = newRunId();
  await writeRunStart(outRoot, { ...BASE, runId, startedAt: '2026-08-26T09:14:00.000Z',
    hostsRequested: ['10.0.0.7'] });
  const p = path.join(outRoot, `scan_run_${runId}.json`);
  const rec = JSON.parse(fs.readFileSync(p, 'utf8')); rec.schema = 99;
  fs.writeFileSync(p, JSON.stringify(rec), 'utf8');
  const r = await loadRun(outRoot, {});
  assert.equal(r.reason, 'unknown-schema');
});

// ── Step 3: happy path + --allow-partial ────────────────────────────────────────────────────

test('a complete run loads, and coverage separates unreachable from not-written', async () => {
  const outRoot = tmp(), runId = newRunId();
  await writeRunStart(outRoot, { ...BASE, runId, startedAt: '2026-08-26T09:14:00.000Z',
    hostsRequested: ['10.0.0.7', '10.0.0.8'] });
  writeHostDir(outRoot, 'd7', runId, { up: true,  findings: [{ severity: 'HIGH', title: 'Weak TLS', port: 443 }] });
  writeHostDir(outRoot, 'd8', runId, { up: false, findings: [] });
  await appendHostWritten(outRoot, runId, { host: '10.0.0.7', dir: 'd7' });
  await appendHostWritten(outRoot, runId, { host: '10.0.0.8', dir: 'd8' });
  await finalizeRunRecord(outRoot, runId, { finishedAt: '2026-08-26T09:31:00.000Z' });
  const r = await loadRun(outRoot, {});
  assert.equal(r.ok, true);
  assert.equal(r.model.coverage.requested, 2);
  assert.equal(r.model.coverage.written, 2);
  assert.equal(r.model.coverage.reachable, 1, 'an unreachable host is written but not reachable');
  assert.equal(r.model.coverage.partial, false);
  assert.equal(r.model.findings.length, 1);
});

test('--allow-partial renders and carries the caveat data rather than dropping it', async () => {
  const outRoot = tmp(), runId = newRunId();
  await writeRunStart(outRoot, { ...BASE, runId, startedAt: '2026-08-26T09:14:00.000Z',
    hostsRequested: ['10.0.0.7', '10.0.0.9'] });
  writeHostDir(outRoot, 'd7', runId);
  await appendHostWritten(outRoot, runId, { host: '10.0.0.7', dir: 'd7' });
  await finalizeRunRecord(outRoot, runId, { finishedAt: '2026-08-26T09:31:00.000Z' });
  const r = await loadRun(outRoot, { allowPartial: true });
  assert.equal(r.ok, true, '--allow-partial must render');
  assert.equal(r.model.coverage.partial, true);
  assert.deepEqual(r.model.coverage.missing, ['10.0.0.9'],
    'the flag MOVES the disclosure to the cover; it must never remove it');
});

// ── Extra coverage beyond the brief's ten, driven by the measurement constraints in the task
//    prompt (report separately if any of these turn out to already be satisfied trivially) ──

test('MEASURED CONSTRAINT: two different unparseable-host inputs are not conflated by one written row', async () => {
  // UNPARSEABLE is a single constant, so two different bad `--host` inputs both collapse to the
  // same sentinel string in hostsRequested. A naive `.some()` membership check (rather than a
  // multiset diff) would see the sentinel "covered" by the ONE written row and read the run as
  // complete even though a second bad input was never scanned at all. Build this with the real
  // writer, on real illegal host strings, not by hand-writing the sentinel into JSON.
  const outRoot = tmp(), runId = newRunId();
  await writeRunStart(outRoot, { ...BASE, runId, startedAt: '2026-08-26T09:14:00.000Z',
    hostsRequested: ['bad$host-one', 'bad$host-two'] });
  writeHostDir(outRoot, 'd1', runId);
  await appendHostWritten(outRoot, runId, { host: 'bad$host-three', dir: 'd1' }); // also unparseable
  await finalizeRunRecord(outRoot, runId, { finishedAt: '2026-08-26T09:31:00.000Z' });
  const r = await loadRun(outRoot, {});
  assert.equal(r.ok, false, 'one written unparseable row must not read as covering every unparseable request');
  assert.equal(r.reason, 'partial-hosts');
  assert.ok(!r.message.includes(UNPARSEABLE),
    'the sentinel token must never be printed as if it were a specific missing host name');
  assert.match(r.message, /coverage cannot be established/);

  const rendered = await loadRun(outRoot, { allowPartial: true });
  assert.equal(rendered.ok, true);
  assert.deepEqual(rendered.model.coverage.missing, [],
    'the unparseable deficit is not a NAMED host, so it must not appear in the named-missing list');
  assert.equal(rendered.model.coverage.partial, true,
    'the run is still partial even though no NAMED host is missing');
});

test('MEASURED CONSTRAINT: an unreadable-but-present run record is its own condition, not "absent"', async () => {
  // readRunRecord/listRunRecords both swallow EACCES/EISDIR as if the file were simply gone.
  // Simulate portably (works even as root, unlike chmod 000): put a DIRECTORY where the run
  // record FILE belongs, so reading it throws EISDIR rather than ENOENT.
  const outRoot = tmp(), runId = newRunId();
  fs.mkdirSync(runRecordPath(outRoot, runId), { recursive: true });
  writeHostDir(outRoot, 'd7', runId);
  const r = await loadRun(outRoot, {});
  assert.equal(r.ok, false);
  assert.notEqual(r.reason, 'record-absent-inside-window',
    'a PRESENT-but-broken record must not be reported as though it were deleted or moved');
  assert.notEqual(r.reason, 'record-absent-outside-window');
  assert.equal(r.reason, 'record-unreadable');
  assert.match(r.message, /present/);
  assert.match(r.message, /could not be read/);
});

test('MEASURED CONSTRAINT: an unreadable-but-present record is caught for an explicit --run too', async () => {
  const outRoot = tmp(), runId = newRunId();
  fs.mkdirSync(runRecordPath(outRoot, runId), { recursive: true });
  const r = await loadRun(outRoot, { runId });
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'record-unreadable');
});

// ── Review round 1, item 1: the EACCES/EISDIR fix was HALF-CLOSED — it only fired when
//    listRunRecords() parsed ZERO records. With one good + one corrupt record present,
//    `records.length > 0` short-circuited past the check entirely, and listRunRecords()'s own
//    `catch { /* unreadable: not a run */ }` silently dropped the corrupt one — so the GOOD run
//    would render under its own (correct) subject line while a DIFFERENT run's record sat
//    corrupted and unreported. That is worse than the single-record case: an operator asking
//    "what happened in this out-root" gets an answer that looks complete and is missing a run. ──

test('REVIEW: a multi-record out-root with ONE corrupt record refuses, not renders the other', async () => {
  const outRoot = tmp(), good = newRunId(), corrupt = newRunId();
  await writeRunStart(outRoot, { ...BASE, runId: good, startedAt: '2026-08-26T09:14:00.000Z',
    hostsRequested: ['10.0.0.7'] });
  writeHostDir(outRoot, 'd-good', good);
  await appendHostWritten(outRoot, good, { host: '10.0.0.7', dir: 'd-good' });
  await finalizeRunRecord(outRoot, good, { finishedAt: '2026-08-26T09:31:00.000Z' });
  // A DIRECTORY where the second run's record FILE belongs: EISDIR on read, portable even as
  // root (unlike chmod 000) — the same simulation the single-record test above uses.
  fs.mkdirSync(runRecordPath(outRoot, corrupt), { recursive: true });

  const r = await loadRun(outRoot, {});
  assert.equal(r.ok, false,
    'the GOOD run must not silently render while a SIBLING record is corrupt and unreported');
  assert.equal(r.reason, 'record-unreadable');
  assert.match(r.message, /1 run record file/);
  assert.match(r.message, /other run record\(s\) parsed successfully/,
    'the message must say a DIFFERENT run parsed fine, not imply nothing exists');
});

test('REVIEW ruling: an explicit --run ignores an UNRELATED corrupt sibling record', async () => {
  // Deliberate ruling (stated in the module, pinned here): the explicit `--run <id>` path only
  // ever inspects the ONE filename it was asked for. A different run's corrupt record is
  // irrelevant to answering "render THIS named run" — refusing over a file nobody asked about
  // would be its own false alarm. This pins TODAY's behaviour so a future change to this
  // function is forced to make the ruling explicit rather than drift into it either way.
  const outRoot = tmp(), wanted = newRunId(), corrupt = newRunId();
  await writeRunStart(outRoot, { ...BASE, runId: wanted, startedAt: '2026-08-26T09:14:00.000Z',
    hostsRequested: ['10.0.0.7'] });
  writeHostDir(outRoot, 'd-wanted', wanted);
  await appendHostWritten(outRoot, wanted, { host: '10.0.0.7', dir: 'd-wanted' });
  await finalizeRunRecord(outRoot, wanted, { finishedAt: '2026-08-26T09:31:00.000Z' });
  fs.mkdirSync(runRecordPath(outRoot, corrupt), { recursive: true });

  const r = await loadRun(outRoot, { runId: wanted });
  assert.equal(r.ok, true, 'a NAMED run that itself parses fine must render regardless of an unrelated sibling');
  assert.equal(r.model.runId, wanted);
});

test('plugin status counts sum across hosts, and byHost carries the per-host manifest', async () => {
  const outRoot = tmp(), runId = newRunId();
  await writeRunStart(outRoot, { ...BASE, runId, startedAt: '2026-08-26T09:14:00.000Z',
    hostsRequested: ['10.0.0.7', '10.0.0.8'] });
  writeHostDir(outRoot, 'd7', runId, { pluginStatus: [
    { id: '010', name: 'port_scanner', status: 'ran', reason: null },
    { id: '040', name: 'tls_cert_auditor', status: 'error', reason: 'boom' },
  ] });
  writeHostDir(outRoot, 'd8', runId, { pluginStatus: [
    { id: '010', name: 'port_scanner', status: 'skipped', reason: 'no scope' },
    { id: '040', name: 'tls_cert_auditor', status: 'timeout', reason: 'slow' },
  ] });
  await appendHostWritten(outRoot, runId, { host: '10.0.0.7', dir: 'd7' });
  await appendHostWritten(outRoot, runId, { host: '10.0.0.8', dir: 'd8' });
  await finalizeRunRecord(outRoot, runId, { finishedAt: '2026-08-26T09:31:00.000Z' });
  const r = await loadRun(outRoot, {});
  assert.equal(r.ok, true);
  assert.equal(r.model.plugins.ran, 1);
  assert.equal(r.model.plugins.skipped, 1);
  assert.equal(r.model.plugins.errored, 1);
  assert.equal(r.model.plugins.timedOut, 1);
  assert.equal(r.model.plugins.byHost.length, 2);
  const d7 = r.model.plugins.byHost.find((h) => h.host === '10.0.0.7');
  assert.ok(Array.isArray(d7.status));
  assert.equal(d7.status.length, 2);
});

// CC-2 (producer side): two DIRECTORIES sharing one host name (`--host 10.0.0.7,10.0.0.7`, a
// repeated --host-file line — utils/host_iterator.mjs de-duplicates neither) must still be
// distinguishable downstream. `dir` is what the renderer keys on (executive_report.mjs's
// renderAppendix) precisely because `host` alone cannot tell the two apart here.
test('CC-2: plugins.byHost carries `dir` alongside `host`, distinguishing two same-named directories', async () => {
  const outRoot = tmp(), runId = newRunId();
  await writeRunStart(outRoot, { ...BASE, runId, startedAt: '2026-08-26T09:14:00.000Z',
    hostsRequested: ['10.0.0.7', '10.0.0.7'] });
  writeHostDir(outRoot, 'dupA', runId, { pluginStatus: [
    { id: '900', name: 'Plugin One', status: 'ran', reason: null },
  ] });
  writeHostDir(outRoot, 'dupB', runId, { pluginStatus: [
    { id: '901', name: 'Plugin Two', status: 'ran', reason: null },
  ] });
  await appendHostWritten(outRoot, runId, { host: '10.0.0.7', dir: 'dupA' });
  await appendHostWritten(outRoot, runId, { host: '10.0.0.7', dir: 'dupB' });
  await finalizeRunRecord(outRoot, runId, { finishedAt: '2026-08-26T09:31:00.000Z' });
  const r = await loadRun(outRoot, {});
  assert.equal(r.ok, true);
  assert.equal(r.model.plugins.byHost.length, 2, 'both same-named directories must produce their own entry');
  const dirs = r.model.plugins.byHost.map((h) => h.dir).sort();
  assert.deepEqual(dirs, ['dupA', 'dupB'], 'each entry must carry its OWN directory, not just the shared host name');
  const byDir = new Map(r.model.plugins.byHost.map((h) => [h.dir, h.status[0]?.name]));
  assert.equal(byDir.get('dupA'), 'Plugin One');
  assert.equal(byDir.get('dupB'), 'Plugin Two');
  // model.hosts must ALSO stay per-directory — this is what lets the renderer use each host
  // entry's own `findings` directly instead of re-deriving them by (collision-prone) name.
  assert.equal(r.model.hosts.length, 2);
  assert.deepEqual(r.model.hosts.map((h) => h.dir).sort(), ['dupA', 'dupB']);
});

test('kev/epss flags pass through honestly; CE carries kevLoaded:false with no synthesised snapshot', async () => {
  const outRoot = tmp(), runId = newRunId();
  await writeRunStart(outRoot, { ...BASE, runId, startedAt: '2026-08-26T09:14:00.000Z',
    hostsRequested: ['10.0.0.7'], kevLoaded: false, kevSnapshot: null, epssLoaded: false, epssSnapshot: null });
  writeHostDir(outRoot, 'd7', runId);
  await appendHostWritten(outRoot, runId, { host: '10.0.0.7', dir: 'd7' });
  await finalizeRunRecord(outRoot, runId, { finishedAt: '2026-08-26T09:31:00.000Z' });
  const r = await loadRun(outRoot, {});
  assert.equal(r.ok, true);
  assert.equal(r.model.kev.loaded, false);
  assert.equal(r.model.kev.snapshot, null);
  assert.equal(r.model.epss.loaded, false);
  assert.equal(r.model.epss.snapshot, null);
});

test('an --allow-partial render of an INCOMPLETE run carries the caveat rather than reading as clean', async () => {
  const outRoot = tmp(), runId = newRunId();
  await writeRunStart(outRoot, { ...BASE, runId, startedAt: '2026-08-26T09:14:00.000Z',
    hostsRequested: ['10.0.0.7'] });
  writeHostDir(outRoot, 'd7', runId);
  await appendHostWritten(outRoot, runId, { host: '10.0.0.7', dir: 'd7' });
  // never finalized
  const r = await loadRun(outRoot, { allowPartial: true });
  assert.equal(r.ok, true);
  assert.equal(r.model.finishedAt, null);
  assert.equal(r.model.coverage.incomplete, true,
    'the model must say this run never recorded completion, not just render silently');
});

test('the older-format refusal states the fact and names BOTH possible causes, never asserts one', async () => {
  const outRoot = tmp();
  fs.mkdirSync(path.join(outRoot, 'legacy'), { recursive: true });
  fs.writeFileSync(path.join(outRoot, 'legacy', 'scan_conclusion_raw.json'),
    JSON.stringify({ results: [] }), 'utf8');
  const r = await loadRun(outRoot, {});
  assert.equal(r.reason, 'older-format');
  // Must not assert a single cause ("an old version") — CTEM watch mode deliberately writes no
  // record too, and both are real possibilities this module cannot distinguish from a bare raw.
  assert.match(r.message, /CTEM/);
  assert.match(r.message, /predates run records|before run records/);
});

test('an explicit --run for a runId that genuinely does not exist is refused, not misread as unreadable', async () => {
  const outRoot = tmp();
  const r = await loadRun(outRoot, { runId: 'nonexistent-run-id' });
  assert.equal(r.ok, false);
  assert.notEqual(r.reason, 'record-unreadable');
});

test('an out-root with nothing scanned in it at all is refused without crashing', async () => {
  const outRoot = tmp();
  const r = await loadRun(outRoot, {});
  assert.equal(r.ok, false);
  assert.equal(typeof r.message, 'string');
});

// ── Review round 1, item 2: the REVERSE two-way binding direction has no fixture. The forward
//    direction (record lists a dir whose raw names a DIFFERENT run) is the required test above.
//    The reverse — a raw on disk claiming THIS run, that the record's hostsWritten does NOT list
//    — was traced by the reviewer as failing SAFE: the arithmetic only reads what hostsWritten
//    declares, so a stray directory is invisible rather than credited. This pins that CURRENT
//    behaviour (safety, not detection) so a future change to the host-loop arithmetic is forced
//    to notice it is removing a safety property, not just refactoring dead code. ──

test('REVIEW: a stray directory claiming THIS run but unlisted in hostsWritten is never credited', async () => {
  const outRoot = tmp(), runId = newRunId();
  await writeRunStart(outRoot, { ...BASE, runId, startedAt: '2026-08-26T09:14:00.000Z',
    hostsRequested: ['10.0.0.7'] });
  writeHostDir(outRoot, 'd7', runId);
  await appendHostWritten(outRoot, runId, { host: '10.0.0.7', dir: 'd7' });
  // A SECOND directory whose raw claims the SAME runId, but which nothing ever appended to the
  // record via appendHostWritten — e.g. a directory copied in from a re-run of the same target,
  // or written by a process that crashed before recording it. Built with fs directly because
  // there is no writer API for scan_conclusion_raw.json (only run_record.mjs's own file has one).
  fs.mkdirSync(path.join(outRoot, 'd-stray'), { recursive: true });
  fs.writeFileSync(path.join(outRoot, 'd-stray', 'scan_conclusion_raw.json'), JSON.stringify({
    runId, pluginStatus: [{ id: '010', name: 'port_scanner', status: 'ran', reason: null }],
    results: [{ id: '010', name: 'port_scanner', result: { up: true,
      findings: [{ severity: 'CRITICAL', title: 'should never be counted', port: 1 }] } }],
  }), 'utf8');
  await finalizeRunRecord(outRoot, runId, { finishedAt: '2026-08-26T09:31:00.000Z' });

  const r = await loadRun(outRoot, {});
  assert.equal(r.ok, true);
  assert.equal(r.model.coverage.requested, 1);
  assert.equal(r.model.coverage.written, 1, 'the stray directory must not inflate written count');
  assert.equal(r.model.hosts.length, 1, 'the stray directory must not appear in hosts');
  assert.ok(!r.model.hosts.some((h) => h.dir === 'd-stray'), 'the stray dir must not be present at all');
  assert.equal(r.model.findings.length, 0,
    'the stray directory\'s finding must never reach the model — pinning fail-SAFE, not detection');
});

// ── Review round 1, item 3: the binding-mismatch catch's wording ("has no readable
//    scan_conclusion_raw.json") is loose rather than false — it also fires on a JSON syntax
//    error in a perfectly READABLE file, which "no readable X" does not honestly describe. ──

test('REVIEW: binding-mismatch wording covers malformed JSON honestly, not just a missing file', async () => {
  const outRoot = tmp(), runId = newRunId();
  await writeRunStart(outRoot, { ...BASE, runId, startedAt: '2026-08-26T09:14:00.000Z',
    hostsRequested: ['10.0.0.7'] });
  fs.mkdirSync(path.join(outRoot, 'd7'), { recursive: true });
  // Readable bytes, invalid JSON — NOT a missing/unreadable file.
  fs.writeFileSync(path.join(outRoot, 'd7', 'scan_conclusion_raw.json'), '{not valid json', 'utf8');
  await appendHostWritten(outRoot, runId, { host: '10.0.0.7', dir: 'd7' });
  await finalizeRunRecord(outRoot, runId, { finishedAt: '2026-08-26T09:31:00.000Z' });

  const r = await loadRun(outRoot, {});
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'binding-mismatch');
  assert.match(r.message, /could not be read or parsed as valid JSON/);
  assert.ok(!/has no readable/i.test(r.message), 'the file WAS readable — only its JSON was invalid');
});
