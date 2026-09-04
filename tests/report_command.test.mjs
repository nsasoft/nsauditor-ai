// tests/report_command.test.mjs — the Pro-gated `report` subcommand.
//
// Two legs, per the task constraints: (a) THROUGH THE CLI, where `NSAUDITOR_LICENSE_KEY` is
// ALWAYS passed explicitly (never omitted to mean CE — the resolver falls through to the macOS
// Keychain and reads the developer's installed licence, which renders here and refuses on CI —
// a verdict that depends on who runs it); (b) AT THE HANDLER, where `resolveCapabilities('pro')`
// reaches Pro directly, because `runReport(args, caps)` takes `caps` as an argument for exactly
// that reason — an env override inside the handler would be a licence bypass in product code.
//
// ⚠️ `writeHostDir` is duplicated here rather than imported from `tests/report_inputs.test.mjs`
// or lifted into a shared `tests/_run_fixtures.mjs`. The plan (progress.md R3) suggested sharing
// it, but this task's own scope constraint is narrower: "Touch only cli.mjs,
// utils/capabilities.mjs, and your test file" — another implementer may share this checkout.
// Creating a shared file or editing Task 4's test file would violate that, so the helper is
// duplicated verbatim instead (it is a small, stable fixture shape).

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

import {
  newRunId, writeRunStart, appendHostWritten, finalizeRunRecord, runRecordPath,
} from '../utils/run_record.mjs';
import { resolveCapabilities } from '../utils/capabilities.mjs';
import { JIRA_COLUMNS } from '../utils/jira_export.mjs';
import { runReport } from '../cli.mjs';

// ── Duplicated from tests/report_inputs.test.mjs (Task 4) — see header note above. ─────────────
function writeHostDir(outRoot, dir, runId, { up = true, findings = [], pluginStatus = null } = {}) {
  fs.mkdirSync(path.join(outRoot, dir), { recursive: true });
  fs.writeFileSync(path.join(outRoot, dir, 'scan_conclusion_raw.json'), JSON.stringify({
    runId, pluginStatus: pluginStatus ?? [{ id: '010', name: 'port_scanner', status: 'ran', reason: null }],
    results: [{ id: '010', name: 'port_scanner', result: { up, findings } }],
  }), 'utf8');
}

// ── Fixture helpers — built with the REAL writer, never by hand (per the task brief). ──────────

async function completeRunFixture({ findings = [{ severity: 'HIGH', title: 'Weak TLS', port: 443 }] } = {}) {
  const outRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-rc-'));
  const runId = newRunId();
  await writeRunStart(outRoot, { runId, startedAt: '2026-08-26T09:14:00.000Z',
    hostsRequested: ['10.0.0.7'], pluginsRequested: ['port_scanner'], portsRequested: '443',
    tier: 'pro', ceVersion: '0.2.50', eeVersion: '0.43.0',
    kevLoaded: true, kevSnapshot: '2026-08-20', epssLoaded: true, epssSnapshot: '2026-08-20' });
  writeHostDir(outRoot, 'd7', runId, { up: true, findings });
  await appendHostWritten(outRoot, runId, { host: '10.0.0.7', dir: 'd7' });
  await finalizeRunRecord(outRoot, runId, { finishedAt: '2026-08-26T09:31:00.000Z' });
  return outRoot;
}

// 1 of 2 hosts written, run FINALIZED — the partial-hosts shape, not the interrupted one.
async function partialRunFixture() {
  const outRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-rp-'));
  const runId = newRunId();
  await writeRunStart(outRoot, { runId, startedAt: '2026-08-26T09:14:00.000Z',
    hostsRequested: ['10.0.0.7', '10.0.0.9'], pluginsRequested: ['port_scanner'],
    portsRequested: '443', tier: 'pro', ceVersion: '0.2.50', eeVersion: '0.43.0',
    kevLoaded: true, kevSnapshot: '2026-08-20', epssLoaded: true, epssSnapshot: '2026-08-20' });
  writeHostDir(outRoot, 'd7', runId, { up: true, findings: [] });
  await appendHostWritten(outRoot, runId, { host: '10.0.0.7', dir: 'd7' });
  await finalizeRunRecord(outRoot, runId, { finishedAt: '2026-08-26T09:31:00.000Z' });
  return outRoot;
}

// ── Extra fixtures, built for the adversarial legs below — same real-writer discipline. ────────

// 1 host written, NEVER finalized — the genuinely-interrupted shape (distinct from partialRunFixture,
// which finalizes with a host deficit). Exercises `model.coverage.incomplete`.
async function incompleteRunFixture() {
  const outRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-ric-'));
  const runId = newRunId();
  await writeRunStart(outRoot, { runId, startedAt: '2026-08-26T09:14:00.000Z',
    hostsRequested: ['10.0.0.7'], pluginsRequested: ['port_scanner'], portsRequested: '443',
    tier: 'pro', ceVersion: '0.2.50', eeVersion: '0.43.0',
    kevLoaded: true, kevSnapshot: '2026-08-20', epssLoaded: true, epssSnapshot: '2026-08-20' });
  writeHostDir(outRoot, 'd7', runId, { up: true, findings: [] });
  await appendHostWritten(outRoot, runId, { host: '10.0.0.7', dir: 'd7' });
  // deliberately never finalized
  return outRoot;
}

// BOTH a host deficit AND never finalized — proves both caveats surface together, not just
// whichever one an `if`/`else if` chain happens to check first.
async function partialAndIncompleteRunFixture() {
  const outRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-rpi-'));
  const runId = newRunId();
  await writeRunStart(outRoot, { runId, startedAt: '2026-08-26T09:14:00.000Z',
    hostsRequested: ['10.0.0.7', '10.0.0.9'], pluginsRequested: ['port_scanner'],
    portsRequested: '443', tier: 'pro', ceVersion: '0.2.50', eeVersion: '0.43.0',
    kevLoaded: true, kevSnapshot: '2026-08-20', epssLoaded: true, epssSnapshot: '2026-08-20' });
  writeHostDir(outRoot, 'd7', runId, { up: true, findings: [] });
  await appendHostWritten(outRoot, runId, { host: '10.0.0.7', dir: 'd7' });
  // 10.0.0.9 never written, AND never finalized.
  return outRoot;
}

// Two unparseable `--host` inputs collapse to the SAME sentinel in hostsRequested; one written
// unparseable row must not read as "covering" every unparseable request (see report_inputs.mjs's
// own `computeMissing`). This is the fixture for the authoritative-count check below.
async function unparseableDeficitRunFixture() {
  const outRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-rup-'));
  const runId = newRunId();
  await writeRunStart(outRoot, { runId, startedAt: '2026-08-26T09:14:00.000Z',
    hostsRequested: ['bad$host-one', 'bad$host-two'], pluginsRequested: ['port_scanner'],
    portsRequested: '443', tier: 'pro', ceVersion: '0.2.50', eeVersion: '0.43.0',
    kevLoaded: true, kevSnapshot: '2026-08-20', epssLoaded: true, epssSnapshot: '2026-08-20' });
  writeHostDir(outRoot, 'd1', runId);
  await appendHostWritten(outRoot, runId, { host: 'bad$host-three', dir: 'd1' }); // also unparseable
  await finalizeRunRecord(outRoot, runId, { finishedAt: '2026-08-26T09:31:00.000Z' });
  return outRoot;
}

// Reads the runId back from the ARTIFACT the writer produced, rather than threading it through a
// second return value — the same "measure the artifact" discipline the fixtures above already
// follow for everything else.
function findRunId(outRoot) {
  const hit = fs.readdirSync(outRoot).map((f) => /^scan_run_(.+)\.json$/.exec(f)).find(Boolean);
  if (!hit) throw new Error(`no run record found under ${outRoot}`);
  return hit[1];
}

// Spawns the published bin so the CLI legs travel the real dispatch path.
// `key` is REQUIRED — EXPIRED_KEY for the CE leg, PRO_KEY for the Pro legs. No "no key" option,
// on purpose: see licEnv's warning.
async function runCli(argv, key) {
  // ⚠️ THE THROW IS THE ENFORCEMENT — the signature is not. JavaScript has no required positional
  // argument, and `spawnSync` DROPS an env entry whose value is `undefined`: measured, a child
  // spawned with `{ NSAUDITOR_LICENSE_KEY: undefined }` reports the variable ABSENT, not empty.
  // Absent means the resolver falls through to the macOS Keychain — Enterprise on a developer
  // machine, CE on CI. So forgetting this one argument silently restores the machine-dependent
  // verdict this helper exists to remove, and it reads green. An empty string is rejected too:
  // it IS passed through (measured present-but-empty) and the resolver treats it as no key.
  if (typeof key !== 'string' || key === '') {
    throw new TypeError('runCli needs an explicit licence key: omitting it reads the operator keychain');
  }
  const bin = new URL('../bin/nsauditor-ai.mjs', import.meta.url).pathname;
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-cli-'));
  const r = spawnSync(process.execPath, [bin, ...argv], { encoding: 'utf8', env: licEnv(key, tmp) });
  return { code: r.status, stdout: r.stdout, stderr: r.stderr };
}

// ── Pre-signed tokens, lifted from tests/license.test.mjs. They verify against the SHIPPED
// public key, so no private key exists at test time and nothing is bypassed.
// ⚠️ VALID_PRO_KEY expires 2036-04-11. When that nears, RE-MINT the fixture; never delete the test.
const LIC = fs.readFileSync(new URL('./license.test.mjs', import.meta.url), 'utf8');
const PRO_KEY = LIC.match(/VALID_PRO_KEY\s*=\s*'([^']+)'/)[1];
const EXPIRED_KEY = LIC.match(/EXPIRED_PRO_KEY\s*=\s*'([^']+)'/)[1];

// ⚠️ TWO DIFFERENT PROTECTIONS, and neither substitutes for the other. These isolation vars are
// what make the EXPIRED and VALID fixtures DETERMINISTIC. They do NOT make an OMITTED key
// deterministic — that is the throw's job in runCli above.
// ⚠️ A KEY IS ALWAYS PASSED. Omitting it does NOT mean CE: measured on a developer machine, the
// resolver reads the macOS Keychain and returns Enterprise, so an absence-based CE test refuses on
// CI and RENDERS here — a verdict that depends on who runs it. EXPIRED_KEY gives a deterministic
// CE on every machine, because the env key is first in the resolution chain.
function licEnv(key, tmp) {
  return { ...process.env, NSAUDITOR_LICENSE_KEY: key,
    XDG_CONFIG_HOME: path.join(tmp, 'nonexistent'),
    NSAUDITOR_LICENSE_STATE_FILE: path.join(tmp, 'lic-state.json'),
    NSAUDITOR_LICENSE_REVOCATIONS_FILE: path.join(tmp, 'lic-revocations.json'),
    NSAUDITOR_LICENSE_ID_REPLAY_DEFENSE: '0' };
}

// ── (a) THROUGH THE CLI — both tiers, each with its own token. ──────────────────────────────────

test('runCli REFUSES to run without an explicit key — absence must never mean CE', async () => {
  // Fourth quadrant first: the correct call works, THEN the omission throws by name. Without the
  // first leg, a runCli hardwired to throw would pass this test.
  const outRoot = await completeRunFixture();
  await runCli(['report', '--from', outRoot, '--format', 'executive'], EXPIRED_KEY);
  await assert.rejects(() => runCli(['report', '--from', outRoot, '--format', 'executive']),
    /explicit licence key/, 'a forgotten key was silently allowed to read the keychain');
});

test('CE is refused BY NAME, non-zero, and writes NO file', async () => {
  const outRoot = await completeRunFixture();
  const dest = path.join(outRoot, 'report.html');
  const { code, stderr } = await runCli(['report', '--from', outRoot, '--format', 'executive', '--out', dest], EXPIRED_KEY);
  assert.equal(code, 2, 'an entitlement problem is a fix-the-request code');
  assert.match(stderr, /Pro/);
  assert.match(stderr, /\bce\b/, 'the refusal must NAME the resolved tier, not just the required one');
  assert.equal(fs.existsSync(dest), false, 'a refused run must not leave a degraded artifact');
});

test('a malformed request is refused IDENTICALLY on CE — flags are validated BEFORE the tier gate', async () => {
  // This is why the ordering matters: if the capability gate ran first, every flag error on CE
  // would be reported as a tier problem, and no flag validation would be testable at all.
  const outRoot = await completeRunFixture();
  const bad = await runCli(['report', '--from', outRoot, '--format', 'nonsense'], EXPIRED_KEY);
  assert.equal(bad.code, 2);
  assert.match(bad.stderr, /--format executive/);
  assert.ok(!/Pro/.test(bad.stderr), 'a bad flag was reported as a tier problem');

  const mismatch = await runCli(['report', '--from', outRoot, '--format', 'jira', '--brand', 'brand.json'], EXPIRED_KEY);
  assert.equal(mismatch.code, 2);
  assert.match(mismatch.stderr, /--brand/);
  assert.match(mismatch.stderr, /jira/i);
  // A flag that quietly does nothing is how an operator concludes a subject was resolved.
});

test('CLI END TO END: a real Pro key renders through the full dispatch path and writes the file', async () => {
  // The six tests above and below prove the HANDLER; this proves the WIRING — arg parsing,
  // getTierFromEnv()/resolveCapabilities() at the real dispatch site, and the actual write —
  // with nothing stubbed.
  const outRoot = await completeRunFixture();
  const dest = path.join(outRoot, 'exec-report.html');
  const { code, stdout } = await runCli(['report', '--from', outRoot, '--format', 'executive', '--out', dest], PRO_KEY);
  assert.equal(code, 0);
  assert.match(stdout, /runId/);
  assert.ok(fs.existsSync(dest), 'the CLI dispatch must actually write the file, not just report success');
  const html = fs.readFileSync(dest, 'utf8');
  assert.match(html, /Weak TLS/, 'the rendered file must carry the finding, not just exist');
});

// ── (b) AT THE HANDLER, where Pro IS reachable — `resolveCapabilities('pro')` is how CE's own
// suite has always reached Pro (tests/capabilities.test.mjs:14). The handler takes caps as an
// argument for exactly this reason; an env override would be a licence bypass in product code.

const PRO = resolveCapabilities('pro');
const CE = resolveCapabilities('ce');

test('Pro renders, exits 0, and PRINTS the subject it chose', async () => {
  const outRoot = await completeRunFixture();
  const r = await runReport({ from: outRoot, format: 'executive' }, PRO);
  assert.equal(r.code, 0);
  assert.match(r.stdout, /runId/);
  assert.match(r.stdout, /started/);
  // A correct report about the wrong run reads identically to a correct one without this line.
});

test('zero findings RENDERS and exits 0', async () => {
  const outRoot = await completeRunFixture({ findings: [] });
  const r = await runReport({ from: outRoot, format: 'executive' }, PRO);
  assert.equal(r.code, 0, 'the exit code must not encode whether findings exist');
});

test('a caveated render is exit 0 with a machine-readable coverage line', async () => {
  const outRoot = await partialRunFixture();          // 1 of 2 hosts written
  const r = await runReport({ from: outRoot, format: 'executive', allowPartial: true }, PRO);
  assert.equal(r.code, 0);
  assert.match(r.stdout, /\[report\] coverage: partial — 1 of 2 not scanned/);
});

test('a run that cannot be reported is 1; a run that is not there is 2', async () => {
  const partial = await partialRunFixture();
  assert.equal((await runReport({ from: partial, format: 'executive' }, PRO)).code, 1,
    'fix-the-RUN problems are 1');
  const empty = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-empty-'));
  assert.equal((await runReport({ from: empty, format: 'executive' }, PRO)).code, 2,
    'nothing under --from is a fix-the-COMMAND problem');
});

test('the default output lands beside the run record, named for the run, and a re-render overwrites it', async () => {
  const outRoot = await completeRunFixture();
  await runReport({ from: outRoot, format: 'executive' }, PRO);
  await runReport({ from: outRoot, format: 'executive' }, PRO);
  const files = fs.readdirSync(outRoot).filter((f) => /^report_.*\.html$/.test(f));
  assert.equal(files.length, 1,
    'a re-render must not leave two files and no way to tell which is current');
});

// ── ADVERSARIAL — beyond the brief's six, per the task's own instruction to spend real effort
// on flag combinations and paths the brief does not enumerate. ─────────────────────────────────

test('ADVERSARIAL: handler-level CE caps refuse clientReporting, by name — the unit leg', async () => {
  const outRoot = await completeRunFixture();
  const r = await runReport({ from: outRoot, format: 'executive' }, CE);
  assert.equal(r.code, 2);
  assert.match(r.stderr, /Pro/);
  assert.match(r.stderr, /\bce\b/);
  assert.equal(r.stdout, '', 'a refused request must print nothing to stdout');
});

test('ADVERSARIAL: no --from at all is refused (2), naming the flag', async () => {
  const r = await runReport({ format: 'executive' }, PRO);
  assert.equal(r.code, 2);
  assert.match(r.stderr, /--from/);
});

test('ADVERSARIAL: no --format at all is refused (2), same message as an unrecognised one', async () => {
  const outRoot = await completeRunFixture();
  const r = await runReport({ from: outRoot }, PRO);
  assert.equal(r.code, 2);
  assert.match(r.stderr, /--format executive/);
});

test('ADVERSARIAL: --from naming a FILE, not a directory, is refused as a command problem (2), not a crash', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-file-'));
  const notADir = path.join(dir, 'not-a-directory.txt');
  fs.writeFileSync(notADir, 'not a directory', 'utf8');
  const r = await runReport({ from: notADir, format: 'executive' }, PRO);
  assert.equal(r.code, 2, 'a --from that names a file, not a directory, must refuse cleanly, not throw');
});

test('ADVERSARIAL: --out naming an existing DIRECTORY is a write failure, refused as 2, names the path', async () => {
  const outRoot = await completeRunFixture();
  const destDir = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-outdir-'));
  const r = await runReport({ from: outRoot, format: 'executive', out: destDir }, PRO);
  assert.equal(r.code, 2);
  assert.ok(r.stderr.includes(destDir), 'the refusal must name the actual path that could not be written');
});

test('ADVERSARIAL: --out inside a nonexistent parent directory is a write failure, refused as 2', async () => {
  const outRoot = await completeRunFixture();
  const dest = path.join(outRoot, 'does', 'not', 'exist', 'report.html');
  const r = await runReport({ from: outRoot, format: 'executive', out: dest }, PRO);
  assert.equal(r.code, 2);
  assert.equal(fs.existsSync(dest), false);
});

test('ADVERSARIAL: --run naming the SAME run present under --from renders normally', async () => {
  const outRoot = await completeRunFixture();
  const runId = findRunId(outRoot);
  const r = await runReport({ from: outRoot, format: 'executive', run: runId }, PRO);
  assert.equal(r.code, 0);
  assert.ok(r.stdout.includes(runId));
});

test('ADVERSARIAL: --run naming a run that genuinely does not exist is refused as 2 (a command problem)', async () => {
  const outRoot = await completeRunFixture();
  const r = await runReport({ from: outRoot, format: 'executive', run: 'totally-bogus-run-id' }, PRO);
  assert.equal(r.code, 2);
});

// ── Exhaustive-switch coverage. Constraint 5 requires the ten `loadRun` reasons to be mapped by
// an EXHAUSTIVE switch, not an if/else — the six tests above and below exercise `partial-hosts`,
// `incomplete-run` and `no-run` already; these fill in the remaining reasons so a mutant that
// reclassifies any ONE case is caught by name, not just by an aggregate pass/fail count.

test('ADVERSARIAL: a present-but-unreadable run record is a command problem (2), not a run problem', async () => {
  const outRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-unreadable-'));
  const runId = newRunId();
  fs.mkdirSync(runRecordPath(outRoot, runId), { recursive: true }); // a DIR where the record FILE belongs
  writeHostDir(outRoot, 'd7', runId);
  const r = await runReport({ from: outRoot, format: 'executive' }, PRO);
  assert.equal(r.code, 2, 'record-unreadable is a command/environment problem, mapped to 2');
});

test('ADVERSARIAL: an ambiguous tie between two runs is a run problem (1)', async () => {
  const outRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-ambiguous-'));
  const at = '2026-08-26T09:14:00.000Z';
  for (const runId of [newRunId(), newRunId()]) {
    await writeRunStart(outRoot, { runId, startedAt: at, hostsRequested: ['10.0.0.7'],
      pluginsRequested: ['port_scanner'], portsRequested: '443', tier: 'pro',
      ceVersion: '0.2.50', eeVersion: '0.43.0', kevLoaded: true, kevSnapshot: '2026-08-20',
      epssLoaded: true, epssSnapshot: '2026-08-20' });
    writeHostDir(outRoot, `d-${runId}`, runId);
    await appendHostWritten(outRoot, runId, { host: '10.0.0.7', dir: `d-${runId}` });
    await finalizeRunRecord(outRoot, runId, { finishedAt: at });
  }
  const r = await runReport({ from: outRoot, format: 'executive' }, PRO);
  assert.equal(r.code, 1, 'ambiguous-run is resolved by re-running with --run, mapped to 1');
});

test('ADVERSARIAL: an older-format run (no run record written at all) is a run problem (1)', async () => {
  const outRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-olderformat-'));
  fs.mkdirSync(path.join(outRoot, 'legacy'), { recursive: true });
  fs.writeFileSync(path.join(outRoot, 'legacy', 'scan_conclusion_raw.json'),
    JSON.stringify({ results: [] }), 'utf8');
  const r = await runReport({ from: outRoot, format: 'executive' }, PRO);
  assert.equal(r.code, 1);
});

test('ADVERSARIAL: a two-way binding mismatch (directory from another engagement) is a run problem (1)', async () => {
  const outRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-mismatch-'));
  const runId = newRunId();
  await writeRunStart(outRoot, { runId, startedAt: '2026-08-26T09:14:00.000Z',
    hostsRequested: ['10.0.0.7'], pluginsRequested: ['port_scanner'], portsRequested: '443',
    tier: 'pro', ceVersion: '0.2.50', eeVersion: '0.43.0', kevLoaded: true,
    kevSnapshot: '2026-08-20', epssLoaded: true, epssSnapshot: '2026-08-20' });
  writeHostDir(outRoot, 'd7', 'A-DIFFERENT-RUN');
  await appendHostWritten(outRoot, runId, { host: '10.0.0.7', dir: 'd7' });
  await finalizeRunRecord(outRoot, runId, { finishedAt: '2026-08-26T09:31:00.000Z' });
  const r = await runReport({ from: outRoot, format: 'executive' }, PRO);
  assert.equal(r.code, 1);
});

test('ADVERSARIAL: an unknown schema is a run problem (1)', async () => {
  const outRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-schema-'));
  const runId = newRunId();
  await writeRunStart(outRoot, { runId, startedAt: '2026-08-26T09:14:00.000Z',
    hostsRequested: ['10.0.0.7'], pluginsRequested: ['port_scanner'], portsRequested: '443',
    tier: 'pro', ceVersion: '0.2.50', eeVersion: '0.43.0', kevLoaded: true,
    kevSnapshot: '2026-08-20', epssLoaded: true, epssSnapshot: '2026-08-20' });
  const p = runRecordPath(outRoot, runId);
  const rec = JSON.parse(fs.readFileSync(p, 'utf8'));
  rec.schema = 99;
  fs.writeFileSync(p, JSON.stringify(rec), 'utf8');
  const r = await runReport({ from: outRoot, format: 'executive' }, PRO);
  assert.equal(r.code, 1);
});

test('ADVERSARIAL: record absent, raw INSIDE the retention window (deleted/moved) is a run problem (1)', async () => {
  const outRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-absent-in-'));
  writeHostDir(outRoot, 'd7', 'run-abc');
  const r = await runReport({ from: outRoot, format: 'executive' }, PRO);
  assert.equal(r.code, 1);
});

test('ADVERSARIAL: record absent, raw OUTSIDE the retention window is a run problem (1)', async () => {
  const outRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-absent-out-'));
  writeHostDir(outRoot, 'd7', 'run-abc');
  const old = new Date(Date.now() - 40 * 86_400_000);
  fs.utimesSync(path.join(outRoot, 'd7', 'scan_conclusion_raw.json'), old, old);
  const r = await runReport({ from: outRoot, format: 'executive' }, PRO);
  assert.equal(r.code, 1);
});

test('ADVERSARIAL: an incomplete (never-finalized) run without --allow-partial is refused as 1', async () => {
  const outRoot = await incompleteRunFixture();
  const r = await runReport({ from: outRoot, format: 'executive' }, PRO);
  assert.equal(r.code, 1);
});

test('ADVERSARIAL: --allow-partial on an incomplete run renders and prints the incomplete caveat', async () => {
  const outRoot = await incompleteRunFixture();
  const r = await runReport({ from: outRoot, format: 'executive', allowPartial: true }, PRO);
  assert.equal(r.code, 0);
  assert.match(r.stdout, /\[report\] coverage: incomplete — the run did not record completion/);
});

test('ADVERSARIAL: a run that is BOTH partial and incomplete discloses BOTH caveats, not just one', async () => {
  // report_inputs.mjs can produce both flags true at once (a host deficit AND no finishedAt).
  // An if/else-if chain over the two would silently drop whichever caveat it checks second —
  // exactly the "operator concludes the wrong thing from what they see" failure this task warns
  // about. Both must print.
  const outRoot = await partialAndIncompleteRunFixture();
  const r = await runReport({ from: outRoot, format: 'executive', allowPartial: true }, PRO);
  assert.equal(r.code, 0);
  assert.match(r.stdout, /\[report\] coverage: partial — 1 of 2 not scanned/);
  assert.match(r.stdout, /\[report\] coverage: incomplete — the run did not record completion/);
});

test('ADVERSARIAL: an unparseable-host deficit is counted, not silently read as zero, in the coverage line', async () => {
  // model.coverage.missing is the NAMED-missing list only; an unparseable deficit is counted but
  // never named (report_inputs.mjs's own computeMissing/describeMissing split). A coverage line
  // built from `coverage.missing.length` alone would print "0 of 2 not scanned" here — true-
  // looking and false. `requested - written` is the authoritative count regardless of whether
  // the deficit can be named (see the "Notes carried from tasks you consume" in the brief).
  const outRoot = await unparseableDeficitRunFixture();
  const r = await runReport({ from: outRoot, format: 'executive', allowPartial: true }, PRO);
  assert.equal(r.code, 0);
  assert.match(r.stdout, /\[report\] coverage: partial — 1 of 2 not scanned/);
});

test('ADVERSARIAL: --format jira writes a Jira-importer-shaped CSV, and a NAMED --run selects it', async () => {
  const outRoot = await completeRunFixture();
  const runId = findRunId(outRoot);
  const dest = path.join(outRoot, 'export.csv');
  const r = await runReport({ from: outRoot, format: 'jira', run: runId, out: dest }, PRO);
  assert.equal(r.code, 0);
  const csv = fs.readFileSync(dest, 'utf8');
  assert.equal(csv.split('\n')[0], JIRA_COLUMNS.join(','),
    'the header row must use Jira CSV importer column names, derived from the real export module');
  assert.match(csv, /Weak TLS/);
});

test('ADVERSARIAL: a --brand file that fails to load is refused (2), naming the reason, writes NO file', async () => {
  const outRoot = await completeRunFixture();
  const brandDir = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-brand-'));
  const brandPath = path.join(brandDir, 'brand.json');
  fs.writeFileSync(brandPath, JSON.stringify({ logoPath: 'logo.svg' }), 'utf8');
  fs.writeFileSync(path.join(brandDir, 'logo.svg'), '<svg></svg>', 'utf8');
  const dest = path.join(outRoot, 'branded.html');
  const r = await runReport({ from: outRoot, format: 'executive', brand: brandPath, out: dest }, PRO);
  assert.equal(r.code, 2);
  assert.match(r.stderr, /SVG/);
  assert.equal(fs.existsSync(dest), false);
});

test('ADVERSARIAL: a nonexistent --brand path is refused (2), not silently rendered unbranded', async () => {
  const outRoot = await completeRunFixture();
  const r = await runReport({ from: outRoot, format: 'executive', brand: '/nonexistent/dir/brand.json' }, PRO);
  assert.equal(r.code, 2);
  assert.match(r.stderr, /Could not read the brand file/);
});
