// tests/report_cli_census_warning.test.mjs — the CLI's OPERATOR-FACING half of the container
// census, pinned through the published bin.
//
// WHAT WAS UNPINNED, MEASURED. The census has three surfaces and only two were guarded:
//   · the census itself            — utils/report_finding_census.mjs (its own tests)
//   · the census -> MODEL seam     — tests/report_multi_source_findings.test.mjs, which drives
//                                    the real loadRun and asserts `model.unreadContainers`
//   · the RENDERER's disclosure    — same file, over a hand-built model
// Nothing read the four `logErr`/`log` lines in cli.mjs's report path. Measured before writing
// this file: `grep -rn "finding-like object" tests/` returned three hits, all three in
// report_multi_source_findings.test.mjs and all three matching the RENDERER's caveat wording
// ("N recorded finding-like object(s) live in containers this report does not read") — not one
// matching the CLI's own "[report] WARNING: … on host …" line. The model shape was pinned; the
// warning built from it was not, so the whole loop could be deleted with the suite green.
//
// The two audiences are different and the split is deliberate (cli.mjs:1371-1380): the REPORT
// discloses to the customer, the WARNING tells the operator who ran the command. A guard over
// the artifact says nothing about the operator's channel.
//
// ⚠️ WHY EVERY LEG SPAWNS THE PUBLISHED BIN WITH AN EXPLICIT KEY, AND WHY OMITTING ONE WOULD
// MAKE THIS WHOLE FILE VACUOUS. `report` is gated on the Pro `clientReporting` capability. With
// NSAUDITOR_LICENSE_KEY absent the resolver falls through to the macOS Keychain
// (utils/license.mjs:155-162), so on this laptop the tier resolves ENTERPRISE and `report`
// runs, while on a machine with no keychain it resolves CE, `report` refuses at exit 2 before
// the census loop is ever reached — and EVERY assertion below about an ABSENT warning line
// passes over a run that never rendered anything. Green, asserting nothing, and green in the
// environment where it matters least. So the key is passed explicitly, and `runCli` THROWS
// rather than spawns if it is not a non-empty string: `spawnSync` silently DROPS an env value
// that is `undefined`, which reproduces the omitted-key case exactly while looking deliberate.
//
// Every leg also asserts the run SUCCEEDED (exit 0, an .html on disk) before asserting anything
// about warnings. A refused run prints no warning either.

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

import {
  newRunId, writeRunStart, appendHostWritten, finalizeRunRecord,
} from '../utils/run_record.mjs';

// ── Pre-signed tokens, lifted from tests/license.test.mjs (the technique
// tests/report_cli_liveness.test.mjs and tests/report_command.test.mjs already use). They verify
// against the SHIPPED public key, so no private key exists at test time and nothing is bypassed.
// ⚠️ VALID_PRO_KEY expires 2036-04-11; re-mint on approach, never delete.
const LIC = fs.readFileSync(new URL('./license.test.mjs', import.meta.url), 'utf8');
const PRO_KEY = LIC.match(/VALID_PRO_KEY\s*=\s*'([^']+)'/)?.[1];

// The extraction above is a REGEX OVER ANOTHER TEST FILE, so it fails by returning `undefined`
// — the exact shape that spawnSync then swallows. Fail at import time, loudly, naming the cause.
if (typeof PRO_KEY !== 'string' || PRO_KEY === '') {
  throw new Error('tests/license.test.mjs no longer exposes VALID_PRO_KEY — every leg in this '
    + 'file would silently fall back to the operator keychain and prove nothing');
}

// The CE arm, for Q0 below: a token that verifies against the shipped public key and is EXPIRED,
// so the refusal is deterministic rather than a property of whatever licence the machine holds.
const EXPIRED_KEY = LIC.match(/EXPIRED_PRO_KEY\s*=\s*'([^']+)'/)?.[1];
if (typeof EXPIRED_KEY !== 'string' || EXPIRED_KEY === '') {
  throw new Error('tests/license.test.mjs no longer exposes EXPIRED_PRO_KEY — Q0 would fall back '
    + 'to the operator keychain and could no longer prove the refusal path');
}

function licEnv(key, tmp) {
  return {
    ...process.env,
    NSAUDITOR_LICENSE_KEY: key,
    XDG_CONFIG_HOME: path.join(tmp, 'nonexistent'),
    NSAUDITOR_LICENSE_STATE_FILE: path.join(tmp, 'lic-state.json'),
    NSAUDITOR_LICENSE_REVOCATIONS_FILE: path.join(tmp, 'lic-revocations.json'),
    NSAUDITOR_LICENSE_ID_REPLAY_DEFENSE: '0',
  };
}

// Spawns the REAL published bin BY PATH, capturing the two streams SEPARATELY — which is the
// only way to assert that the warning lands on stderr rather than inside a redirected
// deliverable. An imported `runReport()` returns `{stdout, stderr}` as strings and would pin the
// handler's own bookkeeping, never what the process actually writes to fd 1 and fd 2.
function runCli(argv, key) {
  if (typeof key !== 'string' || key === '') {
    throw new TypeError('runCli needs an explicit licence key: `spawnSync` DROPS an undefined env '
      + 'value, so the child would read the operator keychain and the tier would become a '
      + 'property of the laptop rather than of this test');
  }
  const bin = new URL('../bin/nsauditor-ai.mjs', import.meta.url).pathname;
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-census-cli-'));
  const r = spawnSync(process.execPath, [bin, ...argv], { encoding: 'utf8', env: licEnv(key, tmp) });
  return { status: r.status, stdout: r.stdout, stderr: r.stderr };
}

// Built with the REAL run-record writers, never by hand — a hand-written record is a fixture
// for a format nobody ships. `results[]` is written verbatim so each leg states exactly which
// container its severity-bearing objects live in.
async function buildRun(hostSpecs) {
  const outRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-census-run-'));
  const runId = newRunId();
  await writeRunStart(outRoot, {
    runId,
    startedAt: '2026-09-05T09:00:00.000Z',
    hostsRequested: hostSpecs.map((h) => h.host),
    pluginsRequested: ['port_scanner'],
    portsRequested: '443',
    tier: 'pro',
    ceVersion: '0.2.51',
    eeVersion: '0.44.0',
    kevLoaded: false,
    kevSnapshot: null,
    epssLoaded: false,
    epssSnapshot: null,
  });
  for (const { host, dir, result } of hostSpecs) {
    fs.mkdirSync(path.join(outRoot, dir), { recursive: true });
    fs.writeFileSync(path.join(outRoot, dir, 'scan_conclusion_raw.json'), JSON.stringify({
      runId,
      pluginStatus: [{ id: '010', name: 'port_scanner', status: 'ran', reason: null }],
      results: [{ id: '010', name: 'port_scanner', result }],
    }), 'utf8');
    await appendHostWritten(outRoot, runId, { host, dir });
  }
  await finalizeRunRecord(outRoot, runId, { finishedAt: '2026-09-05T09:30:00.000Z' });
  return outRoot;
}

const CENSUS_WARNING_RE = /^\[report\] WARNING: .*finding-like object\(s\) on host /;
const censusWarnings = (stderr) => stderr.split('\n').filter((l) => CENSUS_WARNING_RE.test(l));

// A rendered run, asserted the same way in every leg: a refusal prints no warning either, so
// "no warning" is only a measurement once the render is known to have happened.
function assertRendered(r, outRoot) {
  assert.equal(r.status, 0, `bin exited ${r.status}: ${r.stderr}`);
  const f = fs.readdirSync(outRoot).find((x) => x.endsWith('.html'));
  assert.ok(f, 'the run must have RENDERED — an absent warning over a refused run proves nothing');
  return fs.readFileSync(path.join(outRoot, f), 'utf8');
}

// ─────────────────────────────────────────────────────────────────────────────
// Q0 — THE VACUITY MECHANISM ITSELF, PINNED.
//
// `assertRendered` is called by every leg below, and a leg's whole value rests on it. This
// pins WHY. Measured with the EXPIRED token over a fixture carrying a REAL unread container
// (one severity-bearing object in `auditResults[]`): exit 2, no .html on disk, and ZERO census
// warnings — refused at the capability gate 25 lines above the census loop, which never runs.
//
// So "no census warning" is not evidence about the loop unless the render is separately known
// to have happened. That is the precise shape a keychain-resolved tier would give this file in
// CI, and this leg is what makes the dependency explicit rather than a convention someone
// deletes as boilerplate.
// ─────────────────────────────────────────────────────────────────────────────
test('Q0 — a REFUSED run prints no census warning either, which is why every leg proves the render', async () => {
  const outRoot = await buildRun([{ host: '10.0.0.7', dir: 'd7', result: {
    up: true,
    findings: [],
    auditResults: [{ severity: 'high', detail: 'a real unread container, on a refused run' }],
  } }]);
  const r = runCli(['report', '--from', outRoot, '--format', 'executive'], EXPIRED_KEY);

  assert.equal(r.status, 2, `expected the capability refusal, got ${r.status}: ${r.stderr}`);
  assert.match(r.stderr, /`report` is a Pro capability/);
  assert.ok(!fs.readdirSync(outRoot).some((x) => x.endsWith('.html')), 'nothing may be written');
  assert.deepEqual(censusWarnings(r.stderr), [],
    'the census loop is never reached on a refusal — the SAME empty result Q1 asserts, from a '
    + 'run that measured nothing');
});

// ─────────────────────────────────────────────────────────────────────────────
// Q1 — THE FOURTH QUADRANT, WRITTEN FIRST. Silence when there is nothing to say.
//
// This is the leg that rots: every fixture born from the defect (an unread container exists)
// satisfies the positive legs below, so a mutant that emits the warning UNCONDITIONALLY passes
// Q2, Q3 and Q4 together and is caught here alone. It is also the leg most easily made vacuous
// — an empty census over a record with no severity-bearing objects at all would print no
// warning for a reason that has nothing to do with the loop — so the fixture carries a REAL
// severity-bearing finding and the leg proves it reached the deliverable.
// ─────────────────────────────────────────────────────────────────────────────
test('Q1 — a census with NO unread container prints NO warning (and the census had subjects)', async () => {
  const outRoot = await buildRun([{ host: '10.0.0.7', dir: 'd7', result: {
    up: true,
    // `result.findings[]` is a READ container (report_finding_census.mjs READ_CONTAINERS).
    findings: [{ severity: 'HIGH', title: 'Weak TLS on 443', port: 443 }],
  } }]);
  const r = runCli(['report', '--from', outRoot, '--format', 'executive'], PRO_KEY);
  const html = assertRendered(r, outRoot);

  // POSITIVE CONTROL FOR THE SILENCE: the census walked a real severity-bearing object and
  // classified it as READ. Without this, an empty `results[]` would satisfy the assertion below
  // while proving only that a census over nothing finds nothing.
  assert.match(html, /Weak TLS on 443/,
    'the fixture must carry a severity-bearing finding that REACHES the report — otherwise the '
    + 'absent warning is a property of an empty record, not of the loop');
  assert.doesNotMatch(html, /live in containers this report does not read/,
    "the renderer's own caveat must be absent too — both surfaces stay silent together");

  assert.deepEqual(censusWarnings(r.stderr), [],
    'a clean census must print no census warning at all');
});

// ─────────────────────────────────────────────────────────────────────────────
// Q2 — one unread container: EXACTLY one line, naming the container, the host and the count.
// ─────────────────────────────────────────────────────────────────────────────
test('Q2 — an unread container prints exactly ONE warning naming container, host and count', async () => {
  const outRoot = await buildRun([{ host: '10.0.0.7', dir: 'd7', result: {
    up: true,
    findings: [],
    // A producer inventing a container nobody reads — the shape the census exists for. Two
    // objects, so the COUNT in the message is discriminating: a hardcoded "1" fails here.
    auditResults: [
      { severity: 'high', detail: 'invented container, real finding' },
      { severity: 'low', detail: 'invented container, second finding' },
    ],
  } }]);
  const r = runCli(['report', '--from', outRoot, '--format', 'executive'], PRO_KEY);
  assertRendered(r, outRoot);

  const lines = censusWarnings(r.stderr);
  assert.equal(lines.length, 1, `expected exactly one warning, got ${lines.length}: ${r.stderr}`);
  assert.equal(lines[0],
    '[report] WARNING: 2 finding-like object(s) on host 10.0.0.7 live in '
    + '`UNCLASSIFIED:.auditResults[]`, which this report does not read. They are NOT in the output.',
    'the whole line is pinned, not a fragment of it: the count, the host and the container key '
    + 'are the three things an operator acts on, and a partial match lets any of them drift');
});

// ─────────────────────────────────────────────────────────────────────────────
// Q3 — two unread containers on ONE host: two lines, one per container.
//
// The loop is nested (`for (const u of unreadContainers) for (const [container, n] of ...)`),
// so a per-HOST rather than per-CONTAINER emission — the natural way to write it wrong — reports
// one line and drops a whole container. Only a multi-container host can see that.
// ─────────────────────────────────────────────────────────────────────────────
test('Q3 — two unread containers on one host print TWO warnings, one per container', async () => {
  const outRoot = await buildRun([{ host: '10.0.0.7', dir: 'd7', result: {
    up: true,
    findings: [],
    auditResults: [
      { severity: 'high', detail: 'first door' },
      { severity: 'low', detail: 'second door' },
    ],
    postureChecks: [{ severity: 'medium', detail: 'a different door' }],
  } }]);
  const r = runCli(['report', '--from', outRoot, '--format', 'executive'], PRO_KEY);
  assertRendered(r, outRoot);

  const lines = censusWarnings(r.stderr);
  assert.equal(lines.length, 2, `expected one line per container, got ${lines.length}: ${r.stderr}`);
  // Sorted, because the order follows the census walk's key insertion order, which is a property
  // of the record and not a contract this test should hold anyone to.
  assert.deepEqual(lines.slice().sort(), [
    '[report] WARNING: 1 finding-like object(s) on host 10.0.0.7 live in '
    + '`UNCLASSIFIED:.postureChecks[]`, which this report does not read. They are NOT in the output.',
    '[report] WARNING: 2 finding-like object(s) on host 10.0.0.7 live in '
    + '`UNCLASSIFIED:.auditResults[]`, which this report does not read. They are NOT in the output.',
  ].slice().sort());
});

// ─────────────────────────────────────────────────────────────────────────────
// Q4 — the STREAM, not just the text.
//
// `report --format executive` writes its deliverable to a file, but the operator-facing lines
// are split across both streams on purpose (cli.mjs: `log` -> stdout, `logErr` -> stderr). A
// warning that drifted to stdout would land inside anything a caller redirects — and would still
// satisfy every assertion above, all of which read one stream or the other without comparing
// them. This leg asserts BOTH directions over the SAME process.
// ─────────────────────────────────────────────────────────────────────────────
test('Q4 — the warning goes to STDERR, and stdout carries the ordinary report lines instead', async () => {
  const outRoot = await buildRun([{ host: '10.0.0.7', dir: 'd7', result: {
    up: true,
    findings: [],
    auditResults: [{ severity: 'high', detail: 'invented container, real finding' }],
  } }]);
  const r = runCli(['report', '--from', outRoot, '--format', 'executive'], PRO_KEY);
  assertRendered(r, outRoot);

  assert.equal(censusWarnings(r.stderr).length, 1, 'the warning must be on stderr');

  // ⚠️ THE NEGATIVE HALF IS VACUOUS OVER AN EMPTY STREAM. `doesNotMatch` on a stdout that
  // captured nothing passes whatever the code does, so stdout is first proven LIVE by the lines
  // that genuinely belong to it, and only then asserted to be free of the warning.
  assert.match(r.stdout, /^\[report\] wrote .*\.html$/m,
    'stdout must carry the ordinary `wrote` line — otherwise the absence below is a property of '
    + 'an empty capture, not of the stream the warning chose');
  assert.match(r.stdout, /^\[report\] runId /m);
  assert.doesNotMatch(r.stdout, /\[report\] WARNING:/,
    'the census warning must NOT reach stdout: a caller redirecting stdout would silently '
    + 'capture an operator warning into a deliverable');
});

// ─────────────────────────────────────────────────────────────────────────────
// Q5 — HOST ATTRIBUTION. Two hosts, one unread container each.
//
// Not in the brief, added because the brief's legs cannot see it: with one host in the fixture,
// `${u.host}` and `model.hosts[0].host` are indistinguishable, and a warning that names the
// wrong host sends an operator to open the wrong scan directory. Each line here must pair ITS
// OWN container with ITS OWN host.
// ─────────────────────────────────────────────────────────────────────────────
test('Q5 — each warning names the host the container is ON, not the first host in the run', async () => {
  const outRoot = await buildRun([
    { host: '10.0.0.7', dir: 'd7', result: {
      up: true, findings: [], auditResults: [{ severity: 'high', detail: 'on .7' }] } },
    { host: '10.0.0.8', dir: 'd8', result: {
      up: true,
      findings: [],
      postureChecks: [
        { severity: 'high', detail: 'on .8' },
        { severity: 'medium', detail: 'on .8' },
        { severity: 'low', detail: 'on .8' },
      ] } },
  ]);
  const r = runCli(['report', '--from', outRoot, '--format', 'executive'], PRO_KEY);
  assertRendered(r, outRoot);

  const lines = censusWarnings(r.stderr);
  assert.equal(lines.length, 2, `expected one line per host, got ${lines.length}: ${r.stderr}`);
  assert.deepEqual(lines.slice().sort(), [
    '[report] WARNING: 1 finding-like object(s) on host 10.0.0.7 live in '
    + '`UNCLASSIFIED:.auditResults[]`, which this report does not read. They are NOT in the output.',
    '[report] WARNING: 3 finding-like object(s) on host 10.0.0.8 live in '
    + '`UNCLASSIFIED:.postureChecks[]`, which this report does not read. They are NOT in the output.',
  ].slice().sort());
});

// ─────────────────────────────────────────────────────────────────────────────
// THE HARNESS'S OWN FOURTH QUADRANT.
//
// Every leg above is only worth its assertions while a real Pro key reaches the child. The guard
// that enforces that is itself a guard, so it gets a fixture: without this, deleting the `throw`
// in `runCli` leaves this entire file green in CI while proving nothing at all.
// ─────────────────────────────────────────────────────────────────────────────
test('the harness REFUSES to spawn without an explicit key, rather than reading the keychain', () => {
  for (const bad of [undefined, null, '', 0, {}]) {
    assert.throws(() => runCli(['report', '--from', '/nonexistent', '--format', 'executive'], bad),
      /needs an explicit licence key/,
      `runCli must refuse ${JSON.stringify(bad) ?? String(bad)} rather than spawn without a key`);
  }
});
