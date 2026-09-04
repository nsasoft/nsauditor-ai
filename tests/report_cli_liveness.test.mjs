// tests/report_cli_liveness.test.mjs — Task 9: liveness by path.
//
// tests/report_command.test.mjs (Task 8) already proves the handler's decision surface
// exhaustively, including a CLI end-to-end render. This file's narrower job, per the Task 9
// brief, is the three legs the brief names by name:
//   1. CE is refused THROUGH THE PUBLISHED BIN, deterministically (the EXPIRED token) — an
//      imported `main()` proves the function works, never that the subcommand is DISPATCHED.
//   2. Pro RENDERS through the published bin, and `egressViolations` runs over the REAL
//      rendered output on disk — not a fixture string built by the test.
//   3. A report rendered by the REAL renderer (driven at the handler level, where Pro is
//      reachable without a licence bypass) also satisfies the no-egress invariant.
//
// `egressViolations` is a regex over serialised HTML, not a parser (see its own header in
// utils/executive_report.mjs) — running it over bytes the real renderer actually wrote, via
// the real bin process, is the leg that covers what that stated limit cannot: a generator
// defect that only shows up in the ACTUAL serialisation, not in a hand-built test string.
//
// ⚠️ Per the task's own scope constraint, this file duplicates its fixture/CLI helpers rather
// than importing them from tests/report_command.test.mjs or lifting them into a shared file —
// another implementer may share this checkout, and this task touches only this new file.

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

import {
  newRunId, writeRunStart, appendHostWritten, finalizeRunRecord,
} from '../utils/run_record.mjs';
import { resolveCapabilities } from '../utils/capabilities.mjs';
import { egressViolations } from '../utils/executive_report.mjs';
import { runReport } from '../cli.mjs';

// ── Fixture helper — duplicated from tests/report_command.test.mjs (itself duplicated from
// tests/report_inputs.test.mjs), built with the REAL writer, never by hand. ────────────────────
function writeHostDir(outRoot, dir, runId, { up = true, findings = [], pluginStatus = null } = {}) {
  fs.mkdirSync(path.join(outRoot, dir), { recursive: true });
  fs.writeFileSync(path.join(outRoot, dir, 'scan_conclusion_raw.json'), JSON.stringify({
    runId, pluginStatus: pluginStatus ?? [{ id: '010', name: 'port_scanner', status: 'ran', reason: null }],
    results: [{ id: '010', name: 'port_scanner', result: { up, findings } }],
  }), 'utf8');
}

// TEST-QUALITY FIX 2: `cves` must be present here — a finding with no CVE never exercises the
// <a href="https://nvd.nist.gov/…"> exemption, the ONE place egressViolations' own invariant
// deliberately permits an external URL, over bytes the renderer actually wrote (as opposed to a
// hand-built fixture string in tests/executive_report.test.mjs). Without it, both tests below
// that assert `egressViolations(html) === []` would pass identically whether that exemption leg
// works or is silently broken.
async function completeRunFixture({ findings = [{ severity: 'HIGH', title: 'Weak TLS', port: 443,
  cves: ['CVE-2023-38408'] }] } = {}) {
  const outRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-live-'));
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

// ── Pre-signed tokens, lifted from tests/license.test.mjs (same technique report_command.test.mjs
// uses) — they verify against the SHIPPED public key, so no private key exists at test time and
// nothing is bypassed. ⚠️ VALID_PRO_KEY expires 2036-04-11; re-mint on approach, never delete.
const LIC = fs.readFileSync(new URL('./license.test.mjs', import.meta.url), 'utf8');
const PRO_KEY = LIC.match(/VALID_PRO_KEY\s*=\s*'([^']+)'/)[1];
const EXPIRED_KEY = LIC.match(/EXPIRED_PRO_KEY\s*=\s*'([^']+)'/)[1];

// ⚠️ A KEY IS ALWAYS PASSED — omitting it does NOT mean CE. Measured (see report_command.test.mjs):
// the resolver falls through to the macOS Keychain and returns the developer's installed licence
// when the env var is absent, making the verdict a property of the laptop, not the code.
function licEnv(key, tmp) {
  return { ...process.env, NSAUDITOR_LICENSE_KEY: key,
    XDG_CONFIG_HOME: path.join(tmp, 'nonexistent'),
    NSAUDITOR_LICENSE_STATE_FILE: path.join(tmp, 'lic-state.json'),
    NSAUDITOR_LICENSE_REVOCATIONS_FILE: path.join(tmp, 'lic-revocations.json'),
    NSAUDITOR_LICENSE_ID_REPLAY_DEFENSE: '0' };
}

// Spawns the REAL published bin BY PATH — not an import of `main()`. This is what proves the
// `report` subcommand is DISPATCHED, not merely that its handler function works in isolation.
function runCli(argv, key) {
  if (typeof key !== 'string' || key === '') {
    throw new TypeError('runCli needs an explicit licence key: omitting it reads the operator keychain');
  }
  const bin = new URL('../bin/nsauditor-ai.mjs', import.meta.url).pathname;
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-live-cli-'));
  const r = spawnSync(process.execPath, [bin, ...argv], { encoding: 'utf8', env: licEnv(key, tmp) });
  return { status: r.status, stdout: r.stdout, stderr: r.stderr };
}

test('CE is refused through the published bin — deterministically, via the EXPIRED token', async () => {
  const outRoot = await completeRunFixture();
  const r = runCli(['report', '--from', outRoot, '--format', 'executive'], EXPIRED_KEY);
  // The wiring claim: dispatch reached the `report` handler at all. "Unknown command" is what a
  // bin that never wired the subcommand would print for ANY argv naming it.
  assert.ok(!/Unknown command/.test(r.stderr), '`report` never reached its handler');
  assert.equal(r.status, 2);
  assert.match(r.stderr, /Pro/);
});

test('PRO RENDERS through the published bin, and the REAL output satisfies the invariant', async () => {
  const outRoot = await completeRunFixture();
  const r = runCli(['report', '--from', outRoot, '--format', 'executive'], PRO_KEY);
  assert.equal(r.status, 0, `bin exited ${r.status}: ${r.stderr}`);
  assert.match(r.stdout, /runId/);
  const f = fs.readdirSync(outRoot).find((x) => x.endsWith('.html'));
  assert.ok(f, 'the published bin must have written an .html file under --from');
  const html = fs.readFileSync(path.join(outRoot, f), 'utf8');
  // Proves the CVE exemption leg was actually EXERCISED here, not merely that egressViolations
  // returned [] (which would also be true if the CVE never reached the document at all).
  assert.match(html, /href="https:\/\/nvd\.nist\.gov\/vuln\/detail\/CVE-2023-38408"/,
    'the CVE citation link must reach the real rendered output, not just a hand-built fixture');
  assert.deepEqual(egressViolations(html), [], 'a REAL rendered report violated the invariant');
});

test('a report rendered by the REAL renderer satisfies the invariant', async () => {
  // Driven at the handler level, where Pro is reachable via resolveCapabilities('pro') without
  // an env override (an env override inside product code would be a licence bypass) — this leg
  // is what report_command.test.mjs's handler tests do NOT cover: running egressViolations over
  // bytes the renderer actually produced on disk, not a hand-built fixture string.
  const outRoot = await completeRunFixture();
  const r = await runReport({ from: outRoot, format: 'executive' }, resolveCapabilities('pro'));
  assert.equal(r.code, 0, `handler returned ${r.code}: ${r.stderr}`);
  const f = fs.readdirSync(outRoot).find((x) => x.endsWith('.html'));
  assert.ok(f, 'the handler must have written an .html file under --from');
  const html = fs.readFileSync(path.join(outRoot, f), 'utf8');
  assert.match(html, /href="https:\/\/nvd\.nist\.gov\/vuln\/detail\/CVE-2023-38408"/,
    'the CVE citation link must reach the real rendered output, not just a hand-built fixture');
  assert.deepEqual(egressViolations(html), [], 'a REAL rendered report violated the invariant');
});
