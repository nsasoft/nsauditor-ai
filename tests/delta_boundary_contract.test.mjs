// THE BOUNDARY-COMPLETENESS GUARD.
//
// ⚠️ THREE FIELDS WERE DROPPED AT ONE SEAM BEFORE THIS EXISTED, and each was invisible to the
// delta's own tests because every fixture was hand-built with the field present:
//   `resource` — twelve buckets collapsed to one identity; a NEW exposure reported nowhere.
//   `plugin`   — every comparison fell to plugin-not-run: never wrong, entirely useless.
//   `control`  — FAIL-OPEN: a finding whose control left the enumeration read as RESOLVED.
// Three at one boundary is a class, not a coincidence. This guard derives BOTH sides — what the
// delta reads and what the real loader emits — so the fourth instance fails by name.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { loadRun } from '../utils/report_inputs.mjs';
import { newRunId, writeRunStart, appendHostWritten, finalizeRunRecord, readRunRecord } from '../utils/run_record.mjs';
import { CONSUMED_FINDING_FIELDS, OUTPUT_ONLY_FINDING_FIELDS, DECLARED_ABSENT_FINDING_FIELDS,
  FRAMEWORK_MOVEMENT_NOT_EVALUATED, buildScanDelta } from '../utils/scan_delta.mjs';

// EMITTED is MEASURED by driving the real loader, never read from its source — the whole class
// came from the source and the consumer disagreeing.
async function emittedFields() {
  const outRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-bc-'));
  const runId = newRunId();
  await writeRunStart(outRoot, { runId, startedAt: '2026-09-01T10:00:00.000Z', hostsRequested: ['10.0.0.7'],
    pluginsRequested: ['010'], tier: 'pro', ceVersion: '0.2.54', eeVersion: '1.0.0' });
  fs.mkdirSync(path.join(outRoot, 'd1'), { recursive: true });
  fs.writeFileSync(path.join(outRoot, 'd1', 'scan_conclusion_raw.json'), JSON.stringify({
    runId, pluginStatus: [{ id: '010', name: 'aws-s3', status: 'ran', reason: null }],
    results: [{ id: '010', name: 'aws-s3', result: { up: true,
      findings: [{ severity: 'HIGH', title: 'No public access block configured', port: 443, resource: 'bucket-a' }] } }],
  }), 'utf8');
  await appendHostWritten(outRoot, runId, { host: '10.0.0.7', dir: 'd1' });
  await finalizeRunRecord(outRoot, runId, { finishedAt: '2026-09-01T11:00:00.000Z' });
  const loaded = await loadRun(outRoot, { runId, allowPartial: false }, { tier: 'pro' });
  assert.equal(loaded.ok, true, loaded.message);
  return new Set(Object.keys(loaded.model.findings[0]));
}

test('every field the delta CONSUMES is one the real loader EMITS — or is declared absent WITH its disclosure', async () => {
  const emitted = await emittedFields();
  const missing = CONSUMED_FINDING_FIELDS.filter((f) => !emitted.has(f));
  for (const f of missing) {
    const declared = DECLARED_ABSENT_FINDING_FIELDS[f];
    assert.ok(declared, `the delta reads \`${f}\` and the loader does not emit it. Either thread it `
      + 'through report_inputs.mjs, or declare it absent WITH the limit that discloses the gap — '
      + 'silently reading a field nobody produces is how resource, plugin and control each shipped.');
    assert.ok(declared.reason && declared.disclosedBy, `\`${f}\` is declared absent with no reason or disclosure`);
  }
});

test('a declared-absent field’s DISCLOSURE is actually emitted — the carve-out premise is checked, not trusted', () => {
  // A carve-out whose premise nobody verifies is how an absence becomes a silent pass. `control`
  // claims to be disclosed by FRAMEWORK_MOVEMENT_NOT_EVALUATED; this drives the engine and looks.
  assert.equal(DECLARED_ABSENT_FINDING_FIELDS.control.disclosedBy, 'FRAMEWORK_MOVEMENT_NOT_EVALUATED');
  const rec = { schema: 1, runId: 'R', startedAt: 'x', hostsRequested: ['h'], hostsWritten: [],
    pluginsRequested: ['p'], eeVersion: '1.0.0' };
  const d = buildScanDelta({ baseline: { record: rec, findings: [] }, current: { record: { ...rec, runId: 'S' }, findings: [] } });
  assert.ok(d.limits.includes(FRAMEWORK_MOVEMENT_NOT_EVALUATED),
    'the limit that excuses the missing field must actually reach the output');
});

test('the CONSUMED declaration matches what the module actually reads — it cannot rot', () => {
  // DERIVED from source: every `f.<field>` the module reads, minus the fields it WRITES onto its
  // own output records. If a new leg reads a new field, this fails until the declaration follows.
  const src = fs.readFileSync(new URL('../utils/scan_delta.mjs', import.meta.url), 'utf8');
  const body = src.slice(src.indexOf('const keyOf'));
  const read = new Set([...body.matchAll(/\bf\.([a-zA-Z_]\w*)/g)].map((m) => m[1]));
  for (const o of OUTPUT_ONLY_FINDING_FIELDS) read.delete(o);
  assert.deepEqual([...read].sort(), [...CONSUMED_FINDING_FIELDS].sort(),
    'CONSUMED_FINDING_FIELDS no longer matches the fields this module reads');
});

// ── THE VALUE-DOMAIN LEG. The three tests above check that a consumed field is PRESENT; none of
// them checks that its VALUE lives in the same vocabulary as the thing it is compared against.
// That gap is the fourth instance of the class this file was built for, and it is the widest:
// `cli.mjs` writes `pluginsRequested` as plugin IDs (`String(p.id)`) while `report_inputs.mjs`
// stamped `finding.plugin` from the envelope's DISPLAY NAME, so `scan_delta.mjs`'s
// `theirs.plugins.has(f.plugin)` was false on EVERY real record and every disappeared or appeared
// finding bucketed `plugin-not-run` with a sentence that is false about the run.
//
// ⚠️ MEASURED ON THE REAL CORPUS before this leg was written, because a fixture cannot establish
// what a real record looks like: across 152 real run records, `pluginsRequested` holds 7,962
// members and NOT ONE fails /^\d{3,4}$/ — there is no display name anywhere. Across 253 real
// `scan_conclusion_raw.json` files, `results[]` holds 2,182 entries carrying both `id` and `name`
// and `id === name` in ZERO of them. So the two vocabularies never overlap by accident, and every
// CE fixture that spelled a record's `pluginsRequested` in the NAME vocabulary was describing a
// record the shipped CLI has never written.
const REAL_ENVELOPE_ID = '003';
const REAL_ENVELOPE_NAME = 'Port Scanner';

async function loadOneRun(writeRaw, { pluginsRequested }) {
  const outRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-vocab-'));
  const runId = newRunId();
  await writeRunStart(outRoot, { runId, startedAt: '2026-09-01T10:00:00.000Z', hostsRequested: ['192.168.1.1'],
    pluginsRequested, tier: 'pro', ceVersion: '0.2.55', eeVersion: '1.1.0' });
  fs.mkdirSync(path.join(outRoot, 'h'), { recursive: true });
  writeRaw(path.join(outRoot, 'h'), runId);
  await appendHostWritten(outRoot, runId, { host: '192.168.1.1', dir: 'h' });
  await finalizeRunRecord(outRoot, runId, { finishedAt: '2026-09-01T11:00:00.000Z' });
  const loaded = await loadRun(outRoot, { runId, allowPartial: false }, { tier: 'pro' });
  assert.equal(loaded.ok, true, loaded.message);
  return { loaded, rec: await readRunRecord(outRoot, runId) };
}

test('finding.plugin is a MEMBER of record.pluginsRequested through the REAL loader with REAL shapes', async () => {
  const { loaded, rec } = await loadOneRun((dir, runId) => {
    fs.writeFileSync(path.join(dir, 'scan_conclusion_raw.json'), JSON.stringify({
      runId,
      pluginStatus: [{ id: REAL_ENVELOPE_ID, name: REAL_ENVELOPE_NAME, status: 'ran', reason: null }],
      results: [{ id: REAL_ENVELOPE_ID, name: REAL_ENVELOPE_NAME,
        result: { up: true, findings: [{ severity: 'HIGH', title: 'Telnet service exposed', port: 23 }] } }],
    }), 'utf8');
  }, { pluginsRequested: [REAL_ENVELOPE_ID] });

  const f = loaded.model.findings[0];
  assert.ok(rec.pluginsRequested.includes(f.plugin),
    `finding.plugin "${f.plugin}" is not in pluginsRequested ${JSON.stringify(rec.pluginsRequested)} — `
    + "the delta's plugin-scope check can never match on a real record");
});

// ⚠️ IDENTITY AND DISPLAY ARE TWO FIELDS, and this leg is why. `scan_delta.mjs` interpolates the
// producing plugin into the `plugin-not-run` DETAIL, `scan_delta_view.mjs` prints that on stdout,
// and `executive_report.mjs` renders it into the CLIENT HTML's basis cell. Stamping the id alone
// would put "plugin 003 did not run in the other run" in a branded deliverable — a repair that
// fixes the comparison and degrades the artifact it exists to serve.
test('the loader emits BOTH a comparable identity and a human-readable name for the producing plugin', async () => {
  const { loaded } = await loadOneRun((dir, runId) => {
    fs.writeFileSync(path.join(dir, 'scan_conclusion_raw.json'), JSON.stringify({
      runId,
      pluginStatus: [{ id: REAL_ENVELOPE_ID, name: REAL_ENVELOPE_NAME, status: 'ran', reason: null }],
      results: [{ id: REAL_ENVELOPE_ID, name: REAL_ENVELOPE_NAME,
        result: { up: true, findings: [{ severity: 'HIGH', title: 'Telnet service exposed', port: 23 }] } }],
    }), 'utf8');
  }, { pluginsRequested: [REAL_ENVELOPE_ID] });

  const f = loaded.model.findings[0];
  assert.equal(f.plugin, REAL_ENVELOPE_ID, 'plugin carries the ID, which is the vocabulary the record can be checked against');
  assert.equal(f.pluginName, REAL_ENVELOPE_NAME, 'pluginName carries the display name, which is what a client reads');
});

// ⚠️ ALL FIVE PRODUCERS, because a repair applied to the producer that was FOUND is not applied to
// the class. `shapeHostFindings` has FOUR `shapeFinding` call sites and only one of them ever
// received a plugin; `shapeQueueEntry` emitted no `plugin` key at all. MEASURED on the real
// 1.1.0 network run: of that host's 52 findings, the stamping branch produced ZERO — 7 came from
// the 060 category dict, 4 from 1023's zeroTrust, 4 from 040's portResults and 37 from the
// finding queue. A one-branch repair would have moved the AWS run from 0/198 to 198/198 and left
// the network run at 0/52.
test('EVERY container the loader reads stamps a producer identity — all five, not just findings[]', async () => {
  const { loaded, rec } = await loadOneRun((dir, runId) => {
    fs.writeFileSync(path.join(dir, 'scan_conclusion_raw.json'), JSON.stringify({
      runId,
      pluginStatus: [
        { id: '003', name: 'Port Scanner', status: 'ran', reason: null },
        { id: '060', name: 'DNS Security Auditor', status: 'ran', reason: null },
        { id: '1023', name: 'Zero Trust Assessment', status: 'ran', reason: null },
        { id: '040', name: 'TLS Certificate & Cipher Auditor', status: 'ran', reason: null },
      ],
      results: [
        { id: '003', name: 'Port Scanner', result: { up: true,
          findings: [{ severity: 'HIGH', title: 'Telnet service exposed', port: 23 }] } },
        { id: '060', name: 'DNS Security Auditor', result: { up: true,
          findings: { spf: [{ severity: 'MEDIUM', title: 'SPF record missing' }] } } },
        { id: '1023', name: 'Zero Trust Assessment', result: { up: true,
          zeroTrust: { identity: { findings: [{ severity: 'MEDIUM', description: 'No MFA on console access' }] } } } },
        { id: '040', name: 'TLS Certificate & Cipher Auditor', result: { up: true,
          portResults: [{ port: 443, issues: [{ severity: 'HIGH', title: 'Certificate expired' }] }] } },
      ],
    }), 'utf8');
    // The EE finding queue — a SIBLING artifact with its own vocabulary. Its real entries name
    // the producing ANALYSIS AGENT in `evidence.source` (measured across 350 real queue entries:
    // intelligence_engine 302 · crypto_agent 46 · exposure_agent 2) and carry no plugin id at all.
    fs.writeFileSync(path.join(dir, 'scan_finding_queue.json'), JSON.stringify([
      { id: 'F-0001', severity: 'HIGH', title: 'CVE-2020-25681 — dnsmasq 2.78',
        target: { port: 53 }, evidence: { source: 'intelligence_engine', cve: ['CVE-2020-25681'] } },
    ]), 'utf8');
  }, { pluginsRequested: ['003', '060', '1023', '040'] });

  const findings = loaded.model.findings;
  assert.equal(findings.length, 5, 'one finding from each of the five containers');
  for (const f of findings) {
    assert.ok(f.plugin != null, `a finding titled "${f.title}" reached the delta with no producer identity — `
      + 'it can never be compared, and "plugin null did not run in the other run" is false about the run');
    assert.ok(f.pluginName != null, `a finding titled "${f.title}" carries no producer name to render`);
  }
  const envelopeSourced = findings.filter((f) => f.plugin !== 'intelligence_engine');
  assert.equal(envelopeSourced.length, 4);
  for (const f of envelopeSourced) {
    assert.ok(rec.pluginsRequested.includes(f.plugin),
      `"${f.title}" is stamped ${f.plugin}, which is not in pluginsRequested ${JSON.stringify(rec.pluginsRequested)}`);
  }
  const queued = findings.find((f) => f.plugin === 'intelligence_engine');
  assert.ok(queued, 'the queue entry must carry its producing agent as its identity');
});
