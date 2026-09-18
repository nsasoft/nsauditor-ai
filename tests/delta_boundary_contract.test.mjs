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
import { newRunId, writeRunStart, appendHostWritten, finalizeRunRecord } from '../utils/run_record.mjs';
import { CONSUMED_FINDING_FIELDS, OUTPUT_ONLY_FINDING_FIELDS, DECLARED_ABSENT_FINDING_FIELDS,
  FRAMEWORK_MOVEMENT_NOT_EVALUATED, buildScanDelta } from '../utils/scan_delta.mjs';

// EMITTED is MEASURED by driving the real loader, never read from its source — the whole class
// came from the source and the consumer disagreeing.
async function emittedFields() {
  const outRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-bc-'));
  const runId = newRunId();
  await writeRunStart(outRoot, { runId, startedAt: '2026-09-01T10:00:00.000Z', hostsRequested: ['10.0.0.7'],
    pluginsRequested: ['aws-s3'], tier: 'pro', ceVersion: '0.2.54', eeVersion: '1.0.0' });
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
