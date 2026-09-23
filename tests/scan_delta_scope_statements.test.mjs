// A DECLARED SCOPE BOUNDARY IS NOT A FINDING — the delta sets it aside before pairing (EE 1.1.0 build 5).
//
// Seventeen Enterprise plugins emit one INFO row stating what they do NOT examine, flagged
// `details.deferredScope`. It routes to no control and is not an exposure, yet the delta paired it
// like one: a correction to its WORDING — which plugin 1110's own scope row needs this release, where
// it sold a downgrade that no longer fires — read as one finding RESOLVED and another NEW. It is now
// read into the run's scope as a STATEMENT, beside the gaps, and named in `coverage`, never paired.
// A row that carries BOTH flags is a GAP: "could not read" outranks "does not examine".
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { buildScanDelta } from '../utils/scan_delta.mjs';
import { writeRunStart, appendHostWritten, finalizeRunRecord, newRunId } from '../utils/run_record.mjs';
import { loadRun, shapeHostFindings } from '../utils/report_inputs.mjs';

const run = (id) => ({
  schema: 1, runId: id, startedAt: '2026-09-21T00:00:00Z', finishedAt: '2026-09-21T01:00:00Z',
  hostsRequested: ['aws'], hostsWritten: [{ host: 'aws', dir: 'd' }], pluginsRequested: ['1110', '1200'],
  portsRequested: null, tier: 'enterprise', ceVersion: '0.2.55', eeVersion: '1.1.0',
  kevLoaded: false, kevSnapshot: null, epssLoaded: false, epssSnapshot: null,
});
const row = (title, over = {}) => ({ host: 'aws', plugin: '1110', title, severity: 'info', resource: 'iam:scope', ...over });
const delta = (b, c) => buildScanDelta({
  baseline: { record: run('A'), findings: b, pluginStatus: [] },
  current: { record: run('B'), findings: c, pluginStatus: [] },
});
const OLD = 'IAM effective-decrypt scope: HIGH findings downgrade to INFO when no key trusts the principal';
const NEW = 'IAM effective-decrypt scope: the downgrade needs every region\'s keys; this release reads one';

// ── FOURTH QUADRANTS FIRST ───────────────────────────────────────────────────────────────────
test('an evidence-GAP row keeps its gap path — the new rule does not swallow it', () => {
  const gap = row('Evidence gap: ListKeys denied', { evidenceGap: true });
  const d = delta([gap], [gap]);
  assert.equal(d.coverage.gapsInBaseline.length, 1);
  assert.deepEqual(d.coverage.scopeStatementsInBaseline, []);
});

test('a row carrying BOTH flags is a GAP, not a statement', () => {
  const both = row('Evidence gap and scope', { evidenceGap: true, deferredScope: true });
  const d = delta([both], []);
  assert.equal(d.coverage.gapsInBaseline.length, 1, '"could not read" outranks "does not examine"');
  assert.deepEqual(d.coverage.scopeStatementsInBaseline, []);
  assert.equal(d.resolved.length, 0);
});

test('an ordinary finding still pairs: gone is resolved, arrived is new', () => {
  const d = delta([row('HIGH decrypt on *', { severity: 'high', resource: 'iam:user:a' })], [row('HIGH decrypt on *', { severity: 'high', resource: 'iam:user:b' })]);
  assert.equal(d.resolved.length, 1);
  assert.equal(d.newFindings.length, 1);
});

// ── THE DEFECT ───────────────────────────────────────────────────────────────────────────────
test('a REWORDED scope statement is neither resolved nor new — it is named as each run\'s statement', () => {
  const d = delta([row(OLD, { deferredScope: true })], [row(NEW, { deferredScope: true })]);
  assert.equal(d.resolved.length, 0, 'a boundary rewording read as a remediation');
  assert.equal(d.newFindings.length, 0, 'and as a new exposure');
  assert.deepEqual(d.coverage.scopeStatementsInBaseline, [{ host: 'aws', plugin: '1110', title: OLD }]);
  assert.deepEqual(d.coverage.scopeStatementsInCurrent, [{ host: 'aws', plugin: '1110', title: NEW }]);
});

test('THE REAL LOADER carries the flag from `details.deferredScope` — the delta sees what the producer wrote', async () => {
  const outRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-scope-stmt-'));
  try {
    const runId = newRunId();
    await writeRunStart(outRoot, { runId, startedAt: '2026-09-23T10:00:00.000Z', hostsRequested: ['aws'],
      pluginsRequested: ['1110'], tier: 'enterprise', ceVersion: '0.2.55', eeVersion: '1.1.0' });
    fs.mkdirSync(path.join(outRoot, 'd1'), { recursive: true });
    fs.writeFileSync(path.join(outRoot, 'd1', 'scan_conclusion_raw.json'), JSON.stringify({
      runId, pluginStatus: [{ id: '1110', name: 'x', status: 'ran', reason: null }],
      // ⚠️ The statement carries NO 1110 category and the ordinary row BORROWS 1110's scope
      // category without the marker (architect F2): a normaliser keyed on the category passed this
      // leg while the only statement carried it. The marker decides, never the category.
      results: [{ id: '1110', name: 'x', result: { up: true, findings: [
        { severity: 'INFO', title: OLD, resource: 'iam:scope', details: { category: 'some-other-producers-scope-row', deferredScope: true } },
        { severity: 'HIGH', title: 'decrypt on *', resource: 'iam:user:a', details: { category: 'x' } },
        { severity: 'INFO', title: 'borrows the name', resource: 'iam:scope', details: { category: 'iam-decrypt-scope-deferred-v1' } },
      ] } }],
    }));
    await appendHostWritten(outRoot, runId, { host: 'aws', dir: 'd1' });
    await finalizeRunRecord(outRoot, runId, { finishedAt: '2026-09-23T11:00:00.000Z' });
    const loaded = await loadRun(outRoot, { runId, allowPartial: false }, { tier: 'enterprise' });
    assert.equal(loaded.ok, true, loaded.message);
    // By TITLE, never a sorted flag list: a normaliser that flags the name-borrower INSTEAD of the
    // statement yields the same sorted [false, false, true] — found by the fold's own mutant.
    const flags = Object.fromEntries(loaded.model.findings.map((f) => [f.title, f.deferredScope]));
    assert.deepEqual(flags, { [OLD]: true, 'decrypt on *': false, 'borrows the name': false },
      'the statement is flagged; the ordinary finding and the name-borrower are findings');
  } finally { fs.rmSync(outRoot, { recursive: true, force: true }); }
});

// ── THE QUEUE PATH (architect F3) — shape parity with the envelope, pinned in BOTH directions ────
// No queue producer emits a boundary today (measured on the build-4 corpus), so this read was pinned
// by nothing: replaced by the constant `false` it survived every leg above. A queue entry declaring
// one must be set aside like an envelope row, and one that does not must still pair.
const qe = (title, raw) => ({ id: `F-${title}`, title, severity: 'LOW', evidence: { source: 'intelligence_engine', ...(raw ? { raw } : {}) } });
test('THE QUEUE — an entry with `evidence.raw.deferredScope: true` is set aside; one without it pairs', () => {
  const shaped = shapeHostFindings('aws', { results: [] }, [qe('queue boundary', { deferredScope: true }), qe('queue finding')]);
  assert.deepEqual(shaped.map((f) => [f.title, f.deferredScope]).sort(), [['queue boundary', true], ['queue finding', false]]);
  const d = delta(shaped, []);
  assert.deepEqual(d.coverage.scopeStatementsInBaseline.map((x) => x.title), ['queue boundary']);
  const paired = JSON.stringify([d.resolved, d.newFindings, d.notComparable ?? [], d.severityChanged ?? []]);
  assert.ok(paired.includes('queue finding'), 'the ordinary queue entry went through pairing');
  assert.ok(!paired.includes('queue boundary'), 'the declared boundary did not');
});

test('THE QUEUE — a boundary declared at the WRONG depth (top-level, or under `details`) is not read as one', () => {
  const shaped = shapeHostFindings('aws', { results: [] }, [
    { ...qe('top-level flag'), deferredScope: true },
    { ...qe('details flag'), details: { deferredScope: true } },
    qe('truthy but not true', { deferredScope: 'yes' }),
  ]);
  assert.deepEqual(shaped.map((f) => f.deferredScope), [false, false, false], 'the queue\'s vocabulary is evidence.raw, exactly true');
});
