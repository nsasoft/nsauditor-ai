// AN ENTERPRISE STAGE THAT DID NOT RUN ON A HOST FIXED NOTHING THERE (1.1.1 — the audit seat's T1-c ruling, the delta half).
//
// When Enterprise fails to LOAD (utils/ee_load.mjs → `conclusion.result.eeLoadError`) or its enrichment THROWS
// (`conclusion.result.eeEnrichmentError`), the host's analysis agents and CVE mapper produce nothing in that scan. The
// run record still carries Enterprise's version (it is read from the package manifest, which resolves either way) and the
// same tier, so neither whole-comparison refusal fires — and before this leg every agent and engine row the other run
// held on that host read RESOLVED (or NEW, the other way). Both flags now ride from the persisted conclusion to the delta,
// and a queue-path row (an Enterprise producer) on a host where EITHER run carries one is NOT COMPARABLE — `evidence-gap`,
// the same reason an individual agent's not-run record carries; no new reason token. Community's plugins are untouched:
// a plugin's own status on the host governs its rows.
//
// FOURTH QUADRANT FIRST.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import * as SD from '../utils/scan_delta.mjs';
import * as RI from '../utils/report_inputs.mjs';
import { newRunId, writeRunStart, appendHostWritten, finalizeRunRecord, readRunRecord } from '../utils/run_record.mjs';

const { buildScanDelta, NOT_COMPARABLE_REASONS } = SD;
const HOST = '192.0.2.1';
const OTHER = '192.0.2.2';
const run = (id) => ({
  schema: 1, runId: id, startedAt: '2026-09-21T00:00:00Z', finishedAt: '2026-09-21T01:00:00Z',
  hostsRequested: [HOST, OTHER], hostsWritten: [{ host: HOST, dir: 'a' }, { host: OTHER, dir: 'b' }], pluginsRequested: ['003', '040'],
  portsRequested: null, tier: 'enterprise', ceVersion: '0.2.56', eeVersion: '1.1.1',
  kevLoaded: false, kevSnapshot: null, epssLoaded: false, epssSnapshot: null,
});
const agent = (title, plugin = 'crypto_agent', host = HOST) => ({ host, port: 21, protocol: 'tcp', severity: 'MEDIUM', title,
  evidenceGap: false, gapClass: null, plugin, pluginName: plugin, producerKind: 'agent' });
const pluginRow = (title) => ({ host: HOST, port: 443, protocol: 'tcp', severity: 'HIGH', title, evidenceGap: false, gapClass: null,
  plugin: '040', pluginName: 'TLS Certificate Auditor', producerKind: 'plugin' });
const hostStatus = (host, eeStage) => ({ host, dir: host === HOST ? 'a' : 'b', pluginStatusRecorded: true,
  status: [{ id: '003', status: 'ran' }, { id: '040', status: 'ran' }], portScan: { tcpOpen: [21, 443], tcpClosed: [] }, udpServices: [],
  ...(eeStage ? { eeStage } : {}) });
const side = (id, findings, stages = {}) => ({ record: run(id), findings,
  pluginStatus: [hostStatus(HOST, stages[HOST] ?? null), hostStatus(OTHER, stages[OTHER] ?? null)] });
const LOAD = { loadError: "The requested module 'nsauditor-ai/utils/scan_delta.mjs' does not provide an export named 'isUdpTransport'", enrichmentError: null };
const ENRICH = { loadError: null, enrichmentError: 'ENOSPC: no space left on device' };

test('eeStageOf reads BOTH flags from the persisted conclusion, and is null when Enterprise ran', () => {
  assert.equal(typeof RI.eeStageOf, 'function');
  assert.equal(RI.eeStageOf({ conclusion: { result: {} } }), null);
  assert.equal(RI.eeStageOf({}), null);
  assert.deepEqual(RI.eeStageOf({ conclusion: { result: { eeLoadError: 'x' } } }), { loadError: 'x', enrichmentError: null });
  assert.deepEqual(RI.eeStageOf({ conclusion: { result: { eeEnrichmentError: 'y' } } }), { loadError: null, enrichmentError: 'y' });
  assert.ok(!NOT_COMPARABLE_REASONS.some((r) => /ee-|enterprise/i.test(r) && r !== 'ee-presence-differs'), 'no new reason token');
});

// ── FOURTH QUADRANT FIRST ─────────────────────────────────────────────────────────────────────────────
test('(q1) Enterprise ran on both sides → an agent row that vanished reads RESOLVED, as today', () => {
  const d = buildScanDelta({ baseline: side('A', [agent('No transport encryption: ftp on port 21')]), current: side('B', []) });
  assert.equal(d.resolved.length, 1);
});

test('(q1) Enterprise failed on ANOTHER host → this host\'s agent row still reads RESOLVED (the rule is per host)', () => {
  const d = buildScanDelta({ baseline: side('A', [agent('No transport encryption: ftp on port 21')]), current: side('B', [], { [OTHER]: LOAD }) });
  assert.equal(d.resolved.length, 1);
});

test('(q1) a Community PLUGIN row on the failed host is untouched — its own plugin status governs it', () => {
  const d = buildScanDelta({ baseline: side('A', [pluginRow('Certificate expired')]), current: side('B', [], { [HOST]: LOAD }) });
  assert.equal(d.resolved.length, 1);
});

// ── THE DEFECT ────────────────────────────────────────────────────────────────────────────────────────
test('(a) Enterprise FAILED TO LOAD on the host now → the baseline\'s agent AND engine rows are NOT COMPARABLE (evidence-gap), never RESOLVED', () => {
  const base = [agent('No transport encryption: ftp on port 21'), agent('CVE-2023-38408 — tcp/ssh', 'intelligence_engine')];
  const d = buildScanDelta({ baseline: side('A', base), current: side('B', [], { [HOST]: LOAD }) });
  assert.equal(d.resolved.length, 0);
  assert.equal(d.notComparable.length, 2);
  for (const nc of d.notComparable) {
    assert.equal(nc.reason, 'evidence-gap');
    assert.equal(nc.direction, 'disappeared');
    assert.match(nc.detail, /Enterprise failed to load on 192\.0\.2\.1 in the other run/);
    assert.match(nc.detail, /isUdpTransport/, 'the recorded error is carried');
  }
});

test('(a) Enterprise\'s ENRICHMENT threw on the host now → the same refusal, and the detail says which stage', () => {
  const d = buildScanDelta({ baseline: side('A', [agent('No transport encryption: ftp on port 21')]), current: side('B', [], { [HOST]: ENRICH }) });
  assert.equal(d.resolved.length, 0);
  assert.match(d.notComparable[0]?.detail ?? '', /Enterprise failed during enrichment on 192\.0\.2\.1 in the other run/);
});

test('(a) the APPEARED direction: the BASELINE\'s Enterprise failed, an agent row appears now → not NEW', () => {
  const d = buildScanDelta({ baseline: side('A', [], { [HOST]: LOAD }), current: side('B', [agent('No transport encryption: ftp on port 21')]) });
  assert.equal(d.newFindings.length, 0);
  assert.equal(d.notComparable[0]?.reason, 'evidence-gap');
  assert.equal(d.notComparable[0]?.direction, 'appeared');
});

test('(a) the side HOLDING the row recorded the failure (a partial queue written before enrichment threw) → not RESOLVED either', () => {
  const d = buildScanDelta({ baseline: side('A', [agent('No transport encryption: ftp on port 21')], { [HOST]: ENRICH }), current: side('B', []) });
  assert.equal(d.resolved.length, 0);
  assert.match(d.notComparable[0]?.detail ?? '', /Enterprise failed during enrichment on 192\.0\.2\.1 in this run/);
});

// ── THROUGH THE LOADER: two sealed runs on disk, the flag read from the written raw ──────────────────────────
async function sealedRun(outRoot, dir, { conclusionResult = {}, queue = null, startedAt, finishedAt }) {
  const runId = newRunId();
  await writeRunStart(outRoot, { runId, startedAt, hostsRequested: [HOST], pluginsRequested: ['003'], tier: 'enterprise', ceVersion: '0.2.56', eeVersion: '1.1.1' });
  fs.mkdirSync(path.join(outRoot, dir), { recursive: true });
  fs.writeFileSync(path.join(outRoot, dir, 'scan_conclusion_raw.json'), JSON.stringify({
    runId, pluginStatus: [{ id: '003', name: 'Port Scanner', status: 'ran' }],
    results: [{ id: '003', name: 'Port Scanner', result: { up: true, tcpOpen: [21], tcpClosed: [] } }],
    conclusion: { result: { services: [], ...conclusionResult } } }), 'utf8');
  if (queue) fs.writeFileSync(path.join(outRoot, dir, 'scan_finding_queue.json'), JSON.stringify({ findings: queue }), 'utf8');
  await appendHostWritten(outRoot, runId, { host: HOST, dir });
  await finalizeRunRecord(outRoot, runId, { finishedAt });
  return runId;
}

test('THROUGH loadRun: a baseline crypto_agent row, and a current run whose raw records eeLoadError → NOT COMPARABLE, never RESOLVED', async () => {
  const outRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-eestage-'));
  try {
    const q = [{ category: 'CRYPTO', status: 'UNVERIFIED', severity: 'MEDIUM', title: 'No transport encryption: ftp on port 21',
      target: { host: HOST, port: 21, protocol: 'tcp', service: 'ftp' }, evidence: { source: 'crypto_agent', cve: [], mitre: [], raw: {} } }];
    const a = await sealedRun(outRoot, 'a', { queue: q, startedAt: '2026-09-21T00:00:00.000Z', finishedAt: '2026-09-21T00:10:00.000Z' });
    const b = await sealedRun(outRoot, 'b', { conclusionResult: { eeLoadError: LOAD.loadError }, startedAt: '2026-09-22T00:00:00.000Z', finishedAt: '2026-09-22T00:10:00.000Z' });
    const load = async (runId) => {
      const l = await RI.loadRun(outRoot, { runId, allowPartial: false }, { tier: 'enterprise' });
      return { record: await readRunRecord(outRoot, runId), findings: l.model.findings, pluginStatus: l.model.plugins.byHost, integrity: 'chain-verified' };
    };
    const cur = await load(b);
    assert.deepEqual(cur.pluginStatus[0].eeStage, { loadError: LOAD.loadError, enrichmentError: null }, 'the loader carries the flag');
    const d = buildScanDelta({ baseline: await load(a), current: cur });
    assert.equal(d.resolved.length, 0, 'an Enterprise that did not load fixed nothing');
    assert.equal(d.notComparable.find((n) => n.title === q[0].title)?.reason, 'evidence-gap');
  } finally { fs.rmSync(outRoot, { recursive: true, force: true }); }
});
