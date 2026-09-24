// A CLOUD PROVIDER IS ONE HOST, WHATEVER CASE IT WAS TYPED IN (census G6, the Community half).
//
// ⚠️ `--host AWS` WAS ACCEPTED AND RECORDED AS TYPED. The CLI lowercased the sentinel only for its own
// address check; `parseHostArg` returned `AWS`, the run record carried `AWS`, and the cross-run delta
// compares hosts by string — so a baseline scanned as `AWS` beside a current scanned as `aws` read every
// finding host-not-scanned. `canonicalHost` folds the three provider names at PARSE (every new record
// carries `aws`) and at every READ that compares hosts — the loader and the delta, which reads its host
// set and `scopeScanned` from the RAW record — because records already on disk still say `AWS`.
// A network host keeps its case IN THE RECORD; whether two runs saw the same host is answered by
// `hostKey`, which folds every host's case (DNS names are case-insensitive, RFC 4343).
// ⚠️ FOURTH QUADRANT FIRST: the network host that must NOT be folded is asserted before the provider that must.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { canonicalHost, hostKey } from '../utils/cloud_providers.mjs';
import { parseHostArg, parseHostFile } from '../utils/host_iterator.mjs';
import { loadRun } from '../utils/report_inputs.mjs';
import { buildScanDelta } from '../utils/scan_delta.mjs';
import { newRunId, writeRunStart, appendHostWritten, finalizeRunRecord, readRunRecord } from '../utils/run_record.mjs';

test('FOURTH QUADRANT — a network host, a near-miss and a non-string are returned UNCHANGED', () => {
  for (const h of ['MyHost.local', 'Server01.CORP', 'awss', 'aws-prod', '10.0.0.1']) assert.equal(canonicalHost(h), h);
  assert.equal(canonicalHost(undefined), undefined);
  assert.equal(canonicalHost(null), null);
});

test('the three provider names are folded to their own spelling, on an exact case-insensitive match', () => {
  assert.deepEqual(['AWS', 'Aws', ' Azure ', 'GCP', 'aws'].map(canonicalHost), ['aws', 'aws', 'azure', 'gcp', 'aws']);
});

test('PARSE — `--host AWS`, a mixed list and a host file each yield the provider spelling; a network host keeps its case', async () => {
  assert.deepEqual(await parseHostArg('AWS'), ['aws']);
  assert.deepEqual(await parseHostArg('Aws,AZURE,MyHost.local'), ['aws', 'azure', 'MyHost.local']);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-sentinel-'));
  try {
    const file = path.join(dir, 'hosts.txt');
    fs.writeFileSync(file, 'AWS\nServer01.corp\n# a comment\nGcp\n');
    assert.deepEqual(await parseHostFile(file), ['aws', 'Server01.corp', 'gcp']);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

/** One sealed run: `requested` as the record's hostsRequested, `written` as the host that wrote `dir`. */
const BUCKET_ROW = { severity: 'HIGH', title: 'Bucket without a public access block', resource: 's3:bucket:reports', region: 'us-east-1' };
// A finding only the CURRENT run has. Only an UNPAIRED finding consults the host set, `scopeScanned`
// and the host compare, so each pairing leg carries one — it must read NEW, never not-comparable.
const NEW_ROW = { severity: 'HIGH', title: 'Bucket without default encryption', resource: 's3:bucket:archive', region: 'us-east-1' };
async function oneRun(outRoot, { requested, written, dir, startedAt, finishedAt, scope, status = 'ran', findings = [BUCKET_ROW] }) {
  const runId = newRunId();
  await writeRunStart(outRoot, { runId, startedAt, hostsRequested: [requested], pluginsRequested: ['1020'],
    tier: 'enterprise', ceVersion: '0.2.55', eeVersion: '1.1.0' });
  fs.mkdirSync(path.join(outRoot, dir), { recursive: true });
  fs.writeFileSync(path.join(outRoot, dir, 'scan_conclusion_raw.json'), JSON.stringify({
    runId, pluginStatus: [{ id: '1020', name: 'aws-s3', status, reason: status === 'ran' ? null : 'socket hang up' }],
    results: [{ id: '1020', name: 'aws-s3', result: { up: true, findings } }],
  }), 'utf8');
  await appendHostWritten(outRoot, runId, { host: written, dir, ...(scope ? { scopeScanned: scope } : {}) });
  await finalizeRunRecord(outRoot, runId, { finishedAt });
  return runId;
}

test('RECORD — `AWS` requested through parse is recorded as `aws`, in hostsRequested and hostsWritten', async () => {
  const outRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-sentinel-rec-'));
  try {
    const [host] = await parseHostArg('AWS');
    const runId = await oneRun(outRoot, { requested: host, written: host, dir: 'aws_1',
      startedAt: '2026-09-23T10:00:00.000Z', finishedAt: '2026-09-23T10:05:00.000Z' });
    const rec = await readRunRecord(outRoot, runId);
    assert.deepEqual(rec.hostsRequested, ['aws']);
    assert.deepEqual(rec.hostsWritten.map((h) => h.host), ['aws']);
  } finally { fs.rmSync(outRoot, { recursive: true, force: true }); }
});

test('LOADER — a record written as `AWS` before the fold is READ as `aws`; a network host is read as recorded', async () => {
  const outRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-sentinel-load-'));
  try {
    const old = await oneRun(outRoot, { requested: 'AWS', written: 'AWS', dir: 'AWS_1',
      startedAt: '2026-09-20T10:00:00.000Z', finishedAt: '2026-09-20T10:05:00.000Z' });
    assert.deepEqual((await readRunRecord(outRoot, old)).hostsWritten.map((h) => h.host), ['AWS'], 'the fixture must be an OLD-shape record');
    const loaded = await loadRun(outRoot, { runId: old, allowPartial: false }, { tier: 'enterprise' });
    assert.equal(loaded.ok, true, loaded.message);
    assert.deepEqual(loaded.model.hosts.map((h) => h.host), ['aws']);
    assert.deepEqual([...new Set(loaded.model.findings.map((f) => f.host))], ['aws']);

    const net = await oneRun(outRoot, { requested: 'MyHost.local', written: 'MyHost.local', dir: 'MyHost.local_1',
      startedAt: '2026-09-21T10:00:00.000Z', finishedAt: '2026-09-21T10:05:00.000Z' });
    const n = await loadRun(outRoot, { runId: net, allowPartial: false }, { tier: 'enterprise' });
    assert.equal(n.ok, true, n.message);
    assert.deepEqual(n.model.hosts.map((h) => h.host), ['MyHost.local'], 'a network host keeps its case');
  } finally { fs.rmSync(outRoot, { recursive: true, force: true }); }
});

test('DELTA — an old-`AWS` baseline against a new-`aws` current PAIRS: nothing reads host-not-scanned', async () => {
  const outRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-sentinel-delta-'));
  try {
    // `appendHostWritten` keys the entry by the host itself — pass the ENTRY, never a host-keyed object.
    const scope = () => ({ unit: 'region', scanned: ['us-east-1'], byPlugin: { 1020: ['us-east-1'] } });
    const base = await oneRun(outRoot, { requested: 'AWS', written: 'AWS', dir: 'AWS_1', scope: scope('AWS'),
      startedAt: '2026-09-20T10:00:00.000Z', finishedAt: '2026-09-20T10:05:00.000Z' });
    const cur = await oneRun(outRoot, { requested: 'aws', written: 'aws', dir: 'aws_2', scope: scope('aws'),
      startedAt: '2026-09-23T10:00:00.000Z', finishedAt: '2026-09-23T10:05:00.000Z', findings: [BUCKET_ROW, NEW_ROW] });
    const side = async (runId) => {
      const l = await loadRun(outRoot, { runId, allowPartial: false }, { tier: 'enterprise' });
      assert.equal(l.ok, true, l.message);
      return { record: await readRunRecord(outRoot, runId), findings: l.model.findings, pluginStatus: l.model.plugins.byHost, integrity: 'chain-verified' };
    };
    const d = buildScanDelta({ baseline: await side(base), current: await side(cur) });
    assert.equal(d.comparable, true, d.refusal?.detail);
    assert.deepEqual(d.notComparable.map((f) => f.reason), [], 'the case of the provider name made a finding incomparable');
    assert.deepEqual({ unchanged: d.unchanged.length, new: d.newFindings.length, resolved: d.resolved.length },
      { unchanged: 1, new: 1, resolved: 0 }, 'the current-only finding is NEW: the old record\'s host and scope were read as aws');
  } finally { fs.rmSync(outRoot, { recursive: true, force: true }); }
});

// ── ONE COMPARISON KEY FOR "THE SAME HOST" (the architect's ruling on the delta/MTTR inconsistency) ──
test('hostKey — every host trimmed and lower-cased; a non-string is the empty key', () => {
  assert.deepEqual(['MyHost.local', ' AWS ', '10.0.0.7', 'myhost.local'].map(hostKey), ['myhost.local', 'aws', '10.0.0.7', 'myhost.local']);
  assert.equal(hostKey(undefined), '');
});

async function deltaOf(outRoot, base, cur) {
  const side = async (runId) => {
    const l = await loadRun(outRoot, { runId, allowPartial: false }, { tier: 'enterprise' });
    assert.equal(l.ok, true, l.message);
    return { record: await readRunRecord(outRoot, runId), findings: l.model.findings, pluginStatus: l.model.plugins.byHost, integrity: 'chain-verified' };
  };
  return buildScanDelta({ baseline: await side(base), current: await side(cur) });
}
const T0 = { startedAt: '2026-09-20T10:00:00.000Z', finishedAt: '2026-09-20T10:05:00.000Z' };
const T1 = { startedAt: '2026-09-23T10:00:00.000Z', finishedAt: '2026-09-23T10:05:00.000Z' };

// Both case directions: only the CURRENT-only finding consults the host compare, and it can catch a
// raw compare only when its own spelling differs from the other run's key.
for (const [baseHost, curHost] of [['MyHost.local', 'myhost.local'], ['myhost.local', 'MyHost.local']]) {
  test(`DELTA — a network host typed ${baseHost} then ${curHost} PAIRS, and each record keeps its own spelling`, async () => {
    const outRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-hostkey-'));
    try {
      const base = await oneRun(outRoot, { requested: baseHost, written: baseHost, dir: 'h_1', ...T0 });
      const cur = await oneRun(outRoot, { requested: curHost, written: curHost, dir: 'h_2', ...T1, findings: [BUCKET_ROW, NEW_ROW] });
      assert.deepEqual((await readRunRecord(outRoot, base)).hostsWritten.map((h) => h.host), [baseHost]);
      assert.deepEqual((await readRunRecord(outRoot, cur)).hostsWritten.map((h) => h.host), [curHost]);
      const d = await deltaOf(outRoot, base, cur);
      assert.equal(d.comparable, true, d.refusal?.detail);
      assert.deepEqual({ unchanged: d.unchanged.length, new: d.newFindings.length, nc: d.notComparable.map((f) => f.reason) },
        { unchanged: 1, new: 1, nc: [] });
      assert.deepEqual([d.coverage.hostsOnlyInBaseline, d.coverage.hostsOnlyInCurrent], [[], []]);
    } finally { fs.rmSync(outRoot, { recursive: true, force: true }); }
  });
}

test('DELTA — an IP compares as itself, and two DIFFERENT hosts still never pair; each is SHOWN as recorded', async () => {
  const outRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-hostkey-ip-'));
  try {
    const base = await oneRun(outRoot, { requested: 'Alpha.corp', written: 'Alpha.corp', dir: 'a_1', ...T0 });
    const cur = await oneRun(outRoot, { requested: '10.0.0.7', written: '10.0.0.7', dir: 'b_1', ...T1 });
    const d = await deltaOf(outRoot, base, cur);
    assert.deepEqual(d.notComparable.map((f) => f.reason), ['host-not-scanned', 'host-not-scanned']);
    assert.deepEqual([d.coverage.hostsOnlyInBaseline, d.coverage.hostsOnlyInCurrent], [['Alpha.corp'], ['10.0.0.7']],
      'hosts are SHOWN with their recorded spelling, never the comparison key');
  } finally { fs.rmSync(outRoot, { recursive: true, force: true }); }
});

// If the host set paired across case while the gap map did not, the finding would find no gap under the
// other spelling and read RESOLVED — a finding the scanner could not read, called fixed. Driven in BOTH
// case directions: one pins the gap map's key, the other the lookup's.
for (const [baseHost, curHost] of [['MyHost.local', 'myhost.local'], ['myhost.local', 'MyHost.local']]) {
  test(`FAIL-OPEN GUARD — ${baseHost} → ${curHost}: the other run's NOT-MEASURED plugin keeps the finding NOT COMPARABLE, never resolved`, async () => {
    const outRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-hostkey-gap-'));
    try {
      const base = await oneRun(outRoot, { requested: baseHost, written: baseHost, dir: 'h_1', ...T0 });
      const cur = await oneRun(outRoot, { requested: curHost, written: curHost, dir: 'h_2', ...T1, status: 'error', findings: [] });
      const d = await deltaOf(outRoot, base, cur);
      assert.deepEqual(d.resolved, [], 'a finding whose plugin did not run on the other side was called RESOLVED');
      assert.deepEqual(d.notComparable.map((f) => [f.direction, f.reason]), [['disappeared', 'plugin-not-measured']]);
      assert.deepEqual(d.coverage.gapsInCurrent.map((g) => g.host), [curHost], 'the gap is shown on the host as recorded');
    } finally { fs.rmSync(outRoot, { recursive: true, force: true }); }
  });
}
