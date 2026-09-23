// ONE DEFINITION OF A FINDING ACROSS BOTH COMPARISON CHANNELS (board C10).
//
// ⚠️ THE DEFECT, measured on this cycle's own evidence tree. The `192.168.1.1` Gate-2 run recorded
// `findingsCount: 0` in `scan_history.jsonl` while its `scan_finding_queue.json` held 37 entries,
// 21 carrying CVEs (EPSS up to 0.99988, five ELEVATED). `cli.mjs` summed service-level attributes
// and plugin `result.findings`; the queue is neither, so it counted nothing.
//
// ⚠️ IT IS A COMPARISON CHANNEL, which is what makes it a false clean and not a cosmetic count.
// `computeDiff` derives `newFindings` and `findingsDelta` from `findingsCount`, and
// `delta_reporter` gates its webhook on `newFindings` — so a host whose findings ride the queue
// reports zero new and zero delta on EVERY scan, forever, however many CVEs appear.
//
// ⚠️ AND THE PRODUCT'S TWO COMPARISON CHANNELS DISAGREED ABOUT WHAT A FINDING IS. `report --since`
// counts queue entries (the loader shapes them, `producerKind:'agent'`); `scan_history` did not.
// One of them was wrong about the same scan, and a customer can run both.
//
// This is the R-1 fold's own class one producer over: that fold added `cloudFindingsCount` after
// cloud plugins recorded 0 over a 201-finding scan. The queue was never added. A repair enumerated
// PER PRODUCER closes only the producers it enumerates — which is how this channel came to be
// wrong twice. So the count is DERIVED from the same shaping the delta uses, not summed again.
import './helpers/no_operator_keychain.mjs';   // FIRST: keeps this file off the operator's real Keychain
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { countHostFindings, FINDINGS_COUNT_BASIS, shapeHostFindings } from '../utils/report_inputs.mjs';
import { computeDiff } from '../utils/scan_history.mjs';

// Shaped after the REAL 192.168.1.1 envelope: a network host records services and plugin
// `data[]` telemetry, and NO `result.findings` at all. Its findings live in the queue.
const rawNetworkHost = {
  runId: 'R-1',
  pluginStatus: [{ id: '003', name: 'Port Scanner', status: 'ran', reason: null }],
  results: [{ id: '003', name: 'Port Scanner', result: { up: true, findings: [] } }],
};
const queueWithCves = [
  { id: 'F-0001', severity: 'HIGH', title: 'CVE-2020-25681 — dnsmasq 2.78', target: { port: 53 },
    evidence: { source: 'intelligence_engine', cve: ['CVE-2020-25681'] } },
  { id: 'F-0002', severity: 'HIGH', title: 'CVE-2023-50387 — dnsmasq 2.78', target: { port: 53 },
    evidence: { source: 'intelligence_engine', cve: ['CVE-2023-50387'] } },
  { id: 'F-0003', severity: 'MEDIUM', title: 'CVE-2021-3448 — dnsmasq 2.78', target: { port: 53 },
    evidence: { source: 'intelligence_engine', cve: ['CVE-2021-3448'] } },
];

test('a host whose findings ride ONLY the queue is NOT counted as zero', () => {
  // The headline defect, in one assertion.
  assert.equal(countHostFindings('192.168.1.1', rawNetworkHost, queueWithCves), 3);
  assert.notEqual(countHostFindings('192.168.1.1', rawNetworkHost, queueWithCves), 0,
    'this read 0 on the real estate over 37 queue entries, 21 with CVEs — and 0 is what the '
    + 'comparison channel then reported as "no change", forever');
});

test('the count IS the loader shaping — not a third sum beside it', () => {
  // ⚠️ THE WHOLE POINT OF THE FIX. A per-producer sibling (`queueFindingsCount` beside
  // `cloudFindingsCount`) was refused: a repair enumerated per producer closes only the producers
  // it enumerates, which is how this channel came to be wrong twice. Deriving from the shaping
  // `report --since` already uses is what makes ONE definition, so the two channels cannot drift.
  const shaped = shapeHostFindings('192.168.1.1', rawNetworkHost, queueWithCves)
    .filter((f) => f.evidenceGap !== true && f.deferredScope !== true);
  assert.equal(countHostFindings('192.168.1.1', rawNetworkHost, queueWithCves), shaped.length);
});

test('an EVIDENCE GAP is scope, not a finding — excluded, exactly as the delta excludes it', () => {
  // A gap is a surface the scanner could not read. Counting it as a finding would make an
  // AccessDenied look like a vulnerability appearing, and a fixed permission look like a
  // remediation. The delta buckets gaps as not-comparable for the same reason.
  const withGap = {
    ...rawNetworkHost,
    results: [{ id: '010', name: 'aws-s3', result: { up: true, findings: [
      { severity: 'HIGH', title: 'No public access block', port: 443, resource: 'bucket-a' },
      { severity: 'INFO', title: 'AccessDenied listing buckets', resource: 'account',
        details: { evidenceGap: true } },
    ] } }],
  };
  assert.equal(countHostFindings('10.0.0.7', withGap, []), 1,
    'the real finding counts; the gap does not');
});

// ── CFN-3 (architect F4): a DECLARED SCOPE STATEMENT leaves the count, as it left the delta ─────
// The count's own comment says it and the delta are "incapable of drifting apart". The delta began
// setting `deferredScope` rows aside before pairing, so this count must too — or the history and
// the delta disagree about the 12 scope rows of the test estate's AWS run.
test('one gap, one statement, one both-flags row and one finding count ONE', () => {
  const mixed = {
    ...rawNetworkHost,
    results: [{ id: '1110', name: 'iam', result: { up: true, findings: [
      { severity: 'HIGH', title: 'decrypt on *', resource: 'iam:user:a' },
      { severity: 'INFO', title: 'ListKeys denied', resource: 'account', details: { evidenceGap: true } },
      { severity: 'INFO', title: 'what this plugin does not examine', resource: 'iam:scope', details: { deferredScope: true } },
      { severity: 'INFO', title: 'gap and boundary', resource: 'iam:scope', details: { evidenceGap: true, deferredScope: true } },
    ] } }],
  };
  assert.equal(countHostFindings('aws', mixed, []), 1);
});

test('the basis MOVED with the definition, and a v1 line is refused against a v2 line', () => {
  assert.equal(FINDINGS_COUNT_BASIS, 'loader-shaped-v2',
    'scope statements left the count under the same key — a line counted before that is a different basis');
  const d = computeDiff({ host: 'h', findingsCount: 193, findingsCountBasis: FINDINGS_COUNT_BASIS, services: [] },
                        { host: 'h', findingsCount: 205, findingsCountBasis: 'loader-shaped-v1', services: [] });
  assert.equal(d.findingsNotComparable, true);
  assert.equal(d.newFindings, null, 'a fabricated "-12 resolved" is exactly what the refusal prevents');
  assert.equal(d.findingsNotComparableReason, 'basis-changed');
});

test('the count is stamped with its BASIS — the value changed under an unchanged name', () => {
  assert.ok(typeof FINDINGS_COUNT_BASIS === 'string' && FINDINGS_COUNT_BASIS.length >= 3,
    'the basis must be a stable token a history line can carry');
});

// ── THE §5.3 HALF: `findingsCount` KEEPS ITS NAME AND CHANGES ITS VALUE.
test('a CROSS-BASIS comparison is DECLARED not comparable — never computed across', () => {
  // ⚠️ WITHOUT THIS THE FIX ITSELF FABRICATES AN ALARM. A customer's existing history holds lines
  // counted the OLD way; the first scan after upgrading counts the NEW way. Subtracting one from
  // the other reports "+37 new findings" on the webhook for an estate where nothing changed —
  // a fabricated alert produced by our own correction. The same key changing meaning is exactly
  // what contract-v1 §5.3 records about `findingCount`, and the answer there was to REFUSE the
  // comparison rather than compute it.
  const previous = { host: 'h', findingsCount: 0, services: [] };                     // no basis: pre-fix line
  const current = { host: 'h', findingsCount: 37, findingsCountBasis: FINDINGS_COUNT_BASIS, services: [] };
  const diff = computeDiff(current, previous);
  assert.equal(diff.newFindings, null,
    'a number here is a claim that the two counts are commensurable. They are not.');
  assert.ok(diff.findingsNotComparable,
    'the diff must DECLARE it, so a consumer can report the declaration instead of a delta');
  assert.match(String(diff.summary), /not comparable|basis/i,
    'and the human summary must say so rather than silently omitting the findings clause');
});

test('a SAME-BASIS comparison still computes — the accept case', () => {
  // Without this leg the fix could be "never compare findings again", which would satisfy every
  // assertion above and destroy the feature.
  const previous = { host: 'h', findingsCount: 3, findingsCountBasis: FINDINGS_COUNT_BASIS, services: [] };
  const current = { host: 'h', findingsCount: 5, findingsCountBasis: FINDINGS_COUNT_BASIS, services: [] };
  const diff = computeDiff(current, previous);
  assert.equal(diff.newFindings, 2);
  assert.ok(!diff.findingsNotComparable);
  assert.match(String(diff.summary), /findings delta: \+2/);
});

test('two OLD lines still compare — nobody mid-history is punished for the upgrade', () => {
  // Both sides pre-fix: their counts are commensurable with EACH OTHER, so refusing here would
  // break a working comparison for a customer who has not rescanned yet.
  const previous = { host: 'h', findingsCount: 2, services: [] };
  const current = { host: 'h', findingsCount: 5, services: [] };
  const diff = computeDiff(current, previous);
  assert.equal(diff.newFindings, 3);
  assert.ok(!diff.findingsNotComparable);
});

test('NO previous scan reports no number either — absence is not a delta of itself', () => {
  const diff = computeDiff({ host: 'h', findingsCount: 9, findingsCountBasis: FINDINGS_COUNT_BASIS }, null);
  assert.equal(diff.newFindings, 9, 'a first scan legitimately reports its own count as new');
});

// ── THE REPORTER HALF: the declaration must be SENT, not swallowed.
test('a cross-basis diff is REPORTABLE — silence would be "nothing changed" one level up', async () => {
  // ⚠️ `newFindings: null` is falsy, so both of delta_reporter's gates would drop a cross-basis
  // diff and the operator would hear NOTHING — which reads as "no change since last scan". That
  // is the same false clean this whole item is about, moved one layer out. The declaration is
  // the thing worth sending: it tells the operator to rescan, which a silent webhook never does.
  const { hasSignificantChanges, formatDeltaSummary } = await import('../utils/delta_reporter.mjs');
  const crossBasis = computeDiff(
    { host: 'h', findingsCount: 37, findingsCountBasis: FINDINGS_COUNT_BASIS, services: [] },
    { host: 'h', findingsCount: 0, services: [] },
  );
  const report = { newHosts: [], removedHosts: [], hostDiffs: new Map([['h', crossBasis]]) };
  assert.equal(hasSignificantChanges(report), true,
    'a comparison we cannot make is news; reporting nothing asserts that nothing changed');
  assert.match(formatDeltaSummary(report), /not comparable/i,
    'and the text that goes out must carry the declaration, not a number');
});

test('an UNCHANGED same-basis scan is still silent — the accept case for the gate', async () => {
  // Without this the fix could be "always report", which is how an alerting channel gets muted
  // by its own users.
  const { hasSignificantChanges } = await import('../utils/delta_reporter.mjs');
  const same = computeDiff(
    { host: 'h', findingsCount: 3, findingsCountBasis: FINDINGS_COUNT_BASIS, services: [] },
    { host: 'h', findingsCount: 3, findingsCountBasis: FINDINGS_COUNT_BASIS, services: [] },
  );
  assert.equal(hasSignificantChanges({ newHosts: [], removedHosts: [], hostDiffs: new Map([['h', same]]) }), false);
});

// ── THE INTEGRATION LEG: the number cli RECORDS is the shared definition over the bytes it WROTE.
test('a real scan records the shared count over its own persisted artifacts, stamped with the basis', async () => {
  // ⚠️ THIS IS THE "ONE DEFINITION" INVARIANT, asserted end to end rather than argued. If cli ever
  // goes back to summing for itself, this fails even when both numbers happen to be equal today,
  // because the basis stamp disappears with the derivation.
  //
  // ⚠️ STATED LIMIT: Community produces no finding QUEUE — the enrichment hook that writes it is
  // Enterprise — so this leg exercises the envelope arm only. The queue arm is proven on the unit
  // legs above, against a fixture shaped after the real 192.168.1.1 envelope. Saying so here
  // rather than letting a green integration leg imply coverage it does not have.
  const fs2 = await import('node:fs');
  const os2 = await import('node:os');
  const path2 = await import('node:path');
  const { main } = await import('../cli.mjs');
  const { getLastScan } = await import('../utils/scan_history.mjs');

  const root = fs2.default.mkdtempSync(path2.default.join(os2.default.tmpdir(), 'nsa-c10-'));
  const savedArgv = process.argv;
  const saved = { SCAN_OUT_PATH: process.env.SCAN_OUT_PATH, NSA_ALLOW_ALL_HOSTS: process.env.NSA_ALLOW_ALL_HOSTS };
  try {
    process.argv = ['node', 'cli', 'scan', '--host', '127.0.0.1', '--plugins', '003', '--ports', '1-2',
      '--out', root];
    process.env.NSA_ALLOW_ALL_HOSTS = '1';
    await main();
  } finally {
    process.argv = savedArgv;
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k]; else process.env[k] = v;
    }
  }

  const recorded = await getLastScan(root, '127.0.0.1');
  assert.ok(recorded, 'the scan must have recorded a history line');
  assert.equal(recorded.findingsCountBasis, FINDINGS_COUNT_BASIS,
    'the line must declare HOW it counted, or nothing downstream can refuse a cross-basis subtraction');

  // Re-derive from the artifacts on disk and demand the same number.
  const hostDir = fs2.default.readdirSync(root).find((n) => n.startsWith('127.0.0.1_'));
  assert.ok(hostDir, 'the scan directory must exist beside the history');
  const raw = JSON.parse(fs2.default.readFileSync(path2.default.join(root, hostDir, 'scan_conclusion_raw.json'), 'utf8'));
  const qPath = path2.default.join(root, hostDir, 'scan_finding_queue.json');
  const queue = fs2.default.existsSync(qPath) ? JSON.parse(fs2.default.readFileSync(qPath, 'utf8')) : [];
  assert.equal(recorded.findingsCount, countHostFindings('127.0.0.1', raw, queue),
    'the history count and the report loader must agree about this scan — one definition, or the '
    + 'two comparison channels drift apart again');
});

test('deriveFindingsCount READS THE QUEUE from the directory — the producer that was missed', async () => {
  // ⚠️ THIS LEG EXISTS BECAUSE THE END-TO-END ONE CANNOT DISCRIMINATE HERE, and saying so is the
  // point. Community produces no finding queue, so on a CE scan the legacy sum and the loader
  // count are BOTH zero and both mutants below stay green against it:
  //   · reverting cli to `serviceFindingsCount + cloudFindingsCount`
  //   · making the derivation ignore the queue
  // Their discriminating corpus is a run WITH queue entries — the EE Gate-2 estate, where the
  // real defect was measured (0 recorded against 37 entries, 21 with CVEs). This leg supplies
  // that corpus by building the directory directly, so the mechanism is proven even though the
  // end-to-end path cannot reach it from Community.
  const fs2 = (await import('node:fs')).default;
  const os2 = (await import('node:os')).default;
  const path2 = (await import('node:path')).default;
  const { deriveFindingsCount } = await import('../utils/report_inputs.mjs');

  const dir = fs2.mkdtempSync(path2.join(os2.tmpdir(), 'nsa-derive-'));
  fs2.writeFileSync(path2.join(dir, 'scan_conclusion_raw.json'), JSON.stringify(rawNetworkHost), 'utf8');

  const withoutQueue = await deriveFindingsCount(dir, '192.168.1.1');
  assert.equal(withoutQueue.count, 0, 'the envelope alone carries no findings — this is the state that shipped');
  assert.equal(withoutQueue.basis, FINDINGS_COUNT_BASIS);

  fs2.writeFileSync(path2.join(dir, 'scan_finding_queue.json'), JSON.stringify(queueWithCves), 'utf8');
  const withQueue = await deriveFindingsCount(dir, '192.168.1.1');
  assert.equal(withQueue.count, 3,
    'the queue is where a network host\'s findings live; a derivation that does not read it '
    + 'records 0 for a host with CVEs, and the comparison channel then reports "no change" forever');
});

test('deriveFindingsCount returns NULL when the artifacts cannot be read — never a mislabelled line', async () => {
  // Fourth quadrant: the failure must be distinguishable from a genuine zero, because the caller
  // uses null to decide whether it may claim the new basis at all. Returning `{count: 0}` here
  // would stamp an authoritative basis on a number nothing produced.
  const { deriveFindingsCount } = await import('../utils/report_inputs.mjs');
  assert.equal(await deriveFindingsCount('/definitely/not/a/directory', 'h'), null);
});

test('a WRAPPED queue file counts the same in both channels — same path is not the same source', async () => {
  // ⚠️ THE FIRST DRAFT OF `deriveFindingsCount` READ THE SAME PATH AND A DIFFERENT SOURCE. It
  // accepted only a bare array, while `loadRun` also unwraps `{queue:[…]}` / `{findings:[…]}`.
  // A wrapped file would therefore have counted ZERO in the history channel and every entry in
  // the report — "one definition" nominally, two in fact, which is exactly what C10 exists to
  // close. Found by reading the consumer rather than by a failing test, so here is the test.
  const fs2 = (await import('node:fs')).default;
  const os2 = (await import('node:os')).default;
  const path2 = (await import('node:path')).default;
  const { deriveFindingsCount } = await import('../utils/report_inputs.mjs');

  for (const wrapper of [{ queue: queueWithCves }, { findings: queueWithCves }]) {
    const dir = fs2.mkdtempSync(path2.join(os2.tmpdir(), 'nsa-wrap-'));
    fs2.writeFileSync(path2.join(dir, 'scan_conclusion_raw.json'), JSON.stringify(rawNetworkHost), 'utf8');
    fs2.writeFileSync(path2.join(dir, 'scan_finding_queue.json'), JSON.stringify(wrapper), 'utf8');
    const d = await deriveFindingsCount(dir, '192.168.1.1');
    assert.equal(d.count, 3, `a ${Object.keys(wrapper)[0]}-wrapped queue must count the same as a bare array`);
  }
});

test('an UNREADABLE queue file falls back to the in-envelope enrichment — as the loader does', async () => {
  const fs2 = (await import('node:fs')).default;
  const os2 = (await import('node:os')).default;
  const path2 = (await import('node:path')).default;
  const { deriveFindingsCount } = await import('../utils/report_inputs.mjs');
  const dir = fs2.mkdtempSync(path2.join(os2.tmpdir(), 'nsa-fallback-'));
  fs2.writeFileSync(path2.join(dir, 'scan_conclusion_raw.json'), JSON.stringify({
    ...rawNetworkHost,
    conclusion: { result: { eeEnrichment: { queue: queueWithCves } } },
  }), 'utf8');
  // No queue FILE at all — the shape a run written before that artifact existed leaves behind.
  const d = await deriveFindingsCount(dir, '192.168.1.1');
  assert.equal(d.count, 3, 'the history must not report zero for a run the report reads in full');
});
