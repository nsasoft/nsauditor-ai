// THE QUEUE SIDE OF THE GAP SEAM — a gap record that arrives through the FINDING QUEUE.
//
// ⚠️ THE PREMISE THIS FILE REPLACES WAS WRITTEN DOWN AND WAS FALSE ABOUT THE CODE.
// `shapeQueueEntry` carried `evidenceGap: false` as a constant under the comment "A queue entry is
// never a gap record: gaps are emitted by plugins into the host envelope". Enterprise's CPE mapper
// emits SIX classes of coverage-gap record straight into that queue, and one of them exists
// precisely to say "my discovery upstreams did not run". So the seam silently discarded the one
// fact it was carrying: the record reached the delta with `evidenceGap: false`, the gap map stayed
// empty, and three coverage-gap rows that vanished because discovery TIMED OUT were reported to a
// customer as REMEDIATED.
//
// ⚠️ A DECLARED LIMIT MUST BE TRUE ABOUT THE CODE. That is why the fix is not just a field read —
// the comment that asserted the false premise is gone with it.
//
// Two levels are driven here, because the defect lived BETWEEN them: the shaper (does the field
// survive the crossing?) and the delta (does the surviving field actually route anything?).
// Driving only the first is what the producer-side tests already did, and they all passed.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { shapeHostFindings } from '../utils/report_inputs.mjs';
import { buildScanDelta } from '../utils/scan_delta.mjs';

const HOST = '10.0.0.7';

// Shaped exactly as Enterprise's `_buildCoverageGapFinding` and its input-gap sibling shape a
// record: the queue's own vocabulary (`evidence.source`, `target`), never a plugin envelope's.
const queueGapRecord = (overrides = {}) => ({
  category: 'CVE',
  status: 'UNVERIFIED',
  title: '[COVERAGE GAP] INPUT GAP — upstream discovery did not complete: MDNS Scanner (027)',
  description: 'The CPE mapper mapped an INCOMPLETE service set.',
  severity: 'INFO',
  target: { host: HOST, port: 0, protocol: 'tcp', service: 'discovery',
    program: 'upstream-discovery', version: 'unknown' },
  evidence: { source: 'intelligence_engine', cve: [], mitre: [],
    raw: { evidenceGap: true, notMeasured: [{ id: '027', status: 'timeout' }] } },
  ...overrides,
});

const queueFinding = (title, overrides = {}) => ({
  category: 'CVE',
  status: 'UNVERIFIED',
  title,
  severity: 'INFO',
  target: { host: HOST, port: 5353, protocol: 'udp', service: 'mdns' },
  evidence: { source: 'intelligence_engine', cve: [], mitre: [], raw: {} },
  ...overrides,
});

const emptyRaw = () => ({ results: [] });

const shaped = (queue) => shapeHostFindings(HOST, emptyRaw(), queue);

// ── THE SEAM ────────────────────────────────────────────────────────────────────────────────

test('a queue entry carrying the gap flag crosses the seam AS a gap', () => {
  const [f] = shaped([queueGapRecord()]);
  assert.equal(f.evidenceGap, true,
    'the shaper hard-coded false here; the whole defect is that the flag did not survive');
  assert.equal(f.plugin, 'intelligence_engine',
    'the gap map keys on host|plugin, so a gap with no producer routes nothing');
});

// ⚠️ THE FOURTH QUADRANT, AND IT IS THE LEG THAT ROTS. Every fixture born of this incident carries
// the flag. If the read were replaced by a constant `true`, every leg above still passes and every
// intelligence-engine row would be refused for ever. This is the only leg that catches that.
test('ACCEPT — an ordinary queue entry is NOT a gap', () => {
  const [f] = shaped([queueFinding('[COVERAGE GAP] cpe_map_miss — mDNS/Bonjour Unknown (mdns)')]);
  assert.equal(f.evidenceGap, false,
    'a coverage-gap record about ONE service is a finding, not a statement about the run');
});

test('ACCEPT — a queue entry whose raw is absent entirely is NOT a gap', () => {
  const [f] = shaped([queueFinding('TLSv1 enabled on port 19443',
    { evidence: { source: 'crypto_agent' } })]);
  assert.equal(f.evidenceGap, false);
});

test('ACCEPT — the flag must be exactly true, never merely truthy', () => {
  // A producer writing `evidenceGap: 'yes'` has not declared a gap; it has a bug. Reading it as
  // one would let any non-empty string turn a producer's whole output un-differenceable.
  for (const value of ['true', 1, {}, []]) {
    const [f] = shaped([queueGapRecord({
      evidence: { source: 'intelligence_engine', cve: [], mitre: [], raw: { evidenceGap: value } } })]);
    assert.equal(f.evidenceGap, false, `\`${JSON.stringify(value)}\` is not a declaration`);
  }
});

// ── AND THE FLAG ACTUALLY ROUTES ────────────────────────────────────────────────────────────
// The producer-side tests all passed while the record routed nothing. These drive the engine.

// ⚠️ A NOT-COMPARABLE ROW IS THE SHAPED FINDING ITSELF with `reason` and `direction` added —
// NOT a `{finding, reason}` wrapper. My first draft read `r.finding.title`, found nothing, and
// reported the row as silently dropped when the engine had routed it correctly. A driver that
// disagrees with the engine is a finding about the driver.
const side = (findings, { runId }) => ({
  record: { runId, schema: 1, tier: 'enterprise', eeVersion: '1.1.0',
    hostsRequested: [HOST], hostsWritten: [{ host: HOST, dir: 'd1' }],
    pluginsRequested: ['027'], finishedAt: '2026-09-22T10:00:00.000Z' },
  findings,
  integrity: 'chain-verified',
  pluginStatus: [{ host: HOST, dir: 'd1', status: [], pluginStatusRecorded: true }],
});

test('a vanished queue finding is REFUSED when its producer recorded a gap in the other run', () => {
  const vanished = queueFinding('[COVERAGE GAP] cpe_map_miss — mDNS/Bonjour Unknown (mdns)');
  const d = buildScanDelta({
    baseline: side(shaped([vanished]), { runId: 'b' }),
    // The current run mapped an incomplete set and said so.
    current: side(shaped([queueGapRecord()]), { runId: 'c' }),
  });
  assert.equal(d.resolved.length, 0,
    'a finding that disappeared behind an evidence gap was not fixed — nobody looked');
  const row = d.notComparable.find((r) => /cpe_map_miss/.test(String(r.title ?? '')));
  assert.ok(row, 'the vanished row must be reported as not-comparable, not silently dropped');
  assert.equal(row.reason, 'evidence-gap');
});

// ⚠️ THE OTHER DIRECTION, because the gap map is consulted for BOTH sides and a rule that only
// refused disappearances would report the same degraded scan's re-appearances as NEW EXPOSURES.
test('an APPEARED queue finding is REFUSED when the other run recorded a gap', () => {
  const appeared = queueFinding('[COVERAGE GAP] cpe_map_miss — mDNS/Bonjour Unknown (mdns)');
  const d = buildScanDelta({
    baseline: side(shaped([queueGapRecord()]), { runId: 'b' }),
    current: side(shaped([appeared]), { runId: 'c' }),
  });
  assert.equal(d.newFindings.length, 0,
    'a finding that reappeared after a degraded run is not a new exposure');
  const row = d.notComparable.find((r) => /cpe_map_miss/.test(String(r.title ?? '')));
  assert.ok(row);
  assert.equal(row.reason, 'evidence-gap');
});

// ⚠️ AND THE GAP MUST NOT REACH A DIFFERENT PRODUCER. The key is host|producer; a gap recorded
// against the mapper says nothing about the TLS agent, and swallowing its rows would buy a green
// delta by refusing to answer.
test('ACCEPT — a gap on one producer does not refuse another producer\'s rows', () => {
  const tls = () => queueFinding('TLSv1 enabled on port 19443', {
    target: { host: HOST, port: 19443, protocol: 'tcp', service: 'https' },
    evidence: { source: 'crypto_agent', cve: [], mitre: [], raw: {} } });
  const d = buildScanDelta({
    baseline: side(shaped([tls()]), { runId: 'b' }),
    current: side(shaped([queueGapRecord()]), { runId: 'c' }),
  });
  const row = d.notComparable.find((r) => /TLSv1/.test(String(r.title ?? '')));
  assert.notEqual(row?.reason, 'evidence-gap',
    'the mapper\'s gap must not explain away the TLS agent\'s disappearance');
});

// ── THE COUNTING CHANNEL MOVES WITH IT, AND THAT IS THE INTENDED RULE, NOT A SIDE EFFECT ────
// `countHostFindings` excludes gaps because "a gap is scope, not a finding". A producer newly
// DECLARING a gap is that rule working. Asserted here so the coupling is visible rather than
// discovered later by a history line that moved for no apparent reason.
test('a queue gap record is excluded from the finding COUNT, like every other gap', async () => {
  const { countHostFindings } = await import('../utils/report_inputs.mjs');
  const withGap = countHostFindings(HOST, emptyRaw(), [queueFinding('a real one'), queueGapRecord()]);
  const without = countHostFindings(HOST, emptyRaw(), [queueFinding('a real one')]);
  assert.equal(withGap, 1, 'the gap record must not be counted as a finding');
  assert.equal(without, 1, 'and the real finding still is');
});
