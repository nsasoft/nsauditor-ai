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

// ── FOLD 2 — A GAP ON MY OWN SIDE SPEAKS TO MY ABSENCES, NEVER TO MY PRESENCES ──────────────
//
// ⚠️ THIS BRANCH WAS UNREACHABLE UNTIL THE MAPPER'S BOUNDARY WIDENED, WHICH IS WHY IT SHIPPED.
// `incomparabilityReason` read `theirs.gaps.get(k) ?? mine.gaps.get(k)` while its detail sentence
// says "the OTHER run recorded an evidence gap" whichever side answered. Before EE 1.1.0 the
// `mine` half needed a gap on the finding's OWN side beside a bucketed row from the SAME producer,
// and no shipped producer made that pair. Now both sides of any real degraded network comparison
// carry the mapper's gap, so the branch is live on ordinary pairs.
//
// Driven before the fix: a genuinely NEW row on the degraded side, against a full baseline that
// recorded NO gap, came back `new = 0` and `not-comparable · evidence-gap` with the detail "the
// other run recorded an evidence gap …". Both halves wrong — a suppressed new exposure, explained
// by a sentence that is false about the baseline.
//
// The asymmetry is the rule: for a row that VANISHED, `theirs` is the side that failed to look;
// for a row that APPEARED, `theirs` is again the side that failed to look. `mine` is never the
// side that failed to look at a finding MY OWN run is holding.

test('FOURTH QUADRANT — my own gap does NOT refuse my own new row', () => {
  const prior = queueFinding('an unrelated prior row');
  const fresh = queueFinding('[COVERAGE GAP] cpe_map_miss — NEW THING (mdns)');
  const d = buildScanDelta({
    baseline: side(shaped([prior]), { runId: 'b' }),                        // full run, no gap
    current: side(shaped([prior, fresh, queueGapRecord()]), { runId: 'c' }), // degraded, carries a gap
  });
  assert.equal(d.newFindings.length, 1,
    'the baseline looked and did not find it; my own run\'s gap explains my ABSENCES, not this');
  assert.equal(d.newFindings[0].title, fresh.title);
  assert.equal(d.notComparable.filter((r) => /NEW THING/.test(String(r.title ?? ''))).length, 0);
});

test('FOURTH QUADRANT — my own gap does NOT refuse a row only I am holding, in the other direction', () => {
  const only = queueFinding('[COVERAGE GAP] cpe_map_miss — ONLY IN BASELINE (mdns)');
  const d = buildScanDelta({
    baseline: side(shaped([only, queueGapRecord()]), { runId: 'b' }),  // degraded, carries a gap
    current: side(shaped([]), { runId: 'c' }),                         // full run, no gap
  });
  // The current run looked and did not find it. Whether that is remediation is for the ordinary
  // rules; what must NOT happen is a refusal blamed on "the other run" over a gap that is mine.
  const row = d.notComparable.find((r) => /ONLY IN BASELINE/.test(String(r.title ?? '')));
  assert.equal(row?.reason === 'evidence-gap', false,
    'the current run recorded no gap; refusing on MY gap prints a sentence false about the other run');
});

test('…and the refusals that DO depend on the other side are untouched', () => {
  // The negative control for the fold: narrowing to `theirs` must not disarm the legs the whole
  // seam exists for. Both directions, same pair shapes as above with the gap on the OTHER side.
  const row = queueFinding('[COVERAGE GAP] cpe_map_miss — mDNS/Bonjour Unknown (mdns)');
  const vanished = buildScanDelta({
    baseline: side(shaped([row]), { runId: 'b' }),
    current: side(shaped([queueGapRecord()]), { runId: 'c' }),
  });
  assert.equal(vanished.resolved.length, 0);
  assert.equal(vanished.notComparable.find((r) => /cpe_map_miss/.test(String(r.title ?? '')))?.reason,
    'evidence-gap');
  const appeared = buildScanDelta({
    baseline: side(shaped([queueGapRecord()]), { runId: 'b' }),
    current: side(shaped([row]), { runId: 'c' }),
  });
  assert.equal(appeared.newFindings.length, 0);
  assert.equal(appeared.notComparable.find((r) => /cpe_map_miss/.test(String(r.title ?? '')))?.reason,
    'evidence-gap');
});

// ── THE DISCLOSURE A READER ACTUALLY MEETS MUST BE THE ONE THAT DISCLOSES ───────────────────
//
// ⚠️ FOUR QUEUE-PATH FIELDS ARE DECLARED ABSENT AGAINST `AGENT_SCOPE_FROM_TIER`, AND THAT LIMIT
// SAID NOTHING ABOUT THEM. Its text disclosed how an agent's SCOPE is derived; the absences it
// excuses are about IDENTITY — `contentDigest`, `identityQualifier`, `resource` and `region` are
// all missing on this path, so a queue row is identified by host, producer, port and TITLE and by
// nothing else. A reader of the limits block was never told that. A carve-out is only disclosed if
// the sentence that reaches the reader is the sentence that discloses it.
//
// ⚠️ AND THE ABSENCE HAS A LIVE OCCUPANT, WHICH IS WHY THE SENTENCE NAMES THE CONSEQUENCE. On the
// real `192.168.1.1` record, TWENTY CVE rows share host, port, protocol, service, program and
// version — `{port: 53, protocol: 'udp', service: 'dns', program: 'dnsmasq', version: '2.78'}` —
// and are separated only by their titles (20 rows, 20 distinct titles). With no digest on this
// path, one edit to that title template would collapse all twenty into a single identity, and the
// delta's own IDENTITY_COLLAPSE limit is the only thing that would say so, after the fact.
// ⚠️ THE FIGURE WAS 21 IN MY FIRST REPORT AND IT WAS WRONG — derived, it is 20. The class did not
// depend on the number, which is exactly why an unchecked number rides along unnoticed.
test('the agent limit discloses the IDENTITY composition, not only the scope', () => {
  const d = buildScanDelta({
    baseline: side(shaped([queueFinding('a queue row')]), { runId: 'b' }),
    current: side(shaped([queueFinding('a queue row')]), { runId: 'c' }),
  });
  const limit = d.limits.find((l) => l.startsWith('Agent-produced findings'));
  assert.ok(limit, 'the limit must reach the output for any of this to be a disclosure');
  for (const [what, re] of [['the fields it is keyed on', /host/i], ['the producer', /producer/i],
    ['the port', /port/i], ['the title', /title/i]]) {
    assert.match(limit, re, `the disclosure must name ${what}`);
  }
  assert.match(limit, /no (object|resource)|without a (resource|digest)|neither|nor/i,
    'and must say what it is NOT keyed on — an absence a reader cannot infer from a list');
  assert.match(limit, /digest/i,
    'the missing content digest is the one whose absence can MASK a finding; naming it is the point');
});

test('…and the declared-absent queue fields all point at that limit, so the sentence is load-bearing', async () => {
  const { DECLARED_ABSENT_FINDING_FIELDS } = await import('../utils/scan_delta.mjs');
  // ⚠️ QUEUE-ONLY, and my first draft got this wrong. `control` is absent on BOTH paths and is
  // disclosed by FRAMEWORK_MOVEMENT_NOT_EVALUATED — correctly, because it is absent for an
  // entirely different reason (Community ships no compliance data). Demanding that every
  // queue-path absence point at the agent limit would have forced a true declaration to name a
  // limit that does not describe it, which is the opposite of what this leg is for.
  const queueAbsent = Object.entries(DECLARED_ABSENT_FINDING_FIELDS)
    .filter(([, v]) => (v.paths ?? []).length === 1 && v.paths[0] === 'queue');
  assert.ok(queueAbsent.length >= 4, 'the four queue-path absences must still be declared');
  for (const [field, decl] of queueAbsent) {
    assert.equal(decl.disclosedBy, 'AGENT_SCOPE_FROM_TIER',
      `${field} is excused by a limit this leg does not check; either point it here or give it a `
      + 'leg of its own — an unchecked disclosure is not a disclosure');
  }
});
