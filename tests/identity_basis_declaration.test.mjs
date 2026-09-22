// E1(f) — WHEN A PRODUCER'S IDENTITY BASIS CHANGES, THE DELTA DECLARES IT INSTEAD OF FABRICATING.
//
// E1 changed what `resource` CONTAINS for nine producers — three that had claimed a region as
// their object, six that named nothing at all. Canonicalisation makes an old decorated value and
// a new clean one compute the same key, so a producer that always named its object compares
// across the upgrade unchanged. It CANNOT do that for a producer that GAINED an identity: a
// finding keyed on `'-'` in the baseline and on `sg-0def2…` in the current run is the same
// exposure wearing two keys, and a naive delta reports it as one resolved plus one new.
//
// On the feature's headline use — "what changed since last scan" — that is a fabricated
// remediation and a fabricated exposure in the same table. The operator chose per-producer
// DECLARATION over bumping the schema (which would refuse every pre-upgrade baseline outright,
// including for the ~20 producers that did not move), so the cost is paid in DISCLOSURE: the
// affected producer's rows are reported under `plugin-identity-basis-changed` and every other
// producer's delta stands.
//
// ⚠️ THE TABLE IS A CLAIM SURFACE IN BOTH DIRECTIONS, which is why both are fatal:
//   · an UNDECLARED mover fabricates churn — the defect this exists to prevent;
//   · a DECLARED producer that did not move throws a real comparison away, silently, for ever.
// `tests/identity_basis_instrument.test.mjs` holds the table in equality with what the artifacts
// actually show. This file pins the DELTA's behaviour given a table.
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  buildScanDelta, NOT_COMPARABLE_REASONS, DECLARED_OUTCOMES, IDENTITY_BASIS_CHANGED_AT,
  AGENT_PRODUCER_KEYS, identityBasisChanged,
} from '../utils/scan_delta.mjs';

// ⚠️ THE RUN RECORD CARRIES ITS SCOPE, and my first draft omitted it: with no `hostsWritten`
// the scope has no hosts, `host-not-scanned` fires before every other leg, and the test reported
// the wrong reason code for a reason that had nothing to do with identity. A driver missing a
// field the engine reads measures the engine's fallback, not the rule under test.
const REC = (over = {}) => ({ runId: 'r', startedAt: '2026-09-01T00:00:00Z', schema: 1,
  eeVersion: '1.1.0', ceVersion: '0.2.55', tier: 'enterprise',
  hostsWritten: [{ host: 'aws' }], pluginsRequested: ['1170', '1110'], ...over });
const F = (over = {}) => ({ host: 'aws', plugin: '1170', pluginName: 'sg', producerKind: 'plugin',
  title: 'Security Group permits world ingress', severity: 'CRITICAL', evidenceGap: false,
  contentDigest: 'd1', ...over });
const side = (record, findings) => ({ record, findings, integrity: 'chain-verified',
  pluginStatus: [{ host: 'aws', plugin: '1170', status: 'ran' }] });

test('the reason code is DECLARED — an undeclared code is invisible to every consumer', () => {
  assert.ok(NOT_COMPARABLE_REASONS.includes('plugin-identity-basis-changed'));
  assert.ok(DECLARED_OUTCOMES['plugin-identity-basis-changed']);
});

test('a producer that GAINED an identity is DECLARED, not reported as resolved + new', () => {
  // Baseline written before the basis change: no resource. Current: the real object id.
  const d = buildScanDelta({
    baseline: side(REC({ eeVersion: '1.0.0' }), [F({ resource: null })]),
    current: side(REC({ eeVersion: '1.1.0' }), [F({ resource: 'sg-0def2fbb3db67eae5' })]),
  });
  assert.equal(d.resolved.length, 0, 'the baseline row must NOT read as fixed');
  assert.equal(d.newFindings.length, 0, 'and the current row must NOT read as a new exposure');
  const codes = d.notComparable.map((x) => x.reason);
  assert.ok(codes.includes('plugin-identity-basis-changed'),
    `expected the basis declaration; got ${JSON.stringify(codes)}`);
  for (const nc of d.notComparable) {
    assert.match(nc.detail, /1170/, 'the declaration must NAME the producer');
  }
});

// ⚠️ THE NEXT TWO LEGS USE A FINDING THAT DIFFERS ACROSS THE PAIR, AND THE FIRST DRAFT DID NOT.
// They put the SAME finding — `sg-abc` on both sides — and asserted `notComparable.length === 0`.
// A matched-unchanged row never reaches the not-comparable path at all, so that assertion holds
// for ANY rule: a reviewing seat mutated the predicate to "always declare" and to a bidirectional
// `cmpVersion(baseline, current) !== 0` and both stayed GREEN. The legs carrying the whole
// one-directional design claim could not fail.
//
// A finding present in the BASELINE and absent from the CURRENT run is the shape that forces the
// question: it must be reported RESOLVED, and it reaches the incomparability chain on its way
// there, so a rule that declares too widely swallows a real remediation.
test('FOURTH QUADRANT — across the SAME version a vanished finding is RESOLVED, not declared', () => {
  const d = buildScanDelta({
    baseline: side(REC({ eeVersion: '1.1.0' }), [F({ resource: 'sg-abc' })]),
    current: side(REC({ eeVersion: '1.1.0' }), []),
  });
  assert.equal(d.resolved.length, 1,
    'same basis on both sides: a finding that went away was FIXED, and saying otherwise hides it');
  assert.equal(d.notComparable.length, 0, 'nothing to declare when neither side crossed a change');
});

test('FOURTH QUADRANT — a producer that did NOT move still compares across the upgrade', () => {
  // 1110 is not in the table. Its findings must compare normally even though the run versions
  // straddle the change — that is exactly what per-producer declaration buys over a schema bump.
  const g = (over) => F({ plugin: '1110', pluginName: 'iam', resource: 'iam:user:alice', ...over });
  const d = buildScanDelta({
    baseline: { ...side(REC({ eeVersion: '1.0.0' }), [g({})]),
      pluginStatus: [{ host: 'aws', plugin: '1110', status: 'ran' }] },
    current: { ...side(REC({ eeVersion: '1.1.0' }), [g({})]),
      pluginStatus: [{ host: 'aws', plugin: '1110', status: 'ran' }] },
  });
  assert.equal(d.unchanged.length, 1, 'an unmoved producer keeps its comparison across the upgrade');
  assert.equal(d.notComparable.length, 0);
});

test('ONE-DIRECTIONAL — 1.1.0 → 1.2.0 resolves a vanished finding, it does not declare it', () => {
  // The basis changed AT 1.1.0, so two runs both at or after it are commensurable. A rule keyed
  // on the versions merely DIFFERING would declare here — and would go on declaring for every
  // release after 1.1.0, for ever, quietly retiring the feature for these nine producers.
  const d = buildScanDelta({
    baseline: side(REC({ eeVersion: '1.1.0' }), [F({ resource: 'sg-abc' })]),
    current: side(REC({ eeVersion: '1.2.0' }), []),
  });
  assert.equal(d.resolved.length, 1, '1.1.0 → 1.2.0 does not cross this producer\'s change');
  assert.equal(d.notComparable.length, 0);
});

test('ONE-DIRECTIONAL — and the OTHER way: a NEWER baseline against an OLDER current', () => {
  // The guard reads both orderings, so this pair crosses the change and IS declared. It is here
  // because the implementation checks the predicate twice, and a leg that only ever drove one
  // ordering would leave the second call unexercised.
  const d = buildScanDelta({
    baseline: side(REC({ eeVersion: '1.1.0' }), [F({ resource: 'sg-abc' })]),
    current: side(REC({ eeVersion: '1.0.0' }), []),
  });
  assert.equal(d.resolved.length, 0, 'a pair straddling the change may not report a remediation');
  assert.deepEqual(d.notComparable.map((x) => x.reason), ['plugin-identity-basis-changed']);
});

test('the TABLE is exported and every entry names a version the comparison can order', () => {
  assert.ok(IDENTITY_BASIS_CHANGED_AT && typeof IDENTITY_BASIS_CHANGED_AT === 'object');
  const entries = Object.entries(IDENTITY_BASIS_CHANGED_AT);
  assert.ok(entries.length > 0, 'an empty table would make every leg above vacuous');
  // ⚠️ NUMERIC **OR** A DECLARED AGENT SOURCE, AND THE SECOND HALF IS AN ENUMERATED VOCABULARY
  // RATHER THAN "any string". A finding out of the finding QUEUE carries `evidence.source` as its
  // producer identity, never a plugin id, and EE 1.1.0 declares one. Accepting any string would
  // let a typo declare a producer that does not exist — and that failure is SILENT: the lookup
  // finds nothing, so the real producer stays undeclared and fabricates churn, which is the exact
  // defect this table exists to prevent. `AGENT_PRODUCER_KEYS` is held in two-way equality with
  // what Enterprise actually emits by `tests/agent_producer_vocabulary.test.mjs` over there.
  const agents = new Set(AGENT_PRODUCER_KEYS);
  for (const [plugin, version] of entries) {
    assert.ok(/^\d{3,4}$/.test(plugin) || agents.has(plugin),
      `\`${plugin}\` is neither a plugin id nor a declared agent producer `
      + `(${AGENT_PRODUCER_KEYS.join(', ')}) — a key outside the vocabulary can never match a `
      + 'finding, so the declaration is silent and the producer it names stays undeclared');
    assert.match(version, /^\d+\.\d+\.\d+$/, `${plugin} declares ${version}, which cannot be ordered`);
  }
});

// ════════════════════════════════════════════════════════════════════════════════════════════
// THE AGENT DECLARATION — the same rule, on a producer that is not a plugin.
// ════════════════════════════════════════════════════════════════════════════════════════════
//
// ⚠️ WHY AN AGENT NEEDED DECLARING AT ALL. A finding from Enterprise's finding QUEUE emits no
// resource, no region, no identity qualifier and no content digest, so `keyOf` reduces to
// `host · producer · port · TITLE`. The title IS what that producer names. EE 1.1.0 moved the
// coverage-gap title off `${program} ${version}` — a discovery fingerprint that changes when the
// scan does — and onto `${protocol}/${service}`. That is an identity basis change by the same
// definition the nine plugin entries use, read off the field that carries the answer in this
// container.
//
// ⚠️ AND THE KEY TYPE WAS CHECKED, NOT ASSUMED. The table's numeric literals become STRING keys
// (`Object.keys` → `["1020", …]`) and a plugin finding carries `String(id)`, so the existing
// lookups work by coercion. An agent key is a string already. A declaration that is present but
// never consulted is this cycle's own defect class — `AGENT_PRODUCER_KEYS` bounds the vocabulary
// so a typo cannot create one, and the leg below proves the entry is REACHED.
const AGENT = 'intelligence_engine';
const QREC = (over = {}) => ({ runId: 'r', startedAt: '2026-09-01T00:00:00Z', schema: 1,
  eeVersion: '1.1.0', ceVersion: '0.2.55', tier: 'enterprise',
  hostsWritten: [{ host: '127.0.0.1' }], pluginsRequested: ['003'], ...over });
// Shaped as the QUEUE path shapes it: a producer, no resource, no region, no qualifier, no digest.
const Q = (title, over = {}) => ({ host: '127.0.0.1', plugin: AGENT, pluginName: AGENT,
  producerKind: 'agent', port: 5353, title, severity: 'INFO', evidenceGap: false, ...over });
const qside = (record, findings) => ({ record, findings, integrity: 'chain-verified',
  pluginStatus: [{ host: '127.0.0.1', dir: 'd1', status: [], pluginStatusRecorded: true }] });

// ── FOURTH QUADRANT FIRST ───────────────────────────────────────────────────────────────────
// The leg an incident fixture omits: the NORMAL case. Every fixture born of this change straddles
// the boundary, so the row that rots is the one where both runs are on the SAME side — and a
// declaration that refuses there refuses for ever, silently, discarding real comparisons.

test('AGENT — two runs BOTH at or after the change compare normally', () => {
  const d = buildScanDelta({
    baseline: qside(QREC(), [Q('[COVERAGE GAP] cpe_map_miss — udp/mdns')]),
    current: qside(QREC({ runId: 's' }), []),
  });
  assert.equal(d.notComparable.filter((x) => x.reason === 'plugin-identity-basis-changed').length, 0,
    'both runs are past the declared change, so there is nothing to declare — refusing here would '
    + 'throw away every real comparison this producer can ever make');
});

test('AGENT — two runs BOTH before the change compare normally, because the rule is one-directional', () => {
  const d = buildScanDelta({
    baseline: qside(QREC({ eeVersion: '1.0.0' }), [Q('[COVERAGE GAP] cpe_map_miss — mDNS/Bonjour Unknown (mdns)')]),
    current: qside(QREC({ runId: 's', eeVersion: '1.0.0' }), []),
  });
  assert.equal(d.notComparable.filter((x) => x.reason === 'plugin-identity-basis-changed').length, 0,
    'two pre-change runs share one basis; declaring on any version DIFFERENCE would declare for '
    + 'ever and quietly retire the feature');
});

// ── THE DECLARATION ─────────────────────────────────────────────────────────────────────────

test('AGENT — a pair STRADDLING the change is DECLARED, not reported as resolved + new', () => {
  // The live shape: a 1.0.0 record carries `— mDNS/Bonjour Unknown (mdns)`, a post-change record
  // carries `— udp/mdns`. One surface, two keys.
  const d = buildScanDelta({
    baseline: qside(QREC({ eeVersion: '1.0.0' }), [Q('[COVERAGE GAP] cpe_map_miss — mDNS/Bonjour Unknown (mdns)')]),
    current: qside(QREC({ runId: 's', eeVersion: '1.1.0' }), [Q('[COVERAGE GAP] cpe_map_miss — udp/mdns')]),
  });
  assert.equal(d.resolved.length, 0, 'the baseline row must NOT read as fixed');
  assert.equal(d.newFindings.length, 0, 'and the current row must NOT read as a new exposure');
  const codes = d.notComparable.map((x) => x.reason);
  assert.ok(codes.includes('plugin-identity-basis-changed'),
    `expected the basis declaration for the agent; got ${JSON.stringify(codes)}`);
});

// ⚠️ THE SENTENCE A CUSTOMER READS. This detail renders into the client artifact's basis cell, and
// it hardcoded the word "plugin". It was UNREACHABLE for an agent until this declaration existed —
// which is why the wording rides this commit and could not have been fixed earlier.
test('AGENT — the refusal detail calls it a PRODUCER, not a plugin', () => {
  const d = buildScanDelta({
    baseline: qside(QREC({ eeVersion: '1.0.0' }), [Q('[COVERAGE GAP] cpe_map_miss — mDNS/Bonjour Unknown (mdns)')]),
    current: qside(QREC({ runId: 's' }), [Q('[COVERAGE GAP] cpe_map_miss — udp/mdns')]),
  });
  const row = d.notComparable.find((x) => x.reason === 'plugin-identity-basis-changed');
  assert.ok(row, 'the declaration must fire before its wording can be checked');
  assert.doesNotMatch(row.detail, /\bplugin intelligence_engine\b/,
    'an analysis agent is not a plugin, and this sentence reaches a client deliverable — the same '
    + 'class as the "plugin undefined did not run" detail this engine already had to fix');
  assert.match(row.detail, new RegExp(AGENT), 'it must still NAME the producer');
});

test('FOURTH QUADRANT — a PLUGIN is still called a plugin', () => {
  // The wording fix must not rename what was already correct.
  const d = buildScanDelta({
    baseline: side(REC({ eeVersion: '1.0.0' }), [F({ resource: null })]),
    current: side(REC({ eeVersion: '1.1.0' }), [F({ resource: 'sg-0def2fbb3db67eae5' })]),
  });
  const row = d.notComparable.find((x) => x.reason === 'plugin-identity-basis-changed');
  assert.ok(row);
  assert.match(row.detail, /plugin /, 'a plugin finding must keep the noun it always had');
});

// ⚠️ THE LEG THAT CATCHES AN INERT DECLARATION — the shape this cycle has shipped once and caught
// twice. A key present in the table but never consulted passes every leg above that only asserts
// an ABSENCE. This asserts the entry is REACHED, and that the vocabulary bounds it.
test('AGENT — the declaration is REACHED, and its key is a member of the declared vocabulary', () => {
  assert.equal(IDENTITY_BASIS_CHANGED_AT[AGENT], '1.1.0',
    'the entry must exist under exactly the key a queue finding carries in `plugin`');
  assert.ok(AGENT_PRODUCER_KEYS.includes(AGENT),
    'and be a member of the enumerated vocabulary, so a typo cannot declare a producer that does '
    + 'not exist — a lookup that finds nothing leaves the REAL producer undeclared');
});

// ⚠️ TWO OUTCOMES FROM ONE STRADDLE — and the first draft of this leg was leg 2 under another
// name. Asserting "the straddle is refused" proves only that SOMETHING refused it; it cannot tell
// the DECLARATION apart from agent-ness, from the straddle itself, or from any other rule that
// happens to fire on the same pair. The discriminating question is what changes when the only
// thing that differs is whether the producer is DECLARED.
//
// `crypto_agent` is the control: same container, same `producerKind`, a MEMBER of
// `AGENT_PRODUCER_KEYS`, and deliberately NOT in the table. Same straddle, same shapes, opposite
// verdict — so the refusal belongs to the declaration and to nothing else.
test('AGENT — the refusal is the DECLARATION\'s: an undeclared agent straddles the same boundary and compares', () => {
  const straddleFor = (producer) => buildScanDelta({
    baseline: qside(QREC({ eeVersion: '1.0.0' }), [Q('a title', { plugin: producer, pluginName: producer })]),
    current: qside(QREC({ runId: 's' }), [Q('a different title', { plugin: producer, pluginName: producer })]),
  });

  const declared = straddleFor(AGENT);
  assert.ok(declared.notComparable.some((x) => x.reason === 'plugin-identity-basis-changed'),
    'the declared producer must be refused — otherwise the entry is present but never consulted, '
    + 'which is the inert-declaration class this cycle has already shipped once');

  const undeclared = straddleFor('crypto_agent');
  assert.equal(undeclared.notComparable.filter((x) => x.reason === 'plugin-identity-basis-changed').length, 0,
    '`crypto_agent` is an agent, is in the vocabulary, and straddles the SAME boundary — if it is '
    + 'refused too then the refusal is not the declaration\'s, and the leg above proves nothing '
    + 'about the table');
  assert.equal(undeclared.resolved.length + undeclared.newFindings.length, 2,
    'and it must actually be COMPARED — one vanished, one appeared — or it was refused for some '
    + 'other reason and the contrast is illusory');
});

test('AGENT — the lookup key resolves, checked by COERCION and not by eye', () => {
  // The table's numeric literals become STRING keys and a plugin finding carries `String(id)`, so
  // the existing entries work by coercion. An agent key is a string already — but a declaration
  // that is present and never resolves is silent, so it is driven rather than read.
  assert.equal(identityBasisChanged(AGENT, '1.0.0', '1.1.0'), true, 'straddling → declared');
  assert.equal(identityBasisChanged(AGENT, '1.1.0', '1.1.0'), false, 'both after → not declared');
  assert.equal(identityBasisChanged(AGENT, '1.0.0', '1.0.0'), false, 'both before → not declared');
  assert.equal(identityBasisChanged('crypto_agent', '1.0.0', '1.1.0'), false,
    'and an undeclared producer is never declared, whatever it straddles');
});
