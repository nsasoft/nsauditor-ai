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

test('FOURTH QUADRANT — across the SAME version nothing is declared', () => {
  // The leg that rots if the rule is written too wide: two 1.1.0 runs are commensurable, and a
  // declaration that fired on them would throw away every comparison the feature exists for.
  const d = buildScanDelta({
    baseline: side(REC({ eeVersion: '1.1.0' }), [F({ resource: 'sg-abc' })]),
    current: side(REC({ eeVersion: '1.1.0' }), [F({ resource: 'sg-abc' })]),
  });
  assert.equal(d.unchanged.length, 1);
  assert.equal(d.notComparable.length, 0, 'same basis on both sides: nothing to declare');
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

test('the declaration is one-directional in VERSION — a NEWER baseline is not declared', () => {
  // The basis changed AT 1.1.0. Two runs both at or after it are commensurable; the rule keys on
  // the baseline predating the change, never merely on the versions differing.
  const d = buildScanDelta({
    baseline: side(REC({ eeVersion: '1.1.0' }), [F({ resource: 'sg-abc' })]),
    current: side(REC({ eeVersion: '1.2.0' }), [F({ resource: 'sg-abc' })]),
  });
  assert.equal(d.notComparable.length, 0, '1.1.0 → 1.2.0 does not cross this producer\'s change');
});

test('the TABLE is exported and every entry names a version the comparison can order', () => {
  assert.ok(IDENTITY_BASIS_CHANGED_AT && typeof IDENTITY_BASIS_CHANGED_AT === 'object');
  const entries = Object.entries(IDENTITY_BASIS_CHANGED_AT);
  assert.ok(entries.length > 0, 'an empty table would make every leg above vacuous');
  for (const [plugin, version] of entries) {
    assert.match(plugin, /^\d{3,4}$/, `plugin id ${plugin} is not an id`);
    assert.match(version, /^\d+\.\d+\.\d+$/, `${plugin} declares ${version}, which cannot be ordered`);
  }
});
