// tests/identity_basis_community_producer.test.mjs
// ─────────────────────────────────────────────────────────────────────────────
// A COMMUNITY PRODUCER'S IDENTITY CHANGE IS DECLARED ON THE COMMUNITY VERSION — 040 AT 0.2.57 (board (bd)).
//
// Community 0.2.57 retitled the TLS certificate auditor's (040) self-signed and no-subjectAltName rows. Across a
// ≤0.2.56 → ≥0.2.57 pair, `report --since` read the same certificate's row RESOLVED beside its retitled form NEW —
// nothing fixed, nothing new. The identity-basis declaration compared only the run records' `eeVersion`, which cannot see
// a Community change: under Enterprise 1.2.0 with Community 0.2.56 then 0.2.57 the Enterprise version does not move, and
// a Community-only run records no Enterprise version at all. So a Community producer's change is declared in its own
// table, `COMMUNITY_IDENTITY_BASIS_CHANGED_AT`, compared on the run records' `ceVersion` — the same one-directional rule
// (baseline before the change, current at or after it), the same `identity-basis-changed` outcome.
//
// FOURTH QUADRANT FIRST: two runs both at or after 0.2.57 compare — a vanished 040 row is resolved.
// ─────────────────────────────────────────────────────────────────────────────
import test from 'node:test';
import assert from 'node:assert/strict';
import * as delta_ from '../utils/scan_delta.mjs';

const { buildScanDelta, cmpVersion, IDENTITY_BASIS_CHANGED_AT } = delta_;
const HOST = '192.0.2.10';
const REC = (ceVersion, eeVersion = '1.2.0') => ({ runId: `r-${ceVersion}-${eeVersion}`, startedAt: '2026-10-01T00:00:00Z', schema: 1,
  ...(eeVersion === null ? {} : { eeVersion }), ceVersion, tier: eeVersion === null ? 'community' : 'enterprise',
  hostsWritten: [{ host: HOST }], pluginsRequested: ['040', '011'] });
const ROW = (title, over = {}) => ({ host: HOST, plugin: '040', pluginName: 'tls-cert', producerKind: 'plugin', port: 443,
  title, severity: 'MEDIUM', evidenceGap: false, contentDigest: title, ...over });
const OLD = 'Self-signed certificate on port 443';
const NEW = 'TLS certificate is self-signed (port 443)';
const side = (record, findings) => ({ record, findings, integrity: 'chain-verified',
  pluginStatus: [{ host: HOST, plugin: '040', status: 'ran' }, { host: HOST, plugin: '011', status: 'ran' }] });
const delta = (bRec, bRows, cRec, cRows) => buildScanDelta({ baseline: side(bRec, bRows), current: side(cRec, cRows) });
const reasons = (d) => d.notComparable.map((x) => x.reason);

test('(first) both runs at or after 0.2.57: a vanished 040 row IS resolved', () => {
  const d = delta(REC('0.2.57'), [ROW(NEW)], REC('1.0.0'), []);
  assert.equal(d.resolved.length, 1);
  assert.deepEqual(reasons(d), []);
});

test('both runs before 0.2.57: a vanished 040 row IS resolved — the rule is one-directional', () => {
  const d = delta(REC('0.2.55'), [ROW(OLD)], REC('0.2.56'), []);
  assert.equal(d.resolved.length, 1);
  assert.deepEqual(reasons(d), []);
});

test('Enterprise 1.2.0 with Community 0.2.56 → 0.2.57: the retitled row is DECLARED, never resolved + new', () => {
  const d = delta(REC('0.2.56'), [ROW(OLD)], REC('0.2.57'), [ROW(NEW)]);
  assert.equal(d.resolved.length, 0, 'the certificate did not get fixed — its row was retitled');
  assert.equal(d.newFindings.length, 0, 'and it is not a new exposure');
  assert.deepEqual(reasons(d), ['identity-basis-changed', 'identity-basis-changed']);
  for (const nc of d.notComparable) assert.match(nc.detail, /040.*Community 0\.2\.57/s, 'the detail names the producer and the Community release');
});

test('a Community-only run (no Enterprise version) across 0.2.57 is declared too', () => {
  const d = delta(REC('0.2.56', null), [ROW(OLD)], REC('0.2.57', null), [ROW(NEW)]);
  assert.deepEqual([d.resolved.length, d.newFindings.length], [0, 0]);
  assert.deepEqual(reasons(d), ['identity-basis-changed', 'identity-basis-changed']);
});

test('the other ordering — a newer baseline against an older current — is declared too', () => {
  const d = delta(REC('0.2.57'), [ROW(NEW)], REC('0.2.56'), []);
  assert.equal(d.resolved.length, 0);
  assert.deepEqual(reasons(d), ['identity-basis-changed']);
});

test('a 040 row whose identity did not move still compares as UNCHANGED across the straddle', () => {
  const d = delta(REC('0.2.56'), [ROW('Certificate expires in 12 days on port 443')], REC('0.2.57'), [ROW('Certificate expires in 12 days on port 443')]);
  assert.deepEqual([d.unchanged.length, d.notComparable.length], [1, 0]);
});

test('another Community producer across 0.2.57 is not declared — a vanished 011 row is resolved', () => {
  const d = delta(REC('0.2.56'), [ROW('Weak protocol TLSv1.0 accepted', { plugin: '011', pluginName: 'tls' })], REC('0.2.57'), []);
  assert.equal(d.resolved.length, 1);
  assert.deepEqual(reasons(d), []);
});

test('the TABLE: Community plugin ids, each declared at a Community release the comparison can order — and exactly this set', () => {
  const t = delta_.COMMUNITY_IDENTITY_BASIS_CHANGED_AT;
  assert.ok(t && Object.isFrozen(t), 'exported and frozen');
  for (const [plugin, version] of Object.entries(t)) {
    assert.match(plugin, /^0\d{2}$/, `${plugin} is a Community plugin id`);
    assert.match(version, /^\d+\.\d+\.\d+$/, `${plugin} declares ${version}, which cannot be ordered`);
    assert.ok(!(plugin in IDENTITY_BASIS_CHANGED_AT), `${plugin} is declared in both tables`);
  }
  // MOVED DELIBERATELY when a Community producer's identity changes: add it here with its reason.
  assert.deepEqual({ ...t }, { '040': '0.2.57' });
  assert.ok(cmpVersion('0.2.56', t['040']) < 0 && cmpVersion('0.2.57', t['040']) === 0);
});
