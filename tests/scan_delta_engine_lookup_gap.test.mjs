// A CVE ROW WHOSE LOOKUP FAILED IN THE OTHER RUN WAS NOT FIXED — the CVE mapper's lookup gaps, port-scoped (1.1.1, T1b).
//
// Found by the 1.1.1 skill-lens review of T1 and verified from the code: Enterprise's intelligence engine records a
// failed CVE lookup (`[COVERAGE GAP] nvd_lookup_failure — udp/dns`, and five sibling classes) with a `gapClass` and NO
// `evidenceGap` flag, so the delta never read it as a gap. Since 0.2.55, when this scan's NVD lookup for dnsmasq failed,
// the baseline's CVE rows on that service read RESOLVED — TCP and UDP alike — and the only trace was one NEW gap row.
// Flagging the record `evidenceGap` would not do: the recorded-gap leg keys producer-wide (host|producer), so ONE
// cpe_map_miss (every run has some) would set aside every engine row on the host.
//
// The audit seat's ruling (T1b): PORT-SCOPED, keyed on (host, port, transport) from the gap record's own target, the
// transport through TRANSPORT_OF_LABEL — a 53/tcp lookup failure never reaches a udp/53 row. The classes are a TABLE
// held in two-way equality with the engine's GAP_CLASSES (Enterprise's test). And the gap ROW itself is scope, never a
// finding: one that vanishes is not RESOLVED, one that appears is not NEW.
//
// FOURTH QUADRANT FIRST.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as SD from '../utils/scan_delta.mjs';
const { buildScanDelta, NOT_COMPARABLE_REASONS } = SD;

const HOST = '192.0.2.1';
const run = (id) => ({
  schema: 1, runId: id, startedAt: '2026-09-21T00:00:00Z', finishedAt: '2026-09-21T01:00:00Z',
  hostsRequested: [HOST], hostsWritten: [{ host: HOST, dir: 'd' }], pluginsRequested: ['003'], portsRequested: null,
  tier: 'enterprise', ceVersion: '0.2.56', eeVersion: '1.1.1',
  kevLoaded: false, kevSnapshot: null, epssLoaded: false, epssSnapshot: null,
});
const ENG = { plugin: 'intelligence_engine', pluginName: 'intelligence_engine', producerKind: 'agent' };
const cve = (port, protocol, id) => ({ host: HOST, port, protocol, severity: 'HIGH', title: `${id} — ${protocol}/svc`,
  evidenceGap: false, gapClass: null, ...ENG });
const gap = (port, protocol, gapClass) => ({ host: HOST, port, protocol, severity: 'INFO', title: `[COVERAGE GAP] ${gapClass} — ${protocol}/svc`,
  evidenceGap: false, gapClass, ...ENG });
// Both ports measured by every oracle the other rules read, so only THIS rule can decide.
const status = () => [{ host: HOST, dir: 'd', pluginStatusRecorded: true, status: [{ id: '003', status: 'ran' }],
  portScan: { tcpOpen: [22, 53], tcpClosed: [] },
  udpServices: [{ port: 53, protocol: 'udp', service: 'dns', status: 'open', program: 'dnsmasq', version: '2.78' }] }];
const delta = (base, cur) => buildScanDelta({
  baseline: { record: run('A'), findings: base, pluginStatus: status() },
  current: { record: run('B'), findings: cur, pluginStatus: status() },
});
const table = () => SD.ENGINE_GAP_CLASS_KIND ?? {};

test('the classification TABLE: every lookup class is `lookup-failed`, the note is a note, the input gap is the input gap\'s', () => {
  const t = table();
  assert.ok(Object.isFrozen(t));
  for (const c of ['nvd_lookup_failure', 'nvd_response_not_array', 'offline_store_read_error', 'offline_store_no_match', 'cpe_map_miss', 'no_version_detected']) {
    assert.equal(t[c], 'lookup-failed', c);
  }
  assert.equal(t.truncated_low_severity_cves, 'note');
  // 1.2.1 (B6-4b, ruled A1): a CVE NVD lists for the product with NO version (CPE NA) — the lookup WORKED, one CVE could not
  // be decided from the banner. A note, never `lookup-failed`: that kind refuses every CVE row on the port, and an NA CVE is
  // present on every scan of its product, so the product's other CVEs could never resolve.
  assert.equal(t.cve_listed_without_version, 'note');
  assert.equal(t.input_gap, 'input-gap');
  assert.ok(!NOT_COMPARABLE_REASONS.some((r) => /lookup/.test(r)), 'no new reason token — it reads evidence-gap');
});

// ── FOURTH QUADRANT FIRST ─────────────────────────────────────────────────────────────────────────────
test('(q1) the lookup SUCCEEDED in both runs and the CVE rows are unchanged → today\'s verdict', () => {
  const d = delta([cve(53, 'udp', 'CVE-1')], [cve(53, 'udp', 'CVE-1')]);
  assert.equal(d.unchanged.length, 1);
  assert.deepEqual(d.notComparable, []);
});

test('(q1) a lookup gap on a DIFFERENT port does not reach the row → the absence is today\'s verdict (RESOLVED)', () => {
  const d = delta([cve(22, 'tcp', 'CVE-2')], [gap(53, 'udp', 'nvd_lookup_failure')]);
  assert.equal(d.resolved.length, 1);
});

test('(q1) a 53/TCP lookup failure never reaches a 53/UDP row (keyed on transport)', () => {
  const d = delta([cve(53, 'udp', 'CVE-3')], [gap(53, 'tcp', 'nvd_lookup_failure')]);
  assert.equal(d.resolved.length, 1, 'the UDP service was identified and its lookup did not fail');
});

test('(q1) ANOTHER producer\'s row on the gap\'s port is untouched (the rule is the CVE mapper\'s alone)', () => {
  const agent = { host: HOST, port: 53, protocol: 'udp', severity: 'MEDIUM', title: 'DNS open resolver', evidenceGap: false, gapClass: null,
    plugin: 'config_agent', pluginName: 'config_agent', producerKind: 'agent' };
  const d = delta([agent], [gap(53, 'udp', 'nvd_lookup_failure')]);
  assert.equal(d.resolved.length, 1);
});

test('(q1) a COVERAGE NOTE (truncated low-severity CVEs) is not a lookup failure → today\'s verdict', () => {
  const d = delta([cve(53, 'udp', 'CVE-4')], [gap(53, 'udp', 'truncated_low_severity_cves')]);
  assert.equal(d.resolved.length, 1);
});

test('(q1, B6-4b) a cve_listed_without_version NOTE governs no other row: another CVE row on its port keeps today\'s verdict (RESOLVED)', () => {
  const na = { ...gap(443, 'tcp', 'cve_listed_without_version'), title: '[COVERAGE GAP] cve_listed_without_version — tcp/https (CVE-2025-3891)' };
  const d = delta([cve(443, 'tcp', 'CVE-2024-38476')], [na]);
  assert.deepEqual(d.resolved.map((f) => f.title), ['CVE-2024-38476 — tcp/svc']);
  assert.deepEqual(d.newFindings.map((f) => f.title), [na.title], 'the note itself is NEW the first time it appears');
  const again = delta([na], [na]);
  assert.deepEqual([again.unchanged.length, again.newFindings.length, again.resolved.length, again.notComparable.length], [1, 0, 0, 0], 'and UNCHANGED after');
});

test('(q1) the SAME lookup gap in both runs, no CVE rows either side → it PAIRS (unchanged): nothing new, resolved or refused', () => {
  const d = delta([gap(53, 'udp', 'nvd_lookup_failure')], [gap(53, 'udp', 'nvd_lookup_failure')]);
  assert.equal(d.newFindings.length + d.resolved.length + d.notComparable.length, 0);
  assert.equal(d.unchanged.length, 1, 'a gap row carried by both runs is paired like any row — the mapper-gap corpus leg pins this');
});

test('(a) the gap row itself on ONE side only stays VISIBLE, refused with its reason — never dropped from the delta', () => {
  const d = delta([gap(53, 'udp', 'cpe_map_miss')], []);
  assert.equal(d.resolved.length, 0);
  assert.equal(d.notComparable.length, 1);
  assert.equal(d.notComparable[0].reason, 'evidence-gap');
  assert.match(d.notComparable[0].detail, /coverage gap that opened or cleared, not an exposure/);
});

// ── THE DEFECT ────────────────────────────────────────────────────────────────────────────────────────
test('(a) the CVE lookup FAILED now on udp/53 → the baseline\'s CVE rows are NOT COMPARABLE evidence-gap, never RESOLVED', () => {
  const base = ['CVE-2020-25681', 'CVE-2020-25682', 'CVE-2023-50387'].map((id) => cve(53, 'udp', id));
  const d = delta(base, [gap(53, 'udp', 'nvd_lookup_failure')]);
  assert.equal(d.resolved.length, 0);
  const cveNc = d.notComparable.filter((n) => !String(n.title).startsWith('[COVERAGE GAP]'));
  assert.equal(cveNc.length, 3);
  for (const nc of cveNc) {
    assert.equal(nc.reason, 'evidence-gap');
    assert.equal(nc.direction, 'disappeared');
    assert.match(nc.detail, /could not look up/);
    assert.match(nc.detail, /nvd_lookup_failure/);
    assert.match(nc.detail, /53\/udp/);
  }
});

test('(a) TCP too: a failed lookup on 22/tcp sets aside the baseline\'s OpenSSH CVE rows', () => {
  const d = delta([cve(22, 'tcp', 'CVE-2023-38408')], [gap(22, 'tcp', 'nvd_lookup_failure')]);
  assert.equal(d.resolved.length, 0);
  assert.equal(d.notComparable[0]?.reason, 'evidence-gap');
});

test('(a) the APPEARED direction: the BASELINE\'s lookup failed, the CVE rows appear now → not NEW', () => {
  const d = delta([gap(53, 'udp', 'nvd_lookup_failure')], [cve(53, 'udp', 'CVE-5')]);
  assert.equal(d.newFindings.length, 0);
  const row = d.notComparable.find((n) => n.title.startsWith('CVE-5'));
  assert.equal(row?.reason, 'evidence-gap');
  assert.equal(row?.direction, 'appeared');
});

test('(a) every lookup-failed class sets the rows aside; the gap row ITSELF is never NEW and never RESOLVED', () => {
  const classes = Object.keys(table()).filter((c) => table()[c] === 'lookup-failed');
  assert.ok(classes.length >= 6, 'non-vacuity');
  for (const c of classes) {
    const d = delta([cve(53, 'udp', 'CVE-6')], [gap(53, 'udp', c)]);
    assert.equal(d.resolved.length, 0, c);
    assert.equal(d.newFindings.length, 0, `${c}: the gap row that appeared is scope, not a new finding`);
    const back = delta([gap(53, 'udp', c)], [cve(53, 'udp', 'CVE-6')]);
    assert.equal(back.resolved.length, 0, `${c}: the gap row that vanished is not a fix`);
  }
});

test('(a) it outranks the UDP exemption: 53/udp answered AND identified, but its lookup FAILED → not comparable', () => {
  // The UDP rule would call the port measured (dnsmasq 2.78 open) — the lookup gap is what says the mapper did not look.
  const d = delta([cve(53, 'udp', 'CVE-7')], [gap(53, 'udp', 'nvd_response_not_array')]);
  assert.equal(d.resolved.length, 0);
  assert.equal(d.notComparable[0]?.reason, 'evidence-gap');
});

test('isEngineLookupGap / engineLookupGapKey are exported (Enterprise\'s MTTR reads the same decision)', () => {
  assert.equal(typeof SD.isEngineLookupGap, 'function');
  assert.equal(typeof SD.engineLookupGapKey, 'function');
  assert.equal(SD.isEngineLookupGap(gap(53, 'udp', 'cpe_map_miss')), true);
  assert.equal(SD.isEngineLookupGap(gap(0, 'mdns', 'cpe_map_miss')), false, 'port 0 is host-wide — outside a port-scoped rule');
  assert.equal(SD.isEngineLookupGap({ ...gap(53, 'udp', 'cpe_map_miss'), plugin: 'config_agent' }), false);
  assert.equal(SD.engineLookupGapKey(HOST, 53, 'udp'), SD.engineLookupGapKey(HOST.toUpperCase(), '53', 'UDP'));
  assert.notEqual(SD.engineLookupGapKey(HOST, 53, 'udp'), SD.engineLookupGapKey(HOST, 53, 'tcp'));
});
