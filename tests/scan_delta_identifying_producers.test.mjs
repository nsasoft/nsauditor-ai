// THE PRODUCERS THAT ATTRIBUTE ON A SERVICE'S IDENTITY — the CVE mapper AND the service agent (1.2.1, lane 6 — F2 (b)).
//
// The TCP-unidentified rule (`tcpServiceMeasurement`, and the delta's leg that calls it for a TCP port the other run saw
// OPEN) refused a CVE-mapper row's absence on a port whose service the other run could not identify: the mapper had
// nothing to match. Enterprise's service agent judges end-of-life the same way — on a service's program AND version — so
// a scan that leaves out the probe that identifies a service gives it nothing to judge there either, and its earlier
// end-of-life row read RESOLVED. The rule now keys on a DECLARED set, `IDENTIFYING_PRODUCERS`, read at exactly the two
// sites that decide it: the decision's producer branch, and the delta's reach gate (widening the decision alone would
// leave the row RESOLVED, because the gate never calls it).
//
// The other CVE-mapper sites are CVE semantics and do NOT widen: the mapper's own lookup-gap record, its coverage notes,
// `vulnerability-data-changed` (a CVE set moves with NVD's data; an end-of-life table moves only with a release), and
// the "newly attributed" basis note. Each has a leg below, so the widening cannot creep.
//
// FOURTH QUADRANT FIRST.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as SD from '../utils/scan_delta.mjs';

const { buildScanDelta, PORT_NOT_MEASURED_REASON, CVE_MAPPER_PRODUCER, VULNERABILITY_DATA_CHANGED_REASON } = SD;
const HOST = '192.0.2.23';
const run = (id) => ({ schema: 1, runId: id, startedAt: '2026-10-06T00:00:00Z', finishedAt: '2026-10-06T01:00:00Z',
  hostsRequested: [HOST], hostsWritten: [{ host: HOST, dir: 'd' }], pluginsRequested: ['003'], portsRequested: null,
  tier: 'enterprise', ceVersion: '0.2.57', eeVersion: '1.2.1', kevLoaded: false, kevSnapshot: null, epssLoaded: false, epssSnapshot: null });
const EOL = (v = '6.6p1') => `End-of-life OpenSSH ${v} on port 22`;
const eol = (over = {}) => ({ host: HOST, port: 22, protocol: 'tcp', plugin: 'service_agent', pluginName: 'service_agent',
  producerKind: 'agent', severity: 'HIGH', title: EOL(), evidenceGap: false, gapClass: null, ...over });
const cve = (over = {}) => ({ host: HOST, port: 22, protocol: 'tcp', plugin: CVE_MAPPER_PRODUCER, pluginName: CVE_MAPPER_PRODUCER,
  producerKind: 'agent', severity: 'HIGH', title: 'CVE-2024-6387 — tcp/ssh', evidenceGap: false, gapClass: null, ...over });
const svc = (program, version, status = 'open', port = 22, service = 'ssh', protocol = 'tcp') => ({ port, protocol, service, status, program, version });
const OPENSSH = (v = '6.6p1') => svc('OpenSSH', v);
const UNIDENTIFIED = svc('Unknown', 'Unknown', 'open', 22, 'unknown');
const host = (services, tcp = { tcpOpen: [22], tcpClosed: [] }) => [{ host: HOST, dir: 'd', pluginStatusRecorded: true,
  status: [{ id: '003', status: 'ran' }], portScan: tcp,
  ...(services ? { services, udpServices: services.filter((s) => SD.isUdpTransport(s.protocol)) } : {}) }];
const delta = (base, baseHost, cur, curHost) => buildScanDelta({
  baseline: { record: run('A'), findings: base, pluginStatus: baseHost },
  current: { record: run('B'), findings: cur, pluginStatus: curHost },
});
const ncOf = (d, title = EOL()) => d.notComparable.find((f) => f.title === title);
const measure = (...a) => SD.tcpServiceMeasurement(...a);

// ── THE DECLARED SET ──────────────────────────────────────────────────────────────────────────────────────────────────
test('IDENTIFYING_PRODUCERS is declared, frozen, and names exactly the CVE mapper and the service agent', () => {
  assert.ok(Array.isArray(SD.IDENTIFYING_PRODUCERS), 'IDENTIFYING_PRODUCERS is exported');
  assert.ok(Object.isFrozen(SD.IDENTIFYING_PRODUCERS));
  assert.deepEqual([...SD.IDENTIFYING_PRODUCERS], [CVE_MAPPER_PRODUCER, 'service_agent']);
});

// ── FOURTH QUADRANT FIRST: nothing below may move ─────────────────────────────────────────────────────────────────────
test('(q1, first) an agent OUTSIDE the set is unchanged: an open port is measured, identified or not', () => {
  for (const agent of ['config_agent', 'crypto_agent', 'auth_agent', 'exposure_agent']) {
    assert.equal(measure(22, agent, [UNIDENTIFIED], 'this run').measured, true, agent);
  }
});

test('(q2) the end-of-life row\'s port CLOSED now → RESOLVED: a closed TCP port was measured', () => {
  const d = delta([eol()], host([OPENSSH()]), [], host([svc('Unknown', 'Unknown', 'closed', 22, 'unknown')], { tcpOpen: [], tcpClosed: [22] }));
  assert.equal(d.resolved.length, 1); assert.deepEqual(d.notComparable, []);
});

test('(q3) identified in BOTH runs, upgraded past end-of-life → RESOLVED: the rule is silent where the service was identified', () => {
  const d = delta([eol()], host([OPENSSH('6.6p1')]), [], host([OPENSSH('9.8p1')]));
  assert.equal(d.resolved.length, 1); assert.deepEqual(d.notComparable, []);
});

test('(q4) the other run recorded NO service set → silent, as for the mapper: a TCP row with no oracle stays outside', () => {
  const d = delta([eol()], host([OPENSSH()]), [], host(undefined));
  assert.equal(d.resolved.length, 1); assert.deepEqual(d.notComparable, []);
});

test('NOT WIDENED — vulnerability-data-changed stays the MAPPER\'s: the same identity in both runs and the end-of-life row gone → RESOLVED', () => {
  const d = delta([eol()], host([OPENSSH()]), [], host([OPENSSH()]));
  assert.equal(d.resolved.length, 1, 'an end-of-life table moves with a release, not with vulnerability data');
  assert.notEqual(ncOf(d)?.reason, VULNERABILITY_DATA_CHANGED_REASON);
  const m = delta([cve()], host([OPENSSH()]), [], host([OPENSSH()]));
  assert.equal(ncOf(m, 'CVE-2024-6387 — tcp/ssh')?.reason, VULNERABILITY_DATA_CHANGED_REASON, 'positive control: the mapper\'s row still takes it');
});

test('NOT WIDENED — the "newly attributed" basis note stays the MAPPER\'s: an end-of-life row appearing on an unchanged service carries none', () => {
  const d = delta([], host([OPENSSH()]), [eol()], host([OPENSSH()]));
  assert.equal(d.newFindings.length, 1);
  assert.doesNotMatch(d.newFindings[0].basisNote ?? '', /newly attributed/);
  const m = delta([], host([OPENSSH()]), [cve()], host([OPENSSH()]));
  assert.match(m.newFindings[0]?.basisNote ?? '', /newly attributed/, 'positive control: the mapper\'s row still carries it');
});

test('NOT WIDENED — the CVE mapper\'s LOOKUP GAP on the port answers for the mapper\'s rows only', () => {
  const gap = { host: HOST, port: 22, protocol: 'tcp', plugin: CVE_MAPPER_PRODUCER, pluginName: CVE_MAPPER_PRODUCER, producerKind: 'agent',
    severity: 'INFO', title: '[COVERAGE GAP] nvd_lookup_failure — tcp/ssh', evidenceGap: false, gapClass: 'nvd_lookup_failure' };
  const d = delta([eol()], host([OPENSSH('6.6p1')]), [gap], host([OPENSSH('9.8p1')]));
  assert.equal(d.resolved.filter((f) => f.plugin === 'service_agent').length, 1, 'the upgrade is a measured fix for the service agent');
  const m = delta([cve()], host([OPENSSH('6.6p1')]), [gap], host([OPENSSH('9.8p1')]));
  assert.equal(ncOf(m, 'CVE-2024-6387 — tcp/ssh')?.reason, 'evidence-gap', 'positive control: the mapper\'s row is still held by its lookup gap');
});

test('the CVE mapper\'s refusal is BYTE-IDENTICAL: the sentence it carried before the set existed', () => {
  const d = delta([cve()], host([OPENSSH()]), [], host([UNIDENTIFIED]));
  assert.equal(ncOf(d, 'CVE-2024-6387 — tcp/ssh')?.detail, '22/tcp on 192.0.2.23 carries a CVE row in only one of the two runs, and in this run '
    + 'the TCP service on that port answered but was not identified (program absent, version absent). An unidentified service gives '
    + 'the CVE mapper nothing to match, so the absence of a CVE row there is not a measurement. It is NOT reported as fixed or as '
    + 'new — rescan once the service\'s program and version can be read.');
});

// ── THE DEFECT ────────────────────────────────────────────────────────────────────────────────────────────────────────
test('the shared decision: the service agent is measured only where the service was IDENTIFIED (program AND version)', () => {
  assert.deepEqual([measure(22, 'service_agent', [UNIDENTIFIED], 'this run').measured, measure(22, 'service_agent', [UNIDENTIFIED], 'this run').kind],
    [false, 'unidentified']);
  assert.equal(measure(22, 'service_agent', [svc('OpenSSH', 'Unknown')], 'this run').measured, false, 'a program alone is not an identity');
  assert.equal(measure(22, 'service_agent', [OPENSSH()], 'this run').measured, true);
  assert.equal(measure(22, 'service_agent', null, 'this run').measured, null, 'no service set → no oracle');
});

test('the DEFECT: 002 left out — 22/tcp OPEN now and unidentified → the baseline\'s end-of-life row is port-not-measured, never RESOLVED', () => {
  const d = delta([eol()], host([OPENSSH()]), [], host([UNIDENTIFIED]));
  assert.equal(d.resolved.length, 0, 'an unidentified service gives the service agent nothing to judge — its silence is not a fix');
  const nc = ncOf(d);
  assert.equal(nc?.reason, PORT_NOT_MEASURED_REASON);
  assert.match(nc.detail, /^22\/tcp on 192\.0\.2\.23 carries an end-of-life row in only one of the two runs, and in this run the TCP service on that port answered but was not identified \(program absent, version absent\)/);
  assert.match(nc.detail, /gives the service agent nothing to judge, so the absence of an end-of-life row there is not a measurement/);
  assert.doesNotMatch(nc.detail, /CVE/, 'the service agent\'s row is not a CVE row');
});

test('REVERSED: the end-of-life row in the CURRENT run only, the baseline\'s service unidentified → port-not-measured, never NEW', () => {
  const d = delta([], host([UNIDENTIFIED]), [eol()], host([OPENSSH()]));
  assert.equal(d.newFindings.length, 0);
  assert.equal(ncOf(d)?.reason, PORT_NOT_MEASURED_REASON);
  assert.match(ncOf(d).detail, /in the baseline run the TCP service on that port answered but was not identified/);
});
