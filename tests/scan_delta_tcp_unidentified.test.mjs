// A CVE ROW ON A TCP PORT WHOSE SERVICE THE OTHER RUN COULD NOT IDENTIFY WAS NOT MEASURED — `port-not-measured` (1.2.1,
// lane 6: the TCP-unidentified sibling of F2).
//
// The CVE mapper attributes a CVE on a service's program AND version, and returns nothing — no row, no record — for a
// service whose program is `Unknown` (Enterprise's intelligence_engine program guard). MEASURED through the real
// concluder: a run that leaves the SSH probe (002) out concludes 22/tcp as `{service:'unknown', program:'Unknown',
// version:'Unknown', status:'open'}`, so the mapper emits nothing there and a baseline's CVE rows on 22/tcp read RESOLVED.
// UDP has had this refusal since 1.1.1 (`udpPortMeasurement`'s `unidentified`); TCP had no analogue, because the port
// rule keys on 003's lists alone and 22 was OPEN in both runs.
//
// The rule: a CVE-mapper row present in one run only, on a TCP port the OTHER run's port scanner saw OPEN, where no open
// TCP service record on that port carries an identity (a program AND a version, `identityOf`) → NOT COMPARABLE under the
// EXISTING `port-not-measured` reason, both directions. ONE decision, `tcpServiceMeasurement`, beside
// `udpPortMeasurement`, so Enterprise's MTTR asks the same question. The mapper's own lookup-gap record on the port
// answers FIRST (a `no_version_detected` is that record); the vulnerability-data rule answers AFTER.
//
// FOURTH QUADRANT FIRST: every verdict that must not move is written, and green, before the defect legs.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as SD from '../utils/scan_delta.mjs';

// A namespace import, so that before the rule exists each leg fails ON ITS OWN rather than the file failing to load.
const { buildScanDelta, PORT_NOT_MEASURED_REASON, NOT_COMPARABLE_REASONS } = SD;
const measure = (...a) => { assert.equal(typeof SD.tcpServiceMeasurement, 'function', 'tcpServiceMeasurement is exported'); return SD.tcpServiceMeasurement(...a); };
const HOST = '192.0.2.22';
const run = (id) => ({ schema: 1, runId: id, startedAt: '2026-10-05T00:00:00Z', finishedAt: '2026-10-05T01:00:00Z',
  hostsRequested: [HOST], hostsWritten: [{ host: HOST, dir: 'd' }], pluginsRequested: ['003'], portsRequested: null,
  tier: 'enterprise', ceVersion: '0.2.56', eeVersion: '1.2.0', kevLoaded: false, kevSnapshot: null, epssLoaded: false, epssSnapshot: null });
const CVE = 'CVE-2024-6387 — tcp/ssh';
const cve = (over = {}) => ({ host: HOST, port: 22, protocol: 'tcp', plugin: 'intelligence_engine', pluginName: 'intelligence_engine',
  producerKind: 'agent', severity: 'HIGH', title: CVE, evidenceGap: false, gapClass: null, ...over });
const agentRow = { host: HOST, port: 22, protocol: 'tcp', plugin: 'config_agent', pluginName: 'config_agent', producerKind: 'agent',
  severity: 'MEDIUM', title: 'SSH password authentication enabled on port 22', evidenceGap: false, gapClass: null };
const lookupGap = (gapClass) => ({ host: HOST, port: 22, protocol: 'tcp', plugin: 'intelligence_engine', pluginName: 'intelligence_engine',
  producerKind: 'agent', severity: 'INFO', title: `[COVERAGE GAP] ${gapClass} — tcp/ssh`, evidenceGap: false, gapClass });
const svc = (program, version, status = 'open', port = 22, service = 'ssh', protocol = 'tcp') => ({ port, protocol, service, status, program, version });
const OPENSSH = (v = '9.8') => svc('OpenSSH', v);
const UNIDENTIFIED = svc('Unknown', 'Unknown', 'open', 22, 'unknown');
// One host entry as the loader emits it. `services` omitted = the run recorded no service set (no oracle).
const host = (services, tcp = { tcpOpen: [22], tcpClosed: [] }) => [{ host: HOST, dir: 'd', pluginStatusRecorded: true,
  status: [{ id: '003', status: tcp ? 'ran' : 'timeout' }], ...(tcp ? { portScan: tcp } : {}),
  ...(services ? { services, udpServices: services.filter((s) => SD.isUdpTransport(s.protocol)) } : {}) }];
const delta = (base, baseHost, cur, curHost) => buildScanDelta({
  baseline: { record: run('A'), findings: base, pluginStatus: baseHost },
  current: { record: run('B'), findings: cur, pluginStatus: curHost },
});
const ncOf = (d, title = CVE) => d.notComparable.find((f) => f.title === title);

// ── THE VOCABULARY ────────────────────────────────────────────────────────────────────────────────────────────────────
test('no new token: the TCP rule reuses port-not-measured, and the declared reason set is unchanged in size', () => {
  assert.equal(PORT_NOT_MEASURED_REASON, 'port-not-measured');
  assert.equal(NOT_COMPARABLE_REASONS.length, 11, 'append-only under schema 1 — this rule adds nothing to it');
});

// ── FOURTH QUADRANT FIRST: nothing below may move ─────────────────────────────────────────────────────────────────────
test('(q1, first) an AGENT row on 22/tcp, open in both runs, the service unidentified now → RESOLVED: "open" suffices for an agent', () => {
  const d = delta([agentRow], host([OPENSSH()]), [], host([UNIDENTIFIED]));
  assert.equal(d.resolved.length, 1); assert.deepEqual(d.notComparable, []);
});

test('(q2) the CVE row\'s port CLOSED now → RESOLVED: a closed TCP port was measured', () => {
  const d = delta([cve()], host([OPENSSH()]), [], host([svc('Unknown', 'Unknown', 'closed', 22, 'unknown')], { tcpOpen: [], tcpClosed: [22] }));
  assert.equal(d.resolved.length, 1); assert.deepEqual(d.notComparable, []);
});

test('(q3) identified in BOTH runs, a different version → RESOLVED: the rule is silent where the service was identified', () => {
  const d = delta([cve()], host([OPENSSH('9.8')]), [], host([OPENSSH('9.9')]));
  assert.equal(d.resolved.length, 1); assert.deepEqual(d.notComparable, []);
});

test('(q4) identified in BOTH runs, the SAME program and version → vulnerability-data-changed, unchanged', () => {
  const d = delta([cve()], host([OPENSSH()]), [], host([OPENSSH()]));
  assert.equal(ncOf(d)?.reason, 'vulnerability-data-changed');
});

test('(q5) the other run recorded NO service set → silent (today\'s verdict): a TCP row with no oracle stays outside, as the TCP port rule does without 003', () => {
  const d = delta([cve()], host([OPENSSH()]), [], host(undefined));
  assert.equal(d.resolved.length, 1); assert.deepEqual(d.notComparable, []);
});

test('(q6) BOTH apply on the same port — the mapper recorded no_version_detected there AND the service is unidentified: the LOOKUP-GAP leg answers first', () => {
  const d = delta([cve()], host([OPENSSH()]), [lookupGap('no_version_detected')], host([svc('OpenSSH', 'Unknown')]));
  assert.equal(ncOf(d)?.reason, 'evidence-gap', 'the order is pinned, not relied on');
  assert.match(ncOf(d).detail, /no_version_detected/);
});

test('(q7) the shared decision: identified (program AND version) is measured; a UDP record never stands in for TCP', () => {
  assert.equal(measure(22, 'intelligence_engine', [OPENSSH()], 'this run').measured, true);
  const udpOnly = measure(22, 'intelligence_engine', [svc('OpenSSH', '9.8', 'open', 22, 'ssh', 'udp')], 'this run');
  assert.equal(udpOnly.measured, false);
  assert.equal(measure(22, 'intelligence_engine', null, 'this run').measured, null, 'no service set → no oracle → null, never false');
  assert.equal(measure(22, 'config_agent', [UNIDENTIFIED], 'this run').measured, true, 'an analysis agent: an open port is measured');
  // The shapes a re-implementation is likeliest to drift on (the audit seat's list):
  assert.equal(measure(22, 'intelligence_engine', [OPENSSH('9.8'), OPENSSH('9.9')], 'this run').measured, true, 'two identities on one port: identified');
  assert.equal(measure(22, 'intelligence_engine', [svc('OpenSSH', '9.8', 'closed')], 'this run').measured, false, 'a CLOSED record\'s identity is not an open service');
  assert.equal(measure(22, 'intelligence_engine', [svc('Unknown', '9.8')], 'this run').measured, false, 'a version alone is not an identity');
  assert.equal(measure(22, 'intelligence_engine', [], 'this run').measured, false, 'an empty set is a set: nothing on the port');
});

test('(q8) 443 keyed `https` by the HTTP probe (program Unknown) BESIDE `tcp` by the port scanner (identified): the rule looks past the unidentified record', () => {
  const https = svc('Unknown', 'Unknown', 'open', 443, 'http', 'https');
  const tcp443 = (v) => svc('nginx', v, 'open', 443, 'https', 'tcp');
  const row = cve({ port: 443, title: 'CVE-2025-23419 — tcp/https' });
  const d = delta([row], host([https, tcp443('1.24.0')], { tcpOpen: [443], tcpClosed: [] }), [], host([https, tcp443('1.27.0')], { tcpOpen: [443], tcpClosed: [] }));
  assert.equal(d.resolved.length, 1, 'identified on the tcp record: the version moved, a real fix');
  assert.deepEqual(d.notComparable, []);
  assert.equal(measure(443, 'intelligence_engine', [https, tcp443('1.27.0')], 'this run').measured, true);
  assert.equal(measure(443, 'intelligence_engine', [https], 'this run').measured, false, 'the https record alone identifies nothing');
});

// ── THE DEFECT ────────────────────────────────────────────────────────────────────────────────────────────────────────
test('the DEFECT: 002 left out — 22/tcp OPEN now and unidentified → the baseline\'s CVE row is port-not-measured, never RESOLVED', () => {
  const d = delta([cve()], host([OPENSSH()]), [], host([UNIDENTIFIED]));
  assert.equal(d.resolved.length, 0, 'an unidentified service gives the mapper nothing to match — its silence is not a fix');
  const nc = ncOf(d);
  assert.equal(nc?.reason, PORT_NOT_MEASURED_REASON);
  assert.match(nc.detail, /^22\/tcp on 192\.0\.2\.22 carries a CVE row in only one of the two runs, and in this run the TCP service on that port answered but was not identified \(program absent, version absent\)/);
  assert.match(nc.detail, /gives the CVE mapper nothing to match/);
  assert.doesNotMatch(nc.detail, /no answer inside its timeout|filtered/, 'the port ANSWERED — the TCP port rule\'s sentence would be false here');
});

test('the program known, the version not, and NO lookup-gap record in that run (a run before the mapper wrote one) → port-not-measured, the safe direction', () => {
  const d = delta([cve()], host([OPENSSH()]), [], host([svc('OpenSSH', 'Unknown')]));
  assert.equal(ncOf(d)?.reason, PORT_NOT_MEASURED_REASON);
  assert.match(ncOf(d).detail, /\(program OpenSSH, version absent\)/);
});

test('REVERSED: the CVE row in the CURRENT run only, the baseline\'s service unidentified → port-not-measured, never NEW', () => {
  const d = delta([], host([UNIDENTIFIED]), [cve()], host([OPENSSH()]));
  assert.equal(d.newFindings.length, 0);
  assert.equal(ncOf(d)?.reason, PORT_NOT_MEASURED_REASON);
  assert.match(ncOf(d).detail, /in the baseline run the TCP service on that port answered but was not identified/);
});
