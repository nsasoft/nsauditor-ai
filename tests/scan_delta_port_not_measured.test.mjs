// A PORT THAT STOPPED ANSWERING WAS NOT FIXED — `port-not-measured` (EE 1.1.0 build 12).
//
// Gate 2 on build 11, 2026-09-28: during the network scan the gateway answered nothing on 21 and 80 (the port
// scanner RAN and classified both FILTERED; a TCP connect five minutes later found both open). The 1.0.0 → build-11
// delta — the Pro `report --since` a client reads — called three findings on those ports RESOLVED: "FTP port open —
// verify no anonymous or default credentials", "No transport encryption: ftp on port 21", "No transport
// encryption: http on port 80". Build 9's `probe-not-measured` covers an OPEN port whose probe failed; nothing read
// a port that stopped answering. The rule (audit seat, on the operator's "fix before publish"): a port OPEN in the
// run that holds the finding and in NEITHER tcpOpen NOR tcpClosed of the other run was NOT MEASURED there — every
// row on it is NOT COMPARABLE, never RESOLVED and never NEW. A port in tcpClosed WAS measured: RESOLVED there stays.
//
// FOURTH QUADRANT FIRST: every leg that must not move is written, and green, before the defect leg.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  buildScanDelta, PORT_NOT_MEASURED_REASON, PROBE_NOT_MEASURED_REASON, INPUT_GAP_CLASS, NOT_COMPARABLE_REASONS,
} from '../utils/scan_delta.mjs';

const HOST = '192.0.2.1';
const run = (id) => ({
  schema: 1, runId: id, startedAt: '2026-09-21T00:00:00Z', finishedAt: '2026-09-21T01:00:00Z',
  hostsRequested: [HOST], hostsWritten: [{ host: HOST, dir: 'd' }], pluginsRequested: ['003', '004', '040'], portsRequested: null,
  tier: 'enterprise', ceVersion: '0.2.55', eeVersion: '1.1.0',
  kevLoaded: false, kevSnapshot: null, epssLoaded: false, epssSnapshot: null,
});
const row = (port, title, over = {}) => ({ host: HOST, port, plugin: 'crypto_agent', pluginName: 'crypto_agent',
  producerKind: 'agent', severity: 'MEDIUM', title, evidenceGap: false, gapClass: null, ...over });
const portGap = (port) => row(port, `[COVERAGE GAP] INPUT GAP — port ${port} was not measured`,
  { severity: 'INFO', evidenceGap: true, gapClass: INPUT_GAP_CLASS });
// A host's plugin status as the loader carries it (`model.plugins.byHost`), with the port scan beside it.
const scanned = (portScan, host = HOST) => [{ host, dir: 'd', pluginStatusRecorded: true,
  status: [{ id: '003', status: portScan ? 'ran' : 'timeout' }], portScan }];
const delta = (base, baseScan, cur, curScan) => buildScanDelta({
  baseline: { record: run('A'), findings: base, pluginStatus: baseScan },
  current: { record: run('B'), findings: cur, pluginStatus: curScan },
});
const FTP = 'No transport encryption: ftp on port 21';
const OPEN_21 = { tcpOpen: [21, 443], tcpClosed: [22] };

test('the reason is declared, by name, beside probe-not-measured', () => {
  assert.equal(PORT_NOT_MEASURED_REASON, 'port-not-measured');
  assert.ok(NOT_COMPARABLE_REASONS.includes(PORT_NOT_MEASURED_REASON));
  assert.ok(NOT_COMPARABLE_REASONS.indexOf(PORT_NOT_MEASURED_REASON) > NOT_COMPARABLE_REASONS.indexOf(PROBE_NOT_MEASURED_REASON));
});

// ── FOURTH QUADRANT FIRST ─────────────────────────────────────────────────────────────────────────────
test('(b) open in the baseline, CLOSED now → RESOLVED: a closed port was measured, and closing it is a fix', () => {
  const d = delta([row(21, FTP)], scanned(OPEN_21), [], scanned({ tcpOpen: [443], tcpClosed: [21, 22] }));
  assert.equal(d.resolved.length, 1);
  assert.deepEqual(d.notComparable, []);
});

test('(d) open in the baseline, OPEN now, the finding gone → RESOLVED', () => {
  const d = delta([row(21, FTP)], scanned(OPEN_21), [], scanned({ tcpOpen: [21, 443], tcpClosed: [22] }));
  assert.equal(d.resolved.length, 1);
  assert.deepEqual(d.notComparable, []);
});

test('(c) F6 PRECEDENCE, proven where BOTH rules could fire: a port gap AND the port filtered → probe-not-measured, not the new reason', () => {
  const d = delta([row(21, FTP)], scanned(OPEN_21), [portGap(21)], scanned({ tcpOpen: [443], tcpClosed: [], tcpFiltered: [21] }));
  assert.equal(d.notComparable.length, 1);
  assert.equal(d.notComparable[0].reason, PROBE_NOT_MEASURED_REASON);
});

test('(c) open now but the probe failed there → build 9\'s probe-not-measured, unchanged (it answers first)', () => {
  const d = delta([row(21, FTP)], scanned(OPEN_21), [portGap(21)], scanned({ tcpOpen: [21, 443], tcpClosed: [22] }));
  assert.equal(d.notComparable.length, 1);
  assert.equal(d.notComparable[0].reason, PROBE_NOT_MEASURED_REASON);
});

test('a port the holding run did NOT see open (a UDP service, a port no TCP list names) is untouched → RESOLVED', () => {
  const d = delta([row(161, 'SNMP community public accepted')], scanned(OPEN_21), [], scanned({ tcpOpen: [443], tcpClosed: [] }));
  assert.equal(d.resolved.length, 1, 'the rule keys on the HOLDING run\'s tcpOpen; 161 was never in it');
});

// ── THE DECLARED LIMIT (audit seat, CE-1): the other run's port scanner did NOT run on the host ─────────────────
// No port state exists to judge, and firing would set aside every producer's rows on every port — including a
// producer that measured the port itself. The NEIGHBOUR governs: 003's own rows are plugin-not-measured, and each
// agent's HOST-WIDE input-gap record (its service-feeding upstreams were not measured) makes that agent's rows not
// comparable. That is a claim about the neighbour, so it is PROVEN here, not asserted.
const agentHostGap = (plugin = 'crypto_agent') => row(0, `[COVERAGE GAP] INPUT GAP — ${plugin}'s upstream plugins were not measured`,
  { plugin, pluginName: plugin, severity: 'INFO', evidenceGap: true, gapClass: INPUT_GAP_CLASS, port: null });
test('LIMIT, the neighbour PROVEN: 003 timed out now, the agent recorded its host-wide input gap → NOT COMPARABLE through the existing leg, the new reason absent', () => {
  const d = delta([row(21, FTP)], scanned(OPEN_21), [agentHostGap()], scanned(null));
  assert.equal(d.resolved.length, 0);
  assert.equal(d.notComparable.length, 1);
  assert.equal(d.notComparable[0].reason, 'evidence-gap');
  assert.ok(!d.notComparable.some((nc) => nc.reason === PORT_NOT_MEASURED_REASON));
});
test('LIMIT, its negative — STATED, not fixed in build 12: the same current side WITHOUT the input-gap record (a pack from before those records existed) RESOLVES', () => {
  // Measured: with 003 not run and no agent input-gap record, nothing in the current run says port 21 was not
  // measured, so the baseline row reads RESOLVED. That is the pre-existing hole for packs written before build 9's
  // input-gap records; build 12 names it and does not close it.
  const d = delta([row(21, FTP)], scanned(OPEN_21), [], scanned(null));
  assert.equal(d.resolved.length, 1);
});

test('the baseline recorded no port scan at all → silent (a record written before the field existed)', () => {
  const d = delta([row(21, FTP)], [{ host: HOST, dir: 'd', pluginStatusRecorded: true, status: [] }], [],
    scanned({ tcpOpen: [443], tcpClosed: [] }));
  assert.equal(d.resolved.length, 1);
});

test('another host\'s port scan does not reach this host\'s row', () => {
  const d = delta([row(21, FTP)], scanned(OPEN_21), [], [...scanned({ tcpOpen: [443], tcpClosed: [] }, '192.0.2.99'),
    { host: HOST, dir: 'd2', pluginStatusRecorded: true, status: [{ id: '003', status: 'ran' }], portScan: { tcpOpen: [], tcpClosed: [21] } }]);
  assert.equal(d.resolved.length, 1, 'this host\'s own scan says 21 is CLOSED');
});

// ── THE DEFECT ────────────────────────────────────────────────────────────────────────────────────────
test('(a) open in the baseline, FILTERED now → NOT COMPARABLE port-not-measured, never RESOLVED', () => {
  const d = delta([row(21, FTP), row(80, 'No transport encryption: http on port 80')],
    scanned({ tcpOpen: [21, 80, 443], tcpClosed: [] }), [], scanned({ tcpOpen: [443], tcpClosed: [], tcpFiltered: [21, 80] }));
  assert.equal(d.resolved.length, 0);
  assert.equal(d.notComparable.length, 2);
  for (const nc of d.notComparable) {
    assert.equal(nc.reason, PORT_NOT_MEASURED_REASON);
    assert.equal(nc.direction, 'disappeared');
  }
  assert.match(d.notComparable[0].detail, /port 21 on 192\.0\.2\.1 was open in the run that holds this finding/);
  assert.match(d.notComparable[0].detail, /NOT reported as fixed or as new/);
});

test('(a) UNLISTED now — in no list at all, the port scanner did not probe it — is the same verdict', () => {
  const d = delta([row(21, FTP)], scanned(OPEN_21), [], scanned({ tcpOpen: [443], tcpClosed: [] }));
  assert.equal(d.resolved.length, 0);
  assert.equal(d.notComparable[0]?.reason, PORT_NOT_MEASURED_REASON);
});

test('(a) ANY producer\'s row on that port is set aside — a plugin\'s as well as an agent\'s', () => {
  const d = delta([row(21, 'FTP port open — verify no anonymous or default credentials', { plugin: '004', pluginName: 'ftp-banner', producerKind: null })],
    scanned(OPEN_21), [], scanned({ tcpOpen: [443], tcpClosed: [] }));
  assert.equal(d.notComparable[0]?.reason, PORT_NOT_MEASURED_REASON);
});

test('(a) the APPEARED direction: a row on a port the BASELINE did not measure is not NEW', () => {
  const d = delta([], scanned({ tcpOpen: [443], tcpClosed: [] }), [row(21, FTP)], scanned(OPEN_21));
  assert.equal(d.newFindings.length, 0);
  assert.equal(d.notComparable[0]?.reason, PORT_NOT_MEASURED_REASON);
  assert.equal(d.notComparable[0]?.direction, 'appeared');
});

// ── THE LOADER: the port-state oracle is what 003 RECORDED, and only where it ran ─────────────────────────────
import { portScanOf } from '../utils/report_inputs.mjs';
const raw003 = (status, result) => ({ pluginStatus: [{ id: '003', status }], results: [{ id: '003', result }] });
test('loader: 003 RAN with both lists → its open and closed ports (filtered is not carried: "neither" covers it)', () => {
  assert.deepEqual(portScanOf(raw003('ran', { tcpOpen: [21, '80'], tcpClosed: [22], tcpFiltered: [23] })),
    { tcpOpen: [21, 80], tcpClosed: [22] });
});
test('loader: 003 timed out / skipped / absent, or a list missing → null (no oracle — never "nothing open")', () => {
  assert.equal(portScanOf(raw003('timeout', { tcpOpen: [21], tcpClosed: [] })), null);
  assert.equal(portScanOf(raw003('skipped', { tcpOpen: [21], tcpClosed: [] })), null);
  assert.equal(portScanOf(raw003('ran', { tcpOpen: [21] })), null);
  assert.equal(portScanOf({ results: [{ id: '003', result: { tcpOpen: [21], tcpClosed: [] } }] }), null);
  assert.equal(portScanOf({}), null);
});
