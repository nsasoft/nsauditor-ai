// A UDP FINDING THAT VANISHED WAS NOT MEASURED AS FIXED — `port-not-measured` on a UDP transport (1.1.1 board).
//
// Found by the 1.1.0 web cascade's reviewer driving the shipped `buildScanDelta`: build 12's port rule reads the
// TCP ports the port scanner saw open, so an SNMP 161/udp finding that disappeared was filed RESOLVED with no caveat
// anywhere in the client's report. The audit seat's ruling (2026-09-29): NOT COMPARABLE, never RESOLVED, and the
// EXISTING token `port-not-measured` with a UDP-specific detail — no shipped UDP producer records a positive
// negative (SNMP records `no response`, DNS a timeout, 003's `udpClosed` is empty on every sealed raw), so UDP
// silence is indistinguishable from filtered and a vanished UDP row cannot be read as a fix.
//
// UDP-NESS IS READ OFF THE FINDING'S `protocol` — the queue producers' `target.protocol`, carried by the loader —
// and it is an APPLICATION LABEL, not a transport: real values are `udp`, `upnp`, `llmnr`, `mdns`, `dnssd`, `http`,
// `https`, `tcp`. So the decision is a DECLARED transport set, and a label outside it keeps today's verdict.
//
// FOURTH QUADRANT FIRST: every leg that must not move is written, and green, before the defect legs.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as SD from '../utils/scan_delta.mjs';
// A namespace import, so that before the rule exists each leg fails ON ITS OWN rather than the file failing to load.
const { buildScanDelta, PORT_NOT_MEASURED_REASON, INPUT_GAP_CLASS, NOT_COMPARABLE_REASONS } = SD;
const UDP_TRANSPORT_LABELS = SD.UDP_TRANSPORT_LABELS ?? [];
const isUdpTransport = (l) => { assert.equal(typeof SD.isUdpTransport, 'function', 'isUdpTransport is exported'); return SD.isUdpTransport(l); };
import { shapeHostFindings } from '../utils/report_inputs.mjs';

const HOST = '192.0.2.1';
const run = (id) => ({
  schema: 1, runId: id, startedAt: '2026-09-21T00:00:00Z', finishedAt: '2026-09-21T01:00:00Z',
  hostsRequested: [HOST], hostsWritten: [{ host: HOST, dir: 'd' }], pluginsRequested: ['003', '004', '040'], portsRequested: null,
  tier: 'enterprise', ceVersion: '0.2.55', eeVersion: '1.1.0',
  kevLoaded: false, kevSnapshot: null, epssLoaded: false, epssSnapshot: null,
});
const row = (port, title, over = {}) => ({ host: HOST, port, plugin: 'config_agent', pluginName: 'config_agent',
  producerKind: 'agent', severity: 'HIGH', title, evidenceGap: false, gapClass: null, protocol: null, ...over });
const udp = (port, title, over = {}) => row(port, title, { protocol: 'udp', ...over });
// `udpServices`: what that run's service set recorded about its UDP ports (the loader's `udpServicesOf`). Omitted = no
// oracle recorded, which the UDP rule reads CONSERVATIVELY (it fires) — a UDP row with no oracle has no measurement.
const scanned = (portScan, host = HOST, udpServices) => [{ host, dir: 'd', pluginStatusRecorded: true,
  status: [{ id: '003', status: portScan ? 'ran' : 'timeout' }], portScan, ...(udpServices ? { udpServices } : {}) }];
const us = (port, service, status, program = null, version = null, protocol = 'udp') => ({ port, protocol, service, status, program, version });
const ANSWERED_161 = [us(161, 'snmp', 'open', 'net-snmp', '5.9')];
const ANSWERED_53 = [us(53, 'dns', 'open', 'dnsmasq', '2.79')];
const delta = (base, baseScan, cur, curScan) => buildScanDelta({
  baseline: { record: run('A'), findings: base, pluginStatus: baseScan },
  current: { record: run('B'), findings: cur, pluginStatus: curScan },
});
const SNMP = 'SNMP community "public" accepted';
const DNS_CVE = 'CVE-2017-14491 — dnsmasq heap overflow — udp/dns';
const TCP_BOTH = { tcpOpen: [53, 443], tcpClosed: [22] };
const TCP_ONLY_TCP_SEEN = { tcpOpen: [443], tcpClosed: [22] };
// The TCP-only parenthetical that build 12's detail carries. It is TRUE on a TCP row and FALSE on a UDP one.
const TCP_ONLY_SENTENCE = /reads TCP ports the port scanner saw open/;

// ── THE VOCABULARY ────────────────────────────────────────────────────────────────────────────────────
test('no new token: the UDP rule reuses port-not-measured, and the declared reason set is unchanged in size', () => {
  assert.equal(PORT_NOT_MEASURED_REASON, 'port-not-measured');
  assert.equal(NOT_COMPARABLE_REASONS.length, 10, 'NOT_COMPARABLE_REASONS is append-only under schema 1 — this rule adds nothing to it');
  assert.ok(!NOT_COMPARABLE_REASONS.some((r) => /udp/i.test(r)));
});

test('the transport set is declared, frozen, lower-case, and every real UDP label measured on the corpus is in it', () => {
  assert.ok(Object.isFrozen(UDP_TRANSPORT_LABELS));
  for (const l of UDP_TRANSPORT_LABELS) assert.equal(l, l.toLowerCase());
  // Measured on the 192.168.1.1 queues (8 runs): `udp/53/dns` CVE rows, `upnp/1900`, `llmnr/5355`, `mdns/0`.
  for (const l of ['udp', 'upnp', 'llmnr', 'mdns']) assert.ok(isUdpTransport(l), `${l} is a UDP transport`);
});

test('isUdpTransport: TCP labels, application labels over TCP, null, empty and non-strings are NOT UDP (today\'s verdict)', () => {
  for (const l of ['tcp', 'http', 'https', 'ssh', 'ftp', 'smb', '', null, undefined, 161, {}]) {
    assert.equal(isUdpTransport(l), false, `${String(l)} must not read as UDP`);
  }
  assert.equal(isUdpTransport('UDP'), true, 'case-insensitive: a producer that upper-cases its label is still UDP');
});

// ── FOURTH QUADRANT FIRST: nothing below may move ─────────────────────────────────────────────────────
test('(q1) a TCP row whose port is OPEN in both runs and whose finding is gone → RESOLVED, unchanged', () => {
  const d = delta([row(443, 'Weak TLS cipher on 443', { protocol: 'tcp' })], scanned(TCP_BOTH), [], scanned(TCP_BOTH));
  assert.equal(d.resolved.length, 1);
  assert.deepEqual(d.notComparable, []);
});

test('(q1) a TCP row whose port is CLOSED now → RESOLVED, unchanged (a closed TCP port was measured)', () => {
  const d = delta([row(53, 'DNS zone transfer allowed', { protocol: 'tcp' })], scanned(TCP_BOTH), [],
    scanned({ tcpOpen: [443], tcpClosed: [22, 53] }));
  assert.equal(d.resolved.length, 1);
});

test('(q1) an application label over TCP (https) whose port stopped answering keeps build 12\'s TCP verdict AND its TCP detail', () => {
  const d = delta([row(443, 'Weak TLS cipher on 443', { protocol: 'https' })], scanned(TCP_BOTH), [],
    scanned({ tcpOpen: [53], tcpClosed: [22] }));
  assert.equal(d.notComparable.length, 1);
  assert.equal(d.notComparable[0].reason, PORT_NOT_MEASURED_REASON);
  assert.match(d.notComparable[0].detail, TCP_ONLY_SENTENCE, 'the TCP detail stays exactly where it is true');
});

test('(q2) a UDP row present in BOTH runs → unchanged, neither resolved nor not-comparable', () => {
  const d = delta([udp(161, SNMP)], scanned(TCP_BOTH), [udp(161, SNMP)], scanned(TCP_BOTH));
  assert.equal(d.resolved.length, 0);
  assert.equal(d.newFindings.length, 0);
  assert.deepEqual(d.notComparable, []);
  assert.equal(d.unchanged.length, 1);
});

test('(q3) the UDP row\'s PRODUCER recorded an evidence gap in the other run → evidence-gap from the prior leg, never stolen', () => {
  const gap = row(0, '[COVERAGE GAP] INPUT GAP — config_agent\'s upstream plugins were not measured',
    { severity: 'INFO', evidenceGap: true, gapClass: INPUT_GAP_CLASS, port: null });
  const d = delta([udp(161, SNMP)], scanned(TCP_BOTH), [gap], scanned(TCP_BOTH));
  assert.equal(d.notComparable.length, 1);
  assert.equal(d.notComparable[0].reason, 'evidence-gap');
});

test('(q3) a plugin-not-measured producer answers first too (the leg sits after every producer-wide leg)', () => {
  // ⚠️ THE PRODUCER IS ONE THE RUN REQUESTED ('040' ∈ pluginsRequested). The first draft used '007', which the run never
  // requested, so plugin-NOT-RUN answered and the leg could not fail for the reason its name gives (review, verified).
  const baseStatus = scanned(TCP_BOTH);
  const curStatus = [{ ...scanned(TCP_BOTH)[0], status: [{ id: '003', status: 'ran' }, { id: '040', status: 'timeout' }] }];
  const d = delta([udp(161, SNMP, { plugin: '040', pluginName: 'TLS Certificate Auditor', producerKind: 'plugin' })], baseStatus, [], curStatus);
  assert.equal(d.notComparable.length, 1);
  assert.equal(d.notComparable[0].reason, 'plugin-not-measured');
});

test('(q4) a PORTLESS row (host-wide, port null or 0) is untouched even when its label is UDP → RESOLVED', () => {
  for (const port of [null, 0]) {
    const d = delta([udp(port, 'mDNS responder answers from the WAN', { protocol: 'mdns' })], scanned(TCP_BOTH), [], scanned(TCP_BOTH));
    assert.equal(d.resolved.length, 1, `port ${port}: a host-wide row is not a port row`);
  }
});

test('(q5) the DECLARED LIMIT: a row carrying NO protocol (the plugin path — no plugin emits a transport) keeps today\'s verdict', () => {
  const d = delta([row(161, SNMP)], scanned(TCP_BOTH), [], scanned(TCP_ONLY_TCP_SEEN));
  assert.equal(d.resolved.length, 1, 'no transport on the row, so the UDP rule cannot fire — disclosed, not inferred');
});

test('(q6) a label outside the declared set keeps today\'s verdict (unknown is not UDP)', () => {
  const d = delta([row(9999, 'Custom service banner', { protocol: 'quic-ish' })], scanned(TCP_BOTH), [], scanned(TCP_BOTH));
  assert.equal(d.resolved.length, 1);
});

// ── THE EXEMPTION: the other run's UDP service ANSWERED on that port — a measurement, and the verdict stands ─────
// Found by an existing Enterprise leg (cve_row_title_identity: dnsmasq 2.78 → 2.79 on udp/53, a different CVE set):
// blanket refusal filed every CVE row not-comparable although the service answered in BOTH runs — that is how two
// versions, and two CVE sets, were read. The queue producers are pure over the concluder's service set, so "the other
// run's service set carries this UDP port as `open`" is exactly when a producer LOOKED at an answering service.
test('(q7) an AGENT row: the other run\'s SNMP answered on 161 → the absence is a measurement → RESOLVED, and the row shows its work', () => {
  const d = delta([udp(161, SNMP)], scanned(TCP_BOTH, HOST, ANSWERED_161), [], scanned(TCP_BOTH, HOST, ANSWERED_161));
  assert.equal(d.resolved.length, 1, 'SNMP answered and no longer accepts "public" — that is a fix');
  assert.deepEqual(d.notComparable, []);
  assert.equal(d.resolved[0].basisNote, '161/udp answered in the other run (snmp open · net-snmp 5.9)');
});

test('(q7) the APPEARED direction: the baseline\'s service answered on that port → NEW, with its basis', () => {
  const d = delta([], scanned(TCP_BOTH, HOST, ANSWERED_161), [udp(161, SNMP)], scanned(TCP_BOTH, HOST, ANSWERED_161));
  assert.equal(d.newFindings.length, 1);
  assert.match(d.newFindings[0].basisNote, /^161\/udp answered in the other run/);
});

test('(q7) the version-bump shape: the ENGINE\'s udp/53 rows, dnsmasq answered AND identified in both runs → resolved AND new', () => {
  const eng = { plugin: 'intelligence_engine', pluginName: 'intelligence_engine' };
  const d = delta([udp(53, 'CVE-2017-14491 — udp/dns', eng)], scanned(TCP_BOTH, HOST, [us(53, 'dns', 'open', 'dnsmasq', '2.78')]),
    [udp(53, 'CVE-2020-25681 — udp/dns', eng)], scanned(TCP_BOTH, HOST, ANSWERED_53));
  assert.equal(d.resolved.length, 1);
  assert.equal(d.newFindings.length, 1);
  assert.equal(d.resolved[0].basisNote, '53/udp answered in the other run (dns open · dnsmasq 2.79)');
});

test('(q7) a UDP port CLOSED in the other run WAS measured (the concluder writes `closed` only from ECONNREFUSED) → RESOLVED', () => {
  const d = delta([udp(161, SNMP)], scanned(TCP_BOTH, HOST, ANSWERED_161), [], scanned(TCP_BOTH, HOST, [us(161, 'snmp', 'closed')]));
  assert.equal(d.resolved.length, 1);
  assert.equal(d.resolved[0].basisNote, '161/udp closed in the other run (snmp closed)');
});

test('(a) THE ENGINE CONDITION: 53/udp answered but its program is `Unknown` → NOT COMPARABLE, the detail naming the unidentified program', () => {
  // The mapper returns nothing and records nothing for an unidentified service, so an `open` port alone would have
  // "resolved" every CVE row on it (the audit seat's condition — twenty dnsmasq rows on the router corpus).
  const eng = { plugin: 'intelligence_engine', pluginName: 'intelligence_engine' };
  const d = delta([udp(53, DNS_CVE, eng), udp(53, 'CVE-2017-14492 — udp/dns', eng)], scanned(TCP_BOTH, HOST, ANSWERED_53), [],
    scanned(TCP_BOTH, HOST, [us(53, 'dns', 'open', 'Unknown', null)]));
  assert.equal(d.resolved.length, 0);
  assert.equal(d.notComparable.length, 2);
  for (const nc of d.notComparable) {
    assert.equal(nc.reason, PORT_NOT_MEASURED_REASON);
    assert.match(nc.detail, /answered but was not identified \(program Unknown, version absent\)/);
    assert.match(nc.detail, /CVE mapper could not have matched it/);
  }
});

test('(a) THE ENGINE CONDITION: the placeholder version `Unknown` (what the producers write) is NO version → not comparable', () => {
  // The mapper queries a CPE with version `Unknown`, matches nothing and records nothing, so an exemption that took the
  // placeholder as a version would have "resolved" every CVE row on the port (review finding, verified HIGH).
  const eng = { plugin: 'intelligence_engine', pluginName: 'intelligence_engine' };
  const d = delta([udp(53, DNS_CVE, eng)], scanned(TCP_BOTH, HOST, ANSWERED_53), [], scanned(TCP_BOTH, HOST, [us(53, 'dns', 'open', 'dnsmasq', 'Unknown')]));
  assert.equal(d.resolved.length, 0);
  assert.equal(d.notComparable[0]?.reason, PORT_NOT_MEASURED_REASON);
  assert.match(d.notComparable[0].detail, /not identified \(program dnsmasq, version Unknown\)/, 'the detail quotes what the run recorded');
});

test('(a) the UNIDENTIFIED branch is explained as unidentified — never as silence (the service answered)', () => {
  const eng = { plugin: 'intelligence_engine', pluginName: 'intelligence_engine' };
  const d = delta([udp(53, DNS_CVE, eng)], scanned(TCP_BOTH, HOST, ANSWERED_53), [], scanned(TCP_BOTH, HOST, [us(53, 'dns', 'open', 'Unknown', 'Unknown')]));
  const detail = d.notComparable[0]?.detail ?? '';
  assert.match(detail, /answered but was not identified/);
  assert.match(detail, /nothing to match/);
  assert.doesNotMatch(detail, /UDP silence|stopped answering/, 'the service did not go silent');
});

test('(a) THE ENGINE CONDITION, version half: a known program with NO version → not comparable', () => {
  const eng = { plugin: 'intelligence_engine', pluginName: 'intelligence_engine' };
  const d = delta([udp(53, DNS_CVE, eng)], scanned(TCP_BOTH, HOST, ANSWERED_53), [], scanned(TCP_BOTH, HOST, [us(53, 'dns', 'open', 'dnsmasq', null)]));
  assert.equal(d.notComparable[0]?.reason, PORT_NOT_MEASURED_REASON);
});

test('(q7) the engine condition does NOT reach an AGENT row: `open` suffices for an agent even with program Unknown', () => {
  const d = delta([udp(161, SNMP)], scanned(TCP_BOTH, HOST, ANSWERED_161), [], scanned(TCP_BOTH, HOST, [us(161, 'snmp', 'open', 'Unknown')]));
  assert.equal(d.resolved.length, 1);
  assert.equal(d.resolved[0].basisNote, '161/udp answered in the other run (snmp open)');
});

test('(a) the other run\'s service did NOT answer on that port (`no response`) → NOT COMPARABLE, the status named', () => {
  const d = delta([udp(161, SNMP)], scanned(TCP_BOTH, HOST, ANSWERED_161), [], scanned(TCP_BOTH, HOST, [us(161, 'snmp', 'no response')]));
  assert.equal(d.resolved.length, 0);
  assert.equal(d.notComparable[0]?.reason, PORT_NOT_MEASURED_REASON);
  assert.match(d.notComparable[0].detail, /no UDP service answered on that port \(snmp no response\)/);
});

test('(a) the port absent from the other run\'s set → NOT COMPARABLE, said as such', () => {
  const d = delta([udp(161, SNMP)], scanned(TCP_BOTH, HOST, ANSWERED_161), [], scanned(TCP_BOTH, HOST, ANSWERED_53));
  assert.match(d.notComparable[0]?.detail ?? '', /service set holds no UDP service on that port/);
});

test('(a) NO service set recorded on the other side → NOT COMPARABLE, and the detail says it was the oracle that was absent', () => {
  const d = delta([udp(161, SNMP)], scanned(TCP_BOTH, HOST, ANSWERED_161), [], scanned(TCP_BOTH));
  assert.match(d.notComparable[0]?.detail ?? '', /recorded no service set/);
});

test('(a) ANOTHER host\'s answer does not reach this host\'s row', () => {
  const d = delta([udp(161, SNMP)], scanned(TCP_BOTH, HOST, ANSWERED_161), [],
    [...scanned(TCP_BOTH, HOST, []), ...scanned(TCP_BOTH, '192.0.2.99', ANSWERED_161)]);
  assert.equal(d.notComparable[0]?.reason, PORT_NOT_MEASURED_REASON);
});

test('(q8) the other run carries the UDP oracle but NO port scan (003 timed out) → a TCP row keeps today\'s verdict, no crash', () => {
  // The two oracles are independent: an entry holding only `udpServices` must not reach the TCP rule's sets.
  const tcpRow = row(21, 'No transport encryption: ftp on port 21', { protocol: 'tcp' });
  const d = delta([tcpRow], scanned({ tcpOpen: [21], tcpClosed: [] }, HOST, []), [], scanned(null, HOST, []));
  assert.equal(d.resolved.length, 1, 'no TCP oracle on the other side → the TCP rule is silent, as in build 12');
});

// ── THE DEFECT ────────────────────────────────────────────────────────────────────────────────────────
test('(a) SNMP 161/udp vanished while its producer ran → NOT COMPARABLE port-not-measured, never RESOLVED', () => {
  const d = delta([udp(161, SNMP)], scanned(TCP_BOTH), [], scanned(TCP_BOTH));
  assert.equal(d.resolved.length, 0);
  assert.equal(d.notComparable.length, 1);
  const nc = d.notComparable[0];
  assert.equal(nc.reason, PORT_NOT_MEASURED_REASON);
  assert.equal(nc.direction, 'disappeared');
  assert.match(nc.detail, /161\/udp on 192\.0\.2\.1/);
  assert.match(nc.detail, /UDP/);
  assert.match(nc.detail, /NOT reported as fixed or as new/);
  assert.doesNotMatch(nc.detail, TCP_ONLY_SENTENCE, 'the TCP-only sentence is false on a UDP row and must not appear on it');
});

test('(a) udp/53 with TCP/53 in tcpClosed now → NOT COMPARABLE (a closed TCP port says nothing about UDP DNS)', () => {
  const d = delta([udp(53, DNS_CVE, { plugin: 'intelligence_engine', pluginName: 'intelligence_engine' })],
    scanned(TCP_BOTH), [], scanned({ tcpOpen: [443], tcpClosed: [22, 53] }));
  assert.equal(d.resolved.length, 0);
  assert.equal(d.notComparable[0]?.reason, PORT_NOT_MEASURED_REASON);
  assert.match(d.notComparable[0].detail, /53\/udp/);
});

test('(a) udp/53 with TCP/53 FILTERED now → the UDP detail, never build 12\'s TCP one (the TCP leg is gated to non-UDP rows)', () => {
  const d = delta([udp(53, DNS_CVE, { plugin: 'intelligence_engine', pluginName: 'intelligence_engine' })],
    scanned(TCP_BOTH), [], scanned({ tcpOpen: [443], tcpClosed: [22], tcpFiltered: [53] }));
  assert.equal(d.notComparable.length, 1);
  assert.equal(d.notComparable[0].reason, PORT_NOT_MEASURED_REASON);
  assert.doesNotMatch(d.notComparable[0].detail, TCP_ONLY_SENTENCE);
  assert.match(d.notComparable[0].detail, /53\/udp/);
});

test('(a) the 003 of the other run did NOT run → the UDP rule still fires (it never read 003; its precondition is the producer, which the prior legs own)', () => {
  const d = delta([udp(161, SNMP)], scanned(TCP_BOTH), [], scanned(null));
  assert.equal(d.resolved.length, 0);
  assert.equal(d.notComparable[0]?.reason, PORT_NOT_MEASURED_REASON);
});

test('(a) every label in the declared set fires; the row keeps its label in the detail', () => {
  assert.ok(UDP_TRANSPORT_LABELS.length >= 4, 'non-vacuity: an empty set would make this loop prove nothing');
  for (const label of UDP_TRANSPORT_LABELS) {
    const d = delta([udp(1900, `a finding over ${label}`, { protocol: label })], scanned(TCP_BOTH), [], scanned(TCP_BOTH));
    assert.equal(d.notComparable[0]?.reason, PORT_NOT_MEASURED_REASON, `${label} must not resolve`);
    assert.equal(d.resolved.length, 0);
    assert.match(d.notComparable[0].detail, new RegExp(`\\(${label}\\)`), 'the detail names the label it read');
  }
});

test('(a) the APPEARED direction: a UDP row new in the current run is not NEW (the baseline\'s UDP silence was not a measurement either)', () => {
  const d = delta([], scanned(TCP_BOTH), [udp(161, SNMP)], scanned(TCP_BOTH));
  assert.equal(d.newFindings.length, 0);
  assert.equal(d.notComparable[0]?.reason, PORT_NOT_MEASURED_REASON);
  assert.equal(d.notComparable[0]?.direction, 'appeared');
});

test('the resolved count moves by EXACTLY the UDP rows on a mixed pair, and every produced reason is declared', () => {
  const base = [udp(161, SNMP), udp(53, DNS_CVE, { plugin: 'intelligence_engine', pluginName: 'intelligence_engine' }),
    row(443, 'Weak TLS cipher on 443', { protocol: 'tcp' }), row(22, 'SSH password auth enabled', { protocol: 'tcp' })];
  const d = delta(base, scanned(TCP_BOTH), [], scanned({ tcpOpen: [53, 443], tcpClosed: [22] }));
  assert.equal(d.resolved.length, 2, 'the two TCP rows on measured ports still resolve');
  assert.deepEqual(d.resolved.map((f) => f.port).sort((a, b) => a - b), [22, 443]);
  assert.equal(d.notComparable.length, 2);
  for (const nc of d.notComparable) assert.ok(NOT_COMPARABLE_REASONS.includes(nc.reason));
});

// ── THE LOADER: what a run recorded about its UDP ports — the concluder's service set, UDP-transport labels only ─
// Measured over 27 real router raws: udp/53 dns `open` ×22 / `unknown` ×5 · snmp 161 `no response` ×19 · netbios 137
// `unknown` · llmnr 5355 `unknown` · mdns/0 `unknown` · upnp 1900 `open` ×6 / `unknown` ×2 — never `closed`.
import * as RI from '../utils/report_inputs.mjs';
const udpServicesOf = (raw) => { assert.equal(typeof RI.udpServicesOf, 'function', 'udpServicesOf is exported'); return RI.udpServicesOf(raw); };
test('loader: udpServicesOf keeps UDP-transport services with port > 0, verbatim status / program / version', () => {
  const raw = { conclusion: { result: { services: [
    { port: 53, protocol: 'udp', service: 'dns', status: 'open', program: 'dnsmasq', version: '2.78' },
    { port: 161, protocol: 'udp', service: 'snmp', status: 'no response' },
    { port: 1900, protocol: 'upnp', service: 'os', status: 'open', program: 'Unknown' },
    { port: 443, protocol: 'tcp', service: 'https', status: 'open' },
    { port: 0, protocol: 'mdns', service: 'mdns', status: 'open' },
  ] } } };
  assert.deepEqual(udpServicesOf(raw), [
    { port: 53, protocol: 'udp', service: 'dns', status: 'open', program: 'dnsmasq', version: '2.78' },
    { port: 161, protocol: 'udp', service: 'snmp', status: 'no response', program: null, version: null },
    { port: 1900, protocol: 'upnp', service: 'os', status: 'open', program: 'Unknown', version: null },
  ]);
});
test('loader: no service set recorded → null (no oracle — never "nothing answered"); an EMPTY set is a measurement', () => {
  assert.equal(udpServicesOf({}), null);
  assert.equal(udpServicesOf({ conclusion: { result: {} } }), null);
  assert.deepEqual(udpServicesOf({ conclusion: { result: { services: [] } } }), []);
});
test('NEGATIVE CONTROL through the loader: `53/tcp open` never stands in for `53/udp` — TCP 53 open, UDP 53 unknown → the rule FIRES', () => {
  const raw = { conclusion: { result: { services: [
    { port: 53, protocol: 'tcp', service: 'dns', status: 'open', program: 'dnsmasq', version: '2.79' },
    { port: 53, protocol: 'udp', service: 'dns', status: 'unknown' },
  ] } } };
  const eng = { plugin: 'intelligence_engine', pluginName: 'intelligence_engine' };
  const d = delta([udp(53, DNS_CVE, eng)], scanned(TCP_BOTH, HOST, ANSWERED_53), [], scanned(TCP_BOTH, HOST, udpServicesOf(raw)));
  assert.equal(d.resolved.length, 0);
  assert.match(d.notComparable[0]?.detail ?? '', /no UDP service answered on that port \(dns unknown\)/);
});

// ── THE LOADER: the protocol the queue producer wrote reaches the delta row ──────────────────────────────
test('loader: a queue entry\'s target.protocol reaches the shaped row as `protocol`, verbatim', () => {
  const q = [{ id: 'F-1', title: SNMP, severity: 'HIGH', category: 'CONFIG', status: 'CONFIRMED',
    target: { host: HOST, port: 161, protocol: 'udp', service: 'snmp' }, evidence: { source: 'config_agent', cve: [], raw: {} } }];
  const rows = shapeHostFindings(HOST, { results: [] }, q);
  assert.equal(rows.length, 1);
  assert.equal(rows[0].protocol, 'udp');
  assert.equal(rows[0].port, 161);
});

test('loader: a queue entry with no target.protocol carries protocol null — never a guessed transport', () => {
  const q = [{ id: 'F-2', title: 'x', severity: 'LOW', category: 'CONFIG', status: 'CONFIRMED',
    target: { host: HOST, port: 161 }, evidence: { source: 'config_agent', cve: [], raw: {} } }];
  assert.equal(shapeHostFindings(HOST, { results: [] }, q)[0].protocol, null);
});

test('loader: the PLUGIN path carries no transport — a rule protocol in details (an SG rule) is not read as one', () => {
  const raw = { results: [{ id: '1170', result: { up: true, findings: [
    { title: 'SG allows 0.0.0.0/0 on 161', severity: 'HIGH', port: 161, details: { protocol: 'udp', fromPort: 161, toPort: 161 } },
  ] } }] };
  const rows = shapeHostFindings(HOST, raw, []);
  assert.equal(rows.length, 1);
  assert.equal(rows[0].protocol ?? null, null, 'details.protocol on a cloud rule is the RULE\'s protocol, not a service transport');
});
