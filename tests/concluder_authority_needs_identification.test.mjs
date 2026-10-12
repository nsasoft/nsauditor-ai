// tests/concluder_authority_needs_identification.test.mjs
// ─────────────────────────────────────────────────────────────────────────────
// EE 2.0.0 / Community 1.0.0, 4(b) — ON TCP, AN AUTHORITATIVE ROW NEEDS IDENTIFICATION (the architect seat's rulings,
// tasks/release-2.0.0/f4-phantom-rows-design.md in the Enterprise repo).
//
// An authoritative adapter row says what a port IS, and its `status` is the contract: 'open' means the adapter saw a
// protocol-specific response; every other status is non-identification. The concluder used to push an unidentified
// authoritative row as a new service, or let it replace the identity of an open one: re-concluding the 520 raws of the
// evidence tree at HEAD, 501 such TCP rows sat in `services` (tls_scanner's refused 465/563/993/995/443, OpenSearch's
// 5601/9200, NetBIOS's 445). They now leave `services` for evidence, with a reason.
//
// FOURTH QUADRANT FIRST: an IDENTIFIED authoritative row still lands, and still wins identity.
// The census is DERIVED: every adapter the concluder consults is driven with a non-answer, and the rows that come back
// say which are authoritative and under which source — never a hand list. An adapter that answers silence with 'open'
// fails the census by name, so the merge layer is never the only line.
// UDP is a DECLARED LIMIT, pinned below: a UDP non-answer is open|filtered by the protocol, and the delta's UDP
// measurement reads those rows.
// ─────────────────────────────────────────────────────────────────────────────
import { test } from 'node:test';
import assert from 'node:assert/strict';
import concluder, { _ownDirectoryAdapters } from '../plugins/result_concluder.mjs';
import { keyOf, normalizeService } from '../utils/conclusion_utils.mjs';
import { buildScanDelta, tcpServiceMeasurement, PORT_NOT_MEASURED_REASON } from '../utils/scan_delta.mjs';

const wrap = (id, name, result) => ({ id, name, result });
const tcpRow = (port, info, extra = {}) => ({ probe_protocol: 'tcp', probe_port: port, probe_info: info, response_banner: null, ...extra });
const svc = (res, k) => res.services.find((s) => keyOf(s) === k);
const reasonRows = (res, k) => res.evidence.filter((e) => e.reason && `${e.protocol}:${e.port}` === k);

const tls = (rows) => wrap('011', 'TLS Scanner', { up: rows.some((r) => /TLS: /.test(r.probe_info)), data: rows });
const opensearch = (rows) => wrap('012', 'OpenSearch Scanner', { up: false, data: rows });
const portScanner = ({ open = [], closed = [] }) => wrap('003', 'Port Scanner', {
  up: open.length > 0,
  tcpOpen: open, tcpClosed: closed,
  data: [...open.map((p) => tcpRow(p, 'Connected', { status: 'open' })), ...closed.map((p) => tcpRow(p, 'Connection refused', { status: 'closed' }))],
});
const IDENTIFIED_TLS = 'TLS: TLSv1.3 TLS_AES_256_GCM_SHA384';

// ── THE CENSUS ───────────────────────────────────────────────────────────────────────────────────
const NON_ANSWERS = ['Connection timed out', 'Error: Timeout', 'Connection refused', null];

/**
 * Drive every adapter in `registry` with non-answers and read back which TCP rows are authoritative. The candidate ports
 * are derived too: what each adapter emits for an empty non-answer, plus every declared authoritativePorts key.
 * @returns {{ authoritative: Map<string, Set<string>>, violations: string[], udp: string[] }}
 */
export async function nonAnswerCensus(registry) {
  const entries = [...registry.values()].filter((e) => e && typeof e.conclude === 'function' && !e.cloudProvider);
  const drive = async (e, result) => { try { return (await e.conclude({ host: '192.0.2.10', result })) || []; } catch { return []; } };
  const ports = new Set();
  for (const e of entries) {
    for (const r of await drive(e, { up: false, data: [] })) if (String(r?.protocol || 'tcp').toLowerCase() === 'tcp' && Number(r?.port) > 0) ports.add(Number(r.port));
    for (const k of (e.authoritativePorts instanceof Set ? e.authoritativePorts : [])) if (/^tcp:\d+$/.test(k)) ports.add(Number(k.slice(4)));
  }
  const authoritative = new Map(); const violations = []; const udp = [];
  for (const e of entries) {
    const authSet = e.authoritativePorts instanceof Set ? e.authoritativePorts : null;
    const results = [{ up: false, data: [] }, ...NON_ANSWERS.map((info) => ({ up: false, data: [...ports].map((p) => tcpRow(p, info)) }))];
    for (const result of results) {
      for (const raw of await drive(e, result)) {
        const rec = normalizeService({ ...raw });
        const isAuth = (authSet && authSet.has(keyOf(rec))) || raw?.authoritative === true;
        if (!isAuth) continue;
        if (rec.protocol !== 'tcp') { udp.push(`${e.id} ${rec.source} ${keyOf(rec)} ${rec.status}`); continue; }
        if (!authoritative.has(e.id)) authoritative.set(e.id, new Set());
        authoritative.get(e.id).add(rec.source);
        if (rec.status === 'open') violations.push(`${e.id} (${rec.source}) answered a non-answer on ${keyOf(rec)} with status 'open'`);
      }
    }
  }
  return { authoritative, violations: [...new Set(violations)], udp };
}

test('(census) every adapter the concluder consults answers silence with something other than "open" — derived, not listed', async () => {
  const registry = await _ownDirectoryAdapters();
  assert.ok(registry.size > 20, `the concluder's own registry has ${registry.size} adapters — the reader is broken`);
  const { authoritative, violations, udp } = await nonAnswerCensus(registry);
  assert.deepEqual(violations, []);
  // The derived set has both kinds — an adapter declaring authoritativePorts, and one whose rows carry the flag alone —
  // or the census is not reaching what the rule keys on.
  const declaring = [...registry.values()].filter((e) => e.authoritativePorts instanceof Set && [...e.authoritativePorts].some((k) => k.startsWith('tcp:')));
  assert.ok(declaring.length > 0);
  for (const e of declaring) assert.ok(authoritative.has(e.id), `${e.id} declares TCP authoritativePorts and the census never drove a row out of it`);
  const flagOnly = [...authoritative.keys()].filter((id) => !declaring.some((e) => e.id === id));
  assert.ok(flagOnly.length > 0, 'no adapter was found authoritative by its row flag alone — the census is not reading the flag');
  console.log(`[census] TCP-authoritative adapters, sources read from their rows: ${[...authoritative].map(([id, s]) => `${id}=${[...s].join('/')}`).join(' · ')}`);
  console.log(`[census] UDP authoritative non-answer rows (the declared limit, recorded not judged): ${[...new Set(udp)].join(' · ') || 'none'}`);
});

test('(census) a planted adapter that answers silence with "open" fails by NAME — per-row flag and declared set alike', async () => {
  const own = await _ownDirectoryAdapters();
  const planted = new Map(own);
  planted.set('9901', { id: '9901', conclude: () => [{ port: 7001, protocol: 'tcp', service: 'x', status: 'open', source: 'planted-flag', authoritative: true }] });
  planted.set('9902', { id: '9902', authoritativePorts: new Set(['tcp:7002']), conclude: () => [{ port: 7002, protocol: 'tcp', service: 'y', status: 'open', source: 'planted-set' }] });
  const { violations } = await nonAnswerCensus(planted);
  assert.equal(violations.length, 2, violations.join('\n'));
  assert.match(violations.find((v) => v.startsWith('9901')), /planted-flag.*tcp:7001.*'open'/);
  assert.match(violations.find((v) => v.startsWith('9902')), /planted-set.*tcp:7002.*'open'/);
});

// ── FOURTH QUADRANT: an identified authoritative row behaves exactly as before ──────────────────────
test('(first) an IDENTIFIED authoritative row on a port nobody else scanned still lands as a service', async () => {
  const res = await concluder.run([tls([tcpRow(443, IDENTIFIED_TLS)])]);
  const s = svc(res, 'tcp:443');
  assert.equal(s?.status, 'open');
  assert.equal(s.program, 'TLS');
  assert.equal(s.measurementConflict, undefined);
});

test('(first) an IDENTIFIED authoritative row still replaces the port scanner\'s identity', async () => {
  const res = await concluder.run([portScanner({ open: [443] }), tls([tcpRow(443, IDENTIFIED_TLS)])]);
  const s = svc(res, 'tcp:443');
  assert.equal(s.status, 'open');
  assert.equal(s.program, 'TLS');
  assert.equal(s.service, 'https');
  assert.equal(s.source, 'tls-scanner');
});

// ── THE RULE ─────────────────────────────────────────────────────────────────────────────────────
test('F-4: an UNIDENTIFIED authoritative row with no service under it is evidence with its reason, not a service', async () => {
  const res = await concluder.run([opensearch([tcpRow(9200, 'Connection refused'), tcpRow(5601, null)])]);
  assert.equal(svc(res, 'tcp:9200'), undefined);
  assert.equal(svc(res, 'tcp:5601'), undefined);
  for (const k of ['tcp:9200', 'tcp:5601']) {
    const [row] = reasonRows(res, k);
    assert.equal(row?.from, 'opensearch-scanner');
    assert.equal(row.reason, 'not identified by its adapter (status unknown)');
  }
});

test('an UNIDENTIFIED authoritative row over an open service adds evidence and fills blanks — never identity (condition 1)', async () => {
  // An open 9200 whose program is NULL, from a non-authoritative adapter: the shape where blank-fill would hand
  // "OpenSearch" to a port the OpenSearch probe failed to identify.
  const adapters = new Map([['9910', { id: '9910', conclude: () => [{ port: 9200, protocol: 'tcp', service: 'unknown', program: null, version: null, status: 'open', info: null, banner: null, source: 'listener', evidence: [{ n: 1 }], authoritative: false }] }]]);
  const results = [wrap('9910', 'Listener', { up: true }), opensearch([tcpRow(9200, 'HTTP 401 Unauthorized', { response_banner: 'WWW-Authenticate: Basic' })])];
  const res = await concluder.run(results, { adapters });
  const s = svc(res, 'tcp:9200');
  assert.equal(s.status, 'open');
  assert.equal(s.program, null, 'blank-fill handed the unidentified adapter\'s program to the open port');
  assert.equal(s.service, 'unknown');
  assert.equal(s.version, null);
  assert.equal(s.cpe, null);
  assert.equal(s.source, 'listener');
  assert.equal(s.info, 'HTTP 401 Unauthorized', 'a blank info is filled');
  assert.equal(s.banner, 'WWW-Authenticate: Basic', 'a blank banner is filled');
  assert.ok(s.evidence.length > 1, 'the adapter\'s evidence is added');
  assert.equal(reasonRows(res, 'tcp:9200').length, 0, 'merged onto a service, so no reason row');
});

test('an UNIDENTIFIED authoritative row cannot re-identify an IDENTIFIED authoritative one either', async () => {
  const adapters = new Map([['9911', { id: '9911', conclude: () => [{ port: 8443, protocol: 'tcp', service: 'svc-a', program: 'ProgramA', version: '1.0', status: 'open', source: 'probe-a', authoritative: true }] }],
    ['9912', { id: '9912', conclude: () => [{ port: 8443, protocol: 'tcp', service: 'svc-b', program: 'ProgramB', version: '9.9', status: 'unknown', source: 'probe-b', authoritative: true, extraFlag: true }] }]]);
  for (const order of [['9911', '9912'], ['9912', '9911']]) {
    const res = await concluder.run(order.map((id) => wrap(id, id, { up: true })), { adapters });
    const s = svc(res, 'tcp:8443');
    assert.deepEqual([s.service, s.program, s.version, s.source, s.status], ['svc-a', 'ProgramA', '1.0', 'probe-a', 'open'], `order ${order}`);
    assert.equal(s.extraFlag, true, 'a non-identity field the identified row lacks is carried');
  }
});

test('an IDENTIFIED row on a port the port scanner measured CLOSED stays a service and names both measurements (leg 5 as ruled)', async () => {
  const first = await concluder.run([portScanner({ closed: [443] }), tls([tcpRow(443, IDENTIFIED_TLS)])]);
  const s = svc(first, 'tcp:443');
  assert.equal(s?.status, 'open');
  assert.deepEqual(s.measurementConflict, { portScanner: 'closed', adapter: 'open', adapterSource: 'tls-scanner', resultsOrder: 'port-scanner-first' });
  const second = await concluder.run([tls([tcpRow(443, IDENTIFIED_TLS)]), portScanner({ closed: [443] })]);
  assert.equal(svc(second, 'tcp:443').measurementConflict.resultsOrder, 'adapter-first');
});

test('an UNIDENTIFIED row on a port the port scanner measured closed is evidence with THAT reason', async () => {
  const res = await concluder.run([portScanner({ open: [443], closed: [465] }), tls([tcpRow(443, IDENTIFIED_TLS), tcpRow(465, 'Error: connect ECONNREFUSED')])]);
  assert.equal(svc(res, 'tcp:465'), undefined);
  assert.equal(reasonRows(res, 'tcp:465')[0]?.reason, 'port measured closed by the port scanner (003)');
  assert.equal(svc(res, 'tcp:443').status, 'open');
});

test('result order does not matter — the port scanner before the adapters or after them', async () => {
  const set = [portScanner({ open: [443, 9200], closed: [465, 5601] }),
    tls([tcpRow(443, IDENTIFIED_TLS), tcpRow(465, 'Error: connect ECONNREFUSED'), tcpRow(993, 'Error: timeout')]),
    opensearch([tcpRow(9200, 'Connection refused'), tcpRow(5601, null)])];
  const view = (res) => ({ services: res.services.map((s) => [keyOf(s), s.status, s.program, s.source]),
    reasons: res.evidence.filter((e) => e.reason).map((e) => `${e.from} ${e.protocol}:${e.port} ${e.reason}`).sort() });
  const a = view(await concluder.run(set));
  const b = view(await concluder.run([...set].reverse()));
  assert.deepEqual(a, b);
  assert.deepEqual(a.services.map(([k]) => k), ['tcp:443', 'tcp:9200']);
  assert.equal(a.services[1][2], 'Unknown', 'the open 9200 keeps the port scanner\'s identity; the refused OpenSearch probe only adds evidence');
  assert.deepEqual(a.reasons, [
    'opensearch-scanner tcp:5601 port measured closed by the port scanner (003)',
    'tls-scanner tcp:465 port measured closed by the port scanner (003)',
    'tls-scanner tcp:993 not identified by its adapter (status closed)',
  ]);
});

test('DECLARED LIMIT — UDP rows are untouched: an SNMP no-response stays a service row (the delta reads it)', async () => {
  const res = await concluder.run([wrap('007', 'SNMP Scanner', { up: false, data: [{ probe_protocol: 'udp', probe_port: 161, probe_info: 'No SNMP response' }] })]);
  const s = svc(res, 'udp:161');
  assert.equal(s?.status, 'no response', 'if UDP rows ever leave services, teach the delta\'s UDP measurement to read their new home FIRST');
  assert.equal(reasonRows(res, 'udp:161').length, 0);
});

// ── THE DELTA ACROSS THE STRADDLE (the architect seat's Q3: an IDENTITY_BASIS_CHANGED_AT entry only for a consumer the
// measurement shows moving) ───────────────────────────────────────────────────────────────────────────────────────
// The inputs: 003 measured 9200 open and 5601 closed; a non-authoritative probe identified 9200 as Elasticsearch 7.10.2;
// the OpenSearch probe identified neither. BEFORE is the concluder's output for exactly these inputs at CE 452df92 (the
// last commit before 4(b)), measured by running that tree's concluder — pinned as a literal because no shipped code
// produces it any more. AFTER is driven through today's concluder. At 452df92 the unidentified OpenSearch row replaced
// an IDENTIFIED identity on the open port (Elasticsearch 7.10.2 → OpenSearch, no version) and listed the refused 5601.
const STRADDLE_HOST = '192.0.2.40';
const BEFORE_452DF92 = [
  { port: 5601, protocol: 'tcp', service: 'opensearch-dashboards', status: 'unknown', program: 'OpenSearch', version: null },
  { port: 9200, protocol: 'tcp', service: 'opensearch', status: 'open', program: 'OpenSearch', version: null },
];
async function straddleAfter() {
  const adapters = new Map([['9920', { id: '9920', conclude: () => [{ port: 9200, protocol: 'tcp', service: 'http', program: 'Elasticsearch', version: '7.10.2', status: 'open', source: 'listener', authoritative: false }] }]]);
  const res = await concluder.run([portScanner({ open: [9200], closed: [5601] }), wrap('9920', 'Listener', { up: true }),
    opensearch([tcpRow(9200, 'HTTP 401'), tcpRow(5601, 'Connection refused')])], { adapters });
  return res.services.map(({ port, protocol, service, status, program, version }) => ({ port, protocol, service, status, program, version }));
}
const straddleRun = (id, ceVersion) => ({ schema: 1, runId: id, startedAt: '2026-10-12T00:00:00Z', finishedAt: '2026-10-12T01:00:00Z',
  hostsRequested: [STRADDLE_HOST], hostsWritten: [{ host: STRADDLE_HOST, dir: 'd' }], pluginsRequested: ['003'], portsRequested: null,
  tier: 'enterprise', ceVersion, eeVersion: ceVersion === '1.0.0' ? '2.0.0' : '1.3.0', kevLoaded: false, kevSnapshot: null, epssLoaded: false, epssSnapshot: null });
const straddleHost = (services) => [{ host: STRADDLE_HOST, dir: 'd', pluginStatusRecorded: true, status: [{ id: '003', status: 'ran' }],
  portScan: { tcpOpen: [9200], tcpClosed: [5601] }, services, udpServices: [] }];
const engineRow = (port, title, gapClass = null, severity = 'HIGH') => ({ host: STRADDLE_HOST, port, protocol: 'tcp', plugin: 'intelligence_engine',
  pluginName: 'intelligence_engine', producerKind: 'agent', severity, title, evidenceGap: false, gapClass });
const straddle = async (base, cur) => buildScanDelta({
  baseline: { record: straddleRun('A', '0.2.57'), findings: base, pluginStatus: straddleHost(BEFORE_452DF92) },
  current: { record: straddleRun('B', '1.0.0'), findings: cur, pluginStatus: straddleHost(await straddleAfter()) },
});

test('(straddle, first) the AFTER conclusion is what the fixture says, and the identity measurement DOES move at 9200', async () => {
  assert.deepEqual(await straddleAfter(), [{ port: 9200, protocol: 'tcp', service: 'http', status: 'open', program: 'Elasticsearch', version: '7.10.2' }]);
  assert.equal(tcpServiceMeasurement(9200, 'intelligence_engine', BEFORE_452DF92, 'the baseline').measured, false);
  assert.equal(tcpServiceMeasurement(9200, 'intelligence_engine', await straddleAfter(), 'the current run').measured, true);
});

test('(straddle) a CVE row the restored identity makes attributable is NOT reported new — the baseline did not measure it', async () => {
  const cve = engineRow(9200, 'CVE-2021-22145 — tcp/http');
  const d = await straddle([], [cve]);
  assert.deepEqual(d.newFindings, []);
  assert.equal(d.notComparable.find((f) => f.title === cve.title)?.reason, PORT_NOT_MEASURED_REASON);
});

test('(straddle) the phantom row\'s coverage-gap record vanishing is NOT reported resolved — it is a gap that cleared', async () => {
  const gap = engineRow(5601, '[COVERAGE GAP] no_version_detected — tcp/opensearch-dashboards', 'no_version_detected', 'INFO');
  const d = await straddle([gap], []);
  assert.deepEqual(d.resolved, []);
  assert.equal(d.notComparable.find((f) => f.title === gap.title)?.reason, 'evidence-gap');
});
