// THE CLIENT'S BASIS CELL SAYS WHAT THE DELTA CHECKED FOR THAT ROW (1.3.0, lane 6 — the CE half of F2: deltaBasis).
//
// Every resolved / new / changed row of the executive report's "Since Last Scan" table carried ONE sentence —
// "comparable: host, plugin, scope … present in both runs" — beside every row, including an analysis agent's or the CVE
// mapper's, whose "plugin" leg is never checked: an agent is not a requested plugin. The cell is now per row:
//   - a plugin's row keeps today's legs;
//   - an agent's row (an analysis agent or the CVE mapper) says the run that LACKS the row recorded no evidence gap from
//     its producer covering it — TRUE BY CONSTRUCTION, because such a gap makes the row not-comparable earlier (the delta
//     reads the gap only in the run that lacks the row, never in the run that holds it — so the sentence names ONE run);
//   - a TCP row of an identifying producer carries the measurement that made it comparable: the TCP decision's own basis,
//     or the closed-port basis — derived, never typed;
//   - where the run that lacks an agent row predates EE 1.3.0 it could not record an input plugin LEFT OUT of the scan,
//     so the row is not refused, and the cell says so; a run that records no EE version says that instead.
//
// FOURTH QUADRANT FIRST. Driven through Community's REAL buildScanDelta and the REAL executive renderer; the cell is read
// off the written HTML.
import test from 'node:test';
import assert from 'node:assert/strict';
import * as SD from '../utils/scan_delta.mjs';
import { renderExecutiveReport } from '../utils/executive_report.mjs';

const { buildScanDelta, cmpVersion, CVE_MAPPER_PRODUCER } = SD;
const HOST = '192.0.2.24';
const run = (id, eeVersion) => ({ schema: 1, runId: id, startedAt: '2026-10-06T00:00:00Z', finishedAt: '2026-10-06T01:00:00Z',
  hostsRequested: [HOST], hostsWritten: [{ host: HOST, dir: 'd' }], pluginsRequested: ['003', '011'], portsRequested: null,
  tier: 'enterprise', ceVersion: '0.2.57', ...(eeVersion === undefined ? {} : { eeVersion }), kevLoaded: false, kevSnapshot: null,
  epssLoaded: false, epssSnapshot: null });
const svc = (program, version, status = 'open', port = 22, service = 'ssh', protocol = 'tcp') => ({ port, protocol, service, status, program, version });
const host = (services, tcp = { tcpOpen: [22, 443], tcpClosed: [] }) => [{ host: HOST, dir: 'd', pluginStatusRecorded: true,
  status: [{ id: '003', status: 'ran' }, { id: '011', status: 'ran' }], portScan: tcp,
  ...(services ? { services, udpServices: services.filter((s) => SD.isUdpTransport(s.protocol)) } : {}) }];
const row = (over) => ({ host: HOST, protocol: 'tcp', evidenceGap: false, gapClass: null, severity: 'MEDIUM', ...over });
const AGENT = row({ port: 443, plugin: 'crypto_agent', pluginName: 'crypto_agent', producerKind: 'agent', title: 'TLSv1 enabled on port 443' });
const PLUGIN = row({ port: 443, plugin: '011', pluginName: 'tls_scanner', producerKind: 'plugin', title: 'TLSv1 accepted' });
const CVE = row({ port: 22, plugin: CVE_MAPPER_PRODUCER, pluginName: CVE_MAPPER_PRODUCER, producerKind: 'agent', severity: 'HIGH', title: 'CVE-2024-6387 — tcp/ssh' });
const GAP = row({ port: 0, plugin: 'crypto_agent', pluginName: 'crypto_agent', producerKind: 'agent', severity: 'INFO', evidenceGap: true,
  gapClass: 'input_gap', title: '[COVERAGE GAP] INPUT GAP — crypto_agent: a plugin that feeds the service set was not requested in this scan' });
const SERVICES = [svc('OpenSSH', '9.8'), svc('nginx', '1.27.0', 'open', 443, 'https')];

const delta = ({ base = [], cur = [], bEE = '1.3.0', cEE = '1.3.0', bHost = host(SERVICES), cHost = host(SERVICES) }) => buildScanDelta({
  baseline: { record: run('A', bEE), findings: base, pluginStatus: bHost },
  current: { record: run('B', cEE), findings: cur, pluginStatus: cHost },
});
const MODEL = { runId: 'B', startedAt: '2026-10-06T00:00:00Z', finishedAt: '2026-10-06T01:00:00Z', tier: 'enterprise', ceVersion: '0.2.57', eeVersion: '1.3.0',
  coverage: { requested: 1, written: 1, reachable: 1, missing: [], partial: false, incomplete: false },
  plugins: { ran: 2, skipped: 0, errored: 0, timedOut: 0, byHost: [] }, kev: { loaded: false, snapshot: null }, findings: [], hosts: [] };
/** The Basis cell of the delta row titled `title`, as the client reads it (tags stripped, entities decoded). */
function cellOf(d, title) {
  const html = renderExecutiveReport(MODEL, {}, { renderedAt: new Date('2026-10-06T01:00:00Z'), delta: d });
  const tr = html.split(/<tr /).find((x) => /^class="delta-/.test(x) && x.includes(title));
  assert.ok(tr, `no delta row for ${title}`);
  const tds = tr.split('</tr>')[0].split(/<td[^>]*>/).slice(1).map((x) => x.split('</td>')[0]);
  return tds.at(-1).replace(/<[^>]+>/g, '').replace(/&#39;/g, '\'').replace(/&quot;/g, '"').replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>');
}
const LEGACY = /predates EE 1\.3\.0, so it could not record an input plugin left out of the scan: an agent row it lacks is not refused/;

// ── THE COMPARATOR, ONE FOR BOTH SIDES ────────────────────────────────────────────────────────────────────────────────
test('the legacy sentence keys on Community\'s ONE version comparator — numeric, never a string compare', () => {
  assert.equal(cmpVersion('1.2.10', '1.2.9'), 1, 'a string compare puts 1.2.10 below 1.2.9');
  assert.equal(cmpVersion('1.3.0', '1.3.0'), 0);
  assert.equal(cmpVersion('1.2.0', '1.3.0'), -1);
  assert.equal(SD.NOT_REQUESTED_RECORD_SINCE_EE, '1.3.0', 'the release that added the not-requested cause, declared once');
});

// ── FOURTH QUADRANT FIRST: a plugin row keeps today's legs ────────────────────────────────────────────────────────────
test('(fourth quadrant, first) a PLUGIN row resolving keeps today\'s legs — host, plugin, scope — and never the agent or legacy sentence', () => {
  for (const [bEE, cEE] of [['1.3.0', '1.3.0'], ['1.2.0', '1.2.0']]) {
    const c = cellOf(delta({ base: [PLUGIN], bEE, cEE }), PLUGIN.title);
    assert.match(c, /^comparable: host, plugin, scope present in both runs; framework enumeration: /, `${bEE}/${cEE}`);
    assert.doesNotMatch(c, /producer:|predates EE|records no EE version/, `${bEE}/${cEE}`);
  }
});

// ── (2) THE AGENT SENTENCE IS TRUE BY CONSTRUCTION — DRIVEN ───────────────────────────────────────────────────────────
test('(2) the construction, its positive control: with the producer\'s gap record in the run that lacks the row, NO resolved/new row of it exists', () => {
  const gone = delta({ base: [AGENT], cur: [GAP] });
  assert.equal(gone.resolved.filter((f) => f.plugin === 'crypto_agent').length, 0);
  assert.equal(gone.notComparable.find((f) => f.title === AGENT.title)?.reason, 'evidence-gap');
  const appeared = delta({ base: [GAP], cur: [AGENT] });
  assert.equal(appeared.newFindings.filter((f) => f.plugin === 'crypto_agent').length, 0);
});

test('(2) …and the gap is read in the run that LACKS the row only: a gap beside the row it holds does not refuse it — so the sentence names ONE run', () => {
  const d = delta({ base: [AGENT, GAP], cur: [] });
  assert.equal(d.resolved.filter((f) => f.title === AGENT.title).length, 1, 'premise: the baseline\'s own gap does not refuse its row');
  const c = cellOf(d, AGENT.title);
  assert.match(c, /^comparable: host, scope present in both runs; producer: crypto_agent — this run recorded no evidence gap from it covering this row; /);
  assert.doesNotMatch(c, /either run|\bplugin, scope\b/, 'never "either run" (false here), never the plugin leg (an agent is not a requested plugin)');
});

test('(2) a NEW agent row names the BASELINE as the run that recorded no gap', () => {
  assert.match(cellOf(delta({ cur: [AGENT] }), AGENT.title), /producer: crypto_agent — the baseline run recorded no evidence gap from it covering this row/);
});

// ── (1) THE MEASUREMENT RIDES THE ROW, DERIVED ────────────────────────────────────────────────────────────────────────
test('(1) a CVE row resolved on an IDENTIFIED service carries the TCP decision\'s OWN basis — equal to the decision\'s string for that row', () => {
  const now = [svc('OpenSSH', '9.9'), svc('nginx', '1.27.0', 'open', 443, 'https')];
  const d = delta({ base: [CVE], cHost: host(now) });
  const [r] = d.resolved.filter((f) => f.title === CVE.title);
  const decision = SD.tcpServiceMeasurement(22, CVE_MAPPER_PRODUCER, now, SD.RUN_NAMES.current);
  assert.equal(decision.measured, true, 'premise');
  assert.equal(r?.basisNote, decision.basis, 'one composition: the note IS the decision\'s string');
  assert.ok(cellOf(d, CVE.title).endsWith(`; ${decision.basis}`));
});

test('(1) a CVE row resolved on a CLOSED port carries the closed-port basis — nothing was identified, and the cell does not say it was', () => {
  const d = delta({ base: [CVE], cHost: host([svc('Unknown', 'Unknown', 'closed', 22, 'unknown')], { tcpOpen: [443], tcpClosed: [22] }) });
  const [r] = d.resolved.filter((f) => f.title === CVE.title);
  assert.equal(r?.basisNote, SD.tcpPortClosedBasis(22, SD.RUN_NAMES.current));
  assert.equal(r.basisNote, '22/tcp closed in this run');
  assert.doesNotMatch(cellOf(d, CVE.title), /answered|identified/);
});

test('(1) an analysis agent\'s TCP row carries no service measurement — an open port is all it needs, and the cell claims no more', () => {
  const d = delta({ base: [AGENT] });
  assert.equal(d.resolved.find((f) => f.title === AGENT.title)?.basisNote, undefined);
});

// ── (3) THE LEGACY SENTENCE, KEYED ON THE RUN THAT LACKS THE ROW ──────────────────────────────────────────────────────
test('(3) the delta result carries BOTH runs\' EE versions, read off their records', () => {
  const d = delta({ bEE: '1.2.0', cEE: '1.3.0' });
  assert.deepEqual([d.baselineEeVersion, d.currentEeVersion], ['1.2.0', '1.3.0']);
});

test('(3, fourth quadrant) the lacking run is ≥ 1.3.0 — NEW over a 1.3.0 baseline, RESOLVED under a 1.3.0 current: no legacy sentence', () => {
  assert.doesNotMatch(cellOf(delta({ cur: [AGENT], bEE: '1.3.0', cEE: '1.3.0' }), AGENT.title), /predates EE|records no EE version/);
  assert.doesNotMatch(cellOf(delta({ base: [AGENT], bEE: '1.2.0', cEE: '1.3.0' }), AGENT.title), /predates EE|records no EE version/,
    'RESOLVED: the current run lacks the row, and it is 1.3.0 — the 1.2.0 baseline is irrelevant');
  // THE FIXTURE A STRING COMPARE FAILS against this threshold: '1.10.0' sorts BEFORE '1.3.0' as text and comes after it as
  // a version. RE-DERIVE IT WHENEVER THE THRESHOLD MOVES: against the earlier threshold '1.2.1' the fixture '1.2.10' could
  // not tell the two compares apart (the threshold was its prefix) and the string-compare mutant survived it, measured.
  assert.doesNotMatch(cellOf(delta({ cur: [AGENT], bEE: '1.10.0', cEE: '1.10.0' }), AGENT.title), /predates EE/, '1.10.0 is not before 1.3.0');
  assert.doesNotMatch(cellOf(delta({ cur: [AGENT], bEE: '1.20.0', cEE: '1.20.0' }), AGENT.title), /predates EE/, '1.20.0 is not before 1.3.0');
});

test('(3) a patch on the line BEFORE the threshold predates it: 1.2.10 is before 1.3.0', () => {
  assert.match(cellOf(delta({ cur: [AGENT], bEE: '1.2.10', cEE: '1.2.10' }), AGENT.title), /predates EE 1\.3\.0/,
    'NEW over a 1.2.10 baseline: the baseline could not record the omission, and the cell says so');
});

test('(3) a 1.2.0 BASELINE: the reversed-direction NEW agent row is shown UNREFUSED, the legacy sentence beside it', () => {
  const d = delta({ cur: [AGENT], bEE: '1.2.0', cEE: '1.3.0' });
  assert.equal(d.newFindings.filter((f) => f.title === AGENT.title).length, 1, 'not refused — the baseline could not record why it lacked it');
  const c = cellOf(d, AGENT.title);
  assert.match(c, /the baseline run predates EE 1\.3\.0, so it could not record an input plugin left out of the scan: an agent row it lacks is not refused/);
});

test('(3) a 1.2.0 CURRENT run: a RESOLVED agent row carries the sentence naming THIS run', () => {
  const c = cellOf(delta({ base: [AGENT], bEE: '1.2.0', cEE: '1.2.0' }), AGENT.title);
  assert.match(c, /this run predates EE 1\.3\.0, so it could not record an input plugin left out of the scan: an agent row it lacks is not refused/);
});

test('(3) a lacking run that records NO EE version says so, naming that run — never assumed either way', () => {
  const d = delta({ cur: [AGENT], bEE: null, cEE: null });
  assert.equal(d.baselineEeVersion, null);
  const c = cellOf(d, AGENT.title);
  assert.match(c, /the baseline run records no EE version, so whether an input plugin was left out of it is not known/);
  assert.doesNotMatch(c, LEGACY);
});

test('(3) the sentence NEVER rides a plugin row, and never a row whose lacking run is ≥ 1.3.0', () => {
  for (const [bEE, cEE] of [['1.2.0', '1.2.0'], ['1.2.0', '1.3.0']]) {
    assert.doesNotMatch(cellOf(delta({ cur: [PLUGIN], bEE, cEE }), PLUGIN.title), /predates EE|records no EE version/);
  }
  assert.doesNotMatch(cellOf(delta({ base: [AGENT], bEE: '1.2.0', cEE: '1.3.0' }), AGENT.title), LEGACY);
});
