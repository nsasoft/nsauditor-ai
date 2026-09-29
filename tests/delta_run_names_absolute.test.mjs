// EVERY NOT-COMPARABLE DETAIL NAMES ITS RUN ABSOLUTELY (1.1.1 — the audit seat's T1-c fold 1).
//
// The executive page prefixes a not-comparable row with its direction in ABSOLUTE terms — "absent from this run" /
// "appeared in this run", where "this run" is the CURRENT run (1.1.1, T1) — and then prints the reason's detail, which
// named runs RELATIVE to the side holding the row: "in the other run". For a row that DISAPPEARED the holder is the
// baseline, so "the other run" is also the current run, and the assembled line read "absent from this run — …; Enterprise
// failed to load on <host> in the other run" — a reader places the failure in the baseline. Every reason's detail carried
// the relative name (shipped in CE 0.2.55); the absolute prefix is 1.1.1's, so the contradiction was new in 1.1.1. The
// APPEARED direction read right only by accident (the holder is the current run). The detail now names "this run" and
// "the baseline run", from the call site, which knows the frame — and these legs read the ASSEMBLED line, because each
// of the earlier tests asserted its own fragment and passed.
//
// FOURTH QUADRANT FIRST: the APPEARED direction, right today by accident, is pinned before the defect's direction.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { renderExecutiveReport } from '../utils/executive_report.mjs';
import * as SD from '../utils/scan_delta.mjs';

const { buildScanDelta } = SD;
const HOST = '192.0.2.1';
const run = (id, hosts = [HOST]) => ({ schema: 1, runId: id, startedAt: '2026-09-21T00:00:00Z', finishedAt: '2026-09-21T01:00:00Z',
  hostsRequested: hosts, hostsWritten: hosts.map((h, i) => ({ host: h, dir: `d${i}` })), pluginsRequested: ['003', '051'],
  portsRequested: null, tier: 'enterprise', ceVersion: '0.2.56', eeVersion: '1.1.1', kevLoaded: false, kevSnapshot: null, epssLoaded: false, epssSnapshot: null });
const agent = (title) => ({ host: HOST, port: 21, protocol: 'tcp', severity: 'MEDIUM', title, evidenceGap: false, gapClass: null,
  plugin: 'crypto_agent', pluginName: 'crypto_agent', producerKind: 'agent' });
const snmp = (title) => ({ host: HOST, port: 161, protocol: 'udp', severity: 'HIGH', title, evidenceGap: false, gapClass: null,
  plugin: '051', pluginName: 'SNMP Scanner', producerKind: 'plugin' });
const status = ({ eeStage = null, udp = [] } = {}) => [{ host: HOST, dir: 'd0', pluginStatusRecorded: true,
  status: [{ id: '003', status: 'ran' }, { id: '051', status: 'ran' }], portScan: { tcpOpen: [21], tcpClosed: [] }, udpServices: udp,
  ...(eeStage ? { eeStage } : {}) }];
const side = (id, findings, opts, hosts) => ({ record: run(id, hosts), findings, pluginStatus: status(opts) });
const LOAD = { loadError: "does not provide an export named 'isUdpTransport'", enrichmentError: null };
const model = { runId: 'B', startedAt: '2026-09-22T10:00:00.000Z', findings: [],
  coverage: { requested: 1, written: 1, partial: false, incomplete: false, missing: [] }, hosts: [] };
/** The ASSEMBLED line a reader sees for the row titled `title` — tags stripped, entities decoded. */
function lineFor(delta, title) {
  const html = renderExecutiveReport(model, {}, { renderedAt: new Date('2026-09-22T12:00:00Z'), delta });
  const text = html.replace(/<[^>]+>/g, ' ').replace(/&#39;|&apos;/g, "'").replace(/&quot;/g, '"').replace(/&amp;/g, '&').replace(/\s+/g, ' ');
  const at = text.indexOf(title);
  assert.ok(at >= 0, `the row "${title}" is on the page`);
  return text.slice(at, at + 900);
}

// ── FOURTH QUADRANT FIRST: the APPEARED direction ────────────────────────────────────────────────────
test('(q) APPEARED — the baseline\'s Enterprise failed: "appeared in this run … failed to load … in the baseline run"', () => {
  const d = buildScanDelta({ baseline: side('A', [], { eeStage: LOAD }), current: side('B', [agent('No transport encryption: ftp on port 21')]) });
  const line = lineFor(d, 'No transport encryption: ftp on port 21');
  assert.match(line, /appeared in this run — not counted as NEW; evidence-gap: Enterprise failed to load on 192\.0\.2\.1 in the baseline run/);
});

test('(q) APPEARED — a host the baseline never wrote: "not scanned in the baseline run"', () => {
  const d = buildScanDelta({ baseline: side('A', [], {}, ['192.0.2.9']), current: side('B', [agent('No transport encryption: ftp on port 21')]) });
  assert.match(lineFor(d, 'No transport encryption: ftp on port 21'), /appeared in this run — not counted as NEW; host-not-scanned: host 192\.0\.2\.1 was not scanned in the baseline run/);
});

// ── THE DEFECT: the DISAPPEARED direction ────────────────────────────────────────────────────────────
test('(a) DISAPPEARED — Enterprise failed now: "absent from this run … failed to load … in this run", never "the other run"', () => {
  const d = buildScanDelta({ baseline: side('A', [agent('No transport encryption: ftp on port 21')]), current: side('B', [], { eeStage: LOAD }) });
  const line = lineFor(d, 'No transport encryption: ftp on port 21');
  assert.match(line, /absent from this run — not counted as RESOLVED; evidence-gap: Enterprise failed to load on 192\.0\.2\.1 in this run/);
  assert.doesNotMatch(line, /other run/);
});

test('(a) DISAPPEARED — a host this run never wrote: "not scanned in this run"', () => {
  const d = buildScanDelta({ baseline: side('A', [agent('No transport encryption: ftp on port 21')]), current: side('B', [], {}, ['192.0.2.9']) });
  assert.match(lineFor(d, 'No transport encryption: ftp on port 21'), /absent from this run — not counted as RESOLVED; host-not-scanned: host 192\.0\.2\.1 was not scanned in this run/);
});

test('(a) DISAPPEARED UDP row, silent now: the shared oracle\'s sentence names "this run"; APPEARED names "the baseline run"', () => {
  const quiet = [{ port: 161, protocol: 'udp', service: 'snmp', status: 'no response', program: null, version: null }];
  const gone = buildScanDelta({ baseline: side('A', [snmp('SNMP default community public')]), current: side('B', [], { udp: quiet }) });
  assert.match(lineFor(gone, 'SNMP default community public'), /absent from this run — not counted as RESOLVED; port-not-measured: 161\/udp .* in this run no UDP service answered on that port/);
  const came = buildScanDelta({ baseline: side('A', [], { udp: quiet }), current: side('B', [snmp('SNMP default community public')]) });
  assert.match(lineFor(came, 'SNMP default community public'), /appeared in this run — not counted as NEW; port-not-measured: 161\/udp .* in the baseline run no UDP service answered on that port/);
});

test('the basis note on a RESOLVED UDP row names this run; on a NEW one, the baseline run', () => {
  const closed = [{ port: 161, protocol: 'udp', service: 'snmp', status: 'closed', program: null, version: null }];
  const r = buildScanDelta({ baseline: side('A', [snmp('SNMP default community public')]), current: side('B', [], { udp: closed }) });
  assert.match(r.resolved[0]?.basisNote ?? '', /^161\/udp closed in this run/);
  const n = buildScanDelta({ baseline: side('A', [], { udp: closed }), current: side('B', [snmp('SNMP default community public')]) });
  assert.match(n.newFindings[0]?.basisNote ?? '', /^161\/udp closed in the baseline run/);
});

test('CENSUS: no detail literal in utils/scan_delta.mjs names a RELATIVE run — the one exception is the shared oracle\'s default, which Enterprise\'s MTTR rewords', () => {
  const src = fs.readFileSync(path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'utils', 'scan_delta.mjs'), 'utf8');
  const code = src.split('\n').map((l, i) => [i + 1, l.replace(/\s\/\/.*$/, '')]).filter(([, l]) => !/^\s*(\/\/|\*|\/\*)/.test(l));
  const hits = code.filter(([, l]) => /other run/i.test(l)).map(([n, l]) => `${n}: ${l.trim()}`);
  assert.equal(hits.length, 1, hits.join('\n'));
  assert.match(hits[0], /export function udpPortMeasurement\(port, producer, services, runName = 'the other run'\)/);
});
