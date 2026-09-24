// A PORT THE RUN COULD NOT MEASURE IS NOT A PORT THAT WAS FIXED — `probe-not-measured` (EE 1.1.0 build 9, F6).
//
// Build 8's acceptance run: the port scanner saw the gateway's 443 open, and the HTTPS probe's handshake there
// was RESET. crypto_agent's HIGH row about 443 could not be produced, and the 1.0.0 → build 8 delta reported it
// RESOLVED — a measurement failure rendered as remediation. Enterprise now records the port as not measured (a
// service-set INPUT GAP carrying the port, one per agent plus the engine); this engine reads it PER PORT.
//
// FOURTH QUADRANT FIRST: the legs that must NOT move. A per-agent port gap read as a PRODUCER-wide gap would
// silence that agent's genuine fixes on every other port — the widest false outcome this change could make.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  buildScanDelta, PROBE_NOT_MEASURED_REASON, INPUT_GAP_CLASS, portsNotMeasured, portGapKey,
} from '../utils/scan_delta.mjs';

const HOST = '192.0.2.1';
const run = (id, over = {}) => ({
  schema: 1, runId: id, startedAt: '2026-09-21T00:00:00Z', finishedAt: '2026-09-21T01:00:00Z',
  hostsRequested: [HOST], hostsWritten: [{ host: HOST, dir: 'd' }], pluginsRequested: ['003'], portsRequested: null,
  tier: 'enterprise', ceVersion: '0.2.55', eeVersion: '1.1.0',
  kevLoaded: false, kevSnapshot: null, epssLoaded: false, epssSnapshot: null, ...over,
});
// Shaped queue rows, as report_inputs.mjs emits them for an agent's finding.
const row = (port, title, over = {}) => ({ host: HOST, port, plugin: 'crypto_agent', pluginName: 'crypto_agent',
  producerKind: 'agent', severity: 'HIGH', title, evidenceGap: false, gapClass: null, ...over });
const portGap = (port, over = {}) => row(port, `[COVERAGE GAP] INPUT GAP — port ${port} was not measured`,
  { severity: 'INFO', evidenceGap: true, gapClass: INPUT_GAP_CLASS, ...over });
const delta = (base, cur) => buildScanDelta({
  baseline: { record: run('A'), findings: base, pluginStatus: [] },
  current: { record: run('B'), findings: cur, pluginStatus: [] },
});

// ── FOURTH QUADRANT FIRST ─────────────────────────────────────────────────────────────────────────────
test('a row on a port that WAS measured still RESOLVES — even with the same agent gapped on another port', () => {
  const d = delta([row(80, 'No transport encryption: http on port 80')], [portGap(443)]);
  assert.equal(d.resolved.length, 1, 'port 80 was measured: its disappearance is a fix');
  assert.deepEqual(d.notComparable, []);
});

test('a HOST-WIDE input gap (no port) keeps today\'s producer-wide verdict, unchanged', () => {
  const d = delta([row(80, 'No transport encryption: http on port 80')], [portGap(0)]);
  assert.equal(d.resolved.length, 0);
  assert.equal(d.notComparable[0]?.reason, 'evidence-gap');
});

test('an evidence gap of ANOTHER class carrying a port stays producer-wide, as before', () => {
  const d = delta([row(80, 'No transport encryption: http on port 80')], [portGap(443, { gapClass: 'cpe_map_miss' })]);
  assert.equal(d.notComparable[0]?.reason, 'evidence-gap');
});

test('a port gap on ANOTHER HOST does not reach this host\'s row', () => {
  const d = delta([row(443, 'No transport encryption: http on port 443')], [portGap(443, { host: '192.0.2.99' })]);
  assert.equal(d.resolved.length, 1);
});

// ── THE FIX ───────────────────────────────────────────────────────────────────────────────────────────
test('a row on the port the run could NOT measure is not-comparable probe-not-measured, never RESOLVED', () => {
  const d = delta([row(443, 'No transport encryption: http on port 443')], [portGap(443)]);
  assert.equal(d.resolved.length, 0);
  assert.equal(d.notComparable.length, 1);
  assert.equal(d.notComparable[0].reason, PROBE_NOT_MEASURED_REASON);
  assert.equal(d.notComparable[0].direction, 'disappeared');
  assert.match(d.notComparable[0].detail, /port 443 on 192\.0\.2\.1 was not measured in the other run/);
});

test('ANY producer\'s row on that port is set aside — the probe starved every consumer of the port', () => {
  // A PLUGIN's row (040, requested in both runs — else the delta rightly answers plugin-not-run first).
  const both = { pluginsRequested: ['003', '040'] };
  const d = buildScanDelta({
    baseline: { record: run('A', both), findings: [row(443, 'Self-signed certificate', { plugin: '040', pluginName: 'tls-cert-auditor', producerKind: null })], pluginStatus: [] },
    current: { record: run('B', both), findings: [portGap(443)], pluginStatus: [] },
  });
  assert.equal(d.notComparable[0]?.reason, PROBE_NOT_MEASURED_REASON);
});

test('the APPEARED direction: a row on a port the BASELINE could not measure is not NEW', () => {
  const d = delta([portGap(443)], [row(443, 'No transport encryption: http on port 443')]);
  assert.equal(d.newFindings.length, 0);
  assert.equal(d.notComparable[0]?.reason, PROBE_NOT_MEASURED_REASON);
  assert.equal(d.notComparable[0]?.direction, 'appeared');
});

test('the host is keyed by hostKey: a gap recorded under another case reaches the row', () => {
  const upper = (f) => ({ ...f, host: 'Router.LOCAL' });
  const d = buildScanDelta({
    baseline: { record: run('A', { hostsWritten: [{ host: 'router.local', dir: 'd' }] }),
      findings: [{ ...row(443, 'No transport encryption: http on port 443'), host: 'router.local' }], pluginStatus: [] },
    current: { record: run('B', { hostsWritten: [{ host: 'Router.LOCAL', dir: 'd' }] }), findings: [upper(portGap(443))], pluginStatus: [] },
  });
  assert.equal(d.notComparable[0]?.reason, PROBE_NOT_MEASURED_REASON);
});

test('the shared lookup Enterprise imports answers the same question', () => {
  const m = portsNotMeasured([portGap(443), portGap(0), row(80, 'x'), portGap(8443, { gapClass: 'cpe_map_miss' })]);
  assert.deepEqual([...m.keys()], [portGapKey(HOST, 443)]);
});
