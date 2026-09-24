// 040 SAYS WHEN A CERTIFICATE AUDIT DID NOT HAPPEN — driven on the REAL plugin against local listeners.
//
// EE 1.1.0 build 6's Gate-2 run had 443 OPEN per the port scanner and 040's handshake RESET there. The
// result read `totalIssues 0`, `overallSeverity: "pass"`, and the report said nothing: the only record
// was an INFO service row the loader never shapes. The gap is keyed on the PORT SCANNER'S open set, not
// on the error class — the test estate's router answers ENETDOWN on 993/995 in every run, the port
// scanner reads the same, and an error-keyed rule would have put a gap on every scan.
//
// The listeners are real sockets: one that RESETS every connection, one port bound and released (a
// refusal), and a real TLS server with a throwaway certificate. The plugin's own `run` is driven with
// its port list pointed at them (`this.ports`); nothing inside the plugin is stubbed.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';
import tls from 'node:tls';
import { execFileSync } from 'node:child_process';
import tlsCert, { tlsCoverageGap } from '../plugins/040_tls_cert_auditor.mjs';
import { shapeHostFindings, countHostFindings } from '../utils/report_inputs.mjs';

const HOST = '127.0.0.1';
const listen = (server) => new Promise((r) => server.listen(0, HOST, () => r(server.address().port)));

async function resetPort(t) { // every connection is RESET — a port that answered TCP but not the audit
  const server = net.createServer((s) => s.resetAndDestroy());
  const port = await listen(server);
  t.after(() => server.close());
  return port;
}
async function refusedPort() { // bound, then released: nothing listens, the connect is refused
  const server = net.createServer();
  const port = await listen(server);
  await new Promise((r) => server.close(r));
  return port;
}
function certMaterial(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tls-gap-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  try {
    execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-keyout', path.join(dir, 'k.pem'), '-out', path.join(dir, 'c.pem'),
      '-days', '2', '-nodes', '-subj', '/CN=gap.test'], { stdio: 'ignore' });
  } catch {
    if (process.env.CI) assert.fail('openssl is required to build the real TLS server — refusing to skip in CI');
    return null;
  }
  return { key: fs.readFileSync(path.join(dir, 'k.pem')), cert: fs.readFileSync(path.join(dir, 'c.pem')) };
}
async function tlsPort(t) {
  const m = certMaterial(t);
  if (!m) return null;
  const server = tls.createServer({ key: m.key, cert: m.cert }, (s) => s.end());
  const port = await listen(server);
  t.after(() => server.close());
  return port;
}
// The context the orchestrator hands a plugin: the port scanner ran, and this is the set it saw open.
const scanned = (open) => ({ tcpOpen: new Set(open), pluginRunStatus: new Map([['003', 'ran']]) });
const runOn = (ports, opts, namedPort = 0) => tlsCert.run.call({ ...tlsCert, ports }, HOST, namedPort, { timeoutMs: 3000, ...opts });

// ── FOURTH QUADRANT FIRST: the legs where NO gap is the right answer ───────────────────────────────
test('(b) a port the port scanner did NOT see open, failing non-refused (the 993/995 ENETDOWN shape), is NOT a gap', async (t) => {
  const reset = await resetPort(t);
  const r = await runOn([reset], { context: scanned([]) });
  assert.deepEqual(r.failedPorts.map((f) => f.port), [reset], 'precondition: the handshake failed');
  assert.notEqual(r.failedPorts[0].error, 'ECONNREFUSED', 'precondition: the failure is not a refusal');
  assert.equal(r.findings, undefined, `no gap: ${JSON.stringify(r.findings)}`);
});

test('(c) a completed handshake gives the normal findings and no gap', async (t) => {
  const port = await tlsPort(t);
  if (port === null) { t.skip('openssl unavailable (would hard-fail in CI)'); return; }
  const r = await runOn([port], { context: scanned([port]) });
  assert.deepEqual(r.failedPorts, []);
  assert.equal(r.portResults.length, 1);
  assert.ok(r.portResults[0].issues.some((i) => i.check === 'self_signed'), 'the audit ran: the throwaway cert reads self-signed');
  assert.equal(r.findings, undefined);
});

// ── THE GAP ───────────────────────────────────────────────────────────────────────────────────────
test('(d) a port the port scanner saw OPEN whose handshake is RESET is ONE gap, naming the port and ECONNRESET', async (t) => {
  const reset = await resetPort(t);
  const r = await runOn([reset], { context: scanned([reset]) });
  assert.equal(r.findings?.length, 1);
  const [g] = r.findings;
  assert.equal(g.title, `[COVERAGE GAP] TLS certificate audit could not complete on ${reset} (ECONNRESET)`);
  assert.equal(g.severity, 'info');
  assert.equal(g.port, reset);
  assert.deepEqual(g.details, { evidenceGap: true, openness: 'open-per-port-scanner', failedPorts: [{ port: reset, error: 'ECONNRESET' }] });
});

test('(a) a port the port scanner saw OPEN that now REFUSES is a gap too — it answered the scanner, not the audit', async () => {
  const refused = await refusedPort();
  const r = await runOn([refused], { context: scanned([refused]) });
  assert.equal(r.findings?.[0]?.title, `[COVERAGE GAP] TLS certificate audit could not complete on ${refused} (ECONNREFUSED)`);
  assert.equal(r.findings[0].details.openness, 'open-per-port-scanner');
});

test('(a′) with the scanner\'s evidence, only the ports it saw open are gaps — a mixed run names the one', async (t) => {
  const open = await resetPort(t); const notOpen = await resetPort(t); const closed = await refusedPort();
  const r = await runOn([open, notOpen, closed], { context: scanned([open]) });
  assert.equal(r.failedPorts.length, 3);
  assert.deepEqual(r.findings.map((g) => g.details.failedPorts.map((f) => f.port)), [[open]]);
});

// ── NO PORT-SCANNER EVIDENCE: the error class is all there is, and the finding says so ────────────
test('(e) no context — a direct call — a reset on the named port is a gap, stated as openness unknown', async (t) => {
  const reset = await resetPort(t);
  const r = await runOn([], {}, reset);
  assert.equal(r.findings?.length, 1);
  assert.equal(r.findings[0].details.openness, 'unknown');
  assert.deepEqual(r.findings[0].details.failedPorts, [{ port: reset, error: 'ECONNRESET' }]);
});

test('(e′) the port scanner requested but NOT measured (timeout) is no evidence: the fallback applies', async (t) => {
  const reset = await resetPort(t);
  const r = await runOn([reset], { context: { tcpOpen: new Set(), pluginRunStatus: new Map([['003', 'timeout']]) } });
  assert.equal(r.findings?.[0]?.details.openness, 'unknown');
});

test('(e″) without evidence a refusal is still not a gap — a closed port is not an unaudited one', async () => {
  const refused = await refusedPort();
  const r = await runOn([refused], {});
  assert.equal(r.findings, undefined);
});

test('(f) a direct call naming ONE port: a different port failing non-refused is not a gap', async (t) => {
  const named = await refusedPort(); const other = await resetPort(t);
  const r = await runOn([named, other], {}, named);
  assert.deepEqual(r.failedPorts.map((f) => f.port), [named], 'a named port is the only one probed');
  assert.equal(r.findings, undefined);
  // …and the rule itself restricts the fallback to the named port, even handed both:
  assert.equal(tlsCoverageGap([{ port: named, error: 'ECONNREFUSED' }, { port: other, error: 'ECONNRESET' }], {}, named), null);
  assert.deepEqual(tlsCoverageGap([{ port: other, error: 'ECONNRESET' }], {}, 0).details.failedPorts, [{ port: other, error: 'ECONNRESET' }],
    'with no port named, the same failure IS a gap');
});

// ── WHERE THE READER LOOKS: the loader shapes it as a gap, visible and not counted ─────────────────
test('the report loader shapes the gap AS a gap: visible in the finding list, excluded from the finding count', async (t) => {
  const reset = await resetPort(t);
  const result = await runOn([reset], { context: scanned([reset]) });
  const raw = { results: [{ id: '040', name: tlsCert.name, result }] };
  const shaped = shapeHostFindings('192.0.2.10', raw, []);
  const gaps = shaped.filter((f) => /^\[COVERAGE GAP\] TLS certificate audit/.test(f.title ?? ''));
  assert.equal(gaps.length, 1, `shaped: ${JSON.stringify(shaped.map((f) => f.title))}`);
  assert.equal(gaps[0].evidenceGap, true);
  assert.equal(countHostFindings('192.0.2.10', raw, []), shaped.filter((f) => !f.evidenceGap && !f.deferredScope).length);
  assert.equal(countHostFindings('192.0.2.10', raw, []), 0, 'a gap is scope, not a finding');
});
