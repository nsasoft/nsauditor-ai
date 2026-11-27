// G-71 F-040 (architect RULINGS-v402 §4 (b)/(c), VERDICT-v408 §4): A PORT THE PORT SCANNER DID NOT PROBE HAS NO
// PORT-SCANNER EVIDENCE, SO A FAILED TLS HANDSHAKE THERE IS A GAP — SCOPED TO THAT PORT.
//
// Measured before this was written (Z/g71-f040-measure-v348): 040 probes 636, 853, 8883 and 9443, which the default sweep
// never does. With 003 ran, today's rule asked only "was the port in ctx.tcpOpen?", so a TLS port the scanner never
// probed could never be a gap: a reset or a timeout there wrote nothing, and `report --since` read that port's baseline
// rows as RESOLVED (040-a, 040-a2; a real iptables drop on 8883 read 3 RESOLVED). The rule, in C1's order:
//   1. port in ctx.tcpOpen                                    -> today's rule and today's row, byte-identical;
//   2. else port not in ctx.tcpProbed, 003 ran, not REFUSED   -> one gap-only row for that port, its own class;
//   3. else                                                   -> no gap.
// ctx.tcpProbed (003's open ∪ closed ∪ filtered) is set by the manager where it takes 003's lists; ABSENCE IS A STATE
// (today's output). The row's code goes through the waist's one rule, safeCode; "TLS handshake timeout" is ETIMEDOUT.
//
// Every scan here is the REAL manager (its 003 block feeds the real 040 run's context) writing through the REAL
// scanSingleHost; every delta is the REAL `report --since`. 003's lists are DECLARED by a stand-in run (the real
// plugin object otherwise); the listeners are real loopback sockets. FOURTH QUADRANT FIRST.
import './helpers/no_operator_dotenv.mjs';
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';
import tls from 'node:tls';
import { execFileSync } from 'node:child_process';
import tlsCert, {
  tlsCoverageGap, tlsUnprobedPortGaps, tlsFailureCode, TLS_HANDSHAKE_TIMEOUT,
} from '../plugins/040_tls_cert_auditor.mjs';
import portScanner from '../plugins/port_scanner.mjs';
import concluder from '../plugins/result_concluder.mjs';
import { shapeHostFindings } from '../utils/report_inputs.mjs';
import {
  UNPROBED_PORT_GAP_CLASS, INPUT_GAP_CLASS, isPortScopedGap, portsNotMeasured, portGapKey, buildScanDelta,
  PROBE_NOT_MEASURED_REASON,
} from '../utils/scan_delta.mjs';

const LOOP = '127.0.0.1';
const HOST = '192.0.2.10'; // RFC 5737: scanSingleHost's target guard refuses a private address; 040 is pointed at LOOP
const TIMEOUT_MS = 1500;
const ran = (extra = {}) => ({ pluginRunStatus: new Map([['003', 'ran']]), ...extra });
const ctxOf = ({ open = [], probed } = {}, status = 'ran') => ({
  tcpOpen: new Set(open), pluginRunStatus: new Map([['003', status]]), ...(probed ? { tcpProbed: new Set(probed) } : {}),
});

// ── Real listeners ─────────────────────────────────────────────────────────────────────────────────────────────────
let MAT = null; // { bad: 2-day cert, renewed: 400-day cert }, the same subject
function certs() {
  if (MAT) return MAT;
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tls-unprobed-'));
  const mk = (name, days) => {
    try {
      execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-keyout', path.join(dir, `${name}.k`), '-out', path.join(dir, `${name}.c`),
        '-days', String(days), '-nodes', '-subj', '/CN=gap.test'], { stdio: 'ignore' });
    } catch { assert.fail('openssl is required to build the real TLS servers — refusing to skip'); }
    return { key: fs.readFileSync(path.join(dir, `${name}.k`)), cert: fs.readFileSync(path.join(dir, `${name}.c`)) };
  };
  MAT = { bad: mk('bad', 2), renewed: mk('renewed', 400) };
  fs.rmSync(dir, { recursive: true, force: true });
  return MAT;
}
const sockets = new Set();
const track = (s) => { sockets.add(s); s.on('close', () => sockets.delete(s)); s.on('error', () => {}); };
const MAKE = {
  tls: () => { const s = tls.createServer(certs().bad, (c) => { c.on('error', () => {}); c.end(); }); s.on('connection', track); s.on('tlsClientError', () => {}); return s; },
  renewed: () => { const s = tls.createServer(certs().renewed, (c) => { c.on('error', () => {}); c.end(); }); s.on('connection', track); s.on('tlsClientError', () => {}); return s; },
  reset: () => net.createServer((c) => { track(c); c.resetAndDestroy(); }), // accepts, then RST
  'reset-on-data': () => net.createServer((c) => { track(c); c.once('data', () => c.resetAndDestroy()); }), // RST on the ClientHello
  silent: () => net.createServer((c) => { track(c); }), // accepts and never answers: 040's own timer fires
};
const listen = (srv, port) => new Promise((ok, no) => { srv.once('error', no); srv.listen(port, LOOP, () => ok(srv.address().port)); });
async function freePort() { const s = net.createServer(); const p = await listen(s, 0); await new Promise((r) => s.close(r)); return p; }
/** Start each `[kind, port]` ('refused' starts nothing); returns a closer. */
async function up(servers) {
  const started = [];
  for (const [kind, port] of servers) if (kind !== 'refused') { const s = MAKE[kind](); await listen(s, port); started.push(s); }
  return async () => { for (const c of [...sockets]) c.destroy(); for (const s of started) await new Promise((r) => s.close(() => r())); };
}

// ── The plugin, on its own (no report) ─────────────────────────────────────────────────────────────────────────────
const runOn = async (servers, context) => {
  const close = await up(servers);
  try { return await tlsCert.run.call({ ...tlsCert, ports: servers.map(([, p]) => p) }, LOOP, 0, { timeoutMs: TIMEOUT_MS, context }); }
  finally { await close(); }
};

test('L8 (fourth quadrant): 003 ran and ctx.tcpProbed is ABSENT — an unprobed reset writes today\'s output, no new row', async () => {
  const p = await freePort();
  const r = await runOn([['reset', p]], ctxOf({ open: [] }));
  assert.equal(r.failedPorts[0]?.error, 'ECONNRESET', 'precondition: the handshake was reset');
  assert.equal(r.findings, undefined, `absence is a state, not an empty set: ${JSON.stringify(r.findings)}`);
  assert.deepEqual(tlsUnprobedPortGaps(r.failedPorts, ctxOf({ open: [] })), []);
  // A tcpProbed that is not a Set is absence too.
  assert.deepEqual(tlsUnprobedPortGaps(r.failedPorts, { ...ctxOf({ open: [] }), tcpProbed: [] }), []);
});

test('L6 (fourth quadrant): a port 003 PROBED and recorded filtered, failing ENETDOWN (the estate\'s 993/995) writes no gap', async () => {
  const ctx = ctxOf({ open: [], probed: [993, 995] });
  const failed = [{ port: 993, error: 'ENETDOWN' }, { port: 995, error: 'ENETDOWN' }];
  assert.equal(tlsCoverageGap(failed, ctx, 0), null);
  assert.deepEqual(tlsUnprobedPortGaps(failed, ctx), []);
  // And through run(): a real reset on a port 003 recorded filtered.
  const p = await freePort();
  const r = await runOn([['reset', p]], ctxOf({ open: [], probed: [p] }));
  assert.equal(r.failedPorts[0]?.error, 'ECONNRESET');
  assert.equal(r.findings, undefined, JSON.stringify(r.findings));
});

test('L3 (fourth quadrant): an unprobed port that REFUSES writes no gap — a closed port is not an unaudited one', async () => {
  const p = await freePort();
  const r = await runOn([['refused', p]], ctxOf({ open: [], probed: [] }));
  assert.equal(r.failedPorts[0]?.error, 'ECONNREFUSED', 'precondition');
  assert.equal(r.findings, undefined, JSON.stringify(r.findings));
});

test('003 NOT measured (timeout) with ctx.tcpProbed present: today\'s no-evidence row, and no new row', async () => {
  const p = await freePort();
  const r = await runOn([['reset', p]], ctxOf({ open: [], probed: [] }, 'timeout'));
  assert.equal(r.findings?.length, 1, JSON.stringify(r.findings));
  assert.equal(r.findings[0].details.openness, 'unknown', 'today\'s no-evidence branch');
  assert.equal(r.findings[0].details.gapClass, undefined, 'not the new row');
});

test('L7 (C1): a port in ctx.tcpOpen through a NON-003 producer, absent from 003\'s lists, REFUSED — today\'s row lists it, no new row', async () => {
  const p = await freePort();
  const ctx = ctxOf({ open: [p], probed: [] }); // in tcpOpen (another producer), not in tcpProbed
  const r = await runOn([['refused', p]], ctx);
  assert.equal(r.failedPorts[0]?.error, 'ECONNREFUSED', 'precondition');
  assert.equal(r.findings?.length, 1, JSON.stringify(r.findings));
  assert.deepEqual(r.findings[0], tlsCoverageGap(r.failedPorts, ctx, 0), 'today\'s row, byte-identical');
  assert.equal(r.findings[0].details.openness, 'open-per-port-scanner');
});

// ── The new row ────────────────────────────────────────────────────────────────────────────────────────────────────
test('an unprobed port that RESETS gets ONE gap-only row: its port, its own class, 040\'s head, the scanner did not probe it', async () => {
  const p = await freePort();
  const r = await runOn([['reset', p]], ctxOf({ open: [], probed: [] }));
  assert.equal(r.findings?.length, 1, JSON.stringify(r.findings));
  const row = r.findings[0];
  assert.equal(row.severity, 'info', 'INFO, the severity today\'s row carries');
  assert.equal(row.title, `[COVERAGE GAP] TLS certificate audit could not complete on ${p} (ECONNRESET)`);
  assert.doesNotMatch(row.title, /INPUT GAP/);
  assert.match(row.detail, /the port scanner did not probe this port/i);
  assert.equal(row.port, p);
  assert.deepEqual({ ...row.details }, { evidenceGap: true, gapOnly: true, gapClass: UNPROBED_PORT_GAP_CLASS,
    openness: 'not-probed-by-port-scanner', code: 'ECONNRESET' });
  assert.notEqual(UNPROBED_PORT_GAP_CLASS, INPUT_GAP_CLASS, 'Q1: its OWN class');
});

test('L9 (unit): two unprobed ports fail — two rows, each with its own port, never one row with port null', async () => {
  const [a, b] = [await freePort(), await freePort()];
  const r = await runOn([['reset', a], ['reset-on-data', b]], ctxOf({ open: [], probed: [] }));
  assert.deepEqual(r.findings?.map((f) => f.port), [a, b], JSON.stringify(r.findings));
  for (const f of r.findings) assert.equal(isPortScopedGap({ evidenceGap: f.details.evidenceGap, gapClass: f.details.gapClass, port: f.port }), true);
});

test('L10: a mixed run — today\'s row keeps the contentDigest HEAD gives the same input, and one new row stands beside it', async () => {
  // Real sockets: one open-per-003 failure (O) and one unprobed failure (P).
  const [o, p] = [await freePort(), await freePort()];
  const ctx = ctxOf({ open: [o], probed: [o] });
  const r = await runOn([['reset', o], ['reset', p]], ctx);
  assert.equal(r.findings?.length, 2, JSON.stringify(r.findings));
  assert.deepEqual(r.findings[0], tlsCoverageGap(r.failedPorts, ctx, 0), 'today\'s row first, as tlsCoverageGap gives it');
  assert.deepEqual(r.findings.slice(1), tlsUnprobedPortGaps(r.failedPorts, ctx));
  assert.equal(r.findings[1].port, p);
  // DECLARED oracle: the shaped digest and id of today's row for a fixed input, computed at CE 7864383 (HEAD before F-040)
  // over `{ findings: [tlsCoverageGap(failed, ctx)] }`. Beside the new row it must not move.
  const fixedCtx = ctxOf({ open: [8443], probed: [8443] });
  const fixed = [{ port: 8443, error: 'ECONNRESET' }, { port: 8883, error: 'ECONNRESET' }];
  const result = { findings: [tlsCoverageGap(fixed, fixedCtx, 0), ...tlsUnprobedPortGaps(fixed, fixedCtx)] };
  const shaped = shapeHostFindings(HOST, { results: [{ id: '040', name: tlsCert.name, result }] }, []);
  const today = shaped.find((f) => f.port === 8443);
  assert.deepEqual({ title: today.title, contentDigest: today.contentDigest, id: today.id, gapClass: today.gapClass },
    { title: '[COVERAGE GAP] TLS certificate audit could not complete on 8443 (ECONNRESET)', contentDigest: '5138902578f1ca61',
      id: '9378c3a27668d2ff', gapClass: null });
  const added = shaped.find((f) => f.port === 8883);
  assert.equal(added.gapClass, UNPROBED_PORT_GAP_CLASS, 'the loader carries the class');
  assert.equal(added.evidenceGap, true);
});

test('Q4: the row\'s code goes through the waist\'s one rule — "TLS handshake timeout" is ETIMEDOUT, a declared case', () => {
  assert.equal(TLS_HANDSHAKE_TIMEOUT, 'TLS handshake timeout', 'the one spelling 040 resolves its timer with');
  assert.equal(tlsFailureCode(TLS_HANDSHAKE_TIMEOUT), 'ETIMEDOUT');
  for (const c of ['ECONNRESET', 'EPIPE', 'ERR_SSL_WRONG_VERSION_NUMBER']) assert.equal(tlsFailureCode(c), c);
  // Text from outside the process never reaches the row (v408 C5): a message, a message ENDING in a code-shaped run,
  // and R8's two shapes (an array, an object whose toString answers a code) all read EOTHER.
  for (const e of ['Client network socket disconnected before secure TLS connection was established', 'read failed ECONNRESET',
    'ECONNRESET ', ['ECONNRESET'], { toString: () => 'ECONNRESET' }, undefined, null, 5]) {
    assert.equal(tlsFailureCode(e), 'EOTHER', String(e));
  }
});

test('a REAL handshake timeout on an unprobed port (a listener that never answers): the row reads ETIMEDOUT', async () => {
  const p = await freePort();
  const r = await runOn([['silent', p]], ctxOf({ open: [], probed: [] }));
  assert.equal(r.failedPorts[0]?.error, TLS_HANDSHAKE_TIMEOUT, 'precondition: 040\'s own timer fired');
  assert.equal(r.findings?.length, 1);
  assert.equal(r.findings[0].title, `[COVERAGE GAP] TLS certificate audit could not complete on ${p} (ETIMEDOUT)`);
  assert.equal(r.findings[0].details.code, 'ETIMEDOUT');
});

// ── Written through the real scan path, read by the real report ────────────────────────────────────────────────────
const conclusionFiles = (root) => fs.readdirSync(root, { recursive: true }).map(String).filter((f) => f.endsWith('scan_conclusion_raw.json'));
/** One scan through the REAL manager and scanSingleHost. `lists` = 003's declared lists (null: 003 not requested);
 *  `servers` = the loopback listeners 040 audits; `run040` replaces 040's run when a test must declare failures. */
async function scanWritten(outRoot, { lists, servers = [], runId = null, run040 = null }) {
  const keep = { out: process.env.SCAN_OUT_PATH, lic: process.env.NSAUDITOR_LICENSE_KEY, ai: process.env.OPENAI_OUT_PATH };
  process.env.SCAN_OUT_PATH = outRoot; process.env.NSAUDITOR_LICENSE_KEY = 'not-a-licence'; delete process.env.OPENAI_OUT_PATH;
  const close = await up(servers);
  try {
    const { scanSingleHost } = await import('../cli.mjs');
    const { default: PluginManager } = await import('../plugin_manager.mjs');
    const ports = servers.map(([, p]) => p);
    const p040 = { ...tlsCert, ports, requirements: {}, runStrategy: 'single',
      run: run040 ?? ((_h, _p, opts) => tlsCert.run.call({ ...tlsCert, ports }, LOOP, 0, { ...opts, timeoutMs: TIMEOUT_MS })) };
    const p003 = { ...portScanner, requirements: {},
      run: async () => ({ up: true, tcpOpen: lists.open ?? [], tcpClosed: lists.closed ?? [], tcpFiltered: lists.filtered ?? [], udpOpen: [], data: [] }) };
    const pm = await PluginManager.create({ plugins: [...(lists ? [p003] : []), p040, concluder] });
    const absent = () => { throw Object.assign(new Error('not installed'), { code: 'MODULE_NOT_FOUND' }); };
    const before = new Set(conclusionFiles(outRoot));
    await scanSingleHost(pm, HOST, 'all', { resolveEE: absent, ...(runId ? { runId } : {}) }, 'basic');
    const made = conclusionFiles(outRoot).filter((f) => !before.has(f));
    assert.equal(made.length, 1, `scanSingleHost wrote one conclusion file: ${made}`);
    const j = JSON.parse(fs.readFileSync(path.join(outRoot, made[0]), 'utf8'));
    for (const id of [...(lists ? ['003'] : []), '040']) {
      assert.equal(j.pluginStatus?.find((x) => String(x?.id) === id)?.status, 'ran', `the conclusion file records ${id} as ran`);
    }
    return j;
  } finally {
    await close();
    for (const [k, v] of [['SCAN_OUT_PATH', keep.out], ['NSAUDITOR_LICENSE_KEY', keep.lic], ['OPENAI_OUT_PATH', keep.ai]]) {
      if (v === undefined) delete process.env[k]; else process.env[k] = v;
    }
  }
}
const res040 = (j) => j.results.find((x) => String(x.id) === '040')?.result;

async function sinceReport(baseline, current) {
  const { runReport } = await import('../cli.mjs');
  const { resolveCapabilities } = await import('../utils/capabilities.mjs');
  const { newRunId, writeRunStart, finalizeRunRecord } = await import('../utils/run_record.mjs');
  const { sealRunRecord } = await import('../utils/run_chain.mjs');
  const outRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-tls-since-'));
  const written = [];
  const mk = async (startedAt, spec) => {
    const runId = newRunId();
    await writeRunStart(outRoot, { runId, startedAt, hostsRequested: [HOST], pluginsRequested: [...(spec.lists ? ['003'] : []), '040'],
      portsRequested: null, tier: 'pro', ceVersion: '0.2.54', eeVersion: null, prevDigest: null });
    written.push(await scanWritten(outRoot, { ...spec, runId }));
    await finalizeRunRecord(outRoot, runId, { finishedAt: startedAt });
    await sealRunRecord(outRoot, runId);
    return runId;
  };
  const a = await mk('2026-09-01T10:00:00.000Z', baseline); const b = await mk('2026-09-08T10:00:00.000Z', current);
  const rep = await runReport({ from: outRoot, format: 'executive', run: b, since: a, out: path.join(outRoot, 'exec.html') }, resolveCapabilities('pro'));
  assert.equal(rep.code, 0, rep.stderr);
  const m = rep.stdout.match(/(\d+) new · (\d+) resolved · (\d+) changed · (\d+) not-comparable · (\d+) unchanged/);
  assert.ok(m, `the delta line: ${rep.stdout.slice(0, 300)}`);
  const ncRows = rep.stdout.split('\n').filter((l) => /NOT COMPARABLE/.test(l));
  return { stdout: rep.stdout, ncRows, base: res040(written[0]), cur: res040(written[1]),
    n: { new: +m[1], resolved: +m[2], changed: +m[3], notComparable: +m[4], unchanged: +m[5] } };
}
const rowsOn = (result, port) => (result?.portResults ?? []).filter((r) => r.port === port).flatMap((r) => r.issues ?? []).length;

test('L2 + L3 (since, fourth quadrant first): n1 TLS both runs → nothing moves; n3 / 040-c a REFUSED unprobed port → RESOLVED', async () => {
  const [a, p] = [await freePort(), await freePort()];
  const n1 = await sinceReport({ lists: { open: [a] }, servers: [['tls', a], ['tls', p]] }, { lists: { open: [a] }, servers: [['tls', a], ['tls', p]] });
  assert.deepEqual([n1.n.new, n1.n.resolved, n1.n.notComparable], [0, 0, 0], n1.stdout);
  assert.ok(n1.n.unchanged > 0, 'premise: there are rows to compare');
  for (const [label, lists] of [['n3', { open: [a] }], ['040-c', null]]) {
    const d = await sinceReport({ lists, servers: [['tls', a], ['tls', p]] }, { lists, servers: [['tls', a], ['refused', p]] });
    const onP = rowsOn(d.base, p);
    assert.ok(onP > 0, `${label}: premise, the baseline has rows on ${p}`);
    assert.equal(d.cur.findings, undefined, `${label}: a refusal writes no gap`);
    assert.deepEqual([d.n.resolved, d.n.notComparable], [onP, 0], `${label}: ${d.stdout}`);
  }
});

test('L5 (since): n2 (a probed port 003 records filtered) and n2b (003 saw it open) read as at HEAD — the port leg and today\'s row', async () => {
  const [a, q] = [await freePort(), await freePort()];
  const base = { lists: { open: [a, q] }, servers: [['tls', a], ['tls', q]] };
  const n2 = await sinceReport(base, { lists: { open: [a], filtered: [q] }, servers: [['tls', a], ['reset', q]] });
  assert.equal(n2.cur.findings, undefined, 'n2: a probed, filtered port writes no gap');
  assert.equal(n2.n.notComparable, rowsOn(n2.base, q), n2.stdout);
  assert.ok(n2.ncRows.every((l) => /port-not-measured/.test(l)), n2.ncRows.join('\n'));
  const n2b = await sinceReport(base, { lists: { open: [a, q] }, servers: [['tls', a], ['reset-on-data', q]] });
  assert.equal(n2b.cur.findings?.length, 1, 'n2b: today\'s row alone');
  assert.equal(n2b.cur.findings[0].details.openness, 'open-per-port-scanner');
  assert.equal(n2b.n.notComparable, rowsOn(n2b.base, q), n2b.stdout);
  assert.ok(n2b.ncRows.every((l) => /evidence-gap/.test(l)), n2b.ncRows.join('\n'));
});

test('L4 + L13 (since): an unprobed port resets — or times out — in BOTH runs while a row on ANOTHER port is fixed: that row reads RESOLVED', async () => {
  for (const kind of ['reset', 'silent']) {
    const [a, p] = [await freePort(), await freePort()];
    const d = await sinceReport({ lists: { open: [a] }, servers: [['tls', a], [kind, p]] },
      { lists: { open: [a] }, servers: [['renewed', a], [kind, p]] });
    assert.equal(d.cur.findings?.length, 1, `${kind}: the unprobed port's gap row is written`);
    assert.equal(d.cur.findings[0].port, p);
    assert.equal(d.n.resolved, 1, `${kind}: the 2-day expiry row on ${a} is fixed by the 400-day certificate\n${d.stdout}`);
    assert.equal(d.n.notComparable, 0, `${kind}: the gap on ${p} holds nothing on ${a}\n${d.ncRows.join('\n')}`);
  }
});

test('L1 (since, the red): 040-a and 040-a2 — an unprobed port answers TLS, then resets (on accept, on the ClientHello): NOT COMPARABLE, naming the port', async () => {
  for (const kind of ['reset', 'reset-on-data']) {
    const [a, p] = [await freePort(), await freePort()];
    const d = await sinceReport({ lists: { open: [a] }, servers: [['tls', a], ['tls', p]] }, { lists: { open: [a] }, servers: [['tls', a], [kind, p]] });
    const onP = rowsOn(d.base, p);
    assert.ok(onP > 0, 'premise');
    assert.deepEqual([d.n.resolved, d.n.notComparable], [0, onP], `${kind}: ${d.stdout}`);
    assert.equal(d.ncRows.length, onP);
    for (const l of d.ncRows) {
      assert.match(l, new RegExp(`${PROBE_NOT_MEASURED_REASON}: port ${p} on ${HOST.replace(/\./g, '\\.')} was not measured`), l);
    }
  }
});

test('L9 (since): two unprobed ports fail — each row holds its own port; a fixed row on a THIRD port reads RESOLVED', async () => {
  const [p1, p2, p3] = [await freePort(), await freePort(), await freePort()];
  const d = await sinceReport({ lists: { open: [] }, servers: [['tls', p1], ['reset', p2], ['tls', p3]] },
    { lists: { open: [] }, servers: [['reset', p1], ['reset', p2], ['renewed', p3]] });
  assert.deepEqual(d.cur.findings?.map((f) => f.port), [p1, p2], JSON.stringify(d.cur.findings));
  assert.equal(d.n.notComparable, rowsOn(d.base, p1), d.stdout);
  assert.ok(d.ncRows.every((l) => l.includes(`port ${p1} on`)), d.ncRows.join('\n'));
  assert.equal(d.n.resolved, 1, `the expiry row on ${p3}: ${d.stdout}`);
});

test('L12 (since): the new row\'s own reading — its code differs between runs, or it appears, or it vanishes: never NEW, never RESOLVED', async () => {
  const [a, p] = [await freePort(), await freePort()];
  const lists = { open: [a] };
  for (const [b, c] of [['reset', 'silent'], ['refused', 'reset'], ['reset', 'refused']]) {
    const d = await sinceReport({ lists, servers: [['tls', a], [b, p]] }, { lists, servers: [['tls', a], [c, p]] });
    assert.deepEqual([d.n.new, d.n.resolved, d.n.notComparable], [0, 0, 0], `${b} → ${c}: ${d.stdout}`);
  }
});

test('L11 (artifacts): the code rule on the WRITTEN executive page and markdown — a message reads EOTHER, the timeout ETIMEDOUT', async () => {
  const { runReport } = await import('../cli.mjs');
  const { resolveCapabilities } = await import('../utils/capabilities.mjs');
  const { buildMarkdownReport } = await import('../utils/report_md.mjs');
  const { newRunId, writeRunStart, finalizeRunRecord } = await import('../utils/run_record.mjs');
  const { sealRunRecord } = await import('../utils/run_chain.mjs');
  const { escapeHtml } = await import('../utils/brand.mjs');
  const MESSAGE = 'Client network socket disconnected before secure TLS connection was established';
  const failed = [{ port: 7001, error: MESSAGE }, { port: 7002, error: TLS_HANDSHAKE_TIMEOUT }, { port: 7003, error: 'read failed ECONNRESET' },
    { port: 7004, error: ['ECONNRESET'] }, { port: 7005, error: { toString: () => 'ECONNRESET' } }];
  const expect = { 7001: 'EOTHER', 7002: 'ETIMEDOUT', 7003: 'EOTHER', 7004: 'EOTHER', 7005: 'EOTHER' };
  // 040's run declares the failures; its gap rows are built by the real builder over the REAL manager context.
  const run040 = async (_h, _p, opts) => ({ up: false, audit_type: 'tls_certificate', host: HOST, overallSeverity: 'pass', duration_ms: 1,
    summary: {}, portResults: [], failedPorts: failed, findings: tlsUnprobedPortGaps(failed, opts.context) });
  const outRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-tls-exec-'));
  const runId = newRunId(); const at = '2026-09-01T10:00:00.000Z';
  await writeRunStart(outRoot, { runId, startedAt: at, hostsRequested: [HOST], pluginsRequested: ['003', '040'], portsRequested: null,
    tier: 'pro', ceVersion: '0.2.54', eeVersion: null, prevDigest: null });
  const j = await scanWritten(outRoot, { lists: { open: [] }, runId, run040 });
  await finalizeRunRecord(outRoot, runId, { finishedAt: at });
  await sealRunRecord(outRoot, runId);
  assert.equal(res040(j).findings.length, 5, 'premise: the manager context made every port unprobed');
  const out = path.join(outRoot, 'exec.html');
  const rep = await runReport({ from: outRoot, format: 'executive', run: runId, out }, resolveCapabilities('pro'));
  assert.equal(rep.code, 0, rep.stderr);
  const page = fs.readFileSync(out, 'utf8');
  const md = buildMarkdownReport({ host: HOST, conclusion: j.conclusion, toolVersion: 'test', manifest: j.pluginStatus, results: j.results });
  for (const [port, code] of Object.entries(expect)) {
    const title = `[COVERAGE GAP] TLS certificate audit could not complete on ${port} (${code})`;
    assert.ok(page.includes(escapeHtml(title)), `exec.html lists ${title}`);
    // The markdown escapes the brackets and lists the row as gap-only, on its port.
    assert.ok(md.includes(`- ${HOST}:${port} — INFO — **gap only:** ${title.replace(/[[\]]/g, (c) => `\\${c}`)}`), `the markdown lists ${title}`);
  }
  const gapLines = (s) => s.split('\n').filter((l) => /TLS certificate audit could not complete/.test(l)).join('\n');
  for (const s of [gapLines(page), gapLines(md)]) {
    assert.ok(!s.includes(MESSAGE) && !s.includes('read failed'), `no text from outside the process in a gap row:\n${s}`);
  }
});

// ── The delta edit (Q1), both directions ───────────────────────────────────────────────────────────────────────────
test('L13: the port-scoped predicate — the new class and input_gap are port-scoped; nothing else is', () => {
  for (const gapClass of [INPUT_GAP_CLASS, UNPROBED_PORT_GAP_CLASS]) {
    assert.equal(isPortScopedGap({ evidenceGap: true, gapClass, port: 443 }), true, gapClass);
    assert.equal(isPortScopedGap({ evidenceGap: true, gapClass, port: null }), false, `${gapClass}: no port`);
    assert.equal(isPortScopedGap({ evidenceGap: false, gapClass, port: 443 }), false, `${gapClass}: not a gap`);
  }
  for (const gapClass of [null, 'other', 'nvd_lookup_failure']) assert.equal(isPortScopedGap({ evidenceGap: true, gapClass, port: 443 }), false, String(gapClass));
});

test('L13: an input_gap row from an Enterprise queue reads exactly as at HEAD; a 040 row of the new class is held on its port alone', () => {
  const run = (id) => ({ schema: 1, runId: id, startedAt: '2026-09-21T00:00:00Z', finishedAt: '2026-09-21T01:00:00Z', hostsRequested: [HOST],
    hostsWritten: [{ host: HOST, dir: 'd' }], pluginsRequested: ['003'], portsRequested: null, tier: 'enterprise', ceVersion: '0.2.55',
    eeVersion: '1.1.0', kevLoaded: false, kevSnapshot: null, epssLoaded: false, epssSnapshot: null });
  const row = (port, title, over = {}) => ({ host: HOST, port, plugin: 'crypto_agent', pluginName: 'crypto_agent', producerKind: 'agent',
    severity: 'HIGH', title, evidenceGap: false, gapClass: null, ...over });
  const queueGap = row(443, '[COVERAGE GAP] INPUT GAP — port 443 was not measured', { severity: 'INFO', evidenceGap: true, gapClass: INPUT_GAP_CLASS });
  const ceGap = row(8883, '[COVERAGE GAP] TLS certificate audit could not complete on 8883 (ECONNRESET)',
    { plugin: '040', pluginName: tlsCert.name, producerKind: 'plugin', severity: 'INFO', evidenceGap: true, gapClass: UNPROBED_PORT_GAP_CLASS });
  assert.deepEqual([...portsNotMeasured([queueGap, ceGap]).keys()], [portGapKey(HOST, 443), portGapKey(HOST, 8883)]);
  const base = [row(443, 'weak cipher on 443'), row(22, 'weak kex on 22'), row(8883, 'expired cert', { plugin: '040', pluginName: tlsCert.name })];
  const d = buildScanDelta({ baseline: { record: run('A'), findings: base, pluginStatus: [] },
    current: { record: run('B'), findings: [queueGap, ceGap], pluginStatus: [] } });
  const nc = (d.notComparable ?? []).map((f) => `${f.port}:${f.reason}`).sort();
  assert.deepEqual(nc, [`443:${PROBE_NOT_MEASURED_REASON}`, `8883:${PROBE_NOT_MEASURED_REASON}`], JSON.stringify(d.notComparable));
  assert.deepEqual((d.resolved ?? []).map((f) => f.port), [22], 'a measured port still resolves beside both gaps');
});
