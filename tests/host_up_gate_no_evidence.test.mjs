// tests/host_up_gate_no_evidence.test.mjs
// 1.2.1 lane 1 F, ruling (ii) — the port scan is the measurement that decides liveness, so it is not
// gated on a liveness guess; and nothing renders "no evidence the host is up" as DOWN.
//
// Before: port_scanner required `host: "up"`, so with no discovery evidence it was SKIPPED ("host not
// up") and the concluder printed "Host appears DOWN" — driven through the real CLI over an OPEN
// loopback listener: `003 skipped "host not up"`, "Host appears DOWN — No open services detected",
// services []. That was hidden behind host_up_check's send lie, which read almost every host UP; with
// the lie removed (lane F) a firewalled host whose open ports are uncommon would have lost its port
// scan. The seam, end to end: host_up_check → ctx.hostUp → port_scanner's own `up` (an ANSWER only —
// tests/port_scanner_liveness.test.mjs) → every `host: "up"` gate (describeSkipReason) and the
// concluder's summary.
//
// Harness: child_process.execFile is stubbed BEFORE the plugins load (ping_checker and host_up_check
// capture `promisify(execFile)` at module load) and restored straight after, so ping always fails
// in-process; net.Socket and dgram.createSocket are swapped per test. In-process legs never touch the
// network. The CLI legs spawn the real CLI against 127.0.0.1 (a listener this file starts) and
// 127.0.0.2 (only after proving the address is silent on this machine), with HOME and cwd in scratch.

import { withNoDotenv } from './helpers/no_operator_dotenv.mjs';
import './helpers/no_operator_home.mjs';
import { test, afterEach, after } from 'node:test';
import assert from 'node:assert/strict';
import { promisify } from 'node:util';
import { EventEmitter } from 'node:events';
import { syncBuiltinESMExports } from 'node:module';
import cp from 'node:child_process';
import net from 'node:net';
import dgram from 'node:dgram';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

process.env.AI_ENABLED = 'false';

const realExecFile = cp.execFile;
function noAnswer() {
  return Object.assign(new Error('stub: no answer'), { code: 1, stdout: '', stderr: '' });
}
function fakeExecFile(...args) {
  const cb = args[args.length - 1];
  if (typeof cb === 'function') queueMicrotask(() => cb(noAnswer(), '', ''));
}
fakeExecFile[promisify.custom] = () => Promise.reject(noAnswer());
cp.execFile = fakeExecFile;
syncBuiltinESMExports();
const { PluginManager } = await import('../plugin_manager.mjs');
const { default: pingChecker } = await import('../plugins/ping_checker.mjs');
const { default: hostUpCheck } = await import('../plugins/host_up_check.mjs');
const { default: portScanner } = await import('../plugins/port_scanner.mjs');
const { default: tlsAuditor } = await import('../plugins/040_tls_cert_auditor.mjs');
const { default: mcpScanner } = await import('../plugins/mcp_scanner.mjs');
const { default: concluder } = await import('../plugins/result_concluder.mjs');
cp.execFile = realExecFile;
syncBuiltinESMExports();

const realSocket = net.Socket;
const realCreateSocket = dgram.createSocket;
afterEach(() => {
  net.Socket = realSocket;
  dgram.createSocket = realCreateSocket;
});

const HOST = '192.0.2.10'; // TEST-NET-1; in-process legs never contact it
const NO_EVIDENCE = /no evidence the host is up/i;

// ── fakes ────────────────────────────────────────────────────────────────────

class SilentTcp extends EventEmitter { // every TCP connect times out
  setTimeout() {}
  setNoDelay() {}
  destroy() {}
  connect() { setImmediate(() => this.emit('timeout')); }
}
function silentUdp() { // sends succeed, nothing ever comes back
  const s = new EventEmitter();
  let closed = false;
  s.connect = (_p, _h, cb) => setImmediate(() => { if (!closed) cb?.(); });
  s.send = (...args) => { const cb = args.find((a) => typeof a === 'function'); setImmediate(() => cb?.(null, 0)); };
  s.bind = (...args) => { const cb = args.find((a) => typeof a === 'function'); setImmediate(() => cb?.()); };
  s.close = (cb) => { closed = true; cb?.(); };
  s.unref = () => s;
  s.ref = () => s;
  s.address = () => ({ address: '0.0.0.0', port: 0, family: 'IPv4' });
  return s;
}

// A real module's identity and requirements, with its network work replaced by a fixed result.
function stubbed(mod, result, ran) {
  return { ...mod, run: async () => { ran.push(String(mod.id)); return result; } };
}
const NO_PING = { up: false, data: [{ probe_protocol: 'icmp', probe_port: null, probe_info: 'Ping failed', response_banner: null }] };
const NO_EVIDENCE_005 = { up: false, os: null, router_info: null,
  data: [{ probe_protocol: 'udp', probe_port: 54321, probe_info: 'No reply within 3 s - no evidence either way', response_banner: null }] };
const PING_UP = { up: true, data: [{ probe_protocol: 'icmp', probe_port: null, probe_info: 'Ping successful', response_banner: null }] };
const OPEN_8443 = { up: true, tcpOpen: [8443], tcpClosed: [], tcpFiltered: [], udpOpen: [], udpNoResponse: [],
  data: [{ probe_protocol: 'tcp', probe_port: 8443, status: 'open', probe_info: 'TCP connect success (peer closed)', response_banner: null }] };
const ALL_SILENT = { up: false, tcpOpen: [], tcpClosed: [], tcpFiltered: [22, 8443], udpOpen: [], udpNoResponse: [],
  data: [22, 8443].map((p) => ({ probe_protocol: 'tcp', probe_port: p, status: 'filtered', probe_info: 'Timeout', response_banner: null })) };

async function runManager(results) {
  const ran = [];
  const mgr = await PluginManager.create({ plugins: [
    stubbed(pingChecker, results['001'], ran),
    stubbed(hostUpCheck, results['005'], ran),
    stubbed(portScanner, results['003'], ran),
    stubbed(mcpScanner, { up: false, data: [] }, ran),
    stubbed(tlsAuditor, { up: false, data: [] }, ran),
  ] });
  const out = await mgr.run(HOST, 'all');
  const status = Object.fromEntries(out.manifest.map((m) => [String(m.id), m]));
  return { ran, status };
}

// ── the gates, through the REAL PluginManager and each module's REAL requirements ──

test('(fourth quadrant, first) ping answers — the port scan and every host:"up" gate run, as today', async () => {
  const { ran, status } = await runManager({ '001': PING_UP, '005': NO_EVIDENCE_005, '003': OPEN_8443 });
  assert.equal(status['005'].status, 'skipped', '005 runs only while nothing has said up');
  for (const id of ['003', '070', '040']) assert.equal(status[id].status, 'ran', id);
  assert.deepEqual(ran, ['001', '003', '070', '040']);
});

test('no discovery evidence — the port scan STILL runs, and the port it finds opens every downstream gate', async () => {
  const { status } = await runManager({ '001': NO_PING, '005': NO_EVIDENCE_005, '003': OPEN_8443 });
  assert.equal(status['003'].status, 'ran', `port scan: ${JSON.stringify(status['003'])}`);
  for (const id of ['070', '040']) assert.equal(status[id].status, 'ran', `${id}: ${JSON.stringify(status[id])}`);
});

test('no discovery evidence and nothing answers the port scan — it RAN, and the gates it leaves shut say "no evidence", never "down"', async () => {
  const { status } = await runManager({ '001': NO_PING, '005': NO_EVIDENCE_005, '003': ALL_SILENT });
  assert.equal(status['003'].status, 'ran');
  for (const id of ['070', '040']) {
    assert.equal(status[id].status, 'skipped', id);
    assert.match(status[id].reason, NO_EVIDENCE, `${id}: ${status[id].reason}`);
    assert.doesNotMatch(status[id].reason, /down/i);
  }
});

// ── the concluder, on the EXACT result shape the real port scanner produces ──

async function conclude(results) {
  const c = await concluder.run(null, 0, { results });
  return c?.summary ?? c?.result?.summary;
}

test('(fourth quadrant) a found port — the summary still says the host is UP', async () => {
  const summary = await conclude([
    { id: '001', name: 'Ping Checker', result: NO_PING },
    { id: '003', name: 'Port Scanner', result: OPEN_8443 },
  ]);
  assert.match(summary, /^Host is UP/);
});

test('every port silent — the real port scanner\'s result reads "No evidence the host is up", neither UP nor DOWN', async () => {
  net.Socket = SilentTcp;
  const scanned = await portScanner.run(HOST, 0, { tcpPorts: [22, 8443], udpPorts: [], timeoutMs: 50 });
  assert.deepEqual(scanned.tcpFiltered, [22, 8443]);
  const summary = await conclude([
    { id: '001', name: 'Ping Checker', result: NO_PING },
    { id: '005', name: 'Host Up Check', result: NO_EVIDENCE_005 },
    { id: '003', name: 'Port Scanner', result: scanned },
  ]);
  assert.match(summary, NO_EVIDENCE, summary);
  assert.doesNotMatch(summary, /\bUP\b/, summary); // the "is UP" claim, case-sensitive
  assert.doesNotMatch(summary, /down/i, summary);
});

// ── P2′: the whole chain, every plugin REAL, only the network stubbed — runs on every platform ──

test('P2′ (stubbed twin of P2): real 001 → 005 → 003 → concluder over a host that answers nothing', { timeout: 30_000 }, async () => {
  net.Socket = SilentTcp;
  dgram.createSocket = () => silentUdp();
  const prev = process.env.TCP_CONNECT_TIMEOUT_MS;
  process.env.TCP_CONNECT_TIMEOUT_MS = '100'; // the port scanner's UDP wait; TCP times out at once
  try {
    const mgr = await PluginManager.create({ plugins: [pingChecker, hostUpCheck, portScanner, concluder] });
    const out = await mgr.run(HOST, 'all');
    const status = Object.fromEntries(out.manifest.map((m) => [String(m.id), m.status]));
    for (const id of ['001', '005', '003']) assert.equal(status[id], 'ran', `${id}: ${JSON.stringify(out.manifest)}`);
    const byId = Object.fromEntries(out.results.map((r) => [String(r.id), r.result]));
    assert.equal(byId['005'].up, false);
    assert.match(byId['005'].data.find((d) => d.probe_protocol === 'udp').probe_info, /no evidence/i);
    assert.equal(byId['003'].up, false, 'every port filtered is no answer');
    const summary = out.conclusion?.result?.summary;
    assert.match(summary, NO_EVIDENCE, summary);
    assert.doesNotMatch(summary, /\bUP\b/, summary); // the "is UP" claim, case-sensitive
    assert.doesNotMatch(summary, /down/i, summary);
  } finally {
    if (prev === undefined) delete process.env.TCP_CONNECT_TIMEOUT_MS; else process.env.TCP_CONNECT_TIMEOUT_MS = prev;
  }
});

// ── P1 and P2: the REAL CLI, no stub ─────────────────────────────────────────

const CLI = fileURLToPath(new URL('../cli.mjs', import.meta.url));
const WORK = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-host-up-gate-'));
after(() => fs.rmSync(WORK, { recursive: true, force: true }));

function scanCli(args, name) {
  const out = path.join(WORK, name);
  const env = { ...process.env, NSA_ALLOW_ALL_HOSTS: '1', AI_ENABLED: 'false' };
  delete env.NODE_TEST_CONTEXT;
  return new Promise((resolve) => {
    const child = cp.spawn(process.execPath, [CLI, 'scan', ...args, '--out', out], { cwd: WORK, env: withNoDotenv(env) });
    let stderr = '';
    child.stderr.on('data', (d) => { stderr += d; });
    child.on('close', (code) => {
      const hostDir = fs.existsSync(out) ? fs.readdirSync(out).find((n) => /_\d{8}_\d{6}$/.test(n)) : null;
      const raw = hostDir ? JSON.parse(fs.readFileSync(path.join(out, hostDir, 'scan_conclusion_raw.json'), 'utf8')) : null;
      resolve({ code, stderr, raw });
    });
  });
}

test('P1 (real CLI): --plugins 003 alone over an OPEN loopback listener — the port scan runs and finds it', { timeout: 60_000 }, async () => {
  const server = net.createServer((c) => c.end());
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const port = server.address().port;
  try {
    const { code, stderr, raw } = await scanCli(['--host', '127.0.0.1', '--ports', String(port), '--plugins', '003'], 'p1');
    assert.equal(code, 0, stderr.slice(0, 600));
    const ps = raw.pluginStatus.find((p) => p.id === '003');
    assert.equal(ps.status, 'ran', JSON.stringify(ps));
    assert.ok(raw.conclusion.result.services.some((s) => s.port === port && s.status === 'open'), `port ${port} not found open`);
    assert.match(raw.summary, /^Host is UP/);
  } finally {
    server.close();
  }
});

test('P2 (real CLI): 127.0.0.2 through 001 → 005 → 003 — a host that answers nothing reads "no evidence", neither UP nor DOWN', { timeout: 90_000 }, async (t) => {
  const silent = await new Promise((resolve) => {
    const s = new realSocket();
    s.setTimeout(700);
    s.once('timeout', () => { s.destroy(); resolve(true); });
    s.once('connect', () => { s.destroy(); resolve(false); });
    s.once('error', () => { s.destroy(); resolve(false); });
    s.connect(9, '127.0.0.2');
  });
  if (!silent) {
    const why = '127.0.0.2 ANSWERS on this machine (Linux answers all of 127/8) — no silent local host; P2′ covers the chain here';
    t.diagnostic(why);
    return t.skip(why);
  }
  const { code, stderr, raw } = await scanCli(['--host', '127.0.0.2', '--ports', '22,8443', '--plugins', '001,005,003'], 'p2');
  assert.equal(code, 0, stderr.slice(0, 600));
  const status = Object.fromEntries(raw.pluginStatus.map((p) => [p.id, p.status]));
  assert.deepEqual(status, { '001': 'ran', '005': 'ran', '003': 'ran' });
  const byId = Object.fromEntries(raw.results.map((r) => [String(r.id), r.result]));
  assert.equal(byId['005'].up, false);
  assert.match(byId['005'].data.find((d) => d.probe_protocol === 'udp').probe_info, /no evidence/i);
  assert.equal(byId['003'].up, false);
  assert.match(raw.summary, NO_EVIDENCE, raw.summary);
  assert.doesNotMatch(raw.summary, /\bUP\b/, raw.summary); // the "is UP" claim, case-sensitive
  assert.doesNotMatch(raw.summary, /down/i, raw.summary);
});
