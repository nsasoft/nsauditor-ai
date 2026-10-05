// tests/host_up_check_udp_leg.test.mjs
// 1.2.1 lane 1 F — host_up_check's UDP leg marked the host UP on any successful send.
//
// A successful UDP send says only that the local stack accepted the datagram; it is no evidence
// that anything is listening at the far end. The leg used to set `up = true` in the send callback,
// clear its 3 s wait and close the socket, so a host that never answered read UP (and
// plugin_manager's row-text heuristic, `/host .*up|ping .*success|success/`, read the row the same
// way), while an ICMP port-unreachable arriving after the send — the real order on loopback — was
// discarded with the closed socket. Evidence of UP is now an ICMP port-unreachable or a reply;
// silence until the timeout is recorded as "no evidence", never as "down".
//
// Harness: ping is captured at module load (`promisify(execFile)`), so child_process.execFile is
// stubbed BEFORE the import and the builtin ESM exports are re-synced; net.Socket and
// dgram.createSocket are read at call time and are swapped per test. Every leg but the last stubs
// all three probes, so no packet leaves the process; the last drives a REAL dgram socket against
// 127.0.0.1 only. The fake UDP socket behaves as dgram does where it matters here: a closed socket
// emits nothing, and closing it twice throws.

import { test, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { promisify } from 'node:util';
import { EventEmitter } from 'node:events';
import { syncBuiltinESMExports } from 'node:module';
import cp from 'node:child_process';
import net from 'node:net';
import dgram from 'node:dgram';

const realExecFile = cp.execFile;
let pingAnswers = false; // per test; the plugin keeps this stub for the life of the process
const PING_REPLY = '64 bytes from 192.0.2.10: icmp_seq=0 ttl=64 time=0.1 ms\n1 packets transmitted, 1 received, 0% packet loss\n';
function pingBlocked() {
  return Object.assign(new Error('stub: ping blocked'), { code: 1, stdout: '', stderr: '' });
}
function fakeExecFile(...args) {
  const cb = args[args.length - 1];
  queueMicrotask(() => (pingAnswers ? cb(null, PING_REPLY, '') : cb(pingBlocked(), '', '')));
}
fakeExecFile[promisify.custom] = () =>
  (pingAnswers ? Promise.resolve({ stdout: PING_REPLY, stderr: '' }) : Promise.reject(pingBlocked()));
cp.execFile = fakeExecFile;
syncBuiltinESMExports();
const { default: hostUpCheck } = await import('../plugins/host_up_check.mjs');
cp.execFile = realExecFile;
syncBuiltinESMExports();

const realSocket = net.Socket;
const realCreateSocket = dgram.createSocket;
afterEach(() => {
  net.Socket = realSocket;
  dgram.createSocket = realCreateSocket;
  pingAnswers = false;
});

const HOST = '192.0.2.10'; // TEST-NET-1; never contacted — every probe below is stubbed
const UDP_PORT = 54321;

// Every TCP probe times out: no TCP evidence either way.
class TimeoutTcpSocket extends EventEmitter {
  setTimeout() {}
  connect() { setImmediate(() => this.emit('timeout')); }
  destroy() {}
}

// Port 22 refuses (RST — the host answered); every other TCP probe times out.
class RefusingSshTcpSocket extends TimeoutTcpSocket {
  connect(port) {
    if (port !== 22) return super.connect(port);
    setImmediate(() => this.emit('error', Object.assign(new Error('connect ECONNREFUSED'), { code: 'ECONNREFUSED' })));
  }
}

function refusedError() {
  return Object.assign(new Error('connect ECONNREFUSED'), { code: 'ECONNREFUSED', syscall: 'recvmsg' });
}

/**
 * A fake dgram socket. `scenario`:
 *   'send-refused'  — the send callback itself reports ECONNREFUSED
 *   'late-refused'  — the send succeeds, then ICMP port-unreachable arrives as an 'error' event
 *   'reply'         — the send succeeds, then a datagram arrives
 *   'reply+refused' — the send succeeds, then a datagram AND an ICMP error arrive in one turn
 *   'silent'        — the send succeeds and nothing ever arrives
 */
function installUdp(scenario) {
  const record = { connects: [], sends: 0, closes: 0 };
  dgram.createSocket = () => {
    const s = new EventEmitter();
    let closed = false;
    const deliver = (fn) => setTimeout(() => { if (!closed) fn(); }, 20);
    s.connect = (port, host, cb) => {
      record.connects.push([port, host]);
      setImmediate(() => { if (!closed) cb?.(); });
    };
    s.send = (_buf, cb) => {
      record.sends += 1;
      setImmediate(() => {
        if (scenario === 'send-refused') return cb(refusedError());
        cb(null, 0);
        if (scenario === 'late-refused') deliver(() => s.emit('error', refusedError()));
        if (scenario === 'reply') deliver(() => s.emit('message', Buffer.from('pong'), { address: HOST, port: UDP_PORT }));
        if (scenario === 'reply+refused') deliver(() => {
          s.emit('message', Buffer.from('pong'), { address: HOST, port: UDP_PORT });
          s.emit('error', refusedError());
        });
      });
    };
    s.close = () => {
      record.closes += 1;
      if (closed) throw Object.assign(new Error('Not running'), { code: 'ERR_SOCKET_DGRAM_NOT_RUNNING' });
      closed = true;
    };
    return s;
  };
  return record;
}

async function runWith(scenario, { Tcp = TimeoutTcpSocket } = {}) {
  net.Socket = Tcp;
  const udp = installUdp(scenario);
  const t0 = Date.now();
  const res = await hostUpCheck.run(HOST);
  const ms = Date.now() - t0;
  const snapshot = res.data.length;
  // Anything that would append a row AFTER run() resolved has had time to fire by now.
  await new Promise((r) => setTimeout(r, 150));
  const udpRows = res.data.filter((d) => d.probe_protocol === 'udp');
  return { res, udp, udpRows, ms, lateRows: res.data.length - snapshot };
}

// ── ACCEPT: a host that answers ICMP or TCP stays UP while UDP is silent ─────

test('(fourth quadrant, first) ping answers, UDP silent — UP, from the ping', { timeout: 10_000 }, async () => {
  pingAnswers = true;
  const { res, udpRows } = await runWith('silent');
  assert.equal(res.up, true);
  assert.match(res.data.find((d) => d.probe_protocol === 'icmp').probe_info, /^Ping successful/);
  assert.equal(udpRows.length, 1);
});

test('(fourth quadrant) a TCP port refuses, ping blocked, UDP silent — UP, from the refusal', { timeout: 10_000 }, async () => {
  const { res, udpRows } = await runWith('silent', { Tcp: RefusingSshTcpSocket });
  assert.equal(res.up, true);
  const ssh = res.data.find((d) => d.probe_protocol === 'tcp' && d.probe_port === 22);
  assert.equal(ssh.probe_info, 'Connection refused - host up');
  assert.equal(udpRows.length, 1);
});

// ── ACCEPT: a real UDP signal still reads UP ─────────────────────────────────

test('(fourth quadrant, first) ICMP port-unreachable on the send callback reads UP with one UDP row', async () => {
  const { res, udp, udpRows } = await runWith('send-refused');
  assert.equal(res.up, true);
  assert.equal(udpRows.length, 1);
  assert.equal(udpRows[0].probe_port, UDP_PORT);
  assert.equal(udpRows[0].probe_info, 'ICMP Port Unreachable - host up');
  assert.deepEqual(udp.connects, [[UDP_PORT, HOST]]);
  assert.equal(udp.closes, 1);
});

test('(fourth quadrant) ICMP port-unreachable arriving AFTER a successful send — the order on loopback — reads UP and the row names it', async () => {
  const { res, udp, udpRows, lateRows } = await runWith('late-refused');
  assert.equal(res.up, true);
  assert.equal(udpRows.length, 1, `one UDP row, got ${JSON.stringify(udpRows)}`);
  assert.equal(udpRows[0].probe_info, 'ICMP Port Unreachable - host up');
  assert.equal(lateRows, 0);
  assert.equal(udp.closes, 1);
});

test('(fourth quadrant) a UDP reply reads UP and the row names it', async () => {
  const { res, udp, udpRows } = await runWith('reply');
  assert.equal(res.up, true);
  assert.equal(udpRows.length, 1, `one UDP row, got ${JSON.stringify(udpRows)}`);
  assert.equal(udpRows[0].probe_info, 'UDP reply - host up');
  assert.equal(udp.closes, 1);
});

// ── DEFECT: a successful send is not evidence ────────────────────────────────

test('a successful send followed by silence is NOT up — one row, "no evidence", never "up", "success" or "down"', { timeout: 10_000 }, async () => {
  const { res, udpRows, ms, lateRows } = await runWith('silent');
  assert.equal(res.up, false, 'ping blocked, every TCP probe timed out, UDP silent: nothing says up');
  assert.equal(udpRows.length, 1, `one UDP row, got ${JSON.stringify(udpRows)}`);
  assert.match(udpRows[0].probe_info, /no evidence/i);
  // No row of this run may read as up to plugin_manager's row-text heuristic, nor claim "down".
  for (const d of res.data) {
    assert.doesNotMatch(String(d.probe_info), /\bup\b|success/i, `row reads as up: ${d.probe_info}`);
  }
  assert.doesNotMatch(udpRows[0].probe_info, /down/i);
  assert.equal(lateRows, 0);
  // The cost of waiting for a reply, stated: a silent host adds up to the 3 s UDP timeout.
  assert.ok(ms >= 2_900 && ms < 4_000, `silent UDP leg should wait ~3 s for a reply, took ${ms} ms`);
});

test('settles once: a reply and an ICMP error in the same turn give ONE row, ONE close, no late rows', async () => {
  const { res, udp, udpRows, lateRows } = await runWith('reply+refused');
  assert.equal(res.up, true);
  assert.equal(udpRows.length, 1, `one UDP row, got ${JSON.stringify(udpRows)}`);
  assert.equal(udpRows[0].probe_info, 'UDP reply - host up');
  assert.equal(udp.closes, 1, 'dgram throws on a second close');
  assert.equal(lateRows, 0);
});

// ── REAL dependency: the true signal on loopback is captured, not discarded ──

test('real dgram against 127.0.0.1: the ICMP port-unreachable that follows the send reads UP', { timeout: 10_000 }, async (t) => {
  // The port must be closed for the kernel to answer port-unreachable; prove it is free first.
  const free = await new Promise((resolve) => {
    const probe = realCreateSocket('udp4');
    probe.once('error', () => { probe.close(); resolve(false); });
    probe.bind(UDP_PORT, '127.0.0.1', () => probe.close(() => resolve(true)));
  });
  if (!free) return t.skip(`127.0.0.1:${UDP_PORT}/udp is bound on this machine — no port-unreachable to observe`);
  net.Socket = TimeoutTcpSocket; // TCP stubbed; ping is stubbed for the module's life; dgram is real
  const res = await hostUpCheck.run('127.0.0.1');
  const udpRows = res.data.filter((d) => d.probe_protocol === 'udp');
  assert.equal(udpRows.length, 1, `one UDP row, got ${JSON.stringify(udpRows)}`);
  assert.equal(udpRows[0].probe_info, 'ICMP Port Unreachable - host up');
  assert.equal(res.up, true);
});
