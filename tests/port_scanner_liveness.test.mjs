// tests/port_scanner_liveness.test.mjs
// 1.2.1 lane 1 F — the port scanner's host-level `up` counts only an ANSWER from the host.
//
// `up` was `anyTcpEvidence || anyUdpOpen` with anyTcpEvidence = open || closed || FILTERED, and
// classifyTcpError files a timeout, EHOSTUNREACH / ENETUNREACH and any other socket error under
// 'filtered'. So a host that answered nothing read UP — driven against 127.0.0.2 on macOS (routed via
// lo0, unassigned, silent): `up: true, tcpFiltered: [22, 8443]`, every row 'Timeout'. While the port
// scan was gated on `host: "up"` something else had always said up first; once it runs ungated
// (lane F, ruling (ii)) its own `up` opens every downstream gate, so a timeout counted as liveness
// would read every silent host UP. A SYN-ACK or an RST is the host's answer; a timeout is silence,
// and an unreachable is likelier a router's word than the host's. The rows keep every status either
// way — only the host-level verdict changes.
//
// Harness: net.Socket is read at call time and swapped per test; the target is TEST-NET-1 and is
// never contacted. The last leg drives the real socket against 127.0.0.2 only, after proving the
// address is silent on this machine (Linux answers all of 127/8, so there it is skipped, saying why).

import { test, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import net from 'node:net';
import portScanner from '../plugins/port_scanner.mjs';

const realSocket = net.Socket;
afterEach(() => { net.Socket = realSocket; });

// outcome: 'open' | 'timeout' | an errno code (ECONNREFUSED, EHOSTUNREACH, …)
function fakeTcp(outcomeFor) {
  return class extends EventEmitter {
    setTimeout() {}
    setNoDelay() {}
    destroy() {}
    connect(port) {
      const o = outcomeFor(port);
      setImmediate(() => {
        if (o === 'open') this.emit('connect');
        else if (o === 'timeout') this.emit('timeout');
        else this.emit('error', Object.assign(new Error(`connect ${o}`), { code: o }));
      });
    }
  };
}

async function scan(outcomeFor, tcpPorts = [22, 8443]) {
  net.Socket = fakeTcp(outcomeFor);
  return portScanner.run('192.0.2.10', 0, { tcpPorts, udpPorts: [], timeoutMs: 50, bannerTimeoutMs: 10 });
}

test('(fourth quadrant, first) an RST is the host answering — every port refused reads UP', async () => {
  const r = await scan(() => 'ECONNREFUSED');
  assert.equal(r.up, true);
  assert.deepEqual(r.tcpClosed, [22, 8443]);
});

test('(fourth quadrant) one open port among timeouts reads UP', async () => {
  const r = await scan((p) => (p === 8443 ? 'open' : 'timeout'));
  assert.equal(r.up, true);
  assert.deepEqual(r.tcpOpen, [8443]);
  assert.deepEqual(r.tcpFiltered, [22]);
});

test('a host that answers nothing is NOT up — every port timed out', async () => {
  const r = await scan(() => 'timeout');
  assert.equal(r.up, false);
  assert.deepEqual(r.tcpFiltered, [22, 8443], 'the timeouts are still recorded, port by port');
  assert.ok(r.data.every((d) => d.status === 'filtered' && d.probe_info === 'Timeout'));
});

test('an unreachable is not the host answering — every port EHOSTUNREACH / ENETUNREACH is NOT up', async () => {
  for (const code of ['EHOSTUNREACH', 'ENETUNREACH']) {
    const r = await scan(() => code);
    assert.equal(r.up, false, code);
    assert.ok(r.data.every((d) => d.status === 'filtered' && d.probe_info === 'Unreachable'), code);
  }
});

test('any other socket error alone is NOT up', async () => {
  const r = await scan(() => 'EADDRNOTAVAIL');
  assert.equal(r.up, false);
  assert.ok(r.data.every((d) => d.status === 'filtered'));
});

test('real socket against 127.0.0.2: a host that answers nothing is NOT up', { timeout: 15_000 }, async (t) => {
  const silent = await new Promise((resolve) => {
    const s = realSocket ? new realSocket() : null;
    s.setTimeout(700);
    s.once('timeout', () => { s.destroy(); resolve(true); });
    s.once('connect', () => { s.destroy(); resolve(false); });
    s.once('error', () => { s.destroy(); resolve(false); });
    s.connect(9, '127.0.0.2');
  });
  if (!silent) return t.skip('127.0.0.2 answers on this machine (Linux answers all of 127/8) — no silent local host to drive');
  const r = await portScanner.run('127.0.0.2', 0, { tcpPorts: [22, 8443], udpPorts: [], timeoutMs: 800 });
  assert.deepEqual(r.tcpFiltered, [22, 8443]);
  assert.equal(r.up, false);
});
