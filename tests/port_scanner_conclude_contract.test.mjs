// tests/port_scanner_conclude_contract.test.mjs
// Run with: npm test  (which runs `node --test`)
//
// PRODUCER CONTRACT for port_scanner's conclude() adapter.
//
// WHY THIS FILE EXISTS (the defect it pins):
// port_scanner emits ONE data row per scanned port, but had NO conclude()
// adapter — so result_concluder fell through to fallbackRecord(), which does
// `const row = rows.find(Boolean)` and returns a SINGLE-element array. A real
// multi-port scan therefore collapsed N open ports into 1 service record (the
// first-SCANNED row, not the first OPEN one), and every consumer downstream —
// CE reports and the EE analysis agents alike — never saw the rest. Two
// separate defect classes came out of that one line:
//   (a) FALSE-CLEAN: open ports vanish before any consumer runs.
//   (b) FALSE-POSITIVE: the survivor's status came from `result.up` (a
//       host-level boolean), not from its own row, so a FILTERED port was
//       reported `open` whenever any OTHER port on the host was open.
// Both are reproduced below through the REAL concluder — no stub in the chain.
//
// See also EE tests/network_scan_path_live_smoke.test.mjs, which drives the
// same chain through to the EE agents + compliance routing.

import { test } from "node:test";
import assert from "node:assert/strict";
import net from "node:net";
import dgram from "node:dgram";

import portScanner from "../plugins/port_scanner.mjs";
import concluder from "../plugins/result_concluder.mjs";

/* ------------------------------ helpers ------------------------------ */

function listenTcp() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer((s) => { try { s.end(); } catch { /* ignore */ } });
    srv.once("error", reject);
    srv.listen(0, "127.0.0.1", () => resolve({ port: srv.address().port, close: () => srv.close() }));
  });
}

function getRefusedTcpPort() {
  return new Promise((resolve, reject) => {
    const s = net.createServer();
    s.once("error", reject);
    s.listen(0, "127.0.0.1", () => {
      const { port } = s.address();
      s.close(() => resolve(port));
    });
  });
}

function listenUdp() {
  return new Promise((resolve, reject) => {
    const sock = dgram.createSocket("udp4");
    sock.once("error", reject);
    sock.on("message", (msg, rinfo) => { try { sock.send(Buffer.from("hi"), rinfo.port, rinfo.address); } catch { /* ignore */ } });
    sock.bind(0, "127.0.0.1", () => resolve({ port: sock.address().port, close: () => sock.close() }));
  });
}

const conclude = (raw) => concluder.run({ results: [{ name: "Port Scanner", result: raw }] });

/* -------------------------------- tests ------------------------------- */

test("port_scanner conclude(): EVERY open port materializes as its own service record (multi-port collapse)", { timeout: 15000 }, async () => {
  const a = await listenTcp();
  const b = await listenTcp();
  const c = await listenTcp();
  const ports = [a.port, b.port, c.port];
  try {
    // REAL port_scanner -> REAL concluder. No stub, and a REALISTIC (multi-port)
    // input: single-port is the one shape at which 1-row-in/1-record-out hides
    // the collapse.
    const raw = await portScanner.run("127.0.0.1", 0, { tcpPorts: ports });

    // Anti-vacuity: the scan itself must have seen all three, else the
    // assertion below would be testing the scanner, not the adapter.
    assert.deepEqual([...raw.tcpOpen].sort((x, y) => x - y), [...ports].sort((x, y) => x - y),
      "precondition: the raw scan must find all three listeners open");

    const concluded = await conclude(raw);
    const openPorts = concluded.services.filter((s) => s.status === "open").map((s) => s.port).sort((x, y) => x - y);
    assert.deepEqual(openPorts, [...ports].sort((x, y) => x - y),
      `every open port must survive into services[] (got: ${JSON.stringify(concluded.services.map((s) => ({ port: s.port, status: s.status })))})`);
  } finally {
    a.close(); b.close(); c.close();
  }
});

test("port_scanner conclude(): status comes from the port's OWN row, never from the host-level result.up", async () => {
  // A filtered port cannot be produced against loopback (non-listening ports
  // RST rather than time out), so this case feeds the REAL concluder a
  // port_scanner-SHAPED result. The multi-port case above is the real-chain lens;
  // this one pins the status derivation that a real timeout would exercise.
  const raw = {
    up: true, program: "Unknown", version: "Unknown", os: null, type: "port-scan",
    tcpOpen: [22], tcpClosed: [], tcpFiltered: [3389], udpOpen: [], udpClosed: [], udpNoResponse: [],
    data: [
      { probe_protocol: "tcp", probe_port: 3389, status: "filtered", probe_info: "Timeout", response_banner: null, rtt_ms: 1200, error: "ETIMEDOUT" },
      { probe_protocol: "tcp", probe_port: 22, status: "open", probe_info: "TCP connect success (peer closed)", response_banner: null, rtt_ms: 2, error: null },
    ],
  };

  const concluded = await conclude(raw);

  const filtered = concluded.services.find((s) => s.port === 3389);
  assert.ok(!filtered || filtered.status !== "open",
    "a FILTERED port must never be reported open just because another port on the host is open " +
    "(fallbackRecord derived status from result.up — a host-level boolean — and fabricated an exposure)");

  const open = concluded.services.find((s) => s.port === 22);
  assert.ok(open && open.status === "open", "the genuinely open port must be present and open");
});

test("port_scanner conclude(): a refused port is NOT a service — the open ports scanned after it still are", { timeout: 15000 }, async () => {
  // services[] enumerates services FOUND. A refused port is the absence of one,
  // and it is not silently lost: the probe row stays in the conclusion's
  // evidence[] stream and in the scan's own tcpClosed bucket.
  //
  // MEASURED, and the reason this is not merely a taste call: a default sweep of
  // localhost (50 ports, config/services.json) sees 41 refusals and 1 listener.
  // Materializing refusals puts 42 rows into services[] — which every consumer
  // renders unfiltered (report_md table, export_csv row-per-service, SARIF
  // results, attack_map, and the scan_history baseline that deltas compare
  // against) — to carry one bit of signal.
  const a = await listenTcp();
  const refused = await getRefusedTcpPort();
  try {
    const raw = await portScanner.run("127.0.0.1", 0, { tcpPorts: [refused, a.port] });
    assert.deepEqual(raw.tcpClosed, [refused], "precondition: the unbound port must be refused (closed)");

    const concluded = await conclude(raw);
    assert.ok(!concluded.services.some((s) => s.port === refused),
      `a refused port must not appear in services[] (got: ${JSON.stringify(concluded.services.map((s) => ({ port: s.port, status: s.status })))})`);
    assert.ok(concluded.evidence.some((e) => e.port === refused),
      `...but its probe must remain in evidence[] (got: ${JSON.stringify(concluded.evidence)})`);

    const open = concluded.services.find((s) => s.port === a.port);
    assert.ok(open && open.status === "open",
      "the open listener scanned AFTER a refused port must still survive — under the old fallback the " +
      "refused port was the surviving record and the listener vanished");
  } finally {
    a.close();
  }
});

test("port_scanner conclude(): filtered / no-response rows produce NO service record but stay in evidence", async () => {
  const raw = {
    up: true, program: "Unknown", version: "Unknown", os: null, type: "port-scan",
    tcpOpen: [], tcpClosed: [], tcpFiltered: [3389], udpOpen: [], udpClosed: [], udpNoResponse: [161],
    data: [
      { probe_protocol: "tcp", probe_port: 3389, status: "filtered", probe_info: "Timeout", response_banner: null, rtt_ms: 1200, error: "ETIMEDOUT" },
      { probe_protocol: "udp", probe_port: 161, status: "no-response", probe_info: "No UDP response", response_banner: null, rtt_ms: 1200 },
    ],
  };

  const concluded = await conclude(raw);

  // A timeout tells us nothing about the port at all — even weaker evidence than
  // a refusal. Same disposition, same reason.
  assert.deepEqual(concluded.services.map((s) => s.port), [],
    `filtered / no-response probes must not become services (got: ${JSON.stringify(concluded.services)})`);
  const evidencePorts = concluded.evidence.map((e) => e.port);
  assert.ok(evidencePorts.includes(3389) && evidencePorts.includes(161),
    `both probes must remain in evidence[] (got: ${JSON.stringify(concluded.evidence)})`);
});

test("port_scanner conclude(): an open UDP port materializes with protocol udp alongside an open TCP port", { timeout: 15000 }, async () => {
  // Mixed sweep on purpose: TCP rows are emitted before UDP rows, so a UDP-only
  // scan is the degenerate shape in which the old single-record fallback happened
  // to carry the right protocol. Scanning both makes the case non-vacuous.
  const t = await listenTcp();
  const u = await listenUdp();
  try {
    const raw = await portScanner.run("127.0.0.1", 0, { tcpPorts: [t.port], udpPorts: [u.port] });
    assert.deepEqual(raw.udpOpen, [u.port], "precondition: the UDP responder must read open");
    assert.deepEqual(raw.tcpOpen, [t.port], "precondition: the TCP listener must read open");

    const concluded = await conclude(raw);
    const svc = concluded.services.find((s) => s.port === u.port && s.protocol === "udp");
    assert.ok(svc, `the open UDP port must materialize as a service (got: ${JSON.stringify(concluded.services.map((s) => ({ port: s.port, protocol: s.protocol })))})`);
    assert.equal(svc.status, "open");
    assert.ok(concluded.services.some((s) => s.port === t.port && s.protocol === "tcp"),
      "the TCP listener must materialize too — protocol keys the record, so both survive");
  } finally {
    t.close(); u.close();
  }
});

test("port_scanner conclude(): a TCP-connect discovery is labelled 'unknown', NOT a well-known service name", { timeout: 15000 }, async () => {
  // PROVENANCE PIN — load-bearing, and deliberately NOT a well-known-port map.
  //
  // port_scanner completes a TCP connect and nothing more; it has not
  // fingerprinted the protocol. 'unknown' is this codebase's documented
  // not-fingerprinted label (cf. syn_scanner's conclude(), and the EE
  // crypto_agent's CLEARTEXT_PORT_FALLBACK comment: "for services the scanner
  // could not fingerprint (CE labels those 'unknown')").
  //
  // Emitting a well-known NAME here (21 -> 'ftp', 23 -> 'telnet', 80 -> 'http')
  // would silently re-open a defect the EE crypto_agent already fixed from the
  // other side: a label match promotes its cleartext finding from the hedged
  // port-INFERRED tier (MEDIUM, "UNCONFIRMED") to the label-derived tier
  // (HIGH, "cleartext protocol with no in-band TLS upgrade") — certainty prose
  // over an unverified inference, routed into seven frameworks. Any change to
  // this label must re-derive every EE agent service-label map first.
  const a = await listenTcp();
  try {
    const raw = await portScanner.run("127.0.0.1", 0, { tcpPorts: [a.port] });
    const concluded = await conclude(raw);
    const svc = concluded.services.find((s) => s.port === a.port);

    assert.ok(svc && svc.status === "open", "precondition: the listener must be discovered open");
    assert.equal(svc.service, "unknown",
      "a bare TCP-connect discovery must carry the not-fingerprinted label");
    assert.notEqual(svc.service, "port",
      "'port' was the fallbackRecord signature (plugin NAME, lowercased) — its presence means the " +
      "conclude() adapter was skipped and the multi-port collapse is back");
    assert.equal(svc.source, "port_scanner", "source is stamped from the plugin module slug");
  } finally {
    a.close();
  }
});

test("port_scanner conclude(): each service carries its OWN probe row as evidence", { timeout: 15000 }, async () => {
  const a = await listenTcp();
  const b = await listenTcp();
  try {
    const raw = await portScanner.run("127.0.0.1", 0, { tcpPorts: [a.port, b.port] });
    const concluded = await conclude(raw);
    const svc = concluded.services.find((s) => s.port === a.port);
    assert.ok(svc, "precondition: the listener must be discovered");
    assert.ok(Array.isArray(svc.evidence) && svc.evidence.length === 1,
      `per-record evidence must be the record's own row, not the whole sweep (got ${JSON.stringify(svc.evidence)})`);
    assert.equal(svc.evidence[0].probe_port, a.port);
  } finally {
    a.close(); b.close();
  }
});
