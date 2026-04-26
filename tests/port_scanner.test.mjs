// tests/port_scanner.test.mjs
// Run with: npm test  (which runs `node --test`)

import { test } from "node:test";
import assert from "node:assert/strict";
import net from "node:net";
import dgram from "node:dgram";

import portScanner, { parsePortsSpec } from "../plugins/port_scanner.mjs";

/* ------------------------------ helpers ------------------------------ */

function startTcpBannerServer({ banner = "HELLO\r\n" } = {}) {
  return new Promise((resolve, reject) => {
    const server = net.createServer((socket) => {
      // send a short banner, then close
      socket.write(banner);
      socket.end();
    });
    server.on("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      resolve({
        port,
        close: () => server.close(),
      });
    });
  });
}

function startUdpServer({ mode = "reply", reply = Buffer.from("hi") } = {}) {
  return new Promise((resolve, reject) => {
    const server = dgram.createSocket("udp4");
    server.on("error", reject);
    server.on("message", (msg, rinfo) => {
      if (mode === "reply") {
        server.send(reply, rinfo.port, rinfo.address);
      } // else "silent" -> do nothing
    });
    server.bind(0, "127.0.0.1", () => {
      const { port } = server.address();
      resolve({
        port,
        close: () => server.close(),
      });
    });
  });
}

function getUnusedTcpPort() {
  return new Promise((resolve, reject) => {
    const s = net.createServer();
    s.on("error", reject);
    s.listen(0, "127.0.0.1", () => {
      const { port } = s.address();
      s.close(() => resolve(port));
    });
  });
}

/* -------------------------------- tests ------------------------------- */

test("port_scanner: TCP open with banner is captured", { timeout: 3000 }, async () => {
  const { port, close } = await startTcpBannerServer({ banner: "220 Welcome\r\n" });
  try {
    const res = await portScanner.run("127.0.0.1", 0, {
      tcpPorts: [port],
      udpPorts: [],
      timeoutMs: 600,
      bannerTimeoutMs: 200,
      bannerBytes: 256,
      concurrency: 4,
    });

    // basic shape
    assert.equal(res.type, "port-scan");
    assert.ok(Array.isArray(res.data));

    // should record TCP open + banner
    assert.ok(res.tcpOpen.includes(port));
    const row = res.data.find(
      (d) => d.probe_protocol === "tcp" && d.probe_port === port
    );
    assert.ok(row, "TCP data row exists");
    assert.equal(row.status, "open");
    assert.ok((row.response_banner || "").startsWith("220 Welcome"));
    assert.equal(res.up, true);
  } finally {
    close();
  }
});

test("port_scanner: TCP closed (ECONNREFUSED) is detected", { timeout: 3000 }, async () => {
  // Find a port, close the server, then scan that (no listener => ECONNREFUSED)
  const freePort = await getUnusedTcpPort();

  const res = await portScanner.run("127.0.0.1", 0, {
    tcpPorts: [freePort],
    udpPorts: [],
    timeoutMs: 500,
    bannerTimeoutMs: 100,
    concurrency: 4,
  });

  assert.ok(Array.isArray(res.tcpClosed));
  assert.ok(res.tcpClosed.includes(freePort));
  const row = res.data.find(
    (d) => d.probe_protocol === "tcp" && d.probe_port === freePort
  );
  assert.ok(row, "TCP data row exists (closed)");
  assert.equal(row.status, "closed");
  assert.match(row.probe_info, /refused/i);
  // "up" should still be true because we observed a definitive TCP signal
  assert.equal(res.up, true);
});

test("port_scanner: UDP open when server replies", { timeout: 3000 }, async () => {
  const { port, close } = await startUdpServer({ mode: "reply" });
  try {
    const res = await portScanner.run("127.0.0.1", 0, {
      tcpPorts: [],
      udpPorts: [port],
      timeoutMs: 400, // how long to wait for UDP reply
      concurrency: 4,
    });

    assert.ok(res.udpOpen.includes(port));
    const row = res.data.find(
      (d) => d.probe_protocol === "udp" && d.probe_port === port
    );
    assert.ok(row, "UDP data row exists (open)");
    assert.equal(row.status, "open");
    assert.match(row.probe_info, /UDP response/i);
    assert.equal(res.up, true);
  } finally {
    close();
  }
});

test("port_scanner: UDP no-response when server is silent", { timeout: 3000 }, async () => {
  // Bind UDP server but do not reply -> scanner should mark "no-response"
  const { port, close } = await startUdpServer({ mode: "silent" });
  try {
    const res = await portScanner.run("127.0.0.1", 0, {
      tcpPorts: [],
      udpPorts: [port],
      timeoutMs: 250, // keep tests snappy
      concurrency: 4,
    });

    assert.ok(res.udpNoResponse.includes(port));
    const row = res.data.find(
      (d) => d.probe_protocol === "udp" && d.probe_port === port
    );
    assert.ok(row, "UDP data row exists (no-response)");
    assert.equal(row.status, "no-response");
    assert.match(row.probe_info, /no udp response/i);
    // up may be false if no definitive open/closed signals arrived
    assert.equal(typeof res.up, "boolean");
  } finally {
    close();
  }
});

test("port_scanner: aggregates lists correctly and doesn’t scan defaults when lists provided", { timeout: 3000 }, async () => {
  const { port: tcpOpen, close: closeTcp } = await startTcpBannerServer({ banner: "HELLO\r\n" });
  const freeTcp = await getUnusedTcpPort();
  const { port: udpSilent, close: closeUdpSilent } = await startUdpServer({ mode: "silent" });

  try {
    const res = await portScanner.run("127.0.0.1", 0, {
      tcpPorts: [tcpOpen, freeTcp],
      udpPorts: [udpSilent],
      timeoutMs: 300,
      bannerTimeoutMs: 100,
      concurrency: 8,
    });

    // Only the ones we passed in should appear
    assert.ok(res.tcpOpen.includes(tcpOpen));
    assert.ok(res.tcpClosed.includes(freeTcp));
    assert.ok(res.udpNoResponse.includes(udpSilent));

    // Ensure defaults weren't scanned (80/443/etc.)
    const defaultPorts = [21, 22, 80, 443, 3389, 161];
    for (const p of defaultPorts) {
      const any =
        res.tcpOpen.includes(p) ||
        res.tcpClosed.includes(p) ||
        res.tcpFiltered?.includes?.(p) ||
        res.udpOpen.includes(p) ||
        res.udpClosed.includes(p) ||
        res.udpNoResponse.includes(p);
      assert.equal(any, false, `default port ${p} should not be scanned in this test`);
    }
  } finally {
    closeTcp();
    closeUdpSilent();
  }
});

// ---------------------------------------------------------------------------
// N.27 — parsePortsSpec helper (CLI --ports flag parsing)
// ---------------------------------------------------------------------------

test("parsePortsSpec: empty / nullish input returns empty arrays", () => {
  assert.deepEqual(parsePortsSpec(""), { tcp: [], udp: [] });
  assert.deepEqual(parsePortsSpec(null), { tcp: [], udp: [] });
  assert.deepEqual(parsePortsSpec(undefined), { tcp: [], udp: [] });
  assert.deepEqual(parsePortsSpec(8090), { tcp: [], udp: [] }); // not a string
});

test("parsePortsSpec: bare number defaults to TCP", () => {
  assert.deepEqual(parsePortsSpec("8090"), { tcp: [8090], udp: [] });
});

test("parsePortsSpec: comma-separated bare numbers", () => {
  assert.deepEqual(parsePortsSpec("8090,9090"), { tcp: [8090, 9090], udp: [] });
});

test("parsePortsSpec: explicit /tcp suffix", () => {
  assert.deepEqual(parsePortsSpec("8090/tcp"), { tcp: [8090], udp: [] });
});

test("parsePortsSpec: explicit /udp suffix", () => {
  assert.deepEqual(parsePortsSpec("8090/udp"), { tcp: [], udp: [8090] });
});

test("parsePortsSpec: mixed protocols across entries", () => {
  assert.deepEqual(
    parsePortsSpec("8090,9090/udp,7000/tcp"),
    { tcp: [8090, 7000], udp: [9090] }
  );
});

test("parsePortsSpec: protocol suffix is case-insensitive", () => {
  assert.deepEqual(parsePortsSpec("8090/TCP,9090/UDP"), { tcp: [8090], udp: [9090] });
});

test("parsePortsSpec: tolerates surrounding whitespace per entry", () => {
  assert.deepEqual(parsePortsSpec(" 8090 , 9090/udp "), { tcp: [8090], udp: [9090] });
});

test("parsePortsSpec: dedups within each protocol", () => {
  assert.deepEqual(parsePortsSpec("8090,8090,8090"), { tcp: [8090], udp: [] });
});

test("parsePortsSpec: same port on both protocols stays separate", () => {
  assert.deepEqual(parsePortsSpec("8090,8090/udp"), { tcp: [8090], udp: [8090] });
});

test("parsePortsSpec: skips non-numeric entries", () => {
  assert.deepEqual(parsePortsSpec("abc,8090,xyz"), { tcp: [8090], udp: [] });
});

test("parsePortsSpec: skips out-of-range ports", () => {
  assert.deepEqual(parsePortsSpec("0,8090,65536,99999"), { tcp: [8090], udp: [] });
});

test("parsePortsSpec: skips entries with unknown protocol suffix", () => {
  assert.deepEqual(parsePortsSpec("8090/icmp,9090/sctp,7000"), { tcp: [7000], udp: [] });
});

test("parsePortsSpec: skips malformed entries with multiple slashes", () => {
  assert.deepEqual(parsePortsSpec("8090/tcp/extra,9090"), { tcp: [9090], udp: [] });
});

test("parsePortsSpec: empty entries (trailing/leading/double commas) are ignored", () => {
  assert.deepEqual(parsePortsSpec(",,8090,,9090,,"), { tcp: [8090, 9090], udp: [] });
});

// ---------------------------------------------------------------------------
// N.27 — opts.ports flows through to actual port scan
// ---------------------------------------------------------------------------

test("opts.ports: TCP port from CLI flag IS scanned (real localhost server)", async () => {
  const { port: openTcp, close: closeTcp } = await startTcpBannerServer({ banner: "MCP-LIKE\r\n" });
  try {
    // Pass opts.ports as a string (mimicking the CLI flag plumbed through cli.mjs:846).
    // Provide an empty tcpPorts array so opts.ports is the only TCP source — proves
    // the CLI flag value alone gets scanned without falling back to config or relying
    // on other opts arrays.
    const res = await portScanner.run("127.0.0.1", 0, {
      tcpPorts: [],
      udpPorts: [openTcp + 9999], // arbitrary placeholder so the empty-list branch isn't hit
      ports: String(openTcp),
      timeoutMs: 800,
      bannerTimeoutMs: 200,
    });
    assert.ok(res.tcpOpen.includes(openTcp), `expected ${openTcp} in tcpOpen, got ${res.tcpOpen}`);
  } finally {
    closeTcp();
  }
});

test("opts.ports: UDP port from CLI flag IS scanned (real localhost server)", async () => {
  const { port: udpPort, close: closeUdp } = await startUdpServer({ mode: "reply" });
  try {
    const res = await portScanner.run("127.0.0.1", 0, {
      tcpPorts: [65530], // placeholder so empty-list fallback isn't hit
      udpPorts: [],
      ports: `${udpPort}/udp`,
      timeoutMs: 600,
    });
    assert.ok(res.udpOpen.includes(udpPort), `expected ${udpPort} in udpOpen, got ${res.udpOpen}`);
  } finally {
    closeUdp();
  }
});

test("opts.ports merges ADDITIVELY with explicit opts.tcpPorts (not replacing)", async () => {
  // Two real listeners. Pass one via opts.tcpPorts array, the other via opts.ports CLI string.
  // Both must appear in tcpOpen — proves additive semantics, not replacement.
  const a = await startTcpBannerServer({ banner: "A\r\n" });
  const b = await startTcpBannerServer({ banner: "B\r\n" });
  try {
    const res = await portScanner.run("127.0.0.1", 0, {
      tcpPorts: [a.port],
      ports: String(b.port),
      timeoutMs: 800,
      bannerTimeoutMs: 200,
    });
    assert.ok(res.tcpOpen.includes(a.port), `port from opts.tcpPorts (${a.port}) missing`);
    assert.ok(res.tcpOpen.includes(b.port), `port from opts.ports (${b.port}) missing`);
  } finally {
    a.close();
    b.close();
  }
});

test("opts.ports: malformed entries silently skipped — valid entries still scanned", async () => {
  const { port: openTcp, close: closeTcp } = await startTcpBannerServer({ banner: "OK\r\n" });
  try {
    const res = await portScanner.run("127.0.0.1", 0, {
      tcpPorts: [],
      udpPorts: [65531], // placeholder
      ports: `abc,${openTcp},99999,xyz`,
      timeoutMs: 600,
      bannerTimeoutMs: 200,
    });
    assert.ok(res.tcpOpen.includes(openTcp));
  } finally {
    closeTcp();
  }
});

test("opts.ports: NOT set → behavior unchanged (uses opts arrays only)", async () => {
  // Without opts.ports, the scanner should only scan what's in the explicit opts arrays.
  const { port: openTcp, close: closeTcp } = await startTcpBannerServer({ banner: "X\r\n" });
  try {
    const res = await portScanner.run("127.0.0.1", 0, {
      tcpPorts: [openTcp],
      udpPorts: [],
      // no opts.ports
      timeoutMs: 600,
      bannerTimeoutMs: 200,
    });
    // Only the explicit port should be scanned
    assert.equal(res.tcpOpen.length + res.tcpClosed.length + (res.tcpFiltered?.length || 0), 1);
    assert.ok(res.tcpOpen.includes(openTcp));
  } finally {
    closeTcp();
  }
});
