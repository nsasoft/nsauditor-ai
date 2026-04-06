// tests/port_scanner.test.mjs
// Run with: npm test  (which runs `node --test`)

import { test } from "node:test";
import assert from "node:assert/strict";
import net from "node:net";
import dgram from "node:dgram";

import portScanner from "../plugins/port_scanner.mjs";

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
