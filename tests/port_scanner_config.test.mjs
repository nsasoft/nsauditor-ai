// tests/port_scanner_config.test.mjs
// Run with: npm test  (node --test)

import { test } from "node:test";
import assert from "node:assert/strict";
import os from "node:os";
import path from "node:path";
import fsp from "node:fs/promises";
import net from "node:net";
import dgram from "node:dgram";

import portScanner from "../plugins/port_scanner.mjs";

/* ------------------------------ helpers ------------------------------ */

function startTcpBannerServer({ banner = "HELLO\r\n" } = {}) {
  return new Promise((resolve, reject) => {
    const server = net.createServer((socket) => {
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
      }
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

/* -------------------------------- test -------------------------------- */

test("port_scanner: honors config/services.json (array schema)", { timeout: 5000 }, async () => {
  // Spin up services on ephemeral ports
  const { port: tcpOpen, close: closeTcp } = await startTcpBannerServer({ banner: "220 Welcome!\r\n" });
  const { port: udpOpen, close: closeUdp } = await startUdpServer({ mode: "reply" });

  // Create a temp project dir with config/services.json pointing to those ports
  const tmpRoot = await fsp.mkdtemp(path.join(os.tmpdir(), "ps-config-"));
  const prevCwd = process.cwd();
  try {
    const cfgDir = path.join(tmpRoot, "config");
    await fsp.mkdir(cfgDir, { recursive: true });

    const configJson = {
      services: [
        { name: "web", port: tcpOpen, protocol: "http", description: "HTTP web server (test)" },
        { name: "snmp-ish", port: udpOpen, protocol: "udp", description: "UDP echo (test)" },
        // throw in a random TCP/UDP we are NOT listening on to ensure scanner still runs
        { name: "unused-tcp", port: 65000, protocol: "tcp", description: "unused tcp" },
        { name: "unused-udp", port: 65001, protocol: "udp", description: "unused udp" },
      ],
    };
    await fsp.writeFile(
      path.join(cfgDir, "services.json"),
      JSON.stringify(configJson, null, 2),
      "utf8"
    );

    // Make plugin see our temp config by changing cwd
    process.chdir(tmpRoot);

    // Run WITHOUT passing tcpPorts/udpPorts so it loads from config
    const res = await portScanner.run("127.0.0.1", 0, {
      timeoutMs: 400,
      bannerTimeoutMs: 150,
      concurrency: 16,
    });

    // It should have scanned exactly the ports from config (plus ordering, but we just assert presence)
    assert.ok(res.tcpOpen.includes(tcpOpen));
    assert.ok(res.udpOpen.includes(udpOpen));

    // Unused ones should fall into closed/no-response accordingly
    // (TCP unused => likely 'closed', UDP unused => 'no-response' usually)
    // We won't rely on OS specifics too much, just ensure they appear in *some* bucket
    const tcpBuckets = [res.tcpOpen, res.tcpClosed, res.tcpFiltered].filter(Boolean);
    const sawUnusedTcp = tcpBuckets.some((arr) => arr.includes(65000));
    assert.equal(sawUnusedTcp, true, "unused TCP port should appear in at least one TCP bucket");

    const udpBuckets = [res.udpOpen, res.udpClosed, res.udpNoResponse].filter(Boolean);
    const sawUnusedUdp = udpBuckets.some((arr) => arr.includes(65001));
    assert.equal(sawUnusedUdp, true, "unused UDP port should appear in at least one UDP bucket");

    // And confirm banner capture for the TCP open one
    const row = res.data.find(d => d.probe_protocol === "tcp" && d.probe_port === tcpOpen);
    assert.ok(row);
    assert.equal(row.status, "open");
    assert.ok((row.response_banner || "").startsWith("220 Welcome!"));
  } finally {
    // Cleanup
    try { process.chdir(prevCwd); } catch {}
    try { closeTcp(); } catch {}
    try { closeUdp(); } catch {}
    try { await fsp.rm(tmpRoot, { recursive: true, force: true }); } catch {}
  }
});
