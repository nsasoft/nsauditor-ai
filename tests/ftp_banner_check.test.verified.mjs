// tests/ftp_banner_check.test.mjs
// Run with: npm test
import { test } from "node:test";
import assert from "node:assert/strict";
import net from "node:net";
import ftp from "../plugins/ftp_banner_check.mjs";

function startFakeFtp({ banner, delayMs = 0 }) {
  return new Promise((resolve, reject) => {
    const server = net.createServer((sock) => {
      setTimeout(() => {
        sock.write(banner);
        sock.end();
      }, delayMs);
    });
    server.on("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      resolve({ server, port });
    });
  });
}

test("FTP banner: parses typical vsFTPd banner", async () => {
  const { server, port } = await startFakeFtp({ banner: "220 (vsFTPd 3.0.3)\r\n" });
  try {
    const res = await ftp.run("127.0.0.1", port);
    assert.equal(res.up, true);
    assert.ok(res.data[0].response_banner.startsWith("220"));
    // Program may be parsed; at minimum ensure it is not throwing and banner captured
    assert.ok(typeof res.program === "string");
  } finally {
    server.close();
  }
});

test("FTP banner: Pure-FTPd multiline welcome", async () => {
  const multiline =
    "220---------- Welcome to Pure-FTPd [privsep] [TLS] ----------\r\n" +
    "220-You are user number 1 of 50 allowed.\r\n" +
    "220 Local time is now 13:37. Server port: 21.\r\n";
  const { server, port } = await startFakeFtp({ banner: multiline, delayMs: 50 });
  try {
    const res = await ftp.run("127.0.0.1", port);
    assert.equal(res.up, true);
    assert.ok(res.data[0].response_banner.startsWith("220"));
  } finally {
    server.close();
  }
});

test("FTP banner: connection refused => up true but closed", async () => {
  // Bind-and-close to get a free port that's closed
  const temp = net.createServer();
  await new Promise((r) => temp.listen(0, "127.0.0.1", r));
  const { port } = temp.address();
  temp.close();

  const res = await ftp.run("127.0.0.1", port);
  assert.equal(res.up, true);
  assert.ok(/refused|closed/i.test(res.data[0].probe_info));
});
