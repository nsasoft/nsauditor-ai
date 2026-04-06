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

function startFakeFtpWithAnon({ banner, allowAnon = false }) {
  return new Promise((resolve, reject) => {
    const server = net.createServer((sock) => {
      sock.write(banner);
      let state = 'banner-sent';

      sock.on('data', (data) => {
        const cmd = data.toString().trim().toUpperCase();
        if (state === 'banner-sent' && cmd.startsWith('USER')) {
          state = 'user-received';
          sock.write('331 Password required\r\n');
        } else if (state === 'user-received' && cmd.startsWith('PASS')) {
          if (allowAnon) {
            sock.write('230 Login successful\r\n');
          } else {
            sock.write('530 Login incorrect\r\n');
          }
          sock.end();
        }
      });
    });
    server.on("error", reject);
    server.listen(0, "127.0.0.1", () => {
      resolve({ server, port: server.address().port });
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
  const { server, port } = await startFakeFtp({ banner: multiline });
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

test("FTP anon: anonymous login allowed => anonymousLogin true", async () => {
  const saved = process.env.FTP_CHECK_ANON;
  process.env.FTP_CHECK_ANON = 'true';
  try {
    const { server, port } = await startFakeFtpWithAnon({
      banner: "220 (vsFTPd 3.0.3)\r\n",
      allowAnon: true
    });
    try {
      const res = await ftp.run("127.0.0.1", port);
      assert.equal(res.up, true);
      assert.equal(res.anonymousLogin, true);
      // Should have a security finding evidence row
      assert.ok(res.data.length >= 2, 'Expected at least 2 evidence rows');
      assert.ok(res.data.some(d => /anonymous/i.test(d.probe_info)), 'Expected anonymous finding in evidence');
    } finally {
      server.close();
    }
  } finally {
    if (saved === undefined) delete process.env.FTP_CHECK_ANON;
    else process.env.FTP_CHECK_ANON = saved;
  }
});

test("FTP anon: anonymous login denied => anonymousLogin false", async () => {
  const saved = process.env.FTP_CHECK_ANON;
  process.env.FTP_CHECK_ANON = 'true';
  try {
    const { server, port } = await startFakeFtpWithAnon({
      banner: "220 (vsFTPd 3.0.3)\r\n",
      allowAnon: false
    });
    try {
      const res = await ftp.run("127.0.0.1", port);
      assert.equal(res.up, true);
      assert.equal(res.anonymousLogin, false);
      assert.equal(res.data.length, 1, 'Should have only 1 evidence row when denied');
    } finally {
      server.close();
    }
  } finally {
    if (saved === undefined) delete process.env.FTP_CHECK_ANON;
    else process.env.FTP_CHECK_ANON = saved;
  }
});

test("FTP anon: FTP_CHECK_ANON not set => no anonymous check", async () => {
  const saved = process.env.FTP_CHECK_ANON;
  delete process.env.FTP_CHECK_ANON;
  try {
    const { server, port } = await startFakeFtp({ banner: "220 (vsFTPd 3.0.3)\r\n" });
    try {
      const res = await ftp.run("127.0.0.1", port);
      assert.equal(res.up, true);
      assert.equal(res.anonymousLogin, undefined, 'anonymousLogin should not be set when ANON check disabled');
      assert.equal(res.data.length, 1);
    } finally {
      server.close();
    }
  } finally {
    if (saved === undefined) delete process.env.FTP_CHECK_ANON;
    else process.env.FTP_CHECK_ANON = saved;
  }
});
