// tests/ssh_scanner.test.mjs
// Run with: node --test
import { test } from "node:test";
import assert from "node:assert/strict";
import net from "node:net";
import crypto from "node:crypto";

// Adjust the import path if your folder layout differs
import sshScanner, { parseSshBanner, buildClientKexinit, parseServerKexinit } from "../plugins/ssh_scanner.mjs";

/* ---------------------------- parseSshBanner ---------------------------- */

test("parseSshBanner: OpenSSH on Ubuntu", () => {
  const s = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6";
  const r = parseSshBanner(s);
  assert.ok(r);
  assert.equal(r.proto, "2.0");
  assert.equal(r.product, "OpenSSH");
  assert.equal(r.version, "8.9p1");
  assert.equal(r.os, "Ubuntu");
  assert.equal(r.osVersion, "3ubuntu0.6");
});

test("parseSshBanner: OpenSSH no OS trail", () => {
  const s = "SSH-2.0-OpenSSH_9.3";
  const r = parseSshBanner(s);
  assert.ok(r);
  assert.equal(r.product, "OpenSSH");
  assert.equal(r.version, "9.3");
  assert.equal(r.os, "");
  assert.equal(r.osVersion, "");
});

test("parseSshBanner: Sun_SSH -> Solaris", () => {
  const s = "SSH-2.0-Sun_SSH_1.5";
  const r = parseSshBanner(s);
  assert.ok(r);
  assert.equal(r.product, "Sun_SSH");
  assert.equal(r.version, "1.5");
  assert.equal(r.os, "Solaris");
});

test("parseSshBanner: generic vendor token", () => {
  const s = "SSH-2.0-FooSSH_2.1.7 SomeTrail";
  const r = parseSshBanner(s);
  assert.ok(r);
  assert.equal(r.product, "FooSSH");
  assert.equal(r.version, "2.1.7");
});

test("parseSshBanner: non-matching string", () => {
  const r = parseSshBanner("HELLO 123");
  assert.equal(r, null);
});

/* -------------------------------- network -------------------------------- */

/* ---- Helper: build a fake server KEXINIT packet ---- */
function buildServerKexinitPacket(opts = {}) {
  const kex = opts.kex || 'curve25519-sha256,diffie-hellman-group14-sha1';
  const hostKey = opts.hostKey || 'ssh-ed25519,rsa-sha2-512';
  const enc = opts.encryption || 'aes256-ctr,aes128-cbc';
  const mac = opts.mac || 'hmac-sha2-256,hmac-sha1';
  const comp = opts.compression || 'none';

  function encNameList(str) {
    const buf = Buffer.from(str, 'utf8');
    const len = Buffer.alloc(4);
    len.writeUInt32BE(buf.length);
    return Buffer.concat([len, buf]);
  }

  const parts = [
    Buffer.from([20]), // SSH_MSG_KEXINIT
    crypto.randomBytes(16),
    encNameList(kex),
    encNameList(hostKey),
    encNameList(enc), // c2s
    encNameList(enc), // s2c
    encNameList(mac), // c2s
    encNameList(mac), // s2c
    encNameList(comp), // c2s
    encNameList(comp), // s2c
    encNameList(''), // languages c2s
    encNameList(''), // languages s2c
    Buffer.from([0]),
    Buffer.alloc(4, 0),
  ];
  const payload = Buffer.concat(parts);

  const blockSize = 8;
  const minPadding = 4;
  let paddingLen = blockSize - ((1 + payload.length + minPadding) % blockSize);
  if (paddingLen < minPadding) paddingLen += blockSize;
  const packetLength = 1 + payload.length + paddingLen;
  const header = Buffer.alloc(5);
  header.writeUInt32BE(packetLength, 0);
  header[4] = paddingLen;
  const padding = crypto.randomBytes(paddingLen);

  return Buffer.concat([header, payload, padding]);
}

function startSshLikeServer({ banner, delayMs = 0, sendBanner = true, sendKexinit = false, kexinitOpts = {} }) {
  return new Promise((resolve, reject) => {
    const server = net.createServer((socket) => {
      if (sendBanner) {
        setTimeout(() => {
          socket.write(banner + "\n");
          if (sendKexinit) {
            // Send KEXINIT packet after banner (binary)
            socket.write(buildServerKexinitPacket(kexinitOpts));
            // Wait for client KEXINIT before closing
            socket.on('data', () => {
              // We received client data (banner + kexinit), close after a short delay
              setTimeout(() => { try { socket.end(); } catch {} }, 50);
            });
          } else {
            // For banner-only: close after a delay to give scanner time
            // The scanner will close from its side or hit kexinit timeout
            socket.on('data', () => {
              // Client sent something (banner identification), just ignore
            });
            // Don't immediately end — let the scanner timeout on KEXINIT or close itself
            setTimeout(() => { try { socket.end(); } catch {} }, 5000);
          }
        }, delayMs);
      } else {
        // accept but don't send anything; let client timeout
      }
    });
    server.on("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address();
      resolve({ server, port: addr.port });
    });
  });
}

test("sshScanner.run: parses banner and fills fields", async () => {
  const prevEnv = process.env.SSH_CHECK_ALGORITHMS;
  process.env.SSH_CHECK_ALGORITHMS = 'false';
  const banner = "SSH-2.0-OpenSSH_9.6 Debian-1";
  const { server, port } = await startSshLikeServer({ banner });
  try {
    const res = await sshScanner.run("127.0.0.1", port, { timeoutMs: 1000 });
    assert.equal(res.up, true);
    assert.equal(res.program, "OpenSSH");
    assert.equal(res.version, "9.6");
    assert.match(res.os ?? "", /Debian/i);
    assert.ok(Array.isArray(res.data) && res.data.length > 0);
    assert.equal(res.data[0].response_banner.startsWith("SSH-2.0-OpenSSH_9.6"), true);
  } finally {
    if (prevEnv === undefined) delete process.env.SSH_CHECK_ALGORITHMS;
    else process.env.SSH_CHECK_ALGORITHMS = prevEnv;
    server.close();
  }
});

test("sshScanner.run: times out when server never sends banner", async () => {
  const prevEnv = process.env.SSH_CHECK_ALGORITHMS;
  process.env.SSH_CHECK_ALGORITHMS = 'false';
  const { server, port } = await startSshLikeServer({ banner: "", sendBanner: false });
  try {
    const res = await sshScanner.run("127.0.0.1", port, { timeoutMs: 200 });
    // We connected, then timed out -> plugin marks host up, but Unknown program/version
    assert.equal(res.up, true);
    assert.equal(res.program, "Unknown");
    assert.equal(res.version, "Unknown");
    assert.ok(res.data[0].probe_info.toLowerCase().includes("timeout") || res.data[0].probe_info.toLowerCase().includes("error"));
  } finally {
    if (prevEnv === undefined) delete process.env.SSH_CHECK_ALGORITHMS;
    else process.env.SSH_CHECK_ALGORITHMS = prevEnv;
    server.close();
  }
});

test("sshScanner.run: unparseable banner still recorded", async () => {
  const prevEnv = process.env.SSH_CHECK_ALGORITHMS;
  process.env.SSH_CHECK_ALGORITHMS = 'false';
  const { server, port } = await startSshLikeServer({ banner: "SSH-2.0-NotReallySsh" });
  try {
    const res = await sshScanner.run("127.0.0.1", port, { timeoutMs: 1000 });
    assert.equal(res.up, true);
    // Keep vendor token even if no version present
    assert.equal(res.program, "NotReallySsh");
    assert.equal(res.version, "Unknown");
    // Confirm we preserved the exact banner we read
    assert.equal(res.data[0].response_banner, "SSH-2.0-NotReallySsh");
  } finally {
    if (prevEnv === undefined) delete process.env.SSH_CHECK_ALGORITHMS;
    else process.env.SSH_CHECK_ALGORITHMS = prevEnv;
    server.close();
  }
});

/* ----------------------- KEXINIT algorithm tests ----------------------- */

test("sshScanner.run: extracts algorithms from server KEXINIT", async () => {
  const prevEnv = process.env.SSH_CHECK_ALGORITHMS;
  const prevKexTimeout = process.env.SSH_KEXINIT_TIMEOUT;
  process.env.SSH_CHECK_ALGORITHMS = 'true';
  process.env.SSH_KEXINIT_TIMEOUT = '3000';
  const banner = "SSH-2.0-OpenSSH_9.6 Debian-1";
  const kexinitOpts = {
    kex: 'curve25519-sha256,diffie-hellman-group14-sha1',
    hostKey: 'ssh-ed25519,rsa-sha2-512',
    encryption: 'aes256-ctr,aes128-cbc',
    mac: 'hmac-sha2-256,hmac-sha1',
    compression: 'none',
  };
  const { server, port } = await startSshLikeServer({ banner, sendKexinit: true, kexinitOpts });
  try {
    const res = await sshScanner.run("127.0.0.1", port, { timeoutMs: 2000 });
    assert.equal(res.up, true);
    assert.equal(res.program, "OpenSSH");
    assert.ok(res.algorithms, "algorithms should be present");
    assert.deepEqual(res.algorithms.kex, ['curve25519-sha256', 'diffie-hellman-group14-sha1']);
    assert.deepEqual(res.algorithms.hostKey, ['ssh-ed25519', 'rsa-sha2-512']);
    assert.ok(res.algorithms.encryption.includes('aes256-ctr'));
    assert.ok(res.algorithms.encryption.includes('aes128-cbc'));
    assert.ok(res.algorithms.mac.includes('hmac-sha2-256'));
    assert.ok(res.algorithms.mac.includes('hmac-sha1'));
    // Weak algorithms detected
    assert.ok(res.weakAlgorithms.includes('diffie-hellman-group14-sha1'), 'should flag weak kex');
    assert.ok(res.weakAlgorithms.includes('aes128-cbc'), 'should flag weak cipher');
    assert.ok(res.weakAlgorithms.includes('hmac-sha1'), 'should flag weak mac');
  } finally {
    if (prevEnv === undefined) delete process.env.SSH_CHECK_ALGORITHMS;
    else process.env.SSH_CHECK_ALGORITHMS = prevEnv;
    if (prevKexTimeout === undefined) delete process.env.SSH_KEXINIT_TIMEOUT;
    else process.env.SSH_KEXINIT_TIMEOUT = prevKexTimeout;
    server.close();
  }
});

test("sshScanner.run: KEXINIT times out gracefully, returns banner with algorithms=null", async () => {
  const prevEnv = process.env.SSH_CHECK_ALGORITHMS;
  const prevKexTimeout = process.env.SSH_KEXINIT_TIMEOUT;
  process.env.SSH_CHECK_ALGORITHMS = 'true';
  process.env.SSH_KEXINIT_TIMEOUT = '300'; // very short timeout
  const banner = "SSH-2.0-OpenSSH_9.6";
  // Server sends banner but no KEXINIT
  const { server, port } = await startSshLikeServer({ banner, sendKexinit: false });
  try {
    const res = await sshScanner.run("127.0.0.1", port, { timeoutMs: 2000 });
    assert.equal(res.up, true);
    assert.equal(res.program, "OpenSSH");
    assert.equal(res.version, "9.6");
    assert.equal(res.algorithms, null, "algorithms should be null on timeout");
    assert.deepEqual(res.weakAlgorithms, [], "weakAlgorithms should be empty on timeout");
    assert.ok(res.data[0].response_banner.startsWith("SSH-2.0-OpenSSH_9.6"));
  } finally {
    if (prevEnv === undefined) delete process.env.SSH_CHECK_ALGORITHMS;
    else process.env.SSH_CHECK_ALGORITHMS = prevEnv;
    if (prevKexTimeout === undefined) delete process.env.SSH_KEXINIT_TIMEOUT;
    else process.env.SSH_KEXINIT_TIMEOUT = prevKexTimeout;
    server.close();
  }
});

test("sshScanner.run: SSH_CHECK_ALGORITHMS=false skips KEXINIT entirely", async () => {
  const prevEnv = process.env.SSH_CHECK_ALGORITHMS;
  process.env.SSH_CHECK_ALGORITHMS = 'false';
  const banner = "SSH-2.0-OpenSSH_9.6 Debian-1";
  // Even though server sends kexinit, scanner should not attempt exchange
  const { server, port } = await startSshLikeServer({ banner, sendKexinit: true });
  try {
    const res = await sshScanner.run("127.0.0.1", port, { timeoutMs: 1000 });
    assert.equal(res.up, true);
    assert.equal(res.program, "OpenSSH");
    assert.equal(res.algorithms, null, "algorithms should be null when check disabled");
    assert.deepEqual(res.weakAlgorithms, [], "weakAlgorithms should be empty when check disabled");
  } finally {
    if (prevEnv === undefined) delete process.env.SSH_CHECK_ALGORITHMS;
    else process.env.SSH_CHECK_ALGORITHMS = prevEnv;
    server.close();
  }
});

