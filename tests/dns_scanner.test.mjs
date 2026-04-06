// tests/dns_scanner.test.mjs
// Run: node --test

import { test } from "node:test";
import assert from "node:assert/strict";
import dgram from "node:dgram";
import net from "node:net";
import dnsScanner from "../plugins/dns_scanner.mjs";

// --- tiny DNS response helpers (enough for our tests) ---

const QTYPE = { A: 1, MX: 15, TXT: 16, SRV: 33, AXFR: 252 };
const QCLASS = { IN: 1, CH: 3 };

function encodeName(name) {
  const parts = String(name).split(".").filter(Boolean);
  const bufs = [];
  for (const label of parts) {
    const b = Buffer.from(label, "utf8");
    bufs.push(Buffer.from([b.length]));
    bufs.push(b);
  }
  bufs.push(Buffer.from([0]));
  return Buffer.concat(bufs);
}

function parseQuestion(buf) {
  let off = 12;
  // Only one question in our tests
  const labels = [];
  while (buf[off] !== 0) {
    const ln = buf[off];
    labels.push(buf.slice(off + 1, off + 1 + ln).toString("utf8"));
    off += 1 + ln;
  }
  off += 1; // zero
  const qtype = buf.readUInt16BE(off); off += 2;
  const qclass = buf.readUInt16BE(off); off += 2;
  return { qname: labels.join("."), qtype, qclass, qend: off };
}

function buildHeader({ id, flags, qd = 1, an = 1, ns = 0, ar = 0 }) {
  const b = Buffer.alloc(12);
  b.writeUInt16BE(id & 0xffff, 0);
  b.writeUInt16BE(flags & 0xffff, 2);
  b.writeUInt16BE(qd, 4);
  b.writeUInt16BE(an, 6);
  b.writeUInt16BE(ns, 8);
  b.writeUInt16BE(ar, 10);
  return b;
}

function rrTXT(name, ttl, txt) {
  const n = encodeName(name);
  const txtBuf = Buffer.from(txt, "utf8");
  const rdata = Buffer.concat([Buffer.from([txtBuf.length]), txtBuf]);
  const rr = Buffer.alloc(10);
  rr.writeUInt16BE(QTYPE.TXT, 0);
  rr.writeUInt16BE(QCLASS.CH, 2);
  rr.writeUInt32BE(ttl, 4);
  rr.writeUInt16BE(rdata.length, 8);
  return Buffer.concat([n, rr, rdata]);
}

function rrA(name, ttl, ip) {
  const n = encodeName(name);
  const ipBuf = Buffer.from(ip.split(".").map((x) => parseInt(x, 10)));
  const rr = Buffer.alloc(10);
  rr.writeUInt16BE(QTYPE.A, 0);
  rr.writeUInt16BE(QCLASS.IN, 2);
  rr.writeUInt32BE(ttl, 4);
  rr.writeUInt16BE(4, 8);
  return Buffer.concat([n, rr, ipBuf]);
}

function rrMX(name, ttl, preference, exchange) {
  const n = encodeName(name);
  const exBuf = encodeName(exchange);
  const prefBuf = Buffer.alloc(2);
  prefBuf.writeUInt16BE(preference, 0);
  const rdata = Buffer.concat([prefBuf, exBuf]);
  const rr = Buffer.alloc(10);
  rr.writeUInt16BE(QTYPE.MX, 0);
  rr.writeUInt16BE(QCLASS.IN, 2);
  rr.writeUInt32BE(ttl, 4);
  rr.writeUInt16BE(rdata.length, 8);
  return Buffer.concat([n, rr, rdata]);
}

// SOA record helper for AXFR tests
function rrSOA(name, ttl) {
  const n = encodeName(name);
  const mname = encodeName("ns1." + name);
  const rname = encodeName("admin." + name);
  const serial = Buffer.alloc(20);
  serial.writeUInt32BE(2024010101, 0);  // serial
  serial.writeUInt32BE(3600, 4);         // refresh
  serial.writeUInt32BE(600, 8);          // retry
  serial.writeUInt32BE(86400, 12);       // expire
  serial.writeUInt32BE(300, 16);         // minimum
  const rdata = Buffer.concat([mname, rname, serial]);
  const rr = Buffer.alloc(10);
  rr.writeUInt16BE(6, 0);  // SOA type = 6
  rr.writeUInt16BE(QCLASS.IN, 2);
  rr.writeUInt32BE(ttl, 4);
  rr.writeUInt16BE(rdata.length, 8);
  return Buffer.concat([n, rr, rdata]);
}

async function startDnsLikeServer({ versionTxt = "dnsmasq-2.86", aAnswer = "93.184.216.34", replyVersion = true, replyA = true, replyMX = true, mxExchange = "mail.example.com", mxPreference = 10 }) {
  return new Promise((resolve, reject) => {
    const sock = dgram.createSocket("udp4");
    sock.on("error", reject);

    sock.on("message", (msg, rinfo) => {
      try {
        const id = msg.readUInt16BE(0);
        const q = parseQuestion(msg);
        const hdr = buildHeader({ id, flags: 0x8180 }); // QR=1, RD=1, RA=1, rcode=0

        let answer;
        if (q.qname.toLowerCase() === "version.bind" && q.qtype === QTYPE.TXT && q.qclass === QCLASS.CH) {
          if (!replyVersion) return; // simulate no response
          const question = msg.slice(12, q.qend);
          answer = rrTXT("version.bind", 60, versionTxt);
          const res = Buffer.concat([hdr, question, answer]);
          sock.send(res, rinfo.port, rinfo.address);
        } else if (q.qname.toLowerCase() === "example.com" && q.qtype === QTYPE.A && q.qclass === QCLASS.IN) {
          if (!replyA) return;
          const question = msg.slice(12, q.qend);
          answer = rrA("example.com", 60, aAnswer);
          const res = Buffer.concat([hdr, question, answer]);
          sock.send(res, rinfo.port, rinfo.address);
        } else if (q.qtype === QTYPE.MX && q.qclass === QCLASS.IN) {
          if (!replyMX) return;
          const question = msg.slice(12, q.qend);
          answer = rrMX(q.qname, 60, mxPreference, mxExchange);
          const hdrMx = buildHeader({ id, flags: 0x8180 });
          const res = Buffer.concat([hdrMx, question, answer]);
          sock.send(res, rinfo.port, rinfo.address);
        }
      } catch {
        // ignore malformed
      }
    });

    sock.bind(0, "127.0.0.1", () => {
      const addr = sock.address();
      resolve({ server: sock, port: addr.port });
    });
  });
}

// --- tests ---

test("dns_scanner: fingerprints dnsmasq via version.bind and resolves example.com", async () => {
  const { server, port } = await startDnsLikeServer({
    versionTxt: "dnsmasq-2.86",
    aAnswer: "93.184.216.34",
    replyVersion: true,
    replyA: true,
  });
  try {
    const res = await dnsScanner.run("127.0.0.1", port, { timeoutMs: 500 });
    assert.equal(res.up, true);
    assert.equal(res.type, "dns");
    assert.equal(res.program, "dnsmasq");
    assert.equal(res.version, "2.86");
    assert.ok(Array.isArray(res.data) && res.data.length >= 3);
    assert.match(res.data[0].probe_info, /version\.bind/i);
    assert.match(res.data[1].probe_info, /A.*example\.com/i);
    assert.match(res.data[1].response_banner || "", /93\.184\.216\.34/);
    assert.match(res.data[2].probe_info, /MX.*example\.com/i);
    assert.equal(res.axfrAllowed, null);
  } finally {
    server.close();
  }
});

test("dns_scanner: no version.bind but answers A query -> up true, program Unknown", async () => {
  const { server, port } = await startDnsLikeServer({
    replyVersion: false,
    replyA: true,
  });
  try {
    const res = await dnsScanner.run("127.0.0.1", port, { timeoutMs: 500 });
    assert.equal(res.up, true);
    assert.equal(res.program, "Unknown");
    assert.equal(res.version, "Unknown");
    assert.ok((res.data.find(d => /example\.com/i.test(d.probe_info))?.response_banner || "").includes("A example.com"));
  } finally {
    server.close();
  }
});

test("dns_scanner: times out (no responses) -> up false", async () => {
  // Start a server that ignores everything (or don't start any server and send to an unused port).
  const { server, port } = await startDnsLikeServer({
    replyVersion: false,
    replyA: false,
    replyMX: false,
  });
  try {
    const res = await dnsScanner.run("127.0.0.1", port, { timeoutMs: 200 });
    assert.equal(res.up, false);
    assert.equal(res.program, "Unknown");
    assert.equal(res.version, "Unknown");
    assert.ok(res.data.some(d => /No DNS response/i.test(d.probe_info)));
  } finally {
    server.close();
  }
});

// --- MX record parsing test ---

test("dns_scanner: MX record parsed correctly", async () => {
  const { server, port } = await startDnsLikeServer({
    replyVersion: true,
    replyA: true,
    replyMX: true,
    mxExchange: "mail.example.com",
    mxPreference: 10,
  });
  try {
    const res = await dnsScanner.run("127.0.0.1", port, { timeoutMs: 500 });
    assert.equal(res.up, true);
    const mxEntry = res.data.find(d => /MX.*example\.com/i.test(d.probe_info));
    assert.ok(mxEntry, "should have MX probe_info entry");
    assert.match(mxEntry.response_banner || "", /10 mail\.example\.com/);
  } finally {
    server.close();
  }
});

// --- AXFR tests ---

// Helper: build a TCP DNS response message (with 2-byte length prefix)
function buildTcpDnsResponse({ id, flags, question, answers, anCount }) {
  const hdr = buildHeader({ id, flags, qd: question ? 1 : 0, an: anCount ?? answers.length });
  const parts = [hdr];
  if (question) parts.push(question);
  for (const ans of answers) parts.push(ans);
  const msg = Buffer.concat(parts);
  const lenBuf = Buffer.alloc(2);
  lenBuf.writeUInt16BE(msg.length, 0);
  return Buffer.concat([lenBuf, msg]);
}

// Start a TCP server that simulates AXFR responses
async function startAxfrTcpServer({ mode = "success" }) {
  return new Promise((resolve, reject) => {
    const srv = net.createServer(sock => {
      let buf = Buffer.alloc(0);
      sock.on("data", chunk => {
        buf = Buffer.concat([buf, chunk]);
        if (buf.length < 2) return;
        const msgLen = buf.readUInt16BE(0);
        if (buf.length < 2 + msgLen) return;
        const msg = buf.subarray(2, 2 + msgLen);
        const id = msg.readUInt16BE(0);

        // Parse the question section to echo it back
        const question = msg.subarray(12);

        if (mode === "success") {
          // Send SOA + A record + SOA (valid AXFR)
          const soa = rrSOA("example.com", 3600);
          const aRec = rrA("www.example.com", 300, "1.2.3.4");
          const soa2 = rrSOA("example.com", 3600);
          const resp = buildTcpDnsResponse({
            id,
            flags: 0x8480, // QR=1, AA=1, rcode=0
            question,
            answers: [soa, aRec, soa2],
            anCount: 3,
          });
          sock.write(resp);
        } else if (mode === "refused") {
          // Send rcode=5 (REFUSED)
          const resp = buildTcpDnsResponse({
            id,
            flags: 0x8405, // QR=1, AA=1, rcode=5 (REFUSED)
            question,
            answers: [],
            anCount: 0,
          });
          sock.write(resp);
        }
        sock.end();
      });
    });
    srv.listen(0, "127.0.0.1", () => {
      const addr = srv.address();
      resolve({ server: srv, port: addr.port });
    });
    srv.on("error", reject);
  });
}

test("dns_scanner: AXFR success — zone transfer allowed", async () => {
  // We need both a UDP server (for version.bind + A + MX) and a TCP server (for AXFR).
  // Use a combined approach: start both on the same port is tricky, so instead
  // we test AXFR via env vars and opts.axfrDomain with a separate TCP port.
  // However the scanner sends all queries to the same host:port.
  // So we need a server that handles both UDP and TCP on the same port.
  // Simplest: start a UDP server for normal queries and set DNS_CHECK_AXFR env.
  // But AXFR goes to TCP on the same port. We can't easily bind both.
  // Instead: start the TCP AXFR server, start a UDP server on a DIFFERENT port,
  // and for the AXFR test we only care about the AXFR result.
  // The scanner sends UDP queries first (they'll timeout), then AXFR on TCP.
  // Use a short timeout.

  const { server: tcpSrv, port: tcpPort } = await startAxfrTcpServer({ mode: "success" });
  // Also start a UDP server on the same port for version.bind/A/MX queries
  const udpSock = dgram.createSocket("udp4");
  await new Promise((res, rej) => {
    udpSock.on("error", rej);
    // Bind to same port as TCP
    udpSock.bind(tcpPort, "127.0.0.1", () => res());
  });
  // The UDP server won't reply to anything, so version.bind/A/MX will timeout.
  // That's fine — we just want to test AXFR behavior.

  const origCheckAxfr = process.env.DNS_CHECK_AXFR;
  const origAxfrDomain = process.env.DNS_AXFR_DOMAIN;
  process.env.DNS_CHECK_AXFR = "true";
  process.env.DNS_AXFR_DOMAIN = "example.com";
  try {
    const res = await dnsScanner.run("127.0.0.1", tcpPort, { timeoutMs: 500 });
    assert.equal(res.axfrAllowed, true, "axfrAllowed should be true");
    const axfrEntry = res.data.find(d => /AXFR.*allowed/i.test(d.probe_info));
    assert.ok(axfrEntry, "should have AXFR allowed entry");
    assert.match(axfrEntry.response_banner, /AXFR success: \d+ records/);
  } finally {
    process.env.DNS_CHECK_AXFR = origCheckAxfr || "";
    process.env.DNS_AXFR_DOMAIN = origAxfrDomain || "";
    if (!origCheckAxfr) delete process.env.DNS_CHECK_AXFR;
    if (!origAxfrDomain) delete process.env.DNS_AXFR_DOMAIN;
    udpSock.close();
    tcpSrv.close();
  }
});

test("dns_scanner: AXFR refused — rcode 5", async () => {
  const { server: tcpSrv, port: tcpPort } = await startAxfrTcpServer({ mode: "refused" });
  const udpSock = dgram.createSocket("udp4");
  await new Promise((res, rej) => {
    udpSock.on("error", rej);
    udpSock.bind(tcpPort, "127.0.0.1", () => res());
  });

  const origCheckAxfr = process.env.DNS_CHECK_AXFR;
  const origAxfrDomain = process.env.DNS_AXFR_DOMAIN;
  process.env.DNS_CHECK_AXFR = "true";
  process.env.DNS_AXFR_DOMAIN = "example.com";
  try {
    const res = await dnsScanner.run("127.0.0.1", tcpPort, { timeoutMs: 500 });
    assert.equal(res.axfrAllowed, false, "axfrAllowed should be false");
    const axfrEntry = res.data.find(d => /AXFR.*denied/i.test(d.probe_info));
    assert.ok(axfrEntry, "should have AXFR denied entry");
    assert.match(axfrEntry.response_banner, /AXFR refused/);
  } finally {
    process.env.DNS_CHECK_AXFR = origCheckAxfr || "";
    process.env.DNS_AXFR_DOMAIN = origAxfrDomain || "";
    if (!origCheckAxfr) delete process.env.DNS_CHECK_AXFR;
    if (!origAxfrDomain) delete process.env.DNS_AXFR_DOMAIN;
    udpSock.close();
    tcpSrv.close();
  }
});

test("dns_scanner: AXFR disabled by default — no AXFR attempt", async () => {
  const { server, port } = await startDnsLikeServer({
    replyVersion: true,
    replyA: true,
    replyMX: true,
  });
  // Ensure env vars are NOT set
  const origCheckAxfr = process.env.DNS_CHECK_AXFR;
  const origAxfrDomain = process.env.DNS_AXFR_DOMAIN;
  delete process.env.DNS_CHECK_AXFR;
  delete process.env.DNS_AXFR_DOMAIN;
  try {
    const res = await dnsScanner.run("127.0.0.1", port, { timeoutMs: 500 });
    assert.equal(res.axfrAllowed, null, "axfrAllowed should be null when not tested");
    const axfrEntry = res.data.find(d => /AXFR/i.test(d.probe_info));
    assert.equal(axfrEntry, undefined, "should have no AXFR entry in data");
  } finally {
    if (origCheckAxfr) process.env.DNS_CHECK_AXFR = origCheckAxfr;
    if (origAxfrDomain) process.env.DNS_AXFR_DOMAIN = origAxfrDomain;
    server.close();
  }
});
