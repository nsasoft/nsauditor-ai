// tests/helpers/fake_dns_server.mjs
// ─────────────────────────────────────────────────────────────────────────────
// A REAL DNS server on a loopback address, UDP and TCP on ONE port, for the legs that drive plugin 060's raw DNSSEC
// query (G-75 (b); architect VERDICT-v404 L3, v407 L3b–L3e, v412 L3f, v413 L3g/L9/L10, v415 S1–S2).
//
// Nothing in the query path is stubbed: 060 opens its own dgram and net sockets, sends real datagrams to this
// server's address and port, and reads what comes back. The server answers from a HANDLER the test supplies, so each
// leg states its zone as a function of the question — and the hostile modes (a wrong id, QR=0, another question, a
// reply from another source port, TC=1, silence, raw bytes) are fields of the handler's answer, not separate servers.
//
// handler(q, info) → what to send back:
//   null / undefined           no reply at all (silence; over TCP the connection stays open until the client gives up)
//   { raw: Buffer }            exactly these bytes (over TCP with the two-byte length prefix added)
//   a reply spec               { rcode, answers, authority, additional, tc, qr, opcode, id, question, noQuestion,
//                                fromAltPort, tcpClose }
//      answers/authority/additional: [{ type, name?, data? }] — `type` a number or a name in T; `name` defaults to the
//      question's name; `data` defaults to plausible RDATA for the type (see rdataFor).
//      tc: the TC bit · qr: false clears QR · opcode: a number · id: a number replacing the query's id
//      question: { name?, type?, cls? } — what the reply echoes instead of the query's question
//      noQuestion: QDCOUNT 0 · fromAltPort: the UDP reply leaves from ANOTHER socket (another source port)
//      tcpClose: over TCP, close the connection without a reply · delayMs: send the reply this many ms late
//   q    = { id, name, type, cls, transport }  (name as sent, case kept)
//   info = { transport: 'udp'|'tcp', from: { address, port }, n }  — n counts this (name, type) on this transport, from 1
//
// The log records every query the server RECEIVED: { transport, name, type, cls, id, from }.
// ─────────────────────────────────────────────────────────────────────────────
import dgram from 'node:dgram';
import net from 'node:net';

export const T = Object.freeze({ A: 1, NS: 2, CNAME: 5, SOA: 6, TXT: 16, AAAA: 28, DNAME: 39, DS: 43, DNSKEY: 48 });
const typeNum = (t) => (typeof t === 'number' ? t : T[t]);

export function encodeName(name) {
  const labels = String(name).replace(/\.$/, '').split('.').filter(Boolean);
  return Buffer.concat([...labels.map((l) => Buffer.concat([Buffer.from([l.length]), Buffer.from(l, 'latin1')])), Buffer.from([0])]);
}

function ipv6Bytes(addr) {
  const [head, tail] = addr.includes('::') ? addr.split('::') : [addr, null];
  const h = head ? head.split(':') : [];
  const t = tail ? tail.split(':') : [];
  const groups = tail === null ? h : [...h, ...Array(8 - h.length - t.length).fill('0'), ...t];
  const b = Buffer.alloc(16);
  groups.forEach((g, i) => b.writeUInt16BE(parseInt(g || '0', 16), i * 2));
  return b;
}

/** Plausible RDATA for a type, so a parser that reads RDATA lengths reads real ones. */
export function rdataFor(type, name) {
  switch (typeNum(type)) {
    case T.A: return Buffer.from([192, 0, 2, 1]);
    case T.AAAA: return ipv6Bytes('2001:db8::1');
    case T.NS: case T.CNAME: case T.DNAME: return encodeName(`target.${name}`);
    case T.SOA: return Buffer.concat([encodeName(`ns1.${name}`), encodeName(`hostmaster.${name}`), Buffer.alloc(20, 1)]);
    case T.TXT: return Buffer.concat([Buffer.from([4]), Buffer.from('text')]);
    case T.DNSKEY: return Buffer.concat([Buffer.from([0x01, 0x01, 3, 13]), Buffer.alloc(32, 7)]);
    case T.DS: return Buffer.concat([Buffer.from([0x12, 0x34, 13, 2]), Buffer.alloc(32, 9)]);
    default: return Buffer.alloc(4);
  }
}
export const aRecord = (addr) => Buffer.from(addr.split('.').map(Number));
export const aaaaRecord = (addr) => ipv6Bytes(addr);

function encodeRR(rr, qname) {
  const name = rr.name ?? qname;
  const type = typeNum(rr.type);
  const data = rr.data ?? rdataFor(type, name);
  const fixed = Buffer.alloc(10);
  fixed.writeUInt16BE(type, 0);
  fixed.writeUInt16BE(1, 2);
  fixed.writeUInt32BE(300, 4);
  fixed.writeUInt16BE(data.length, 8);
  return Buffer.concat([encodeName(name), fixed, data]);
}

/** The id, name (case kept), type and class of a query's ONE question; null when it cannot be read. */
export function parseQuery(m) {
  if (m.length < 12 || m.readUInt16BE(4) < 1) return null;
  const labels = [];
  let o = 12;
  for (;;) {
    if (o >= m.length) return null;
    const len = m[o];
    if (len === 0) { o += 1; break; }
    if (len > 63 || o + 1 + len > m.length) return null;
    labels.push(m.toString('latin1', o + 1, o + 1 + len));
    o += 1 + len;
  }
  if (o + 4 > m.length) return null;
  return { id: m.readUInt16BE(0), flags: m.readUInt16BE(2), name: labels.join('.'), type: m.readUInt16BE(o), cls: m.readUInt16BE(o + 2) };
}

/** A reply to `q` built from a spec (fields as the header describes). */
export function buildReply(q, spec = {}) {
  const header = Buffer.alloc(12);
  header.writeUInt16BE(spec.id ?? q.id, 0);
  const qr = spec.qr === false ? 0 : 1;
  const opcode = spec.opcode ?? 0;
  const rd = (q.flags >> 8) & 0x01;
  header[2] = (qr << 7) | ((opcode & 0x0f) << 3) | (spec.tc ? 0x02 : 0) | rd;
  header[3] = 0x80 | ((spec.rcode ?? 0) & 0x0f); // RA=1
  const answers = spec.answers ?? [];
  const authority = spec.authority ?? [];
  const additional = spec.additional ?? [];
  header.writeUInt16BE(spec.noQuestion ? 0 : 1, 4);
  header.writeUInt16BE(answers.length, 6);
  header.writeUInt16BE(authority.length, 8);
  header.writeUInt16BE(additional.length, 10);
  const parts = [header];
  if (!spec.noQuestion) {
    const qq = { name: q.name, type: q.type, cls: q.cls, ...(spec.question ?? {}) };
    const tail = Buffer.alloc(4);
    tail.writeUInt16BE(typeNum(qq.type), 0);
    tail.writeUInt16BE(qq.cls, 2);
    parts.push(encodeName(qq.name), tail);
  }
  for (const rr of [...answers, ...authority, ...additional]) parts.push(encodeRR(rr, q.name));
  return Buffer.concat(parts);
}

// ── Hostile replies (VERDICT-v407 L3e). Each echoes the query's id and question, so it MATCHES and reaches the parser.
/** Fewer than 12 bytes. */
export const shortReply = (q) => Buffer.from([q.id >> 8, q.id & 0xff, 0x81, 0x80, 0, 1, 0, 1]);
/** One answer whose owner name is a compression pointer to ITSELF. */
export function pointerLoopReply(q) {
  const head = buildReply(q, { answers: [] });
  head.writeUInt16BE(1, 6);
  const at = head.length;
  const ptr = Buffer.from([0xc0 | (at >> 8), at & 0xff]);
  const fixed = Buffer.alloc(10);
  fixed.writeUInt16BE(q.type, 0);
  fixed.writeUInt16BE(1, 2);
  return Buffer.concat([head, ptr, fixed]);
}
/** ANCOUNT far larger than the records the message carries. */
export function countOverflowReply(q) {
  const m = buildReply(q, { answers: [{ type: q.type }] });
  m.writeUInt16BE(0xffff, 6);
  return m;
}

function bindUdp(host, port) {
  return new Promise((resolve, reject) => {
    const s = dgram.createSocket({ type: net.isIP(host) === 6 ? 'udp6' : 'udp4', ipv6Only: net.isIP(host) === 6 });
    s.once('error', reject);
    s.bind(port, host, () => { s.off('error', reject); resolve(s); });
  });
}
function listenTcp(server, host, port) {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen({ port, host, ipv6Only: net.isIP(host) === 6 }, () => { server.off('error', reject); resolve(); });
  });
}

/**
 * Starts the server. `tcp: false` leaves TCP unbound on the port, so a TCP connect there is REFUSED.
 * `port` binds a given port (the L9 decoy takes the configured server's port number on the other loopback family).
 * `unref: true` lets the process exit with the server still open (for a test file that never closes it).
 * → { address, port, entry, log, handler (assignable), close() }
 */
export async function startFakeDns({ handler = () => null, host = '127.0.0.1', port = 0, tcp = true, unref = false } = {}) {
  const log = [];
  const seen = new Map();
  const count = (transport, q) => {
    const k = `${transport} ${q.name.toLowerCase()} ${q.type}`;
    const n = (seen.get(k) ?? 0) + 1;
    seen.set(k, n);
    return n;
  };
  const state = { handler };
  const sockets = new Set();
  const timers = new Set();
  const later = (ms, fn) => {
    if (!ms) return fn();
    const t = setTimeout(() => { timers.delete(t); fn(); }, ms);
    timers.add(t);
  };
  let udp;
  let tcpServer = null;
  let alt;
  for (let attempt = 0; ; attempt++) {
    udp = await bindUdp(host, port);
    const p = udp.address().port;
    if (!tcp) break;
    tcpServer = net.createServer();
    try {
      await listenTcp(tcpServer, host, p);
      break;
    } catch (err) {
      udp.close();
      if (port !== 0 || attempt >= 20 || err.code !== 'EADDRINUSE') throw err;
    }
  }
  alt = await bindUdp(host, 0);
  const boundPort = udp.address().port;
  if (unref) { udp.unref(); alt.unref(); tcpServer?.unref(); }

  const answerOf = (q, info) => {
    const out = state.handler(q, info);
    if (out == null) return null;
    if (Buffer.isBuffer(out)) return { bytes: out };
    if (out.raw) return { bytes: out.raw, spec: out };
    if (out.tcpClose) return { close: true, spec: out };
    return { bytes: buildReply(q, out), spec: out };
  };

  udp.on('message', (m, rinfo) => {
    const parsed = parseQuery(m);
    if (!parsed) return;
    const q = { ...parsed, transport: 'udp' };
    log.push({ transport: 'udp', name: q.name, type: q.type, cls: q.cls, id: q.id, from: { address: rinfo.address, port: rinfo.port } });
    const a = answerOf(q, { transport: 'udp', from: rinfo, n: count('udp', q) });
    if (!a?.bytes) return;
    later(a.spec?.delayMs, () => (a.spec?.fromAltPort ? alt : udp).send(a.bytes, rinfo.port, rinfo.address));
  });

  tcpServer?.on('connection', (c) => {
    sockets.add(c);
    c.on('close', () => sockets.delete(c));
    c.on('error', () => {});
    let buf = Buffer.alloc(0);
    c.on('data', (d) => {
      buf = Buffer.concat([buf, d]);
      while (buf.length >= 2 && buf.length >= 2 + buf.readUInt16BE(0)) {
        const m = buf.subarray(2, 2 + buf.readUInt16BE(0));
        buf = buf.subarray(2 + m.length);
        const parsed = parseQuery(m);
        if (!parsed) continue;
        const q = { ...parsed, transport: 'tcp' };
        log.push({ transport: 'tcp', name: q.name, type: q.type, cls: q.cls, id: q.id, from: { address: c.remoteAddress, port: c.remotePort } });
        const a = answerOf(q, { transport: 'tcp', from: { address: c.remoteAddress, port: c.remotePort }, n: count('tcp', q) });
        if (!a) continue;
        if (a.close) { c.destroy(); return; }
        const len = Buffer.alloc(2);
        len.writeUInt16BE(a.bytes.length);
        const framed = Buffer.concat([len, a.bytes]);
        later(a.spec?.delayMs, () => { if (!c.destroyed) c.write(framed); });
      }
    });
  });

  const entry = net.isIP(host) === 6 ? `[${host}]:${boundPort}` : `${host}:${boundPort}`;
  return {
    address: host,
    port: boundPort,
    entry,
    log,
    /** Whether a socket is one of this server's own (its replies are not the client's egress). */
    owns: (sock) => sock === udp || sock === alt,
    get handler() { return state.handler; },
    set handler(h) { state.handler = h; },
    async close() {
      for (const t of timers) clearTimeout(t);
      for (const c of sockets) c.destroy();
      await Promise.all([
        new Promise((r) => udp.close(r)),
        new Promise((r) => alt.close(r)),
        tcpServer ? new Promise((r) => tcpServer.close(r)) : null,
      ]);
    },
  };
}

/** A zone handler: `zone` maps "NAME TYPE" (TYPE a name in T, NAME lower-case) to a spec or a function (q, info) → spec.
 *  Anything not in the map answers NOERROR with no record. */
export function zoneHandler(zone) {
  return (q, info) => {
    const typeName = Object.keys(T).find((k) => T[k] === q.type) ?? String(q.type);
    const key = `${q.name.toLowerCase()} ${typeName}`;
    if (!(key in zone)) return { answers: [] };
    const v = zone[key];
    return typeof v === 'function' ? v(q, info) : v;
  };
}
