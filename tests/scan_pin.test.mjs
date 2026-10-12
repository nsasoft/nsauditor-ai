// tests/scan_pin.test.mjs
// ─────────────────────────────────────────────────────────────────────────────
// THE SCAN-TARGET PIN, family by family (EE 2.0.0, R1b). DRIVEN, OFFLINE: `localhost` is the rebinding name — the
// system resolver answers loopback for it with no network, where a receiver counts connections. A pinned run answers
// 203.0.113.10 for it instead (RFC 5737, routed nowhere), so a connect that honours the pin never reaches the receiver.
//
// FOURTH QUADRANT FIRST, per family: unpinned, the connect lands on the loopback receiver — or the pinned result proves
// nothing.
// ─────────────────────────────────────────────────────────────────────────────
import { test } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import tls from 'node:tls';
import http from 'node:http';
import dgram from 'node:dgram';
import dnsPromises from 'node:dns/promises';
import dns, { lookup as namedLookup } from 'node:dns';
import { runPinned, pinnedAddressFor, pinnedAnswersFor } from '../utils/scan_pin.mjs';

const ELSEWHERE = [{ address: '203.0.113.10', family: 4 }];
/** Server-side `connection` events can trail the client's own `connect`: give stragglers time before reading a count. */
const settle = () => new Promise((r) => setTimeout(r, 150));
const PIN = { localhost: ELSEWHERE };

/** A TCP receiver on 127.0.0.1 that counts connections (and answers HTTP so http/fetch complete when they arrive). */
async function receiver() {
  let connections = 0;
  const server = http.createServer((req, res) => { res.writeHead(200, { connection: 'close' }); res.end('ok'); });
  server.on('connection', () => { connections += 1; });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  return { port: server.address().port, count: () => connections, close: () => new Promise((r) => server.close(r)) };
}

const tcp = (port) => new Promise((resolve) => {
  const s = net.connect({ host: 'localhost', port, family: 4 });
  s.setTimeout(400, () => { s.destroy(); resolve('timeout'); });
  s.on('connect', () => { s.destroy(); resolve('connected'); });
  s.on('error', (e) => resolve(e.code ?? 'error'));
});
const tlsConnect = (port) => new Promise((resolve) => {
  // Certificate verification stays ON: this leg only measures WHERE the socket lands (the receiver speaks no TLS).
  const s = tls.connect({ host: 'localhost', port, family: 4, timeout: 400 });
  s.on('timeout', () => { s.destroy(); resolve('timeout'); });
  s.on('error', (e) => resolve(e.code ?? 'error'));
  s.on('secureConnect', () => { s.destroy(); resolve('secure'); });
});
const httpGet = (port) => new Promise((resolve) => {
  const req = http.get({ host: 'localhost', port, family: 4, timeout: 400 }, (res) => { res.resume(); res.on('end', () => resolve(res.statusCode)); });
  req.on('timeout', () => { req.destroy(); resolve('timeout'); });
  req.on('error', (e) => resolve(e.code ?? 'error'));
});
const fetchGet = async (port) => {
  try { const r = await fetch(`http://localhost:${port}/`, { signal: AbortSignal.timeout(500) }); await r.text(); return r.status; }
  catch (e) { return e.name ?? 'error'; }
};

for (const [family, connect] of [['TCP (net.connect)', tcp], ['TLS (tls.connect)', tlsConnect], ['HTTP (http.get)', httpGet], ['fetch', fetchGet]]) {
  test(`${family}: unpinned it lands on loopback (positive control); pinned it never does`, async () => {
    const rx = await receiver();
    try {
      await connect(rx.port);
      await settle();
      const unpinned = rx.count();
      assert.ok(unpinned >= 1, `positive control: an unpinned ${family} connect to localhost did not reach the loopback receiver`);
      await runPinned(PIN, () => connect(rx.port));
      await settle();
      assert.equal(rx.count(), unpinned, `a pinned ${family} connect reached loopback — the pin did not govern it`);
    } finally { await rx.close(); }
  });
}

test('UDP (dgram): unpinned the datagram reaches loopback; pinned it goes to the pinned address', async () => {
  const sock = dgram.createSocket('udp4');
  let got = 0;
  sock.on('message', () => { got += 1; });
  await new Promise((r) => sock.bind(0, '127.0.0.1', r));
  const port = sock.address().port;
  const send = () => new Promise((resolve) => {
    const c = dgram.createSocket('udp4');
    c.send('x', port, 'localhost', () => { c.close(); resolve(); });
  });
  try {
    await send(); await new Promise((r) => setTimeout(r, 100));
    assert.equal(got, 1, 'positive control: an unpinned datagram to localhost reached loopback');
    await runPinned(PIN, send); await new Promise((r) => setTimeout(r, 100));
    assert.equal(got, 1, 'a pinned datagram reached loopback');
  } finally { sock.close(); }
});

test('the resolvers themselves: dns/promises, callback dns and an ESM NAMED import all answer the pin inside, and nothing outside', async () => {
  const inside = await runPinned(PIN, async () => ({
    promises: await dnsPromises.lookup('localhost', { family: 4 }),
    named: await new Promise((r) => namedLookup('localhost', { family: 4 }, (e, a) => r(a))),
    all: await dnsPromises.lookup('LOCALHOST.', { all: true }),
    answers: pinnedAnswersFor('localhost'),
    address: pinnedAddressFor('LocalHost'),
  }));
  assert.deepEqual(inside.promises, { address: '203.0.113.10', family: 4 });
  assert.equal(inside.named, '203.0.113.10', 'an ESM named import bypassed the pin (syncBuiltinESMExports missing)');
  assert.deepEqual(inside.all, ELSEWHERE, 'case and a trailing dot name the same host');
  assert.deepEqual(inside.answers, ELSEWHERE);
  assert.equal(inside.address, '203.0.113.10');
  const outside = await dnsPromises.lookup('localhost', { family: 4 });
  assert.equal(outside.address, '127.0.0.1', 'the pin leaked outside its run');
  assert.equal(pinnedAddressFor('localhost'), null);
});

test('a family the check never answered is NOT FOUND inside the pin — never handed to the real resolver', async () => {
  // Positive control: unpinned, the system resolver answers an IPv6 loopback for localhost — the leak this leg watches for.
  assert.equal((await dnsPromises.lookup('localhost', { family: 6 })).address, '::1', 'positive control: no IPv6 answer for localhost here');
  await assert.rejects(runPinned(PIN, () => dnsPromises.lookup('localhost', { family: 6 })), { code: 'ENOTFOUND' });
  const viaCallback = await runPinned(PIN, () => new Promise((r) => dns.lookup('localhost', 6, (e, a) => r(e ? e.code : a))));
  assert.equal(viaCallback, 'ENOTFOUND');
});

test('a THROWN scan leaves nothing pinned, and two OVERLAPPING scans keep their own answer sets', async () => {
  await assert.rejects(runPinned(PIN, async () => { await new Promise((r) => setTimeout(r, 5)); throw new Error('scan failed'); }), /scan failed/);
  assert.equal((await dnsPromises.lookup('localhost', { family: 4 })).address, '127.0.0.1', 'a thrown scan left its pin behind');
  const [a, b] = await Promise.all([
    runPinned({ localhost: [{ address: '203.0.113.10', family: 4 }] }, async () => { await new Promise((r) => setTimeout(r, 20)); return (await dnsPromises.lookup('localhost', { family: 4 })).address; }),
    runPinned({ localhost: [{ address: '198.51.100.7', family: 4 }] }, async () => { await new Promise((r) => setTimeout(r, 5)); return (await dnsPromises.lookup('localhost', { family: 4 })).address; }),
  ]);
  assert.deepEqual([a, b], ['203.0.113.10', '198.51.100.7'], 'one scan answered with the other scan\'s pin');
});

test('a NESTED run (a redirect hop) inherits the scan\'s pins and adds its own; the scan\'s are unchanged after it', async () => {
  const seen = await runPinned(PIN, async () => {
    const inner = await runPinned({ 'hop.test': [{ address: '198.51.100.7', family: 4 }], localhost: [{ address: '198.51.100.8', family: 4 }] }, async () => ({
      hop: (await dnsPromises.lookup('hop.test', { family: 4 })).address,
      target: (await dnsPromises.lookup('localhost', { family: 4 })).address,
    }));
    return { inner, after: (await dnsPromises.lookup('localhost', { family: 4 })).address, hopAfter: pinnedAddressFor('hop.test') };
  });
  assert.deepEqual(seen, { inner: { hop: '198.51.100.7', target: '198.51.100.8' }, after: '203.0.113.10', hopAfter: null });
  const innerOnly = await runPinned(PIN, () => runPinned({ 'hop.test': [{ address: '198.51.100.7', family: 4 }] }, () => dnsPromises.lookup('localhost', { family: 4 })));
  assert.equal(innerOnly.address, '203.0.113.10', 'the inner run dropped the scan\'s own pin');
});

test('KEEP-ALIVE, A STATED LIMIT (measured): fetch pools connections by NAME, so a scan can reuse an idle connection an EARLIER scan of that name opened — to the address THAT scan\'s check admitted', async () => {
  // This leg first claimed the reuse never happens and asserted only that no NEW connection opened, which a reused one
  // satisfies too; it passed because scan 2 ran before the pooled socket went idle. With the socket idle, scan 2 reuses it.
  let connections = 0; let requests = 0;
  const keep = http.createServer((req, res) => { requests += 1; res.writeHead(200); res.end('a'); });   // keep-alive on (default)
  keep.on('connection', () => { connections += 1; });
  await new Promise((r) => keep.listen(0, '127.0.0.1', r));
  const port = keep.address().port;
  try {
    assert.equal(await runPinned({ localhost: [{ address: '127.0.0.1', family: 4 }] }, () => fetchGet(port)), 200, 'positive control: scan 1 reached the server');
    assert.equal(connections, 1);
    await new Promise((r) => setTimeout(r, 300));   // scan 1's connection is idle in the pool
    const second = await runPinned(PIN, () => fetchGet(port));
    // Every connect scan 2 makes goes where it is pinned: it opens none here …
    assert.equal(connections, 1, 'scan 2 opened a connection its pin did not govern');
    // … but its request rides scan 1's pooled connection to scan 1's checked address. If these two go red, the limit has
    // closed: update utils/scan_pin.mjs, the README and SKILL.md, which state it.
    assert.equal(second, 200, 'LIMIT CLOSED? scan 2 no longer reuses scan 1\'s idle connection');
    assert.equal(requests, 2);
  } finally { keep.closeAllConnections(); await new Promise((r) => keep.close(r)); }
});

test('LAST (it replaces the resolvers): a resolver REPLACED after the pin was installed is pinned again on the next run — outright or delegating, with no loop', async () => {
  await runPinned(PIN, () => dnsPromises.lookup('localhost', { family: 4 }));   // installed
  const pinnedPromises = dnsPromises.lookup; const pinnedCallback = dns.lookup;
  const cb = (name) => new Promise((r) => dns.lookup(name, { family: 4 }, (e, a) => r(e ? e.code : a)));
  try {
    // (a) a DELEGATING wrapper over the pinned resolver — the shape an APM agent or a caching library installs.
    let through = 0;
    dnsPromises.lookup = function wrapped(h, o) {
      through += 1;
      // A chain that LOOPS overflows the stack inside V8's promise hook, which the runner charges to the FILE, not this leg.
      if (through > 5) throw new Error('the resolver chain LOOPS — a wrapper reached itself through the pin');
      return pinnedPromises.call(dnsPromises, h, o);
    };
    assert.equal((await runPinned(PIN, () => dnsPromises.lookup('localhost', { family: 4 }))).address, '203.0.113.10');
    assert.equal((await dnsPromises.lookup('localhost', { family: 4 })).address, '127.0.0.1', 'the pin leaked outside its run');
    // The pin answers a pinned name before the wrapper is reached; every UNPINNED lookup still goes through it.
    assert.equal(through, 1, 'the delegating wrapper fell out of the chain for an unpinned lookup');
    // (b) an OUTRIGHT replacement that never reaches the pin — a flag saying "installed" would leave every later scan unpinned.
    dnsPromises.lookup = async () => ({ address: '127.0.0.1', family: 4 });
    dns.lookup = (h, o, callback) => process.nextTick(typeof o === 'function' ? o : callback, null, '127.0.0.1', 4);
    assert.equal((await runPinned(PIN, () => dnsPromises.lookup('localhost', { family: 4 }))).address, '203.0.113.10', 'dns/promises was not pinned again');
    assert.equal(await runPinned(PIN, () => cb('localhost')), '203.0.113.10', 'callback dns was not pinned again');
    assert.equal(await cb('localhost'), '127.0.0.1', 'outside a run the replacement answers');
  } finally {
    dnsPromises.lookup = pinnedPromises; dns.lookup = pinnedCallback;
  }
});
