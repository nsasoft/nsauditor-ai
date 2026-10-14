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

const tcp = (port, host = 'localhost') => new Promise((resolve) => {
  const s = net.connect({ host, port, family: 4 });
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
const fetchGet = async (port, host = 'localhost') => {
  try { const r = await fetch(`http://${host}:${port}/`, { signal: AbortSignal.timeout(500) }); await r.text(); return r.status; }
  catch (e) { return e.name ?? 'error'; }
};
/** http.get with a URL STRING — which is URL-parsed, so it looks up the ASCII form of the name (the options form does not). */
const httpGetUrl = (port, host) => new Promise((resolve) => {
  const req = http.get(`http://${host}:${port}/`, { timeout: 400 }, (res) => { res.resume(); res.on('end', () => resolve(res.statusCode)); });
  req.on('timeout', () => { req.destroy(); resolve('timeout'); });
  req.on('error', (e) => resolve(e.code ?? 'error'));
});

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

// ─────────────────────────────────────────────────────────────────────────────
// G1 — THE KEY IS THE NAME A CLIENT LOOKS UP, NOT THE SPELLING THE OPERATOR TYPED. The host check resolves the spelling
// as given, and `node:dns` `lookup` applies the IDNA ToASCII mapping inside, so `ⓛocalhost` or `bücher.example` passes the
// check. Every URL-parsing client — fetch, http.get with a URL —
// looks up the ASCII form (`localhost`, `xn--bcher-kva.example`). A pin keyed on the spelling missed that lookup, and the
// client resolved the name again: a rebinding name reached whatever its second answer named.
//
// FOURTH QUADRANT FIRST: (a) and (b) are what the canonical key must NOT change; (c)–(e) are the defect.
// ─────────────────────────────────────────────────────────────────────────────

test('G1 (a): an ASCII name keeps its key — case and one trailing dot fold, and a different name is not pinned', async () => {
  const X = [{ address: '198.51.100.20', family: 4 }];
  const seen = await runPinned({ 'Example.COM.': X, 'foo_bar.example': ELSEWHERE }, async () => ({
    lookup: await dnsPromises.lookup('example.com', { family: 4 }),
    keys: ['example.com', 'EXAMPLE.COM', 'example.com.'].map((h) => pinnedAnswersFor(h)),
    underscore: pinnedAnswersFor('FOO_BAR.example'),
    other: pinnedAnswersFor('example.org'),
    sub: pinnedAnswersFor('www.example.com'),
  }));
  assert.deepEqual(seen.lookup, { address: '198.51.100.20', family: 4 });
  for (const answers of seen.keys) assert.deepEqual(answers, X, 'an ASCII name no longer folds case and one trailing dot');
  assert.deepEqual(seen.underscore, ELSEWHERE, 'an underscore label (valid in DNS, kept by domainToASCII) lost its pin');
  assert.equal(seen.other, null, 'a different name answered another name\'s pin');
  assert.equal(seen.sub, null, 'a subdomain answered its parent\'s pin');
});

test('G1 (b): a name domainToASCII REJECTS keeps its raw key (trimmed, lower-cased) and still pins net.connect — and two rejected names never share a key', async () => {
  const rx = await receiver();
  try {
    // Negative control: unpinned, the resolver refuses this label outright (EINVAL, offline), so a connect that lands on
    // the receiver below landed there through the pin and nothing else.
    assert.notEqual(await tcp(rx.port, 'xn--zz'), 'connected', 'negative control: an unpinned xn--zz resolved somewhere');
    await settle();
    assert.equal(rx.count(), 0, 'negative control: an unpinned xn--zz reached the receiver');
    const AT_RX = [{ address: '127.0.0.1', family: 4 }];
    const seen = await runPinned({ ' XN--ZZ ': AT_RX }, async () => ({
      connect: await tcp(rx.port, 'xn--zz'),
      // A canonical form with no fallback keys EVERY rejected name as '' — one pin would answer for all of them.
      other: pinnedAnswersFor('xn--yy'),
      spaced: pinnedAnswersFor('exa mple'),
      empty: pinnedAnswersFor(''),
    }));
    assert.equal(seen.connect, 'connected', 'a name domainToASCII rejects lost its pin');
    await settle();
    assert.equal(rx.count(), 1);
    assert.equal(seen.other, null, 'two names domainToASCII rejects share one key — the raw-key fallback is missing');
    assert.equal(seen.spaced, null, 'a rejected name answered another rejected name\'s pin');
    assert.equal(seen.empty, null, 'the empty name answered a pin');
  } finally { await rx.close(); }
});

// Each spelling kills a different wrong fix: an enclosed letter and fullwidth letters are mapped by NFKC as well, but a
// soft hyphen is DELETED by the IDNA mapping and KEPT by NFKC — a `normalize('NFKC')` "fix" leaves that one open.
const G1_SPELLINGS = [['ⓛocalhost', 'an enclosed letter'], ['ＬＯＣＡＬＨＯＳＴ', 'fullwidth letters'], ['local­host', 'a soft hyphen']];
// net.connect looks up the spelling as given; fetch and http.get with a URL look up the ASCII form. A key canonicalised on
// ONE side only (the merge or the lookup) fails one of these.
const G1_CLIENTS = [['net.connect', tcp], ['fetch', fetchGet], ['http.get(url)', httpGetUrl]];
for (const [spelling, what] of G1_SPELLINGS) {
  for (const [client, connect] of G1_CLIENTS) {
    test(`G1 (c): pinned under ${what} (${JSON.stringify(spelling)}), ${client} never reaches loopback; unpinned it does`, async () => {
      const rx = await receiver();
      try {
        await connect(rx.port, spelling);
        await settle();
        const unpinned = rx.count();
        assert.ok(unpinned >= 1, `positive control: an unpinned ${client} to ${JSON.stringify(spelling)} did not reach the loopback receiver`);
        await runPinned({ [spelling]: ELSEWHERE }, () => connect(rx.port, spelling));
        await settle();
        assert.equal(rx.count(), unpinned, `a ${client} to ${JSON.stringify(spelling)} reached loopback under its pin — the client looked up a name the pin was not keyed on`);
      } finally { await rx.close(); }
    });
  }
  test(`G1 (c): pinned under the ASCII name, net.connect to ${what} (${JSON.stringify(spelling)}) never reaches loopback — both sides share one key`, async () => {
    const rx = await receiver();
    try {
      await tcp(rx.port, spelling);
      await settle();
      const unpinned = rx.count();
      assert.ok(unpinned >= 1, 'positive control: an unpinned net.connect did not reach the loopback receiver');
      await runPinned(PIN, () => tcp(rx.port, spelling));
      await settle();
      assert.equal(rx.count(), unpinned, `net.connect to ${JSON.stringify(spelling)} escaped the pin on 'localhost'`);
    } finally { await rx.close(); }
  });
}

test('G1 (d): pinned under a Unicode name, the punycode name a URL client looks up is pinned — and the connect follows the PINNED answer', async () => {
  const rx = await receiver();
  try {
    const AT_RX = [{ address: '127.0.0.1', family: 4 }];
    // Both runs are pinned, so neither asks a real resolver: the outcome follows the pinned answer — the receiver under
    // AT_RX, nowhere under ELSEWHERE — and that pairing is the control that the answer came from the pin.
    const toRx = await runPinned({ 'bücher.example': AT_RX }, async () => ({
      answers: pinnedAnswersFor('xn--bcher-kva.example'),
      address: pinnedAddressFor('xn--bcher-kva.example'),
      fetched: await fetchGet(rx.port, 'bücher.example'),
    }));
    assert.deepEqual(toRx.answers, AT_RX, 'xn--bcher-kva.example is not pinned under the pin on bücher.example');
    assert.equal(toRx.address, '127.0.0.1');
    assert.equal(toRx.fetched, 200, 'fetch looked up xn--bcher-kva.example, missed the pin on bücher.example and resolved the name live');
    await settle();
    const reached = rx.count();
    assert.equal(reached, 1);
    await runPinned({ 'bücher.example': ELSEWHERE }, () => fetchGet(rx.port, 'bücher.example'));
    await settle();
    assert.equal(rx.count(), reached, 'pinned elsewhere, fetch to bücher.example still reached the receiver');
    // The other direction: a pin on the ASCII form answers the Unicode spelling.
    const reverse = await runPinned({ 'xn--bcher-kva.example': ELSEWHERE }, async () => ({
      unicode: pinnedAnswersFor('bücher.example'),
      upper: pinnedAnswersFor('BÜCHER.EXAMPLE'),
    }));
    assert.deepEqual(reverse, { unicode: ELSEWHERE, upper: ELSEWHERE }, 'a pin on xn--bcher-kva.example does not answer bücher.example');
  } finally { await rx.close(); }
});

test('G1 (e): case, one trailing dot, an ideographic full stop and surrounding whitespace still fold — to the key the client looks up', async () => {
  const X = [{ address: '198.51.100.30', family: 4 }];
  const seen = await runPinned({ ' BÜCHER。Example。 ': X }, async () => (
    ['xn--bcher-kva.example', 'XN--BCHER-KVA.EXAMPLE.', 'bücher.example', 'Bücher.Example.'].map((h) => pinnedAnswersFor(h))
  ));
  for (const answers of seen) assert.deepEqual(answers, X, 'a spelling of bücher.example did not fold to its pinned key');
  // U+3002 is a label separator to IDNA and to the URL parser: `localhost。` is fetched as `localhost.`.
  const rx = await receiver();
  try {
    await fetchGet(rx.port, 'localhost。');
    await settle();
    const unpinned = rx.count();
    assert.ok(unpinned >= 1, 'positive control: an unpinned fetch to localhost。 did not reach the loopback receiver');
    await runPinned({ 'localhost。': ELSEWHERE }, () => fetchGet(rx.port, 'localhost。'));
    await settle();
    assert.equal(rx.count(), unpinned, 'pinned under localhost。, fetch looked up localhost. and reached loopback');
  } finally { await rx.close(); }
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
