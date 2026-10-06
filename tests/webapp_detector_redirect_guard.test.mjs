// tests/webapp_detector_redirect_guard.test.mjs
// 1.3.0 lane 2, item D (operator ruling R2: the per-hop SSRF guard is IN).
//
// Plugin 010 fetched with `redirect: 'follow'`: undici follows any 3xx to any host, up to 20 hops, and
// the scan-entry guard (CLI / MCP) had run once, on the host the OPERATOR named. So a target could send
// the scanner to 127.0.0.1 or 169.254.169.254 — addresses the entry guard refuses — and the redirect's
// response headers landed in the result banner. The TARGET chooses a hop, not the operator, so every
// hop to a different host now goes through the same classifier and resolver as the MCP guard: loopback,
// link-local, metadata and unspecified are refused in every configuration; private ranges only under
// NSA_ALLOW_ALL_HOSTS; a name is refused if ANY answer is. A hop to the host the operator named (any
// port, any scheme between http and https) was admitted at entry and is followed. At most 5 hops.
//
// Harness: globalThis.fetch is a recording stub for the in-process legs (no socket opens); DNS is a
// stub on the default export of node:dns/promises; the last two legs drive REAL undici between two
// loopback listeners this file starts. Env is restored after each leg.
//
// A CARVE-OUT, stated (1.3.0 item 12 made --ports ADDITIVE: the detector always tries https:443 and http:80 first, then
// each added port). These legs are about the chain that starts at http:80, or at an added port, so the DEFAULT URL a leg
// gives no route is refused with DEFAULT_MISS_REASON, kept out of the recorded calls, and removed from the result by
// withoutDefaultMisses — keyed on the URL AND the reason together, never on "any refusal", so a hop refusal can never be
// hidden by it, nor satisfied by a default port's miss. The real-undici legs refuse both default URLs the same way
// (binding 80 / 443 needs privileges, and what listens there is the machine's business). The leg after ACCEPT asserts
// the UNFILTERED result: https:443 is tried first, its miss is a row with exactly that reason, and it is the only row
// the filter removes.

import { test, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import dns from 'node:dns/promises';
import webappDetector from '../plugins/webapp_detector.mjs';

const realFetch = globalThis.fetch;
const realLookup = dns.lookup;
const realAllowAll = process.env.NSA_ALLOW_ALL_HOSTS;
const realExtra = process.env.HTTP_EXTRA_HEADERS;
afterEach(() => {
  globalThis.fetch = realFetch;
  dns.lookup = realLookup;
  if (realAllowAll === undefined) delete process.env.NSA_ALLOW_ALL_HOSTS; else process.env.NSA_ALLOW_ALL_HOSTS = realAllowAll;
  if (realExtra === undefined) delete process.env.HTTP_EXTRA_HEADERS; else process.env.HTTP_EXTRA_HEADERS = realExtra;
});

const WP = '<html><head><meta name="generator" content="WordPress 6.5.2"/></head><body>ok</body></html>';

/**
 * routes: { url: { status, location?, body? } }. Records every URL CONTACTED as [url, opts.redirect].
 * Faithful to fetch where it matters here: under `redirect: 'follow'` (the default) a 3xx with a
 * Location is followed — up to 20 hops, as undici does — and each hop is a contact; under 'manual'
 * the 3xx itself is returned.
 */
const SCANNED = '203.0.113.5';
const DEFAULT_MISS_REASON = 'default port, no route in this leg';
const defaultMissText = (url) => `connect ECONNREFUSED (${url}: ${DEFAULT_MISS_REASON})`;
const refuseDefault = (url) => { throw new Error(defaultMissText(url)); };
/** The result minus the miss rows of exactly these refused DEFAULT URLs — URL and reason both; nothing else is removed. */
const withoutDefaultMisses = (r, urls) =>
  ({ ...r, data: r.data.filter((d) => !urls.some((u) => d.probe_info === `Webapp detect error: ${defaultMissText(u)}`)) });
function stubFetch(routes) {
  const calls = [];
  globalThis.fetch = async (url, opts = {}) => {
    let current = String(url);
    if (!routes[current] && current === `https://${SCANNED}/`) refuseDefault(current);
    for (let hop = 0; hop <= 20; hop++) {
      calls.push([current, opts.redirect, { ...(opts.headers ?? {}) }]);
      const r = routes[current];
      if (!r) throw new Error(`stub: no route for ${current}`);
      const status = r.status ?? 200;
      if (opts.redirect !== 'manual' && status >= 300 && status < 400 && r.location) {
        current = new URL(r.location, current).href;
        continue;
      }
      const headers = r.location ? { location: r.location } : {};
      return Object.assign(new Response(r.body ?? '', { status, headers }), {});
    }
    throw new TypeError('fetch failed: redirect count exceeded');
  };
  return calls;
}
function stubDns(answers) {
  const asked = [];
  dns.lookup = async (name) => {
    asked.push(name);
    const a = answers[name];
    if (!a) throw Object.assign(new Error(`getaddrinfo ENOTFOUND ${name}`), { code: 'ENOTFOUND' });
    return a.map((address) => ({ address, family: address.includes(':') ? 6 : 4 }));
  };
  return asked;
}
const unfiltered = (host) => webappDetector.run(host, 0, {});
const run = async (host) => withoutDefaultMisses(await unfiltered(host), [`https://${host}/`]);
const errorRows = (r) => r.data.filter((d) => /error|refused|limit/i.test(d.probe_info));
/** Real undici, with the two DEFAULT URLs on the scanned host refused (marked); every other URL goes to the real fetch. */
const DEFAULTS_LOOPBACK = ['https://127.0.0.1/', 'http://127.0.0.1/'];
function realFetchDefaultsRefused(host) {
  globalThis.fetch = async (url, init) => (url === `https://${host}/` || url === `http://${host}/` ? refuseDefault(url) : realFetch(url, init));
}

// ── ACCEPT ───────────────────────────────────────────────────────────────────

test('(fourth quadrant, first) a redirect to the SAME host the operator named — another scheme or port — is followed and detection works', async () => {
  const calls = stubFetch({
    'http://203.0.113.5/': { status: 301, location: 'https://203.0.113.5:8443/' },
    'https://203.0.113.5:8443/': { status: 200, body: WP },
  });
  const r = await run('203.0.113.5');
  assert.equal(r.up, true);
  assert.match(r.data[0].probe_info, /WordPress/);
  assert.deepEqual(calls.map((c) => c[0]), ['http://203.0.113.5/', 'https://203.0.113.5:8443/']);
});

test('(fourth quadrant) a hop to a PUBLIC name whose every answer is public is followed', async () => {
  stubDns({ 'www.example.net': ['93.184.215.14', '2606:2800:21f:cb07:6820:80da:af6b:8b2c'] });
  const calls = stubFetch({
    'http://203.0.113.5/': { status: 302, location: 'http://www.example.net/' },
    'http://www.example.net/': { status: 200, body: WP },
  });
  const r = await run('203.0.113.5');
  assert.equal(r.up, true);
  assert.equal(calls.length, 2);
});

test('(fourth quadrant) under NSA_ALLOW_ALL_HOSTS=1 a hop to a PRIVATE address is followed — the operator admitted private ranges', async () => {
  process.env.NSA_ALLOW_ALL_HOSTS = '1';
  const calls = stubFetch({
    'http://203.0.113.5/': { status: 302, location: 'http://10.0.0.9/' },
    'http://10.0.0.9/': { status: 200, body: WP },
  });
  const r = await run('203.0.113.5');
  assert.equal(r.up, true);
  assert.equal(calls.length, 2);
});

test('(fourth quadrant) the UNFILTERED result: https:443 is tried FIRST, its miss is a row with exactly the stated reason, and it is the only row the filter removes', async () => {
  const calls = stubFetch({ 'http://203.0.113.5/': { status: 200, body: WP } });
  const r = await unfiltered('203.0.113.5');
  assert.equal(r.up, true);
  assert.deepEqual(r.data.map((d) => [d.probe_protocol, d.probe_port]), [['https', 443], ['http', 80]], 'https:443 first, then http:80');
  assert.equal(r.data[0].probe_info, `Webapp detect error: ${defaultMissText('https://203.0.113.5/')}`);
  assert.deepEqual(withoutDefaultMisses(r, ['https://203.0.113.5/']).data, r.data.slice(1), 'the filter removes that row and nothing else');
  assert.deepEqual(calls.map((c) => c[0]), ['http://203.0.113.5/'], 'the refused default is not a recorded call');
});

// ── DEFECT ───────────────────────────────────────────────────────────────────

test('every request is made with redirect: "manual" — the plugin follows hops itself, never undici', async () => {
  const calls = stubFetch({
    'http://203.0.113.5/': { status: 301, location: 'http://203.0.113.5/home' },
    'http://203.0.113.5/home': { status: 200, body: WP },
  });
  await run('203.0.113.5');
  assert.ok(calls.length >= 1);
  assert.deepEqual(calls.map((c) => c[1]), calls.map(() => 'manual'));
});

test('a hop to cloud metadata or loopback is REFUSED in every configuration — no request, and a row names the refused hop', async () => {
  for (const allowAll of [undefined, '1']) {
    if (allowAll) process.env.NSA_ALLOW_ALL_HOSTS = allowAll; else delete process.env.NSA_ALLOW_ALL_HOSTS;
    for (const target of ['http://169.254.169.254/latest/meta-data/', 'http://127.0.0.1:8080/', 'http://[::ffff:7f00:1]/', 'http://0x7f000001/']) {
      const calls = stubFetch({ 'http://203.0.113.5/': { status: 302, location: target } });
      const r = await run('203.0.113.5');
      assert.equal(calls.length, 1, `${target} (allow-all ${allowAll}): no request may follow the refused hop`);
      assert.equal(r.up, false);
      assert.ok(errorRows(r).some((d) => /refused/i.test(d.probe_info)), `${target}: ${JSON.stringify(r.data)}`);
    }
  }
});

test('a hop to a PRIVATE address is refused unless the operator allowed all hosts', async () => {
  delete process.env.NSA_ALLOW_ALL_HOSTS;
  const calls = stubFetch({ 'http://203.0.113.5/': { status: 302, location: 'http://192.168.1.1/' } });
  const r = await run('203.0.113.5');
  assert.equal(calls.length, 1);
  assert.ok(errorRows(r).some((d) => /refused/i.test(d.probe_info)));
});

test('a hop to a name with ANY blocked answer, or one that does not resolve, is refused', async () => {
  stubDns({ 'mixed.example': ['93.184.215.14', '127.0.0.1'] });
  for (const name of ['mixed.example', 'nowhere.example']) {
    const calls = stubFetch({ 'http://203.0.113.5/': { status: 302, location: `http://${name}/` } });
    const r = await run('203.0.113.5');
    assert.equal(calls.length, 1, name);
    assert.ok(errorRows(r).some((d) => /refused/i.test(d.probe_info)), name);
  }
});

test('a hop to a non-http(s) scheme is refused', async () => {
  for (const loc of ['file:///etc/passwd', 'gopher://203.0.113.9/']) {
    const calls = stubFetch({ 'http://203.0.113.5/': { status: 302, location: loc } });
    const r = await run('203.0.113.5');
    assert.equal(calls.length, 1, loc);
    assert.ok(errorRows(r).some((d) => /refused/i.test(d.probe_info)), loc);
  }
});

test('the hop chain is bounded at 5 — the sixth redirect is not followed', async () => {
  const routes = {};
  for (let i = 0; i <= 6; i++) routes[`http://203.0.113.5/${i ? i : ''}`] = { status: 302, location: `http://203.0.113.5/${i + 1}` };
  const calls = stubFetch(routes);
  const r = await run('203.0.113.5');
  assert.equal(calls.length, 6, 'the first request plus 5 hops');
  assert.ok(errorRows(r).some((d) => /limit/i.test(d.probe_info)));
});

// ── the operator's extra headers never travel to another origin ──────────────
// (Security review of the first hop-loop commit: following hops itself, the detector re-sent every header
// — HTTP_EXTRA_HEADERS included, where an operator puts an Authorization or an API key — to whatever host
// the target named. undici's own follow drops Authorization on a cross-origin hop; this drops ALL the
// operator's extra headers once the chain leaves the origin the operator named, and never re-adds them.)
const SECRET = { Authorization: 'Bearer operator-secret', 'X-Api-Key': 'k-123' };
const carriesSecret = (h) => Object.keys(h).some((k) => /^(authorization|x-api-key)$/i.test(k));

test('(fourth quadrant) a hop within the SAME origin keeps the operator\'s extra headers', async () => {
  process.env.HTTP_EXTRA_HEADERS = JSON.stringify(SECRET);
  const calls = stubFetch({
    'http://203.0.113.5/': { status: 301, location: '/home' },
    'http://203.0.113.5/home': { status: 200, body: WP },
  });
  await run('203.0.113.5');
  assert.deepEqual(calls.map((c) => carriesSecret(c[2])), [true, true]);
});

test('a hop to ANOTHER HOST carries none of the operator\'s extra headers — and they are not re-added on the way back', async () => {
  process.env.HTTP_EXTRA_HEADERS = JSON.stringify(SECRET);
  stubDns({ 'www.example.net': ['93.184.215.14'] });
  const calls = stubFetch({
    'http://203.0.113.5/': { status: 302, location: 'http://www.example.net/' },
    'http://www.example.net/': { status: 302, location: 'http://203.0.113.5/back' },
    'http://203.0.113.5/back': { status: 200, body: WP },
  });
  await run('203.0.113.5');
  assert.deepEqual(calls.map((c) => [c[0], carriesSecret(c[2])]), [
    ['http://203.0.113.5/', true], ['http://www.example.net/', false], ['http://203.0.113.5/back', false]]);
});

test('a same-host hop that changes scheme or port is another origin — the extra headers are dropped', async () => {
  process.env.HTTP_EXTRA_HEADERS = JSON.stringify(SECRET);
  // The scheme change goes to a PATH on the https origin: its root is also the default https:443 URL, tried first since item 12.
  for (const next of ['https://203.0.113.5/landing', 'http://203.0.113.5:8080/']) {
    const calls = stubFetch({
      'http://203.0.113.5/': { status: 301, location: next },
      [next]: { status: 200, body: WP },
    });
    await run('203.0.113.5');
    assert.deepEqual(calls.map((c) => carriesSecret(c[2])), [true, false], next);
  }
});

// ── REAL dependency: undici between two loopback listeners ───────────────────

async function listen(handler) {
  const hits = [];
  const srv = http.createServer((req, res) => { hits.push(req.url); handler(req, res); });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  return { srv, hits, port: srv.address().port };
}

test('real undici: A on 127.0.0.1 redirects to B on the SAME host (another port) — followed, B answers', async () => {
  const B = await listen((req, res) => res.end(WP));
  const A = await listen((req, res) => { res.writeHead(302, { location: `http://127.0.0.1:${B.port}/` }); res.end(); });
  realFetchDefaultsRefused('127.0.0.1');
  try {
    const r = withoutDefaultMisses(await webappDetector.run('127.0.0.1', 0, { ports: [A.port] }), DEFAULTS_LOOPBACK);
    assert.equal(B.hits.length, 1);
    assert.equal(r.up, true);
  } finally { A.srv.close(); B.srv.close(); }
});

test('real undici: A on 127.0.0.1 redirects to "localhost" (a different host, loopback answers) — refused, B receives NOTHING', async () => {
  delete process.env.NSA_ALLOW_ALL_HOSTS;
  const B = await listen((req, res) => res.end(WP));
  const A = await listen((req, res) => { res.writeHead(302, { location: `http://localhost:${B.port}/` }); res.end(); });
  realFetchDefaultsRefused('127.0.0.1');
  try {
    const r = withoutDefaultMisses(await webappDetector.run('127.0.0.1', 0, { ports: [A.port] }), DEFAULTS_LOOPBACK);
    assert.equal(A.hits.length >= 1, true, 'positive control: A was asked');
    assert.equal(B.hits.length, 0, 'the target steered the scanner to a loopback name; the hop must not be made');
    assert.ok(errorRows(r).some((d) => /refused/i.test(d.probe_info)), JSON.stringify(r.data));
  } finally { A.srv.close(); B.srv.close(); }
});
