// tests/webapp_detector_redirect_guard.test.mjs
// 1.2.1 lane 2, item D (operator ruling R2: the per-hop SSRF guard is IN).
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

import { test, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import dns from 'node:dns/promises';
import webappDetector from '../plugins/webapp_detector.mjs';

const realFetch = globalThis.fetch;
const realLookup = dns.lookup;
const realAllowAll = process.env.NSA_ALLOW_ALL_HOSTS;
afterEach(() => {
  globalThis.fetch = realFetch;
  dns.lookup = realLookup;
  if (realAllowAll === undefined) delete process.env.NSA_ALLOW_ALL_HOSTS; else process.env.NSA_ALLOW_ALL_HOSTS = realAllowAll;
});

const WP = '<html><head><meta name="generator" content="WordPress 6.5.2"/></head><body>ok</body></html>';

/**
 * routes: { url: { status, location?, body? } }. Records every URL CONTACTED as [url, opts.redirect].
 * Faithful to fetch where it matters here: under `redirect: 'follow'` (the default) a 3xx with a
 * Location is followed — up to 20 hops, as undici does — and each hop is a contact; under 'manual'
 * the 3xx itself is returned.
 */
function stubFetch(routes) {
  const calls = [];
  globalThis.fetch = async (url, opts = {}) => {
    let current = String(url);
    for (let hop = 0; hop <= 20; hop++) {
      calls.push([current, opts.redirect]);
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
const run = (host) => webappDetector.run(host, 0, { ports: [80] });
const errorRows = (r) => r.data.filter((d) => /error|refused|limit/i.test(d.probe_info));

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
  try {
    const r = await webappDetector.run('127.0.0.1', 0, { ports: [A.port] });
    assert.equal(B.hits.length, 1);
    assert.equal(r.up, true);
  } finally { A.srv.close(); B.srv.close(); }
});

test('real undici: A on 127.0.0.1 redirects to "localhost" (a different host, loopback answers) — refused, B receives NOTHING', async () => {
  delete process.env.NSA_ALLOW_ALL_HOSTS;
  const B = await listen((req, res) => res.end(WP));
  const A = await listen((req, res) => { res.writeHead(302, { location: `http://localhost:${B.port}/` }); res.end(); });
  try {
    const r = await webappDetector.run('127.0.0.1', 0, { ports: [A.port] });
    assert.equal(A.hits.length >= 1, true, 'positive control: A was asked');
    assert.equal(B.hits.length, 0, 'the target steered the scanner to a loopback name; the hop must not be made');
    assert.ok(errorRows(r).some((d) => /refused/i.test(d.probe_info)), JSON.stringify(r.data));
  } finally { A.srv.close(); B.srv.close(); }
});
