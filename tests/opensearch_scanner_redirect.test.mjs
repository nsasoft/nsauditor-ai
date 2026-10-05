// tests/opensearch_scanner_redirect.test.mjs
// 1.2.1 lane 2, item D (operator ruling R2) — the THIRD redirect-following path, found while building the
// call-keyed fetch census: the OpenSearch scanner binds fetch through getFetch() (`doFetch`), passed no
// redirect option, and so followed any 3xx from the scanned port to any host. It reads the banner and
// version at `/` and has no need to follow, so it no longer does: a 3xx is recorded as the target's answer.
//
// Harness: the first two legs use a recording stub for fetch (no socket); the last two drive REAL undici
// against loopback listeners this file starts. Env is restored after each leg.

import { test, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import opensearchScanner from '../plugins/opensearch_scanner.mjs';

const KEYS = ['OPENSEARCH_SCANNER_PORTS', 'OPENSEARCH_SCANNER_SCHEMES', 'OPENSEARCH_SCANNER_TIMEOUT_MS'];
const saved = Object.fromEntries(KEYS.map((k) => [k, process.env[k]]));
const realFetch = globalThis.fetch;
afterEach(() => {
  globalThis.fetch = realFetch;
  for (const k of KEYS) { if (saved[k] === undefined) delete process.env[k]; else process.env[k] = saved[k]; }
});
function scanPort(port) {
  process.env.OPENSEARCH_SCANNER_PORTS = `${port}:opensearch`;
  process.env.OPENSEARCH_SCANNER_SCHEMES = 'http';
  process.env.OPENSEARCH_SCANNER_TIMEOUT_MS = '2000';
  return opensearchScanner.run('127.0.0.1');
}
const OS_JSON = JSON.stringify({ version: { distribution: 'opensearch', number: '2.13.0' } });

test('(fourth quadrant, first) a 200 from the target is read as before — the version is parsed', async () => {
  const calls = [];
  globalThis.fetch = async (url, opts = {}) => {
    calls.push([String(url), opts.redirect]);
    return new Response(OS_JSON, { status: 200, headers: { 'content-type': 'application/json' } });
  };
  const raw = await scanPort(9200);
  assert.equal(calls.length, 1);
  assert.ok(JSON.stringify(raw).includes('2.13.0'), JSON.stringify(raw).slice(0, 400));
});

test('the request is made with redirect: "manual" — a 3xx is the target\'s answer, never followed', async () => {
  const calls = [];
  globalThis.fetch = async (url, opts = {}) => {
    calls.push([String(url), opts.redirect]);
    return new Response('', { status: 200 });
  };
  await scanPort(9200);
  assert.deepEqual(calls.map((c) => c[1]), ['manual']);
});

async function listen(handler) {
  const hits = [];
  const srv = http.createServer((q, r) => { hits.push(q.url); handler(q, r); });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  return { srv, hits, port: srv.address().port };
}

test('(fourth quadrant) real undici: a target answering 200 JSON is read', async () => {
  const A = await listen((q, r) => { r.writeHead(200, { 'content-type': 'application/json' }); r.end(OS_JSON); });
  try {
    const raw = await scanPort(A.port);
    assert.equal(A.hits.length, 1);
    assert.ok(JSON.stringify(raw).includes('2.13.0'));
  } finally { A.srv.close(); }
});

test('real undici: a target answering 302 to another host — the other host receives NOTHING', async () => {
  const B = await listen((q, r) => { r.writeHead(200, { 'content-type': 'application/json' }); r.end(OS_JSON); });
  const A = await listen((q, r) => { r.writeHead(302, { location: `http://localhost:${B.port}/` }); r.end(); });
  try {
    await scanPort(A.port);
    assert.ok(A.hits.length >= 1, 'positive control: the target was asked');
    assert.equal(B.hits.length, 0, 'the target steered the scanner to another host; it must not follow');
  } finally { A.srv.close(); B.srv.close(); }
});
