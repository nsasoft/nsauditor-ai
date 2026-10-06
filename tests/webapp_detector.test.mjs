// tests/webapp_detector.test.mjs
// Run with: npm test  (node --test)

import { test } from 'node:test';
import assert from 'node:assert/strict';

import webappDetector, { conclude } from '../plugins/webapp_detector.mjs';
import { detectFromHtml } from '../plugins/webapp_detector.mjs';

// --- helpers ---------------------------------------------------------------

function wpHtml() {
  return `<!doctype html>
<html><head>
<meta name="generator" content="WordPress 6.5.2"/>
<link rel="stylesheet" href="/wp-includes/css/style.css">
<script src="/wp-includes/js/wp-emoji.js"></script>
</head><body>ok</body></html>`;
}

function joomlaHtml() {
  return `<!doctype html>
<html><head>
<meta name="generator" content="Joomla! - Open Source Content Management"/>
</head><body>ok</body></html>`;
}

// Minimal fetch stub returning WHATWG Response objects.
// We rely on Node's global Response (undici) being available.
function makeFetchStub(routes) {
  return async function fetchStub(url, opts) {
    // route match by prefix or exact
    const key = Object.keys(routes).find(k => url.startsWith(k));
    if (!key) throw new Error(`No route for ${url}`);
    const rule = routes[key];

    if (rule.throw) {
      throw new Error(rule.throw);
    }

    const status = rule.status ?? 200;
    const headers = rule.headers ?? {};
    const body = typeof rule.body === 'function' ? rule.body(url, opts) : (rule.body ?? '');
    return new Response(body, { status, headers });
  };
}

// Utility: find an app by name (case-insensitive) inside result.apps
function hasApp(result, name) {
  const apps = Array.isArray(result?.apps) ? result.apps : [];
  return apps.some(a => new RegExp(name, 'i').test(String(a?.name || a?.label || '')));
}

// --- tests -----------------------------------------------------------------

test('webapp_detector: falls back to HTTP and detects WordPress', { timeout: 3000 }, async (t) => {
  const origFetch = globalThis.fetch;
  try {
    // First HTTPS attempt fails, HTTP succeeds with WP-ish HTML and nginx header
    globalThis.fetch = makeFetchStub({
      'https://127.0.0.1/': { throw: 'certificate error: self signed' },
      'http://127.0.0.1/': {
        status: 200,
        headers: { 'server': 'nginx', 'content-type': 'text/html', 'x-powered-by': 'PHP/8.1.0' },
        body: wpHtml(),
      },
    });

    const res = await webappDetector.run('127.0.0.1', 0, {});
    assert.equal(res.up, true, 'result.up should be true when HTTP fallback works');

    // Must report apps and include WordPress
    assert.ok(Array.isArray(res.apps), 'result.apps should be an array');
    assert.equal(hasApp(res, 'WordPress'), true, 'apps should include WordPress');

    // Should have at least one data row marking HTTP probe
    assert.ok(Array.isArray(res.data) && res.data.length > 0, 'result.data present');
    const row = res.data.find(d => d.probe_protocol === 'http');
    assert.ok(row, 'expected an HTTP data row');
    assert.equal(row.probe_port, 80, 'HTTP port should be 80 (fallback)');
  } finally {
    globalThis.fetch = origFetch;
  }
});

test('webapp_detector: prefers HTTPS and detects Joomla', { timeout: 3000 }, async (t) => {
  const origFetch = globalThis.fetch;
  try {
    // HTTPS returns Joomla; HTTP would also work, but we shouldn't need it
    globalThis.fetch = makeFetchStub({
      'https://example.local/': {
        status: 200,
        headers: { 'server': 'Apache', 'content-type': 'text/html' },
        body: joomlaHtml(),
      },
      // Keep a fallback route in case implementation still touches HTTP (shouldn't be used)
      'http://example.local/': {
        status: 200,
        headers: { 'server': 'Apache', 'content-type': 'text/html' },
        body: joomlaHtml(),
      },
    });

    const res = await webappDetector.run('example.local', 443, {});
    assert.equal(res.up, true);

    // Should detect Joomla
    assert.equal(hasApp(res, 'Joomla'), true, 'apps should include Joomla');

    // Verify it recorded HTTPS probe
    const row = res.data.find(d => d.probe_protocol === 'https');
    assert.ok(row, 'expected an HTTPS data row');
    assert.equal(row.probe_port, 443);
  } finally {
    globalThis.fetch = origFetch;
  }
});

test('conclude() emits detected apps as service records', async () => {
  const result = {
    up: true,
    apps: [
      { name: 'WordPress', version: '6.4', categories: ['CMS'] },
      { name: 'jQuery', version: '3.6.0', categories: ['JavaScript frameworks'] },
    ],
    data: [{ probe_protocol: 'https', probe_port: 443, probe_info: 'ok', response_banner: null }],
  };
  const records = await conclude({ host: '10.0.0.1', result });
  assert.equal(records.length, 2);
  assert.equal(records[0].service, 'WordPress');
  assert.equal(records[0].version, '6.4');
  assert.equal(records[0].port, 443);
  assert.equal(records[0].protocol, 'https');
  assert.equal(records[0].authoritative, false);
});

test('conclude() returns [] when result is not up', async () => {
  const records = await conclude({ host: '10.0.0.1', result: { up: false, apps: [] } });
  assert.equal(records.length, 0);
});

test('conclude() returns [] when no apps detected', async () => {
  const records = await conclude({ host: '10.0.0.1', result: { up: true, apps: [], data: [] } });
  assert.equal(records.length, 0);
});

test('webapp_detector: both HTTPS and HTTP fail → up=false and error row recorded', { timeout: 3000 }, async (t) => {
  const origFetch = globalThis.fetch;
  try {
    globalThis.fetch = makeFetchStub({
      'https://nope.local/': { throw: 'getaddrinfo ENOTFOUND' },
      'http://nope.local/': { throw: 'getaddrinfo ENOTFOUND' },
    });

    const res = await webappDetector.run('nope.local', 0, {});
    assert.equal(res.up, false, 'result.up should be false on total failure');
    assert.ok(Array.isArray(res.apps) && res.apps.length === 0, 'apps should be empty on failure');
    assert.ok(res.data.some(d => /error/i.test(String(d?.probe_info || ''))), 'should record an error row');
  } finally {
    globalThis.fetch = origFetch;
  }
});

test('detectFromHtml uses the in-house fingerprinter (nginx + WordPress, no network)', async () => {
  const html = '<meta name="generator" content="WordPress 6.5"><script src="/wp-includes/a.js"></script>';
  const apps = await detectFromHtml('http://x/', html, 200, { server: 'nginx/1.25.0' });
  const names = apps.map(a => a.name);
  assert.ok(names.includes('Nginx'), 'Nginx detected');
  assert.ok(names.includes('WordPress'), 'WordPress detected');
});

// ── 1.3.0 lane 4, item 12: --ports reaches the detector in the form the CLI passes ─────────────────────────────────────
// The CLI keeps --ports as a STRING ('8443,9090/udp'); the detector read opts.ports only as an ARRAY, so the flag never
// reached it. A recording fetch stub: 443 and 80 fail, so the loop goes on to the added ports (it stops at the first that
// answers — the stated reach, item 12's ruling).
function recordingFetch(answering) {
  const seen = [];
  const fn = async (url) => {
    seen.push(url);
    if (url === answering) return new Response(wpHtml(), { status: 200, headers: { 'content-type': 'text/html' } });
    throw new Error('connect ECONNREFUSED');
  };
  return { fn, seen };
}
async function urlsFor(ports, answering = null) {
  const orig = globalThis.fetch;
  const rec = recordingFetch(answering);
  globalThis.fetch = rec.fn;
  try {
    const res = await webappDetector.run('203.0.113.60', 0, ports === undefined ? {} : { ports });
    return { seen: rec.seen, res };
  } finally { globalThis.fetch = orig; }
}

test('(fourth quadrant, first) no --ports: https:443 then http:80, nothing else', { timeout: 3000 }, async () => {
  assert.deepEqual((await urlsFor(undefined)).seen, ['https://203.0.113.60/', 'http://203.0.113.60/']);
});

test('the CLI STRING form reaches the detector: after 443 and 80, each added TCP port, both schemes', { timeout: 3000 }, async () => {
  const { seen, res } = await urlsFor('8443', 'https://203.0.113.60:8443/');
  assert.deepEqual(seen, ['https://203.0.113.60/', 'http://203.0.113.60/', 'https://203.0.113.60:8443/']);
  assert.equal(res.up, true, 'the added port answered');
  assert.equal(res.data.at(-1).probe_port, 8443);
});

test('a /udp port adds no URL; malformed entries are skipped (the port scanner\'s own parse)', { timeout: 3000 }, async () => {
  assert.deepEqual((await urlsFor('9090/udp,abc')).seen, ['https://203.0.113.60/', 'http://203.0.113.60/']);
});

test('the ARRAY form is ADDED to the defaults too — it used to replace them', { timeout: 3000 }, async () => {
  assert.deepEqual((await urlsFor([8443])).seen,
    ['https://203.0.113.60/', 'http://203.0.113.60/', 'https://203.0.113.60:8443/', 'http://203.0.113.60:8443/']);
});

test('the detector stops at the first URL that answers: an added port is not fetched when 443 answers (the stated reach)', { timeout: 3000 }, async () => {
  const { seen } = await urlsFor('8443', 'https://203.0.113.60/');
  assert.deepEqual(seen, ['https://203.0.113.60/']);
});
