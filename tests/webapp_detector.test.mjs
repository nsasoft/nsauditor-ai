// tests/webapp_detector.test.mjs
// Run with: npm test  (node --test)

import { test } from 'node:test';
import assert from 'node:assert/strict';

import webappDetector, { conclude } from '../plugins/webapp_detector.mjs';

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
