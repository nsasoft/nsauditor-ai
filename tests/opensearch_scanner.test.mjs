// tests/opensearch_scanner.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';

/**
 * Hermetic test: stub global fetch so no network is used.
 * We simulate:
 *  - 9200: JSON body with {"version":{"number":"2.13.0"}} (OpenSearch core)
 *  - 5601: No JSON, but a header with an opensearch-js UA exposing Linux + Node.js
 */

// Minimal Headers-like helper for iteration
class H {
  constructor(obj) { this._o = obj || {}; }
  *[Symbol.iterator]() {
    for (const [k, v] of Object.entries(this._o)) yield [k, v];
  }
}

function makeJsonResponse(obj, extraHeaders = {}) {
  const headers = new H({ 'content-type': 'application/json', ...extraHeaders });
  return {
    status: 200,
    headers,
    async json() { return obj; },
    async text() { return JSON.stringify(obj); }
  };
}

function makeTextResponse(text, extraHeaders = {}) {
  const headers = new H({ 'content-type': 'text/plain', ...extraHeaders });
  return {
    status: 200,
    headers,
    async json() { throw new Error('not json'); },
    async text() { return text; }
  };
}

// Stub global fetch before importing the plugin
globalThis.fetch = async function(url, opts) {
  if (String(url).includes(':9200/')) {
    // Root API: return version JSON
    return makeJsonResponse({ version: { distribution: 'opensearch', number: '2.13.0' } }, {
      server: 'opensearch'
    });
  }
  if (String(url).includes(':5601/')) {
    // Dashboards: provide banner-like header with UA
    const ua = 'opensearch-js/3.4.0 (linux 6.19.14-linuxkit-x64; Node.js v20.10.0)';
    return makeTextResponse('OK', { 'user-agent': ua });
  }
  // Any other port -> 404ish
  return { status: 404, headers: new H({}), async json(){ return {}; }, async text(){ return ''; } };
};

// Import AFTER stubbing fetch so plugin's getFetch() picks it up
const { default: opensearchScanner } = await import('../plugins/opensearch_scanner.mjs');
const { default: concluder }        = await import('../plugins/result_concluder.mjs');

test('OpenSearch Scanner: parses version + OS/Node banner and integrates with concluder', async () => {
  // Restrict ports to the two we simulate
  process.env.OPENSEARCH_SCANNER_PORTS = '9200:opensearch,5601:opensearch-dashboards';
  process.env.OPENSEARCH_SCANNER_SCHEMES = 'http'; // keep it simple
  process.env.OPENSEARCH_SCANNER_TIMEOUT_MS = '1000';
  process.env.OPENSEARCH_SCANNER_DEBUG = '1';

  const raw = await opensearchScanner.run('127.0.0.1');
  assert.equal(raw.up, true);
  assert.equal(raw.program, 'OpenSearch');
  assert.equal(raw.version, '2.13.0');
  assert.ok(Array.isArray(raw.data));
  assert.equal(raw.data.length, 2);

  // Find rows by port
  const row9200 = raw.data.find(r => r.probe_port === 9200);
  const row5601 = raw.data.find(r => r.probe_port === 5601);
  assert.ok(row9200 && row5601);

  // 9200 should include OpenSearch version in probe_info
  assert.match(String(row9200.probe_info || ''), /OpenSearch:\s*2\.13\.0/);

  // 5601 should extract Linux + Node.js from header banner
  const pi5601 = String(row5601.probe_info || '');
  assert.match(pi5601, /Linux:\s*6\.19\.14-linuxkit-x64/);
  assert.match(pi5601, /Node\.js:\s*v20\.10\.0/);

  // Concluder integration
  const conclusion = await concluder.run({ results: [{ name: 'OpenSearch Scanner', result: raw }] });
  // Expect authoritative records for both 9200 and 5601
  const s9200 = conclusion.services.find(s => s.port === 9200);
  const s5601 = conclusion.services.find(s => s.port === 5601);
  assert.ok(s9200 && s5601);
  assert.equal(s9200.service, 'opensearch');
  assert.equal(s5601.service, 'opensearch-dashboards');
  assert.equal(s9200.status, 'open'); // version present triggers 'open'
});
