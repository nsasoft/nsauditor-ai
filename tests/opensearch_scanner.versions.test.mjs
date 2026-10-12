// tests/opensearch_scanner.versions.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';

/**
 * Hermetic test focusing on Linux/Node parser variations.
 * We simulate:
 *  - 9200: JSON with OpenSearch 2.12.0 (to keep 'open' status)
 *  - 5601: header-only UA with linux 5.10.0-custom and Node.js v18.19.1
 *  - 443 : body text containing a UA with linux 4.19.0-slim and Node.js v16.20.2
 */

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

// Stub fetch
globalThis.fetch = async function(url, _opts) {
  const s = String(url);
  if (s.includes(':9200/')) {
    return makeJsonResponse({ version: { distribution: 'opensearch', number: '2.12.0' } }, {
      server: 'opensearch'
    });
  }
  if (s.includes(':5601/')) {
    const ua = 'opensearch-js/3.5.0 (linux 5.10.0-custom; Node.js v18.19.1)';
    return makeTextResponse('OK', { 'user-agent': ua });
  }
  if (s.includes(':443/')) {
    const bodyUa = 'hello opensearch-js/3.2.1 (linux 4.19.0-slim; Node.js v16.20.2) bye';
    return makeTextResponse(bodyUa, { 'x-powered-by': 'express' });
  }
  return { status: 404, headers: new H({}), async json(){ return {}; }, async text(){ return ''; } };
};

const { default: opensearchScanner } = await import('../plugins/opensearch_scanner.mjs');
const { default: concluder }        = await import('../plugins/result_concluder.mjs');

test('OpenSearch Scanner: Linux/Node UA parsing works across headers and body', async () => {
  process.env.OPENSEARCH_SCANNER_PORTS = '9200:opensearch,5601:opensearch-dashboards,443:https';
  process.env.OPENSEARCH_SCANNER_SCHEMES = 'http'; // keep simple
  process.env.OPENSEARCH_SCANNER_TIMEOUT_MS = '1000';
  process.env.OPENSEARCH_SCANNER_DEBUG = '1';

  const raw = await opensearchScanner.run('127.0.0.1');
  assert.equal(raw.up, true);
  assert.equal(raw.program, 'OpenSearch');
  assert.equal(raw.version, '2.12.0');

  // 5601: header UA
  const row5601 = raw.data.find(r => r.probe_port === 5601);
  assert.ok(row5601);
  const pi5601 = String(row5601.probe_info || '');
  assert.match(pi5601, /Linux:\s*5\.10\.0-custom/);
  assert.match(pi5601, /Node\.js:\s*v18\.19\.1/);

  // 443: body UA
  const row443 = raw.data.find(r => r.probe_port === 443);
  assert.ok(row443);
  const pi443 = String(row443.probe_info || '');
  assert.match(pi443, /Linux:\s*4\.19\.0-slim/);
  assert.match(pi443, /Node\.js:\s*v16\.20\.2/);

  // Concluder: 9200 is open and identified; 5601 and 443 carry no explicit OpenSearch version, so the adapter says
  // 'unknown' there. FLIPPED DELIBERATELY at EE 2.0.0 / Community 1.0.0 (4(b)): this leg used to assert SERVICES on 5601
  // and 443 with that 'unknown' status — the phantom shape. They are evidence now, each with its reason.
  const conclusion = await concluder.run({ results: [{ name: 'OpenSearch Scanner', result: raw }] });
  const s9200 = conclusion.services.find(s => s.port === 9200);
  assert.ok(s9200);
  assert.equal(s9200.status, 'open');
  for (const port of [5601, 443]) {
    assert.equal(conclusion.services.find(s => s.port === port), undefined, `an unidentified ${port} is not a service`);
    assert.match(conclusion.evidence.find(e => e.port === port && e.reason)?.reason ?? '', /not identified by its adapter \(status unknown\)/);
  }
});
