// tests/nvd_client_no_redirect.test.mjs
//
// THE NVD LOOKUP GOES ONLY TO THE NVD API — A REDIRECT IS REFUSED, NEVER FOLLOWED (EE board B158's Community site; the
// Community release paired with Enterprise 2.1.2, placed by the two seats under the operator's delegation of 2026-11-03).
//
// The client's one `fetch` (utils/nvd_client.mjs) passed no `redirect` option, so it followed. Measured on Node 24.22.1
// (EE audit-evidence-samples/ee-2.2.0/b129/04): a CUSTOM header such as `apiKey` is FORWARDED to wherever a cross-origin
// redirect points — so with NVD_API_KEY set, a redirect from the API sent the key to another host, with the CPE (scan
// content) in the query string — and the redirect target's answer was returned, and CACHED, as NVD's.
// Now the request pins `redirect: 'manual'` and a 3xx is refused, naming the status and the host it pointed at (the host
// only: the message reaches Enterprise's lookup-failure gap, its AI payload and a GRC push). Nothing is cached.
//
// Every leg drives the REAL `fetch`: `globalThis.fetch` is wrapped only to move the NVD host to a local listener, and the
// client's own options — `redirect` included — reach the real `fetch` unchanged. A second listener records every request
// that reaches it: the witness that nothing was followed.
//
// FOURTH QUADRANT FIRST: an answer from the API itself is parsed, its apiKey sent there, and cached.
import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';

const NVD_ORIGIN = 'https://services.nvd.nist.gov';
const KEY = 'b158-nvd-api-key-0123456789';
const CPE = 'cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*';
const ANSWER = { resultsPerPage: 1, startIndex: 0, totalResults: 1, vulnerabilities: [{ cve: { id: 'CVE-2021-41773', published: '2021-10-05', lastModified: '2021-10-06', descriptions: [{ lang: 'en', value: 'path traversal' }], metrics: { cvssMetricV31: [{ cvssData: { baseScore: 7.5, baseSeverity: 'HIGH', vectorString: 'CVSS:3.1/AV:N' } }] } } }] };

async function listener(answer) {
  const seen = [];
  const server = http.createServer((req, res) => {
    seen.push({ method: req.method, url: req.url, apiKey: req.headers.apikey ?? null });
    const [status, headers, body] = answer(req);
    res.writeHead(status, headers);
    res.end(body);
  });
  await new Promise((done) => server.listen(0, '127.0.0.1', done));
  const origin = `http://127.0.0.1:${server.address().port}`;
  return { origin, host: new URL(origin).host, seen, close: () => new Promise((done) => server.close(done)) };
}

/** Run `fn` with the NVD host moved to `origin`; every option the client passes reaches the real fetch unchanged. */
async function againstNvdAt(origin, fn) {
  const real = globalThis.fetch;
  globalThis.fetch = (url, init) => real(String(url).replace(NVD_ORIGIN, origin), init);
  try { return await fn(); } finally { globalThis.fetch = real; }
}
async function client(cacheDir) {
  const { createNvdClient } = await import('../utils/nvd_client.mjs');
  return createNvdClient({ cacheDir, apiKey: KEY });
}

let elsewhere;
let dir;
before(async () => {
  elsewhere = await listener(() => [200, { 'content-type': 'application/json' }, JSON.stringify({ vulnerabilities: [] })]);
  dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'nsa-b158-nvd-'));
});
after(async () => { await elsewhere.close(); await fsp.rm(dir, { recursive: true, force: true }); });
const freshCache = () => fs.mkdtempSync(path.join(dir, 'cache-'));
const cached = (cacheDir) => fs.readdirSync(cacheDir, { recursive: true }).filter((f) => fs.statSync(path.join(cacheDir, String(f))).isFile());

describe('an answer from the NVD API itself is parsed, keyed and cached (written first)', () => {
  it('(first) a 200 returns its CVEs, the apiKey went to the API, and the answer is cached', async () => {
    const nvd = await listener(() => [200, { 'content-type': 'application/json' }, JSON.stringify(ANSWER)]);
    const cacheDir = freshCache();
    try {
      const r = await againstNvdAt(nvd.origin, async () => (await client(cacheDir)).queryCvesByCpe(CPE));
      assert.deepEqual(r.map((c) => [c.cveId, c.severity]), [['CVE-2021-41773', 'HIGH']]);
      assert.deepEqual(nvd.seen.map((q) => q.apiKey), [KEY]);
      assert.ok(cached(cacheDir).length >= 1, 'the answer was not cached');
    } finally { await nvd.close(); }
  });
});

describe('a redirect from the NVD API is refused: nothing reaches the host it points at, the key included, and nothing is cached', () => {
  for (const status of [301, 302, 303, 307, 308]) {
    for (const origin of ['cross-origin', 'same-origin']) {
      it(`a ${origin} ${status}: the lookup rejects naming the status and the host; the other host receives nothing; nothing cached`, async () => {
        const before = elsewhere.seen.length;
        const nvd = await listener((req) => (req.url.startsWith('/rest/')
          ? [status, { location: origin === 'cross-origin' ? `${elsewhere.origin}/rest/json/cves/2.0?x=1` : '/moved/rest/json/cves/2.0' }, '']
          : [200, { 'content-type': 'application/json' }, JSON.stringify({ vulnerabilities: [] })]));
        const cacheDir = freshCache();
        try {
          // A relative Location resolves against the URL the client asked for — the NVD API's own host — exactly as it
          // would in use; the wrapper moved that host to the listener without the client's knowledge.
          const target = origin === 'cross-origin' ? elsewhere.host : 'services.nvd.nist.gov';
          await assert.rejects(againstNvdAt(nvd.origin, async () => (await client(cacheDir)).queryCvesByCpe(CPE)), (err) => {
            assert.match(err.message, new RegExp(`^NVD API ${status} → ${target.replace(/\./g, '\\.')}: `), err.message);
            assert.match(err.message, /never followed/);
            assert.ok(!err.message.includes(KEY) && !err.message.includes('x=1'), 'a key or a query string reached the message');
            return true;
          });
          assert.equal(nvd.seen.filter((q) => q.url.startsWith('/rest/')).length, 1, 'the API was not asked exactly once');
          assert.ok(!nvd.seen.some((q) => q.url.startsWith('/moved/')), 'a same-origin redirect was followed');
          assert.equal(elsewhere.seen.length, before, `the lookup — and its apiKey — reached the host the ${status} pointed at`);
          assert.deepEqual(cached(cacheDir), [], 'a refused redirect was cached');
        } finally { await nvd.close(); }
      });
    }
  }

  // Owed on the audit seat's read of f6cef5d: the bounds of the refusal itself, not only the five common statuses.
  for (const status of [300, 399]) {
    it(`a ${status} at the bound is refused with the named refusal, and nothing is cached`, async () => {
      const nvd = await listener(() => [status, { location: `${elsewhere.origin}/x` }, '']);
      const cacheDir = freshCache();
      try {
        await assert.rejects(againstNvdAt(nvd.origin, async () => (await client(cacheDir)).queryCvesByCpe(CPE)), new RegExp(`NVD API ${status} → .*never followed`));
        assert.deepEqual(cached(cacheDir), []);
      } finally { await nvd.close(); }
    });
  }

  it('validateCveId on a redirect: transient, not cached, nothing elsewhere', async () => {
    const before = elsewhere.seen.length;
    const nvd = await listener(() => [302, { location: `${elsewhere.origin}/x` }, '']);
    const cacheDir = freshCache();
    try {
      const r = await againstNvdAt(nvd.origin, async () => (await client(cacheDir)).validateCveId('CVE-2021-41773'));
      assert.deepEqual(r, { exists: false, cveId: 'CVE-2021-41773', transient: true });
      assert.equal(elsewhere.seen.length, before);
      assert.deepEqual(cached(cacheDir), []);
    } finally { await nvd.close(); }
  });

  it('a redirect with no Location header is refused too, and says so', async () => {
    const nvd = await listener(() => [302, {}, '']);
    try {
      await assert.rejects(againstNvdAt(nvd.origin, async () => (await client(freshCache())).queryCvesByCpe(CPE)), /^Error: NVD API 302 → no Location header|NVD API 302 → no Location header/);
    } finally { await nvd.close(); }
  });

  it('the anchor token Enterprise\'s egress register checks is kept: `fetch(url, { headers`', () => {
    const src = fs.readFileSync(new URL('../utils/nvd_client.mjs', import.meta.url), 'utf8');
    assert.ok(src.includes('fetch(url, { headers'), 'EE utils/egress_register.mjs anchors the nvd-mcp-tool row on this token');
    assert.ok(/fetch\(url, \{ headers[^)]*redirect: 'manual'/.test(src), 'the pin sits in that call');
  });
});
