import { describe, it, mock, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import fsp from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';

// --- Fixtures ---

const NVD_RESPONSE_2_CVES = {
  resultsPerPage: 2,
  startIndex: 0,
  totalResults: 2,
  vulnerabilities: [
    {
      cve: {
        id: 'CVE-2021-44228',
        descriptions: [{ lang: 'en', value: 'Apache Log4j2 allows RCE via JNDI.' }],
        published: '2021-12-10T10:15:00.000',
        lastModified: '2023-11-07T03:39:00.000',
        metrics: {
          cvssMetricV31: [{
            cvssData: {
              version: '3.1',
              vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
              baseScore: 10.0,
              baseSeverity: 'CRITICAL',
            },
          }],
        },
      },
    },
    {
      cve: {
        id: 'CVE-2021-45046',
        descriptions: [{ lang: 'en', value: 'Log4j2 Thread Context bypass.' }],
        published: '2021-12-14T19:15:00.000',
        lastModified: '2023-11-07T03:39:00.000',
        metrics: {
          cvssMetricV30: [{
            cvssData: {
              version: '3.0',
              vectorString: 'CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H',
              baseScore: 9.0,
              baseSeverity: 'CRITICAL',
            },
          }],
        },
      },
    },
  ],
};

const NVD_RESPONSE_SINGLE = {
  resultsPerPage: 1,
  startIndex: 0,
  totalResults: 1,
  vulnerabilities: [NVD_RESPONSE_2_CVES.vulnerabilities[0]],
};

const NVD_RESPONSE_EMPTY = {
  resultsPerPage: 0,
  startIndex: 0,
  totalResults: 0,
  vulnerabilities: [],
};

// --- Helpers ---

let tmpDir;

async function makeTmpDir() {
  tmpDir = await fsp.mkdtemp(path.join(os.tmpdir(), 'nvd-test-'));
  return tmpDir;
}

async function cleanTmpDir() {
  if (tmpDir) await fsp.rm(tmpDir, { recursive: true, force: true });
}

// Fresh import with isolated cache dir. We need dynamic import to avoid
// module-level caching of the global `fetch` reference.
async function freshClient(opts = {}) {
  const { createNvdClient } = await import('../utils/nvd_client.mjs');
  return createNvdClient({ cacheDir: tmpDir, ...opts });
}

// --- Tests ---

describe('NVD Client', () => {
  let fetchMock;

  beforeEach(async () => {
    await makeTmpDir();
    fetchMock = mock.fn(() =>
      Promise.resolve({
        ok: true,
        json: () => Promise.resolve(NVD_RESPONSE_2_CVES),
        text: () => Promise.resolve(''),
      }),
    );
    mock.method(globalThis, 'fetch', fetchMock);
  });

  afterEach(async () => {
    mock.restoreAll();
    await cleanTmpDir();
  });

  // 1. queryCvesByCpe — parsed output shape
  it('queryCvesByCpe parses NVD response with 2 CVEs', async () => {
    const client = await freshClient();
    const results = await client.queryCvesByCpe('cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*');

    assert.equal(results.length, 2);

    // First CVE — CVSS v3.1
    assert.equal(results[0].cveId, 'CVE-2021-44228');
    assert.equal(results[0].cvssScore, 10.0);
    assert.equal(results[0].severity, 'CRITICAL');
    assert.ok(results[0].vectorString.startsWith('CVSS:3.1'));
    assert.equal(results[0].description, 'Apache Log4j2 allows RCE via JNDI.');
    assert.equal(results[0].published, '2021-12-10T10:15:00.000');

    // Second CVE — CVSS v3.0 fallback
    assert.equal(results[1].cveId, 'CVE-2021-45046');
    assert.equal(results[1].cvssScore, 9.0);
    assert.ok(results[1].vectorString.startsWith('CVSS:3.0'));
  });

  // 2. queryCvesByCpe — cache hit
  it('queryCvesByCpe returns cached data without fetching again', async () => {
    const client = await freshClient();
    const cpe = 'cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*';

    await client.queryCvesByCpe(cpe);
    assert.equal(fetchMock.mock.callCount(), 1);

    const results = await client.queryCvesByCpe(cpe);
    assert.equal(fetchMock.mock.callCount(), 1); // no additional fetch
    assert.equal(results.length, 2);
  });

  // 3. validateCveId — existing CVE
  it('validateCveId returns exists:true for known CVE', async () => {
    fetchMock.mock.mockImplementation(() =>
      Promise.resolve({
        ok: true,
        json: () => Promise.resolve(NVD_RESPONSE_SINGLE),
        text: () => Promise.resolve(''),
      }),
    );

    const client = await freshClient();
    const result = await client.validateCveId('CVE-2021-44228');

    assert.equal(result.exists, true);
    assert.equal(result.cveId, 'CVE-2021-44228');
    assert.equal(result.cvssScore, 10.0);
    assert.equal(result.severity, 'CRITICAL');
    assert.ok(result.description.includes('Log4j2'));
  });

  // 4. validateCveId — non-existent CVE (empty response)
  it('validateCveId returns exists:false for unknown CVE', async () => {
    fetchMock.mock.mockImplementation(() =>
      Promise.resolve({
        ok: true,
        json: () => Promise.resolve(NVD_RESPONSE_EMPTY),
        text: () => Promise.resolve(''),
      }),
    );

    const client = await freshClient();
    const result = await client.validateCveId('CVE-9999-99999');

    assert.equal(result.exists, false);
    assert.equal(result.cveId, 'CVE-9999-99999');
  });

  // 5. API key header is set when provided
  it('sets apiKey header when key is provided', async () => {
    const client = await freshClient({ apiKey: 'test-key-123' });
    await client.queryCvesByCpe('cpe:2.3:a:test:test:1.0:*:*:*:*:*:*:*');

    assert.equal(fetchMock.mock.callCount(), 1);
    const callArgs = fetchMock.mock.calls[0].arguments;
    assert.equal(callArgs[1].headers.apiKey, 'test-key-123');
  });
});

describe('RateLimiter', () => {
  // 6. Rate limiter delays when limit is exceeded
  it('delays requests that exceed the rate limit', async () => {
    const { RateLimiter } = await import('../utils/nvd_client.mjs');
    const limiter = new RateLimiter(2, 200); // 2 requests per 200ms

    const start = Date.now();
    await limiter.wait(); // 1st — instant
    await limiter.wait(); // 2nd — instant
    await limiter.wait(); // 3rd — must wait
    const elapsed = Date.now() - start;

    // Should have waited roughly 200ms for the window to slide
    assert.ok(elapsed >= 150, `Expected >= 150ms delay, got ${elapsed}ms`);
  });
});
