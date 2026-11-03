// tests/nvd_client_missing_vulnerabilities.test.mjs
//
// AN NVD ANSWER WITHOUT A `vulnerabilities` LIST IS A FAILED LOOKUP, NOT "NO CVEs" — AND IS NEVER CACHED (EE board B160;
// the Community release paired with Enterprise 2.1.2, placed by the two seats under the operator's delegation of
// 2026-11-03).
//
// `queryCvesByCpe` read `(body.vulnerabilities || [])` and `validateCveId` read `body.vulnerabilities || []`, so a 200
// whose body carried no such list — a malformed answer, a proxy's page, another host's answer — was read as a CPE with no
// CVEs, or a CVE that does not exist, and CACHED that way for the cache's lifetime (measured in the B158 re-derivation:
// `[]` written, then served from the cache). A false clean that outlives the answer that caused it.
// Now an answer whose `vulnerabilities` is absent, or not a list, throws, and nothing is cached: the CPE lookup fails and a
// CVE check reads as a transient failure. Scoped to that one key — every other field is read as before.
//
// FOURTH QUADRANT FIRST: a genuine answer of zero CVEs (`vulnerabilities: []`) is still an answer, returned and cached.
import { describe, it, mock, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

const CPE = 'cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*';
let cacheDir;
const answer = (body) => mock.method(globalThis, 'fetch', async () => ({ ok: true, status: 200, headers: { get: () => null }, json: async () => body, text: async () => JSON.stringify(body) }));
async function client() {
  const { createNvdClient } = await import('../utils/nvd_client.mjs');
  return createNvdClient({ cacheDir, apiKey: 'b160-key' });
}
const cached = () => fs.readdirSync(cacheDir, { recursive: true }).filter((f) => fs.statSync(path.join(cacheDir, String(f))).isFile());

beforeEach(async () => { cacheDir = await fsp.mkdtemp(path.join(os.tmpdir(), 'nsa-b160-')); });
afterEach(async () => { mock.restoreAll(); await fsp.rm(cacheDir, { recursive: true, force: true }); });

describe('a genuine answer of zero CVEs is still an answer (written first)', () => {
  it('(first) `vulnerabilities: []` returns [] for a CPE and is cached', async () => {
    answer({ resultsPerPage: 0, startIndex: 0, totalResults: 0, vulnerabilities: [] });
    assert.deepEqual(await (await client()).queryCvesByCpe(CPE), []);
    assert.ok(cached().length >= 1, 'a genuine empty answer was not cached');
  });

  it('(first) `vulnerabilities: []` reads a CVE as not existing, and is cached', async () => {
    answer({ vulnerabilities: [] });
    assert.deepEqual(await (await client()).validateCveId('CVE-2099-0001'), { exists: false, cveId: 'CVE-2099-0001' });
    assert.ok(cached().length >= 1);
  });
});

describe('an answer with no `vulnerabilities` list is a failed lookup, and nothing is cached', () => {
  for (const [label, body] of [['the key absent', { resultsPerPage: 0, totalResults: 0 }], ['the key null', { vulnerabilities: null }],
    ['the key not a list', { vulnerabilities: { cve: {} } }], ['a JSON array', []], ['a JSON string', 'not found']]) {
    it(`${label}: the CPE lookup rejects and the cache stays empty`, async () => {
      answer(body);
      await assert.rejects((await client()).queryCvesByCpe(CPE), /NVD API answer carried no vulnerabilities list/);
      assert.deepEqual(cached(), [], 'a malformed answer was cached as "no CVEs"');
    });
    it(`${label}: a CVE check reads as transient, never as "does not exist", and is not cached`, async () => {
      answer(body);
      assert.deepEqual(await (await client()).validateCveId('CVE-2021-41773'), { exists: false, cveId: 'CVE-2021-41773', transient: true });
      assert.deepEqual(cached(), []);
    });
  }
});
