// tests/cve_validator.test.mjs
// Run with: node --test tests/cve_validator.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { extractCveIds, annotateCveText } from '../utils/cve_validator.mjs';

// --- extractCveIds ---

test('extractCveIds — extracts CVEs from markdown text and deduplicates', () => {
  const text = 'Found CVE-2021-44228 and CVE-2023-44487. Also CVE-2021-44228 again.';
  const ids = extractCveIds(text);
  assert.deepEqual(ids, ['CVE-2021-44228', 'CVE-2023-44487']);
});

test('extractCveIds — empty/no-CVE text returns empty array', () => {
  assert.deepEqual(extractCveIds(''), []);
  assert.deepEqual(extractCveIds('No vulnerabilities found here.'), []);
  assert.deepEqual(extractCveIds(null), []);
  assert.deepEqual(extractCveIds(undefined), []);
});

// --- annotateCveText ---

test('annotateCveText — verified CVE gets VERIFIED marker', () => {
  const map = new Map([['CVE-2021-44228', { exists: true }]]);
  const result = annotateCveText('Found CVE-2021-44228', map);
  assert.ok(result.includes('{{CVE_VERIFIED:CVE-2021-44228}}'));
});

test('annotateCveText — unverified CVE gets UNVERIFIED marker', () => {
  const map = new Map([['CVE-2099-99999', { exists: false }]]);
  const result = annotateCveText('Found CVE-2099-99999', map);
  assert.ok(result.includes('{{CVE_UNVERIFIED:CVE-2099-99999}}'));
});

test('annotateCveText — unknown status (exists: null) leaves CVE unchanged', () => {
  const map = new Map([['CVE-2021-44228', { exists: null }]]);
  const result = annotateCveText('Found CVE-2021-44228', map);
  assert.ok(result.includes('CVE-2021-44228'));
  assert.ok(!result.includes('{{CVE_VERIFIED'));
  assert.ok(!result.includes('{{CVE_UNVERIFIED'));
});

// --- Report HTML integration ---

test('Report HTML — annotated text produces correct CSS classes and links', async () => {
  const { buildHtmlReport } = await import('../utils/report_html.mjs');
  const html = await buildHtmlReport({
    host: 'test',
    whenIso: new Date().toISOString(),
    model: 'test',
    md: '{{CVE_VERIFIED:CVE-2021-44228}} and {{CVE_UNVERIFIED:CVE-2099-99999}}'
  });

  // Verified CVE should have cve-verified class and NVD link
  assert.ok(html.includes('cve-verified'), 'Missing cve-verified class');
  assert.ok(html.includes('nvd.nist.gov/vuln/detail/CVE-2021-44228'), 'Verified CVE missing NVD link');

  // Unverified CVE should have cve-unverified class and NO NVD link
  assert.ok(html.includes('cve-unverified'), 'Missing cve-unverified class');
  assert.ok(html.includes('unverified'), 'Missing unverified label');
  assert.ok(!html.includes('nvd.nist.gov/vuln/detail/CVE-2099-99999'), 'Unverified CVE should NOT have NVD link');
});
