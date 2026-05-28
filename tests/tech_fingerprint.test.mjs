import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fingerprint } from '../utils/tech_fingerprint.mjs';

test('detects Nginx from Server header + extracts version', () => {
  const apps = fingerprint({ url: 'http://x/', html: '', statusCode: 200, headers: { server: 'nginx/1.25.3' } });
  const ng = apps.find(a => a.name === 'Nginx');
  assert.ok(ng, 'Nginx detected');
  assert.equal(ng.version, '1.25.3');
  assert.ok(Array.isArray(ng.categories) && ng.categories.includes('Web servers'));
  assert.ok(ng.confidence >= 50 && ng.confidence <= 100);
});

test('detects PHP from X-Powered-By + version', () => {
  const apps = fingerprint({ url: 'http://x/', html: '', statusCode: 200, headers: { 'x-powered-by': 'PHP/8.2.10' } });
  const php = apps.find(a => a.name === 'PHP');
  assert.ok(php && php.version === '8.2.10');
});

test('detects WordPress from meta generator + implies PHP; version extracted', () => {
  const html = '<html><head><meta name="generator" content="WordPress 6.5.2"></head><body><script src="/wp-includes/js/x.js"></script></body></html>';
  const apps = fingerprint({ url: 'http://x/', html, statusCode: 200, headers: {} });
  const wp = apps.find(a => a.name === 'WordPress');
  assert.ok(wp && wp.version === '6.5.2', 'WordPress + version');
  assert.ok(apps.find(a => a.name === 'PHP'), 'implies PHP');
});

test('detects jQuery from script src + version', () => {
  const html = '<script src="https://cdn/jquery-3.7.1.min.js"></script>';
  const apps = fingerprint({ url: 'http://x/', html, statusCode: 200, headers: {} });
  const jq = apps.find(a => a.name === 'jQuery');
  assert.ok(jq && jq.version === '3.7.1');
});

test('detects Cloudflare from cf-ray header (multi-signal raises confidence)', () => {
  const apps = fingerprint({ url: 'http://x/', html: '', statusCode: 200, headers: { server: 'cloudflare', 'cf-ray': '8abc-DFW' } });
  const cf = apps.find(a => a.name === 'Cloudflare');
  assert.ok(cf && cf.confidence >= 75, 'two surfaces → ≥75');
});

test('empty input → no detections, never throws', () => {
  assert.deepEqual(fingerprint({ url: 'http://x/', html: '', statusCode: 0, headers: {} }), []);
  assert.deepEqual(fingerprint({}), []);
});

test('dedupes a tech matched on multiple surfaces into one entry', () => {
  const html = '<meta name="generator" content="WordPress"><script src="/wp-content/themes/a.js"></script>';
  const apps = fingerprint({ url: 'http://x/', html, statusCode: 200, headers: {} });
  assert.equal(apps.filter(a => a.name === 'WordPress').length, 1);
});
