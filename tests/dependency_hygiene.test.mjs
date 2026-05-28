// tests/dependency_hygiene.test.mjs — CE dependency-hygiene drift guard (0.1.86)
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const pkg = JSON.parse(readFileSync(fileURLToPath(new URL('../package.json', import.meta.url)), 'utf8'));

test('@anthropic-ai/sdk constraint is above the GHSA-p7fg-763f-g4gf range (>0.91.0)', () => {
  const range = pkg.dependencies['@anthropic-ai/sdk'];
  const f = range.replace(/[^\d.]/g, '').split('.').map(Number); // ^0.100.0 -> [0,100,0]
  assert.ok(f[0] > 0 || f[1] >= 92, `@anthropic-ai/sdk floor ${range} must be > 0.91.0`);
});

test('CE no longer declares a direct uuid dep (uses crypto.randomUUID)', () => {
  assert.ok(!('uuid' in pkg.dependencies), 'direct uuid dropped in favor of crypto.randomUUID()');
});

test('CE no longer declares simple-wappalyzer (abandoned wappalyzer-core)', () => {
  assert.ok(!('simple-wappalyzer' in pkg.dependencies), 'simple-wappalyzer removed; in-house fingerprinter replaces it');
});
