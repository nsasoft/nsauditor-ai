import test from 'node:test';
import assert from 'node:assert/strict';

import { lookupVendor, probableOsFromVendor } from '../utils/oui.mjs';

test('lookupVendor: handles different MAC formats and is resilient if OUI DB missing', async () => {
  const macColon = '28:F0:76:6E:52:82'; // Apple OUI
  const macDash  = '28-f0-76-6e-52-82';
  const macRaw   = '28f0766e5282';

  const v1 = await lookupVendor(macColon);
  const v2 = await lookupVendor(macDash);
  const v3 = await lookupVendor(macRaw);

  assert.equal(typeof v1 === 'string' || v1 === null, true);
  assert.equal(v1, v2, 'dash and colon formats should normalize to the same vendor');
  assert.equal(v2, v3, 'raw 12-hex format should normalize to the same vendor');

  if (typeof v1 === 'string') {
    assert.match(v1, /apple/i);
  }
});

test('probableOsFromVendor: maps well-known vendors to OS families', () => {
  const appleOs = probableOsFromVendor('Apple, Inc.');
  // Accept either current implementation or a future wording
  assert.ok(
    ['Apple/macOS (heuristic)', 'macOS or iOS'].includes(appleOs),
    `unexpected Apple mapping: ${appleOs}`
  );

  assert.equal(probableOsFromVendor('Microsoft Corporation'), 'Windows');
  assert.equal(probableOsFromVendor('Samsung Electronics'), 'Android');
  assert.equal(probableOsFromVendor('Google LLC'), 'Android or ChromeOS');
  assert.equal(probableOsFromVendor('Dell Inc.'), 'Windows');
  assert.equal(probableOsFromVendor('Hewlett Packard'), 'Windows');

  // Unknown or ambiguous vendors fall back to 'Unknown'
  assert.equal(probableOsFromVendor('Some Random Vendor'), 'Unknown');
});
