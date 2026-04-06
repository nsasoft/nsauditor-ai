// tests/arp_scanner.test.mjs
import test from 'node:test';
import assert from 'node:assert/strict';

import arpScanner, { parseArpOutput } from '../plugins/arp_scanner.mjs';
import { lookupVendor, probableOsFromVendor } from '../utils/oui.mjs';

test('plugin metadata is present', () => {
  assert.equal(arpScanner.id, '026');
  assert.equal(typeof arpScanner.name, 'string');
  assert.ok(Array.isArray(arpScanner.protocols));
  assert.ok(Array.isArray(arpScanner.ports));
});

test('parseArpOutput parses macOS/Linux format', () => {
  const out = `
? (192.168.1.16) at 28:f0:76:6e:52:82 on en0 ifscope [ethernet]
`;
  const mac = parseArpOutput(out, '192.168.1.16');
  assert.equal(mac, '28:F0:76:6E:52:82');
});

test('parseArpOutput parses Windows format', () => {
  const out = `
Interface: 192.168.1.10 --- 0x6
  Internet Address      Physical Address      Type
  192.168.1.16         28-f0-76-6e-52-82     dynamic
`;
  const mac = parseArpOutput(out, '192.168.1.16');
  assert.equal(mac, '28:F0:76:6E:52:82');
});

test('lookupVendor returns a string or null (graceful when OUI DB not present)', async () => {
  const mac = '28:F0:76:6E:52:82'; // Apple OUI
  const vendor = await lookupVendor(mac);
  // either a real vendor string (if oui-data is available) or null
  assert.equal(typeof vendor === 'string' || vendor === null, true);
});

test('probableOsFromVendor maps well-known vendors', () => {
  assert.equal(probableOsFromVendor('Apple, Inc.'), 'macOS or iOS');
  assert.equal(probableOsFromVendor('Microsoft Corporation'), 'Windows');
  assert.equal(probableOsFromVendor('Samsung Electronics'), 'Android');
});
