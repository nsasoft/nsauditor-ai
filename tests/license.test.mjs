import { test } from 'node:test';
import assert from 'node:assert/strict';
import { getTierFromEnv, loadLicense } from '../utils/license.mjs';

test('getTierFromEnv returns ce when no key set', () => {
  delete process.env.NSAUDITOR_LICENSE_KEY;
  assert.equal(getTierFromEnv(), 'ce');
});

test('getTierFromEnv parses pro prefix', () => {
  process.env.NSAUDITOR_LICENSE_KEY = 'pro_test123';
  assert.equal(getTierFromEnv(), 'pro');
  delete process.env.NSAUDITOR_LICENSE_KEY;
});

test('getTierFromEnv parses enterprise prefix', () => {
  process.env.NSAUDITOR_LICENSE_KEY = 'enterprise_test123';
  assert.equal(getTierFromEnv(), 'enterprise');
  delete process.env.NSAUDITOR_LICENSE_KEY;
});

test('getTierFromEnv returns ce for unrecognized prefix', () => {
  process.env.NSAUDITOR_LICENSE_KEY = 'invalid_key';
  assert.equal(getTierFromEnv(), 'ce');
  delete process.env.NSAUDITOR_LICENSE_KEY;
});

test('loadLicense returns ce tier when no key', async () => {
  const result = await loadLicense(undefined);
  assert.equal(result.tier, 'ce');
  assert.equal(result.valid, false);
});
