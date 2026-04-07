// tests/keychain.test.mjs
import test from 'node:test';
import assert from 'node:assert/strict';
import { platform } from 'node:os';
import { resolveSecret, keychainGet } from '../utils/keychain.mjs';

const isMac = platform() === 'darwin';

test('resolveSecret: returns null for empty/undefined', async () => {
  assert.equal(await resolveSecret(undefined), null);
  assert.equal(await resolveSecret(null), null);
  assert.equal(await resolveSecret(''), null);
  assert.equal(await resolveSecret('  '), null);
});

test('resolveSecret: returns plain value as-is', async () => {
  assert.equal(await resolveSecret('sk-abc123'), 'sk-abc123');
  assert.equal(await resolveSecret('  sk-abc123  '), 'sk-abc123');
});

test('resolveSecret: keychain: prefix with empty label returns null', async () => {
  assert.equal(await resolveSecret('keychain:'), null);
  assert.equal(await resolveSecret('keychain:  '), null);
});

test('resolveSecret: keychain: prefix for missing entry returns null', async () => {
  if (!isMac) return; // skip on non-macOS
  const result = await resolveSecret('keychain:nsauditor-test-nonexistent-key');
  assert.equal(result, null);
});

test('keychainGet: returns null for non-existent entry', async () => {
  if (!isMac) return;
  const result = await keychainGet('nsauditor-test-nonexistent-key-12345');
  assert.equal(result, null);
});

test('keychainGet: returns null on non-macOS', async () => {
  if (isMac) return; // only test on non-mac
  const result = await keychainGet('anything');
  assert.equal(result, null);
});
