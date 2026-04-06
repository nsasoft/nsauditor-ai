import test from 'node:test';
import assert from 'node:assert/strict';

import { isBlockedIp, resolveAndValidate } from '../utils/net_validation.mjs';

// ---------------------------------------------------------------------------
// isBlockedIp
// ---------------------------------------------------------------------------

test('isBlockedIp — loopback addresses', () => {
  assert.equal(isBlockedIp('127.0.0.1'), true);
  assert.equal(isBlockedIp('127.255.255.255'), true);
});

test('isBlockedIp — RFC 1918 10.x', () => {
  assert.equal(isBlockedIp('10.0.0.1'), true);
});

test('isBlockedIp — RFC 1918 172.16-31.x', () => {
  assert.equal(isBlockedIp('172.16.0.1'), true);
  assert.equal(isBlockedIp('172.31.255.255'), true);
});

test('isBlockedIp — RFC 1918 192.168.x', () => {
  assert.equal(isBlockedIp('192.168.1.1'), true);
});

test('isBlockedIp — RFC 6598 CGNAT range', () => {
  assert.equal(isBlockedIp('100.64.0.0'), true);
  assert.equal(isBlockedIp('100.127.255.255'), true);
});

test('isBlockedIp — link-local', () => {
  assert.equal(isBlockedIp('169.254.1.1'), true);
});

test('isBlockedIp — unspecified 0.0.0.0', () => {
  assert.equal(isBlockedIp('0.0.0.0'), true);
});

test('isBlockedIp — IPv6 loopback ::1', () => {
  assert.equal(isBlockedIp('::1'), true);
});

test('isBlockedIp — IPv6 link-local fe80::1', () => {
  assert.equal(isBlockedIp('fe80::1'), true);
});

test('isBlockedIp — IPv6-mapped loopback ::ffff:127.0.0.1', () => {
  assert.equal(isBlockedIp('::ffff:127.0.0.1'), true);
});

test('isBlockedIp — public IPs are not blocked', () => {
  assert.equal(isBlockedIp('8.8.8.8'), false);
  assert.equal(isBlockedIp('1.1.1.1'), false);
});

test('isBlockedIp — just outside RFC 1918 172.16/12', () => {
  assert.equal(isBlockedIp('172.15.255.255'), false);
  assert.equal(isBlockedIp('172.32.0.0'), false);
});

test('isBlockedIp — just outside RFC 6598 CGNAT', () => {
  assert.equal(isBlockedIp('100.63.255.255'), false);
  assert.equal(isBlockedIp('100.128.0.0'), false);
});

test('isBlockedIp — bracket notation [::1]', () => {
  assert.equal(isBlockedIp('[::1]'), true);
});

// ---------------------------------------------------------------------------
// resolveAndValidate
// ---------------------------------------------------------------------------

test('resolveAndValidate — rejects hostname resolving to loopback', async () => {
  await assert.rejects(
    () => resolveAndValidate('localhost'),
    { message: /blocked IP range/ },
  );
});

test('resolveAndValidate — resolves a public hostname', async () => {
  // dns.google is a well-known hostname that resolves to 8.8.8.8 / 8.8.4.4
  const ip = await resolveAndValidate('dns.google');
  assert.equal(isBlockedIp(ip), false);
});
