import test from 'node:test';
import assert from 'node:assert/strict';

import net from 'node:net';
import { isBlockedIp, resolveAndValidate } from '../utils/net_validation.mjs';
// Through the namespace, so a missing export fails its own legs, never the whole file.
import * as nv from '../utils/net_validation.mjs';

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

test('isBlockedIp blocks fc00::/7 unique local', () => {
  assert.equal(isBlockedIp('fc00::1'), true);
  assert.equal(isBlockedIp('fd12:3456:789a::1'), true);
});

test('isBlockedIp blocks ::127.0.0.1 (IPv4-compatible loopback)', () => {
  assert.equal(isBlockedIp('::127.0.0.1'), true);
});

test('isBlockedIp allows public IPv6', () => {
  assert.equal(isBlockedIp('2001:db8::1'), false);
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

// ── 1.2.1 lane 1 A — the shared address classifier ─────────────────────────────
//
// ⚠️ A HARNESS THAT PROBES THE NETWORK IS A SCANNER. Every spelling below is classified as a
// string, and every name is answered by a STUBBED dns.lookup — no address under test ever reaches
// getaddrinfo or a socket (a 1.2.1 scout's `net.connect('0177.0.0.1')` left the machine). This
// file used to resolve `dns.google` for real; that leg is replaced by the stubbed accept leg below.

/** Answer every dns.lookup from `answers`, recording each call. The module's default import is
 *  the same object, so no production seam is needed. */
async function withLookup(answers, fn) {
  const dns = (await import('node:dns/promises')).default;
  const orig = dns.lookup;
  const calls = [];
  dns.lookup = async (name, opts) => {
    calls.push({ name, opts });
    const list = answers.map((address) => ({ address, family: net.isIP(address) }));
    return opts && opts.all ? list : list[0];
  };
  try { return await fn(calls); } finally { dns.lookup = orig; }
}

test('(fourth quadrant, first) public addresses stay unblocked in every spelling', () => {
  for (const ip of ['8.8.8.8', '1.1.1.1', '::ffff:808:808', '2001:4860:4860::8888', '2001:db8::1']) {
    assert.equal(isBlockedIp(ip), false, `${ip} is public — an over-fix that blocks every ::ffff: or every IPv6 address is refused here`);
  }
});

test('(fourth quadrant) resolveAndValidate resolves a name whose every answer is public', async () => {
  await withLookup(['93.184.216.34'], async (calls) => {
    assert.equal(await resolveAndValidate('public.example'), '93.184.216.34');
    assert.equal(calls.length, 1);
  });
});

test('loopback, unspecified and link-local are blocked in every spelling (1.2.1 A)', () => {
  for (const ip of [
    '0:0:0:0:0:0:0:1', '0::1', '::0:1', '[0:0:0:0:0:0:0:1]',           // ::1, long and short forms
    '::ffff:7f00:1', '0:0:0:0:0:ffff:7f00:1',                         // 127.0.0.1, hex-mapped
    '::ffff:a9fe:a9fe',                                              // 169.254.169.254, hex-mapped
    'febf::1', 'fe80::1%en0',                                        // all of fe80::/10; zone id
    '127.0.0.1%en0', 'fe80::1%',                                     // a zone suffix net.isIP REJECTS: stripped, classified by base
    '0x7f000001', '0177.0.0.1', '2130706433', '127.1', '0x7f.1',      // legacy IPv4 spellings
  ]) {
    assert.equal(isBlockedIp(ip), true, `${ip} must be blocked — it is loopback / link-local / metadata`);
  }
});

test('classifyAddress: "always" (refused in every arm), "private" (refused only without allow-all), null (public or a name)', () => {
  assert.equal(typeof nv.classifyAddress, 'function', 'classifyAddress is not exported');
  for (const ip of ['127.0.0.1', '::1', '::', '0.0.0.0', '169.254.169.254', 'fe80::1', '::127.0.0.1',
    'fd00:ec2::254', '100.100.100.200', '::ffff:a9fe:a9fe']) {
    assert.equal(nv.classifyAddress(ip), 'always', `${ip}`);
  }
  for (const ip of ['10.0.0.1', '172.16.0.1', '192.168.1.1', '100.64.0.1', 'fd12:3456::1', '::ffff:c0a8:101']) {
    assert.equal(nv.classifyAddress(ip), 'private', `${ip}`);
  }
  for (const v of ['8.8.8.8', '2001:4860:4860::8888', 'example.com', 'localhost', '']) {
    assert.equal(nv.classifyAddress(v), null, `${JSON.stringify(v)}: a public address or a NAME is not classified — names are resolved`);
  }
});

test('fails CLOSED: a name the resolver cannot answer, or answers with nothing, is refused — never "not blocked"', async () => {
  // classifyAddress returns null for anything that is not an IP literal: that is a ROUTE ("resolve
  // it"), not a verdict. net.BlockList itself answers false, silently, for a non-IP string — so the
  // only safe meaning of null is "go and resolve", and resolution that yields nothing must refuse.
  const dns = (await import('node:dns/promises')).default;
  const orig = dns.lookup;
  dns.lookup = async () => { const e = new Error('getaddrinfo ENOTFOUND nowhere.invalid'); e.code = 'ENOTFOUND'; throw e; };
  try { await assert.rejects(() => resolveAndValidate('nowhere.invalid')); } finally { dns.lookup = orig; }
  await withLookup([], async () => {
    await assert.rejects(() => resolveAndValidate('empty.example'), /did not resolve/);
  });
});

test('resolveAndValidate reads EVERY answer: one blocked answer refuses the name (1.2.1 A)', async () => {
  await withLookup(['93.184.216.34', '127.0.0.1'], async (calls) => {
    await assert.rejects(() => resolveAndValidate('multi.example'), /blocked/);
    assert.ok(calls[0]?.opts?.all === true, 'the lookup must ask for all answers');
  });
  await withLookup(['::ffff:a9fe:a9fe'], async () => {
    await assert.rejects(() => resolveAndValidate('mapped-metadata.example'), /blocked/);
  });
});
