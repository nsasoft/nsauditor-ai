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

// ── 1.3.0 lane 1 A — the shared address classifier ─────────────────────────────
//
// ⚠️ A HARNESS THAT PROBES THE NETWORK IS A SCANNER. Every spelling below is classified as a
// string, and every name is answered by a STUBBED dns.lookup — no address under test ever reaches
// getaddrinfo or a socket (a 1.3.0 scout's `net.connect('0177.0.0.1')` left the machine). This
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

test('loopback, unspecified and link-local are blocked in every spelling (1.3.0 A)', () => {
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

test('a URL-shaped string is never canonicalised into a literal — userinfo, a port, a path or a CIDR suffix routes to resolution', () => {
  // The WHATWG parser reads '127.0.0.1@8.8.8.8' as userinfo + host 8.8.8.8 and '126.0.0.0/7' as host
  // 126.0.0.0 + path — so a classifier that fed it ANY string would call the first a public literal
  // and the second a public address whose /7 spans 127/8. Only a legacy-IPv4-shaped string (digits,
  // hex, x, dots) may reach the URL parser; everything else is a name and must be resolved.
  for (const v of ['127.0.0.1@8.8.8.8', '8.8.8.8@127.0.0.1', '192.168.1.0/24', '126.0.0.0/7',
    '8.8.8.8:80', '8.8.8.8#x', '8.8.8.8?a']) {
    assert.equal(nv.canonicalIp(v), null, `${v} must not canonicalise to a literal`);
    assert.equal(nv.classifyAddress(v), null, `${v} is a route to resolution, not a verdict`);
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

test('resolveAndValidate reads EVERY answer: one blocked answer refuses the name (1.3.0 A)', async () => {
  await withLookup(['93.184.216.34', '127.0.0.1'], async (calls) => {
    await assert.rejects(() => resolveAndValidate('multi.example'), /blocked/);
    assert.ok(calls[0]?.opts?.all === true, 'the lookup must ask for all answers');
  });
  await withLookup(['::ffff:a9fe:a9fe'], async () => {
    await assert.rejects(() => resolveAndValidate('mapped-metadata.example'), /blocked/);
  });
});

// ---------------------------------------------------------------------------
// B216 (M1 of the architect's verdict on EE cc422af): a scan host reaches curl's URL in http_probe, and curl expands `{}` and
// `[]` there into names it resolves itself, outside the --resolve pin. The resolver every entry shares (the CLI's
// assertScanTargetAllowed and MCP's validateHostPinned both call resolveAndValidateAll for a name) now refuses a host that is
// neither an IP literal nor dot-separated labels of letters, digits, hyphens and underscores — BEFORE the first lookup,
// because a wildcard zone answers a brace name (dns.lookup('nas{a,b}.invalid') is ENOTFOUND, a resolution failure, not a
// syntax refusal). The check reads the typed string AND its domainToASCII form: the pin and curl's URL use the ASCII form
// (utils/scan_pin.mjs keyOf), and UTS 46 maps a fullwidth brace (U+FF5B) to `{`.
// FOURTH QUADRANT FIRST: the names a scan must keep accepting.
// ---------------------------------------------------------------------------

const HOST_OK = ['example.com', 'EXAMPLE.Com', 'example.com.', 'router', 'my_host.lan', 'a-b.example', 'xn--bcher-kva.example',
  'bücher.example', `${'a'.repeat(63)}.example`, '0.pool.ntp.org', '127.example.test',
  // Digits are LDH: a name ending in digits reaches the lookup (domainToASCII answers '' for it, reading a failed IPv4), where
  // the OS reads '6425673729' as 127.0.0.1 and the answer check refuses it (cli_ssrf, mcp_server).
  '6425673729', 'host.123'];
const HOST_BAD = {
  'a brace list (curl expands it)': 'nas{a,b}.invalid',
  'a bracket range (curl expands it)': 'nas[1-2].invalid',
  'a fullwidth brace list (UTS 46 maps it to braces)': 'x｛a,b｝.com',
  'a comma': 'a,b.com',
  'an asterisk': '*.example',
  'a space': 'a b.example',
  'a percent escape (the URL parser decodes it)': 'x%41.com',
  'a backslash (the URL parser cuts at it)': 'a\\b.example',
  // Each of these two converts to a valid ASCII name (xn--ba-xka.example; xn--b-eha, cut at the backslash), so only the
  // typed-string rule refuses them — the lookup would receive a string that is not the name the pin and curl are given.
  'a percent escape beside non-ASCII (the conversion launders it)': 'b\u00fc%41.example',
  'a backslash beside non-ASCII (the conversion cuts at it)': 'b\u00fc\\x.example',
  'a slash': 'a/b.example',
  'a port': 'example.com:80',
  'userinfo': 'user@example.com',
  'a leading hyphen': '-a.example',
  'a trailing hyphen': 'a-.example',
  'an empty label': 'a..example',
  'a lone dot': '.',
  'empty': '',
  'a 64-character label': `${'a'.repeat(64)}.example`,
  'a 254-character name': `${'a.'.repeat(126)}ab`,
  'an unassigned code point (domainToASCII answers empty)': 'a\u0378b.example',
  'a private-use code point (domainToASCII answers empty)': 'a\uE000b.example',
};

test('(B216, fourth quadrant, first) isHostnameSyntax accepts LDH names, underscores, a trailing dot, single labels and IDN', () => {
  assert.equal(typeof nv.isHostnameSyntax, 'function', 'net_validation must export isHostnameSyntax');
  for (const h of HOST_OK) assert.equal(nv.isHostnameSyntax(h), true, `${JSON.stringify(h)} must be accepted`);
});

test('(B216) isHostnameSyntax refuses every shape curl or the URL parser would read as something other than one name', () => {
  assert.equal(typeof nv.isHostnameSyntax, 'function', 'net_validation must export isHostnameSyntax');
  for (const [why, h] of Object.entries(HOST_BAD)) assert.equal(nv.isHostnameSyntax(h), false, `${why}: ${JSON.stringify(h)} must be refused`);
  for (const v of [null, undefined, 42, {}]) assert.equal(nv.isHostnameSyntax(v), false, `a non-string ${String(v)} must be refused`);
});

test('(B216, fourth quadrant, first) resolveAndValidateAll still resolves an LDH name, an underscore name and an IP literal', async () => {
  await withLookup(['93.184.216.34'], async (calls) => {
    for (const h of ['public.example', 'my_host.example', 'bücher.example']) {
      assert.deepEqual(await nv.resolveAndValidateAll(h), [{ address: '93.184.216.34', family: 4 }], h);
    }
    // An IP literal is not a host NAME, and it is not refused for that: the lookup answers it as itself.
    assert.deepEqual(await nv.resolveAndValidateAll('2001:db8::1'), [{ address: '93.184.216.34', family: 4 }]);
    assert.equal(calls.length, 4, 'every accepted host reached the lookup once');
  });
});

test('(B216) resolveAndValidateAll refuses a malformed host BEFORE the first lookup — EHOSTSYNTAX, in both answer modes and through resolveAndValidate', async () => {
  await withLookup(['93.184.216.34'], async (calls) => {
    for (const h of ['nas{a,b}.invalid', 'nas[1-2].invalid', 'x｛a,b｝.com', 'x%41.com']) {
      for (const run of [() => nv.resolveAndValidateAll(h), () => nv.resolveAndValidateAll(h, { checkAnswers: false }),
        () => nv.resolveAndValidateAll(h, { allowPrivate: true }), () => resolveAndValidate(h)]) {
        const err = await run().then(() => null, (e) => e);
        assert.equal(err?.code, 'EHOSTSYNTAX', `${JSON.stringify(h)}: ${err?.message}`);
        assert.doesNotMatch(err.message, /blocked|did not resolve/, 'a syntax refusal must not read as a range refusal or a resolution failure');
      }
    }
    assert.deepEqual(calls, [], 'a malformed host reached the lookup');
  });
});
