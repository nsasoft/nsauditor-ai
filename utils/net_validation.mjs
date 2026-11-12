// utils/net_validation.mjs
// Shared IP/host validation utilities for SSRF prevention.
//
// 1.3.0 lane 1 A: the classifier was a set of string tests — an exact `addr === '::1'`, mapped
// IPv4 only in dotted notation, `/^fe80:/` for fe80::/10, IPv4 only as four decimal parts — and the
// resolver read the FIRST answer only. So `0:0:0:0:0:0:0:1`, `::ffff:7f00:1` (127.0.0.1),
// `::ffff:a9fe:a9fe` (169.254.169.254), `febf::1`, `0x7f000001` and a name answering
// [public, 127.0.0.1] all passed. It now classifies on net.BlockList — which compares by address
// value, so every IPv6 spelling of one address agrees and IPv4 rules also match the IPv4-mapped
// form — after canonicalising the input, and the resolver checks EVERY answer.
//
// Stated limit: NAT64 (64:ff9b::/96) addresses that embed a blocked IPv4 are not classified.

import dns from 'node:dns/promises';
import net from 'node:net';
import { canonicalHost } from './scan_pin.mjs';

// Refused by every check that classifies — the MCP server's, a redirect hop's, the DNS audit's zone-transfer connect —
// NSA_ALLOW_ALL_HOSTS included: loopback,
// unspecified, link-local and the cloud metadata endpoints. The CLI's scan entry does not classify under
// NSA_ALLOW_ALL_HOSTS (cli.mjs assertScanTargetAllowed returns first), so there the variable lifts the whole guard.
const ALWAYS = new net.BlockList();
ALWAYS.addSubnet('127.0.0.0', 8, 'ipv4');          // loopback
ALWAYS.addSubnet('0.0.0.0', 8, 'ipv4');            // "this network" / unspecified
ALWAYS.addSubnet('169.254.0.0', 16, 'ipv4');       // link-local, incl. 169.254.169.254 (AWS/GCP/Azure metadata)
ALWAYS.addAddress('100.100.100.200', 'ipv4');      // Alibaba Cloud metadata (inside 100.64/10)
ALWAYS.addAddress('::1', 'ipv6');                  // loopback
ALWAYS.addAddress('::', 'ipv6');                   // unspecified
ALWAYS.addSubnet('::', 96, 'ipv6');                // IPv4-compatible (::a.b.c.d), deprecated — BlockList misses ::127.0.0.1 without it
ALWAYS.addSubnet('fe80::', 10, 'ipv6');            // link-local, the whole /10
ALWAYS.addAddress('fd00:ec2::254', 'ipv6');        // AWS IMDS over IPv6 (inside fc00::/7)

// Refused unless the operator allows all hosts: private and shared address space.
const PRIVATE = new net.BlockList();
PRIVATE.addSubnet('10.0.0.0', 8, 'ipv4');          // RFC 1918
PRIVATE.addSubnet('172.16.0.0', 12, 'ipv4');       // RFC 1918
PRIVATE.addSubnet('192.168.0.0', 16, 'ipv4');      // RFC 1918
PRIVATE.addSubnet('100.64.0.0', 10, 'ipv4');       // RFC 6598 CGNAT
PRIVATE.addSubnet('fc00::', 7, 'ipv6');            // unique local

// N2 (2.2.0): the one IPv6 range whose zone id names the host — an unscoped fe80::1 is not the host fe80::1%en0.
const LINK_LOCAL = new net.BlockList();
LINK_LOCAL.addSubnet('fe80::', 10, 'ipv6');

/**
 * N2 (2.2.0, the architect's verdict on Community 1264650): whether `s` is a NUMERIC host with a leading-zero part — every
 * dot-separated part decimal digits or `0x` hex, and some part a `0` followed by a digit. Its readers disagree: the WHATWG
 * URL parser (canonicalIp's) reads such a part as OCTAL, macOS getaddrinfo reads it as DECIMAL in a dotted quad, so
 * `0127.0.0.1` was classified as public 87.0.0.1 and connected to 127.0.0.1, and `010.0.0.01` reached 10.0.0.1 classified as
 * 8.0.0.1. Refused at admission, before any lookup — a single-part number too (`02130706433`): macOS agrees there today, but
 * no honest target needs the spelling and the resolvers on other systems are not measured. This reads ASCII digits only; the
 * same spelling in other digit or dot glyphs is refused by isHostnameSyntax's reads-as-an-address rule. A name with a non-numeric part
 * (`0123.cafe`) is a name.
 * @param {string} s
 */
function hasAmbiguousLeadingZero(s) {
  const parts = String(s).replace(/\.$/, '').split('.');
  return parts.every((p) => /^(?:0x[0-9a-f]*|\d+)$/i.test(p)) && parts.some((p) => /^0\d/.test(p));
}

/**
 * Canonical IP literal for `input`, or null when it is not an IP literal (a name).
 * Strips brackets and an IPv6 zone id of interface-name characters (any other `%` makes the input a name — see
 * literalOf), then accepts what net.isIP accepts; anything else is run
 * through the WHATWG URL parser — but only when it is shaped like a legacy IPv4 spelling (digits,
 * hex, x, dots) — which reads those spellings (0x7f000001, 2130706433, 127.1) as the dotted quad an OS resolver would.
 * A spelling with a leading-zero part (0177.0.0.1) is NOT admitted: readers disagree on it (N2, hasAmbiguousLeadingZero).
 * A link-local IPv6 address keeps its zone (`fe80::1%en0`); any other address is returned without one.
 * @param {string} input
 * @returns {string|null}
 */
export function canonicalIp(input) {
  return literalOf(input, false);
}

/**
 * canonicalIp's body. B216 review finding 1: canonicalIp ADMITS a literal — the entries skip the lookup and the pin for it —
 * so it strips an IPv6 zone id only from an IPv6 address, and only when the zone is interface-name characters (RFC 6874's
 * `%25` encoding included). Until 2.2.0 `%.*$` was stripped from ANY string, so '2001:db8::1%@127.0.0.1:51448/admin/reboot?x='
 * read as a public literal — admitted unpinned, with no lookup — while curl, handed the typed string in http_probe's URL, read
 * everything before `@` as userinfo and sent its GET to loopback. Any other string carrying `%` is a NAME there, which the
 * syntax check (isHostnameSyntax) refuses. classifyAddress keeps the LENIENT strip (`liberalZone`): a classifier only ever
 * refuses, and a lenient resolver may read the suffix away (macOS getaddrinfo answers '::1%@x.invalid' with ::1), so
 * '127.0.0.1%en0' stays loopback to it.
 * @param {unknown} input
 * @param {boolean} liberalZone
 */
function literalOf(input, liberalZone) {
  const typed = String(input ?? '').trim();
  let s = typed.replace(/^\[|\]$/g, '');
  let zone = '';
  if (s.includes('%')) {
    if (liberalZone) s = s.replace(/%.*$/, '');
    else {
      const zoned = /^([^%]+)%([\w.-]+)$/.exec(s);
      if (!zoned || net.isIP(zoned[1]) !== 6) return null;
      s = zoned[1];
      // N2: the zone is kept only for a link-local address, where it names the host; elsewhere it is dropped. Inside brackets
      // RFC 6874 writes the delimiter as `%25`, so `[fe80::1%25en0]` is the zone `en0`.
      if (LINK_LOCAL.check(s, 'ipv6')) zone = typed.startsWith('[') && /^25./.test(zoned[2]) ? zoned[2].slice(2) : zoned[2];
    }
  }
  if (!s) return null;
  if (net.isIP(s)) return zone ? `${s}%${zone}` : s;
  // N2: the admitting reader refuses a spelling its readers disagree on (hasAmbiguousLeadingZero); the classifying reader
  // keeps reading it, because a classifier only ever refuses.
  if (!liberalZone && hasAmbiguousLeadingZero(s)) return null;
  // Only a legacy-IPv4-SHAPED string may reach the URL parser. Fed anything else it reads
  // userinfo, a port or a path: '127.0.0.1@8.8.8.8' parses to host 8.8.8.8 and '126.0.0.0/7' to
  // host 126.0.0.0 — a public literal and a public network whose /7 spans 127/8. Those are NAMES
  // here, routed to resolution, which refuses them.
  if (!/^[0-9a-fx.]+$/i.test(s)) return null;
  try {
    const host = new URL(`http://${s}`).hostname.replace(/^\[|\]$/g, '');
    return net.isIP(host) ? host : null;
  } catch {
    return null;
  }
}

/**
 * How the SSRF guards treat an address.
 *   'always'  — refused in every configuration (loopback, unspecified, link-local, metadata)
 *   'private' — refused unless the operator allows all hosts (RFC 1918, CGNAT, unique local)
 *   null      — a public address, or not an IP literal at all (a name: resolve it, then classify
 *               every answer)
 * @param {string} ip
 * @returns {'always'|'private'|null}
 */
export function classifyAddress(ip) {
  const addr = literalOf(ip, true);   // the lenient zone strip: see literalOf
  if (!addr) return null;
  const type = net.isIP(addr) === 6 ? 'ipv6' : 'ipv4';
  if (ALWAYS.check(addr, type)) return 'always';
  if (PRIVATE.check(addr, type)) return 'private';
  return null;
}

/**
 * Check whether an IP address belongs to a blocked (internal/private) range.
 * Covers loopback, RFC 1918, RFC 6598, link-local, unspecified, metadata and their IPv6 and
 * IPv4-mapped equivalents, in any spelling.
 * @param {string} ip
 * @returns {boolean}
 */
export function isBlockedIp(ip) {
  return classifyAddress(ip) !== null;
}

/**
 * True when `ip` is a private/local-network address.
 * Plugins that operate only on local networks use this to filter targets.
 * @param {string|null|undefined} ip
 * @returns {boolean}
 */
export function isPrivateLike(ip) {
  if (!ip) return false;
  return isBlockedIp(ip);
}

/**
 * Whether the operator has lifted the private-range check (NSA_ALLOW_ALL_HOSTS). Only an explicit
 * truthy word lifts it — "0", "false", "no", "off" and "" do NOT (before 1.3.0 any non-empty value
 * did, so "=0" and "=false" silently lifted the guard). Same convention as host_up_check.mjs.
 * @param {Record<string,string|undefined>} [env]
 * @returns {boolean}
 */
export function allowAllHosts(env = process.env) {
  return /^(1|true|yes|on)$/i.test(String(env.NSA_ALLOW_ALL_HOSTS ?? '').trim());
}

/**
 * Resolve a hostname and verify that NO resolved address is in a blocked range — a name whose
 * answers include a single blocked address is refused, because a connecting client may try every
 * answer (Node's net.connect does, with autoSelectFamily).
 * @param {string} hostname
 * @param {{ allowPrivate?: boolean }} [opts] allowPrivate: admit 'private' answers (the operator's
 *   allow-all); 'always' answers — loopback, link-local, metadata — are refused regardless
 * @returns {Promise<string>} the first resolved address (every answer having passed)
 * @throws {Error} if any answer is in a blocked range, or DNS fails
 */
export async function resolveAndValidate(hostname, { allowPrivate = false } = {}) {
  return (await resolveAndValidateAll(hostname, { allowPrivate }))[0].address;
}

const HOST_SYNTAX_REFUSAL = 'Host is not a valid host name: an IP literal, or dot-separated labels of letters, digits, '
  + 'hyphens and underscores';
const READS_AS_ADDRESS_REFUSAL = (address) => `Host is written in characters that a URL parser reads as the IP address ${address}, `
  + 'which the system resolver may read differently — type the address in ASCII digits';
const AMBIGUOUS_NUMERIC_REFUSAL = 'Host is a numeric address with a leading zero in a part: some resolvers read that part as '
  + 'octal and others as decimal, so it is not one address — write it without the leading zero (for example 10.0.0.1)';
const HOST_LABEL_RE = /^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$/;

/**
 * Whether `host` is a host NAME a scan may resolve and hand to a subprocess (B216, 2.2.0): dot-separated labels of ASCII
 * letters, digits, hyphens and underscores — no label empty, longer than 63 or starting or ending with a hyphen; at most 253
 * characters; one trailing dot allowed. Read TWICE, because the lookup uses the string as typed while the pin and curl's URL
 * use canonicalHost's form (utils/scan_pin.mjs): the typed string may carry no ASCII outside that alphabet (`%` and `\` are
 * refused there — the URL parser decodes `%41` and cuts at a backslash, so the conversion would launder them), and
 * canonicalHost's form must pass the label rule. That form is the domainToASCII conversion — UTS 46 maps a fullwidth brace
 * (U+FF5B) to `{`, refused there — or the typed name lowercased when the conversion answers '' (a name ending in digits is
 * read as a failed IPv4: '6425673729' reaches the lookup, whose loopback answer refuses it; a non-ASCII name the conversion
 * refuses keeps its non-ASCII and fails the label rule).
 *
 * Underscores are admitted: internal DNS and container names carry them, the --host-file line rule (utils/host_iterator.mjs)
 * already does, and none is a curl glob character. An IP literal is NOT a host name — callers test canonicalIp first.
 * @param {unknown} host
 * @returns {boolean}
 */
export function isHostnameSyntax(host) {
  if (typeof host !== 'string') return false;
  if (host.trim() !== host) return false;   // canonicalHost trims Unicode whitespace (NBSP, U+3000, U+FEFF); the lookup does not
  if (/[\x00-\x2c\x2f\x3a-\x40\x5b-\x5e\x60\x7b-\x7f]/.test(host)) return false;   // ASCII other than [A-Za-z0-9._-]
  const name = canonicalHost(host);   // what the pin keys on and curl's URL carries; one trailing dot already dropped
  if (name.length > 253) return false;   // an empty name fails the label rule below
  // N2: octal to one reader, decimal to another — in ASCII digits.
  if (hasAmbiguousLeadingZero(host)) return false;
  // N2 review (81d299c): a NAME whose canonical form IS an IP address. Typed in other digits or dots (U+FF10, U+FF0E,
  // U+1D7CE), `0177.0.0.1` is no literal to canonicalIp, so it was resolved as a name — the system resolver answered 177.0.0.1
  // (decimal, public) — while canonicalHost and the URL parser normalise the glyphs and read 127.0.0.1 (octal), and a plugin
  // that builds a URL connected there with no lookup to pin. Refused whatever the glyphs: no honest name reads as an address.
  if (net.isIP(name)) return false;
  return name.split('.').every((label) => HOST_LABEL_RE.test(label));
}

/**
 * The WHOLE checked answer set, in resolver order — what a scan PINS (EE 2.0.0, R1b: the operator's ruling "CLI pins too").
 * Every answer passes the check, as resolveAndValidate requires. With `checkAnswers: false` (the CLI's NSA_ALLOW_ALL_HOSTS,
 * which lifts the whole guard) the answers are returned unchecked: allow-all relaxes WHICH answers are admitted, never
 * whether an answer may change between the check and the connect.
 * @param {string} hostname
 * @param {{ allowPrivate?: boolean, checkAnswers?: boolean }} [opts]
 * @returns {Promise<Array<{ address: string, family: 4|6 }>>}
 * @throws {Error} if DNS fails, nothing resolves, or (when checked) any answer is in a blocked range
 */
export async function resolveAndValidateAll(hostname, { allowPrivate = false, checkAnswers = true } = {}) {
  // B216: a host that is neither an IP literal nor a host name is refused BEFORE the lookup, whatever the answer mode — a
  // wildcard zone answers a brace name, so the lookup cannot be the refusal. Coded, so each entry names it as a syntax refusal.
  if (!canonicalIp(hostname) && !isHostnameSyntax(hostname)) {
    const typed = String(hostname ?? '').trim();
    const asAddress = canonicalHost(typed);
    const message = hasAmbiguousLeadingZero(typed) ? AMBIGUOUS_NUMERIC_REFUSAL
      : net.isIP(asAddress) ? READS_AS_ADDRESS_REFUSAL(asAddress) : HOST_SYNTAX_REFUSAL;
    throw Object.assign(new Error(message), { code: 'EHOSTSYNTAX' });
  }
  const answers = await dns.lookup(hostname, { all: true, verbatim: true });
  const list = (Array.isArray(answers) ? answers : [answers]).filter((a) => a && typeof a.address === 'string');
  if (list.length === 0) throw new Error(`Host did not resolve`);
  if (checkAnswers) {
    for (const { address } of list) {
      const cls = classifyAddress(address);
      if (cls === 'always' || (cls === 'private' && !allowPrivate)) {
        throw new Error(`Host resolves to blocked IP range`);
      }
    }
  }
  return list.map(({ address, family }) => ({ address, family: family === 6 || net.isIP(address) === 6 ? 6 : 4 }));
}
