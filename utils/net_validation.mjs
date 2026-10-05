// utils/net_validation.mjs
// Shared IP/host validation utilities for SSRF prevention.
//
// 1.2.1 lane 1 A: the classifier was a set of string tests — an exact `addr === '::1'`, mapped
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

// Refused in every configuration, NSA_ALLOW_ALL_HOSTS included: loopback, unspecified,
// link-local and the cloud metadata endpoints.
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

/**
 * Canonical IP literal for `input`, or null when it is not an IP literal (a name).
 * Strips brackets and an IPv6 zone id, then accepts what net.isIP accepts; anything else is run
 * through the WHATWG URL parser, which reads the legacy IPv4 spellings an OS resolver would
 * (0x7f000001, 0177.0.0.1, 2130706433, 127.1) as the dotted quad they mean.
 * @param {string} input
 * @returns {string|null}
 */
function canonicalIp(input) {
  const s = String(input ?? '').trim().replace(/^\[|\]$/g, '').replace(/%.*$/, '');
  if (!s) return null;
  if (net.isIP(s)) return s;
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
  const addr = canonicalIp(ip);
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
 * Resolve a hostname and verify that NO resolved address is in a blocked range — a name whose
 * answers include a single blocked address is refused, because a connecting client may try every
 * answer (Node's net.connect does, with autoSelectFamily).
 * @param {string} hostname
 * @returns {Promise<string>} the first resolved address (every answer having passed)
 * @throws {Error} if any answer is in a blocked range, or DNS fails
 */
export async function resolveAndValidate(hostname) {
  const answers = await dns.lookup(hostname, { all: true, verbatim: true });
  const list = Array.isArray(answers) ? answers : [answers];
  if (list.length === 0) throw new Error(`Host did not resolve`);
  for (const { address } of list) {
    if (isBlockedIp(address)) {
      throw new Error(`Host resolves to blocked IP range`);
    }
  }
  return list[0].address;
}
