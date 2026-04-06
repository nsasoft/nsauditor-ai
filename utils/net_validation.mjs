// utils/net_validation.mjs
// Shared IP/host validation utilities for SSRF prevention.

import dns from 'node:dns/promises';

/**
 * Check whether an IP address belongs to a blocked (internal/private) range.
 * Covers loopback, RFC 1918, RFC 6598, link-local, unspecified, and IPv6 equivalents.
 * @param {string} ip
 * @returns {boolean}
 */
export function isBlockedIp(ip) {
  const addr = ip.replace(/^\[|\]$/g, '').trim();

  // IPv6-mapped IPv4 — extract the IPv4 part and check it
  const mappedMatch = addr.match(/^::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/i);
  if (mappedMatch) return isBlockedIp(mappedMatch[1]);

  // IPv6 blocked addresses
  if (addr === '::1' || addr === '::') return true;
  if (/^fe80:/i.test(addr)) return true;                     // link-local (fe80::/10)
  if (/^f[cd]/i.test(addr.slice(0, 2))) return true;        // fc00::/7 unique local (fc__ and fd__)
  // IPv4-compatible loopback: ::127.0.0.1 maps to 127.0.0.1/8
  const compatMatch = addr.match(/^::(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/i);
  if (compatMatch) return isBlockedIp(compatMatch[1]);

  // IPv4 checks
  const parts = addr.split('.');
  if (parts.length === 4 && parts.every((p) => /^\d{1,3}$/.test(p))) {
    const [a, b] = parts.map(Number);
    if (a === 127) return true;                          // 127.0.0.0/8  (loopback)
    if (a === 10) return true;                           // 10.0.0.0/8   (RFC 1918)
    if (a === 172 && b >= 16 && b <= 31) return true;    // 172.16.0.0/12 (RFC 1918)
    if (a === 192 && b === 168) return true;             // 192.168.0.0/16 (RFC 1918)
    if (a === 100 && b >= 64 && b <= 127) return true;   // 100.64.0.0/10 (RFC 6598 CGNAT)
    if (a === 169 && b === 254) return true;             // 169.254.0.0/16 (link-local)
    if (a === 0) return true;                            // 0.0.0.0/8
  }

  return false;
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
 * Resolve a hostname and verify the resolved IP is not in a blocked range.
 * @param {string} hostname
 * @returns {Promise<string>} resolved IP address
 * @throws {Error} if hostname resolves to a blocked IP or DNS fails
 */
export async function resolveAndValidate(hostname) {
  const { address } = await dns.lookup(hostname);
  if (isBlockedIp(address)) {
    throw new Error(`Host resolves to blocked IP range`);
  }
  return address;
}
