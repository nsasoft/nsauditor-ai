// utils/host_iterator.mjs
// Expand host specifications: single IP, CIDR notation, or host file paths.

import fsp from 'node:fs/promises';
import path from 'node:path';

/**
 * Parse a dotted-quad IPv4 string into a 32-bit unsigned integer.
 * Throws on invalid format.
 */
function ipToUint32(ip) {
  const parts = ip.split('.');
  if (parts.length !== 4) throw new Error(`Invalid IPv4 address: ${ip}`);
  let num = 0;
  for (let i = 0; i < 4; i++) {
    const octet = Number(parts[i]);
    if (!Number.isInteger(octet) || octet < 0 || octet > 255) {
      throw new Error(`Invalid IPv4 address: ${ip}`);
    }
    num = (num * 256) + octet;
  }
  return num >>> 0; // ensure unsigned
}

/**
 * Convert a 32-bit unsigned integer back to dotted-quad string.
 */
function uint32ToIp(num) {
  return [
    (num >>> 24) & 0xFF,
    (num >>> 16) & 0xFF,
    (num >>> 8) & 0xFF,
    num & 0xFF
  ].join('.');
}

/**
 * Expand a CIDR notation string to an array of host IPs.
 * Example: '192.168.1.0/30' → ['192.168.1.1', '192.168.1.2']
 * Excludes network address and broadcast address for /31 and larger.
 * For /32 returns the single IP. For /31 returns both IPs (point-to-point).
 */
export function expandCidr(cidr) {
  const parts = cidr.split('/');
  if (parts.length !== 2) throw new Error(`Invalid CIDR notation: ${cidr}`);

  const ip = parts[0];
  const prefix = Number(parts[1]);

  if (!Number.isInteger(prefix) || prefix < 0 || prefix > 32) {
    throw new Error(`Invalid prefix length: ${parts[1]} (must be 0-32)`);
  }
  if (prefix < 16) {
    throw new Error(`Prefix /${prefix} too large (max 65534 hosts). Minimum prefix is /16.`);
  }

  const ipNum = ipToUint32(ip); // validates IP format

  if (prefix === 32) {
    return [ip];
  }

  if (prefix === 31) {
    // RFC 3021 point-to-point: return both IPs
    const mask = (0xFFFFFFFF << (32 - prefix)) >>> 0;
    const network = (ipNum & mask) >>> 0;
    return [uint32ToIp(network), uint32ToIp((network + 1) >>> 0)];
  }

  // Standard subnets: exclude network and broadcast
  const mask = (0xFFFFFFFF << (32 - prefix)) >>> 0;
  const network = (ipNum & mask) >>> 0;
  const broadcast = (network | (~mask >>> 0)) >>> 0;
  const hosts = [];
  for (let addr = network + 1; addr < broadcast; addr++) {
    hosts.push(uint32ToIp(addr >>> 0));
  }
  return hosts;
}

/**
 * Read a host file (one host per line, # comments, blank lines ignored).
 */
const HOST_LINE_RE = /^[\w.:\/\-]+$/;

export async function parseHostFile(filePath) {
  const content = await fsp.readFile(filePath, 'utf8');
  return content
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith('#'))
    .filter((line) => {
      if (!HOST_LINE_RE.test(line)) {
        console.warn(`[host-file] Ignoring suspicious line: ${line.slice(0, 50)}`);
        return false;
      }
      return true;
    });
}

/**
 * Expand a dash-range notation to an array of IPs.
 * Example: '192.168.1.1-50' → ['192.168.1.1', '192.168.1.2', ..., '192.168.1.50']
 * Also supports full IP ranges: '192.168.1.1-192.168.1.50'
 */
export function expandRange(range) {
  // Full range: 192.168.1.1-192.168.1.50
  const fullMatch = range.match(/^(\d{1,3}(?:\.\d{1,3}){3})-(\d{1,3}(?:\.\d{1,3}){3})$/);
  if (fullMatch) {
    const startNum = ipToUint32(fullMatch[1]);
    const endNum = ipToUint32(fullMatch[2]);
    if (endNum < startNum) throw new Error(`Invalid range: end < start in ${range}`);
    const count = endNum - startNum + 1;
    if (count > 65534) throw new Error(`Range too large: ${count} hosts (max 65534)`);
    const hosts = [];
    for (let i = startNum; i <= endNum; i++) hosts.push(uint32ToIp(i >>> 0));
    return hosts;
  }

  // Short range: 192.168.1.1-50 (last octet range)
  const shortMatch = range.match(/^(\d{1,3}\.\d{1,3}\.\d{1,3})\.(\d{1,3})-(\d{1,3})$/);
  if (shortMatch) {
    const prefix = shortMatch[1];
    const start = Number(shortMatch[2]);
    const end = Number(shortMatch[3]);
    if (start > 255 || end > 255) throw new Error(`Invalid octet in range: ${range}`);
    if (end < start) throw new Error(`Invalid range: end < start in ${range}`);
    const hosts = [];
    for (let i = start; i <= end; i++) hosts.push(`${prefix}.${i}`);
    return hosts;
  }

  throw new Error(`Invalid range notation: ${range}`);
}

/**
 * Detect input type and return array of hosts.
 * - If contains '/' → CIDR
 * - If contains '-' with IP pattern → dash range
 * - If file exists → host file
 * - Otherwise → single IP/hostname
 */
export async function parseHostArg(arg) {
  // Match CIDR notation: digits.digits.digits.digits/digits
  if (/^\d{1,3}(\.\d{1,3}){3}\/\d{1,2}$/.test(arg)) {
    return expandCidr(arg);
  }

  // Match dash-range notation: 192.168.1.1-50 or 192.168.1.1-192.168.1.50
  if (/^\d{1,3}(\.\d{1,3}){3}-\d/.test(arg)) {
    return expandRange(arg);
  }

  // Path traversal guard: reject absolute paths and paths resolving outside cwd
  if (path.isAbsolute(arg)) return [arg]; // treat as hostname, not file
  const resolved = path.resolve(arg);
  if (!resolved.startsWith(process.cwd() + path.sep)) return [arg]; // outside CWD = hostname

  try {
    await fsp.access(arg);
    return parseHostFile(arg);
  } catch {
    // Not a file — treat as single host
    return [arg];
  }
}
