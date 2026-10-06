// A PRELOAD FOR A SPAWNED CLI (`node --import <this> cli.mjs …`): every DNS query answers NXDOMAIN — what a resolver
// answers for a name that does not exist, and for an IP literal used as a name — and every socket that could leave
// the machine throws. Loopback TCP is let through (a scan of 127.0.0.1 may need it). The number of DNS queries is
// written to stderr at exit as `[dns-stub] queries <n>`, so a leg can assert that a declined target made NONE.
// A `.mjs` under tests/helpers/, never `*.test.mjs`: the suite glob does not run it.
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const dnsP = require('node:dns').promises;
const dgram = require('node:dgram');
const net = require('node:net');

let queries = 0;
const nxdomain = async (name) => {
  queries += 1;
  throw Object.assign(new Error(`queryX ENOTFOUND ${name}`), { code: 'ENOTFOUND' });
};
for (const k of ['resolve', 'resolve4', 'resolve6', 'resolveTxt', 'resolveCname', 'resolveMx', 'resolveNs', 'resolveSoa',
  'resolveCaa', 'resolveAny', 'resolveSrv', 'resolvePtr', 'resolveNaptr', 'reverse', 'lookup']) dnsP[k] = nxdomain;
const connect = net.createConnection;
const loopback = (h) => /^(127\.|::1$|localhost$)/.test(String(h));
net.createConnection = net.connect = (...a) => {
  const host = a[0] && typeof a[0] === 'object' ? a[0].host : a[1];
  if (host && !loopback(host)) throw new Error(`dns stub: refused a non-loopback TCP connection to ${host}`);
  return connect(...a);
};
dgram.createSocket = () => { throw new Error('dns stub: refused a UDP socket'); };
process.on('exit', () => process.stderr.write(`[dns-stub] queries ${queries}\n`));
