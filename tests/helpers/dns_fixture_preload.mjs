// tests/helpers/dns_fixture_preload.mjs — `node --import` this into a CHILD CLI process (G-75 (f) CLI legs).
// It points the process's default resolver at the localhost fixture named by NSA_DNS_FIXTURE (c-ares and
// dns.getServers(), which 060's raw SOA/DNSKEY/DS path reads, share it), answers the CLI's target guard (dns.lookup) with
// a documentation address so a .test name is admitted, and refuses any UDP send or TCP connect to a non-loopback address,
// so a scan under it cannot reach the network. It prints `[dns-fixture] refused <n>` on exit.
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const dns = require('node:dns');
const dgram = require('node:dgram');
const net = require('node:net');

const at = process.env.NSA_DNS_FIXTURE;
if (!at) throw new Error('dns_fixture_preload: NSA_DNS_FIXTURE is not set');
dns.setServers([at]);
const DOC = { address: '198.51.100.10', family: 4 };
dns.promises.lookup = async (name, opts = {}) => {
  const literal = net.isIP(String(name));
  const answer = literal ? { address: String(name), family: literal } : DOC;
  return opts && opts.all ? [answer] : answer;
};
let refused = 0;
const loopback = (h) => /^(127\.|::1$|localhost$)/.test(String(h));
const send = dgram.Socket.prototype.send;
dgram.Socket.prototype.send = function (msg, ...rest) {
  const address = rest.find((x) => typeof x === 'string');
  if (address && !loopback(address)) { refused += 1; throw new Error(`dns_fixture_preload: refused UDP to ${address}`); }
  return send.call(this, msg, ...rest);
};
const connect = net.createConnection;
net.createConnection = net.connect = (...a) => {
  const host = a[0] && typeof a[0] === 'object' ? a[0].host : a[1];
  if (host && !loopback(host)) { refused += 1; throw new Error(`dns_fixture_preload: refused TCP to ${host}`); }
  return connect(...a);
};
process.on('exit', () => process.stderr.write(`[dns-fixture] refused ${refused}\n`));
