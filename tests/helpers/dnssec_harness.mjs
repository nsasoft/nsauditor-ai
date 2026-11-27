// tests/helpers/dnssec_harness.mjs
// ─────────────────────────────────────────────────────────────────────────────
// Runs plugin 060 whole, with its DNSSEC check pointed at a REAL localhost DNS server (fake_dns_server.mjs) and every
// OTHER check answered offline, so the DNSSEC legs (G-75 (b)) read the plugin's real result and conclude line while
// nothing leaves the machine.
//
// What is stubbed, and why it is not the DNSSEC query path:
//   dns.promises.getServers  → the entries the test names. 060 reads it at call time to choose where its raw DNSSEC
//                              queries go; pointing it at a localhost server is the whole point. (Without this a test
//                              that runs 060 in-process sends REAL UDP to the machine's resolver — pick-up v353 trap 2.)
//   resolve4/6, Cname, Mx, Ns, Soa, Txt, Caa  → a fully answered zone for ANY name (c-ares reads its own server list,
//                              not getServers, so these would otherwise go to the network). They feed the six other checks.
//   dns.promises.resolve     → DNSKEY and DS go to the REAL function (until Community 1.2.0 that was 060's DNSSEC path:
//                              Node refuses both types synchronously); any other type is recorded and refused. Every
//                              call is recorded, so a leg can assert the raw path never touches it.
//   dns.promises.resolveAny  → recorded and refused (ENOTIMP, what most resolvers answer). The fallback that called it is
//                              deleted by (b); a leg asserts it is never called.
// Import this module BEFORE the plugin.
// ─────────────────────────────────────────────────────────────────────────────
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const dnsP = require('node:dns').promises;

export const calls = { resolve: [], resolveAny: 0 };
let servers = [];
export function setServers(list) { servers = [...list]; }

const realResolve = dnsP.resolve;
const err = (code, what) => Object.assign(new Error(`${what} ${code}`), { code });
const KEY_2048 = 'A'.repeat(344);
const parentOf = (n) => n.split('.').slice(-2).join('.');

dnsP.getServers = () => [...servers];
dnsP.resolve4 = async (n) => {
  if (n.startsWith('nsauditor-wildcard-probe-')) throw err('ENOTFOUND', n);
  if (n.startsWith('ns1.')) return ['198.51.100.1'];
  if (n.startsWith('ns2.')) return ['203.0.113.1'];
  return ['192.0.2.10'];
};
dnsP.resolve6 = async (n) => { throw err('ENODATA', n); };
dnsP.resolveCname = async (n) => { throw err('ENODATA', n); };
dnsP.resolveMx = async (n) => [{ priority: 10, exchange: `mx1.${parentOf(n)}` }];
dnsP.resolveNs = async (n) => [`ns1.${parentOf(n)}`, `ns2.${parentOf(n)}`];
dnsP.resolveSoa = async (n) => ({ nsname: `ns1.${parentOf(n)}`, hostmaster: `hostmaster.${parentOf(n)}`, serial: 1 });
dnsP.resolveTxt = async (n) => {
  if (n.startsWith('_dmarc.')) return [[`v=DMARC1; p=reject; sp=reject; rua=mailto:d@${parentOf(n)}`]];
  if (n.includes('._domainkey.')) return [[`v=DKIM1; k=rsa; p=${KEY_2048}`]];
  return [['v=spf1 -all']];
};
dnsP.resolveCaa = async () => [{ critical: 0, issue: 'ca.example' }];
dnsP.resolveAny = async (n) => { calls.resolveAny += 1; throw err('ENOTIMP', `resolveAny ${n}`); };
dnsP.resolve = function resolve(n, t = 'A') {
  calls.resolve.push(t);
  if (t === 'DNSKEY' || t === 'DS') return realResolve(n, t);
  throw err('EUNEXPECTED', `dns.resolve(${n}, ${t}) is not answered by this harness`);
};

const { default: dnsSec } = await import('../../plugins/060_dns_sec_auditor.mjs');
export { dnsSec };
export const plugin = await import('../../plugins/060_dns_sec_auditor.mjs');

/**
 * One whole run of 060 at `host` with the DNSSEC queries going to `serverEntries`.
 * → { result, record, rows, nm, dnssec, line, ms }
 *   rows: the dnssec category's checks · nm: the dnssec not-measured entries as "RRTYPE:CODE"
 *   dnssec: result.details.dnssec · line: the conclude line's DNSSEC segment · ms: the run's wall time
 */
export async function runDnssec(host, serverEntries, { timeoutMs = 1200 } = {}) {
  setServers(serverEntries);
  const t0 = Date.now();
  const result = await dnsSec.run(host, 0, { dkimSelectors: 'google', timeoutMs });
  const ms = Date.now() - t0;
  const [record] = dnsSec.conclude({ result, host });
  const rows = (result.findings?.dnssec ?? []).map((i) => i.check);
  const nmRaw = (result.details?.notMeasured ?? []).filter((e) => e.check === 'dnssec');
  const nm = nmRaw.map((e) => `${e.rrtype}:${e.code}`);
  const line = String(record?.info ?? '').split(' | ').find((s) => /DNSSEC/.test(s)) ?? null;
  return { result, record, rows, nm, nmRaw, dnssec: result.details?.dnssec, line, ms };
}

/** The queries a server received, as "transport TYPE name" with TYPE named. */
export const TYPE_NAME = { 1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 16: 'TXT', 28: 'AAAA', 39: 'DNAME', 43: 'DS', 48: 'DNSKEY' };
export const queriesOf = (server) => server.log.map((l) => `${l.transport} ${TYPE_NAME[l.type] ?? l.type} ${l.name.toLowerCase()}`);
