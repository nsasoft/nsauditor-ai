// tests/dns_posture_nameserver_address.test.mjs
// ─────────────────────────────────────────────────────────────────────────────
// A NAMESERVER THAT RESOLVES TO A NON-PUBLIC ADDRESS IS `ns_private_ip`, BY THE SHARED CLASSIFIER — EVERY SPELLING.
//
// Plugin 060 graded `ns_private_ip` with a hand-kept prefix list: 10/8, 172.16/12, 192.168/16, 169.254/16 and the single
// address 127.0.0.1. So a nameserver at 127.0.0.2 (loopback) or 100.64.0.1 (CGNAT, RFC 6598) read as public, and a
// nameserver reachable over IPv6 only was never classified at all. The check now asks `isBlockedIp`, the classifier every
// connect guard uses (loopback, RFC 1918, CGNAT, link-local, unspecified, metadata, unique local — IPv4 and IPv6, in any
// spelling), over every address the nameserver resolved to. The finding's wording is unchanged.
//
// DRIVEN, OFFLINE: DNS answers from a per-test table.
//
// FOURTH QUADRANT FIRST: a public nameserver — the documentation ranges included, which the classifier leaves public —
// is not graded, or the widening could pass by grading everything.
// ─────────────────────────────────────────────────────────────────────────────
import './helpers/no_operator_home.mjs';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const dnsP = require('node:dns').promises;

const ZONE = 'example.test';
let TABLE = {};
const answer = (type, name) => {
  const key = name.startsWith('nsauditor-wildcard-probe-') ? `A *.${ZONE}` : `${type} ${name}`;
  const v = key in TABLE ? TABLE[key] : 'ENODATA';
  if (typeof v === 'string') throw Object.assign(new Error(`query ${v} ${key}`), { code: v });
  return v;
};
for (const [k, t] of Object.entries({ resolve4: 'A', resolve6: 'AAAA', resolveCname: 'CNAME', resolveMx: 'MX', resolveNs: 'NS',
  resolveSoa: 'SOA', resolveTxt: 'TXT', resolveCaa: 'CAA', resolveAny: 'ANY' })) dnsP[k] = async (n) => answer(t, n);
dnsP.resolve = async (n, t = 'A') => answer(t, n);

const { default: dnsSec } = await import('../plugins/060_dns_sec_auditor.mjs');

const NS1 = `ns1.${ZONE}`;
/** The ns_private_ip findings for one nameserver answering these A / AAAA records. */
async function privateIps({ a, aaaa }) {
  TABLE = { [`NS ${ZONE}`]: [NS1], ...(a ? { [`A ${NS1}`]: a } : {}), ...(aaaa ? { [`AAAA ${NS1}`]: aaaa } : {}) };
  const result = await dnsSec.run(ZONE, 0, {});
  return result.findings.ns.filter((i) => i.check === 'ns_private_ip');
}

// ── FOURTH QUADRANT FIRST ─────────────────────────────────────────────────────────────────────────────────────────────
test('(first) public nameservers are not graded — the documentation ranges included, IPv4 and IPv6', async () => {
  for (const a of [['8.8.8.8'], ['192.0.2.53'], ['198.51.100.1'], ['203.0.113.7']]) assert.deepEqual(await privateIps({ a }), [], a[0]);
  for (const aaaa of [['2001:4860:4860::8888'], ['2001:db8::53']]) assert.deepEqual(await privateIps({ aaaa }), [], aaaa[0]);
});

// ── THE MEASURED GAPS ──────────────────────────────────────────────────────────────────────────────────────────────────
test('loopback beyond 127.0.0.1 (127.0.0.2) is graded — HIGH, the wording unchanged', async () => {
  const found = await privateIps({ a: ['127.0.0.2'] });
  assert.deepEqual(found.map((i) => [i.severity, i.detail]),
    [['high', 'Nameserver ns1.example.test resolves to private IP 127.0.0.2 — unreachable from public internet']]);
});
test('CGNAT (100.64/10, RFC 6598) is graded', async () => {
  assert.equal((await privateIps({ a: ['100.64.0.1'] })).length, 1);
  assert.equal((await privateIps({ a: ['100.127.255.254'] })).length, 1);
  assert.deepEqual(await privateIps({ a: ['100.128.0.1'] }), [], 'just outside 100.64/10 is public');
});
test('the ranges graded before are still graded (RFC 1918, link-local, 127.0.0.1)', async () => {
  for (const ip of ['10.1.2.3', '172.16.0.1', '172.31.255.1', '192.168.1.1', '169.254.169.254', '127.0.0.1']) {
    assert.equal((await privateIps({ a: [ip] })).length, 1, ip);
  }
});
test('each non-public address of a nameserver is its own finding; a public one beside it is not', async () => {
  const found = await privateIps({ a: ['198.51.100.1', '10.0.0.53', '127.0.0.2'] });
  assert.deepEqual(found.map((i) => i.detail.match(/private IP (\S+)/)[1]), ['10.0.0.53', '127.0.0.2']);
});

// ── A NAMESERVER REACHABLE OVER IPv6 ONLY ──────────────────────────────────────────────────────────────────────────────
test('an IPv6-only nameserver at a unique-local or loopback address is graded', async () => {
  assert.deepEqual((await privateIps({ aaaa: ['fd00::53'] })).map((i) => i.detail),
    ['Nameserver ns1.example.test resolves to private IP fd00::53 — unreachable from public internet']);
  assert.equal((await privateIps({ aaaa: ['::1'] })).length, 1);
  assert.equal((await privateIps({ aaaa: ['fe80::1'] })).length, 1);
});
