// tests/dns_posture_ipv6_only_nameserver.test.mjs
// ─────────────────────────────────────────────────────────────────────────────
// A NAMESERVER THAT ANSWERS OVER IPv6 ONLY IS NOT A LAME DELEGATION.
//
// Plugin 060 checks that each of a zone's nameservers resolves, and called one "lame" when its A lookup came back empty —
// but a nameserver whose name has an AAAA record and no A record resolves perfectly well. It was graded
// `ns_lame_delegation` (HIGH), and because the /24 diversity check compares IPv4 addresses only, the one remaining
// IPv4 nameserver was then "compared" with itself and the zone graded `ns_same_subnet` too.
//
// Now an empty A answer (NODATA) is followed by an AAAA lookup: an address of either family resolves the nameserver,
// an absence of both is still the lame delegation, and an AAAA lookup that failed for any other reason leaves the NS
// check not measured. The /24 check is graded only when every nameserver has IPv4 addresses to compare.
//
// DRIVEN, OFFLINE: answers from a per-test table; anything not in it answers ENODATA.
//
// FOURTH QUADRANT FIRST: two IPv4 nameservers in different /24s grade nothing, and in one /24 still grade
// ns_same_subnet — or the diversity fix could pass by never grading it.
// ─────────────────────────────────────────────────────────────────────────────
import './helpers/no_operator_home.mjs';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const dnsP = require('node:dns').promises;
const net = require('node:net');

const ZONE = 'example.test';
let TABLE = {};
const answer = (type, name) => {
  const v = `${type} ${name}` in TABLE ? TABLE[`${type} ${name}`] : 'ENODATA';
  if (typeof v === 'string') throw Object.assign(new Error(`query ${v} ${type} ${name}`), { code: v });
  return v;
};
for (const [k, t] of Object.entries({ resolve4: 'A', resolve6: 'AAAA', resolveCname: 'CNAME', resolveMx: 'MX', resolveNs: 'NS',
  resolveSoa: 'SOA', resolveTxt: 'TXT', resolveCaa: 'CAA', resolveAny: 'ANY' })) dnsP[k] = async (n) => answer(t, n);
dnsP.resolve = async (n, t = 'A') => answer(t, n);
net.createConnection = () => { throw new Error('no connection expected'); };

const { default: dnsSec } = await import('../plugins/060_dns_sec_auditor.mjs');

async function ns(table) {
  TABLE = { [`NS ${ZONE}`]: Object.keys(table.ns), ...table.extra };
  for (const [name, { a, aaaa }] of Object.entries(table.ns)) {
    if (a !== undefined) TABLE[`A ${name}`] = a;
    if (aaaa !== undefined) TABLE[`AAAA ${name}`] = aaaa;
  }
  const result = await dnsSec.run(ZONE, 0, {});
  return { checks: result.findings.ns.map((i) => i.check).sort(), result };
}

// ── FOURTH QUADRANT FIRST ─────────────────────────────────────────────────────────────────────────────────────────────
test('(first) two IPv4 nameservers in different /24s: nothing graded', async () => {
  const { checks } = await ns({ ns: { 'ns1.example.test': { a: ['198.51.100.1'] }, 'ns2.example.test': { a: ['203.0.113.1'] } } });
  assert.deepEqual(checks, []);
});
test('(first) two IPv4 nameservers in one /24 still grade ns_same_subnet', async () => {
  const { checks } = await ns({ ns: { 'ns1.example.test': { a: ['198.51.100.1'] }, 'ns2.example.test': { a: ['198.51.100.2'] } } });
  assert.deepEqual(checks, ['ns_same_subnet']);
});

// ── THE IPv6-ONLY NAMESERVER ───────────────────────────────────────────────────────────────────────────────────────────
test('a nameserver with an AAAA record and no A record resolves: no lame delegation, no /24 finding', async () => {
  const { checks, result } = await ns({ ns: { 'ns1.example.test': { a: ['198.51.100.1'] },
    'ns6.example.test': { a: 'ENODATA', aaaa: ['2001:db8::53'] } } });
  assert.deepEqual(checks, []);
  const ns6 = result.details.nameservers.find((n) => n.nameserver === 'ns6.example.test');
  assert.equal(ns6.resolves, true);
  assert.deepEqual(ns6.ips, [], 'ips stays the IPv4 list');
  assert.deepEqual(ns6.ips6, ['2001:db8::53']);
  assert.deepEqual(result.details.notMeasured, []);
});
test('a nameserver with neither an A nor an AAAA record is still the measured lame delegation', async () => {
  const { checks, result } = await ns({ ns: { 'ns1.example.test': { a: ['198.51.100.1'] },
    'ns2.example.test': { a: 'ENODATA', aaaa: 'ENODATA' } } });
  assert.ok(checks.includes('ns_lame_delegation'));
  assert.deepEqual(result.details.notMeasured, []);
});
test('a lame nameserver beside one IPv4 nameserver: lame is graded, the /24 check is not (one address is no comparison)', async () => {
  const { checks } = await ns({ ns: { 'ns1.example.test': { a: ['198.51.100.1'] },
    'ns2.example.test': { a: 'ENODATA', aaaa: 'ENODATA' } } });
  assert.deepEqual(checks, ['ns_lame_delegation']);
});
test('a nameserver name that does not exist (NXDOMAIN) is lame without asking for AAAA', async () => {
  const { checks } = await ns({ ns: { 'ns1.example.test': { a: ['198.51.100.1'] },
    'gone.example.test': { a: 'ENOTFOUND', aaaa: ['2001:db8::99'] } } });
  assert.ok(checks.includes('ns_lame_delegation'), 'NXDOMAIN on the name answers for every record type');
});
test('an empty A answer and an AAAA lookup that timed out: the NS check is not measured, nothing graded for it', async () => {
  const { checks, result } = await ns({ ns: { 'ns1.example.test': { a: ['198.51.100.1'] },
    'ns6.example.test': { a: 'ENODATA', aaaa: 'ETIMEOUT' } } });
  assert.ok(!checks.includes('ns_lame_delegation') && !checks.includes('ns_same_subnet'), JSON.stringify(checks));
  assert.deepEqual(result.details.notMeasured.map((e) => `${e.check}:${e.rrtype}:${e.name}:${e.code}`),
    ['ns:AAAA:ns6.example.test:ETIMEOUT']);
  assert.equal(result.up, false);
});
