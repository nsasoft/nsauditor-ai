// tests/dns_posture_axfr_address_guard.test.mjs
// ─────────────────────────────────────────────────────────────────────────────
// THE ZONE-TRANSFER ATTEMPT CHECKS THE ADDRESS IT WOULD CONNECT TO (the next Community release, its first item).
//
// When the transfer check is opted in (DNS_AUDIT_AXFR_CHECK / the `checkAxfr` option), 060 opens a TCP connection to port
// 53 at the first IPv4 each nameserver name resolves to. That address comes from the zone's own NS records — no host check
// looked at it — so it is classified first, with the same classifier every other connect uses (utils/net_validation.mjs):
// the `always` class (loopback, link-local and cloud metadata, the unspecified address) is refused in EVERY configuration,
// NSA_ALLOW_ALL_HOSTS included; the `private` class (RFC 1918, carrier-grade NAT, unique-local) is refused unless
// NSA_ALLOW_ALL_HOSTS is set. A refused nameserver is RECORDED, never graded: its `details.nameservers[i].axfr` reads
// `{ attempted: false, reason: 'address-refused', addressClass, address, answers }` — `address` is the exact literal that
// would have been connected (the first answer; there is no fall-through to another), `answers` how many the name had —
// and conclude() carries the same list, in the nameservers' order, as `dnsSecurity.axfrNotAttempted`.
//
// DRIVEN, OFFLINE: the zone's NS and A answers are set per test; every other query answers ENODATA; net.createConnection
// RECORDS where it was asked to connect and fails the socket at once — nothing leaves the process.
//
// FOURTH QUADRANT FIRST: a public nameserver is attempted and carries no record — or every refusal leg proves nothing.
// ─────────────────────────────────────────────────────────────────────────────
import './helpers/no_operator_home.mjs';
import { test, beforeEach, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { EventEmitter } from 'node:events';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const dnsP = require('node:dns').promises;
const net = require('node:net');

const ZONE = 'example.test';
let NS_NAMES = [];      // the zone's NS answer
let A = {};             // nameserver name → its A answers
const nodata = async (name) => { throw Object.assign(new Error(`queryX ENODATA ${name}`), { code: 'ENODATA' }); };
for (const k of ['resolve', 'resolve4', 'resolve6', 'resolveTxt', 'resolveCname', 'resolveMx', 'resolveNs', 'resolveSoa',
  'resolveCaa', 'resolveAny']) dnsP[k] = nodata;
dnsP.resolveNs = async (name) => (name === ZONE ? NS_NAMES : nodata(name));
dnsP.resolve4 = async (name) => (Object.hasOwn(A, name) ? A[name] : nodata(name));

let connects = [];
const realCreateConnection = net.createConnection;
net.createConnection = (opts) => {
  connects.push(`${opts.host}:${opts.port}`);
  const socket = new EventEmitter();
  socket.write = () => true;
  socket.destroy = () => {};
  process.nextTick(() => socket.emit('error', Object.assign(new Error('recorded, never connected'), { code: 'ECONNREFUSED' })));
  return socket;
};

const saved = { axfr: process.env.DNS_AUDIT_AXFR_CHECK, all: process.env.NSA_ALLOW_ALL_HOSTS };
const restore = (k, v) => { if (v === undefined) delete process.env[k]; else process.env[k] = v; };
beforeEach(() => { connects = []; delete process.env.DNS_AUDIT_AXFR_CHECK; delete process.env.NSA_ALLOW_ALL_HOSTS; });
after(() => {
  net.createConnection = realCreateConnection;
  restore('DNS_AUDIT_AXFR_CHECK', saved.axfr);
  restore('NSA_ALLOW_ALL_HOSTS', saved.all);
});

const { default: dnsSec } = await import('../plugins/060_dns_sec_auditor.mjs');

/** One zone: `ns` maps nameserver name → its A answers. Runs 060 opted in unless `optIn` is false. */
async function run(ns, { allowAll, optIn = true } = {}) {
  NS_NAMES = Object.keys(ns);
  A = ns;
  connects = [];
  if (allowAll === undefined) delete process.env.NSA_ALLOW_ALL_HOSTS; else process.env.NSA_ALLOW_ALL_HOSTS = allowAll;
  const result = await dnsSec.run(ZONE, 0, optIn ? { checkAxfr: true } : {});
  assert.equal(result.skipped, undefined, 'the audit ran on the domain');
  return { result, connects: [...connects], records: dnsSec.conclude({ result, host: ZONE }) };
}
const axfrOf = (result, name) => result.details.nameservers.find((n) => n.nameserver === name)?.axfr;
const refused = (address, addressClass, answers = 1) => ({ attempted: false, reason: 'address-refused', addressClass, address, answers });

// ── FOURTH QUADRANT FIRST ─────────────────────────────────────────────────────────────────────────────────────────────
test('(1, first) a public nameserver is attempted, and carries no not-attempted record', async () => {
  const { result, connects: c, records } = await run({ 'ns1.example.test': ['192.0.2.53'] });
  assert.deepEqual(c, ['192.0.2.53:53']);
  assert.equal(axfrOf(result, 'ns1.example.test'), undefined);
  assert.equal(records[0].dnsSecurity.axfrNotAttempted, undefined);
});

test('(2) a public and a refused nameserver: the public one is attempted, the refused one recorded — the loop goes on', async () => {
  const { result, connects: c, records } = await run({ 'ns1.example.test': ['169.254.169.254'], 'ns2.example.test': ['192.0.2.54'] });
  assert.deepEqual(c, ['192.0.2.54:53'], 'the nameserver after the refused one must still be attempted');
  assert.deepEqual(axfrOf(result, 'ns1.example.test'), refused('169.254.169.254', 'always'));
  assert.equal(axfrOf(result, 'ns2.example.test'), undefined);
  assert.deepEqual(records[0].dnsSecurity.axfrNotAttempted, [{ nameserver: 'ns1.example.test', ...refused('169.254.169.254', 'always') }]);
});

// ── THE REFUSALS ─────────────────────────────────────────────────────────────────────────────────────────────────────
test('(3) the cloud metadata address is never connected: the record names it and its class', async () => {
  const { result, connects: c } = await run({ 'ns1.example.test': ['169.254.169.254'] });
  assert.deepEqual(c, []);
  assert.deepEqual(axfrOf(result, 'ns1.example.test'), refused('169.254.169.254', 'always'));
});

test('(4) loopback — 127.0.0.1 and 127.0.0.2 — and the unspecified address are refused as `always`', async () => {
  for (const ip of ['127.0.0.1', '127.0.0.2', '0.0.0.0']) {
    const { result, connects: c } = await run({ 'ns1.example.test': [ip] });
    assert.deepEqual(c, [], `${ip} must not be connected`);
    assert.deepEqual(axfrOf(result, 'ns1.example.test'), refused(ip, 'always'), ip);
  }
});

test('(5) private and carrier-grade NAT addresses are refused as `private`; 10.x keeps its ns_private_ip finding', async () => {
  for (const ip of ['10.0.0.53', '100.64.0.53']) {
    const { result, connects: c } = await run({ 'ns1.example.test': [ip] });
    assert.deepEqual(c, [], `${ip} must not be connected`);
    assert.deepEqual(axfrOf(result, 'ns1.example.test'), refused(ip, 'private'), ip);
  }
  const { result } = await run({ 'ns1.example.test': ['10.0.0.53'] });
  assert.ok(result.findings.ns.some((i) => i.check === 'ns_private_ip'), 'the ns_private_ip finding is kept');
});

test('(6) NSA_ALLOW_ALL_HOSTS admits a private nameserver; unset, 0 or false keeps it refused', async () => {
  for (const v of ['1', 'true']) {
    const { result, connects: c } = await run({ 'ns1.example.test': ['10.0.0.53'] }, { allowAll: v });
    assert.deepEqual(c, ['10.0.0.53:53'], `NSA_ALLOW_ALL_HOSTS=${v}`);
    assert.equal(axfrOf(result, 'ns1.example.test'), undefined);
  }
  for (const v of [undefined, '0', 'false']) {
    const { connects: c } = await run({ 'ns1.example.test': ['10.0.0.53'] }, { allowAll: v });
    assert.deepEqual(c, [], `NSA_ALLOW_ALL_HOSTS=${v}`);
  }
});

test('(7) NSA_ALLOW_ALL_HOSTS never admits the `always` class', async () => {
  for (const ip of ['169.254.169.254', '127.0.0.1']) {
    const { result, connects: c } = await run({ 'ns1.example.test': [ip] }, { allowAll: '1' });
    assert.deepEqual(c, [], `${ip} under NSA_ALLOW_ALL_HOSTS=1`);
    assert.deepEqual(axfrOf(result, 'ns1.example.test'), refused(ip, 'always'));
  }
});

test('(8) the decision is about the FIRST answer — the literal that would be connected — with no fall-through', async () => {
  const { result, connects: c } = await run({ 'ns1.example.test': ['169.254.169.254', '192.0.2.53'] });
  assert.deepEqual(c, [], 'a public second answer is not tried in place of a refused first one');
  assert.deepEqual(axfrOf(result, 'ns1.example.test'), refused('169.254.169.254', 'always', 2));
  const ok = await run({ 'ns1.example.test': ['192.0.2.53', '169.254.169.254'] });
  assert.deepEqual(ok.connects, ['192.0.2.53:53'], 'a public first answer is attempted');
});

test('(9) a refusal is never graded: no finding, no severity, no actionable count, nothing in the concluded findings', async () => {
  const off = await run({ 'ns1.example.test': ['169.254.169.254'] }, { optIn: false });
  const on = await run({ 'ns1.example.test': ['169.254.169.254'] });
  assert.deepEqual(on.result.findings.axfr, []);
  assert.equal(on.result.overallSeverity, off.result.overallSeverity);
  assert.deepEqual(on.result.summary, off.result.summary);
  assert.deepEqual(on.records[0].dnsSecurity.findings, off.records[0].dnsSecurity.findings);
  assert.equal(on.records[0].dnsSecurity.severity, off.records[0].dnsSecurity.severity);
  assert.equal(on.records[0].dnsSecurity.actionable, off.records[0].dnsSecurity.actionable);
  const { flagFindings } = await import('../utils/service_flags.mjs');
  assert.deepEqual(flagFindings(on.records[0], { target: ZONE }), flagFindings(off.records[0], { target: ZONE }),
    'the record must add no service-flag finding');
});

test('(10) with the switch off, a refused-class nameserver is neither connected nor recorded', async () => {
  const { result, connects: c, records } = await run({ 'ns1.example.test': ['169.254.169.254'] }, { optIn: false });
  assert.deepEqual(c, []);
  assert.equal(axfrOf(result, 'ns1.example.test'), undefined);
  assert.equal(records[0].dnsSecurity.axfrNotAttempted, undefined);
});

test('(11) a refusal leaves the result up, and the plugin still carries exactly one `up: false` (its IP-literal decline)', async () => {
  const { result } = await run({ 'ns1.example.test': ['169.254.169.254'] });
  assert.equal(result.up, true);
  const src = fs.readFileSync(new URL('../plugins/060_dns_sec_auditor.mjs', import.meta.url), 'utf8');
  assert.equal(src.split('up: false').length - 1, 1);
});
