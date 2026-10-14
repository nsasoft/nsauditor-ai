// tests/dns_posture_axfr_opt_in.test.mjs
// ─────────────────────────────────────────────────────────────────────────────
// THE DNS-SECURITY AUDIT'S ZONE-TRANSFER ATTEMPT IS OPT-IN (Community 1.0.0).
//
// 060 tries an AXFR of the scanned name against each of the zone's nameservers: a TCP connection to port 53 at the first
// IPv4 each nameserver name resolves to. That address comes from the zone's own NS records, never from the scan's host
// check, so the scan-target pin does not govern it and no address-class check stands in front of it — and a large
// referral (RCODE 0 with no answer) reads as an open transfer. Until 1.0.0 the attempt ran on every scan of a name unless
// DNS_AUDIT_AXFR_CHECK was set to anything but the exact string "true". It now runs only when asked:
// DNS_AUDIT_AXFR_CHECK, or the `checkAxfr` option a library caller passes, set to 1, true, yes or on — the convention
// of every other switch here (dns_scanner's DNS_CHECK_AXFR). An explicit option wins over the environment.
//
// DRIVEN, OFFLINE: the zone answers one nameserver at 192.0.2.53 (RFC 5737), every other query answers ENODATA, and
// net.createConnection RECORDS where it was asked to connect and fails the socket at once — nothing leaves the process.
//
// FOURTH QUADRANT FIRST: opted in, the attempt is made — or every "no connection" leg below proves nothing.
// ─────────────────────────────────────────────────────────────────────────────
import './helpers/no_operator_home.mjs';
import { test, beforeEach, after } from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const dnsP = require('node:dns').promises;
const net = require('node:net');

const ZONE = 'example.test';
const NS = 'ns1.example.test';
const NS_IP = '192.0.2.53';
const nodata = async (name) => { throw Object.assign(new Error(`queryX ENODATA ${name}`), { code: 'ENODATA' }); };
for (const k of ['resolve', 'resolve4', 'resolve6', 'resolveTxt', 'resolveCname', 'resolveMx', 'resolveNs', 'resolveSoa',
  'resolveCaa', 'resolveAny']) dnsP[k] = nodata;
dnsP.resolveNs = async (name) => (name === ZONE ? [NS] : nodata(name));
dnsP.resolve4 = async (name) => (name === NS ? [NS_IP] : nodata(name));

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

const savedEnv = process.env.DNS_AUDIT_AXFR_CHECK;
beforeEach(() => { connects = []; delete process.env.DNS_AUDIT_AXFR_CHECK; });
after(() => {
  net.createConnection = realCreateConnection;
  if (savedEnv === undefined) delete process.env.DNS_AUDIT_AXFR_CHECK; else process.env.DNS_AUDIT_AXFR_CHECK = savedEnv;
});

const { default: dnsSec } = await import('../plugins/060_dns_sec_auditor.mjs');
const { PluginManager } = await import('../plugin_manager.mjs');
const ATTEMPT = [`${NS_IP}:53`];
/** Run 060 on the zone with `env` (undefined = unset) and `opts`; return where it asked to connect. */
async function attempted(env, opts = {}) {
  connects = [];
  if (env === undefined) delete process.env.DNS_AUDIT_AXFR_CHECK; else process.env.DNS_AUDIT_AXFR_CHECK = env;
  const r = await dnsSec.run(ZONE, 0, opts);
  assert.equal(r.skipped, undefined, 'the audit ran on the domain');
  return connects;
}

// ── FOURTH QUADRANT FIRST: opted in, the attempt is made ─────────────────────────────────────────────────────────────
test('(first) opted in through the environment — 1, true, yes or on, any case — the transfer is attempted against the nameserver', async () => {
  for (const v of ['true', 'TRUE', '1', 'yes', 'on', ' true ']) assert.deepEqual(await attempted(v), ATTEMPT, `DNS_AUDIT_AXFR_CHECK=${JSON.stringify(v)}`);
});

test('(first) opted in through the option — true or "true" — the transfer is attempted, and an explicit option wins over the environment', async () => {
  assert.deepEqual(await attempted(undefined, { checkAxfr: true }), ATTEMPT, 'checkAxfr: true');
  assert.deepEqual(await attempted(undefined, { checkAxfr: 'true' }), ATTEMPT, 'checkAxfr: "true"');
  assert.deepEqual(await attempted('false', { checkAxfr: true }), ATTEMPT, 'checkAxfr: true beside DNS_AUDIT_AXFR_CHECK=false');
});

test('(first) through the public PluginManager.run, the caller\'s checkAxfr reaches the audit', async () => {
  const pm = await PluginManager.create({ plugins: [dnsSec] });
  connects = [];
  await pm.run(ZONE, ['060'], { checkAxfr: true });
  assert.deepEqual(connects, ATTEMPT);
});

// ── OFF BY DEFAULT ───────────────────────────────────────────────────────────────────────────────────────────────────
test('by default — nothing set — no transfer is attempted and no connection is opened', async () => {
  assert.deepEqual(await attempted(undefined), []);
  const pm = await PluginManager.create({ plugins: [dnsSec] });
  connects = [];
  await pm.run(ZONE, ['060'], {});
  assert.deepEqual(connects, [], 'a default run through the plugin manager opened a connection');
});

test('switched off — false, 0, no, off or empty — no connection, and an explicit false option wins over the environment', async () => {
  for (const v of ['false', '0', 'no', 'off', '']) assert.deepEqual(await attempted(v), [], `DNS_AUDIT_AXFR_CHECK=${JSON.stringify(v)}`);
  assert.deepEqual(await attempted('true', { checkAxfr: false }), [], 'checkAxfr: false beside DNS_AUDIT_AXFR_CHECK=true');
  assert.deepEqual(await attempted('true', { checkAxfr: 'false' }), [], 'checkAxfr: "false" beside DNS_AUDIT_AXFR_CHECK=true');
});

test('the rest of the audit still runs by default — the nameserver is resolved and checked, only the transfer waits for the opt-in', async () => {
  const r = await dnsSec.run(ZONE, 0, {});
  assert.deepEqual(connects, []);
  assert.ok(r.details?.nameservers?.some?.((n) => n.nameserver === NS || n === NS) ?? JSON.stringify(r).includes(NS),
    'the NS module still read the zone\'s nameservers');
});
