// tests/dns_posture_axfr_measured.test.mjs
// ─────────────────────────────────────────────────────────────────────────────
// THE ZONE-TRANSFER ATTEMPT IS MEASURED: WHAT EACH NAMESERVER ANSWERED, AND WHY A NAMESERVER WAS NOT ASKED.
//
// With the opt-in zone-transfer check on, plugin 060 used to read "open" from the first TCP chunk alone — RCODE 0 and more
// than 50 bytes — so a nameserver that answered an AXFR query with any record at all (an A record, a lone SOA) was graded
// `axfr_open` CRITICAL; and every other outcome — refused, NOTAUTH, a timeout, a refused connection, a reply cut short, a
// nameserver with no IPv4 address — left NOTHING, byte-identical to "the check was off".
//
// Now each nameserver carries a record: `{ attempted: true, address, outcome, … }` — `transferred` (RCODE 0, the answer
// opens with the zone's SOA and carries more records; `complete` when the closing SOA arrived), `answered-not-transferred`
// (RCODE 0 with anything else: no zone came back), `refused` (an error RCODE, or TCP/53 refused) or `no-answer` (a timeout,
// a transport error, a reply cut short — the AXFR check is then NOT MEASURED for that nameserver) — or
// `{ attempted: false, reason }` for one that was not asked. Only `transferred` is `axfr_open` (CRITICAL);
// `answered-not-transferred` is `axfr_answered_not_transferred` (LOW): the server answers AXFR queries instead of refusing
// them, and no zone left it.
//
// DRIVEN, OFFLINE: DNS answers from a per-test table; `net.createConnection` is a fake TCP/53 that replays crafted DNS
// messages per address — nothing leaves the process.
//
// FOURTH QUADRANT FIRST: a real transfer is still `axfr_open` and nothing else — or the narrowing could pass by never
// grading one.
// ─────────────────────────────────────────────────────────────────────────────
import './helpers/no_operator_home.mjs';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const dnsP = require('node:dns').promises;
const net = require('node:net');

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

// ── A fake TCP/53: per address, the bytes it sends back (or how it fails) ────────────────────────────────────────────
const TYPE = { A: 1, NS: 2, CNAME: 5, SOA: 6, TXT: 16 };
const u16 = (n) => { const b = Buffer.alloc(2); b.writeUInt16BE(n); return b; };
const qname = (d) => Buffer.concat([...d.split('.').map((l) => Buffer.concat([Buffer.from([l.length]), Buffer.from(l)])), Buffer.from([0])]);
/** One TCP-framed DNS response: an RCODE and the answer records' types, in order. */
function message({ rcode = 0, types = [] }) {
  const hdr = Buffer.alloc(12);
  hdr.writeUInt16BE(0x1234, 0); hdr.writeUInt16BE(0x8400 | rcode, 2); hdr.writeUInt16BE(1, 4); hdr.writeUInt16BE(types.length, 6);
  const rrs = types.map((t) => Buffer.concat([Buffer.from([0xc0, 0x0c]), u16(TYPE[t]), u16(1), Buffer.from([0, 0, 1, 44]), u16(4),
    Buffer.from([192, 0, 2, 1])]));
  const body = Buffer.concat([hdr, qname(ZONE), u16(252), u16(1), ...rrs]);
  return Buffer.concat([u16(body.length), body]);
}
let SERVERS = {};
net.createConnection = (opts, onConnect) => {
  const s = new EventEmitter();
  const plan = SERVERS[opts.host] ?? { error: 'ECONNREFUSED' };
  let destroyed = false;
  s.write = () => {
    if (plan.chunks) {
      setImmediate(() => {
        for (const c of plan.chunks) if (!destroyed) s.emit('data', c);
        if (plan.close !== false && !destroyed) s.emit('close');
      });
    }
    return true;
  };
  s.destroy = () => { destroyed = true; };
  setImmediate(() => {
    if (plan.error) return s.emit('error', Object.assign(new Error(plan.error), { code: plan.error }));
    if (plan.silent) return;
    onConnect?.();
  });
  return s;
};

const { default: dnsSec } = await import('../plugins/060_dns_sec_auditor.mjs');

const NS1 = `ns1.${ZONE}`;
async function axfr(plan, { nsExtra = {}, opts = {} } = {}) {
  TABLE = { [`NS ${ZONE}`]: [NS1, ...Object.keys(nsExtra)], [`A ${NS1}`]: ['192.0.2.53'], ...Object.fromEntries(
    Object.entries(nsExtra).flatMap(([n, v]) => Object.entries(v).map(([t, a]) => [`${t} ${n}`, a]))) };
  SERVERS = { '192.0.2.53': plan };
  const result = await dnsSec.run(ZONE, 0, { checkAxfr: true, timeoutMs: 80, ...opts });
  const record = dnsSec.conclude({ result, host: ZONE })[0];
  const checks = result.findings.axfr.map((i) => `${i.check}:${i.severity}`);
  const ns = (name) => result.details.nameservers.find((n) => n.nameserver === name)?.axfr;
  return { result, record, checks, ns };
}
const full = (...msgs) => ({ chunks: [Buffer.concat(msgs.map(message))] });

// ── FOURTH QUADRANT FIRST ─────────────────────────────────────────────────────────────────────────────────────────────
test('(first) a real transfer — SOA, records, closing SOA — is axfr_open CRITICAL and nothing else', async () => {
  const { checks, ns, result } = await axfr(full({ types: ['SOA', 'NS', 'A', 'SOA'] }));
  assert.deepEqual(checks, ['axfr_open:critical']);
  assert.deepEqual(ns(NS1), { attempted: true, address: '192.0.2.53', outcome: 'transferred', records: 4, firstType: 'SOA', complete: true });
  assert.deepEqual(result.details.notMeasured, []);
  assert.equal(result.details.axfrTested, true);
});
test('(first) a transfer across several messages and TCP chunks is still read whole', async () => {
  const bytes = Buffer.concat([message({ types: ['SOA', 'A'] }), message({ types: ['A', 'SOA'] })]);
  const { checks, ns } = await axfr({ chunks: [bytes.subarray(0, 7), bytes.subarray(7, 40), bytes.subarray(40)] });
  assert.deepEqual(checks, ['axfr_open:critical']);
  assert.equal(ns(NS1).records, 4);
});

test('a transfer the server ends WITHOUT its closing SOA is still transferred — complete:false, axfr_open with the cut on the finding', async () => {
  const { checks, ns, result } = await axfr(full({ types: ['SOA', 'NS', 'A'] }));
  assert.deepEqual(checks, ['axfr_open:critical'], 'graded by what left the server, never LOW');
  assert.deepEqual(ns(NS1), { attempted: true, address: '192.0.2.53', outcome: 'transferred', records: 3, firstType: 'SOA', complete: false });
  assert.deepEqual([result.findings.axfr[0].records, result.findings.axfr[0].complete], [3, false], 'the cut is named on the finding');
});

// ── ANSWERED, NOT TRANSFERRED ──────────────────────────────────────────────────────────────────────────────────────────
test('an SOA alone is answered-not-transferred — LOW, never axfr_open', async () => {
  const { checks, ns, result } = await axfr(full({ types: ['SOA'] }));
  assert.deepEqual(checks, ['axfr_answered_not_transferred:low']);
  assert.deepEqual(ns(NS1), { attempted: true, address: '192.0.2.53', outcome: 'answered-not-transferred', records: 1, firstType: 'SOA' });
  assert.deepEqual([result.findings.axfr[0].records, result.findings.axfr[0].firstType], [1, 'SOA'], 'what came back is on the finding');
});
test('an answer whose first record is not the SOA (CNAME, A) is answered-not-transferred', async () => {
  const { checks, ns } = await axfr(full({ types: ['CNAME', 'A'] }));
  assert.deepEqual(checks, ['axfr_answered_not_transferred:low']);
  assert.equal(ns(NS1).firstType, 'CNAME');
  assert.equal(ns(NS1).records, 2);
});

// ── THE DETAIL IS THE FINDING'S IDENTITY: what the transfer carried is evidence ON the finding, never in its words ──────
// The cross-run delta keys a host finding on its title and a digest of its detail (utils/report_inputs.mjs), and Enterprise
// keys the same text. A record count in the detail made one open transfer a different finding each time the zone gained a
// record — read "resolved" beside a "new" one — and moved the 1.0.0 wording, so every open transfer would read resolved
// across the upgrade. The count, the cut and the first record's type stay on the finding and on the nameserver's record.
const V1_AXFR_OPEN = 'Zone transfer (AXFR) allowed on ns1.example.test (192.0.2.53) — entire zone is exposed';
async function identityOf(issue) {
  const { shapeFinding } = await import('../utils/report_inputs.mjs');
  const s = shapeFinding(ZONE, issue, '060', 'DNS Security Auditor');
  return [s.title, s.contentDigest];
}
test('(first) the detail still names its nameserver — two open nameservers are two findings, never one', async () => {
  TABLE = { [`NS ${ZONE}`]: [NS1, `ns2.${ZONE}`], [`A ${NS1}`]: ['192.0.2.53'], [`A ns2.${ZONE}`]: ['192.0.2.54'] };
  SERVERS = { '192.0.2.53': full({ types: ['SOA', 'A', 'SOA'] }), '192.0.2.54': full({ types: ['SOA', 'A', 'SOA'] }) };
  const result = await dnsSec.run(ZONE, 0, { checkAxfr: true, timeoutMs: 80 });
  const open = result.findings.axfr.filter((i) => i.check === 'axfr_open');
  assert.equal(open.length, 2);
  assert.notDeepEqual(await identityOf(open[0]), await identityOf(open[1]));
});
test('axfr_open keeps its 1.0.0 wording verbatim, and a zone of another size is the SAME finding', async () => {
  const small = (await axfr(full({ types: ['SOA', 'A', 'SOA'] }))).result.findings.axfr[0];
  const large = (await axfr(full({ types: ['SOA', 'NS', 'A', 'A', 'TXT', 'SOA'] }))).result.findings.axfr[0];
  assert.equal(small.detail, V1_AXFR_OPEN);
  assert.deepEqual([small.records, large.records], [3, 6], 'the count is still measured, on the finding');
  assert.deepEqual(await identityOf(large), await identityOf(small));
});
test('a transfer cut before its closing SOA is the same finding as a whole one — the cut is on the finding', async () => {
  const whole = (await axfr(full({ types: ['SOA', 'A', 'SOA'] }))).result.findings.axfr[0];
  const cut = (await axfr(full({ types: ['SOA', 'A'] }))).result.findings.axfr[0];
  assert.deepEqual([whole.complete, cut.complete], [true, false]);
  assert.deepEqual(await identityOf(cut), await identityOf(whole));
});
test('axfr_answered_not_transferred: what came back is on the finding, and its words do not move with it', async () => {
  const soa = (await axfr(full({ types: ['SOA'] }))).result.findings.axfr[0];
  const cname = (await axfr(full({ types: ['CNAME', 'A'] }))).result.findings.axfr[0];
  assert.deepEqual([soa.check, cname.check], ['axfr_answered_not_transferred', 'axfr_answered_not_transferred']);
  assert.deepEqual([[soa.records, soa.firstType], [cname.records, cname.firstType]], [[1, 'SOA'], [2, 'CNAME']]);
  assert.deepEqual(await identityOf(cname), await identityOf(soa));
});

// ── REFUSED: MEASURED, NOT GRADED ──────────────────────────────────────────────────────────────────────────────────────
for (const [label, rcode] of [['REFUSED', 5], ['NOTAUTH', 9], ['SERVFAIL', 2]]) {
  test(`${label} is a measured refusal: no finding, the record says so`, async () => {
    const { checks, ns, result } = await axfr(full({ rcode, types: [] }));
    assert.deepEqual(checks, []);
    assert.deepEqual(ns(NS1), { attempted: true, address: '192.0.2.53', outcome: 'refused', rcode });
    assert.deepEqual(result.details.notMeasured, []);
  });
}
test('TCP/53 refusing the connection is a measured refusal too', async () => {
  const { checks, ns } = await axfr({ error: 'ECONNREFUSED' });
  assert.deepEqual(checks, []);
  assert.deepEqual(ns(NS1), { attempted: true, address: '192.0.2.53', outcome: 'refused', code: 'ECONNREFUSED' });
});

// ── NO ANSWER: THE AXFR CHECK IS NOT MEASURED FOR THAT NAMESERVER ──────────────────────────────────────────────────────
for (const [label, plan, code] of [
  ['a timeout', { silent: true }, 'ETIMEOUT'],
  ['a transport error', { error: 'EHOSTUNREACH' }, 'EHOSTUNREACH'],
  ['a reply cut short before its message ends', { chunks: [message({ types: ['SOA', 'A'] }).subarray(0, 20)] }, 'ECLOSED'],
]) {
  test(`${label}: no finding, outcome no-answer, and the AXFR check is recorded not measured`, async () => {
    const { checks, ns, result } = await axfr(plan);
    assert.deepEqual(checks, []);
    assert.equal(ns(NS1).outcome, 'no-answer');
    assert.equal(ns(NS1).code, code);
    assert.deepEqual(result.details.notMeasured.map((e) => `${e.check}:${e.rrtype}:${e.name}:${e.code}`), [`axfr:AXFR:${NS1}:${code}`]);
    assert.equal(result.up, false);
    assert.match(result.reason, /AXFR \(/);
  });
}

// ── NOT ATTEMPTED, WITH THE REASON ─────────────────────────────────────────────────────────────────────────────────────
test('a nameserver with only an IPv6 address is not attempted — reason no-ipv4-address', async () => {
  const { ns, record } = await axfr(full({ rcode: 5, types: [] }), { nsExtra: { [`ns6.${ZONE}`]: { AAAA: ['2001:db8::53'] } } });
  assert.deepEqual(ns(`ns6.${ZONE}`), { attempted: false, reason: 'no-ipv4-address' });
  assert.ok(record.dnsSecurity.axfrNotAttempted.some((n) => n.nameserver === `ns6.${ZONE}` && n.reason === 'no-ipv4-address'));
});
test('a nameserver that does not resolve is not attempted — reason does-not-resolve', async () => {
  const { ns } = await axfr(full({ rcode: 5, types: [] }), { nsExtra: { [`gone.${ZONE}`]: { A: 'ENOTFOUND' } } });
  assert.deepEqual(ns(`gone.${ZONE}`), { attempted: false, reason: 'does-not-resolve' });
});
test('a nameserver whose address lookup failed is not attempted — reason address-unknown', async () => {
  const { ns } = await axfr(full({ rcode: 5, types: [] }), { nsExtra: { [`ns3.${ZONE}`]: { A: 'ETIMEOUT' } } });
  assert.deepEqual(ns(`ns3.${ZONE}`), { attempted: false, reason: 'address-unknown' });
});
test('with the check off, no nameserver is asked and none carries a record — axfrTested says why', async () => {
  const { result, checks } = await axfr(full({ types: ['SOA', 'A', 'SOA'] }), { opts: { checkAxfr: false } });
  assert.deepEqual(checks, []);
  assert.equal(result.details.axfrTested, 'opt-in-off');
  assert.ok(result.details.nameservers.every((n) => n.axfr === undefined));
});

// ── THE HISTORY DELTA: an open transfer, then a run with the check off, is not compared — never "fixed" ─────────────────
test('(delta) axfr_open, then a run with the zone-transfer check OFF: not compared with why, never cleared', async () => {
  const [{ default: concluder }, { historyServiceEntry, historyHostEntry, computeDiff }, { FINDINGS_COUNT_BASIS }] = await Promise.all([
    import('../plugins/result_concluder.mjs'), import('../utils/scan_history.mjs'), import('../utils/report_inputs.mjs')]);
  const line = async (opts) => {
    const { result } = await axfr(full({ types: ['SOA', 'A', 'SOA'] }), { opts });
    const c = await concluder.run([{ id: '060', name: 'DNS Security Auditor', result }]);
    return { findingsCount: 0, findingsCountBasis: FINDINGS_COUNT_BASIS, tier: 'pro',
      services: c.services.map(historyServiceEntry), ...historyHostEntry({ result: c }) };
  };
  const on = await line({});
  const d = computeDiff(await line({ checkAxfr: false }), on);
  const h = d.changedFlags.find((c) => c.port == null) ?? { cleared: [], notCompared: [] };
  assert.ok(!h.cleared.includes('dnsSecurity:axfr_open'), JSON.stringify(h));
  assert.ok(JSON.stringify(h.notCompared).includes('dnsSecurity:axfr_open'), JSON.stringify(h));
  // And with the check ON in both runs, a transfer that stops IS compared — it reads cleared.
  const refusedNow = await (async () => {
    const { result } = await axfr(full({ rcode: 5, types: [] }));
    const c = await concluder.run([{ id: '060', name: 'DNS Security Auditor', result }]);
    return { findingsCount: 0, findingsCountBasis: FINDINGS_COUNT_BASIS, tier: 'pro',
      services: c.services.map(historyServiceEntry), ...historyHostEntry({ result: c }) };
  })();
  const fixed = computeDiff(refusedNow, on).changedFlags.find((c) => c.port == null) ?? { cleared: [] };
  assert.ok(fixed.cleared.includes('dnsSecurity:axfr_open'), JSON.stringify(fixed));
});
