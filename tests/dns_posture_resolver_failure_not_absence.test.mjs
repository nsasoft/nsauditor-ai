// tests/dns_posture_resolver_failure_not_absence.test.mjs
// ─────────────────────────────────────────────────────────────────────────────
// A RESOLVER FAILURE IS NOT AN ABSENCE.
//
// Plugin 060 grades a domain's DNS posture from what its lookups return. A lookup that answers NODATA (`ENODATA`) or
// NXDOMAIN (`ENOTFOUND`) MEASURED an absence: "no SPF record" is then a finding. Any other failure — a timeout, SERVFAIL,
// a refused or unreachable resolver, a malformed reply — measured nothing, and used to read exactly like the absence:
// every check graded "missing" (SPF, DMARC, NS, DKIM, DNSSEC, MX, CAA), a present-but-weak record (`spf_plus_all`,
// `dmarc_policy_none`) was silently replaced by "missing", a timed-out DS beside a present DNSKEY read as a broken chain
// of trust, a timed-out nameserver address read as a lame delegation, and a timed-out MX beside an A record read as an A
// fallback. In the other direction a timed-out wildcard or MX-is-CNAME probe read as "nothing found".
//
// Now a check whose lookup failed that way is NOT MEASURED: it grades nothing, its failure is recorded with its code in
// `details.notMeasured` (and `dnsSecurity.notMeasured` on the concluded record), and the result is `up: false` with a
// `reason` that names the checks it could not measure and the ones it did — a reader that only sees `up` fails closed,
// and the measured checks' findings stay in the result. The concluded status reads `incomplete` when nothing measured is
// actionable but something was not measured; `action_required` still wins.
//
// DRIVEN, OFFLINE: every lookup answers from a per-test table keyed by record type and name; anything not in the table
// answers ENODATA; nothing leaves the process.
//
// FOURTH QUADRANT FIRST: a fully answered zone and a genuinely empty zone grade exactly as before — or every
// not-measured leg below could be satisfied by refusing to grade anything.
// ─────────────────────────────────────────────────────────────────────────────
import './helpers/no_operator_home.mjs';
import './helpers/no_operator_dotenv.mjs';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const dnsP = require('node:dns').promises;
const net = require('node:net');

const ZONE = 'example.test';
const WILDCARD = `A *.${ZONE}`;
let TABLE = {};
const fail = (code, what) => { throw Object.assign(new Error(`query ${code} ${what}`), code ? { code } : {}); };
/** One lookup: an array/object answers, a string is the error code it fails with, `{ message }` fails with no code (its
 *  message prefixed `query null `), `{ raw }` fails with no code and EXACTLY that message (VERDICT-v403 R1: a message that
 *  begins with a code-shaped token — the prefixed form cannot make one). */
function answer(type, name) {
  const key = name.startsWith('nsauditor-wildcard-probe-') ? WILDCARD : `${type} ${name}`;
  const v = key in TABLE ? TABLE[key] : 'ENODATA';
  if (typeof v === 'string') return fail(v, key);
  if (v && typeof v === 'object' && !Array.isArray(v) && Object.hasOwn(v, 'message')) return fail(null, v.message);
  if (v && typeof v === 'object' && !Array.isArray(v) && Object.hasOwn(v, 'raw')) throw new Error(v.raw);
  return v;
}
dnsP.resolve4 = async (n) => answer('A', n);
dnsP.resolve6 = async (n) => answer('AAAA', n);
dnsP.resolveCname = async (n) => answer('CNAME', n);
dnsP.resolveMx = async (n) => answer('MX', n);
dnsP.resolveNs = async (n) => answer('NS', n);
dnsP.resolveSoa = async (n) => answer('SOA', n);
dnsP.resolveTxt = async (n) => answer('TXT', n);
dnsP.resolveCaa = async (n) => answer('CAA', n);
dnsP.resolveAny = async (n) => answer('ANY', n);
dnsP.resolve = async (n, t = 'A') => answer(t, n);
net.createConnection = () => { throw new Error('060 opened a connection; the zone-transfer attempt is not opted in here'); };

const { default: dnsSec } = await import('../plugins/060_dns_sec_auditor.mjs');

// A zone where every check is measured and answered — and nothing in it is actionable.
const KEY_2048 = 'A'.repeat(344);
const PRESENT = Object.freeze({
  [`A ${ZONE}`]: ['192.0.2.10'],
  [`MX ${ZONE}`]: [{ priority: 10, exchange: `mx1.${ZONE}` }],
  [`NS ${ZONE}`]: [`ns1.${ZONE}`, `ns2.${ZONE}`],
  [`A ns1.${ZONE}`]: ['198.51.100.1'],
  [`A ns2.${ZONE}`]: ['203.0.113.1'],
  [`SOA ${ZONE}`]: { nsname: `ns1.${ZONE}`, hostmaster: `hostmaster.${ZONE}`, serial: 1 },
  [`TXT ${ZONE}`]: [['v=spf1 -all']],
  [`TXT _dmarc.${ZONE}`]: [['v=DMARC1; p=reject; sp=reject; rua=mailto:d@example.test']],
  [`TXT google._domainkey.${ZONE}`]: [[`v=DKIM1; k=rsa; p=${KEY_2048}`]],
  [`DNSKEY ${ZONE}`]: [{ flags: 257 }],
  [`DS ${ZONE}`]: [{ digestType: 2 }],
  [`CAA ${ZONE}`]: [{ critical: 0, issue: 'ca.example' }],
  [WILDCARD]: 'ENOTFOUND',
});

async function run(table) {
  TABLE = table;
  const result = await dnsSec.run(ZONE, 0, { dkimSelectors: 'google,default' });
  const [record] = dnsSec.conclude({ result, host: ZONE });
  const graded = Object.entries(result.findings)
    .flatMap(([category, issues]) => issues.map((i) => `${category}:${i.check}:${i.severity}`)).sort();
  return { result, record, graded, notMeasured: result.details?.notMeasured ?? null };
}
const checksOf = (nm) => [...new Set(nm.map((e) => e.check))].sort();

// The seven findings a genuinely empty zone grades — and the ones a resolver failure used to fabricate.
const ABSENCE_SET = ['caa:no_caa:low', 'dkim:dkim_none_found:medium', 'dmarc:missing_dmarc:high', 'dnssec:no_dnssec:medium',
  'mx:no_mx:info', 'ns:no_ns_records:high', 'spf:missing_spf:high'];

// ── FOURTH QUADRANT FIRST ─────────────────────────────────────────────────────────────────────────────────────────────
test('(1, first) a fully answered zone: every check measured, no record of a failure, up, nothing graded missing', async () => {
  const { result, record, graded, notMeasured } = await run(PRESENT);
  assert.equal(result.up, true);
  assert.equal(result.reason, undefined);
  assert.deepEqual(notMeasured, []);
  assert.equal(record.dnsSecurity.notMeasured, undefined, 'a record, only when there is something to record');
  assert.equal(result.summary.notMeasured, 0);
  for (const f of ABSENCE_SET) assert.ok(!graded.includes(f), `${f} on a fully answered zone`);
  assert.ok(graded.includes('dnssec:dnssec_active:pass'));
  assert.equal(record.dnsSecurity.status, 'hardened');
});

for (const code of ['ENODATA', 'ENOTFOUND']) {
  test(`(2, first) a genuinely empty zone (${code} everywhere) grades the seven absence findings, measured, up`, async () => {
    const empty = new Proxy({}, { has: () => true, get: () => code });
    const { result, record, graded, notMeasured } = await run(empty);
    assert.deepEqual(graded, ABSENCE_SET);
    assert.equal(result.up, true);
    assert.deepEqual(notMeasured, []);
    assert.equal(record.dnsSecurity.status, 'action_required');
  });
}

// ── A RESOLVER THAT ANSWERED NOTHING USABLE ────────────────────────────────────────────────────────────────────────────
test('every lookup times out: nothing is graded missing, every check is recorded not measured, up is false', async () => {
  const dead = new Proxy({}, { has: () => true, get: () => 'ETIMEOUT' });
  const { result, record, graded, notMeasured } = await run(dead);
  assert.deepEqual(graded.filter((g) => !g.endsWith(':pass') && !g.endsWith(':info')), [], 'no finding from a timeout');
  // One entry per check, in the result's order — except DKIM, which records EVERY failed selector lookup (G-71 F-060):
  // here both configured selectors, google then default.
  assert.deepEqual([...new Set(notMeasured.map((e) => e.check))],
    ['cname', 'spf', 'dmarc', 'dkim', 'ns', 'dnssec', 'mx', 'caa', 'wildcard'], 'every check, in the result\'s order');
  assert.deepEqual(notMeasured.filter((e) => e.check === 'dkim').map((e) => e.name), [`google._domainkey.${ZONE}`, `default._domainkey.${ZONE}`]);
  assert.equal(notMeasured.filter((e) => e.check !== 'dkim').length, 8, 'one entry for each other check');
  assert.ok(notMeasured.every((e) => e.code === 'ETIMEOUT' && typeof e.rrtype === 'string' && typeof e.name === 'string'));
  assert.equal(result.up, false);
  assert.equal(result.skipped, undefined, 'skipped is the declined-address case, never this one');
  assert.equal(result.summary.notMeasured, notMeasured.length);
  assert.equal(record.dnsSecurity.status, 'incomplete');
  assert.deepEqual(record.dnsSecurity.notMeasured, notMeasured);
  assert.match(result.reason, /no check was measured/);
  assert.doesNotMatch(record.info, /SPF missing|DMARC missing/, 'the summary line says not measured, never missing');
  assert.match(record.info, /SPF not measured \(ETIMEOUT\)/);
});

// ── ONE CHECK AT A TIME: its finding is never fabricated, and every other check is untouched ───────────────────────
const ONE_AT_A_TIME = [
  ['spf', `TXT ${ZONE}`],
  ['dmarc', `TXT _dmarc.${ZONE}`],
  ['ns', `NS ${ZONE}`],
  ['ns', `A ns1.${ZONE}`],
  ['caa', `CAA ${ZONE}`],
  ['mx', `MX ${ZONE}`],
  ['mx', `CNAME mx1.${ZONE}`],
  ['cname', `CNAME ${ZONE}`],
  ['wildcard', WILDCARD],
  ['dkim', `TXT google._domainkey.${ZONE}`],
  ['dnssec', `DS ${ZONE}`],
];
const { graded: PRESENT_GRADED } = await run(PRESENT);
for (const [check, key] of ONE_AT_A_TIME) {
  test(`${key} times out: ${check} is not measured, nothing is fabricated, every other check grades as before`, async () => {
    const { result, graded, notMeasured } = await run({ ...PRESENT, [key]: 'ETIMEOUT' });
    assert.deepEqual(checksOf(notMeasured), [check]);
    const [entry] = notMeasured.filter((e) => e.check === check);
    if (key === WILDCARD) {
      assert.equal(entry.rrtype, 'A');
      assert.ok(entry.name.startsWith('nsauditor-wildcard-probe-') && entry.name.endsWith(`.${ZONE}`), entry.name);
    } else {
      assert.equal(`${entry.rrtype} ${entry.name}`, key);
    }
    assert.equal(entry.code, 'ETIMEOUT');
    const otherCategories = (g) => !g.startsWith(`${check}:`);
    assert.deepEqual(graded.filter(otherCategories), PRESENT_GRADED.filter(otherCategories));
    for (const fabricated of ['missing_spf', 'missing_dmarc', 'no_ns_records', 'ns_lame_delegation', 'ns_same_subnet',
      'no_caa', 'no_mx', 'no_mx_a_fallback', 'dkim_none_found', 'no_dnssec', 'dnssec_partial']) {
      assert.ok(!graded.some((g) => g.includes(`:${fabricated}:`)), `${fabricated} fabricated from a timeout`);
    }
    assert.equal(result.up, false);
  });
}

test('a present-but-weak record that times out is not replaced by "missing" (spf_plus_all, dmarc_policy_none)', async () => {
  const weak = { ...PRESENT, [`TXT ${ZONE}`]: [['v=spf1 +all']], [`TXT _dmarc.${ZONE}`]: [['v=DMARC1; p=none']] };
  const before = await run(weak);
  assert.ok(before.graded.some((g) => g.startsWith('spf:spf_plus_all:')));
  assert.ok(before.graded.some((g) => g.startsWith('dmarc:dmarc_policy_none:')));
  const after = await run({ ...weak, [`TXT ${ZONE}`]: 'ETIMEOUT', [`TXT _dmarc.${ZONE}`]: 'ESERVFAIL' });
  assert.deepEqual(after.graded.filter((g) => g.startsWith('spf:') || g.startsWith('dmarc:')), []);
  assert.deepEqual(after.notMeasured.filter((e) => ['spf', 'dmarc'].includes(e.check)).map((e) => `${e.check}:${e.code}`),
    ['spf:ETIMEOUT', 'dmarc:ESERVFAIL']);
});

// ── WHAT COUNTS AS AN ABSENCE ──────────────────────────────────────────────────────────────────────────────────────────
for (const code of ['ESERVFAIL', 'EREFUSED', 'ECONNREFUSED', 'EBADRESP', 'ECANCELLED', 'ETIMEOUT']) {
  test(`${code} is not an absence`, async () => {
    const { graded, notMeasured } = await run({ ...PRESENT, [`TXT ${ZONE}`]: code });
    assert.deepEqual(notMeasured.map((e) => `${e.check}:${e.code}`), [`spf:${code}`]);
    assert.ok(!graded.includes('spf:missing_spf:high'));
  });
}
test('an error with no code at all is not an absence either', async () => {
  const { notMeasured } = await run({ ...PRESENT, [`TXT ${ZONE}`]: { message: 'resolver crashed' } });
  assert.deepEqual(checksOf(notMeasured), ['spf']);
});
for (const code of ['ENODATA', 'ENOTFOUND']) {
  test(`${code} on the SPF lookup is a measured absence: missing_spf, nothing recorded, still up`, async () => {
    const { result, graded, notMeasured } = await run({ ...PRESENT, [`TXT ${ZONE}`]: code });
    assert.ok(graded.includes('spf:missing_spf:high'));
    assert.deepEqual(notMeasured, []);
    assert.equal(result.up, true);
  });
}

// ── THE CHECKS THAT ASK MORE THAN ONE QUESTION ─────────────────────────────────────────────────────────────────────────
test('DKIM: a found selector beside a timed-out one — the found selector is measured, and the timed-out lookup is recorded (G-71 F-060)', async () => {
  const { graded, notMeasured } = await run({ ...PRESENT, [`TXT default._domainkey.${ZONE}`]: 'ETIMEOUT' });
  assert.deepEqual(notMeasured.map((e) => `${e.check}:${e.name}:${e.code}:${e.partial}`), [`dkim:default._domainkey.${ZONE}:ETIMEOUT:true`]);
  assert.ok(!graded.some((g) => g.startsWith('dkim:dkim_none_found')));
});
test('DKIM: no selector found and every lookup an absence is the measured dkim_none_found', async () => {
  const { graded, notMeasured } = await run({ ...PRESENT, [`TXT google._domainkey.${ZONE}`]: 'ENOTFOUND' });
  assert.ok(graded.includes('dkim:dkim_none_found:medium'));
  assert.deepEqual(notMeasured, []);
});
test('DNSSEC: timed-out DNSKEY and DS, but the ANY fallback shows both — measured, active', async () => {
  const { graded, notMeasured } = await run({ ...PRESENT, [`DNSKEY ${ZONE}`]: 'ETIMEOUT', [`DS ${ZONE}`]: 'ETIMEOUT',
    [`ANY ${ZONE}`]: [{ type: 'DNSKEY' }, { type: 'DS' }] });
  assert.deepEqual(notMeasured, []);
  assert.ok(graded.includes('dnssec:dnssec_active:pass'));
});
test('DNSSEC: a timed-out DNSKEY beside an absent DS, the ANY fallback refused — not measured, never no_dnssec', async () => {
  const { graded, notMeasured } = await run({ ...PRESENT, [`DNSKEY ${ZONE}`]: 'ETIMEOUT', [`DS ${ZONE}`]: 'ENODATA',
    [`ANY ${ZONE}`]: 'EREFUSED' });
  assert.deepEqual(notMeasured.map((e) => `${e.check}:${e.rrtype}:${e.code}`), ['dnssec:DNSKEY:ETIMEOUT']);
  assert.ok(!graded.some((g) => g.startsWith('dnssec:')));
});
test('DNSSEC: both absent and the ANY fallback refused is the measured no_dnssec (a refused ANY is expected)', async () => {
  const { graded, notMeasured } = await run({ ...PRESENT, [`DNSKEY ${ZONE}`]: 'ENODATA', [`DS ${ZONE}`]: 'ENODATA',
    [`ANY ${ZONE}`]: 'EREFUSED' });
  assert.ok(graded.includes('dnssec:no_dnssec:medium'));
  assert.deepEqual(notMeasured, []);
});
test('MX: an absent MX beside a present A is the measured no_mx_a_fallback', async () => {
  const { graded, notMeasured } = await run({ ...PRESENT, [`MX ${ZONE}`]: 'ENODATA' });
  assert.ok(graded.includes('mx:no_mx_a_fallback:low'));
  assert.deepEqual(notMeasured, []);
});
test('MX: an absent MX, an A that timed out and no AAAA — the fallback is unknown, so MX is not measured', async () => {
  const { graded, notMeasured } = await run({ ...PRESENT, [`MX ${ZONE}`]: 'ENODATA', [`A ${ZONE}`]: 'ETIMEOUT' });
  assert.deepEqual(notMeasured.map((e) => `${e.check}:${e.rrtype}`), ['mx:A']);
  assert.ok(!graded.some((g) => g.startsWith('mx:')));
});
test('NS: a nameserver whose address is NXDOMAIN is still the measured lame delegation', async () => {
  const { graded, notMeasured } = await run({ ...PRESENT, [`A ns1.${ZONE}`]: 'ENOTFOUND' });
  assert.ok(graded.includes('ns:ns_lame_delegation:high'));
  assert.deepEqual(notMeasured, []);
});
const TARGET = 'app.vendor.test';
test('CNAME: a target that answers neither A nor AAAA (both absences) is the measured dangling_cname', async () => {
  const { graded, notMeasured } = await run({ ...PRESENT, [`CNAME ${ZONE}`]: [TARGET] });
  assert.ok(graded.includes('cname:dangling_cname:critical'));
  assert.deepEqual(notMeasured, []);
});
test('CNAME: a target whose A lookup timed out (AAAA absent) is not measured — never dangling, never "resolves"', async () => {
  const { graded, notMeasured } = await run({ ...PRESENT, [`CNAME ${ZONE}`]: [TARGET], [`A ${TARGET}`]: 'ETIMEOUT' });
  assert.deepEqual(notMeasured.map((e) => `${e.check}:${e.rrtype}:${e.name}:${e.code}`), [`cname:A:${TARGET}:ETIMEOUT`]);
  assert.ok(!graded.some((g) => g.startsWith('cname:dangling_cname')));
});
test('CNAME: a target whose A answers is measured — not dangling, nothing recorded, though its AAAA timed out', async () => {
  const { graded, notMeasured } = await run({ ...PRESENT, [`CNAME ${ZONE}`]: [TARGET], [`A ${TARGET}`]: ['192.0.2.20'],
    [`AAAA ${TARGET}`]: 'ETIMEOUT' });
  assert.deepEqual(notMeasured, []);
  assert.ok(!graded.some((g) => g.startsWith('cname:dangling_cname')));
});

test('wildcard: a random name that answers is the measured wildcard_dns', async () => {
  const { graded, notMeasured } = await run({ ...PRESENT, [WILDCARD]: ['192.0.2.99'] });
  assert.ok(graded.includes('wildcard:wildcard_dns:low'));
  assert.deepEqual(notMeasured, []);
});

// ── WHAT THE RESULT SAYS ───────────────────────────────────────────────────────────────────────────────────────────────
test('the reason names the checks not measured with their codes, and the checks that were', async () => {
  const { result } = await run({ ...PRESENT, [`TXT ${ZONE}`]: 'ETIMEOUT', [`CAA ${ZONE}`]: 'ETIMEOUT',
    [`TXT google._domainkey.${ZONE}`]: 'ESERVFAIL' });
  assert.equal(result.reason,
    'resolver failure on SPF, CAA (ETIMEOUT) and DKIM (ESERVFAIL): those 3 checks are not measured; '
    + 'CNAME, DMARC, NS, DNSSEC, MX and wildcard were measured and their findings are in the result');
});
test('status: action_required still wins over not measured; a measured finding stays in the result', async () => {
  const { result, record, graded } = await run({ ...PRESENT, [`TXT ${ZONE}`]: 'ETIMEOUT',
    [`TXT _dmarc.${ZONE}`]: [['v=DMARC1; p=none']] });
  assert.ok(graded.some((g) => g.startsWith('dmarc:dmarc_policy_none:')));
  assert.equal(result.up, false);
  assert.equal(record.dnsSecurity.status, 'action_required');
  assert.ok(record.dnsSecurity.findings.some((f) => f.check === 'dmarc_policy_none'));
  assert.deepEqual(record.dnsSecurity.notMeasured.map((e) => e.check), ['spf']);
});
test('through the concluder: the not-measured record reaches the 53/udp service with its status, findings kept', async () => {
  const { default: concluder } = await import('../plugins/result_concluder.mjs');
  const { result } = await run({ ...PRESENT, [`TXT ${ZONE}`]: 'ETIMEOUT', [`TXT _dmarc.${ZONE}`]: [['v=DMARC1; p=none']] });
  const dns009 = { id: '009', name: 'dns_scanner', result: { up: true, program: 'BIND', version: '9.18',
    data: [{ probe_port: 53, probe_protocol: 'udp', probe_info: 'version.bind' }] } };
  const { services } = await concluder.run([dns009, { id: '060', name: 'DNS Security Auditor', result }]);
  const rec = services.find((s) => s.port === 53 && s.protocol === 'udp');
  assert.ok(rec, 'the 53/udp record is concluded');
  assert.deepEqual(rec.dnsSecurity?.notMeasured?.map((e) => `${e.check}:${e.code}`), ['spf:ETIMEOUT']);
  assert.equal(rec.dnsSecurity?.status, 'action_required');
  assert.ok(rec.dnsSecurity?.findings?.some((f) => f.check === 'dmarc_policy_none'), 'a measured finding is kept');
  assert.ok(!rec.dnsSecurity?.findings?.some((f) => f.check === 'missing_spf'));
});

// ── THE HISTORY DELTA: a run that did not measure the audit never clears the previous run's findings ─────────────────
async function historyLine(table) {
  const [{ default: concluder }, { historyServiceEntry, historyHostEntry }, { FINDINGS_COUNT_BASIS }] = await Promise.all([
    import('../plugins/result_concluder.mjs'), import('../utils/scan_history.mjs'), import('../utils/report_inputs.mjs')]);
  const { result } = await run(table);
  const c = await concluder.run([{ id: '060', name: 'DNS Security Auditor', result }]);
  return { findingsCount: 0, findingsCountBasis: FINDINGS_COUNT_BASIS, tier: 'pro',
    services: c.services.map(historyServiceEntry), ...historyHostEntry({ result: c }) };
}
const WEAK = { ...PRESENT, [`TXT ${ZONE}`]: [['v=spf1 +all']], [`TXT _dmarc.${ZONE}`]: [['v=DMARC1; p=none']] };
const hostChange = (d) => d.changedFlags.find((c) => c.port == null) ?? { appeared: [], cleared: [], notCompared: [] };

test('(delta, first) a weak record FIXED between two measured runs still reads cleared', async () => {
  const { computeDiff } = await import('../utils/scan_history.mjs');
  const d = computeDiff(await historyLine(PRESENT), await historyLine(WEAK));
  const h = hostChange(d);
  assert.ok(h.cleared.includes('dnsSecurity:spf_plus_all') && h.cleared.includes('dnsSecurity:dmarc_policy_none'), JSON.stringify(h));
  assert.deepEqual(h.notCompared ?? [], []);
});
test('(delta) every lookup timing out after a measured run clears nothing: the findings are not compared, with why', async () => {
  const { computeDiff } = await import('../utils/scan_history.mjs');
  const dead = new Proxy({}, { has: () => true, get: () => 'ETIMEOUT' });
  const d = computeDiff(await historyLine(dead), await historyLine(WEAK));
  const h = hostChange(d);
  assert.deepEqual(h.cleared, [], 'a run that could not measure the audit cleared nothing');
  assert.deepEqual(h.appeared, []);
  const notCompared = (h.notCompared ?? []).map((n) => n.cid ?? n);
  for (const cid of ['dnsSecurity:spf_plus_all', 'dnsSecurity:dmarc_policy_none']) {
    assert.ok(JSON.stringify(h.notCompared).includes(cid), `${cid} not compared: ${JSON.stringify(h.notCompared)}`);
  }
  assert.match(JSON.stringify(h.notCompared), /DNS lookup/);
  assert.ok(notCompared.length > 0);
});

// ── PER CHECK: a check this run DID measure still compares; one it could not measure never clears ──────────────────────
test('(delta, per check, first) SPF fixed while CAA timed out: the SPF fix reads cleared — CAA\'s failure does not hide it', async () => {
  const { computeDiff } = await import('../utils/scan_history.mjs');
  const d = computeDiff(await historyLine({ ...WEAK, [`TXT ${ZONE}`]: [['v=spf1 -all']], [`CAA ${ZONE}`]: 'ETIMEOUT' }),
    await historyLine(WEAK));
  const h = hostChange(d);
  assert.ok(h.cleared.includes('dnsSecurity:spf_plus_all'), JSON.stringify(h));
  assert.ok(!JSON.stringify(h.notCompared ?? []).includes('dnsSecurity:dmarc_policy_none'), 'a finding of a measured check is compared');
});
test('(delta, per check) a CAA finding, then CAA unmeasured: not compared with why, never cleared — the other checks still compare', async () => {
  const { computeDiff } = await import('../utils/scan_history.mjs');
  const before = { ...WEAK, [`CAA ${ZONE}`]: 'ENODATA' };
  const d = computeDiff(await historyLine({ ...before, [`CAA ${ZONE}`]: 'ETIMEOUT', [`TXT ${ZONE}`]: [['v=spf1 -all']] }),
    await historyLine(before));
  const h = hostChange(d);
  assert.ok(!h.cleared.includes('dnsSecurity:no_caa'), JSON.stringify(h));
  assert.ok(JSON.stringify(h.notCompared).includes('dnsSecurity:no_caa'));
  assert.match(JSON.stringify(h.notCompared), /not measured this run/);
  assert.ok(h.cleared.includes('dnsSecurity:spf_plus_all'), 'the SPF fix in the same run still reads cleared');
});

// ── THE CODE A HISTORY LINE RECORDS: one cause, one code — Enterprise's comparison names the same cause the same way ─
test('(delta) the history line records why an unmeasured check was not tried as `check-not-measured`', async () => {
  const line = await historyLine({ ...WEAK, [`CAA ${ZONE}`]: 'ETIMEOUT' });
  assert.equal(line.hostChecks.dnsSecurity.notTried, 'check-not-measured');
  assert.ok(!line.hostChecks.dnsSecurity.tried.includes('no_caa') && line.hostChecks.dnsSecurity.tried.includes('spf_plus_all'));
});
test('(delta) a line recording any other code for an untried check is still not compared — never cleared', async () => {
  const { computeDiff } = await import('../utils/scan_history.mjs');
  const before = await historyLine({ ...WEAK, [`CAA ${ZONE}`]: 'ENODATA' });
  const now = await historyLine({ ...WEAK, [`CAA ${ZONE}`]: 'ETIMEOUT' });
  // The spelling a pre-release build wrote before the code was aligned; no release wrote it.
  now.hostChecks.dnsSecurity = { ...now.hostChecks.dnsSecurity, notTried: 'dns-check-not-measured' };
  const h = hostChange(computeDiff(now, before));
  assert.ok(!h.cleared.includes('dnsSecurity:no_caa'), JSON.stringify(h));
  assert.ok(JSON.stringify(h.notCompared).includes('dnsSecurity:no_caa'), JSON.stringify(h));
});

// ── `report --since`: the cross-run delta reads the same record ─────────────────────────────────────────────────────
async function reportSide(id, table) {
  const [{ shapeHostFindings }] = await Promise.all([import('../utils/report_inputs.mjs')]);
  const { result } = await run(table);
  return { record: { schema: 1, runId: id, startedAt: '2026-01-01T00:00:00Z', finishedAt: '2026-01-01T00:10:00Z',
    hostsRequested: [ZONE], hostsWritten: [{ host: ZONE, dir: 'd' }], pluginsRequested: ['060'], portsRequested: null,
    tier: 'pro', ceVersion: '1.0.0', eeVersion: null, kevLoaded: false, kevSnapshot: null, epssLoaded: false, epssSnapshot: null },
  // A run whose 060 lookups failed is still `ran` in the manifest: the plugin completed and recorded what it could not measure.
  pluginStatus: [{ host: ZONE, status: [{ id: '060', status: 'ran' }] }],
  findings: shapeHostFindings(ZONE, { results: [{ id: '060', name: 'DNS Security Auditor', result }] }) };
}
test('(report, first) a weak record FIXED between two measured runs is still reported resolved', async () => {
  const { buildScanDelta } = await import('../utils/scan_delta.mjs');
  const d = buildScanDelta({ baseline: await reportSide('A', WEAK), current: await reportSide('B', PRESENT) });
  assert.ok(d.resolved.some((r) => /\+all/.test(r.title ?? '')), JSON.stringify(d.resolved.map((r) => r.title)));
  assert.deepEqual(d.notComparable, []);
});
test('(report) a run that could not measure the audit resolves nothing: the baseline\'s DNS rows are not comparable', async () => {
  const { buildScanDelta } = await import('../utils/scan_delta.mjs');
  const dead = new Proxy({}, { has: () => true, get: () => 'ETIMEOUT' });
  const baseline = await reportSide('A', WEAK);
  const d = buildScanDelta({ baseline, current: await reportSide('B', dead) });
  assert.deepEqual(d.resolved, [], 'nothing was fixed: nothing was looked at');
  assert.ok(d.notComparable.length > 0 && d.notComparable.every((n) => n.reason === 'evidence-gap'), JSON.stringify(d.notComparable));
  assert.match(d.notComparable[0].detail, /not measured/);
});
test('(report) the not-measured record is a shaped evidence-gap row per check, never a finding', async () => {
  const { shapeHostFindings } = await import('../utils/report_inputs.mjs');
  const { result } = await run({ ...PRESENT, [`TXT ${ZONE}`]: 'ETIMEOUT' });
  const rows = shapeHostFindings(ZONE, { results: [{ id: '060', name: 'DNS Security Auditor', result }] });
  const gaps = rows.filter((r) => r.evidenceGap === true);
  assert.equal(gaps.length, 1);
  assert.equal(gaps[0].severity, 'INFO');
  assert.equal(gaps[0].title, 'Evidence gap: the SPF check was not measured — the TXT lookup for example.test failed (ETIMEOUT)');
  const { result: measured } = await run(PRESENT);
  assert.ok(!shapeHostFindings(ZONE, { results: [{ id: '060', name: 'DNS Security Auditor', result: measured }] })
    .some((r) => r.evidenceGap === true), 'a fully measured run carries no gap row');
});

test('a timed-out SOA is not "no SOA": hasSOA is null, not false', async () => {
  const measured = await run(PRESENT);
  assert.equal(measured.result.records.hasSOA, true);
  const { result } = await run({ ...PRESENT, [`SOA ${ZONE}`]: 'ETIMEOUT' });
  assert.equal(result.records.hasSOA, null);
});

// ── G-71 F-060 (EE Z-1, architect RULINGS-v402 §4): EVERY DKIM selector lookup that failed to measure is recorded, a
// selector found or not. Until now only the FIRST failure was kept, and only when no selector was found, so a weak-key row
// on a selector that now SERVFAILs read RESOLVED beside a selector that still resolves (driven on the real CLI:
// Z/g71-drive-v345, arm 060-dkim). A failed lookup beside a found selector is marked `partial`: the check measured the
// selectors that answered. An entry carries the lookup only (check, rrtype, the name built from the configured selector,
// an error CODE, partial) — no text from the reply, and never an error message: under G-72 R1 the gap row reaches the md
// that MCP scan_host returns. FOURTH QUADRANT FIRST: a lookup ANSWERED negatively is a measured removal, never an entry.
const dkimEntries = (nm) => nm.filter((e) => e.check === 'dkim');
const WEAK_DKIM = [[`v=DKIM1; k=rsa; p=${'A'.repeat(86)}`]];   // ~520 bits: dkim_weak_key
const SHORT_DKIM = [[`v=DKIM1; k=rsa; p=${'B'.repeat(172)}`]]; // ~1032 bits: dkim_short_key
test('F-060 (accept, first): a found selector beside one ANSWERED negatively is measured — no entry, no dkim_none_found, up', async () => {
  for (const code of ['ENOTFOUND', 'ENODATA']) {
    const { result, graded, notMeasured } = await run({ ...PRESENT, [`TXT default._domainkey.${ZONE}`]: code });
    assert.deepEqual(notMeasured, [], code);
    assert.equal(result.up, true, code);
    assert.ok(!graded.some((g) => g.startsWith('dkim:dkim_none_found')), code);
  }
});
test('F-060: a found selector beside a timed-out one — that lookup is recorded, partial; the found selector keeps its row; not up; the reason says partly', async () => {
  const { result, graded, notMeasured } = await run({ ...PRESENT, [`TXT google._domainkey.${ZONE}`]: WEAK_DKIM,
    [`TXT default._domainkey.${ZONE}`]: 'ETIMEOUT' });
  assert.deepEqual(notMeasured, [{ check: 'dkim', rrtype: 'TXT', name: `default._domainkey.${ZONE}`, code: 'ETIMEOUT', partial: true }]);
  assert.ok(graded.includes('dkim:dkim_weak_key:high'));
  assert.deepEqual(result.details.dkimSelectors.map((x) => x.selector), ['google']);
  assert.equal(result.up, false);
  assert.equal(result.reason,
    'resolver failure on DKIM (ETIMEOUT): DKIM is partly measured — a selector lookup that failed measured nothing, and the '
    + 'selectors that answered are in the result; CNAME, SPF, DMARC, NS, DNSSEC, MX, CAA and wildcard were measured and their '
    + 'findings are in the result');
});
test('F-060: no selector found and BOTH lookups failed — both recorded, in selector order, neither partial; no dkim_none_found', async () => {
  const { graded, notMeasured } = await run({ ...PRESENT, [`TXT google._domainkey.${ZONE}`]: 'ESERVFAIL',
    [`TXT default._domainkey.${ZONE}`]: 'ETIMEOUT' });
  assert.deepEqual(dkimEntries(notMeasured), [
    { check: 'dkim', rrtype: 'TXT', name: `google._domainkey.${ZONE}`, code: 'ESERVFAIL' },
    { check: 'dkim', rrtype: 'TXT', name: `default._domainkey.${ZONE}`, code: 'ETIMEOUT' }]);
  assert.ok(!graded.some((g) => g.startsWith('dkim:dkim_none_found')));
});
test('F-060: a DKIM entry never carries an error message — a failure with no code is recorded as ENOCODE', async () => {
  const { notMeasured } = await run({ ...PRESENT, [`TXT default._domainkey.${ZONE}`]: { message: 'zqremote reply text' } });
  assert.deepEqual(dkimEntries(notMeasured), [
    { check: 'dkim', rrtype: 'TXT', name: `default._domainkey.${ZONE}`, code: 'ENOCODE', partial: true }]);
  assert.ok(!JSON.stringify(notMeasured).includes('zqremote'));
});

// F-060 through the REAL `report --since`: the conclusion file is written by the REAL scanSingleHost (the real 060 object,
// its run() handing back the result driven above), the run record by the real record writers; nothing here is written by
// the test. The delta's reading is taken by row title from the stdout (held rows) and from the written page (every row).
const SINCE_HOST_060 = '192.0.2.10';
const conclusionFiles060 = (root) => fs.readdirSync(root, { recursive: true }).map(String).filter((f) => f.endsWith('scan_conclusion_raw.json'));
async function scanWritten060(outRoot, result, runId) {
  const keep = { out: process.env.SCAN_OUT_PATH, lic: process.env.NSAUDITOR_LICENSE_KEY, ai: process.env.OPENAI_OUT_PATH };
  process.env.SCAN_OUT_PATH = outRoot; process.env.NSAUDITOR_LICENSE_KEY = 'not-a-licence'; delete process.env.OPENAI_OUT_PATH;
  try {
    const { scanSingleHost } = await import('../cli.mjs');
    const { default: PluginManager } = await import('../plugin_manager.mjs');
    const { default: concluder } = await import('../plugins/result_concluder.mjs');
    const pm = await PluginManager.create({ plugins: [{ ...dnsSec, requirements: {}, runStrategy: 'single', run: async () => result }, concluder] });
    const absent = () => { throw Object.assign(new Error('not installed'), { code: 'MODULE_NOT_FOUND' }); };
    const before = new Set(conclusionFiles060(outRoot));
    await scanSingleHost(pm, SINCE_HOST_060, 'all', { resolveEE: absent, runId }, 'basic');
    const made = conclusionFiles060(outRoot).filter((f) => !before.has(f));
    assert.equal(made.length, 1, `scanSingleHost wrote one conclusion file: ${made}`);
    const j = JSON.parse(fs.readFileSync(path.join(outRoot, made[0]), 'utf8'));
    // The premise every arm depends on: the manifest records 060 as RAN — a held row is then the gap's doing, not the status's.
    assert.equal(j.pluginStatus?.find((p) => String(p?.id) === '060')?.status, 'ran', 'the conclusion file records 060 as ran');
  } finally {
    for (const [k, v] of [['SCAN_OUT_PATH', keep.out], ['NSAUDITOR_LICENSE_KEY', keep.lic], ['OPENAI_OUT_PATH', keep.ai]]) {
      if (v === undefined) delete process.env[k]; else process.env[k] = v;
    }
  }
}
const pageRows060 = (page) => {
  const at = page.indexOf('Since Last Scan');
  const sect = at < 0 ? '' : page.slice(at, page.indexOf('</table>', at));
  const strip = (x) => x.replace(/<[^>]+>/g, ' ').replace(/&quot;/g, '"').replace(/&amp;/g, '&').replace(/\s+/g, ' ').trim();
  return (sect.match(/<tr[\s\S]*?<\/tr>/g) ?? []).slice(1).map((tr) => (tr.match(/<td[\s\S]*?<\/td>/g) ?? []).map(strip));
};
async function since060(beforeTable, afterTable) {
  const { runReport } = await import('../cli.mjs');
  const { resolveCapabilities } = await import('../utils/capabilities.mjs');
  const { newRunId, writeRunStart, finalizeRunRecord } = await import('../utils/run_record.mjs');
  const { sealRunRecord } = await import('../utils/run_chain.mjs');
  const outRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-dkim-since-'));
  const mk = async (startedAt, table) => {
    const { result } = await run(table);
    const runId = newRunId();
    await writeRunStart(outRoot, { runId, startedAt, hostsRequested: [SINCE_HOST_060], pluginsRequested: ['060'], portsRequested: '',
      tier: 'pro', ceVersion: '0.2.54', eeVersion: null, prevDigest: null });
    await scanWritten060(outRoot, result, runId);
    await finalizeRunRecord(outRoot, runId, { finishedAt: startedAt });
    await sealRunRecord(outRoot, runId);
    return runId;
  };
  const a = await mk('2026-09-01T10:00:00.000Z', beforeTable); const b = await mk('2026-09-08T10:00:00.000Z', afterTable);
  const rep = await runReport({ from: outRoot, format: 'executive', run: b, since: a, out: path.join(outRoot, 'exec.html') }, resolveCapabilities('pro'));
  assert.equal(rep.code, 0, rep.stderr);
  const m = rep.stdout.match(/(\d+) new · (\d+) resolved · (\d+) changed · (\d+) not-comparable · (\d+) unchanged/);
  assert.ok(m, `the delta line: ${rep.stdout.slice(0, 300)}`);
  const rows = pageRows060(fs.readFileSync(path.join(outRoot, 'exec.html'), 'utf8'));
  return { stdout: rep.stdout, n: { new: +m[1], resolved: +m[2], notComparable: +m[4], unchanged: +m[5] },
    change: (title) => rows.filter((r) => r[1] === title).map((r) => r[0]) };
}
const DKIM_BASE = { ...PRESENT, [`TXT google._domainkey.${ZONE}`]: WEAK_DKIM, [`TXT default._domainkey.${ZONE}`]: SHORT_DKIM };
const WEAK_TITLE = 'DKIM selector "google" has a weak key (~520 bits) — minimum 1024, recommended 2048';
const SHORT_TITLE = 'DKIM selector "default" uses ~1032-bit key — 2048+ recommended';
test('F-060 report --since (accept, first): google now ANSWERED negatively beside default resolving — its row reads RESOLVED', async () => {
  const d = await since060(DKIM_BASE, { ...DKIM_BASE, [`TXT google._domainkey.${ZONE}`]: 'ENOTFOUND' });
  assert.deepEqual(d.change(WEAK_TITLE), ['resolved'], d.stdout);
  assert.equal(d.n.resolved, 1, d.stdout);
  assert.equal(d.n.notComparable, 0, d.stdout);
});
test('F-060 report --since: nothing changed — 0 resolved, both DKIM rows unchanged', async () => {
  const d = await since060(DKIM_BASE, DKIM_BASE);
  assert.equal(d.n.resolved, 0, d.stdout);
  assert.equal(d.n.notComparable, 0, d.stdout);
});
test('F-060 report --since (the red arm, 060-dkim): google now SERVFAILs beside default resolving — its row reads NOT COMPARABLE, held by the partial gap', async () => {
  const d = await since060(DKIM_BASE, { ...DKIM_BASE, [`TXT google._domainkey.${ZONE}`]: 'ESERVFAIL' });
  assert.equal(d.n.resolved, 0, d.stdout);
  assert.deepEqual(d.change(WEAK_TITLE), ['not-comparable'], d.stdout);
  const held = d.stdout.split('\n').find((l) => l.includes(`NOT COMPARABLE (disappeared)  ${WEAK_TITLE} — evidence-gap: `));
  assert.ok(held, d.stdout);
  assert.match(held, /Evidence gap: the DKIM check was not fully measured — the TXT lookup for google\._domainkey\.example\.test failed \(ESERVFAIL\)/);
});
test('F-060 report --since (control, 060-n): both selectors SERVFAIL — both DKIM rows NOT COMPARABLE, and the gap text says not measured', async () => {
  const d = await since060(DKIM_BASE, { ...DKIM_BASE, [`TXT google._domainkey.${ZONE}`]: 'ESERVFAIL', [`TXT default._domainkey.${ZONE}`]: 'ESERVFAIL' });
  assert.equal(d.n.resolved, 0, d.stdout);
  for (const t of [WEAK_TITLE, SHORT_TITLE]) assert.deepEqual(d.change(t), ['not-comparable'], `${t}\n${d.stdout}`);
  // Neither entry is partial (no selector answered), so the text the hold cites says NOT measured. Since VERDICT-v403 R3 it
  // is ONE row for the check, naming both lookups in selector order.
  assert.match(d.stdout, /Evidence gap: the DKIM check was not measured — 2 TXT lookups failed: google\._domainkey\.example\.test \(ESERVFAIL\), default\._domainkey\.example\.test \(ESERVFAIL\)/);
  assert.doesNotMatch(d.stdout, /not fully measured/);
});
test('F-060 STATED LIMIT: the hold is the 060 gap\'s, host-wide — an SPF fix in the same run as a DKIM selector failure reads NOT COMPARABLE, never resolved', async () => {
  const d = await since060({ ...DKIM_BASE, [`TXT ${ZONE}`]: [['v=spf1 +all']] },
    { ...DKIM_BASE, [`TXT ${ZONE}`]: [['v=spf1 -all']], [`TXT google._domainkey.${ZONE}`]: 'ESERVFAIL' });
  assert.equal(d.n.resolved, 0, d.stdout);
  assert.ok(d.n.notComparable >= 2, d.stdout);
});

// ── G-71 F-060 R1–R3 (EE Z-1, architect VERDICT-v403) ─────────────────────────────────────────────────────────────────────
// R1: an entry's code is code-shaped or ENOCODE for EVERY check, applied where all entries pass (the sort into check
// order): `safeResolve` falls back to an error's MESSAGE when it has no code, and the message reached the reason and the gap
// row. The END anchor is load-bearing: a message that only BEGINS with a code-shaped token is still a message.
// FOURTH QUADRANT FIRST: a code-shaped code — Node's own ERR_INVALID_ARG_VALUE among them — is kept as it is.
async function runWith(table, dkimSelectors) {
  TABLE = table;
  const result = await dnsSec.run(ZONE, 0, { dkimSelectors });
  return { result, notMeasured: result.details?.notMeasured ?? [] };
}
const gapRows = async (result) => {
  const { shapeHostFindings } = await import('../utils/report_inputs.mjs');
  return shapeHostFindings(ZONE, { results: [{ id: '060', name: 'DNS Security Auditor', result }] }).filter((r) => r.evidenceGap === true);
};
test('F-060 R1 (accept, first): a code-shaped code is kept as it is — ERR_INVALID_ARG_VALUE on DNSKEY, ESERVFAIL on SPF', async () => {
  const { result, notMeasured } = await run({ ...PRESENT, [`DNSKEY ${ZONE}`]: 'ERR_INVALID_ARG_VALUE', [`DS ${ZONE}`]: 'ENODATA',
    [`TXT ${ZONE}`]: 'ESERVFAIL' });
  assert.deepEqual(notMeasured.map((e) => `${e.check}:${e.rrtype}:${e.code}`), ['spf:TXT:ESERVFAIL', 'dnssec:DNSKEY:ERR_INVALID_ARG_VALUE']);
  assert.match(result.reason, /^resolver failure on SPF \(ESERVFAIL\) and DNSSEC \(ERR_INVALID_ARG_VALUE\): /);
});
test('F-060 R1: a codeless DKIM failure whose message BEGINS with a code-shaped token is ENOCODE — no message text anywhere in the result', async () => {
  // The fixture's own shape: it begins with a code-shaped token and is not one, so only the END anchor refuses it.
  assert.ok(/^E[A-Z0-9_]+/.test('ESERVFAIL zqremote reply text') && !/^E[A-Z0-9_]+$/.test('ESERVFAIL zqremote reply text'));
  const { result, notMeasured } = await run({ ...PRESENT, [`TXT default._domainkey.${ZONE}`]: { raw: 'ESERVFAIL zqremote reply text' } });
  assert.deepEqual(dkimEntries(notMeasured), [
    { check: 'dkim', rrtype: 'TXT', name: `default._domainkey.${ZONE}`, code: 'ENOCODE', partial: true }]);
  assert.ok(!JSON.stringify(result).includes('zqremote'), JSON.stringify(result.details.notMeasured));
});
test('F-060 R1: a codeless failure on any other check is ENOCODE too — the entry, the reason and the gap row carry no message text', async () => {
  for (const [form, message] of [['message', 'resolver crashed zqremote'], ['raw', 'ETIMEOUT zqremote reply text']]) {
    const { result, notMeasured } = await run({ ...PRESENT, [`CAA ${ZONE}`]: { [form]: message } });
    assert.deepEqual(notMeasured, [{ check: 'caa', rrtype: 'CAA', name: ZONE, code: 'ENOCODE' }], message);
    assert.ok(!result.reason.includes('zqremote'), result.reason);
    assert.match(result.reason, /^resolver failure on CAA \(ENOCODE\): /, message);
    const rows = await gapRows(result);
    assert.deepEqual(rows.map((r) => r.title), ['Evidence gap: the CAA check was not measured — the CAA lookup for example.test failed (ENOCODE)'], message);
  }
});

// R2: THE HOLD IS host|060 IN BOTH DIRECTIONS. A baseline that recorded one failed DKIM lookup beside a found selector holds
// a row that APPEARS in a fully measured current run, as well as one that vanished: a NEW SPF exposure reads not comparable,
// never new. This is a STATED LIMIT, pinned so a change to it is a decision: the repair is a hold keyed on the check (a
// scan_delta.mjs rule, boarded beside 040's port-scoped hold).
const SPF_PLUS_ALL_TITLE = 'SPF uses "+all" — permits ALL senders, completely defeats SPF purpose';
test('F-060 STATED LIMIT (the other direction): a baseline with one failed DKIM lookup beside a found selector — a NEW SPF row in a fully measured run reads NOT COMPARABLE, held by the baseline\'s gap, never new', async () => {
  const d = await since060({ ...DKIM_BASE, [`TXT google._domainkey.${ZONE}`]: 'ESERVFAIL' }, { ...DKIM_BASE, [`TXT ${ZONE}`]: [['v=spf1 +all']] });
  assert.equal(d.n.new, 0, d.stdout);
  assert.deepEqual(d.change(SPF_PLUS_ALL_TITLE), ['not-comparable'], d.stdout);
  const held = d.stdout.split('\n').find((l) => l.includes(`NOT COMPARABLE (appeared)  ${SPF_PLUS_ALL_TITLE} — evidence-gap: `));
  assert.ok(held, d.stdout);
  assert.match(held, /recorded an evidence gap on .*: Evidence gap: the DKIM check was not fully measured — the TXT lookup for google\._domainkey\.example\.test failed \(ESERVFAIL\)/);
  // The google row appears too, and its hold is the gap doing its job: the baseline could not read that selector.
  assert.deepEqual(d.change(WEAK_TITLE), ['not-comparable'], d.stdout);
});

// R3: ONE synthesised gap row PER CHECK, naming every failed lookup with its code; `details.notMeasured` stays one entry per
// lookup. With the resolver down and 18 selectors configured the md listed 18 DKIM lines with one cause, burying the other
// checks' gaps, and Enterprise already writes one gap per check. A check with ONE entry keeps the one-lookup sentence byte
// for byte (the SPF leg under "(report)" above and the red arm hold it). "Not fully" when every entry of the check is
// partial, the rule the reason uses.
test('F-060 R3: the resolver down with the default selectors — ONE DKIM gap row naming every failed lookup with its code; one gap row per check', async () => {
  const dead = new Proxy({}, { has: () => true, get: () => 'ETIMEOUT' });
  TABLE = dead;
  const result = await dnsSec.run(ZONE, 0, {});
  const nm = result.details.notMeasured;
  const dk = dkimEntries(nm);
  assert.equal(dk.length, 18, 'premise: the default selector list is 18 names and every lookup failed');
  const rows = await gapRows(result);
  assert.equal(rows.length, new Set(nm.map((e) => e.check)).size, rows.map((r) => r.title).join('\n'));
  const dkimRows = rows.filter((r) => r.title.startsWith('Evidence gap: the DKIM check '));
  const whole = `Evidence gap: the DKIM check was not measured — 18 TXT lookups failed: ${dk.map((e) => `${e.name} (ETIMEOUT)`).join(', ')}`;
  // The md and executive listings print coverageGapText, which recovers the whole text from the row's detail; the TITLE is the
  // row's identity and takes the shared 160-character cut, as every long title does.
  const { coverageGapText } = await import('../utils/report_inputs.mjs');
  const { cutAtWord } = await import('../utils/cloud_finding_summary.mjs');
  assert.deepEqual(dkimRows.map((r) => coverageGapText(r)), [whole]);
  assert.deepEqual(dkimRows.map((r) => r.title), [cutAtWord(whole)]);
});
test('F-060 R3: a partial check and a fully unmeasured check in one run — two rows, each in its own words, in check order', async () => {
  const { result } = await runWith({ ...PRESENT, [`TXT google._domainkey.${ZONE}`]: WEAK_DKIM, [`TXT default._domainkey.${ZONE}`]: 'ETIMEOUT',
    [`TXT s1._domainkey.${ZONE}`]: 'ESERVFAIL', [`TXT ${ZONE}`]: 'ETIMEOUT' }, 'google,default,s1');
  assert.deepEqual((await gapRows(result)).map((r) => r.title), [
    'Evidence gap: the SPF check was not measured — the TXT lookup for example.test failed (ETIMEOUT)',
    'Evidence gap: the DKIM check was not fully measured — 2 TXT lookups failed: default._domainkey.example.test (ETIMEOUT), '
      + 's1._domainkey.example.test (ESERVFAIL)']);
  assert.equal(dkimEntries(result.details.notMeasured).length, 2, 'notMeasured stays one entry per lookup');
});
test('F-060 R3: lookups of different record types in one check — one row, each lookup named with its type', async () => {
  const { result } = await run({ ...PRESENT, [`A ns1.${ZONE}`]: 'ETIMEOUT', [`A ns2.${ZONE}`]: 'ENODATA', [`AAAA ns2.${ZONE}`]: 'ESERVFAIL' });
  assert.deepEqual((await gapRows(result)).map((r) => r.title),
    ['Evidence gap: the NS check was not measured — 2 lookups failed: A ns1.example.test (ETIMEOUT), AAAA ns2.example.test (ESERVFAIL)']);
});
// The loader reads `details.notMeasured` on ANY result, so its rule is pinned on a hand-built list: 060 never mixes the flag
// within a check today (`partial` is set from one per-run fact), which is why no producer-driven leg can tell "every" from
// "some". A check with one full entry beside a partial one reads "not measured", as 060's reason does.
test('F-060 R3: "not fully" only when EVERY entry of the check is partial — a partial entry beside a full one reads "not measured"', async () => {
  const nm = [{ check: 'dkim', rrtype: 'TXT', name: `a._domainkey.${ZONE}`, code: 'ETIMEOUT', partial: true },
    { check: 'dkim', rrtype: 'TXT', name: `b._domainkey.${ZONE}`, code: 'ESERVFAIL' }];
  assert.deepEqual((await gapRows({ details: { notMeasured: nm } })).map((r) => r.title),
    ['Evidence gap: the DKIM check was not measured — 2 TXT lookups failed: a._domainkey.example.test (ETIMEOUT), b._domainkey.example.test (ESERVFAIL)']);
  assert.deepEqual((await gapRows({ details: { notMeasured: nm.map((e) => ({ ...e, partial: true })) } })).map((r) => r.title),
    ['Evidence gap: the DKIM check was not fully measured — 2 TXT lookups failed: a._domainkey.example.test (ETIMEOUT), b._domainkey.example.test (ESERVFAIL)']);
});
