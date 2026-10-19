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
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const dnsP = require('node:dns').promises;
const net = require('node:net');

const ZONE = 'example.test';
const WILDCARD = `A *.${ZONE}`;
let TABLE = {};
const fail = (code, what) => { throw Object.assign(new Error(`query ${code} ${what}`), code ? { code } : {}); };
/** One lookup: an array/object answers, a string is the error code it fails with, `{ message }` fails with no code. */
function answer(type, name) {
  const key = name.startsWith('nsauditor-wildcard-probe-') ? WILDCARD : `${type} ${name}`;
  const v = key in TABLE ? TABLE[key] : 'ENODATA';
  if (typeof v === 'string') return fail(v, key);
  if (v && typeof v === 'object' && !Array.isArray(v) && Object.hasOwn(v, 'message')) return fail(null, v.message);
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
  assert.deepEqual(notMeasured.map((e) => e.check),
    ['cname', 'spf', 'dmarc', 'dkim', 'ns', 'dnssec', 'mx', 'caa', 'wildcard'], 'one entry per check, in the result\'s order');
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
test('DKIM: a found selector beside a timed-out one is measured — present, nothing recorded', async () => {
  const { graded, notMeasured } = await run({ ...PRESENT, [`TXT default._domainkey.${ZONE}`]: 'ETIMEOUT' });
  assert.deepEqual(notMeasured, []);
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
