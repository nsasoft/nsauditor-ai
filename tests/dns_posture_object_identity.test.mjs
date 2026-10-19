// tests/dns_posture_object_identity.test.mjs
// ─────────────────────────────────────────────────────────────────────────────
// A DNS FINDING THAT FIRES ONCE PER OBJECT IS COMPARED PER OBJECT — A FIX ON ONE AND A NEW EXPOSURE ON ANOTHER ARE TWO
// CHANGES, NEVER NONE.
//
// The history delta (and the `--watch` alert, which compares the same lines) keyed every DNS-security finding of plugin
// 060 on its CHECK alone — `dnsSecurity:<check>`. A check that fires once per nameserver, address, CNAME target, DKIM
// selector, SPF range or MX host collapsed to one identity: with ns1's lame delegation fixed and ns2 newly lame between
// two scans, both lines carried `dnsSecurity:ns_lame_delegation` and the delta reported NO CHANGE — a new exposure that
// never read "appeared". Those checks are declared in `CHECK_OBJECT_FIELD` (the issue field that names the object, held
// equal both ways to the issue literals that carry one), `conclude` carries the object, and the identity becomes
// `dnsSecurity:<check>@<object>`. Every other check keeps `dnsSecurity:<check>`.
//
// The comparison basis moves to `service-flags-v2`. A line written on `service-flags-v1` recorded no object, so when
// EITHER side is v1 both are compared at check granularity — what v1 recorded — and the comparison says so; nothing is
// fabricated as cleared or appeared across the upgrade.
//
// DRIVEN, OFFLINE: DNS answers from a per-run table; real 060, real concluder, real history lines and delta.
//
// FOURTH QUADRANT FIRST: two identical v2 runs compare to nothing, and a per-domain check keeps its old identity.
// ─────────────────────────────────────────────────────────────────────────────
import './helpers/no_operator_home.mjs';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
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

const SRC = fs.readFileSync(new URL('../plugins/060_dns_sec_auditor.mjs', import.meta.url), 'utf8');
const { default: dnsSec, CHECK_OBJECT_FIELD, CHECK_IDS_BY_CATEGORY } = await import('../plugins/060_dns_sec_auditor.mjs');
const { default: concluder } = await import('../plugins/result_concluder.mjs');
const { historyServiceEntry, historyHostEntry, computeDiff } = await import('../utils/scan_history.mjs');
const { FINDINGS_COUNT_BASIS } = await import('../utils/report_inputs.mjs');
const { FLAGS_BASIS, flagFindings } = await import('../utils/service_flags.mjs');
const { buildDeltaReport, hasSignificantChanges } = await import('../utils/delta_reporter.mjs');

const [NS1, NS2] = [`ns1.${ZONE}`, `ns2.${ZONE}`];
const BASE = Object.freeze({ [`A ${ZONE}`]: ['192.0.2.10'], [`NS ${ZONE}`]: [NS1, NS2], [`A ${NS1}`]: ['192.0.2.53'],
  [`A ${NS2}`]: ['198.51.100.53'], [`TXT ${ZONE}`]: [['v=spf1 -all']] });
const LAME1 = { ...BASE, [`A ${NS1}`]: 'ENOTFOUND' };
const LAME2 = { ...BASE, [`A ${NS2}`]: 'ENOTFOUND' };

async function run(table) { TABLE = table; return dnsSec.run(ZONE, 0, {}); }
async function line(table) {
  const result = await run(table);
  const c = await concluder.run([{ id: '060', name: 'DNS Security Auditor', result }]);
  return { findingsCount: 0, findingsCountBasis: FINDINGS_COUNT_BASIS, tier: 'pro',
    services: c.services.map(historyServiceEntry), ...historyHostEntry({ result: c }) };
}
/** The same line as a service-flags-v1 build wrote it: no object in any identity. */
const asV1 = (l) => ({ ...l, flagsBasis: 'service-flags-v1',
  hostFlags: [...new Set(l.hostFlags.map((cid) => cid.replace(/@.*$/, '')))].sort() });
const host = (d) => d.changedFlags.find((c) => c.port == null) ?? { appeared: [], cleared: [], firstObserved: [], notCompared: [] };
const dnsOnly = (ids) => ids.map((x) => (typeof x === 'string' ? x : x.id)).filter((id) => id.startsWith('dnsSecurity:'));

// ── THE DECLARATION IS THE CODE'S ──────────────────────────────────────────────────────────────────────────────────────
// Fields an issue may carry that are evidence ABOUT the finding, not the object it is about. Every other field on an
// issue literal must be an object field, so a new field is classified here or the build fails.
const EVIDENCE_FIELDS = new Set(['service', 'records', 'complete', 'firstType']);
function issueLiterals() {
  const out = [];
  for (const m of SRC.matchAll(/issues\.push\(\{([\s\S]*?)\}\);/g)) {
    const check = /check:\s*"([a-z0-9_]+)"/.exec(m[1])?.[1];
    // A property is `name: value` or the shorthand `name,` — a reader of only the first form is blind to the second.
    const fields = [...m[1].matchAll(/^[ \t]*(\w+)[ \t]*(?::|,?[ \t]*$)/gm)].map((f) => f[1])
      .filter((f) => !['severity', 'check', 'detail'].includes(f));
    out.push({ check, fields });
  }
  return out;
}
test('(first) CHECK_OBJECT_FIELD equals, both ways, the checks whose issue literal carries an object field', () => {
  const objectFields = new Set(Object.values(CHECK_OBJECT_FIELD));
  const derived = {};
  for (const { check, fields } of issueLiterals()) {
    for (const f of fields) {
      assert.ok(objectFields.has(f) || EVIDENCE_FIELDS.has(f), `${check} carries "${f}" — an object field or evidence? classify it`);
      if (objectFields.has(f)) {
        assert.ok(!(check in derived) || derived[check] === f, `${check} names two objects`);
        derived[check] = f;
      }
    }
  }
  assert.deepEqual(derived, { ...CHECK_OBJECT_FIELD });
  const allIds = new Set(Object.values(CHECK_IDS_BY_CATEGORY).flat());
  for (const id of Object.keys(CHECK_OBJECT_FIELD)) assert.ok(allIds.has(id), `${id} is a declared finding id`);
});

// ── WHAT A RUN CARRIES ─────────────────────────────────────────────────────────────────────────────────────────────────
test('the concluded record carries the object of every per-object finding, and none on a per-domain one', async () => {
  const result = await run({ ...LAME1, [`A ${NS2}`]: ['10.0.0.53'] });
  const [record] = dnsSec.conclude({ result, host: ZONE });
  const by = Object.fromEntries(record.dnsSecurity.findings.map((f) => [`${f.check}`, f.object ?? null]));
  assert.equal(by.ns_lame_delegation, NS1);
  assert.equal(by.ns_private_ip, '10.0.0.53');
  assert.ok('missing_dmarc' in by && by.missing_dmarc === null, 'a per-domain finding carries no object');
});
test('the identity: a per-object finding is dnsSecurity:<check>@<object>; a per-domain one keeps dnsSecurity:<check>', () => {
  const cids = flagFindings({ dnsSecurity: { findings: [
    { severity: 'high', check: 'ns_lame_delegation', detail: 'x', object: NS1 },
    { severity: 'high', check: 'missing_dmarc', detail: 'y' },
  ] } }).map((f) => f.cid);
  assert.deepEqual(cids, [`dnsSecurity:ns_lame_delegation@${NS1}`, 'dnsSecurity:missing_dmarc']);
  assert.equal(FLAGS_BASIS, 'service-flags-v2');
});

// ── THE DELTA, BOTH LINES ON v2 ────────────────────────────────────────────────────────────────────────────────────────
test('(first) two identical runs compare to nothing', async () => {
  const d = computeDiff(await line(LAME1), await line(LAME1));
  assert.deepEqual([dnsOnly(host(d).appeared), dnsOnly(host(d).cleared), dnsOnly(host(d).notCompared)], [[], [], []]);
  assert.equal(d.flagsBasisNote ?? null, null);
});
test('THE SWAP: ns1 fixed and ns2 newly lame reads cleared on ns1 AND appeared on ns2', async () => {
  const h = host(computeDiff(await line(LAME2), await line(LAME1)));
  assert.deepEqual(dnsOnly(h.appeared), [`dnsSecurity:ns_lame_delegation@${NS2}`]);
  assert.deepEqual(dnsOnly(h.cleared), [`dnsSecurity:ns_lame_delegation@${NS1}`]);
});
test('a per-object finding gone entirely reads cleared at its object', async () => {
  const h = host(computeDiff(await line(BASE), await line(LAME1)));
  assert.deepEqual(dnsOnly(h.cleared), [`dnsSecurity:ns_lame_delegation@${NS1}`]);
  assert.deepEqual(dnsOnly(h.appeared), []);
});
test('a per-object finding whose check could not be measured now is not compared, with why — never cleared', async () => {
  const h = host(computeDiff(await line({ ...BASE, [`A ${NS1}`]: 'ETIMEOUT' }), await line(LAME1)));
  assert.deepEqual(dnsOnly(h.cleared), []);
  assert.deepEqual(dnsOnly(h.notCompared), [`dnsSecurity:ns_lame_delegation@${NS1}`]);
  assert.match(JSON.stringify(h.notCompared), /DNS check that produces it was not measured/);
});

// ── ACROSS THE UPGRADE: either line on v1 ──────────────────────────────────────────────────────────────────────────────
test('v1 baseline, v2 now, the SAME swap: compared per check — no change fabricated either way — and the basis is stated', async () => {
  const d = computeDiff(await line(LAME2), asV1(await line(LAME1)));
  assert.equal(d.flagsNotComparable, false, 'the comparison is not refused');
  assert.deepEqual([dnsOnly(host(d).appeared), dnsOnly(host(d).cleared)], [[], []]);
  assert.equal(d.flagsBasisNote, 'dns-security-per-check');
  assert.match(d.summary, /DNS-security findings compared per check, not per object/);
});
test('v1 baseline, v2 now: a check that is gone entirely still reads cleared, at check granularity', async () => {
  const h = host(computeDiff(await line(BASE), asV1(await line(LAME1))));
  assert.deepEqual(dnsOnly(h.cleared), ['dnsSecurity:ns_lame_delegation']);
});
test('v2 baseline, v1 now (either side): compared per check, stated', async () => {
  const d = computeDiff(asV1(await line(LAME2)), await line(LAME1));
  assert.deepEqual([dnsOnly(host(d).appeared), dnsOnly(host(d).cleared)], [[], []]);
  assert.equal(d.flagsBasisNote, 'dns-security-per-check');
});
test('a basis this build does not know is still refused, never read per check', async () => {
  const d = computeDiff(await line(LAME2), { ...asV1(await line(LAME1)), flagsBasis: 'service-flags-v0' });
  assert.deepEqual([d.flagsNotComparable, d.flagsNotComparableReason], [true, 'basis-changed']);
});

// ── THE --watch ALERT READS THE SAME COMPARISON ────────────────────────────────────────────────────────────────────────
test('--watch: two cycles whose only change is the swap are a significant change', async () => {
  const report = buildDeltaReport(new Map([[ZONE, { scanSummary: await line(LAME2) }]]),
    new Map([[ZONE, { scanSummary: await line(LAME1) }]]));
  assert.equal(hasSignificantChanges(report), true);
  const same = buildDeltaReport(new Map([[ZONE, { scanSummary: await line(LAME1) }]]),
    new Map([[ZONE, { scanSummary: await line(LAME1) }]]));
  assert.equal(hasSignificantChanges(same), false, 'and two identical cycles are not');
});
