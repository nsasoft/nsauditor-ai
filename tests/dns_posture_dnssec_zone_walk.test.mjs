// tests/dns_posture_dnssec_zone_walk.test.mjs
// ─────────────────────────────────────────────────────────────────────────────
// G-75 (D1) (b): DNSKEY AND DS ARE ASKED AT THE ZONE APEX, FOUND BY A RAW SOA WALK — AND THE ROW SAYS WHICH ZONE.
//
// A name below the apex answers NOERROR with no DNSKEY and no DS even inside a signed zone (architect VERDICT-v407 G3,
// measured on www.isc.org and www.ietf.org), so asking at the target read `no_dnssec` — a MEDIUM "can be spoofed" — on
// signed zones. (b) walks up the target's labels by raw SOA query (VERDICT-v412 choice (A)): an alias (CNAME/DNAME in
// the answer) steps up; an SOA with no alias is the apex; NOERROR with no answer steps up; NXDOMAIN AT THE TARGET is not
// measured (W2′, VERDICT-v414: one ENOTFOUND entry per record type, no row, never through isAbsence); anything else is not
// measured with its code, as ONE entry for the SOA lookup that was sent (VERDICT-v416 Q1 (a)). A single label is never a
// zone (W5: ENOAPEX) and the root is never asked. One deadline covers the walk and both queries (G14).
//
// Every leg drives the whole plugin against a real localhost DNS server (helpers/fake_dns_server.mjs). Accept first.
// ─────────────────────────────────────────────────────────────────────────────
import './helpers/no_operator_home.mjs';
import './helpers/no_operator_dotenv.mjs';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runDnssec, dnsSec, queriesOf } from './helpers/dnssec_harness.mjs';
import { startFakeDns, zoneHandler, encodeName } from './helpers/fake_dns_server.mjs';
import { shapeHostFindings } from '../utils/report_inputs.mjs';

const KEYS = { answers: [{ type: 'DNSKEY' }] };
const DS = { answers: [{ type: 'DS' }] };
const SOA = { answers: [{ type: 'SOA' }] };
const NODATA = { answers: [] };
const signedAt = (apex) => ({ [`${apex} SOA`]: SOA, [`${apex} DNSKEY`]: KEYS, [`${apex} DS`]: DS });

async function withZone(zone, fn) {
  const s = await startFakeDns({ handler: zoneHandler(zone) });
  try { return await fn(s); } finally { await s.close(); }
}
const keyQueries = (s) => queriesOf(s).filter((q) => / (DNSKEY|DS) /.test(q));
const gapOf = (r) => r.nmRaw.map((e) => `${e.rrtype}:${e.name}:${e.code}`);
function assertNoRow(r) {
  assert.deepEqual(r.rows, []);
  assert.equal(r.dnssec.hasDNSKEY, null);
  assert.equal(r.dnssec.hasDS, null);
}
/** The Community report's evidence-gap sentence for the DNSSEC check. */
const communityGap = (r, host) => shapeHostFindings(host, { results: [{ id: '060', name: dnsSec.name, result: r.result }] })
  .map((f) => f.detail ?? f.title ?? '').find((d) => /the DNSSEC check/.test(d)) ?? null;

test('L3f (accept): SOA at the target — the target is the apex; DNSKEY and DS are asked there; the row names the zone', async () => {
  await withZone(signedAt('example.test'), async (s) => {
    const r = await runDnssec('example.test', [s.entry]);
    assert.deepEqual(r.rows, ['dnssec_active']);
    assert.equal(r.dnssec.zone, 'example.test');
    assert.equal(r.dnssec.alias, false);
    assert.deepEqual(keyQueries(s).sort(), ['udp DNSKEY example.test', 'udp DS example.test']);
    assert.match(r.result.findings.dnssec[0].detail, /the zone example\.test\b/);
  });
});

test('L3f (accept): NODATA at www, SOA one label up — DNSKEY and DS at the apex, never at www; the row and the line name the zone that holds www', async () => {
  await withZone({ ...signedAt('example.test'), 'www.example.test SOA': NODATA }, async (s) => {
    const r = await runDnssec('www.example.test', [s.entry]);
    assert.deepEqual(r.rows, ['dnssec_active'], JSON.stringify(r.nm));
    assert.equal(r.dnssec.zone, 'example.test');
    assert.deepEqual(keyQueries(s).sort(), ['udp DNSKEY example.test', 'udp DS example.test']);
    assert.match(r.result.findings.dnssec[0].detail, /the zone example\.test, which holds www\.example\.test/);
    // The zone is in the sentence and in details.dnssec.zone, never a field on the issue: an object field would make
    // report --since compare zones (dns_posture_object_identity), and the identity stays `check` (v412 G12).
    assert.equal(Object.hasOwn(r.result.findings.dnssec[0], 'zone'), false, 'no zone field on the issue');
    assert.match(r.line, /zone example\.test/);
  });
});

test('L3f: an alias to an apex in ANOTHER zone — the verdict is the zone that holds the alias, never the target zone; fixed alias words, no alias target printed, no entry added', async () => {
  // A recursive resolver follows the alias, so the SOA query at www.a.test answers [CNAME → b.test, SOA of b.test].
  const followed = { answers: [{ type: 'CNAME', data: encodeName('b.test') }, { type: 'SOA', name: 'b.test' }] };
  await withZone({ ...signedAt('a.test'), 'www.a.test SOA': followed, ...signedAt('b.test') }, async (s) => {
    const r = await runDnssec('www.a.test', [s.entry]);
    assert.deepEqual(r.rows, ['dnssec_active']);
    assert.deepEqual(r.nm, [], 'the containing zone was measured');
    assert.equal(r.dnssec.zone, 'a.test');
    assert.equal(r.dnssec.alias, true);
    assert.deepEqual(keyQueries(s).sort(), ['udp DNSKEY a.test', 'udp DS a.test'], 'b.test is never asked');
    const detail = r.result.findings.dnssec[0].detail;
    assert.match(detail, /www\.a\.test is an alias \(CNAME\); the zone it points into was not checked/);
    for (const text of [detail, r.line]) assert.ok(!/b\.test/.test(text.replace(/www\.a\.test|a\.test/g, '')), `alias target printed: ${text}`);
    assert.match(r.line, /alias \(CNAME\)/);
  });
});

test('L3f: an alias to a non-apex name — the walk steps up to the zone that holds the alias', async () => {
  await withZone({ ...signedAt('a.test'), 'www.a.test SOA': { answers: [{ type: 'CNAME', data: encodeName('x.y.b.test') }] } }, async (s) => {
    const r = await runDnssec('www.a.test', [s.entry]);
    assert.deepEqual(r.rows, ['dnssec_active']);
    assert.equal(r.dnssec.zone, 'a.test');
    assert.equal(r.dnssec.alias, true);
  });
});

test('L3f / H3: NXDOMAIN at the target — DNSKEY and DS not measured (ENOTFOUND), no row, no walk to the parent; never read as no_dnssec', async () => {
  await withZone({ ...signedAt('a.test'), 'nope.a.test SOA': { rcode: 3 } }, async (s) => {
    const r = await runDnssec('nope.a.test', [s.entry]);
    assertNoRow(r);
    assert.deepEqual(gapOf(r), ['DNSKEY:nope.a.test:ENOTFOUND', 'DS:nope.a.test:ENOTFOUND']);
    assert.ok(!(r.result.findings.dnssec ?? []).some((i) => /dnssec/.test(i.check)), 'no dnssec row id on the written result');
    assert.deepEqual(queriesOf(s), ['udp SOA nope.a.test'], 'the parent is never asked');
  });
});

test('L3f: SERVFAIL in the middle of the walk — one SOA entry for that step; DNSKEY and DS never asked; the Community sentence names the SOA lookup', async () => {
  await withZone({ ...signedAt('example.test'), 'a.b.example.test SOA': NODATA, 'b.example.test SOA': { rcode: 2 } }, async (s) => {
    const r = await runDnssec('a.b.example.test', [s.entry]);
    assertNoRow(r);
    assert.deepEqual(gapOf(r), ['SOA:b.example.test:ESERVFAIL']);
    assert.deepEqual(keyQueries(s), []);
    assert.match(communityGap(r, 'a.b.example.test') ?? '', /the SOA lookup for b\.example\.test failed \(ESERVFAIL\)/);
  });
});

test('L3f: NXDOMAIN at a LATER step — one SOA entry, ENOTFOUND, never an absence', async () => {
  await withZone({ 'a.b.example.test SOA': NODATA, 'b.example.test SOA': { rcode: 3 } }, async (s) => {
    const r = await runDnssec('a.b.example.test', [s.entry]);
    assertNoRow(r);
    assert.deepEqual(gapOf(r), ['SOA:b.example.test:ENOTFOUND']);
  });
});

test('L3f / W5: a walk that would reach a single label — ENOAPEX for the target; neither the TLD nor the root is asked', async () => {
  await withZone({ 'a.b.test SOA': NODATA, 'b.test SOA': NODATA }, async (s) => {
    const r = await runDnssec('a.b.test', [s.entry]);
    assertNoRow(r);
    assert.deepEqual(gapOf(r), ['SOA:a.b.test:ENOAPEX']);
    assert.deepEqual(queriesOf(s), ['udp SOA a.b.test', 'udp SOA b.test']);
  });
});

test('L3f / W5: a single-label target — ENOAPEX, and nothing is sent', async () => {
  await withZone({}, async (s) => {
    const r = await runDnssec('intranet', [s.entry]);
    assertNoRow(r);
    assert.deepEqual(gapOf(r), ['SOA:intranet:ENOAPEX']);
    assert.deepEqual(s.log, []);
  });
});

test('L3f / G14: ONE deadline covers the whole walk — slow but answering steps run out of time: ETIMEOUT on the SOA step being asked', async () => {
  // timeoutMs 1000 → each attempt waits 250 ms. Every step answers 180 ms late: each step alone fits its attempt; seven
  // steps (1260 ms) do not fit one deadline, so it runs out at the sixth. Without the shared deadline the walk would finish and decide.
  const slow = (spec) => () => ({ ...spec, delayMs: 180 });
  const labels = ['l1', 'l2', 'l3', 'l4', 'l5', 'l6', 'example', 'test'];
  const names = labels.slice(0, -1).map((_, i) => labels.slice(i).join('.')); // seven names, the last the apex
  const zone = Object.fromEntries(names.slice(0, -1).map((n) => [`${n} SOA`, slow(NODATA)]));
  Object.assign(zone, { 'example.test SOA': slow(SOA), 'example.test DNSKEY': slow(KEYS), 'example.test DS': slow(DS) });
  await withZone(zone, async (s) => {
    const r = await runDnssec(names[0], [s.entry], { timeoutMs: 1000 });
    assertNoRow(r);
    const [gap] = r.nmRaw;
    assert.equal(r.nmRaw.length, 1, JSON.stringify(r.nmRaw));
    assert.equal(gap.rrtype, 'SOA');
    assert.equal(gap.code, 'ETIMEOUT');
    assert.ok(names.includes(gap.name), gap.name);
    assert.ok(r.ms < 1000 + 1500, `took ${r.ms} ms`);
  });
});
