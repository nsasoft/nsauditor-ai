// tests/dns_posture_dnssec_raw_query.test.mjs
// ─────────────────────────────────────────────────────────────────────────────
// G-75 (D1) (b): THE DNSSEC CHECK ASKS BY RAW DNS, AND A REPLY DECIDES ONLY WHEN IT ANSWERS THE QUESTION ASKED.
//
// From Community 1.1.0 to 1.2.0 plugin 060 asked Node's resolver for DNSKEY and DS, and Node refuses both types
// synchronously (ERR_INVALID_ARG_VALUE): the check measured no domain at all. (b) sends the queries itself, as DNS
// messages, to the configured resolvers (dns.getServers()), UDP then TCP after TC=1.
//
// Every leg below drives the WHOLE plugin against a REAL DNS server on localhost (helpers/fake_dns_server.mjs): 060
// opens its own sockets and reads real datagrams. Nothing in the query path is stubbed; getServers() is pointed at the
// localhost server so nothing leaves the machine (helpers/dnssec_harness.mjs says what else is stubbed and why).
//
// Legs (architect rulings VERDICT-v404 L1–L3, v407 L3b–L3e, v413 L3g/L9/L10 and the socket rule, v415 S1–S2), each with
// its accept case FIRST — a check that refused every reply would pass every veto below and fail only the accepts.
// ─────────────────────────────────────────────────────────────────────────────
import './helpers/no_operator_home.mjs';
import './helpers/no_operator_dotenv.mjs';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import dgram from 'node:dgram';
import net from 'node:net';
import dnsCallback from 'node:dns';
import { calls, runDnssec, plugin, queriesOf } from './helpers/dnssec_harness.mjs';
import {
  startFakeDns, zoneHandler, T, buildReply, shortReply, pointerLoopReply, countOverflowReply,
  labelThenPointerToOwnStartReply, labelThenPointerToQuestionReply,
} from './helpers/fake_dns_server.mjs';

const APEX = 'example.test';
const KEYS = { answers: [{ type: 'DNSKEY' }, { type: 'DNSKEY' }] };
const DS = { answers: [{ type: 'DS' }] };
const SOA = { answers: [{ type: 'SOA' }] };
const SIGNED = Object.freeze({ [`${APEX} SOA`]: SOA, [`${APEX} DNSKEY`]: KEYS, [`${APEX} DS`]: DS });
const UNSIGNED = Object.freeze({ [`${APEX} SOA`]: SOA });
const zone = (over = {}) => zoneHandler({ ...SIGNED, ...over });

async function withServer(opts, fn) {
  const s = await startFakeDns(opts);
  try { return await fn(s); } finally { await s.close(); }
}
/** A UDP port on 127.0.0.1 with nothing bound to it. */
async function closedUdpPort() {
  const s = dgram.createSocket('udp4');
  await new Promise((r) => s.bind(0, '127.0.0.1', r));
  const { port } = s.address();
  await new Promise((r) => s.close(r));
  return port;
}
/** A walk that could not find the apex writes ONE entry, for the SOA lookup, naming the step and its code; no row, and
 *  both has* null (VERDICT-v416 Q1 (a): a renderer prints "the <rrtype> lookup for <name> failed", so an entry names the
 *  query that was actually sent). */
function assertWalkGap(r, name, code) {
  assert.deepEqual(r.nmRaw.map((e) => `${e.rrtype}:${e.name}:${e.code}`), [`SOA:${name}:${code}`]);
  assert.deepEqual(r.rows, []);
  assert.equal(r.dnssec.hasDNSKEY, null);
  assert.equal(r.dnssec.hasDS, null);
}
const MEASURED_ACTIVE = (r) => {
  assert.deepEqual(r.rows, ['dnssec_active'], `rows ${JSON.stringify(r.rows)}; not measured ${JSON.stringify(r.nm)}`);
  assert.deepEqual(r.nm, []);
  assert.equal(r.dnssec.hasDNSKEY, true);
  assert.equal(r.dnssec.hasDS, true);
};

// ── L2: the premise pin ─────────────────────────────────────────────────────
test('L2 (premise): the real Node resolver refuses DNSKEY and DS — why 060 cannot ask through it', async () => {
  const resolver = new dnsCallback.promises.Resolver({ timeout: 50, tries: 1 });
  resolver.setServers([`127.0.0.1:${await closedUdpPort()}`]);
  for (const type of ['DNSKEY', 'DS']) {
    let refused = null;
    try { await resolver.resolve(APEX, type); } catch (e) { refused = e.code; }
    assert.equal(refused, 'ERR_INVALID_ARG_VALUE',
      `Node now ACCEPTS ${type} (got ${refused}): the raw query in 060 may be replaceable — revisit G-75 before relying on either`);
  }
});

// ── L1: the census of record types 060 hands to dns.resolve ─────────────────
const RESOLVE_TYPE_SITES = /\bdns\.resolve\s*(?:,\s*[^,()]+,\s*|\(\s*[^,()]+,\s*)["'`]([A-Za-z0-9]+)["'`]/g;
const typesPassed = (src) => [...src.matchAll(RESOLVE_TYPE_SITES)].map((m) => m[1]);
test('L1 (census, accept first): the census reads a planted dns.resolve type, in both call forms', () => {
  assert.deepEqual(typesPassed('safeResolve(dns.resolve, host, "DNSKEY"); await dns.resolve(host, \'TXT\');'), ['DNSKEY', 'TXT']);
});
test('L1 (census): every record type 060 passes to dns.resolve — in source and in a whole run — is one the REAL resolver accepts', async () => {
  const src = fs.readFileSync(new URL('../plugins/060_dns_sec_auditor.mjs', import.meta.url), 'utf8');
  calls.resolve.length = 0;
  await withServer({ handler: zone() }, (s) => runDnssec(APEX, [s.entry]));
  const types = [...new Set([...typesPassed(src), ...calls.resolve])];
  const resolver = new dnsCallback.promises.Resolver({ timeout: 50, tries: 1 });
  resolver.setServers([`127.0.0.1:${await closedUdpPort()}`]);
  const refused = [];
  for (const type of types) {
    try { await resolver.resolve(APEX, type); } catch (e) { if (e.code === 'ERR_INVALID_ARG_VALUE') refused.push(type); }
  }
  assert.deepEqual(refused, [], `060 passes ${refused.join(', ')} to dns.resolve, which the real resolver refuses — that check measures nothing`);
});

// ── L3: a real server answers; the check is measured ────────────────────────
test('L3 (accept): a signed zone on a real localhost server reads dnssec_active, measured, asked of the configured server only', async () => {
  await withServer({ handler: zone() }, async (s) => {
    calls.resolve.length = 0;
    calls.resolveAny = 0;
    const r = await runDnssec(APEX, [s.entry]);
    MEASURED_ACTIVE(r);
    const q = queriesOf(s);
    for (const want of [`udp SOA ${APEX}`, `udp DNSKEY ${APEX}`, `udp DS ${APEX}`]) assert.ok(q.includes(want), `${want} not received; got ${q}`);
    assert.deepEqual(calls.resolve.filter((t) => t === 'DNSKEY' || t === 'DS'), [], 'DNSKEY/DS never go through dns.resolve');
    assert.equal(calls.resolveAny, 0, 'the resolveAny fallback is deleted');
  });
});
test('L3: an unsigned zone (NOERROR, no DNSKEY, no DS) reads no_dnssec, measured', async () => {
  await withServer({ handler: zoneHandler(UNSIGNED) }, async (s) => {
    const r = await runDnssec(APEX, [s.entry]);
    assert.deepEqual(r.rows, ['no_dnssec']);
    assert.deepEqual(r.nm, []);
    assert.equal(r.dnssec.hasDNSKEY, false);
    assert.equal(r.dnssec.hasDS, false);
  });
});

// ── L3b: the match rule — one term at a time ────────────────────────────────
const L3B_ACCEPT = [
  ['the exact echo', () => KEYS],
  ['the question echoed in another case', (q) => ({ ...KEYS, question: { name: q.name.toUpperCase() } })],
];
const L3B_VETO = [
  ['a wrong id', (q) => ({ ...KEYS, id: (q.id + 1) & 0xffff })],
  ['QR=0', () => ({ ...KEYS, qr: false })],
  ['opcode 2', () => ({ ...KEYS, opcode: 2 })],
  ['another name in the question', () => ({ ...KEYS, question: { name: `other.${APEX}` } })],
  ['another type in the question', () => ({ ...KEYS, question: { type: T.DS } })],
  ['another class in the question', () => ({ ...KEYS, question: { cls: 3 } })],
  ['no question', () => ({ ...KEYS, noQuestion: true })],
  ['the right reply from another source port', () => ({ ...KEYS, fromAltPort: true })],
];
for (const [what, reply] of L3B_ACCEPT) {
  test(`L3b (accept): ${what} decides`, async () => {
    await withServer({ handler: zone({ [`${APEX} DNSKEY`]: reply }) }, async (s) => MEASURED_ACTIVE(await runDnssec(APEX, [s.entry])));
  });
}
for (const [what, reply] of L3B_VETO) {
  test(`L3b: ${what} never decides — the DNSKEY side ends ETIMEOUT, no row`, async () => {
    await withServer({ handler: zone({ [`${APEX} DNSKEY`]: reply }) }, async (s) => {
      const r = await runDnssec(APEX, [s.entry], { timeoutMs: 800 });
      assert.deepEqual(r.rows, []);
      assert.deepEqual(r.nm, ['DNSKEY:ETIMEOUT']);
      assert.equal(r.dnssec.hasDNSKEY, null);
      assert.equal(r.dnssec.hasDS, true);
    });
  });
}

// ── L3c: TC=1 never decides ─────────────────────────────────────────────────
const byTransport = (udp, tcp) => (q, info) => (info.transport === 'udp' ? udp : tcp);
test('L3c (accept): TC=1 with an empty answer, then TCP answers DNSKEY — TCP\'s answer is the one read', async () => {
  await withServer({ handler: zone({ [`${APEX} DNSKEY`]: byTransport({ tc: true, answers: [] }, KEYS) }) }, async (s) => {
    MEASURED_ACTIVE(await runDnssec(APEX, [s.entry]));
    assert.ok(queriesOf(s).includes(`tcp DNSKEY ${APEX}`));
  });
});
test('L3c: TC=1 WITH a DNSKEY in it, then TCP answers none — absent, from TCP; the truncated record is not read', async () => {
  await withServer({ handler: zone({ [`${APEX} DNSKEY`]: byTransport({ tc: true, ...KEYS }, { answers: [] }) }) }, async (s) => {
    const r = await runDnssec(APEX, [s.entry]);
    assert.deepEqual(r.rows, ['dnssec_ds_without_dnskey']);
    assert.equal(r.dnssec.hasDNSKEY, false);
  });
});
test('L3c: TC=1 and TCP refused — not measured, ECONNREFUSED, no row', async () => {
  await withServer({ handler: zone({ [`${APEX} DNSKEY`]: { tc: true, ...KEYS } }), tcp: false }, async (s) => {
    const r = await runDnssec(APEX, [s.entry]);
    assert.deepEqual(r.rows, []);
    assert.deepEqual(r.nm, ['DNSKEY:ECONNREFUSED']);
  });
});
test('L3c: TC=1, and TCP truncated again — not measured, ETRUNCATED', async () => {
  await withServer({ handler: zone({ [`${APEX} DNSKEY`]: { tc: true, ...KEYS } }) }, async (s) => {
    const r = await runDnssec(APEX, [s.entry]);
    assert.deepEqual(r.nm, ['DNSKEY:ETRUNCATED']);
  });
});
test('L3c: TC=1, and TCP closes without a reply — not measured, with a code', async () => {
  await withServer({ handler: zone({ [`${APEX} DNSKEY`]: byTransport({ tc: true, answers: [] }, { tcpClose: true }) }) }, async (s) => {
    const r = await runDnssec(APEX, [s.entry]);
    assert.deepEqual(r.rows, []);
    assert.deepEqual(r.nm, ['DNSKEY:ECONNRESET']);
  });
});

// ── L3d: presence is keyed on the answer's TYPE; an alias never decides; a failing rcode is not an absence ─────
const L3D = [
  ['a CNAME-only answer', { [`${APEX} DNSKEY`]: { answers: [{ type: 'CNAME' }] } }, 'DNSKEY:ECNAME'],
  ['[CNAME, DNSKEY, DNSKEY]', { [`${APEX} DNSKEY`]: { answers: [{ type: 'CNAME' }, { type: 'DNSKEY' }, { type: 'DNSKEY' }] } }, 'DNSKEY:ECNAME'],
  ['[DNAME, DNSKEY]', { [`${APEX} DNSKEY`]: { answers: [{ type: 'DNAME' }, { type: 'DNSKEY' }] } }, 'DNSKEY:ECNAME'],
  ['[CNAME, DS]', { [`${APEX} DS`]: { answers: [{ type: 'CNAME' }, { type: 'DS' }] } }, 'DS:ECNAME'],
  ['SERVFAIL', { [`${APEX} DNSKEY`]: { rcode: 2 } }, 'DNSKEY:ESERVFAIL'],
  ['REFUSED', { [`${APEX} DNSKEY`]: { rcode: 5 } }, 'DNSKEY:EREFUSED'],
  ['FORMERR', { [`${APEX} DNSKEY`]: { rcode: 1 } }, 'DNSKEY:EFORMERR'],
  ['NOTIMP', { [`${APEX} DNSKEY`]: { rcode: 4 } }, 'DNSKEY:ENOTIMP'],
  ['rcode 9', { [`${APEX} DNSKEY`]: { rcode: 9 } }, 'DNSKEY:ERCODE9'],
  ['no reply', { [`${APEX} DNSKEY`]: () => null }, 'DNSKEY:ETIMEOUT'],
];
test('L3d (accept): NXDOMAIN, and NOERROR carrying only another type, are each an ABSENCE of DNSKEY', async () => {
  for (const reply of [{ rcode: 3 }, { answers: [{ type: 'A' }] }]) {
    await withServer({ handler: zone({ [`${APEX} DNSKEY`]: reply }) }, async (s) => {
      const r = await runDnssec(APEX, [s.entry]);
      assert.deepEqual(r.nm, [], JSON.stringify(reply));
      assert.equal(r.dnssec.hasDNSKEY, false, JSON.stringify(reply));
      assert.deepEqual(r.rows, ['dnssec_ds_without_dnskey']);
    });
  }
});
for (const [what, over, entry] of L3D) {
  test(`L3d: ${what} is not measured (${entry}), never presence and never absence`, async () => {
    await withServer({ handler: zone(over) }, async (s) => {
      const r = await runDnssec(APEX, [s.entry], { timeoutMs: 800 });
      assert.deepEqual(r.rows, []);
      assert.deepEqual(r.nm, [entry]);
    });
  });
}

// ── L3e: a hostile reply ends in an error within a bound, and the scan finishes ─────────────────
// EE VERDICT-v418 C2, accept FIRST: an owner written as a label, then a pointer to an EARLIER name (`03 77 77 77 C0 0C`,
// www + the question's name) is the commonest compressed owner a real server sends, and it still decides. The owner name is
// not compared with the question (a stated limit in 060's header), so this reply reads as the DNSKEY it carries.
test('L3e (accept): an owner that is a label, then a pointer to the question name at offset 12, parses and decides', async () => {
  await withServer({ handler: zone({ [`${APEX} DNSKEY`]: (q) => ({ raw: labelThenPointerToQuestionReply(q) }) }) }, async (s) => {
    MEASURED_ACTIVE(await runDnssec(APEX, [s.entry]));
  });
  const q = { id: 7, flags: 0x0100, name: APEX, type: T.DNSKEY, cls: 1 };
  assert.deepEqual(plugin.parseDnsAnswerTypes(labelThenPointerToQuestionReply(q)), { rcode: 0, types: ['48'] });
});
const L3E = [
  ['a reply under 12 bytes (cannot match)', (q) => ({ raw: shortReply(q) }), 'DNSKEY:ETIMEOUT'],
  ['a compression pointer to itself', (q) => ({ raw: pointerLoopReply(q) }), 'DNSKEY:EBADRESP'],
  // EE VERDICT-v418 C2: the pointer is bounded at the START OF THE NAME it ends, not at the pointer. 6934439 read this owner
  // as a DNSKEY and wrote dnssec_active (measured, EE audit-evidence-samples/ee-2.2.1/z1/architect-v418/drive_r2_pointer.out).
  ['a label, then a pointer to the start of the same name', (q) => ({ raw: labelThenPointerToOwnStartReply(q) }), 'DNSKEY:EBADRESP'],
  ['ANCOUNT larger than the message', (q) => ({ raw: countOverflowReply(q) }), 'DNSKEY:EBADRESP'],
];
for (const [what, reply, entry] of L3E) {
  test(`L3e: ${what} — ${entry}, no row, the scan finishes`, async () => {
    await withServer({ handler: zone({ [`${APEX} DNSKEY`]: reply }) }, async (s) => {
      const r = await runDnssec(APEX, [s.entry], { timeoutMs: 800 });
      assert.deepEqual(r.rows, []);
      assert.deepEqual(r.nm, [entry]);
      assert.ok(r.ms < 800 + 1500, `the scan took ${r.ms} ms`);
    });
  });
}
test('L3e: the REAL parseDnsAnswerTypes rejects each hostile shape within a bound', () => {
  assert.equal(typeof plugin.parseDnsAnswerTypes, 'function', '060 does not export its reply parser, so no leg can drive it');
  const q = { id: 7, flags: 0x0100, name: APEX, type: T.DNSKEY, cls: 1 };
  for (const m of [shortReply(q), pointerLoopReply(q), labelThenPointerToOwnStartReply(q), countOverflowReply(q)]) {
    const t0 = Date.now();
    assert.throws(() => plugin.parseDnsAnswerTypes(m));
    assert.ok(Date.now() - t0 < 50);
  }
});

// ── L3g: a dead resolver is unknown with a code, the process survives, the next resolver is asked ─────────────
test('L3g (accept): a closed UDP port first, a live server second — the live one decides', async () => {
  const dead = `127.0.0.1:${await closedUdpPort()}`;
  await withServer({ handler: zone() }, async (s) => MEASURED_ACTIVE(await runDnssec(APEX, [dead, s.entry], { timeoutMs: 2000 })));
});
test('L3g: TCP refused after TC=1 at the first resolver — the second is asked and decides', async () => {
  await withServer({ handler: zone({ [`${APEX} DNSKEY`]: { tc: true, answers: [] } }), tcp: false }, async (a) => {
    await withServer({ handler: zone() }, async (b) => {
      MEASURED_ACTIVE(await runDnssec(APEX, [a.entry, b.entry], { timeoutMs: 2000 }));
      assert.ok(queriesOf(b).includes(`udp DNSKEY ${APEX}`));
    });
  });
});
test('L3g: the only resolver is a closed UDP port — not measured, ETIMEOUT, no row, the process survives', async () => {
  const r = await runDnssec(APEX, [`127.0.0.1:${await closedUdpPort()}`], { timeoutMs: 800 });
  assertWalkGap(r, APEX, 'ETIMEOUT');
});
test('L3g: two resolvers failing with DIFFERENT codes — the entry carries the FIRST skipped resolver\'s code, never ENOSERVER', async () => {
  const dead = `127.0.0.1:${await closedUdpPort()}`;
  assertWalkGap(await runDnssec(APEX, ['not-an-address', dead], { timeoutMs: 800 }), APEX, 'EBADSERVER');
  assertWalkGap(await runDnssec(APEX, [dead, 'not-an-address'], { timeoutMs: 800 }), APEX, 'ETIMEOUT');
});
test('L3g: no resolver configured at all — ENOSERVER', async () => {
  assertWalkGap(await runDnssec(APEX, []), APEX, 'ENOSERVER');
});

// ── v415 S1: one lost datagram is not silence ───────────────────────────────
test('S1 (accept): the first datagram of every question is dropped and the second answered — measured, each retry under a NEW id', async () => {
  await withServer({ handler: (q, info) => (info.transport === 'udp' && info.n === 1 ? null : zone()(q, info)) }, async (s) => {
    MEASURED_ACTIVE(await runDnssec(APEX, [s.entry], { timeoutMs: 2400 }));
    for (const type of [T.SOA, T.DNSKEY, T.DS]) {
      const ids = s.log.filter((l) => l.transport === 'udp' && l.type === type).map((l) => l.id);
      assert.equal(ids.length, 2, `type ${type}: ${ids}`);
      assert.notEqual(ids[0], ids[1], 'a retry carries a new id');
    }
  });
});

test('S1: a reply to the FIRST id that arrives during the retry window is not read (each attempt has its own socket)', async () => {
  // timeoutMs 1200 → each attempt waits 300 ms. The first SOA reply leaves 400 ms late, inside the retry's window; the
  // retry itself is never answered.
  const late = (q, info) => (info.transport !== 'udp' ? null : info.n === 1 ? { ...SOA, delayMs: 400 } : null);
  await withServer({ handler: zoneHandler({ ...SIGNED, [`${APEX} SOA`]: late }) }, async (s) => {
    assertWalkGap(await runDnssec(APEX, [s.entry], { timeoutMs: 1200 }), APEX, 'ETIMEOUT');
    assert.equal(s.log.filter((l) => l.type === T.SOA).length, 2);
  });
});

// ── v416 Q5: the attempt window ─────────────────────────────────────────────
test('Q5: the attempt window is min(1999, max(100, floor(timeoutMs / 4))) — declared values', () => {
  assert.equal(typeof plugin.dnsAttemptMs, 'function', '060 exports no attempt-window function');
  for (const [timeoutMs, want] of [[5000, 1250], [400, 100], [8000, 1999], [1200, 300]]) {
    assert.equal(plugin.dnsAttemptMs(timeoutMs), want, `timeoutMs ${timeoutMs}`);
  }
});
test('Q5: two silent resolvers use the whole deadline — a third is never asked, ETIMEOUT', async () => {
  await withServer({ handler: () => null }, async (a) => {
    await withServer({ handler: () => null }, async (b) => {
      await withServer({ handler: zone() }, async (c) => {
        assertWalkGap(await runDnssec(APEX, [a.entry, b.entry, c.entry], { timeoutMs: 1200 }), APEX, 'ETIMEOUT');
        assert.equal(a.log.length, 2, 'two attempts at the first');
        assert.equal(b.log.length, 2, 'two attempts at the second');
        assert.deepEqual(c.log, [], 'the third is never asked');
      });
    });
  });
});

// ── v415: silence, fourth quadrant first ────────────────────────────────────
test('silence (accept): a silent primary and an answering secondary — decided, inside the one deadline', async () => {
  await withServer({ handler: () => null }, async (mute) => {
    await withServer({ handler: zoneHandler({ ...SIGNED, [`www.${APEX} SOA`]: { answers: [] } }) }, async (s) => {
      const r = await runDnssec(`www.${APEX}`, [mute.entry, s.entry], { timeoutMs: 2400 });
      MEASURED_ACTIVE(r);
      assert.ok(r.ms < 2400, `took ${r.ms} ms`);
      assert.equal(mute.log.filter((l) => l.type === T.DNSKEY || l.type === T.DS).length, 0, 'a resolver marked silent is not asked again');
    });
  });
});
test('silence: every resolver silent — not measured, ETIMEOUT, no row; silence never reads as absent', async () => {
  await withServer({ handler: () => null }, async (a) => {
    await withServer({ handler: () => null }, async (b) => {
      const r = await runDnssec(APEX, [a.entry, b.entry], { timeoutMs: 1200 });
      assertWalkGap(r, APEX, 'ETIMEOUT');
      assert.ok(r.ms < 1200 + 1500, `took ${r.ms} ms`);
    });
  });
});

test('silence: a resolver marked silent is skipped for the rest of the probe — after the preferred one REFUSES, the next asked is the THIRD', async () => {
  // [mute, s1, s2], target www.example.test: step 0 costs mute two attempts and s1 decides it (NODATA). At step 1 s1
  // REFUSES; mute, already silent, is skipped; s2 decides. Without the skip mute is asked again and the walk hits the deadline.
  await withServer({ handler: () => null }, async (mute) => {
    await withServer({ handler: zoneHandler({ [`www.${APEX} SOA`]: { answers: [] }, [`${APEX} SOA`]: { rcode: 5 } }) }, async (s1) => {
      await withServer({ handler: zoneHandler({ ...SIGNED, [`www.${APEX} SOA`]: { answers: [] } }) }, async (s2) => {
        const r = await runDnssec(`www.${APEX}`, [mute.entry, s1.entry, s2.entry], { timeoutMs: 2400 });
        MEASURED_ACTIVE(r);
        assert.equal(mute.log.length, 2, `the silent resolver received ${JSON.stringify(queriesOf(mute))}`);
        assert.ok(r.ms < 2400, `took ${r.ms} ms`);
      });
    });
  });
});

// ── v415 S2 / v416 Q3: the resolver whose reply DECIDED is asked first; details.dnssec counts the deciding resolvers ──
const askedFor = (server, ...types) => server.log.filter((l) => types.includes(l.type)).length;
test('Q3 (accept): the first resolver answers everything — one deciding resolver, the second is never asked', async () => {
  await withServer({ handler: zone() }, async (r1) => {
    await withServer({ handler: zone() }, async (r2) => {
      const r = await runDnssec(APEX, [r1.entry, r2.entry]);
      MEASURED_ACTIVE(r);
      assert.equal(r.dnssec.resolverCount, 1);
      assert.deepEqual(r2.log, []);
    });
  });
});
test('Q3: the first REFUSES the walk and the second decides it — DNSKEY and DS go to the second; the first holds one query', async () => {
  await withServer({ handler: zoneHandler({ [`${APEX} SOA`]: { rcode: 5 }, [`${APEX} DNSKEY`]: KEYS, [`${APEX} DS`]: DS }) }, async (r1) => {
    await withServer({ handler: zoneHandler(UNSIGNED) }, async (r2) => {
      const r = await runDnssec(APEX, [r1.entry, r2.entry]);
      assert.deepEqual(r.rows, ['no_dnssec'], 'the apex and both record types come from ONE resolver (G13)');
      assert.equal(r1.log.length, 1, `the first resolver received ${JSON.stringify(queriesOf(r1))}`);
      assert.equal(askedFor(r1, T.DNSKEY, T.DS), 0);
      assert.equal(r.dnssec.resolverCount, 1);
    });
  });
});
test('Q3: an UNKNOWN walk reply (SERVFAIL, FORMERR, a reply the parser rejects) never makes that resolver preferred', async () => {
  for (const soa of [{ rcode: 2 }, { rcode: 1 }, (q) => ({ raw: pointerLoopReply(q) })]) {
    await withServer({ handler: zoneHandler({ [`${APEX} SOA`]: soa, [`${APEX} DNSKEY`]: KEYS, [`${APEX} DS`]: DS }) }, async (r1) => {
      await withServer({ handler: zoneHandler(UNSIGNED) }, async (r2) => {
        const r = await runDnssec(APEX, [r1.entry, r2.entry]);
        assert.deepEqual(r.rows, ['no_dnssec'], String(soa.rcode ?? 'raw'));
        assert.equal(askedFor(r1, T.DNSKEY, T.DS), 0, String(soa.rcode ?? 'raw'));
      });
    });
  }
});
test('Q3: the first decides the walk then falls silent; the second decides DNSKEY and DS — two deciding resolvers', async () => {
  const silentKeys = { [`${APEX} DNSKEY`]: () => null, [`${APEX} DS`]: () => null };
  await withServer({ handler: zoneHandler({ ...SIGNED, ...silentKeys }) }, async (r1) => {
    await withServer({ handler: zone() }, async (r2) => {
      const r = await runDnssec(APEX, [r1.entry, r2.entry], { timeoutMs: 2400 });
      MEASURED_ACTIVE(r);
      assert.equal(r.dnssec.resolverCount, 2);
      const one = await runDnssec(APEX, [r2.entry]);
      assert.equal(one.dnssec.resolverCount, 1);
      assert.equal(r.result.findings.dnssec[0].detail, one.result.findings.dnssec[0].detail, 'the count stays out of the row\'s sentence');
    });
  });
});

// ── EE VERDICT-v418 C1: a SERVFAIL the probe held vetoes the PASS ──────────────────────────────────────────────────
// A validating resolver's SERVFAIL is the only sign of a bogus chain this probe can see, since it validates no signature
// itself. So when any matched reply the probe read carried rcode 2, the PASS row (dnssec_active) is NOT written: ONE
// not-measured entry names the first such query, and both has* are null. The three MEDIUM rows stand — they fail toward a
// finding. Only rcode 2 vetoes. Stated limit: a resolver later in the list is not asked once an earlier one decides, so its
// SERVFAIL is never seen (leg (iv), pinned and not endorsed). Before the fix (CE 6934439) leg (i) read dnssec_active and
// recorded nothing about the SERVFAIL (EE audit-evidence-samples/ee-2.2.1/z1/architect-v418/drive_r1_servfail.out).
const rcodeEverywhere = (rcode) => ({ handler: () => ({ rcode }) });
test('C1 (ii, fourth quadrant first): [A REFUSED, B signed] — dnssec_active stands, servfail false; details.dnssec carries servfail', async () => {
  await withServer(rcodeEverywhere(5), async (a) => {
    await withServer({ handler: zone() }, async (b) => {
      const r = await runDnssec(APEX, [a.entry, b.entry]);
      MEASURED_ACTIVE(r);
      assert.equal(r.dnssec.servfail, false);
      assert.equal(a.log.length, 1, 'A was asked and refused');
      assert.deepEqual(Object.keys(r.dnssec).sort(), ['alias', 'hasDNSKEY', 'hasDS', 'resolverCount', 'servfail', 'zone']);
    });
  });
});
test('C1 (i): [A SERVFAIL, B signed] — no row, ONE entry SOA:<apex>:ESERVFAIL, has* null, up false, "DNSSEC not measured"', async () => {
  await withServer(rcodeEverywhere(2), async (a) => {
    await withServer({ handler: zone() }, async (b) => {
      const r = await runDnssec(APEX, [a.entry, b.entry]);
      assert.deepEqual(r.rows, [], 'never a PASS over a SERVFAIL the probe held');
      assert.deepEqual(r.nmRaw.map((e) => `${e.rrtype}:${e.name}:${e.code}`), [`SOA:${APEX}:ESERVFAIL`]);
      assert.equal(r.dnssec.hasDNSKEY, null);
      assert.equal(r.dnssec.hasDS, null);
      assert.equal(r.dnssec.servfail, true);
      assert.equal(r.result.up, false);
      assert.equal(r.line, 'DNSSEC not measured (ESERVFAIL)');
      assert.ok(askedFor(b, T.DNSKEY) === 1 && askedFor(b, T.DS) === 1, 'B decided the apex, DNSKEY and DS');
    });
  });
});
test('C1 (iii): [A SERVFAIL, B unsigned] — no_dnssec stands (a MEDIUM row is never vetoed), servfail true', async () => {
  await withServer(rcodeEverywhere(2), async (a) => {
    await withServer({ handler: zoneHandler(UNSIGNED) }, async (b) => {
      const r = await runDnssec(APEX, [a.entry, b.entry]);
      assert.deepEqual(r.rows, ['no_dnssec']);
      assert.deepEqual(r.nm, []);
      assert.equal(r.dnssec.servfail, true);
    });
  });
});
test('C1: the entry names the query that was SENT — a SERVFAIL on DNSKEY alone reads DNSKEY:<apex>:ESERVFAIL', async () => {
  await withServer({ handler: zone({ [`${APEX} DNSKEY`]: { rcode: 2 } }) }, async (a) => {
    await withServer({ handler: zone() }, async (b) => {
      const r = await runDnssec(APEX, [a.entry, b.entry]);
      assert.deepEqual(r.rows, []);
      assert.deepEqual(r.nmRaw.map((e) => `${e.rrtype}:${e.name}:${e.code}`), [`DNSKEY:${APEX}:ESERVFAIL`]);
      assert.equal(r.dnssec.hasDNSKEY, null);
      assert.equal(r.dnssec.hasDS, null);
      assert.equal(askedFor(b, T.DNSKEY), 1, 'B answered the DNSKEY question A SERVFAILed');
    });
  });
});
test('C1: two SERVFAILs — the entry names the FIRST (a walk step below the apex), not the later DNSKEY one', async () => {
  const HOST = `www.${APEX}`;
  // A: SERVFAILs the walk at the target and DNSKEY at the apex; answers the apex SOA and DS. B: no SOA at the target,
  // REFUSES the apex SOA (so A decides it and DNSKEY goes to A first), answers DNSKEY. Every step is sequential but the
  // last two, so the order of the two SERVFAILs is fixed.
  await withServer({ handler: zone({ [`${HOST} SOA`]: { rcode: 2 }, [`${APEX} DNSKEY`]: { rcode: 2 } }) }, async (a) => {
    await withServer({ handler: zone({ [`${APEX} SOA`]: { rcode: 5 } }) }, async (b) => {
      const r = await runDnssec(HOST, [a.entry, b.entry]);
      assert.deepEqual(r.rows, []);
      assert.deepEqual(r.nmRaw.map((e) => `${e.rrtype}:${e.name}:${e.code}`), [`SOA:${HOST}:ESERVFAIL`]);
      assert.equal(askedFor(a, T.DNSKEY), 1, 'A SERVFAILed DNSKEY too — the later SERVFAIL exists and is not the one named');
      assert.equal(askedFor(b, T.DNSKEY), 1);
    });
  });
});
test('C1: servfail is a boolean on a walk-gap return too — true for a SERVFAIL walk step, false for a silent resolver', async () => {
  await withServer(rcodeEverywhere(2), async (a) => {
    const r = await runDnssec(APEX, [a.entry]);
    assertWalkGap(r, APEX, 'ESERVFAIL');
    assert.equal(r.dnssec.servfail, true);
  });
  const r = await runDnssec(APEX, [`127.0.0.1:${await closedUdpPort()}`], { timeoutMs: 400 });
  assertWalkGap(r, APEX, 'ETIMEOUT');
  assert.equal(r.dnssec.servfail, false);
});
// A matched reply's rcode is read from its HEADER, whatever else the reply is: a TC=1 reply (which never decides) and a reply
// the parser rejects (EBADRESP) are still matched replies, and a SERVFAIL among them vetoes the PASS. Found by the (b2)
// fresh-reader review, driven: before this, each of the three shapes below read dnssec_active with servfail false.
const tcpRefused = (spec) => ({ handler: zone({ [`${APEX} DNSKEY`]: spec }), tcp: false });
test('C1 (accept, first): a TC=1 reply with rcode 0 (TCP refused), and an unparseable rcode-0 reply, do NOT veto — dnssec_active, servfail false', async () => {
  for (const a of [tcpRefused({ answers: [], tc: true }), { handler: zone({ [`${APEX} DNSKEY`]: (q) => ({ raw: pointerLoopReply(q) }) }) }]) {
    await withServer(a, async (s) => {
      await withServer({ handler: zone() }, async (b) => {
        const r = await runDnssec(APEX, [s.entry, b.entry]);
        MEASURED_ACTIVE(r);
        assert.equal(r.dnssec.servfail, false);
        assert.equal(askedFor(b, T.DNSKEY), 1, 'A did not decide DNSKEY; B did');
      });
    });
  }
});
/** A matched SERVFAIL whose ANCOUNT says one record and which carries none: the parser rejects it (EBADRESP). */
function malformedServfail(q) {
  const m = buildReply(q, { rcode: 2, answers: [] });
  m.writeUInt16BE(1, 6);
  return m;
}
for (const [what, a] of [
  ['A1: TC=1 with rcode 2, then TCP refused', tcpRefused({ answers: [], tc: true, rcode: 2 })],
  ['A2: TC=1, then TCP truncated again with rcode 2', { handler: zone({ [`${APEX} DNSKEY`]: (q, info) => ({ answers: [], tc: true, ...(info.transport === 'tcp' ? { rcode: 2 } : {}) }) }) }],
  ['A3: a SERVFAIL the parser rejects (ANCOUNT 1, no record)', { handler: zone({ [`${APEX} DNSKEY`]: (q) => ({ raw: malformedServfail(q) }) }) }],
]) {
  test(`C1: ${what} — the SERVFAIL is read from the header and vetoes the PASS: DNSKEY:<apex>:ESERVFAIL`, async () => {
    await withServer(a, async (s) => {
      await withServer({ handler: zone() }, async (b) => {
        const r = await runDnssec(APEX, [s.entry, b.entry]);
        assert.deepEqual(r.rows, [], 'never a PASS over a matched SERVFAIL');
        assert.deepEqual(r.nmRaw.map((e) => `${e.rrtype}:${e.name}:${e.code}`), [`DNSKEY:${APEX}:ESERVFAIL`]);
        assert.equal(r.dnssec.servfail, true);
      });
    });
  });
}
test('C1 (iv) STATED LIMIT — PINNED, NOT ENDORSED: [B signed, A SERVFAIL] — B decides first, A is never asked, dnssec_active', async () => {
  await withServer({ handler: zone() }, async (b) => {
    await withServer(rcodeEverywhere(2), async (a) => {
      const r = await runDnssec(APEX, [b.entry, a.entry]);
      MEASURED_ACTIVE(r);
      assert.equal(r.dnssec.servfail, false);
      assert.equal(a.log.length, 0, 'a resolver later in the list is not asked once an earlier one decides — its SERVFAIL is never seen');
    });
  });
});

// ── L9 / v416 Q2: the destination is the configured resolver, never an address from a reply ───────────────
/** Records every UDP send and TCP connect the process makes outside the given servers' own sockets, calling through. */
function recordDestinations(servers) {
  const seen = [];
  const send = dgram.Socket.prototype.send;
  const connect = net.Socket.prototype.connect;
  dgram.Socket.prototype.send = function recordedSend(...args) {
    if (!servers.some((s) => s.owns(this))) {
      const at = args.findLastIndex((a) => typeof a === 'string');
      seen.push(`udp ${args[at]}:${args[at - 1]}`);
    }
    return send.apply(this, args);
  };
  net.Socket.prototype.connect = function recordedConnect(...args) {
    const o = Array.isArray(args[0]) ? args[0][0] : args[0];
    if (o && typeof o === 'object') seen.push(`tcp ${o.host}:${o.port}`);
    else seen.push(`tcp ${args[1]}:${args[0]}`);
    return connect.apply(this, args);
  };
  return { seen, restore() { dgram.Socket.prototype.send = send; net.Socket.prototype.connect = connect; } };
}
/** The configured server at 127.0.0.1:P and a decoy at [::1]:P (a new P while [::1]:P is taken). */
async function configuredAndDecoy(t) {
  for (let i = 0; i < 20; i++) {
    const s = await startFakeDns({ handler: zone() });
    try {
      return { s, decoy: await startFakeDns({ host: '::1', port: s.port, handler: zone() }) };
    } catch (e) {
      await s.close();
      if (e.code === 'EADDRINUSE') continue;
      if (process.env.CI) assert.fail(`::1 cannot be bound (${e.code}) — the decoy arm cannot run here`);
      t.diagnostic(`::1 cannot be bound (${e.code}): the decoy arm did not run; the destination record still did`);
      return { s: await startFakeDns({ handler: zone() }), decoy: null };
    }
  }
  assert.fail('[::1]:P stayed taken across 20 ports');
}
const decoyRecord = { type: 'AAAA', name: `ns.${APEX}`, data: Buffer.from('00000000000000000000000000000001', 'hex') };
const carryDecoy = (handler) => (q, info) => {
  const spec = handler(q, info);
  if (!spec || spec.raw) return spec;
  return { ...spec, answers: [...(spec.answers ?? []), decoyRecord], authority: [decoyRecord], additional: [decoyRecord] };
};
test('L9 (accept first): the configured server receives the queries; a decoy whose address rides in every section receives nothing; every destination is the configured one', async (t) => {
  const { s, decoy } = await configuredAndDecoy(t);
  const rec = recordDestinations([s, ...(decoy ? [decoy] : [])]);
  try {
    s.handler = carryDecoy(zone());
    MEASURED_ACTIVE(await runDnssec(APEX, [s.entry]));
    assert.ok(s.log.length >= 3, 'the configured server received the queries');
    if (decoy) assert.deepEqual(decoy.log, [], `the decoy at [::1]:${s.port} received ${JSON.stringify(decoy.log)}`);
    const udp = rec.seen.filter((d) => d.startsWith('udp '));
    assert.ok(udp.length >= 3, `the record is live: ${rec.seen}`);
    assert.deepEqual([...new Set(rec.seen)], [`udp 127.0.0.1:${s.port}`]);
  } finally {
    rec.restore();
    await s.close();
    await decoy?.close();
  }
});
test('L9: in a TC=1 arm the TCP connect also goes only to the configured resolver (the record sees a connect)', async (t) => {
  const { s, decoy } = await configuredAndDecoy(t);
  const rec = recordDestinations([s, ...(decoy ? [decoy] : [])]);
  try {
    s.handler = carryDecoy(zone({ [`${APEX} DNSKEY`]: byTransport({ tc: true, answers: [] }, KEYS) }));
    MEASURED_ACTIVE(await runDnssec(APEX, [s.entry]));
    assert.ok(rec.seen.includes(`tcp 127.0.0.1:${s.port}`), `no TCP connect recorded: ${rec.seen}`);
    assert.deepEqual([...new Set(rec.seen)].sort(), [`tcp 127.0.0.1:${s.port}`, `udp 127.0.0.1:${s.port}`]);
    if (decoy) assert.deepEqual(decoy.log, []);
  } finally {
    rec.restore();
    await s.close();
    await decoy?.close();
  }
});

// ── L10: getServers() entries, through the real parser ──────────────────────
test('L10: each getServers() form yields the right family, address and port', () => {
  assert.equal(typeof plugin.parseResolverEntry, 'function', '060 has no parser for dns.getServers() entries');
  const cases = [
    ['192.0.2.1', { family: 4, address: '192.0.2.1', port: 53 }],
    ['192.0.2.1:5353', { family: 4, address: '192.0.2.1', port: 5353 }],
    ['2001:db8::1', { family: 6, address: '2001:db8::1', port: 53 }],
    ['[2001:db8::1]:5353', { family: 6, address: '2001:db8::1', port: 5353 }],
  ];
  for (const [entry, want] of cases) assert.deepEqual(plugin.parseResolverEntry(entry), want, entry);
  for (const bad of ['not-an-address', '192.0.2.1:0', '192.0.2.1:70000', '[2001:db8::1]']) assert.equal(plugin.parseResolverEntry(bad), null, bad);
});
test('L10: an entry that cannot be read is unknown (EBADSERVER) and the next resolver is asked', async () => {
  await withServer({ handler: zone() }, async (s) => {
    MEASURED_ACTIVE(await runDnssec(APEX, ['not-an-address', s.entry]));
    assertWalkGap(await runDnssec(APEX, ['not-an-address']), APEX, 'EBADSERVER');
  });
});
test('L10: a link-local IPv6 address without its scope — no special case: unknown with what the send gives, the next resolver decides', async () => {
  // What the send gives, measured 2026-11-27 on this machine: the callback fires with no error, and no reply comes back. The
  // kernel has no route for a scopeless fe80::1 (`route -n get -inet6 fe80::1`: not in table), and which interface it then
  // used cannot be seen without root — so this arm reproduces that outcome at the udp6 socket's send instead of putting a
  // datagram on a link (the suite under the EE air-gap probe recorded four sends to fe80::1:53 from this arm before).
  const orig = dgram.createSocket;
  const sent = [];
  dgram.createSocket = function createSocket(type, ...rest) {
    const sock = orig.call(dgram, type, ...rest);
    if ((typeof type === 'string' ? type : type?.type) === 'udp6') {
      const realSend = sock.send.bind(sock);
      sock.send = (buf, port, addr, cb) => {
        if (!String(addr).toLowerCase().startsWith('fe80:')) return realSend(buf, port, addr, cb);
        sent.push(`${addr}:${port}`);
        process.nextTick(() => cb?.(null));
      };
    }
    return sock;
  };
  try {
    await withServer({ handler: zone() }, async (s) => MEASURED_ACTIVE(await runDnssec(APEX, ['fe80::1', s.entry], { timeoutMs: 2400 })));
    assert.ok(sent.length >= 1 && sent.every((d) => d === 'fe80::1:53'), `060 sent to the entry as written: ${sent.join(' ')}`);
  } finally {
    dgram.createSocket = orig;
  }
});
test('L10: a send the socket REFUSES is unknown with the send\'s own code, and the next resolver is asked', async () => {
  // Measured 2026-11-27 on this machine: no address makes a UDP send fail here (fe80::1, fe80::1%lo0, 255.255.255.255,
  // 0.0.0.0, ff02::1 all call back without an error), so the refusal is injected into udp6 sockets' send callback.
  const orig = dgram.createSocket;
  dgram.createSocket = function createSocket(type, ...rest) {
    const sock = orig.call(dgram, type, ...rest);
    if ((typeof type === 'string' ? type : type?.type) === 'udp6') {
      sock.send = (buf, port, addr, cb) => process.nextTick(() => cb(Object.assign(new Error('injected'), { code: 'EADDRNOTAVAIL' })));
    }
    return sock;
  };
  try {
    assertWalkGap(await runDnssec(APEX, ['2001:db8::53']), APEX, 'EADDRNOTAVAIL');
    await withServer({ handler: zone() }, async (s) => MEASURED_ACTIVE(await runDnssec(APEX, ['2001:db8::53', s.entry])));
  } finally {
    dgram.createSocket = orig;
  }
});
