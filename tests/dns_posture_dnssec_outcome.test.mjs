// tests/dns_posture_dnssec_outcome.test.mjs
// ─────────────────────────────────────────────────────────────────────────────
// G-75 (D1) (b): EVERY CELL OF THE (DNSKEY, DS) PAIR IS DECIDED, AND THE CONCLUDE LINE SAYS WHAT THE ROW SAYS.
//
// Each record type is present | absent | unknown (architect VERDICT-v407 (b) SHAPE). Before (b) two cells were silent:
// a failed DNSKEY beside an answered DS read as an absence (G1), and DNSKEY absent beside DS present wrote no row and
// printed "no DNSSEC" (G2). And the conclude line read `hasDNSKEY ? "DNSSEC active" : "no DNSSEC"`, so dnssec_partial
// printed "DNSSEC active" beside a MEDIUM row (G4).
//
//   unknown in either  → one not-measured entry per unknown type, NO row, that side's has* null
//   absent,  absent    → no_dnssec (MEDIUM)            present, absent → dnssec_partial (MEDIUM)
//   absent,  present   → dnssec_ds_without_dnskey (MEDIUM, new)     present, present → dnssec_active (PASS)
//
// L6 drives the nine cells through the real decision function AND end to end on a real localhost server; L7 asserts the
// conclude line for each row and for a not-measured run (the WRITTEN-md form of L7 is a CLI leg).
// ─────────────────────────────────────────────────────────────────────────────
import './helpers/no_operator_home.mjs';
import './helpers/no_operator_dotenv.mjs';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runDnssec, plugin } from './helpers/dnssec_harness.mjs';
import { startFakeDns, zoneHandler } from './helpers/fake_dns_server.mjs';

const APEX = 'example.test';
const WIRE = {
  DNSKEY: { present: { answers: [{ type: 'DNSKEY' }] }, absent: { answers: [] }, unknown: { rcode: 2 } },
  DS: { present: { answers: [{ type: 'DS' }] }, absent: { answers: [] }, unknown: { rcode: 2 } },
};
const STATES = ['present', 'absent', 'unknown'];
const ROW = {
  'absent absent': 'no_dnssec', 'present absent': 'dnssec_partial',
  'absent present': 'dnssec_ds_without_dnskey', 'present present': 'dnssec_active',
};
const SEVERITY = { no_dnssec: 'medium', dnssec_partial: 'medium', dnssec_ds_without_dnskey: 'medium', dnssec_active: 'pass' };
const has = (s) => (s === 'present' ? true : s === 'absent' ? false : null);

async function runCell(k, d, host = APEX, extra = {}) {
  const s = await startFakeDns({ handler: zoneHandler({ [`${APEX} SOA`]: { answers: [{ type: 'SOA' }] },
    [`${APEX} DNSKEY`]: WIRE.DNSKEY[k], [`${APEX} DS`]: WIRE.DS[d], ...extra }) });
  try { return await runDnssec(host, [s.entry]); } finally { await s.close(); }
}

test('L6: the new row is declared in CHECK_IDS_BY_CATEGORY.dnssec beside the other three', () => {
  for (const id of Object.values(ROW)) assert.ok(plugin.CHECK_IDS_BY_CATEGORY.dnssec.includes(id), id);
});

test('L6: the nine cells, through the REAL decision function — each yields a row or an entry, never neither', () => {
  assert.equal(typeof plugin.dnssecOutcome, 'function', '060 has no single decision function over the pair');
  for (const k of STATES) {
    for (const d of STATES) {
      const out = plugin.dnssecOutcome({ state: k, code: k === 'unknown' ? 'ESERVFAIL' : undefined },
        { state: d, code: d === 'unknown' ? 'ESERVFAIL' : undefined });
      const cell = `${k} ${d}`;
      assert.equal(out.row, ROW[cell] ?? null, cell);
      assert.deepEqual(out.unknown, [['DNSKEY', k], ['DS', d]].filter(([, s]) => s === 'unknown').map(([rrtype]) => ({ rrtype, code: 'ESERVFAIL' })), cell);
      assert.equal(out.hasDNSKEY, has(k), cell);
      assert.equal(out.hasDS, has(d), cell);
      assert.ok(out.row !== null || out.unknown.length > 0, `${cell} yields neither a row nor an entry`);
    }
  }
});

for (const k of STATES) {
  for (const d of STATES) {
    const cell = `${k} ${d}`;
    test(`L6 (end to end): DNSKEY ${k}, DS ${d} → ${ROW[cell] ?? 'not measured, no row'}`, async () => {
      const r = await runCell(k, d);
      const row = ROW[cell];
      assert.deepEqual(r.rows, row ? [row] : []);
      if (row) assert.equal(r.result.findings.dnssec[0].severity, SEVERITY[row]);
      assert.deepEqual(r.nm, [['DNSKEY', k], ['DS', d]].filter(([, s]) => s === 'unknown').map(([t]) => `${t}:ESERVFAIL`));
      for (const e of r.nmRaw) assert.equal(e.name, APEX);
      assert.equal(r.dnssec.hasDNSKEY, has(k));
      assert.equal(r.dnssec.hasDS, has(d));
    });
  }
}

// ── L7, in-process: the conclude line reads the ROW ─────────────────────────
const LINE = {
  'present present': `DNSSEC active (zone ${APEX})`,
  'present absent': `DNSSEC partial: DNSKEY without DS (zone ${APEX})`,
  'absent present': `DNSSEC: DS without DNSKEY (zone ${APEX})`,
  'absent absent': `no DNSSEC (zone ${APEX})`,
};
for (const [cell, want] of Object.entries(LINE)) {
  test(`L7: ${ROW[cell]} → the conclude line reads "${want}"`, async () => {
    const [k, d] = cell.split(' ');
    const r = await runCell(k, d);
    assert.equal(r.line, want);
    if (ROW[cell] !== 'dnssec_active') assert.ok(!/DNSSEC active/.test(r.line), '"DNSSEC active" only for dnssec_active');
  });
}
test('L7: a not-measured run → "DNSSEC not measured (<code>)", never a row\'s words', async () => {
  const r = await runCell('unknown', 'present');
  assert.equal(r.line, 'DNSSEC not measured (ESERVFAIL)');
});
test('L7: a target below the apex — the line names the zone that was measured', async () => {
  const r = await runCell('present', 'present', `www.${APEX}`);
  assert.equal(r.line, `DNSSEC active (zone ${APEX})`);
});
test('L7: an alias target — the line carries the fixed alias words and no alias target', async () => {
  const r = await runCell('present', 'present', `www.${APEX}`, { [`www.${APEX} SOA`]: { answers: [{ type: 'CNAME' }] } });
  assert.equal(r.line, `DNSSEC active (zone ${APEX}; the name is an alias (CNAME), the zone it points into was not checked)`);
});
