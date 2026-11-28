// tests/helpers/dnssec_cli_zone.mjs
// ─────────────────────────────────────────────────────────────────────────────
// The fixture zones the G-75 (f) CLI legs scan (tests/dns_posture_dnssec_cli.test.mjs) — and the zones the committed
// 7864383 baseline was written against (tests/fixtures/g75_dnssec_upgrade_baseline/), so the two runs of an upgrade leg
// see the same zone. A real localhost DNS server (UDP and TCP, fake_dns_server.mjs); every answer the CLI's 060 asks for
// comes from this table, through c-ares (A, NS, TXT …) and through its raw path (SOA, DNSKEY, DS) alike.
//
//   signed.test     apex SOA, DNSKEY and DS          → dnssec_active
//   unsigned.test   apex SOA, no DNSKEY, no DS       → no_dnssec
//   partial.test    DNSKEY, no DS                    → dnssec_partial
//   dsonly.test     DS, no DNSKEY                    → dnssec_ds_without_dnskey
//   servfail.test   the DNSKEY query SERVFAILs       → DNSSEC not measured (ESERVFAIL), no row
//   www.signed.test a name below signed.test's apex (no SOA there) → the row names the zone signed.test
//   www.alias.test  an alias (its SOA query answers a CNAME) inside the signed zone alias.test
//   spf.test        signed; its SPF TXT is settable (setSpf), for the report --since leg
// Every zone answers NS (target.<zone>) and that name's A, an A for the apex, and an SPF TXT; nothing else (MX, CAA,
// DMARC, DKIM) is answered, so those checks MEASURE an absence. Answers carry no text from outside this file.
// ─────────────────────────────────────────────────────────────────────────────
import { startFakeDns, T } from './fake_dns_server.mjs';

const txt = (s) => Buffer.concat([Buffer.from([s.length]), Buffer.from(s)]);
const KIND = {
  'signed.test': { dnskey: 'present', ds: 'present' },
  'unsigned.test': { dnskey: 'absent', ds: 'absent' },
  'partial.test': { dnskey: 'present', ds: 'absent' },
  'dsonly.test': { dnskey: 'absent', ds: 'present' },
  'servfail.test': { dnskey: 'servfail', ds: 'present' },
  'alias.test': { dnskey: 'present', ds: 'present' },
  'spf.test': { dnskey: 'present', ds: 'present' },
};
export const APEXES = Object.freeze(Object.keys(KIND));

export async function startDnssecZones() {
  let spf = 'v=spf1 -all';
  const handler = (q) => {
    const name = q.name.toLowerCase();
    if (name === 'www.signed.test' && q.type === T.A) return { answers: [{ type: 'A' }] };
    if (name === 'www.alias.test') return q.type === T.SOA ? { answers: [{ type: 'CNAME' }] } : { answers: [] };
    const zone = APEXES.find((z) => name === z || name === `target.${z}`);
    if (!zone) return { answers: [] };
    if (name === `target.${zone}`) return q.type === T.A ? { answers: [{ type: 'A' }] } : { answers: [] };
    const k = KIND[zone];
    switch (q.type) {
      case T.SOA: return { answers: [{ type: 'SOA' }] };
      case T.NS: return { answers: [{ type: 'NS' }] };
      case T.A: return { answers: [{ type: 'A' }] };
      case T.TXT: return { answers: [{ type: 'TXT', data: txt(zone === 'spf.test' ? spf : 'v=spf1 -all') }] };
      case T.DNSKEY: return k.dnskey === 'servfail' ? { rcode: 2 } : { answers: k.dnskey === 'present' ? [{ type: 'DNSKEY' }] : [] };
      case T.DS: return { answers: k.ds === 'present' ? [{ type: 'DS' }] : [] };
      default: return { answers: [] };
    }
  };
  const server = await startFakeDns({ handler });
  return { server, entry: server.entry, setSpf: (v) => { spf = v; }, close: () => server.close() };
}
