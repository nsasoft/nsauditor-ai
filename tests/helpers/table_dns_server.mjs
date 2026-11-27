// tests/helpers/table_dns_server.mjs
// ─────────────────────────────────────────────────────────────────────────────
// For the in-process 060 tests that describe a zone as a TABLE of c-ares answers (`answer(type, name)` → a value, or a
// throw carrying a code). Since G-75 (b), 060 asks SOA, DNSKEY and DS by RAW DNS to dns.getServers(); such a test must
// point getServers() at a localhost server or it sends real UDP to the machine's resolver (pick-up v353 trap 2).
//
// serveTable(answer) starts a real localhost DNS server (fake_dns_server.mjs) that answers SOA, DNSKEY and DS from the
// SAME table, translating each c-ares outcome to the wire outcome a resolver would have produced:
//   records (a non-empty array, or an object for SOA) → NOERROR with records of the asked type
//   ENODATA → NOERROR, no record · ENOTFOUND → NXDOMAIN · ESERVFAIL → SERVFAIL · EREFUSED / ECONNREFUSED → REFUSED
//   EFORMERR → FORMERR · ENOTIMP → NOTIMP · ETIMEOUT → no reply · EBADRESP → a reply the parser rejects
//   any other outcome → THROWS in the server's handler. The plugin then hears silence and reads ETIMEOUT, but the throw
//   reaches node:test as an uncaught exception and fails the file, so a table value with no wire form is never a quiet
//   answer nobody chose.
// It then sets dns.promises.getServers to that server. The server's sockets are unref'd, so the test process exits
// without closing it.
// ─────────────────────────────────────────────────────────────────────────────
import { createRequire } from 'node:module';
import { startFakeDns, T, pointerLoopReply } from './fake_dns_server.mjs';

const require = createRequire(import.meta.url);
const dnsP = require('node:dns').promises;

const RCODE = { ENOTFOUND: 3, ESERVFAIL: 2, EREFUSED: 5, ECONNREFUSED: 5, EFORMERR: 1, ENOTIMP: 4 };
const NAME = { [T.SOA]: 'SOA', [T.DNSKEY]: 'DNSKEY', [T.DS]: 'DS' };

export async function serveTable(answer) {
  const server = await startFakeDns({
    unref: true,
    handler: (q) => {
      const type = NAME[q.type];
      if (!type) throw new Error(`table_dns_server: 060 asked ${q.type} for ${q.name}; only SOA, DNSKEY and DS go by raw DNS`);
      let value;
      let code = null;
      try { value = answer(type, q.name.toLowerCase()); } catch (e) { code = e?.code ?? null; if (!code) throw e; }
      if (code === null && value instanceof Promise) throw new Error('table_dns_server: the table must answer synchronously');
      if (code === null) {
        const records = Array.isArray(value) ? value : value && typeof value === 'object' ? [value] : [];
        return { answers: records.map(() => ({ type })) };
      }
      if (code === 'ENODATA') return { answers: [] };
      if (code === 'ETIMEOUT') return null;
      if (code === 'EBADRESP') return { raw: pointerLoopReply(q) };
      if (code in RCODE) return { rcode: RCODE[code] };
      throw new Error(`table_dns_server: the table answers ${type} ${q.name} with ${code}, which has no wire form`);
    },
  });
  dnsP.getServers = () => [server.entry];
  return server;
}
