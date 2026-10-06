// tests/service_check_not_tested.test.mjs
// 1.2.1 lane 3, (s3) — a check that did not run, or ran and could not complete, is NOT TESTED, said with its reason —
// never "none", never "denied".
//
// Three opt-in checks had no not-tested state, and each wrote a NEGATIVE where nothing was measured:
//   - DNS zone transfer: null for opt-in off and for "on, no domain" alike; and a timeout, a TCP error, a parse error or a
//     close with no answer all wrote axfrAllowed:false and an evidence row reading "denied".
//   - Anonymous FTP login: with the check on, a server that did not greet with 220, or an exchange that timed out, wrote
//     anonymousLogin:false.
//   - SMB null session: false by default — opt-in off, a timeout and a socket error all read as "refused".
// The HTTP methods (a4) already had their state (methodsTested); it moves onto the same table.
//
// Harness: every network leg talks to a loopback listener this file starts (or to a loopback port nothing listens on).
// FOURTH QUADRANT FIRST: a check that ran and measured lists nothing.

import './helpers/no_operator_dotenv.mjs';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import * as T from '../utils/service_flags.mjs';
import { buildMarkdownReport } from '../utils/report_md.mjs';
import { maxSeverityInConclusion } from '../cli.mjs';
import dnsScanner, { conclude as dnsConclude } from '../plugins/dns_scanner.mjs';
import ftpCheck, { conclude as ftpConclude } from '../plugins/ftp_banner_check.mjs';
import { probeNullSession, conclude as netbiosConclude } from '../plugins/netbios_scanner.mjs';

const open = (fields) => ({ port: 1, protocol: 'tcp', service: 'x', status: 'open', ...fields });
const reasons = (fields) => T.notTestedChecks(open(fields)).map((n) => [n.check, n.reason]);

// ── THE TABLE ────────────────────────────────────────────────────────────────────────────────────────────────────
test('(fourth quadrant, first) a check that ran and measured lists nothing — allowed or refused alike', () => {
  for (const fields of [{ axfrAllowed: false, axfrTested: true }, { axfrAllowed: true, axfrTested: true },
    { anonymousLogin: false, anonymousLoginTested: true }, { nullSessionAllowed: false, nullSessionTested: true },
    { methodsTested: true, allowedMethods: ['GET'], dangerousMethods: [] }, { program: 'OpenSSH' }]) {
    assert.deepEqual(reasons(fields), [], JSON.stringify(fields));
  }
});

test('each not-tested state is said with its reason', () => {
  assert.deepEqual(reasons({ axfrAllowed: null, axfrTested: 'opt-in-off' }), [['DNS zone transfer', 'the check is off (DNS_CHECK_AXFR is unset)']]);
  assert.deepEqual(reasons({ axfrAllowed: null, axfrTested: 'no-domain' }), [['DNS zone transfer', 'no domain was given (DNS_AXFR_DOMAIN is unset)']]);
  assert.deepEqual(reasons({ axfrAllowed: null, axfrTested: 'no-answer' }), [['DNS zone transfer', 'the exchange did not complete, so nothing was measured']]);
  assert.deepEqual(reasons({ anonymousLogin: null, anonymousLoginTested: 'opt-in-off' }), [['Anonymous FTP login', 'the check is off (FTP_CHECK_ANON is unset)']]);
  assert.deepEqual(reasons({ anonymousLogin: null, anonymousLoginTested: 'no-answer' }), [['Anonymous FTP login', 'the exchange did not complete, so nothing was measured']]);
  assert.deepEqual(reasons({ nullSessionAllowed: null, nullSessionTested: 'opt-in-off' }), [['SMB null session', 'the check is off (SMB_NULL_SESSION is unset)']]);
  assert.deepEqual(reasons({ nullSessionAllowed: null, nullSessionTested: 'no-answer' }), [['SMB null session', 'the exchange did not complete, so nothing was measured']]);
  assert.deepEqual(reasons({ methodsTested: false, allowedMethods: null, dangerousMethods: null }),
    [['HTTP methods', 'no Allow header was read, so dangerous methods were not checked there (not "none")']]);
});

test('a record written before 1.2.1 — the result null, no state recorded — is NOT TESTED "not recorded", never refused', () => {
  assert.deepEqual(reasons({ axfrAllowed: null }), [['DNS zone transfer', 'the scan that wrote this record did not record whether the check ran']]);
  assert.deepEqual(reasons({ nullSessionAllowed: null }), [['SMB null session', 'the scan that wrote this record did not record whether the check ran']]);
});

test('NOT TESTED is never a finding — no grade, and --fail-on stays at info', () => {
  const states = [{ axfrAllowed: null, axfrTested: 'no-answer' }, { anonymousLogin: null, anonymousLoginTested: 'no-answer' },
    { nullSessionAllowed: null, nullSessionTested: 'no-answer' }, { methodsTested: false, dangerousMethods: null }];
  for (const fields of states) assert.deepEqual(T.flagFindings(open(fields)), [], JSON.stringify(fields));
  assert.equal(maxSeverityInConclusion({ result: { services: states.map(open) } }), 0);
});

test('a service that did not answer lists no not-tested check — the check had nothing to run against', () => {
  assert.deepEqual(T.notTestedChecks({ ...open({ axfrAllowed: null, axfrTested: 'no-answer' }), status: 'filtered' }), []);
});

test('the Markdown report says each NOT TESTED check, grouped by reason, with its targets', () => {
  const md = buildMarkdownReport({ host: 'h', conclusion: { result: { services: [
    { port: 53, protocol: 'udp', service: 'dns', status: 'open', axfrAllowed: null, axfrTested: 'no-domain' },
    { port: 5353, protocol: 'udp', service: 'dns', status: 'open', axfrAllowed: null, axfrTested: 'no-domain' },
    { port: 21, protocol: 'tcp', service: 'ftp', status: 'open', anonymousLogin: null, anonymousLoginTested: 'no-answer' },
    { port: 80, protocol: 'http', service: 'http', status: 'open', methodsTested: false, dangerousMethods: null },
  ] } } });
  assert.match(md, /- \*\*DNS zone transfer not tested:\*\* 53\/udp, 5353\/udp — no domain was given \(DNS\\_AXFR\\_DOMAIN is unset\)/);
  assert.match(md, /- \*\*Anonymous FTP login not tested:\*\* 21\/tcp — the exchange did not complete, so nothing was measured/);
  assert.match(md, /- \*\*HTTP methods not tested:\*\* 80\/http — no Allow header was read, so dangerous methods were not checked there \(not "none"\)/);
  assert.match(md, /\*\*Security findings:\*\* 0/, 'none of them is a finding');
});

// ── THE PRODUCERS — each driven against a loopback listener ─────────────────────────────────────────────────────────
async function listen(t, onConn) {
  const srv = net.createServer(onConn);
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const sockets = new Set();
  srv.on('connection', (s) => { sockets.add(s); s.on('close', () => sockets.delete(s)); });
  t.after(() => { for (const s of sockets) s.destroy(); srv.close(); });
  return srv.address().port;
}
async function closedPort() {
  const srv = net.createServer();
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const { port } = srv.address();
  await new Promise((r) => srv.close(r));
  return port;
}
function withEnv(t, vars) {
  const prev = Object.fromEntries(Object.keys(vars).map((k) => [k, process.env[k]]));
  for (const [k, v] of Object.entries(vars)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
  t.after(() => { for (const [k, v] of Object.entries(prev)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; } });
}
const axfrOf = async (port) => {
  const r = await dnsScanner.run('127.0.0.1', port, { timeoutMs: 300 });
  const [rec] = await dnsConclude({ host: '127.0.0.1', result: r });
  return { r, rec };
};
// A DNS-over-TCP listener answering every query with the given RCODE (header only, the query's id echoed).
const dnsAnswering = (rcode) => (sock) => sock.on('data', (buf) => {
  if (buf.length < 4) return;
  const id = buf.readUInt16BE(2);
  const msg = Buffer.alloc(12);
  msg.writeUInt16BE(id, 0);
  msg.writeUInt16BE(0x8000 | rcode, 2);
  const len = Buffer.alloc(2); len.writeUInt16BE(msg.length, 0);
  sock.write(Buffer.concat([len, msg]));
});

test('DNS zone transfer: opt-in off and "on, no domain" are told apart', async (t) => {
  const port = await closedPort();
  withEnv(t, { DNS_CHECK_AXFR: undefined, DNS_AXFR_DOMAIN: undefined });
  assert.deepEqual([(await axfrOf(port)).rec.axfrAllowed, (await axfrOf(port)).rec.axfrTested], [null, 'opt-in-off']);
  process.env.DNS_CHECK_AXFR = '1';
  assert.deepEqual([(await axfrOf(port)).rec.axfrAllowed, (await axfrOf(port)).rec.axfrTested], [null, 'no-domain']);
});

test('(fourth quadrant) DNS zone transfer: an explicit refusal, or TCP/53 refusing the connection, IS a measurement — refused', async (t) => {
  withEnv(t, { DNS_CHECK_AXFR: '1', DNS_AXFR_DOMAIN: 'example.test' });
  const refusing = await listen(t, dnsAnswering(5));
  const a = await axfrOf(refusing);
  assert.deepEqual([a.rec.axfrAllowed, a.rec.axfrTested], [false, true]);
  assert.ok(a.r.data.some((d) => /AXFR example\.test denied/.test(d.probe_info)), 'the evidence row says denied');
  const b = await axfrOf(await closedPort());
  assert.deepEqual([b.rec.axfrAllowed, b.rec.axfrTested], [false, true], 'nothing listens on TCP: no transfer can be had');
});

test('DNS zone transfer: a TIMEOUT, or a close with no answer, is NOT TESTED — never "denied"', async (t) => {
  withEnv(t, { DNS_CHECK_AXFR: '1', DNS_AXFR_DOMAIN: 'example.test' });
  for (const [what, onConn] of [['timeout', () => {}], ['close with no answer', (s) => s.on('data', () => s.end())]]) {
    const { r, rec } = await axfrOf(await listen(t, onConn));
    assert.deepEqual([rec.axfrAllowed, rec.axfrTested], [null, 'no-answer'], what);
    const row = r.data.find((d) => /AXFR example\.test/.test(d.probe_info));
    assert.ok(row && !/denied/.test(row.probe_info), `${what}: the evidence row does not say denied — ${row?.probe_info}`);
    assert.match(row.probe_info, /not measured/);
  }
});

// FTP: a loopback server that greets with `greeting`, then answers USER / PASS as told (undefined = never answers).
const ftpServer = (greeting, { user, pass } = {}) => (sock) => {
  sock.write(`${greeting}\r\n`);
  sock.on('data', (buf) => {
    const line = buf.toString();
    if (/^USER/.test(line) && user) sock.write(`${user}\r\n`);
    if (/^PASS/.test(line) && pass) sock.write(`${pass}\r\n`);
  });
};
const ftpOf = async (port) => {
  const r = await ftpCheck.run('127.0.0.1', port, {});
  const [rec] = await ftpConclude({ host: '127.0.0.1', result: r });
  return rec;
};

test('anonymous FTP login: opt-in off is NOT TESTED "opt-in-off" on an FTP record that answered', async (t) => {
  withEnv(t, { FTP_CHECK_ANON: undefined });
  const rec = await ftpOf(await listen(t, ftpServer('220 test FTP')));
  assert.deepEqual([rec.status, rec.anonymousLogin, rec.anonymousLoginTested], ['open', null, 'opt-in-off']);
});

test('(fourth quadrant) anonymous FTP login: accepted, and refused, are measurements', async (t) => {
  withEnv(t, { FTP_CHECK_ANON: '1' });
  const ok = await ftpOf(await listen(t, ftpServer('220 test FTP', { user: '331 password please', pass: '230 welcome' })));
  assert.deepEqual([ok.anonymousLogin, ok.anonymousLoginTested], [true, true]);
  const no = await ftpOf(await listen(t, ftpServer('220 test FTP', { user: '331 password please', pass: '530 login incorrect' })));
  assert.deepEqual([no.anonymousLogin, no.anonymousLoginTested], [false, true]);
});

test('anonymous FTP login: no 220 greeting, or an exchange that never answers, is NOT TESTED — never "refused"', async (t) => {
  withEnv(t, { FTP_CHECK_ANON: '1' });
  const busy = await ftpOf(await listen(t, ftpServer('421 too many connections')));
  assert.deepEqual([busy.anonymousLogin, busy.anonymousLoginTested], [null, 'no-answer'], 'no 220 greeting');
  const silent = await ftpOf(await listen(t, ftpServer('220 test FTP')));
  assert.deepEqual([silent.anonymousLogin, silent.anonymousLoginTested], [null, 'no-answer'], 'USER never answered');
});

// SMB: the null-session probe, through its exported seam (port and switch default to production's 445 and env).
const smb2 = (status) => {
  const hdr = Buffer.alloc(64);
  hdr.writeUInt32BE(0xfe534d42, 0);
  hdr.writeUInt16LE(64, 4);
  hdr.writeUInt32LE(status >>> 0, 8);
  const nbss = Buffer.alloc(4); nbss.writeUInt32BE(hdr.length, 0);
  return Buffer.concat([nbss, hdr]);
};
const STATUS = { SUCCESS: 0x00000000, ACCESS_DENIED: 0xc0000022, NOT_SUPPORTED: 0xc00000bb };
const smbServer = (...replies) => (sock) => { let i = 0; sock.on('data', () => { if (i < replies.length) sock.write(smb2(replies[i++])); }); };

test('SMB null session: opt-in off is NOT TESTED "opt-in-off", not "refused"', async () => {
  const r = await probeNullSession('127.0.0.1', { enabled: false });
  assert.deepEqual([r.nullSessionAllowed, r.nullSessionTested], [null, 'opt-in-off']);
});

test('(fourth quadrant) SMB null session: a session setup the server DENIES is a measurement — refused', async (t) => {
  const port = await listen(t, smbServer(STATUS.SUCCESS, STATUS.ACCESS_DENIED));
  const r = await probeNullSession('127.0.0.1', { enabled: true, port, timeoutMs: 2000 });
  assert.deepEqual([r.nullSessionAllowed, r.nullSessionTested], [false, true]);
});

test('SMB null session: a timeout, or a negotiate the server rejects, is NOT TESTED — never "refused"', async (t) => {
  const silent = await probeNullSession('127.0.0.1', { enabled: true, port: await listen(t, () => {}), timeoutMs: 300 });
  assert.deepEqual([silent.nullSessionAllowed, silent.nullSessionTested], [null, 'no-answer'], 'timeout');
  const noNeg = await probeNullSession('127.0.0.1', { enabled: true, port: await listen(t, smbServer(STATUS.NOT_SUPPORTED)), timeoutMs: 2000 });
  assert.deepEqual([noNeg.nullSessionAllowed, noNeg.nullSessionTested], [null, 'no-answer'], 'negotiate rejected');
});

test('the NetBIOS adapter carries the state, and an old result with no state is null — never the old default false', async () => {
  const [now] = await netbiosConclude({ host: 'h', result: { up: true, nullSessionAllowed: null, nullSessionTested: 'opt-in-off',
    data: [{ probe_port: 445, probe_protocol: 'tcp', probe_info: 'SMB2' }] } });
  assert.deepEqual([now.nullSessionAllowed, now.nullSessionTested], [null, 'opt-in-off']);
  const [old] = await netbiosConclude({ host: 'h', result: { up: true, data: [{ probe_port: 445, probe_protocol: 'tcp', probe_info: 'SMB2' }] } });
  assert.deepEqual([old.nullSessionAllowed, old.nullSessionTested], [null, null]);
});

// The FTP and DNS twins of the NetBIOS leg above (the audit seat's fold): an adapter handed a result an earlier release
// wrote — no state field — must say it was NOT RECORDED. Defaulting the state to 'opt-in-off' names a switch that may well
// have been set: a false reason, which two surviving mutants showed nothing caught.
test('the FTP and DNS adapters: an old result with no state is null → "not recorded", never a reason it did not record', async () => {
  const [ftpRec] = await ftpConclude({ host: 'h', result: { up: true, program: 'vsftpd', version: '3.0.3',
    data: [{ probe_protocol: 'tcp', probe_port: 21, probe_info: '220 vsFTPd', response_banner: '220 (vsFTPd 3.0.3)' }] } });
  assert.equal(ftpRec.status, 'open', 'positive control: an answering FTP record');
  assert.deepEqual([ftpRec.anonymousLogin, ftpRec.anonymousLoginTested], [null, null]);
  assert.deepEqual(T.notTestedChecks(ftpRec).map((n) => n.reason), ['the scan that wrote this record did not record whether the check ran']);
  const [dnsRec] = await dnsConclude({ host: 'h', result: { up: true, program: 'BIND', version: '9.18',
    data: [{ probe_protocol: 'udp', probe_port: 53, probe_info: 'version.bind', response_banner: '9.18' }] } });
  assert.equal(dnsRec.status, 'open', 'positive control: an answering DNS record');
  assert.deepEqual([dnsRec.axfrAllowed, dnsRec.axfrTested], [null, null]);
  assert.deepEqual(T.notTestedChecks(dnsRec).map((n) => n.reason), ['the scan that wrote this record did not record whether the check ran']);
});

// ── WHERE A READER LEARNS WHAT A NULL MEANS ─────────────────────────────────────────────────────────────────────────
// scan_host returns the records as they are, so the AI client reading `nullSessionAllowed: null` is told what that
// means — and the README says it for operators. Tied to the fields the table reads, so the sentence names what lands.
test('the scan_host description and the README name each state field and say a null result is NOT TESTED', async () => {
  const fs = await import('node:fs');
  const { TOOLS } = await import('../mcp_server.mjs');
  const d = TOOLS.find((x) => x.name === 'scan_host').description;
  const readme = fs.readFileSync(new URL('../README.md', import.meta.url), 'utf8');
  for (const field of ['axfrTested', 'anonymousLoginTested', 'nullSessionTested']) {
    assert.match(d, new RegExp(field)); assert.match(readme, new RegExp(field));
  }
  assert.match(d, /null result is NOT TESTED, never "refused"/);
  assert.match(readme, /null result is not tested, never "refused"/);
  assert.match(d, /SMB_NULL_SESSION/); assert.match(readme, /SMB_NULL_SESSION=true/);
});
