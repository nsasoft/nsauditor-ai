// THE DNS-POSTURE AUDIT (060) DECLINES AN IP-LITERAL TARGET (0.2.57).
//
// 060 audits a DOMAIN's DNS posture — SPF, DMARC, DKIM, NS delegation, DNSSEC, CAA, wildcard records — and it has no
// requirements, so it runs on every default scan (`--plugins` defaults to all). Given an IP literal, it queried the
// literal as a name, every query answered NXDOMAIN, and every absence became a finding: missing SPF, missing DMARC and
// no NS records (HIGH), no DKIM selector and no DNSSEC (MEDIUM), no CAA (LOW). Measured through the real CLI
// (`scan --host 192.0.2.1 --plugins 060 --fail-on high`, a resolver stub answering NXDOMAIN): Community 0.2.56 put
// none of them in the graded table and instead concluded an OPEN 53/tcp `dns` service on a host no probe had touched
// (exit 0); 0.2.57's concluder no longer invents that port, and the same six findings reached the graded table, so
// the scan exited 1 under `--fail-on high` — on every default scan of an IP address. An IP address has no SPF, DMARC
// or NS posture to audit, so 060 now DECLINES it: `{ skipped: true, reason }`, recorded on the plugin's status, never
// a silent no-op. A HOSTNAME that merely resolves to an address — `localhost` included — is a domain and still runs.
//
// FOURTH QUADRANT FIRST. Every DNS query here answers NXDOMAIN and every non-loopback socket throws, in-process and in
// the spawned CLI alike, so not even the red phase of these legs can reach the network.
import { withNoDotenv } from './helpers/no_operator_dotenv.mjs';
import './helpers/no_operator_home.mjs';
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import cp from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const dnsP = require('node:dns').promises;
const net = require('node:net');
const dgram = require('node:dgram');
let queries = 0;
const nxdomain = async (name) => { queries += 1; throw Object.assign(new Error(`queryX ENOTFOUND ${name}`), { code: 'ENOTFOUND' }); };
for (const k of ['resolve', 'resolve4', 'resolve6', 'resolveTxt', 'resolveCname', 'resolveMx', 'resolveNs', 'resolveSoa',
  'resolveCaa', 'resolveAny']) dnsP[k] = nxdomain;
net.createConnection = net.connect = () => { throw new Error('in-process leg: refused a TCP connection'); };
dgram.createSocket = () => { throw new Error('in-process leg: refused a UDP socket'); };

const { default: dnsSec } = await import('../plugins/060_dns_sec_auditor.mjs');
const { PluginManager } = await import('../plugin_manager.mjs');
const DECLINE = /^DNS posture needs a domain name — .+ is an IP address, which has no SPF, DMARC or NS records to audit$/;
const runOn = async (host) => { queries = 0; const r = await dnsSec.run(host, 0, {}); return { r, queries }; };

// ── FOURTH QUADRANT FIRST: a domain still runs ────────────────────────────────────────────────────────────────────────
test('(q, first) a DOMAIN target still runs: it queries DNS and reports what it found', async () => {
  const { r, queries: n } = await runOn('example.test');
  assert.ok(n > 0, 'the audit queried DNS for the domain');
  assert.notEqual(r.skipped, true);
  assert.ok(r.findings && r.summary.high >= 1, 'a domain with no SPF / DMARC / NS records is reported, as before');
});

test('(q) a HOSTNAME that resolves to an address is still a domain — localhost runs; the guard is the IP literal alone', async () => {
  const { r, queries: n } = await runOn('localhost');
  assert.ok(n > 0); assert.notEqual(r.skipped, true);
});

// ── THE DECLINE ───────────────────────────────────────────────────────────────────────────────────────────────────────
test('an IPv4 literal is DECLINED with its reason, and no DNS query is made', async () => {
  const { r, queries: n } = await runOn('192.0.2.1');
  assert.equal(n, 0, 'nothing to query: an address is not a name');
  assert.equal(r.skipped, true);
  assert.equal(r.up, false);
  assert.match(r.reason, DECLINE);
  assert.equal(r.findings, undefined, 'no finding of any severity');
});

test('an IPv6 literal is DECLINED the same way — both families', async () => {
  for (const host of ['2001:db8::1', '::1']) {
    const { r, queries: n } = await runOn(host);
    assert.deepEqual([n, r.skipped, DECLINE.test(r.reason)], [0, true, true], host);
  }
});

test('the decline is RECORDED on the plugin\'s status — skipped, with the reason — never a silent no-op; a domain is "ran"', async () => {
  const mgr = new PluginManager('/nonexistent');
  const at = async (host) => (await mgr._runOrchestrated(host, [dnsSec])).manifest.find((m) => m.id === '060');
  const ip = await at('192.0.2.1');
  assert.deepEqual([ip?.status, DECLINE.test(ip?.reason ?? '')], ['skipped', true]);
  assert.equal((await at('example.test'))?.status, 'ran');
});

test('the 0.2.56 class stays impossible: a declined result concludes to NOTHING — no service row, no open port', () => {
  assert.deepEqual(dnsSec.conclude({ result: { up: false, skipped: true, reason: 'x' }, host: '192.0.2.1' }), []);
});

// ── THROUGH THE REAL CLI ──────────────────────────────────────────────────────────────────────────────────────────────
const CLI = fileURLToPath(new URL('../cli.mjs', import.meta.url));
const STUB = fileURLToPath(new URL('./helpers/dns_nxdomain_stub.mjs', import.meta.url));
const WORK = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-dns-posture-ip-'));
after(() => fs.rmSync(WORK, { recursive: true, force: true }));

function scanCli(host, name) {
  const out = path.join(WORK, name);
  const env = { ...process.env, AI_ENABLED: 'false' };
  delete env.NODE_TEST_CONTEXT;
  return new Promise((resolve) => {
    const child = cp.spawn(process.execPath, ['--import', STUB, CLI, 'scan', '--host', host, '--plugins', '060', '--fail-on', 'high',
      '--out', out], { cwd: WORK, env: withNoDotenv(env) });
    let stderr = '';
    child.stderr.on('data', (d) => { stderr += d; });
    child.on('close', (code) => {
      const hostDir = fs.existsSync(out) ? fs.readdirSync(out).find((n) => /_\d{8}_\d{6}$/.test(n)) : null;
      const raw = hostDir ? JSON.parse(fs.readFileSync(path.join(out, hostDir, 'scan_conclusion_raw.json'), 'utf8')) : null;
      const hist = fs.existsSync(path.join(out, 'scan_history.jsonl'))
        ? JSON.parse(fs.readFileSync(path.join(out, 'scan_history.jsonl'), 'utf8').trim().split('\n').pop()) : null;
      const q = /\[dns-stub\] queries (\d+)/.exec(stderr);
      resolve({ code, stderr, raw, hist, queries: q ? Number(q[1]) : null });
    });
  });
}

test('(q) THE CLI over a DOMAIN: the posture findings still reach --fail-on — exit 1 at high', async () => {
  const r = await scanCli('example.test', 'domain');
  assert.ok(r.queries > 0, `the stub answered the audit's queries: ${r.stderr.slice(-300)}`);
  assert.equal(r.code, 1, `a domain with no SPF / DMARC / NS records fails --fail-on high: ${r.stderr.slice(-300)}`);
});

test('THE CLI over an IP: 060 declined, no DNS query, no service, no open port, nothing counted — exit 0 at --fail-on high', async () => {
  const r = await scanCli('192.0.2.1', 'ip');
  assert.equal(r.queries, 0, 'the audit made no DNS query for an address');
  assert.equal(r.code, 0, `nothing at or above high: ${r.stderr.slice(-300)}`);
  const res = r.raw?.conclusion?.result;
  assert.ok(res, 'the conclusion was written');
  assert.deepEqual(res.services, [], 'no service row — the invented 53/tcp of 0.2.56 stays impossible');
  assert.doesNotMatch(res.summary, /Open: dns\/53/);
  assert.equal((res.evidence ?? []).filter((e) => e.dnsSecurity).length, 0, 'no DNS-posture record');
  const st = (r.raw?.pluginStatus ?? []).find((p) => String(p.id) === '060');
  assert.deepEqual([st?.status, DECLINE.test(st?.reason ?? '')], ['skipped', true], 'the decline is on the run record with its reason');
  assert.deepEqual([r.hist?.findingsCount, r.hist?.openPorts], [0, []], 'the history line counts nothing for the address');
});
