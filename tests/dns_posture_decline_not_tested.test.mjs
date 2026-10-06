// THE DNS-POSTURE AUDIT'S DECLINE IS SAID WHERE scan_host's READER LOOKS (1.3.0 build 4 — Gate 3-A finding F-1, the
// operator's ruling "Fix now").
//
// 060 declines an IP-address target (0.2.57): `{ skipped: true, reason }`, recorded on the plugin's status, which
// scan_host returns in `manifest`. But scan_host's description said the audit "lands on the 53/udp record when the scan
// found a 53/udp service, otherwise in the conclusion's evidence", and its markdown listed "the DNS-security audit of the
// domain (060)" among the checks it counts and said nothing more. Measured on build 3's router run (an IP target, a
// 53/udp dnsmasq service): `dnsSecurity` on neither the record nor the evidence — an absence where the tool promised a
// result, which a reader takes for "no DNS issues". Now:
//  - the markdown carries `DNS-security audit (060) not tested: <host> — <the plugin's own reason>`, DERIVED FROM THE
//    PLUGIN STATUS, never from the absence of `dnsSecurity`. 060 absent from the manifest was not REQUESTED, which is not
//    a decline, so it adds no line;
//  - scan_host and the CLI's `--output-format md` both hand the renderer the manifest (the CLI leg lives with the
//    decline's own CLI legs, in dns_posture_declines_ip_target.test.mjs);
//  - the description and the README condition the sentence on the target's form.
//
// FOURTH QUADRANT FIRST: a domain on which 060 RAN carries no such line, and neither does a run that did not request it.
// Every DNS query answers NXDOMAIN and every socket throws, so no leg reaches the network.
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const dnsP = require('node:dns').promises;
const net = require('node:net');
const dgram = require('node:dgram');
const nxdomain = async (name) => { throw Object.assign(new Error(`queryX ENOTFOUND ${name}`), { code: 'ENOTFOUND' }); };
for (const k of ['resolve', 'resolve4', 'resolve6', 'resolveTxt', 'resolveCname', 'resolveMx', 'resolveNs', 'resolveSoa',
  'resolveCaa', 'resolveAny']) dnsP[k] = nxdomain;
net.createConnection = net.connect = () => { throw new Error('refused a TCP connection'); };
dgram.createSocket = () => { throw new Error('refused a UDP socket'); };

const { default: dnsSec } = await import('../plugins/060_dns_sec_auditor.mjs');
const { default: concluder } = await import('../plugins/result_concluder.mjs');
const { default: PluginManager } = await import('../plugin_manager.mjs');
const { buildMarkdownReport } = await import('../utils/report_md.mjs');
const { TOOLS, handleScanHost, _setPluginManager, _setValidateHost } = await import('../mcp_server.mjs');

const LINE = /^- \*\*DNS-security audit \(060\) not tested:\*\* (.+?) — (.+)$/m;
const IP = '192.0.2.1';
const DECLINE = `DNS posture needs a domain name — ${IP} is an IP address, which has no SPF, DMARC or NS records to audit`;
const scan = async (host, plugins = [dnsSec, concluder]) => (await PluginManager.create({ plugins })).run(host, 'all');
const render = (host, out, manifest = out.manifest) => buildMarkdownReport({ host, conclusion: out.conclusion, manifest });
const at060 = (out) => out.manifest.find((m) => String(m.id) === '060');

// ── FOURTH QUADRANT FIRST ──────────────────────────────────────────────────────────────────────────────────────────────
test('(q, first) a DOMAIN on which 060 RAN carries NO not-tested line — its findings are counted instead', async () => {
  const out = await scan('example.test');
  assert.equal(at060(out)?.status, 'ran', 'positive control: the audit ran');
  const md = render('example.test', out);
  assert.doesNotMatch(md, LINE);
  assert.match(md, /\*\*Security findings:\*\* [1-9]/, 'the domain\'s missing SPF / DMARC / NS are counted');
});

test('(q) a run that did not REQUEST 060 adds no line — absent from the manifest is not a decline', async () => {
  const quiet = { id: '9301', name: 'Quiet', runStrategy: 'single', priority: 50, requirements: {}, run: async () => ({ up: true, data: [] }) };
  const out = await scan(IP, [quiet, concluder]);
  assert.equal(at060(out), undefined, 'positive control: 060 is not in the manifest');
  assert.doesNotMatch(render(IP, out), LINE);
});

test('(q) the line comes from the STATUS, never from the absence of dnsSecurity — the same conclusion without the manifest says nothing', async () => {
  const out = await scan(IP);
  const res = out.conclusion?.result ?? {};
  assert.equal([...(res.services ?? []), ...(res.evidence ?? [])].filter((r) => r.dnsSecurity).length, 0, 'no dnsSecurity anywhere');
  assert.doesNotMatch(buildMarkdownReport({ host: IP, conclusion: out.conclusion }), LINE);
});

// ── THE DECLINE, SAID ──────────────────────────────────────────────────────────────────────────────────────────────────
test('an IP target: the markdown says the DNS-security audit was NOT TESTED, with the plugin\'s own reason, verbatim', async () => {
  const out = await scan(IP);
  assert.equal(at060(out)?.status, 'skipped');
  const m = LINE.exec(render(IP, out));
  assert.ok(m, 'the not-tested line is present');
  assert.deepEqual([m[1], m[2]], [IP, DECLINE]);
  assert.equal(m[2], at060(out).reason, 'the reason is the manifest\'s, not a second wording');
});

test('an audit that timed out or errored is NOT TESTED too, with its reason — "could not complete" is not "nothing found"', () => {
  for (const entry of [{ id: '060', status: 'timeout', reason: 'timed out after 90000ms' },
    { id: '060', status: 'error', reason: 'resolver exploded' }]) {
    const m = LINE.exec(buildMarkdownReport({ host: 'example.test', conclusion: {}, manifest: [entry] }));
    assert.deepEqual([m?.[1], m?.[2]], ['example.test', entry.reason], entry.status);
  }
});

test('scan_host hands the renderer its manifest: the decline is in the markdown it returns, and a domain\'s is not', async () => {
  _setValidateHost(async (h) => h);
  after(() => { _setPluginManager(null); _setValidateHost(null); });
  _setPluginManager(await PluginManager.create({ plugins: [dnsSec, concluder] }));
  const ip = await handleScanHost({ host: IP });
  assert.equal(ip.manifest.find((m) => String(m.id) === '060')?.status, 'skipped');
  assert.equal(LINE.exec(ip.markdown)?.[2], DECLINE);
  _setPluginManager(await PluginManager.create({ plugins: [dnsSec, concluder] }));
  assert.doesNotMatch((await handleScanHost({ host: 'example.test' })).markdown, LINE, 'fourth quadrant: a domain');
});

// ── THE TEXT A READER IS GIVEN ─────────────────────────────────────────────────────────────────────────────────────────
// A unit that says where the DNS-security audit LANDS must say it lands only for a domain name, and that an IP address
// is declined. The predicate is driven on the sentence that shipped in build 3 before it judges the shipped text.
const BUILD3 = 'the DNS-security audit (060, dnsSecurity) lands on the 53/udp record when the scan found a 53/udp service, '
  + 'otherwise in the conclusion\'s evidence.';
const conditioned = (u) => /domain-name target/.test(u) && /IP-address target/.test(u) && /declin/i.test(u);
const landing = (u) => /(?:dnsSecurity|DNS-security audit)[^.]*53\/udp/.test(u);

test('(q) the predicate refuses build 3\'s sentence and accepts a conditioned one', () => {
  assert.equal(landing(BUILD3) && !conditioned(BUILD3), true, 'build 3\'s sentence is a landing claim with no condition');
  const fixed = 'For a domain-name target the DNS-security audit (060, dnsSecurity) lands on the 53/udp record when the scan '
    + 'found a 53/udp service; for an IP-address target it declines.';
  assert.equal(conditioned(fixed), true);
});

test('scan_host\'s description conditions where the DNS-security audit lands on the target\'s form', () => {
  const d = TOOLS.find((t) => t.name === 'scan_host').description;
  const units = d.split(/(?<=\.)\s+/).filter(landing);
  assert.ok(units.length >= 1, 'positive control: the description says where the audit lands');
  for (const u of units) assert.ok(conditioned(u), `unconditioned: ${u}`);
});

test('the README\'s scan_host row conditions it the same way', () => {
  const readme = fs.readFileSync(new URL('../README.md', import.meta.url), 'utf8');
  const units = readme.split('\n').filter(landing);
  assert.ok(units.length >= 1, 'positive control: the README says where the audit lands');
  for (const u of units) assert.ok(conditioned(u), `unconditioned: ${u.slice(0, 200)}`);
});
