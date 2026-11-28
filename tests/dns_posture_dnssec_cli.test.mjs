// tests/dns_posture_dnssec_cli.test.mjs — G-75 (D1) (f): the DNSSEC probe through the REAL CLI (EE VERDICT-v404 L4/L5,
// v407 L7/L8, v412 L7/L8 extensions).
//
// Every scan here is the real CLI (cli.mjs `scan --host <zone> --plugins 060`) in a CHILD process, spawned async so this
// process's event loop stays free to answer it. The child's resolver is the localhost fixture in this process
// (tests/helpers/dnssec_cli_zone.mjs) through tests/helpers/dns_fixture_preload.mjs, which also refuses any UDP send or TCP
// connect to a non-loopback address: every leg asserts the child refused nothing. The child runs as a Community-only
// install (tests/helpers/ee_absent_preload.mjs: the Enterprise package does not resolve, as when L8's baseline was
// written; the run record says tier "ce" and eeVersion null), AI off, no operator .env.
//
// `report` is a Pro subcommand, so a delta is read by the REAL runReport in-process with Pro capabilities, over run
// directories the real CLI wrote (the shape of the F-060 legs in dns_posture_resolver_failure_not_absence.test.mjs).
//
// WHERE THE CONCLUDE LINE IS WRITTEN (measured for this file): the md that `--output-format md` writes carries the ROWS
// (each non-PASS row as a finding, a not-measured check as its gap line) and never the conclude line; the conclude line
// is written into the conclusion's evidence `info` (scan_conclusion_raw.json) and the page rendered from it
// (scan_conclusion_raw.html). L7's written half asserts each on the file it is written to.
//
// L8's BASELINE is not written by this file: tests/fixtures/g75_dnssec_upgrade_baseline/<arm>/ is what Community
// 7864383's own CLI wrote over these same zones (DNSSEC not measured, ERR_INVALID_ARG_VALUE: the refused
// dns.resolve(host, "DNSKEY") of 1.1.0–1.2.0), copied unchanged except that each run's scan_history.jsonl is left out
// (tests/public_repo_hygiene.test.mjs refuses a tracked .jsonl, and the report does not read it); the generator and its
// transcript are sealed in the EE evidence tree (z1/g75-f-l8-baseline-v357).
import { withNoDotenv } from './helpers/no_operator_dotenv.mjs';
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import cp from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { startDnssecZones } from './helpers/dnssec_cli_zone.mjs';

const CLI = fileURLToPath(new URL('../cli.mjs', import.meta.url));
const PRELOAD = fileURLToPath(new URL('./helpers/dns_fixture_preload.mjs', import.meta.url));
const EE_ABSENT = fileURLToPath(new URL('./helpers/ee_absent_preload.mjs', import.meta.url));
const BASELINE = fileURLToPath(new URL('./fixtures/g75_dnssec_upgrade_baseline/', import.meta.url));
const WORK = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-dnssec-cli-'));
const zones = await startDnssecZones();
after(async () => { await zones.close(); fs.rmSync(WORK, { recursive: true, force: true }); });

let seq = 0;
/** One real-CLI scan of `host` into `out` (a fresh directory unless given). Reads back what it wrote. */
function scanCli(host, out = path.join(WORK, `out${++seq}`)) {
  const env = { ...process.env, AI_ENABLED: 'false', NSAUDITOR_LICENSE_KEY: 'not-a-licence', NSA_DNS_FIXTURE: zones.entry,
    NSAUDITOR_LICENSE_STATE_FILE: path.join(WORK, 'licence-state.json') };
  delete env.NODE_TEST_CONTEXT;
  return new Promise((resolve) => {
    const child = cp.spawn(process.execPath, ['--import', EE_ABSENT, '--import', PRELOAD, CLI, 'scan', '--host', host, '--plugins', '060',
      '--output-format', 'md', '--out', out], { cwd: WORK, env: withNoDotenv(env) });
    let stderr = '';
    child.stderr.on('data', (d) => { stderr += d; });
    child.stdout.on('data', () => {});
    child.on('close', (code) => {
      const read = (f) => fs.readFileSync(f, 'utf8');
      const runs = runIdsOf(out);
      const record = JSON.parse(read(path.join(out, `scan_run_${runs.at(-1)}.json`)));
      // The run record names the directory it wrote (two scans in one second get a `_2` suffix).
      assert.equal(record.hostsWritten?.length, 1, `one host written: ${JSON.stringify(record.hostsWritten)}\n${stderr.slice(-600)}`);
      const dir = path.join(out, record.hostsWritten[0].dir);
      const raw = JSON.parse(read(path.join(dir, 'scan_conclusion_raw.json')));
      const result = raw.results.find((x) => String(x.id) === '060')?.result;
      resolve({ code, stderr, out, raw, result, record, runId: runs.at(-1), md: read(path.join(out, 'scan_report.md')),
        html: read(path.join(dir, 'scan_conclusion_raw.html')),
        info: (raw.conclusion?.result?.evidence ?? []).find((e) => e.dnsSecurity)?.info ?? null,
        refused: Number(/\[dns-fixture\] refused (\d+)/.exec(stderr)?.[1] ?? NaN) });
    });
  });
}
/** The run ids in `out`, oldest first (by the record's own startedAt). */
function runIdsOf(out) {
  return fs.readdirSync(out).filter((n) => /^scan_run_.+\.json$/.test(n))
    .map((n) => [n.slice('scan_run_'.length, -'.json'.length), JSON.parse(fs.readFileSync(path.join(out, n), 'utf8')).startedAt])
    .sort((a, b) => a[1].localeCompare(b[1])).map(([id]) => id);
}
/** What every leg needs true of a run before its own assertion means anything. */
function premise(r, host) {
  assert.equal(r.refused, 0, `the child reached nothing off loopback: ${r.stderr.slice(-400)}`);
  assert.deepEqual([r.record.tier, r.record.eeVersion], ['ce', null], 'the scan ran as a Community-only install');
  assert.equal(r.raw.pluginStatus.find((p) => String(p.id) === '060')?.status, 'ran', `060 ran on ${host}: ${r.stderr.slice(-400)}`);
  assert.equal(r.code, 0, r.stderr.slice(-400));
}
const memo = new Map();
const scanOnce = (host) => { if (!memo.has(host)) memo.set(host, scanCli(host)); return memo.get(host); };
const dnssecEntries = (r) => (r.result.details.notMeasured ?? []).filter((e) => e.check === 'dnssec').map((e) => `${e.rrtype}:${e.name}:${e.code}`);

// ── L7's not-measured run FIRST (the fourth quadrant of L4: the probe ran and wrote no row) ─────────────────────────────
test('L4/L7 (first): a resolver SERVFAIL on DNSKEY — no DNSSEC row, one entry, and the written line says "DNSSEC not measured (ESERVFAIL)"', async () => {
  const r = await scanOnce('servfail.test');
  premise(r, 'servfail.test');
  assert.deepEqual(r.result.findings.dnssec, []);
  assert.deepEqual(dnssecEntries(r), ['DNSKEY:servfail.test:ESERVFAIL']);
  assert.match(r.info, /\| DNSSEC not measured \(ESERVFAIL\)(?: \||$)/, r.info);
  assert.ok(r.html.includes('DNSSEC not measured (ESERVFAIL)'), 'the page carries the line');
  assert.ok(r.md.includes('**gap only:** Evidence gap: the DNSSEC check was not measured — the DNSKEY lookup for servfail.test failed (ESERVFAIL)'),
    `the md carries the gap line:\n${r.md}`);
  for (const f of [r.md, r.html, r.info]) assert.doesNotMatch(f, /DNSSEC active/);
});

// ── L4: signed and unsigned, every check measured ───────────────────────────────────────────────────────────────────────
for (const [host, row, severity] of [['unsigned.test', 'no_dnssec', 'medium'], ['signed.test', 'dnssec_active', 'pass']]) {
  test(`L4: the real CLI over ${host} → ${row}, notMeasured empty`, async () => {
    const r = await scanOnce(host);
    premise(r, host);
    assert.deepEqual(r.result.findings.dnssec.map((i) => [i.check, i.severity]), [[row, severity]]);
    assert.deepEqual(r.result.details.notMeasured, [], 'every check measured');
    assert.equal(r.result.summary.notMeasured, 0);
    assert.equal(r.result.details.dnssec.zone, host);
  });
}

// ── L7, written half: the conclude line for each row, on the files it is written to ──────────────────────────────────────
const LINES = [
  ['signed.test', 'dnssec_active', 'DNSSEC active (zone signed.test)'],
  ['unsigned.test', 'no_dnssec', 'no DNSSEC (zone unsigned.test)'],
  ['partial.test', 'dnssec_partial', 'DNSSEC partial: DNSKEY without DS (zone partial.test)'],
  ['dsonly.test', 'dnssec_ds_without_dnskey', 'DNSSEC: DS without DNSKEY (zone dsonly.test)'],
  ['www.signed.test', 'dnssec_active', 'DNSSEC active (zone signed.test)'],
  ['www.alias.test', 'dnssec_active', 'DNSSEC active (zone alias.test; the name is an alias (CNAME), the zone it points into was not checked)'],
];
for (const [host, row, line] of LINES) {
  test(`L7 (written): ${host} → ${row} → the written conclusion and page read "${line}"`, async () => {
    const r = await scanOnce(host);
    premise(r, host);
    assert.deepEqual(r.result.findings.dnssec.map((i) => i.check), [row]);
    assert.deepEqual(r.result.details.notMeasured, []);
    assert.ok(r.info.split(' | ').includes(line), `the conclusion's info carries the line: ${r.info}`);
    assert.ok(r.html.includes(line.replace(/&/g, '&amp;')), 'the page carries the line');
    // "DNSSEC active" only for dnssec_active, on every written file; the md never carries it (a PASS is not a finding).
    assert.doesNotMatch(r.md, /DNSSEC active/);
    if (row !== 'dnssec_active') for (const f of [r.html, r.info]) assert.doesNotMatch(f, /DNSSEC active/);
    // A non-PASS row is a finding in the md, in the row's own words.
    const detail = r.result.findings.dnssec[0].detail;
    if (row === 'dnssec_active') assert.ok(!r.md.includes(detail));
    else assert.ok(r.md.includes(`DNS security: ${detail}`), `the md lists the ${row} row:\n${r.md}`);
  });
}
test('L7 (written): a target below the apex names the zone that holds it, and an alias never prints the alias target', async () => {
  const below = await scanOnce('www.signed.test');
  assert.equal(below.result.details.dnssec.zone, 'signed.test');
  const alias = await scanOnce('www.alias.test');
  assert.deepEqual([alias.result.details.dnssec.zone, alias.result.details.dnssec.alias], ['alias.test', true]);
  // The fixture's CNAME points at target.www.alias.test (fake_dns_server.mjs rdataFor). No written file names it.
  const written = fs.readdirSync(alias.out, { recursive: true }).map(String).filter((f) => fs.statSync(path.join(alias.out, f)).isFile());
  for (const f of written) assert.ok(!fs.readFileSync(path.join(alias.out, f), 'utf8').includes('target.www.alias.test'), f);
});

// ── report --since over real-CLI runs ───────────────────────────────────────────────────────────────────────────────────
async function since(out, base, cur) {
  const { runReport } = await import('../cli.mjs');
  const { resolveCapabilities } = await import('../utils/capabilities.mjs');
  const rep = await runReport({ from: out, format: 'executive', run: cur, since: base, out: path.join(out, 'exec.html') }, resolveCapabilities('pro'));
  assert.equal(rep.code, 0, rep.stderr);
  const m = rep.stdout.match(/(\d+) new · (\d+) resolved · (\d+) changed · (\d+) not-comparable · (\d+) unchanged/);
  assert.ok(m, `the delta line: ${rep.stdout.slice(0, 300)}`);
  const page = fs.readFileSync(path.join(out, 'exec.html'), 'utf8');
  const at = page.indexOf('Since Last Scan');
  const sect = at < 0 ? '' : page.slice(at, page.indexOf('</table>', at));
  const strip = (x) => x.replace(/<[^>]+>/g, ' ').replace(/&quot;/g, '"').replace(/&amp;/g, '&').replace(/\s+/g, ' ').trim();
  const rows = (sect.match(/<tr[\s\S]*?<\/tr>/g) ?? []).slice(1).map((tr) => (tr.match(/<td[\s\S]*?<\/td>/g) ?? []).map(strip));
  // A long title is cut at a fixed width and ends "…": a row is found by the visible prefix of its full text.
  const visible = (t) => t.replace(/…$/, '');
  const change = (full) => rows.filter((r) => r[1].length >= 40 && full.startsWith(visible(r[1]))).map((r) => r[0]);
  const held = (full) => rep.stdout.split('\n').filter((l) => {
    const h = / NOT COMPARABLE \((?:appeared|disappeared)\) {2}(.+?) — evidence-gap: /.exec(l);
    return h && h[1].length >= 40 && full.startsWith(visible(h[1]));
  });
  return { stdout: rep.stdout, n: { new: +m[1], resolved: +m[2], changed: +m[3], notComparable: +m[4] }, change, held, rows };
}

test('L5: report --since over two real-CLI runs of a fully measured zone — the removed SPF "+all" row reads RESOLVED', async () => {
  const out = path.join(WORK, 'l5');
  zones.setSpf('v=spf1 +all');
  let a;
  try { a = await scanCli('spf.test', out); } finally { zones.setSpf('v=spf1 -all'); }
  const b = await scanCli('spf.test', out);
  for (const r of [a, b]) { premise(r, 'spf.test'); assert.deepEqual(r.result.details.notMeasured, [], 'both runs fully measured'); }
  const plusAll = a.result.findings.spf.find((i) => /\+all/.test(i.detail));
  assert.ok(plusAll, 'premise: run 1 graded the +all row');
  assert.ok(!b.result.findings.spf.some((i) => /\+all/.test(i.detail)), 'premise: run 2 did not');
  const d = await since(out, a.runId, b.runId);
  assert.deepEqual(d.change(plusAll.detail), ['resolved'], d.stdout);
  // The PASS is a row of the delta: the fixed policy reads one NEW row, run 2's own "-all" PASS, and nothing else.
  const minusAll = b.result.findings.spf.find((i) => /"-all"/.test(i.detail));
  assert.equal(minusAll?.severity, 'pass', 'premise: run 2 graded the "-all" PASS');
  assert.deepEqual(d.change(minusAll.detail), ['new'], d.stdout);
  assert.deepEqual([d.n.new, d.n.resolved, d.n.notComparable], [1, 1, 0], d.stdout);
});

// ── L8: the upgrade delta, the baseline written by 7864383's own code ─────────────────────────────────────────────────
for (const [arm, host, row, zone] of [
  ['unsigned', 'unsigned.test', 'no_dnssec', 'unsigned.test'],
  ['signed', 'signed.test', 'dnssec_active', 'signed.test'],
  ['nonapex', 'www.signed.test', 'dnssec_active', 'signed.test'],
]) {
  test(`L8 (${arm}): baseline 7864383 (DNSSEC not measured, ERR_INVALID_ARG_VALUE) → after ${row} on ${host} — never NEW: held, citing the baseline's gap`, async () => {
    const out = path.join(WORK, `l8-${arm}`);
    fs.cpSync(path.join(BASELINE, arm), out, { recursive: true });
    const [baseId] = runIdsOf(out);
    const baseDir = JSON.parse(fs.readFileSync(path.join(out, `scan_run_${baseId}.json`), 'utf8')).hostsWritten[0].dir;
    const base = JSON.parse(fs.readFileSync(path.join(out, baseDir, 'scan_conclusion_raw.json'), 'utf8')).results.find((x) => String(x.id) === '060').result;
    assert.deepEqual(base.findings.dnssec, [], 'premise: the baseline wrote no DNSSEC row');
    assert.deepEqual(base.details.notMeasured.filter((e) => e.check === 'dnssec').map((e) => `${e.rrtype}:${e.name}:${e.code}`),
      [`DNSKEY:${host}:ERR_INVALID_ARG_VALUE`], 'premise: the baseline recorded DNSSEC not measured, as 7864383 did');
    const r = await scanCli(host, out);
    premise(r, host);
    assert.deepEqual(r.result.findings.dnssec.map((i) => i.check), [row]);
    assert.deepEqual(r.result.details.notMeasured, [], 'the after-run measured every check');
    assert.equal(r.result.details.dnssec.zone, zone);
    const detail = r.result.findings.dnssec[0].detail;
    // v412 G12: a target below the apex — the row names the zone measured AND the target it holds.
    if (host !== zone) assert.ok(detail.includes(`for the zone ${zone}, which holds ${host},`), detail);
    const d = await since(out, baseId, r.runId);
    assert.equal(d.n.new, 0, d.stdout);
    assert.deepEqual(d.change(detail), ['not-comparable'], d.stdout);
    const held = d.held(detail);
    assert.equal(held.length, 1, d.stdout);
    assert.match(held[0], new RegExp(`NOT COMPARABLE \\(appeared\\) .* — evidence-gap: the baseline run recorded an evidence gap on .*: Evidence gap: the DNSSEC check was not measured — the DNSKEY lookup for ${host.replace(/\./g, '\\.')} failed \\(ERR_INVALID_ARG_VALUE\\)`), held[0]);
  });
}
