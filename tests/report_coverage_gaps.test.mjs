// tests/report_coverage_gaps.test.mjs
// ─────────────────────────────────────────────────────────────────────────────
// G-72 (EE Z-1, architect RULINGS-v392 items 1-2, as replaced by VERDICT-v395 §4 and RULINGS-v396 C1-C5): a row that
// carries the coverage-gap marker (`evidenceGap`) is always LISTED, in the md report and in the executive html report. It
// leaves the executive COUNT only when its producer DECLARES (`gapOnly`) that the row records nothing but a surface the
// scanner could not read. A gap-flagged row with no declaration is counted as before AND listed: on Enterprise cloud rows
// the marker is additive (a public bucket whose object sample was truncated is one row), so the rule fails toward counting.
// Today the declaring producers are CE's 040 and 050 and the loader's 060 row; no Enterprise producer declares.
//
// One fixture per loader SOURCE path, each driven by the REAL producer where one exists in CE:
//   040 result.findings[] (array)        a port the port scanner saw open whose every connection is RESET (two ports)
//   050 result.findings.coverage (dict)  every reply gzip-coded, so no body was read
//   060 result.details.notMeasured[]     the DMARC lookup times out, on a 120-char zone (the loader cuts its title: Q1)
//   a MEDIUM array gap                   shape copied from the Gate-2 aws run, plugin 1120, result.findings[] (v394 M2)
//   the EE finding queue                 shape copied from EE utils/service_set_input_gap.mjs:103-127 (v394 M4)
//   F-A / F-B / F-C                      Enterprise rows on which the marker is additive (support/…/_cloud_mixed_rows.mjs),
//                                        their bars, findings rows and Top Risks captured at CE 6618bae BEFORE the change
// The conclusion files the executive legs read are written by the REAL scanSingleHost (v393 G-B); the run records by the
// real record writers. The queue file is the one file written here: no EE producer runs in CE.
// ─────────────────────────────────────────────────────────────────────────────
import './helpers/no_operator_dotenv.mjs';
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import cp from 'node:child_process';
import fs from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

// 060's resolver, patched BEFORE 060 loads (as tests/dns_posture_resolver_failure_not_absence.test.mjs does). The resolve*
// family only: 040 and 050 need real loopback sockets, and 060 opens none without the zone-transfer opt-in.
const dnsP = createRequire(import.meta.url)('node:dns').promises;
const ZONE = `${'a'.repeat(63)}.${'b'.repeat(43)}.example.test`; // 120 chars: long enough that the loader cuts the title
let TABLE = {};
const answer = (t, n) => {
  const k = n.startsWith('nsauditor-wildcard-probe-') ? `A *.${ZONE}` : `${t} ${n}`;
  const v = k in TABLE ? TABLE[k] : 'ENODATA';
  if (typeof v === 'string') throw Object.assign(new Error(`query ${v} ${k}`), { code: v });
  return v;
};
for (const [fn, t] of [['resolve4', 'A'], ['resolve6', 'AAAA'], ['resolveCname', 'CNAME'], ['resolveMx', 'MX'], ['resolveNs', 'NS'],
  ['resolveSoa', 'SOA'], ['resolveTxt', 'TXT'], ['resolveCaa', 'CAA'], ['resolveAny', 'ANY']]) dnsP[fn] = async (n) => answer(t, n);
dnsP.resolve = async (n, t = 'A') => answer(t, n);

const { default: p040 } = await import('../plugins/040_tls_cert_auditor.mjs');
const { default: p050 } = await import('../plugins/050_tribe_health.mjs');
const { default: p060 } = await import('../plugins/060_dns_sec_auditor.mjs');
const { default: concluder } = await import('../plugins/result_concluder.mjs');
const { buildMarkdownReport } = await import('../utils/report_md.mjs');
const { shapeHostFindings } = await import('../utils/report_inputs.mjs');
const { escapeHtml } = await import('../utils/brand.mjs');
const { EVIDENCE_GAPS_RECORDED } = await import('../utils/scan_delta.mjs');
const { describeFinding } = await import('../utils/cloud_finding_summary.mjs');
const { MIXED_PLUGINS, MIXED_RESULTS, MIXED_LABELS } = await import('./support/report_coverage_gaps/_cloud_mixed_rows.mjs');

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const FIXTURES = path.join(ROOT, 'tests', 'support', 'report_coverage_gaps'); // captured at CE 6618bae, BEFORE the G-72 change
const HOST = '192.0.2.10'; // RFC 5737: scanSingleHost's target guard refuses a private address
const SCAN_TIME = '2026-11-26T00:00:00.000Z'; // v394 M1: every md is built at a FIXED time, never compared across instants
const listen = (srv) => new Promise((ok) => srv.listen(0, '127.0.0.1', () => ok(srv.address().port)));
const isGap = (f) => f?.evidenceGap === true;
// The declaration, read independently of the writers' isGapOnly: exactly `true`, and only on a gap-flagged row.
const isDeclared = (f) => isGap(f) && f?.gapOnly === true;
// Captured at CE 6618bae by `git archive 6618bae` + the same realRun/runReport path (EE Z/g72-v343/, sealed there).
const GOLD_MIXED = JSON.parse(fs.readFileSync(path.join(FIXTURES, 'cloud-mixed-6618bae.json'), 'utf8')).pages;
const GOLD_IDENTITY = JSON.parse(fs.readFileSync(path.join(FIXTURES, 'gap-identity-6618bae.json'), 'utf8')).rows;
/** Each listener port replaced by a fixed token before shaping, exactly as the 6618bae capture did (C5). */
const pinPorts = (result, ports) => {
  let s = JSON.stringify(result);
  ports.forEach((p, i) => { s = s.replace(new RegExp(`\\b${p}\\b`, 'g'), String(50001 + i)); });
  return JSON.parse(s);
};

// ── the real gap results ──────────────────────────────────────────────────────────────────────────────────────────────
async function run040({ pin = false } = {}) {
  const servers = [net.createServer((s) => s.resetAndDestroy()), net.createServer((s) => s.resetAndDestroy())];
  const ports = [];
  for (const s of servers) ports.push(await listen(s));
  try {
    const r = await p040.run.call({ ...p040, ports }, '127.0.0.1', 0,
      { timeoutMs: 3000, context: { tcpOpen: new Set(ports), pluginRunStatus: new Map([['003', 'ran']]) } });
    return pin ? pinPorts(r, ports) : r;
  } finally { for (const s of servers) s.close(); }
}
async function run050({ pin = false } = {}) {
  const gz = Buffer.from([0x1f, 0x8b, 0x08, 0x00, 0xde, 0xad, 0xbe, 0xef]);
  const srv = http.createServer((req, res) => { req.resume(); res.writeHead(200, { 'content-encoding': 'gzip', 'content-type': 'application/json' }); res.end(gz); });
  const port = await listen(srv);
  try { const r = await p050.run('127.0.0.1', port, { timeoutMs: 3000 }); return pin ? pinPorts(r, [port]) : r; } finally { srv.close(); srv.closeAllConnections?.(); }
}
async function run060() {
  TABLE = { [`A ${ZONE}`]: ['192.0.2.10'], [`TXT ${ZONE}`]: [['v=spf1 -all']], [`TXT _dmarc.${ZONE}`]: 'ETIMEOUT', [`A *.${ZONE}`]: 'ENOTFOUND' };
  return p060.run(ZONE, 0, { dkimSelectors: 'google' });
}
// v394 M2: a gap at MEDIUM, its shape copied from the Gate-2 aws run (plugin 1120, result.findings[], a replication
// destination whose region could not be read). Names are examples, not the account's. A graded MEDIUM sits beside it.
const p1120 = { id: '1120', name: 'AWS S3 Lifecycle + Cross-Region Replication Auditor', priority: 100, requirements: {}, runStrategy: 'single' };
const r1120 = () => ({ up: true, findings: [
  { resource: 's3:bucket:repl-src-example', severity: 'medium', region: 'us-east-1',
    issues: ["S3 bucket 'repl-src-example' replication rule 'r1' is Enabled → destination arn:aws:s3:::repl-dst-example; destination region UNDETERMINED (NoSuchBucket). Conservative classification: unverified IS NOT verified-OK."],
    details: { category: 's3-replication-dest-region-unknown', bucketName: 'repl-src-example', ruleId: 'r1', destBucketArn: 'arn:aws:s3:::repl-dst-example', sourceBucketRegion: 'us-east-1', evidenceGap: true } },
  { resource: 's3:bucket:logs-example', severity: 'medium', region: 'us-east-1',
    issues: ["S3 bucket 'logs-example' has no lifecycle rule for noncurrent versions."], details: { category: 's3-lifecycle', bucketName: 'logs-example' } },
] });
// v394 M4: an EE queue entry, the shape of agentInputGapRecord (EE utils/service_set_input_gap.mjs:103-127).
const QUEUE_GAP = { id: 'F-g72-input-gap', category: 'CRYPTO', status: 'UNVERIFIED', severity: 'INFO', cvss: null,
  title: '[COVERAGE GAP] INPUT GAP — a plugin that feeds the service set did not complete, so transport-encryption checks (TLS versions, cipher suites, certificates, cleartext protocols) were NOT assessed for the services it would have contributed',
  description: 'This analysis ran over a service set that was INCOMPLETE: one or more plugins that feed it were requested and NOT measured on this host.',
  target: { host: HOST, port: 0, protocol: 'tcp', service: 'service-set', program: 'upstream-plugins', version: 'unknown' },
  evidence: { source: 'crypto_agent', cve: [], mitre: [], raw: { evidenceGap: true, gapClass: 'input_gap', notMeasured: [{ id: '003', status: 'timeout' }] } } };

/** The same result with its gap rows removed — the paired control, stripped where each source path writes the gap. */
function strip(id, r) {
  const y = structuredClone(r);
  if (id === '050') { delete y.findings.coverage; y.details.notRead = []; } else if (id === '060') y.details.notMeasured = [];
  else y.findings = y.findings.filter((f) => f?.details?.evidenceGap !== true);
  return y;
}

const R = { '040': await run040(), '050': await run050(), '060': await run060(), 1120: r1120() };
const PLUGIN = { '040': p040, '050': p050, '060': p060, 1120: p1120, ...MIXED_PLUGINS };

// ── the real writers ──────────────────────────────────────────────────────────────────────────────────────────────────
const conclusionFiles = (root) => fs.readdirSync(root, { recursive: true }).map(String).filter((f) => f.endsWith('scan_conclusion_raw.json'));
const KEEP = { out: process.env.SCAN_OUT_PATH, lic: process.env.NSAUDITOR_LICENSE_KEY, ai: process.env.OPENAI_OUT_PATH };
after(() => { for (const [k, v] of [['SCAN_OUT_PATH', KEEP.out], ['NSAUDITOR_LICENSE_KEY', KEEP.lic], ['OPENAI_OUT_PATH', KEEP.ai]]) { if (v === undefined) delete process.env[k]; else process.env[k] = v; } });

/** One run: record by the real writers, conclusion file by the REAL scanSingleHost; the queue file, if any, beside it. */
async function realRun(outRoot, id, result, { queue = null, startedAt = '2026-09-08T10:00:00.000Z' } = {}) {
  const { scanSingleHost } = await import('../cli.mjs');
  const { default: PluginManager } = await import('../plugin_manager.mjs');
  const { newRunId, writeRunStart, finalizeRunRecord } = await import('../utils/run_record.mjs');
  const { sealRunRecord } = await import('../utils/run_chain.mjs');
  process.env.SCAN_OUT_PATH = outRoot; process.env.NSAUDITOR_LICENSE_KEY = 'not-a-licence'; delete process.env.OPENAI_OUT_PATH;
  const runId = newRunId();
  await writeRunStart(outRoot, { runId, startedAt, hostsRequested: [HOST], pluginsRequested: [id], portsRequested: '443',
    tier: 'pro', ceVersion: '0.2.54', eeVersion: null, prevDigest: null });
  const pm = await PluginManager.create({ plugins: [{ ...PLUGIN[id], requirements: {}, runStrategy: 'single', run: async () => result }, concluder] });
  const absent = () => { throw Object.assign(new Error('not installed'), { code: 'MODULE_NOT_FOUND' }); };
  const before = new Set(conclusionFiles(outRoot));
  await scanSingleHost(pm, HOST, 'all', { resolveEE: absent, runId }, 'basic');
  const made = conclusionFiles(outRoot).filter((f) => !before.has(f));
  assert.equal(made.length, 1, `scanSingleHost wrote one conclusion file: ${made}`);
  const file = JSON.parse(fs.readFileSync(path.join(outRoot, made[0]), 'utf8'));
  assert.equal(file.pluginStatus?.find((p) => String(p?.id) === id)?.status, 'ran', `the conclusion file records ${id} as ran`);
  if (queue) fs.writeFileSync(path.join(outRoot, path.dirname(made[0]), 'scan_finding_queue.json'), JSON.stringify(queue), 'utf8');
  await finalizeRunRecord(outRoot, runId, { finishedAt: startedAt });
  await sealRunRecord(outRoot, runId);
  return { runId, file, queue: queue ?? [] };
}
const normalise = (h) => h.replace(/Report rendered [^<.]*/g, 'Report rendered X').replace(/\d{8}T\d{6}Z-[0-9a-f]{6}/g, 'RUN')
  .replace(/_\d{8}_\d{6}(?:_\d+)?/g, '_STAMP');
/** The executive html of the newest run in a fresh root (Pro), optionally --since a baseline run. */
async function executive(id, result, { queue = null, since = null } = {}) {
  const { runReport } = await import('../cli.mjs');
  const { resolveCapabilities } = await import('../utils/capabilities.mjs');
  const outRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-g72-exec-'));
  const base = since ? await realRun(outRoot, id, since, { startedAt: '2026-09-01T10:00:00.000Z' }) : null;
  const cur = await realRun(outRoot, id, result, { queue });
  const out = path.join(outRoot, 'exec.html');
  const rep = await runReport({ from: outRoot, format: 'executive', run: cur.runId, ...(base ? { since: base.runId } : {}), out }, resolveCapabilities('pro'));
  assert.equal(rep.code, 0, rep.stderr);
  const loader = shapeHostFindings(HOST, cur.file, cur.queue);
  return { html: normalise(fs.readFileSync(out, 'utf8')), loader, gaps: loader.filter(isGap) };
}
const bars = (h) => Object.fromEntries([...h.matchAll(/data-severity="(\w+)" data-count="(\d+)"/g)].map((m) => [m[1], +m[2]]));
const severityRows = (h) => [...h.matchAll(/<tr data-row-severity="[^"]*">[\s\S]*?<\/tr>/g)].map((m) => m[0]);
const gapRows = (h) => [...h.matchAll(/<tr data-coverage-gap="true">[\s\S]*?<\/tr>/g)].map((m) => m[0]);
const section = (h, id) => h.match(new RegExp(`<section id="${id}">[\\s\\S]*?</section>`))?.[0] ?? '';
const coverNumber = (h) => { const m = section(h, 'cover').match(/(\d+) coverage-gap rows? recorded/); return m ? +m[1] : 0; };
/** The cells of a data-coverage-gap row: host, port, severity, counted as a finding, text. */
const cells = (row) => [...row.matchAll(/<td>([\s\S]*?)<\/td>/g)].map((m) => m[1]);
// The two sentences a reader can take as "this row is not a defect". VERDICT-v395 G2: neither may govern an undeclared row.
const FALSE_OVER_UNDECLARED = /could not (?:be )?read|not (?:a )?findings?\b|not counted/;
/**
 * The text a writer shows for a gap row (v394 Q1, and the architect's closing note on it): its title, or — when the title IS
 * describeFinding's cut of `[resource — ]detail` — that whole text. Keyed on EQUALITY with the public describeFinding's own
 * output, never on a prefix match: the cut is describeFinding's (a 160-char slice less the trailing partial word, which on a
 * 120-char zone takes the whole zone and leaves 68 chars), and the 1120 title is cut after a resource prefix, where a
 * prefix match on `detail` never holds. Derived here independently of the writers' helper (coverageGapText).
 */
const shown = (f) => [f.resource ? `${f.resource} — ${f.detail}` : null, f.detail]
  .find((s) => s && f.title && s !== f.title && describeFinding({ issues: [s] }) === f.title) ?? f.title ?? f.detail;
const dump = (name, body) => { if (process.env.G72_DUMP) fs.writeFileSync(path.join(process.env.G72_DUMP, name), body, 'utf8'); };
const md = async (id, result, extra = {}) => buildMarkdownReport({ host: HOST, scanTime: SCAN_TIME, toolVersion: 'm', manifest: [],
  conclusion: { id: 'concluder', name: 'concluder', result: await concluder.run([{ id, name: PLUGIN[id].name, result }]) },
  results: [{ id, name: PLUGIN[id].name, result }], ...extra });

// ── FOURTH QUADRANT FIRST ─────────────────────────────────────────────────────────────────────────────────────────────
test('(g-1) no finding and no gap: the executive html and the md are byte-identical to the pages CE 6618bae built', async () => {
  const clean = strip('040', R['040']);
  assert.deepEqual(clean.findings, [], 'the premise: no finding, no gap');
  const { html } = await executive('040', clean);
  const m = await md('040', clean);
  dump('no-finding-no-gap.html', html); dump('no-finding-no-gap.md', m);
  assert.equal(html, fs.readFileSync(path.join(FIXTURES, 'no-finding-no-gap.html'), 'utf8'));
  assert.equal(m, fs.readFileSync(path.join(FIXTURES, 'no-finding-no-gap.md'), 'utf8'));
  assert.match(section(html, 'cover'), /<p>No findings were recorded for the 1 hosts scanned in this run\.<\/p>/);
  assert.match(section(html, 'top-risks'), /<p>No findings were recorded in this run\.<\/p>/);
});

test('(g-1b) findings and no gap: the md is byte-identical to the page CE 6618bae built (results given, none a gap)', async () => {
  const m = await md('050', strip('050', R['050']));
  dump('findings-no-gap-050.md', m);
  assert.equal(m, fs.readFileSync(path.join(FIXTURES, 'findings-no-gap-050.md'), 'utf8'));
});

test('(g-2) an ordinary INFO finding stays in its bar: the 050 run\'s permissions-policy row is INFO 1, with the gap and without', async () => {
  const g = await executive('050', R['050']); const n = await executive('050', strip('050', R['050']));
  assert.equal(bars(g.html).INFO, 1); assert.equal(bars(n.html).INFO, 1);
  assert.equal(severityRows(g.html).filter((r) => r.includes('data-row-severity="INFO"')).length, 1);
});

// G-72 C3 (RULINGS-v396): the declaration counts only as `gapOnly === true` on a gap-flagged row. Fourth quadrant first: a
// declaration with no gap marker, and a gap marker with a declaration that is not exactly `true`, are both COUNTED.
const gapBlock = (h) => [...h.matchAll(/<h4>Coverage gaps<\/h4>[\s\S]*?<\/table>/g)].map((m) => m[0]).join('\n');
const r1120With = (details) => ({ up: true, findings: [{ resource: 's3:bucket:decl-example', severity: 'medium', region: 'us-east-1',
  issues: ["S3 bucket 'decl-example' replication destination region UNDETERMINED (NoSuchBucket)."], details }] });
const queueWith = (raw) => [{ ...structuredClone(QUEUE_GAP), evidence: { ...structuredClone(QUEUE_GAP.evidence), raw } }];
const QUEUE_CONTROL = () => strip('040', R['040']);

test('(c3-a) gapOnly true with NO gap marker is counted and not listed — on the details path and on the evidence.raw path', async () => {
  const d = await executive('1120', r1120With({ category: 'x', gapOnly: true }));
  assert.equal(d.loader.length, 1); assert.equal(d.gaps.length, 0, 'the premise: no gap marker');
  assert.equal(severityRows(d.html).length, 1, 'details path: counted'); assert.equal(bars(d.html).MEDIUM, 1);
  assert.equal(gapRows(d.html).length, 0, 'details path: not listed'); assert.equal(coverNumber(d.html), 0);
  const q = await executive('040', QUEUE_CONTROL(), { queue: queueWith({ gapOnly: true, gapClass: 'input_gap' }) });
  const n = await executive('040', QUEUE_CONTROL());
  assert.equal(q.gaps.length, 0, 'the premise: no gap marker on the queue entry');
  assert.equal(severityRows(q.html).length, severityRows(n.html).length + 1, 'evidence.raw path: counted');
  assert.equal(bars(q.html).INFO, (bars(n.html).INFO ?? 0) + 1);
  assert.equal(gapRows(q.html).length, 0, 'evidence.raw path: not listed'); assert.equal(coverNumber(q.html), 0);
});

for (const v of ['true', 1]) {
  test(`(c3-b) a gap marker with gapOnly ${JSON.stringify(v)} is counted AND listed — on the details path and on the evidence.raw path`, async () => {
    const d = await executive('1120', r1120With({ category: 'x', evidenceGap: true, gapOnly: v }));
    assert.equal(d.gaps.length, 1); assert.equal(d.gaps.filter(isDeclared).length, 0, 'the premise: not exactly true');
    assert.equal(severityRows(d.html).length, 1, 'details path: counted'); assert.equal(bars(d.html).MEDIUM, 1);
    assert.equal(gapRows(d.html).length, 1, 'details path: listed'); assert.equal(cells(gapRows(d.html)[0])[3], 'Yes');
    const q = await executive('040', QUEUE_CONTROL(), { queue: queueWith({ evidenceGap: true, gapOnly: v, gapClass: 'input_gap' }) });
    const n = await executive('040', QUEUE_CONTROL());
    assert.equal(q.gaps.length, 1);
    assert.equal(severityRows(q.html).length, severityRows(n.html).length + 1, 'evidence.raw path: counted');
    assert.equal(gapRows(q.html).length, 1, 'evidence.raw path: listed'); assert.equal(cells(gapRows(q.html)[0])[3], 'Yes');
  });
}

test('(c3-d) the predicate itself: isGapOnly is exactly-true AND gap-flagged, whatever the shaping did upstream', async () => {
  const { isGapOnly } = await import('../utils/report_inputs.mjs');
  assert.equal(isGapOnly({ evidenceGap: true, gapOnly: true }), true);
  for (const v of ['true', 1, {}, false, null, undefined]) assert.equal(isGapOnly({ evidenceGap: true, gapOnly: v }), false, `gapOnly ${JSON.stringify(v)}`);
  assert.equal(isGapOnly({ gapOnly: true }), false, 'no gap marker: not declared');
  assert.equal(isGapOnly({ evidenceGap: 'true', gapOnly: true }), false, 'a marker that is not exactly true: not a gap');
});

test('(c3-c) every non-gap row the loader shapes from the real 050 run carries gapOnly false (040: tls_cert_coverage_gap c′)', () => {
  const rows = shapeHostFindings(HOST, { results: [{ id: '050', name: p050.name, result: R['050'] }] });
  const plain = rows.filter((f) => !isGap(f));
  assert.ok(plain.length >= 1, 'the premise: the 050 run shapes non-gap rows');
  for (const f of plain) assert.equal(f.gapOnly, false, `a non-gap 050 row is not declared: ${f.title}`);
});

// ── C4: every declaring site has a leg that fails when its declaration is removed ─────────────────────────────────────
test('(c4) the declaring sites: 050\'s REAL gap row and the loader\'s 060 row declare gapOnly, and the shaped rows carry it (040: tls_cert_coverage_gap d)', () => {
  const cov = R['050'].findings.coverage;
  const raw050 = (Array.isArray(cov) ? cov : [cov]).filter((f) => f?.details?.evidenceGap === true);
  assert.equal(raw050.length, 1, 'the premise: the real 050 run wrote one gap row');
  assert.equal(raw050[0].details.gapOnly, true, '050 declares its gap row');
  for (const [id, n] of [['040', 1], ['050', 1], ['060', 1]]) {
    const gaps = shapeHostFindings(HOST, { results: [{ id, name: PLUGIN[id].name, result: R[id] }] }).filter(isGap);
    assert.equal(gaps.length, n, `${id}: the premise`);
    for (const f of gaps) assert.equal(f.gapOnly, true, `${id}: the shaped gap row is declared`);
  }
  assert.equal(R['060'].details.notMeasured.length >= 1, true, 'the premise: 060 recorded an unmeasured check (the loader writes the row)');
});

// ── C5: the identity of the declared rows is the value captured at CE 6618bae, before the change ─────────────────────
test('(c5) id and contentDigest of the 040, 050 and 060 gap rows equal the values captured at CE 6618bae', async () => {
  for (const [id, run] of [['040', () => run040({ pin: true })], ['050', () => run050({ pin: true })], ['060', run060]]) {
    const rows = shapeHostFindings(HOST, { results: [{ id, name: PLUGIN[id].name, result: await run() }] }).filter(isGap);
    assert.deepEqual(rows.map((f) => ({ id: f.id, contentDigest: f.contentDigest, title: f.title })), GOLD_IDENTITY[id],
      `${id}: the identity the cross-run delta keys on did not move`);
  }
});

// ── THE GAP FIXTURES: the executive html ──────────────────────────────────────────────────────────────────────────────
// counted = every row the loader shapes less the DECLARED gap rows; listed = every gap-flagged row. Declared: 040, 050, 060.
// Undeclared (counted AND listed): the 1120 MEDIUM row and the EE queue row. The DECLARED MEDIUM row is synthetic — v395 §4 (2):
// no shipped producer declares a gap at MEDIUM today — and is what the plugin-id mutant and M2's any-severity property need.
const FIX = [
  ['040 array (two reset ports)', '040', () => R['040'], null],
  ['050 dict (every reply coded)', '050', () => R['050'], null],
  ['060 details.notMeasured (120-char zone)', '060', () => R['060'], null],
  ['a MEDIUM array gap (1120 shape), undeclared', '1120', () => R[1120], null],
  ['a MEDIUM array gap, DECLARED (synthetic)', '1120', () => { const r = structuredClone(R[1120]); r.findings[0].details.gapOnly = true; return r; }, null],
  ['the EE queue (input-gap shape), undeclared', '040', () => strip('040', R['040']), [QUEUE_GAP]],
];
const SEV = (f) => String(f.severity).toUpperCase();
for (const [label, id, gapResult, queue] of FIX) {
  test(`(g-3) ${label}: counted = loader less declared; listed = every gap row; the cover names the listed count`, async () => {
    const g = await executive(id, gapResult(), { queue });
    const n = await executive(id, queue ? gapResult() : strip(id, gapResult()));
    assert.ok(g.gaps.length >= 1, 'the premise: the loader shapes at least one gap row');
    assert.equal(n.gaps.length, 0, 'the control carries none');
    const counted = g.loader.filter((f) => !isDeclared(f));
    const undeclared = g.gaps.filter((f) => !isDeclared(f));
    const want = { ...bars(n.html) };
    for (const f of undeclared) want[SEV(f)] = (want[SEV(f)] ?? 0) + 1;
    assert.deepEqual(bars(g.html), want, 'every bar is the stripped run\'s bar plus the undeclared gap rows at their own severity (M2: any severity)');
    const sum = Object.values(bars(g.html)).reduce((a, b) => a + b, 0);
    assert.equal(sum, severityRows(g.html).length, 'the bars sum to the findings rows');
    assert.equal(severityRows(g.html).length, counted.length, 'the findings rows are the loader rows less the declared gap rows');
    assert.equal(gapRows(g.html).length, g.gaps.length, 'one data-coverage-gap row per loader gap row, declared or not');
    assert.equal(coverNumber(g.html), g.gaps.length, 'the cover names the listed count');
    // G6 (VERDICT-v395): on the 050 fixture the Top Risks check below cannot fail. Its gap is INFO and at least ten counted
    // rows rank above INFO, so Top Risks (ten rows) is full before an INFO row could rank. The premise is pinned here.
    if (id === '050') assert.ok(counted.filter((f) => !['INFO', 'PASS'].includes(SEV(f))).length >= 10, 'G6: the 050 Top Risks leg is vacuous');
    for (const f of g.gaps) {
      const text = escapeHtml(shown(f));
      const row = gapRows(g.html).find((r) => r.includes(text));
      assert.ok(row, `the gap is listed under Coverage gaps: ${shown(f).slice(0, 60)}`);
      assert.equal(cells(row)[3], isDeclared(f) ? 'No' : 'Yes', 'the listing says whether the row is also counted');
      // A findings row and Top Risks print the row's TITLE, which for a cut title is not its whole text: look for both.
      const forms = [text, f.title ? escapeHtml(f.title) : null].filter(Boolean);
      const inRows = severityRows(g.html).some((r) => forms.some((t) => r.includes(t)));
      if (isDeclared(f)) {
        assert.ok(!inRows, 'no findings row carries a declared gap');
        assert.ok(!forms.some((t) => section(g.html, 'top-risks').includes(t)), 'Top Risks does not rank a declared gap');
      } else {
        assert.ok(inRows, 'an undeclared gap row is ALSO a findings row');
      }
    }
    for (const r of gapRows(g.html)) assert.doesNotMatch(r, /class="sev-|null/, 'a gap row carries no sev- class and prints no null');
  });
}

test('(g-4) the 040 two-port gap row names both ports and prints no null; the 060 row shows the full detail the title lost', async () => {
  const g4 = await executive('040', R['040']);
  const [row] = gapRows(g4.html);
  const ports = R['040'].findings.find((f) => f.details?.evidenceGap).details.failedPorts.map((p) => String(p.port));
  assert.equal(ports.length, 2);
  for (const p of ports) assert.ok(row.includes(p), `port ${p} named`);
  const g6 = await executive('060', R['060']);
  const [f] = g6.gaps;
  assert.ok(f.title.endsWith('…') && !/\(ETIMEOUT\)/.test(f.title), 'the premise (v394 Q1): the loader cut the title and lost the code');
  assert.ok(gapRows(g6.html)[0].includes('(ETIMEOUT)') && gapRows(g6.html)[0].includes(ZONE), 'the row shows the zone and the code');
  // The MEDIUM 1120 gap: its title is cut AFTER the resource prefix, so the reason the region could not be read is lost.
  const g11 = await executive('1120', R[1120]);
  const [f11] = g11.gaps;
  assert.ok(f11.title.endsWith('…') && !f11.title.includes('UNDETERMINED (NoSuchBucket)'), 'the premise: the cut lost the reason');
  const [row11] = gapRows(g11.html);
  assert.ok(row11.includes('UNDETERMINED (NoSuchBucket)') && row11.includes('s3:bucket:repl-src-example'), `the row shows the resource and the reason: ${row11}`);
});

test('(u-1) coverageGapText is keyed on describeFinding\'s cut, not on a prefix match', async () => {
  const { coverageGapText } = await import('../utils/report_inputs.mjs');
  const [g060] = shapeHostFindings(HOST, { results: [{ id: '060', name: 'x', result: R['060'] }] }).filter(isGap);
  assert.equal(coverageGapText(g060), g060.detail, 'a title describeFinding cut from the detail shows the whole detail');
  const [g1120] = shapeHostFindings(HOST, { results: [{ id: '1120', name: 'x', result: R[1120] }] }).filter(isGap);
  assert.equal(coverageGapText(g1120), `${g1120.resource} — ${g1120.detail}`, 'a cut after a resource prefix shows resource and detail');
  // FOURTH QUADRANT: a producer title that ENDS in '…' and BEGINS like its detail, but is not the rule's cut of it, is shown as
  // it is. A prefix match reads it as a cut and swaps in the detail; this is the case that tells the two apart.
  const detail = 'Evidence gap: the DMARC check was not measured — the TXT lookup failed (ETIMEOUT)';
  assert.equal(coverageGapText({ title: 'Evidence gap: the DMARC…', detail, resource: null }), 'Evidence gap: the DMARC…');
  assert.equal(coverageGapText({ title: 'A whole title', detail, resource: null }), 'A whole title', 'an uncut title is shown');
  assert.equal(coverageGapText({ title: null, detail, resource: null }), detail, 'no title: the detail');
});

test('(g-5) the tie to scan_delta.mjs:1377 — the page that prints "gaps are listed under coverage" lists them there, and counts none', async () => {
  const withGap = await executive('050', R['050'], { since: strip('050', R['050']) });
  const noGap = await executive('050', strip('050', R['050']), { since: strip('050', R['050']) });
  assert.ok(withGap.html.includes(escapeHtml(EVIDENCE_GAPS_RECORDED)), 'the page prints the limit');
  assert.ok(!noGap.html.includes(escapeHtml(EVIDENCE_GAPS_RECORDED)), 'the control does not');
  assert.equal(gapRows(withGap.html).length, withGap.gaps.length);
  assert.equal(coverNumber(withGap.html), withGap.gaps.length);
  assert.deepEqual(bars(withGap.html), bars(noGap.html), 'no bar counts a gap');
  assert.equal(severityRows(withGap.html).length, severityRows(noGap.html).length, 'no findings row counts a gap');
});

test('(g-6) a gap-only run is not a clean result: the cover, Top Risks and the host section say so, with the count', async () => {
  const g = await executive('040', R['040']);
  assert.equal(g.loader.length, 1); assert.equal(g.gaps.length, 1);
  assert.equal(g.gaps.filter(isDeclared).length, 1, 'the premise: the row is declared, so nothing is counted');
  assert.match(section(g.html, 'cover'), /No findings were recorded for the 1 hosts scanned in this run, and 1 coverage-gap row is listed in the appendix, declared by its producer to record a surface the scanner could not read: this is not a clean result\./);
  assert.match(section(g.html, 'top-risks'), /No findings were recorded in this run, and 1 coverage-gap row is listed in the appendix, declared by its producer to record a surface the scanner could not read: this is not a clean result\./);
  assert.match(section(g.html, 'appendix'), /No findings were recorded for this host, and 1 coverage-gap row is listed below, declared by its producer to record a surface the scanner could not read: this is not a clean result\./);
  assert.doesNotMatch(g.html, /<p>No findings were recorded in this run\.<\/p>/, 'never the bare sentence beside a gap');
});

test('(g-7) a declared row beside an undeclared one: the cover lists both, and each sentence names its own count, taken by a filter', async () => {
  const g = await executive('040', R['040'], { queue: [QUEUE_GAP] });
  assert.equal(g.gaps.length, 2); assert.equal(g.gaps.filter(isDeclared).length, 1, 'the premise: one declared (040), one not (the queue)');
  const cover = section(g.html, 'cover');
  assert.equal(coverNumber(g.html), 2, 'the cover number is the listed count, never listed less counted');
  assert.match(cover, /2 coverage-gap rows recorded, listed per host under Coverage gaps in the appendix\./);
  assert.match(cover, / 1 row is declared by its producer to record only a surface the scanner could not read, and is not counted in the severity chart or in Top Risks\./);
  assert.match(cover, / 1 row carries the gap marker without that declaration and is also counted as a finding at its producer's severity\./);
  assert.doesNotMatch(g.html, /this is not a clean result/, 'a counted row is present: the page states no gap-only result');
  const block = gapBlock(g.html);
  assert.match(block, /<p>2 rows on this host carry a coverage-gap marker\. 1 row is declared by its producer/);
  assert.match(block, /1 row carries the marker without that declaration: it is also counted as a finding in the table above/);
  assert.match(block, /<th>Counted as a finding<\/th>/); assert.doesNotMatch(block, /Not read/, 'the header is not "Not read"');
  assert.deepEqual(gapRows(g.html).map((r) => cells(r)[3]).sort(), ['No', 'Yes']);
});

test('(g-8) Top Risks empty beside an UNDECLARED gap row (a PASS-severity row is counted, not ranked): no could-not-read clause', async () => {
  const pass = structuredClone(r1120With({ category: 'x', evidenceGap: true })); pass.findings[0].severity = 'pass';
  const p = await executive('1120', pass);
  assert.equal(p.gaps.length, 1); assert.equal(p.gaps.filter(isDeclared).length, 0, 'the premise: one undeclared gap row');
  assert.equal(severityRows(p.html).length, 1, 'the premise: the PASS row is counted');
  const top = section(p.html, 'top-risks');
  assert.match(top, /No findings were recorded in this run, and 1 coverage-gap row is listed in the appendix: this is not a clean result\./);
  assert.doesNotMatch(top, FALSE_OVER_UNDECLARED, 'the clause names no unread surface over a row nobody declared');
});

// ── F-A / F-B / F-C: Enterprise rows on which the marker is additive (VERDICT-v395 G1, G2) ────────────────────────────
for (const id of Object.keys(MIXED_RESULTS)) {
  test(`(f) ${MIXED_LABELS[id]}: bars, findings rows and Top Risks equal the CE 6618bae page; the row is also listed; no false sentence governs it`, async () => {
    const g = await executive(id, MIXED_RESULTS[id]());
    assert.equal(g.loader.length, 1); assert.equal(g.gaps.length, 1); assert.equal(g.gaps.filter(isDeclared).length, 0, 'the premise: one undeclared gap row');
    assert.deepEqual(bars(g.html), GOLD_MIXED[id].bars, 'the bars of the 6618bae page');
    assert.deepEqual(severityRows(g.html), GOLD_MIXED[id].severityRows, 'the findings rows of the 6618bae page');
    assert.equal(section(g.html, 'top-risks'), GOLD_MIXED[id].topRisks, 'the Top Risks of the 6618bae page');
    const [row] = gapRows(g.html);
    assert.ok(row && row.includes(escapeHtml(shown(g.gaps[0]))), 'the row is also listed, with its text');
    assert.equal(cells(row)[3], 'Yes', 'the listing says it is counted');
    assert.equal(coverNumber(g.html), 1);
    for (const where of ['cover', 'top-risks']) assert.doesNotMatch(section(g.html, where), FALSE_OVER_UNDECLARED, `${where}: no sentence calls it unread or not a finding`);
    assert.doesNotMatch(gapBlock(g.html).replace(row, ''), FALSE_OVER_UNDECLARED, 'the listing\'s own sentences call it neither');
  });
}

// ── textBeforeCut's two stated limits, each with a live occupant (VERDICT-v395 (b)) ──────────────────────────────────
test('(t-1) limit 1: a title cut from a lead clause that is not the first issue is not recognised — F-A lists its cut title', async () => {
  const { coverageGapText } = await import('../utils/report_inputs.mjs');
  const [f] = shapeHostFindings(HOST, { results: [{ id: '1222', name: 'x', result: MIXED_RESULTS[1222]() }] });
  assert.ok(f.title.endsWith('…') && f.title.includes('grants the highly-privileged role'), 'the premise: the title is the SECOND clause, cut');
  assert.ok(f.detail.includes('(least-privilege erosion)'), 'the premise: the detail holds the whole clause');
  // If this goes RED because the listing now shows the whole clause, the limit closed: rewrite it in textBeforeCut.
  assert.equal(coverageGapText(f), f.title, 'the listing shows the cut title and loses the tail');
});

test('(t-2) limit 2: a resource read under another key (bucket:) is not recognised — the listing keeps the cut title', async () => {
  const { coverageGapText } = await import('../utils/report_inputs.mjs');
  const long = 'could not read the destination region: UNDETERMINED (NoSuchBucket) ' + 'padding-word '.repeat(14) + 'TAILCODE-E42';
  const [f] = shapeHostFindings(HOST, { results: [{ id: '1120', name: 'x', result: { findings: [{ bucket: 'bucket-a', severity: 'MEDIUM', issues: [long], details: { evidenceGap: true } }] } }] });
  assert.ok(f.title.endsWith('…') && f.detail.includes('TAILCODE-E42'), 'the premise: the title was cut, the detail is whole');
  // If this goes RED because the listing now shows TAILCODE-E42, the limit closed: rewrite it in textBeforeCut.
  assert.equal(coverageGapText(f), f.title); assert.ok(!coverageGapText(f).includes('TAILCODE-E42'));
});

// ── THE MD REPORT ─────────────────────────────────────────────────────────────────────────────────────────────────────
const gapSection = (m) => m.split('\n## ').find((s) => s.startsWith('Coverage gaps\n')) ?? null;
const DECLARED_MARK = '**gap only:**';
const UNDECLARED_MARK = '**may also state a finding (not declared gap-only by its producer):**';
const headline = (m) => m.split('\n').find((l) => l.startsWith('- **Security findings:**'));

test('(m-1) ABSENT is not EMPTY: an md built without plugin results says coverage gaps were not evaluated, and lists none', async () => {
  const m = await md('050', R['050'], { results: undefined });
  assert.match(m, /^- \*\*Coverage gaps:\*\* not evaluated — this report was built without the plugin results/m);
  assert.equal(gapSection(m), null);
});

for (const id of ['040', '050', '060']) {
  test(`(m-2) ${id}: the md lists each gap under "Coverage gaps" marked gap only, counts it beside the headline, and the headline does not move`, async () => {
    const m = await md(id, R[id]); const m0 = await md(id, strip(id, R[id]));
    const gaps = shapeHostFindings(HOST, { results: [{ id, name: PLUGIN[id].name, result: R[id] }] }).filter(isGap);
    assert.equal(headline(m), headline(m0), 'the Security findings headline is the same with and without the gap');
    assert.match(m, new RegExp(`^- \\*\\*Coverage gaps:\\*\\* ${gaps.length} rows?, listed under Coverage gaps below \\(Security findings counts service checks only, so no coverage-gap row is part of it\\)$`, 'm'));
    const sec = gapSection(m);
    assert.ok(sec, 'the section is present');
    assert.match(sec, /Enterprise analysis-agent gaps are not listed in this report/);
    const lines = sec.split('\n').filter((l) => l.startsWith('- '));
    assert.equal(lines.length, gaps.length, 'one line per loader gap row');
    assert.ok(lines.every((l) => l.startsWith(`- ${HOST}`) && !/null/.test(l)), 'each line names the host and prints no null');
    assert.ok(lines.every((l) => l.includes(` — ${DECLARED_MARK} `)), 'each declared row is marked gap only');
    assert.match(sec, /A row marked \*\*gap only\*\* is declared by its producer to record only a surface the scanner could not read/);
    assert.ok(!sec.includes('may also state a finding'), 'no undeclared row, so no sentence about one');
    if (id === '050') assert.match(lines[0], /the body of 37 replies on port \d+ was not read/);
    if (id === '040') for (const p of R['040'].findings[0].details.failedPorts) assert.ok(lines[0].includes(String(p.port)));
    if (id === '060') assert.ok(lines[0].includes('\\(ETIMEOUT\\)') || lines[0].includes('(ETIMEOUT)'), 'the full detail, code included');
  });
}

test('(m-3) a gap-only md: the Findings sentence names the gap count; it never reads as a clean result', async () => {
  const m = await md('040', R['040']);
  assert.match(m, /_None of the counted service checks found anything, and 1 coverage-gap row was recorded, listed under Coverage gaps below\. This is not a clean result\./);
});

// m-7 (VERDICT-v395 §4 (2)): the md's Security findings counts the concluder's service checks and never a loader row, so it
// can say "counted" of no gap row. An undeclared row is marked as one that may also state a finding, and no sentence of the
// section calls it unread or not a finding.
for (const id of Object.keys(MIXED_RESULTS)) {
  test(`(m-7) ${MIXED_LABELS[id]}: the md lists the row marked "may also state a finding", and no sentence calls it unread`, async () => {
    const m = await md(id, MIXED_RESULTS[id]()); const m0 = await md(id, { up: true, findings: [] });
    assert.equal(headline(m), headline(m0), 'the Security findings headline does not move');
    assert.match(m, /^- \*\*Coverage gaps:\*\* 1 row, listed under Coverage gaps below/m);
    const sec = gapSection(m);
    assert.ok(sec, 'the section is present');
    const lines = sec.split('\n').filter((l) => l.startsWith('- '));
    assert.equal(lines.length, 1);
    assert.ok(lines[0].includes(` — ${UNDECLARED_MARK} `), `marked undeclared: ${lines[0]}`);
    assert.doesNotMatch(sec.replace(lines[0], ''), FALSE_OVER_UNDECLARED, 'no sentence of the section calls the row unread or not a finding');
    assert.match(sec, /A row marked \*\*may also state a finding \(not declared gap-only by its producer\)\*\* carries the marker without that declaration/);
  });
}

test('(m-4) every gap line is escaped: a title carrying [x](y) and a pipe renders as text', async () => {
  const r = structuredClone(R['040']); r.findings[0].title = '[COVERAGE GAP] [x](y) | <b>z</b>';
  const sec = gapSection(await md('040', r));
  assert.ok(sec.includes('\\[COVERAGE GAP\\] \\[x\\](y) \\| \\<b\\>z\\</b\\>'), sec);
});

// ── THE ARTIFACTS: the md the real CLI wrote, and the real scan_host handler's markdown (v394 Q2 b) ───────────────────
test('(m-5) the scan_report.md the real CLI path writes lists the 060 gaps (cli.mjs hands the writer its results)', async () => {
  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-g72-cli-'));
  const out = path.join(work, 'out');
  const env = { ...process.env, AI_ENABLED: 'false', NSA_DNS_STUB_RECORD_CODE: 'ETIMEOUT' };
  delete env.NODE_TEST_CONTEXT;
  const { withNoDotenv } = await import('./helpers/no_operator_dotenv.mjs');
  const code = await new Promise((resolve) => {
    const child = cp.spawn(process.execPath, ['--import', path.join(ROOT, 'tests', 'helpers', 'dns_nxdomain_stub.mjs'), path.join(ROOT, 'cli.mjs'),
      'scan', '--host', 'example.test', '--plugins', '060', '--output-format', 'md', '--out', out], { cwd: work, env: withNoDotenv(env) });
    child.stdout.resume(); child.stderr.resume(); child.on('close', resolve);
  });
  const mdPath = path.join(out, 'scan_report.md');
  assert.ok(fs.existsSync(mdPath), `the CLI wrote scan_report.md (exit ${code})`);
  const m = fs.readFileSync(mdPath, 'utf8');
  assert.doesNotMatch(m, /Coverage gaps:\*\* not evaluated/, 'the CLI passed the results');
  const sec = gapSection(m);
  assert.ok(sec && /DMARC check was not measured/.test(sec), `the 060 gaps are listed:\n${m.slice(0, 1200)}`);
});

test('(m-6) the real scan_host handler\'s markdown lists the 050 gap (mcp_server.mjs hands the writer its results)', async () => {
  const { handleScanHost, _setPluginManager, _setValidateHost } = await import('../mcp_server.mjs');
  const { default: PluginManager } = await import('../plugin_manager.mjs');
  _setValidateHost(async (raw) => raw);
  _setPluginManager(await PluginManager.create({ plugins: [{ ...p050, requirements: {}, runStrategy: 'single', run: async () => R['050'] }, concluder], tier: 'ce' }));
  try {
    const out = await handleScanHost({ host: 'lan-host' });
    assert.doesNotMatch(out.markdown, /Coverage gaps:\*\* not evaluated/, 'the handler passed the results');
    const sec = gapSection(out.markdown);
    assert.ok(sec && /the body of 37 replies on port \d+ was not read/.test(sec), out.markdown.slice(0, 1200));
  } finally { _setValidateHost(null); _setPluginManager(null); }
});
