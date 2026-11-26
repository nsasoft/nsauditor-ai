// tests/tribe_health_waist.test.mjs
// ─────────────────────────────────────────────────────────────────────────────
// C-4 (EE Z-1, architect v388 RULINGS items 1–14): 050_tribe_health sends every request through utils/target_http.mjs.
// Every leg drives the REAL plugin against a REAL node:http server on 127.0.0.1 — no fetch stub, no hand-built result.
//
// The gap criterion is DERIVED from what the code decided before the move (v388 item 2): a reply is listed iff today's
// code would have read its body to decide — probeHealth when 200 <= status < 400, probeDebugEndpoints when status === 200,
// probeErrorVerbosity on any reply. The ping, headers, CORS, auth and method probes never read a body and list nothing.
// The list's scope is stated in the record: a probe that got no reply is not listed (G-64 boards that false clean).
// ─────────────────────────────────────────────────────────────────────────────
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import plugin from '../plugins/050_tribe_health.mjs';
import concluder from '../plugins/result_concluder.mjs';
import { shapeHostFindings, countHostFindings } from '../utils/report_inputs.mjs';
import { rowOf, NOT_COMPARED_REASONS } from '../utils/service_flags.mjs';
import { computeDiff, historyServiceEntry, historyHostEntry } from '../utils/scan_history.mjs';
import { NOT_READ_REASONS } from '../utils/target_http.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const SRC = fs.readFileSync(path.join(ROOT, 'plugins', '050_tribe_health.mjs'), 'utf8');
const TRIBE_ENV = ['TRIBE_API_HOST', 'TRIBE_API_PORT', 'TRIBE_API_SCHEME', 'TRIBE_API_TIMEOUT_MS', 'TRIBE_API_AUTH_TOKEN', 'TRIBE_API_ALLOW_REMOTE'];
const saved = {};
before(() => { for (const k of TRIBE_ENV) { saved[k] = process.env[k]; delete process.env[k]; } });
after(() => { for (const k of TRIBE_ENV) { if (saved[k] === undefined) delete process.env[k]; else process.env[k] = saved[k]; } });

// The plugin's own path constants, in probe order (health, debug, errors) — the declared list a coded-everywhere 200
// server must produce, held by EQUALITY.
const HEALTH = ['/health', '/healthz', '/status', '/ping', '/ready'];
const DEBUG = ['/debug', '/debug/vars', '/debug/pprof', '/debug/pprof/heap', '/debug/requests', '/metrics', '/graphql',
  '/graphiql', '/swagger', '/swagger-ui', '/swagger.json', '/openapi.json', '/api-docs', '/docs', '/.env', '/config', '/admin',
  '/internal', '/actuator', '/actuator/env', '/actuator/beans', '/trace', '/__trace', '/server-info', '/info',
  '/_debug/neural-gate', '/api/v1/debug', '/api/v2/debug'];
const ERRORS = ['/this-does-not-exist-nsauditor-probe', '/api/v99/nonexistent', '/null%00byte', '/%2e%2e/etc/passwd'];
const coded = (p) => ({ path: p, method: 'GET', reason: 'encoded-body', encoding: ['gzip'] });
const SENT_METHODS = ['DELETE', 'GET', 'OPTIONS', 'PATCH', 'PUT'];

/** A real server. `reply(req)` returns { status, headers, body } or null for a 404 'not found'. */
async function serve(reply) {
  const seen = [];
  const server = http.createServer((req, res) => {
    seen.push({ method: req.method, url: req.url, ua: req.headers['user-agent'], auth: req.headers.authorization ?? null });
    req.resume();
    const r = reply(req) ?? { status: 404, headers: { 'content-type': 'text/plain' }, body: 'not found' };
    res.writeHead(r.status, r.headers ?? {});
    res.end(r.body ?? '');
  });
  await new Promise((ok) => server.listen(0, '127.0.0.1', ok));
  return { port: server.address().port, seen, close: () => new Promise((ok) => server.close(ok)) };
}
const run = (port, extra = {}) => plugin.run('127.0.0.1', port, { timeoutMs: 3000, ...extra });
const gzipJunk = Buffer.from([0x1f, 0x8b, 0x08, 0x00, 0xde, 0xad, 0xbe, 0xef]);
const CODED_200 = () => ({ status: 200, headers: { 'content-encoding': 'gzip', 'content-type': 'application/json' }, body: gzipJunk });
const actionable = (r) => Object.values(r.findings).flat().filter((f) => f.details?.evidenceGap !== true);

// ── (t-1) FOURTH QUADRANT FIRST: every reply read — no list, no gap, conclude byte-identical to today's ─────────────
test('(t-1) an uncoded server: details.notRead is [], no coverage category, and conclude\'s info is today\'s sentence', async () => {
  const s = await serve((req) => (req.url === '/health'
    ? { status: 200, headers: { 'content-type': 'application/json' }, body: '{"version":"1.2.3","status":"ok"}' } : null));
  try {
    const r = await run(s.port);
    assert.equal(r.up, true);
    assert.deepEqual(r.details?.notRead, [], 'the stable key is present and empty when every reply was read');
    assert.equal('coverage' in r.findings, false, 'no coverage category when nothing was left unread');
    assert.ok(r.findings.health.some((f) => f.check === 'health_info_leak'), 'positive control: a body-derived finding fires');
    const [rec] = plugin.conclude({ result: r });
    assert.equal(rec.info, `API probe complete: ${r.summary.critical} critical, ${r.summary.high} high, ${r.summary.medium} medium findings`);
    assert.equal('notRead' in rec.tribeHealth, false);
  } finally { await s.close(); }
});

// ── (t-2) coded on EVERY path: the list equals the declared derivation ─────────────────────────────────────────────────
test('(t-2) a server answering coded 200 on every path: the not-read list EQUALS the declared (path, method) list', async () => {
  const s = await serve(CODED_200);
  try {
    const r = await run(s.port);
    assert.equal(r.up, true);
    assert.deepEqual(r.details.notRead, [...HEALTH, ...DEBUG, ...ERRORS].map(coded));
    assert.equal(r.findings.coverage.length, 1);
    const gap = r.findings.coverage[0];
    assert.equal(gap.details.evidenceGap, true);
    assert.equal(gap.severity, 'info');
    assert.equal(gap.check, 'tribe_probe_not_read');
    assert.match(gap.title, /^\[COVERAGE GAP\] /);
    assert.equal(gap.port, s.port, 'the gap names the port PROBED (v388 10)');
    assert.deepEqual(gap.details.notRead, r.details.notRead);
    assert.match(gap.detail, /a probe that got no reply is not listed/, 'the list states its own scope (v388 11)');
    // A body-derived finding does not fire and nothing guesses in its place; a status-only one still fires.
    assert.equal(r.findings.health.length, 0);
    assert.equal(r.findings.errors.length, 0);
    assert.equal(r.findings.debug.length, DEBUG.length);
    assert.ok(r.findings.debug.every((f) => !/returns content/.test(f.detail)), 'no content upgrade from a body that was not read');
    // Not counted, does not move the severity (v388 1c).
    assert.equal(r.summary.totalChecks, actionable(r).length);
    assert.equal(r.summary.info, actionable(r).filter((f) => f.severity === 'info').length);
  } finally { await s.close(); }
});

test('(t-3) S-1 by status: health lists a coded 200-399 only, debug a coded 200 only, error paths any coded reply', async () => {
  // Health reads a body when 200 <= status < 400: /ready 302 is listed, /status 500 is not. Debug reads a body only on
  // 200: /debug is listed; /admin 401 and /metrics 302 are findings decided by status alone, not listed. Every other
  // path answers a coded 404: nothing listed for health or debug, every error path listed.
  const STATUS = { '/ready': 302, '/status': 500, '/debug': 200, '/admin': 401, '/metrics': 302 };
  const s = await serve((req) => (req.url === '/' ? { status: 200, body: 'root' }
    : { status: STATUS[req.url] ?? 404, headers: { 'content-encoding': 'gzip' }, body: gzipJunk }));
  try {
    const r = await run(s.port);
    assert.deepEqual(r.details.notRead, ['/ready', '/debug', ...ERRORS].map(coded));
    assert.deepEqual(r.findings.debug.map((f) => [f.endpoint, f.httpStatus]).sort(), [['/admin', 401], ['/debug', 200], ['/metrics', 302]]);
  } finally { await s.close(); }
});

test('(t-4) the 8 KiB cut is gone: a marker at byte 10 000 of a 20 KiB health body is found; a body over the cap is listed', async () => {
  const body = `{"pad":"${'x'.repeat(10000)}","version":"9.9.9","tail":"${'y'.repeat(10000)}"}`;
  assert.ok(body.indexOf('"version"') >= 10000 && body.length > 20000);
  const big = 'z'.repeat(1024 * 1024 + 10);
  const s = await serve((req) => (req.url === '/health' ? { status: 200, body }
    : req.url === '/healthz' ? { status: 200, body: big } : null));
  try {
    const r = await run(s.port);
    assert.ok(r.findings.health.some((f) => f.check === 'health_info_leak' && f.endpoint === '/health'));
    assert.deepEqual(r.details.notRead, [{ path: '/healthz', method: 'GET', reason: 'body-cap' }]);
    assert.ok(r.details.notRead.every((e) => NOT_READ_REASONS.includes(e.reason)));
  } finally { await s.close(); }
});

// ── (t-5) the target's text: never in a gap; in run()'s result ONLY where 050 reports header text (v388 1b, 5, 14) ────
const CANARY = 'zqcanary7731';
function canaryPaths(value, at = '$', out = new Set()) {
  if (typeof value === 'string') { if (value.includes(CANARY)) out.add(at); return out; }
  if (Array.isArray(value)) { value.forEach((v) => canaryPaths(v, `${at}[${v?.check ?? '#'}:${v?.header ?? v?.endpoint ?? ''}]`, out)); return out; }
  if (value && typeof value === 'object') for (const [k, v] of Object.entries(value)) canaryPaths(v, `${at}.${k}`, out);
  return out;
}
const EVERY_HEADER = {
  server: CANARY, 'x-powered-by': CANARY, 'x-aspnet-version': CANARY, 'x-debug-token': CANARY, 'x-debug-token-link': CANARY,
  allow: CANARY, 'access-control-allow-methods': CANARY, 'access-control-allow-origin': `https://${CANARY}.example`,
  'access-control-allow-credentials': 'true', 'set-cookie': `sid=${CANARY}; Path=/`, 'x-canary': CANARY,
  'content-type': `application/${CANARY}`, 'content-encoding': `gzip, x${CANARY}`,
};
test('(t-5) a coded server with a canary in every header and the body: the canary is in no gap, and in run()\'s result ONLY at the declared header-text paths', async () => {
  const s = await serve(() => ({ status: 200, headers: EVERY_HEADER, body: Buffer.from(CANARY) }));
  try {
    const r = await run(s.port);
    assert.ok(r.details.notRead.length > 0);
    assert.ok(r.details.notRead.every((e) => e.reason === 'encoded-body' && e.encoding.join() === 'gzip,other'), 'an unregistered coding is `other`');
    assert.deepEqual([...canaryPaths({ notRead: r.details.notRead, coverage: r.findings.coverage })], []);
    const leaky = ['server', 'x-powered-by', 'x-aspnet-version', 'x-debug-token', 'x-debug-token-link']
      .flatMap((h) => [`$.findings.headers[leaky_header:${h}].detail`, `$.findings.headers[leaky_header:${h}].value`]);
    assert.deepEqual([...canaryPaths(r)].sort(), [
      '$.serverInfo.server', '$.serverInfo.poweredBy', ...leaky,
      '$.findings.headers[cors_credentials:].detail',
      '$.findings.methods[options_allow:/].detail', '$.findings.methods[options_allow:/api/v1/health].detail',
    ].sort());
    const [rec] = plugin.conclude({ result: r });
    assert.equal(rec.info.includes(CANARY), false);
    assert.deepEqual([...canaryPaths(rec.tribeHealth.notRead)], []);
  } finally { await s.close(); }
  // Positive control: the walker sees a leak — the same canary in Server: of an UNCODED server reaches serverInfo.
  const u = await serve(() => ({ status: 200, headers: { server: CANARY }, body: 'ok' }));
  try {
    assert.ok((await run(u.port)).serverInfo.server.includes(CANARY));
  } finally { await u.close(); }
});

// ── (t-6) a refused port and a silent one (v388 6) ──────────────────────────────────────────────────────────────────
test('(t-6) a refused port: the down record\'s error and info name the waist\'s fixed text; the concluder does not relabel it', async () => {
  const s = await serve(() => null); const port = s.port; await s.close();
  const r = await run(port);
  const want = `Cannot reach http://127.0.0.1:${port}: target request failed (ECONNREFUSED)`;
  assert.equal(r.up, false);
  assert.equal(r.error, want);
  const [rec] = plugin.conclude({ result: r });
  assert.equal(rec.info, want);
  assert.equal(rec.tribeHealth.error, want);
  assert.equal(rec.tribeHealth.state, 'down');
  const c = await concluder.run([{ id: '050', name: plugin.name, result: r }]);
  const svc = c.services.find((x) => x.source === 'tribe-health');
  assert.ok(svc, 'the down record reaches the conclusion');
  assert.notEqual(svc.status, 'closed', 'result_concluder :134 does not apply: 050 has an adapter and its down record carries no status');
});

test('(t-6b) a server that accepts and never answers: an AbortError still reads "timeout"', async () => {
  const sockets = [];
  const server = http.createServer(() => {});
  server.on('connection', (sock) => sockets.push(sock));
  await new Promise((ok) => server.listen(0, '127.0.0.1', ok));
  try {
    const r = await run(server.address().port, { timeoutMs: 300 });
    assert.equal(r.up, false);
    assert.equal(r.error, `Cannot reach http://127.0.0.1:${server.address().port}: timeout`);
  } finally { for (const x of sockets) x.destroy(); await new Promise((ok) => server.close(ok)); }
});

// ── (t-7) S-4: a bad argument is a TypeError naming what the operator typed, never a down reading (v388 7) ──────────────
test('(t-7) a bad TRIBE_API_* value throws a TypeError naming the variable and its range — never a down record, never "timeout"', async () => {
  for (const [k, v, re] of [['TRIBE_API_TIMEOUT_MS', 'abc', /TRIBE_API_TIMEOUT_MS.*1.*120000/], ['TRIBE_API_TIMEOUT_MS', '0', /TRIBE_API_TIMEOUT_MS/],
    ['TRIBE_API_TIMEOUT_MS', '120001', /TRIBE_API_TIMEOUT_MS/], ['TRIBE_API_SCHEME', 'ftp', /TRIBE_API_SCHEME.*http.*https/],
    ['TRIBE_API_PORT', '70000', /TRIBE_API_PORT.*1.*65535/]]) {
    process.env[k] = v;
    try {
      await assert.rejects(plugin.run('127.0.0.1', 8080, {}), (e) => e instanceof TypeError && re.test(e.message) && !/timeoutMs/.test(e.message));
    } finally { delete process.env[k]; }
  }
  // An unbracketed IPv6 literal: the waist's own TypeError propagates (bracketing is a behaviour fix, boarded G-65).
  await assert.rejects(plugin.run('::1', 8080, { timeoutMs: 1000 }), TypeError);
});

test('(t-7b) through the REAL plugin manager, a thrown run() is recorded as status "error" with its message — not ran-and-clean', async () => {
  const { default: PluginManager } = await import('../plugin_manager.mjs');
  const mgr = new PluginManager('/nonexistent');
  // The real run() and conclude(); requirements emptied only so the manager does not skip it for a closed 8080.
  mgr.plugins = [{ ...plugin, requirements: {}, runStrategy: 'single' }];
  process.env.TRIBE_API_TIMEOUT_MS = 'abc';
  try {
    const { manifest } = await mgr._runOrchestrated('127.0.0.1', mgr.plugins);
    assert.equal(manifest.length, 1);
    assert.equal(manifest[0].id, '050');
    assert.equal(manifest[0].status, 'error');
    assert.match(manifest[0].reason, /TRIBE_API_TIMEOUT_MS/);
  } finally { delete process.env.TRIBE_API_TIMEOUT_MS; }
});

// ── (t-8) the operator's token reaches the target and nothing else (v388 12) ───────────────────────────────────────
test('(t-8) TRIBE_API_AUTH_TOKEN appears in no outcome, record, gap or error text', async () => {
  const TOKEN = 'tok-zq-5512-secret';
  process.env.TRIBE_API_AUTH_TOKEN = TOKEN;
  try {
    const s = await serve((req) => (req.url.startsWith('/api/v1/users')
      ? (req.headers.authorization === `Bearer ${TOKEN}` ? { status: 200, body: 'ok' } : { status: 401, body: 'no' })
      : CODED_200()));
    try {
      const r = await run(s.port);
      assert.ok(s.seen.some((x) => x.auth === `Bearer ${TOKEN}`), 'positive control: the token was sent');
      assert.ok(r.findings.auth.some((f) => f.check === 'auth_enforced' && f.endpoint === '/api/v1/users'));
      assert.ok(r.details.notRead.length > 0);
      assert.equal(JSON.stringify(r).includes(TOKEN), false);
      assert.equal(JSON.stringify(plugin.conclude({ result: r })).includes(TOKEN), false);
    } finally { await s.close(); }
    const d = await serve(() => null); const port = d.port; await d.close();
    const down = await run(port);
    assert.equal(JSON.stringify({ down, rec: plugin.conclude({ result: down }) }).includes(TOKEN), false);
  } finally { delete process.env.TRIBE_API_AUTH_TOKEN; }
});

// ── (t-9) the methods 050 sends: the source AND the wire, by equality (v388 13) ────────────────────────────────────
test('(t-9) every method 050 can send — the array literal, every `method:` value, the default — EQUALS the declared set', () => {
  const array = SRC.match(/const dangerousMethods = \[([^\]]*)\]/);
  assert.ok(array, 'the dangerousMethods array literal is where the leg reads it');
  const methods = new Set([...array[1].matchAll(/["']([A-Z]+)["']/g)].map((m) => m[1]));
  // One declared non-send occurrence: notReadEntry's output field copies the method probe() SENT (`res.method`).
  const entryFn = SRC.match(/function notReadEntry\([^)]*\) \{[\s\S]*?\n\}/)?.[0] ?? '';
  assert.match(entryFn, /\bmethod: res\.method,/, 'notReadEntry is where the leg reads its one copied field');
  let sites = 0;
  for (const m of SRC.replace(entryFn, '').matchAll(/\bmethod:\s*([^,}\n]+?)\s*[,}\n]/g)) {
    sites++;
    const v = m[1];
    const lit = v.match(/^["']([A-Z]+)["']$/);
    const dflt = v.match(/^options\.method \|\| ["']([A-Z]+)["']$/);
    assert.ok(lit || dflt, `a \`method:\` value is neither a string literal nor the default form: ${v}`);
    methods.add((lit ?? dflt)[1]);
  }
  assert.ok(sites >= 1, 'positive control: the default `method:` site was read');
  // A shorthand `method` property is a value the `method:` scan cannot see: exactly one exists, the loop-variable site.
  assert.equal((SRC.match(/[{,]\s*method\s*[,}]/g) ?? []).length, 1, 'a shorthand `method` property other than the loop site');
  assert.ok(/probe\(`\$\{baseUrl\(config\)\}\$\{target\}`, config, \{ method \}\)/.test(SRC), 'the one loop-variable site');
  assert.deepEqual([...methods].sort(), SENT_METHODS);
});

test('(t-9b) the methods a real server RECEIVES equal the same set, every request carries the TribeProbe User-Agent', async () => {
  const s = await serve(() => ({ status: 200, body: 'ok' }));
  try {
    await run(s.port);
    assert.deepEqual([...new Set(s.seen.map((x) => x.method))].sort(), SENT_METHODS);
    assert.deepEqual([...new Set(s.seen.map((x) => x.ua))], ['NSAuditor-AI/TribeProbe'], 'v388 12: the User-Agent stays');
  } finally { await s.close(); }
});

test('(t-11) 050 never reads a Set-Cookie line; its one `cookie` token is the CORS-credentials detail text', () => {
  assert.equal((SRC.match(/setCookie/g) ?? []).length, 0);
  assert.deepEqual(SRC.match(/[^\n]*cookie[^\n]*/gi)?.map((l) => l.trim()), ['detail: "CORS reflects Origin AND allows credentials — full cookie theft possible",']);
});

// ── (t-12) history: a not-read probe holds a vanished finding; an all-read run resolves it (v388 3, 4 CE half) ───────
async function line(result) {
  const c = await concluder.run([{ id: '050', name: plugin.name, result }]);
  return { findingsCount: 0, tier: 'pro', services: c.services.map(historyServiceEntry), ...historyHostEntry({ result: c }) };
}
const LEAKY_HEALTH = (req) => (req.url === '/health' ? { status: 200, body: '{"version":"1.0"}' } : null);
const tribeAt = (d) => d.changedFlags.find((c) => c.port === 8080) ?? { appeared: [], cleared: [], notCompared: [] };
test('(t-12) history — FOURTH QUADRANT FIRST: every reply read and the finding absent → cleared', async () => {
  const a = await serve(LEAKY_HEALTH); const b = await serve(() => null);
  try {
    const prev = await line(await run(a.port)); const curr = await line(await run(b.port));
    const leak = prev.services.flatMap((x) => x.flags).find((cid) => /health_info_leak/.test(cid));
    assert.ok(leak, `the prior scan carries the body-derived finding: ${JSON.stringify(prev.services.map((x) => x.flags))}`);
    assert.ok(tribeAt(computeDiff(curr, prev)).cleared.includes(leak));
  } finally { await a.close(); await b.close(); }
});

test('(t-12b) history: a probe not read and the finding absent → NOT COMPARED with the payload-partial sentence; a new status-only finding still appears', async () => {
  const a = await serve(LEAKY_HEALTH); const b = await serve(CODED_200);
  try {
    const prev = await line(await run(a.port)); const currResult = await run(b.port); const curr = await line(currResult);
    const leak = prev.services.flatMap((x) => x.flags).find((cid) => /health_info_leak/.test(cid));
    const d = tribeAt(computeDiff(curr, prev));
    assert.equal(d.cleared.includes(leak), false, 'a vanished body-derived finding must not read as resolved');
    assert.deepEqual(d.notCompared.find((n) => n.id === leak), { id: leak, reason: NOT_COMPARED_REASONS['payload-partial']() });
    assert.ok(d.appeared.some((cid) => /debug_endpoint_exposed/.test(cid)), 'new findings still appear');
    const rec = curr.services.find((x) => x.port === 8080);
    assert.equal(rec.checks.tribeHealth, 'payload-partial');
  } finally { await a.close(); await b.close(); }
});

test('(t-12c) measured: up and all read → true; up with a not-read list → payload-partial; down → payload-down', () => {
  const m = rowOf('tribeHealth').measured;
  assert.equal(m({ tribeHealth: { state: 'up' } }), true);
  assert.equal(m({ tribeHealth: { state: 'up', notRead: [] } }), true);
  assert.equal(m({ tribeHealth: { state: 'up', notRead: [coded('/health')] } }), 'payload-partial');
  assert.equal(m({ tribeHealth: { state: 'down' } }), 'payload-down');
  assert.equal(typeof NOT_COMPARED_REASONS['payload-partial'](), 'string');
  assert.notEqual(NOT_COMPARED_REASONS['payload-partial'](), NOT_COMPARED_REASONS['payload-down']());
});

// ── (t-13) the artifact: the gap reaches the loader AS a gap, and the conclusion keeps it whole (v388 1e) ───────────
test('(t-13) the report loader shapes the gap as a gap, uncounted; conclude keeps it whole and says the probe is incomplete', async () => {
  const s = await serve(CODED_200);
  try {
    const r = await run(s.port);
    const raw = { results: [{ id: '050', name: plugin.name, result: r }] };
    const shaped = shapeHostFindings('127.0.0.1', raw);
    const gaps = shaped.filter((f) => f.evidenceGap === true);
    assert.equal(gaps.length, 1);
    assert.match(gaps[0].title, /^\[COVERAGE GAP\] /);
    assert.equal(countHostFindings('127.0.0.1', raw), shaped.length - 1, 'the gap is not counted');
    const [rec] = plugin.conclude({ result: r });
    assert.equal(rec.port, 8080, 'the record key stays 8080 (v388 10, G-67)');
    assert.doesNotMatch(rec.info, /^API probe complete/, 'v388 1d');
    assert.match(rec.info, new RegExp(`${r.details.notRead.length} replies`));
    assert.deepEqual(rec.tribeHealth.notRead, r.details.notRead);
    assert.deepEqual(rec.tribeHealth.findings.find((f) => f.details?.evidenceGap === true), { ...r.findings.coverage[0], category: 'coverage' });
    const c = await concluder.run(raw.results);
    assert.deepEqual(c.services.find((x) => x.source === 'tribe-health').tribeHealth.notRead, r.details.notRead);
  } finally { await s.close(); }
});

test('(t-14) the conclude comment says which fields carry the target\'s header text, and makes no ZDE claim it cannot keep', () => {
  assert.doesNotMatch(SRC, /ZDE: no response bodies or header values in conclude output/);
  assert.match(SRC, /serverInfo\.server/);
});
