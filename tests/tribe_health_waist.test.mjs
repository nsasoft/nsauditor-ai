// tests/tribe_health_waist.test.mjs
// ─────────────────────────────────────────────────────────────────────────────
// C-4 (EE Z-1, architect v388 RULINGS items 1–14): 050_tribe_health sends every request through utils/target_http.mjs.
// Every leg drives the REAL plugin against a REAL node:http server on 127.0.0.1 — no fetch stub, no hand-built result.
//
// The gap criterion: a reply is listed iff a check could not decide (v388 item 2, as changed by v391 C4-R1). It is DERIVED
// from what the code read before the move — probeHealth when 200 <= status < 400, probeDebugEndpoints when status === 200,
// probeErrorVerbosity on any reply — less one case: a debug 200 over the 1 MiB cap has proved more than the 10 bytes the
// upgrade asks for, so it decides, takes the upgrade and is not listed. The ping, headers, CORS, auth and method probes
// never read a body and list nothing. The list's scope is stated in the record: a probe that got no reply is not listed
// (G-64 boards that false clean).
// ─────────────────────────────────────────────────────────────────────────────
import './helpers/no_operator_dotenv.mjs';
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
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
    const entry = { method: req.method, url: req.url, ua: req.headers['user-agent'], auth: req.headers.authorization ?? null };
    seen.push(entry);
    req.resume();
    const r = reply(req) ?? { status: 404, headers: { 'content-type': 'text/plain' }, body: 'not found' };
    res.writeHead(r.status, r.headers ?? {});
    // N1 (v393): the framing node chose for THIS reply. writeHead has stored the head, so it is decided here: with no
    // Content-Length in `headers`, the end(buf) below goes out chunked (trap (4)); with one, it does not.
    entry.chunked = res.chunkedEncoding;
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

// ── (t-4b) v391 C4-R1: a debug 200 over the cap DECIDES (it proved more than 10 bytes) — the upgrade holds, not listed ──
const BIG_BODY = Buffer.alloc(2 * 1024 * 1024, 0x78);
for (const [framing, headers] of [['Content-Length', { 'content-type': 'text/plain', 'content-length': String(BIG_BODY.length) }],
  ['chunked', { 'content-type': 'text/plain' }]]) {
  test(`(t-4b) /metrics answering 200 with a 2 MiB uncoded body (${framing}) is CRITICAL with the content suffix and is not listed; a health and an error path over the cap stay listed`, async () => {
    const s = await serve((req) => (req.url === '/metrics' ? { status: 200, headers, body: BIG_BODY }
      : req.url === '/healthz' || req.url === '/api/v99/nonexistent' ? { status: req.url === '/healthz' ? 200 : 500, headers, body: BIG_BODY }
        : null));
    try {
      const r = await run(s.port, { timeoutMs: 5000 });
      const metrics = r.findings.debug.filter((f) => f.endpoint === '/metrics');
      assert.equal(metrics.length, 1);
      assert.equal(metrics[0].severity, 'critical', 'D-A: the upgrade a 2 KiB body takes, a 2 MiB body takes too');
      assert.match(metrics[0].detail, / — returns content without authentication$/);
      assert.equal(r.overallSeverity, 'critical');
      // Only the checks that read CONTENT could not decide: health and error paths over the cap are listed, /metrics is not.
      assert.deepEqual(r.details.notRead, [{ path: '/healthz', method: 'GET', reason: 'body-cap' },
        { path: '/api/v99/nonexistent', method: 'GET', reason: 'body-cap' }]);
      // N1 (v393 G-C): the arm is the framing its name says, as sent — not only as written in `headers`.
      const sent = s.seen.filter((q) => q.url === '/metrics' && q.method === 'GET');
      assert.ok(sent.length >= 1, 'the /metrics GET reached the server');
      assert.deepEqual(sent.map((q) => q.chunked), sent.map(() => framing === 'chunked'), `/metrics went out ${framing}`);
    } finally { await s.close(); }
  });
}

test('(t-4c) contrast: a CODED /metrics 200 cannot decide — high, no suffix, listed encoded-body', async () => {
  const s = await serve((req) => (req.url === '/metrics' ? CODED_200() : null));
  try {
    const r = await run(s.port);
    const [metrics] = r.findings.debug.filter((f) => f.endpoint === '/metrics');
    assert.equal(metrics.severity, 'high');
    assert.doesNotMatch(metrics.detail, /returns content/);
    assert.deepEqual(r.details.notRead, [coded('/metrics')]);
  } finally { await s.close(); }
});

// v392 R1(a): the branch's premise is "over the cap ⇒ more than 10 bytes", true only at the waist's DEFAULT cap (1 MiB).
test('(t-4d) the premise: 050 passes no maxBodyBytes, so an 8-byte /metrics body is READ — high, no suffix, not listed', async () => {
  assert.equal((SRC.match(/maxBodyBytes/g) ?? []).length, 0, 'no maxBodyBytes anywhere in 050: the cap is the waist default');
  const s = await serve((req) => (req.url === '/metrics' ? { status: 200, headers: { 'content-type': 'text/plain' }, body: '12345678' } : null));
  try {
    const r = await run(s.port);
    const [metrics] = r.findings.debug.filter((f) => f.endpoint === '/metrics');
    assert.equal(metrics.severity, 'high', 'an 8-byte body is not over 10 bytes, and no cap below it turned it into a body-cap');
    assert.doesNotMatch(metrics.detail, /returns content/);
    assert.deepEqual(r.details.notRead, []);
  } finally { await s.close(); }
});

// v392 R1(b), the veto's accept (fourth quadrant): a DECLARED length proves nothing; only received bytes do.
test('(t-4e) a 200 that DECLARES Content-Length 2 MiB, sends 5 bytes and closes does not take the upgrade: it reads body-error and is listed', async () => {
  const server = http.createServer((req, res) => {
    req.resume();
    if (req.url !== '/metrics') { res.writeHead(404, { 'content-type': 'text/plain' }); return res.end('not found'); }
    res.writeHead(200, { 'content-type': 'text/plain', 'content-length': String(2 * 1024 * 1024) });
    res.write('12345', () => res.socket.destroy());
  });
  await new Promise((ok) => server.listen(0, '127.0.0.1', ok));
  try {
    const r = await run(server.address().port);
    const [metrics] = r.findings.debug.filter((f) => f.endpoint === '/metrics');
    assert.equal(metrics.severity, 'high');
    assert.doesNotMatch(metrics.detail, /returns content/);
    assert.deepEqual(r.details.notRead, [{ path: '/metrics', method: 'GET', reason: 'body-error' }]);
  } finally { await new Promise((ok) => server.close(ok)); }
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

// ── (t-5b) v391 C4-R4: the BODY half — an UNCODED server with the canary in every body and in no header ─────────────────
test('(t-5b) an uncoded server with a canary in every BODY: body-derived findings fire, and the canary is in 0 places of run()\'s result and of conclude\'s record', async () => {
  const C = CANARY;
  const BODY = `{"version":"${C}","hostname":"${C}","uptime":"${C}","database":"${C}","env":"dev","password":"${C}"}\n` +
    `Traceback (most recent call last)\n  at ${C} (/srv/${C}.js:1:1)\n  at x.${C}.java:12\nSELECT * FROM ${C} WHERE k='${C}'\n` +
    `/home/${C}/app goroutine 7 Exception ${'e'.repeat(200)}\n`;
  const isErrorPath = (url) => ERRORS.some((p) => url === p);
  const s = await serve((req) => ({ status: isErrorPath(req.url) ? 500 : 200, headers: { 'content-type': 'application/json' }, body: BODY }));
  try {
    const r = await run(s.port);
    assert.deepEqual(r.details.notRead, [], 'every body was read');
    // Positive control: the body WAS read, and every body-reading check decided from it.
    assert.ok(r.findings.health.filter((f) => f.check === 'health_info_leak').length > 0, 'health leaks fired');
    assert.ok(r.findings.errors.length > 0, 'error-body findings fired');
    assert.ok(r.findings.debug.filter((f) => / — returns content without authentication$/.test(f.detail)).length > 0, 'debug upgrades fired');
    assert.deepEqual([...canaryPaths({ body: BODY.slice(0, 40) })], ['$.body'], 'positive control: the walker sees a body excerpt');
    assert.deepEqual([...canaryPaths(r)], [], 'no body text in run()\'s result');
    const [rec] = plugin.conclude({ result: r });
    assert.deepEqual([...canaryPaths(rec)], [], 'no body text in conclude\'s record');
  } finally { await s.close(); }
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

// ── (t-7c) v391 C4-R2: the timeout and the port are read STRICTLY — digits only after trim, else the TypeError ─────────
const NOT_DIGITS = ['1e3', '30s', '5000ms', '0x10', '+80', '-1', '8080.0', '1_000', '８０８０', '   '];
test('(t-7c) TRIBE_API_TIMEOUT_MS / TRIBE_API_PORT that are not digits after trim ("1e3", "30s", "+80", "8080.0", fullwidth, blank …) throw the TypeError; an explicit 0 in opts throws; env "" is unset', async () => {
  for (const k of ['TRIBE_API_TIMEOUT_MS', 'TRIBE_API_PORT']) {
    for (const v of NOT_DIGITS) {
      process.env[k] = v;
      try {
        await assert.rejects(plugin.run('127.0.0.1', 8080), (e) => e instanceof TypeError && e.message.startsWith(k),
          `${k}=${JSON.stringify(v)} must be the TypeError, never a down or "timeout" reading`);
      } finally { delete process.env[k]; }
    }
  }
  // v392 6(i): an explicit falsy opts value is a value, read strictly — it does not fall through to the next source.
  await assert.rejects(plugin.run('127.0.0.1', 8080, { timeoutMs: 0 }), (e) => e instanceof TypeError && e.message.startsWith('TRIBE_API_TIMEOUT_MS'));
  await assert.rejects(plugin.run('127.0.0.1', 8080, { timeoutMs: 1000, port: 0 }), (e) => e instanceof TypeError && e.message.startsWith('TRIBE_API_PORT'));
  // Accept arm, against real servers that answer at once.
  const s = await serve(() => ({ status: 200, body: 'ok' }));
  const c = await serve(CODED_200);
  try {
    process.env.TRIBE_API_TIMEOUT_MS = ' 250 ';
    try {
      assert.equal((await plugin.run('127.0.0.1', s.port)).up, true, '" 250 " is 250 ms, and the server answers inside it');
    } finally { delete process.env.TRIBE_API_TIMEOUT_MS; }
    assert.equal((await plugin.run('127.0.0.1', s.port, { timeoutMs: 250 })).up, true);
    // Env "" is UNSET (beside "   ", which is a value and throws above): the default timeout, the scan's port.
    process.env.TRIBE_API_TIMEOUT_MS = ''; process.env.TRIBE_API_PORT = '';
    try {
      const r = await plugin.run('127.0.0.1', s.port);
      assert.equal(r.up, true);
      assert.equal(r.target, `http://127.0.0.1:${s.port}`);
    } finally { delete process.env.TRIBE_API_TIMEOUT_MS; delete process.env.TRIBE_API_PORT; }
    // The padded port is the port probed, and it is the NUMBER (v392 6(iii)): in the target and in the gap row.
    process.env.TRIBE_API_PORT = ` ${c.port} `;
    try {
      const r = await plugin.run('127.0.0.1', 9, { timeoutMs: 3000 });
      assert.equal(r.up, true, 'the padded TRIBE_API_PORT is the port probed');
      assert.equal(r.target, `http://127.0.0.1:${c.port}`, 'and it is the number, not the padded text');
      assert.equal(typeof r.findings.coverage[0].port, 'number');
      assert.equal(r.findings.coverage[0].port, c.port);
    } finally { delete process.env.TRIBE_API_PORT; }
    assert.equal((await plugin.run('127.0.0.1', 9, { timeoutMs: 3000, port: s.port })).target, `http://127.0.0.1:${s.port}`);
  } finally { await s.close(); await c.close(); }
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
  // Two declared non-send occurrences: notReadEntry's and noReplyEntry's output field each copy the method probe() SENT
  // (`res.method`). Only that one LINE of each leaves the scan (v391 nit): a second `method:` written anywhere in either
  // function is still read.
  const copiedLine = /\n[ \t]*method: res\.method,[ \t]*(?=\n)/;
  let scanned = SRC;
  for (const name of ['notReadEntry', 'noReplyEntry']) {
    const entryFn = scanned.match(new RegExp(`function ${name}\\([^)]*\\) \\{[\\s\\S]*?\\n\\}`))?.[0] ?? '';
    assert.match(entryFn, copiedLine, `${name} is where the leg reads its one copied field`);
    const before = scanned.length;
    scanned = scanned.replace(entryFn, entryFn.replace(copiedLine, ''));
    assert.equal(scanned.length, before - entryFn.match(copiedLine)[0].length, `exactly the one line of ${name} left the scan`);
  }
  let sites = 0;
  for (const m of scanned.matchAll(/\bmethod:\s*([^,}\n]+?)\s*[,}\n]/g)) {
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

// ── C4-R6 (v393 G-B): ONE helper writes the scan conclusion file through the REAL scanSingleHost — t-13b reads it back,
// and t-13c's `report --since` runs over it. So the file the loader reads in t-13c is the file t-13b holds, not a copy the
// test writes. With a runId, scanSingleHost also appends the host to that run's record, as the scan command does.
const conclusionFiles = (root) => fs.readdirSync(root, { recursive: true }).map(String).filter((f) => f.endsWith('scan_conclusion_raw.json'));
async function scanWritten(outRoot, result, { host = '192.0.2.10', runId = null, status = 'ran' } = {}) {
  const keep = { out: process.env.SCAN_OUT_PATH, lic: process.env.NSAUDITOR_LICENSE_KEY, ai: process.env.OPENAI_OUT_PATH };
  process.env.SCAN_OUT_PATH = outRoot; process.env.NSAUDITOR_LICENSE_KEY = 'not-a-licence'; delete process.env.OPENAI_OUT_PATH;
  try {
    const { scanSingleHost } = await import('../cli.mjs');
    const { default: PluginManager } = await import('../plugin_manager.mjs');
    // The REAL plugin object (its conclude included); run() hands back the real result driven by the caller, so the scan
    // does not depend on the scan target serving the API.
    const pm = await PluginManager.create({ plugins: [{ ...plugin, requirements: {}, runStrategy: 'single', run: async () => result }, concluder] });
    const absent = () => { throw Object.assign(new Error('not installed'), { code: 'MODULE_NOT_FOUND' }); };
    const before = new Set(conclusionFiles(outRoot));
    await scanSingleHost(pm, host, 'all', { resolveEE: absent, ...(runId ? { runId } : {}) }, 'basic');
    const made = conclusionFiles(outRoot).filter((f) => !before.has(f));
    assert.equal(made.length, 1, `scanSingleHost wrote one conclusion file: ${made}`);
    const j = JSON.parse(fs.readFileSync(path.join(outRoot, made[0]), 'utf8'));
    // The premise every reader of this file depends on, held where the file is read: its manifest records 050 as RAN.
    // Without this the since arms are blind to a file that loses the entry — measured (v340 battery R6-M1): the loss hits
    // the baseline and the current run alike, the delta reads an absent status as measured, and t-13c stays green.
    assert.equal(j.pluginStatus?.find((p) => String(p?.id) === '050')?.status, status, `the conclusion file records 050 as ${status}`);
    return j;
  } finally {
    for (const [k, v] of [['SCAN_OUT_PATH', keep.out], ['NSAUDITOR_LICENSE_KEY', keep.lic], ['OPENAI_OUT_PATH', keep.ai]]) {
      if (v === undefined) delete process.env[k]; else process.env[k] = v;
    }
  }
}

// ── (t-13b) v391 C4-R3: the SCAN CONCLUSION FILE, written by the REAL scanSingleHost, carries the gap whole ─────────────
test('(t-13b) scan_conclusion_raw.json written by scanSingleHost carries the gap: in results[050] and in the tribe-health record, whole', async () => {
  const s = await serve(CODED_200);
  let r;
  try { r = await run(s.port); } finally { await s.close(); }
  const outRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-tribe-conclusion-'));
  {
    // Read back from DISK (v392 4(d)): the four facts by name.
    const j = await scanWritten(outRoot, r);
    assert.equal(conclusionFiles(outRoot).length, 1, 'one conclusion file');
    const ALL = HEALTH.length + DEBUG.length + ERRORS.length;
    const res = j.results.find((x) => x.id === '050').result;
    assert.equal(res.findings.coverage.length, 1, 'fact 1: results[050] carries one coverage row');
    assert.deepEqual(res.findings.coverage, r.findings.coverage, 'the raw result keeps the gap row');
    assert.equal(res.details.notRead.length, ALL, `fact 2: results[050].details.notRead has ${ALL} entries`);
    assert.deepEqual(res.details.notRead, r.details.notRead);
    const svc = (j.conclusion?.result?.services ?? []).find((x) => x.source === 'tribe-health');
    assert.ok(svc, 'the tribe-health record is in the written conclusion');
    assert.equal(svc.tribeHealth.notRead.length, ALL, `fact 3: the tribe-health record's notRead has ${ALL} entries`);
    assert.deepEqual(svc.tribeHealth.notRead, r.details.notRead);
    // fact 4: the gap whole in tribeHealth.findings.
    assert.deepEqual(svc.tribeHealth.findings.filter((f) => f.details?.evidenceGap === true), [{ ...r.findings.coverage[0], category: 'coverage' }]);
    assert.match(svc.info, /^API probe incomplete: the body of \d+ replies was not read/);
  }
});

// ── (t-13c) v391 C4-R3 + v393 C4-R6: `report --since` through the REAL runReport. The run record is written by the real
// record writers (writeRunStart, then scanSingleHost's own appendHostWritten, finalize, seal); the conclusion file by
// the REAL scanSingleHost, through scanWritten — the helper t-13b reads back. No file here is written by the test. ─────
// A documentation-range address (RFC 5737): scanSingleHost's target guard refuses a private one such as 10.0.0.7.
const SINCE_HOST = '192.0.2.10';
async function sinceReport(before, after, { afterStatus = 'ran' } = {}) {
  const { runReport } = await import('../cli.mjs');
  const { resolveCapabilities } = await import('../utils/capabilities.mjs');
  const { newRunId, writeRunStart, finalizeRunRecord } = await import('../utils/run_record.mjs');
  const { sealRunRecord } = await import('../utils/run_chain.mjs');
  const outRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-tribe-since-'));
  const mk = async (startedAt, result, status = 'ran') => {
    const runId = newRunId();
    await writeRunStart(outRoot, { runId, startedAt, hostsRequested: [SINCE_HOST], pluginsRequested: ['050'], portsRequested: '8080',
      tier: 'pro', ceVersion: '0.2.54', eeVersion: null, prevDigest: null });
    const j = await scanWritten(outRoot, result, { host: SINCE_HOST, runId, status });
    assert.equal(j.runId, runId, 'the conclusion file names the run it was written for');
    await finalizeRunRecord(outRoot, runId, { finishedAt: startedAt });
    await sealRunRecord(outRoot, runId);
    return runId;
  };
  const a = await mk('2026-09-01T10:00:00.000Z', before); const b = await mk('2026-09-08T10:00:00.000Z', after, afterStatus);
  const rep = await runReport({ from: outRoot, format: 'executive', run: b, since: a, out: path.join(outRoot, 'exec.html') }, resolveCapabilities('pro'));
  assert.equal(rep.code, 0, rep.stderr);
  const m = rep.stdout.match(/(\d+) new · (\d+) resolved · (\d+) changed · (\d+) not-comparable · (\d+) unchanged/);
  assert.ok(m, `the delta line: ${rep.stdout.slice(0, 300)}`);
  return { stdout: rep.stdout, page: fs.readFileSync(path.join(outRoot, 'exec.html'), 'utf8'),
    n: { new: +m[1], resolved: +m[2], notComparable: +m[4], unchanged: +m[5] } };
}
// The baseline's two body-derived rows: the health leak, and /metrics upgraded on its 64-byte body.
const LEAKY_TWO = (req) => (req.url === '/health' ? { status: 200, headers: { 'content-type': 'application/json' }, body: '{"version":"1.0"}' }
  : req.url === '/metrics' ? { status: 200, headers: { 'content-type': 'text/plain' }, body: 'm'.repeat(64) } : null);
async function runOn(reply) { const s = await serve(reply); try { return await run(s.port); } finally { await s.close(); } }
const LEAK_TITLES = ['/health exposes: version/build info',
  '/metrics is accessible (HTTP 200) – Prometheus metrics — returns content without authentication'];
test('(t-13c) report --since, both arms (v392 4(e)): every reply read and the two rows absent → 2 resolved; replies not read → 0 resolved, both rows NOT COMPARABLE by title for the evidence gap', async () => {
  const baseline = await runOn(LEAKY_TWO);
  // Arm 1, FOURTH QUADRANT FIRST — the accept: the rows are gone and every reply was read.
  const read = await sinceReport(baseline, await runOn(() => null));
  assert.equal(read.n.resolved, 2, read.stdout);
  assert.equal(read.n.notComparable, 0, read.stdout);
  // Arm 2 — the replies were not read: nothing is resolved, and each baseline row is held, by its title.
  const held = await sinceReport(baseline, await runOn(CODED_200));
  assert.equal(held.n.resolved, 0, 'a body that was not read fixed nothing');
  assert.equal(held.n.notComparable, 2, held.stdout);
  const rows = held.stdout.split('\n').filter((l) => /NOT COMPARABLE/.test(l));
  for (const title of LEAK_TITLES) {
    const row = rows.find((l) => l.includes(`NOT COMPARABLE (disappeared)  ${title} — evidence-gap: `));
    assert.ok(row, `the baseline row "${title}" is held with the reason evidence-gap:\n${rows.join('\n')}`);
    assert.match(row, /recorded an evidence gap on 192\.0\.2\.10\/.*\(050\): \[COVERAGE GAP\] TRIBE API probe/);
  }
  assert.doesNotMatch(held.stdout, /NOT COMPARABLE \([a-z]+\)\s+\[COVERAGE GAP\]/, 'the gap is the REASON, never the subject of a row');
});

// v392 4(e3): R1 in the delta — an UNCODED /metrics over the cap keeps the row's text, so the row is UNCHANGED.
test('(t-13c3) report --since: the same /metrics now answering 2 MiB uncoded reads UNCHANGED — not held, not new (R1 in the delta)', async () => {
  const baseline = await runOn(LEAKY_TWO);
  const big = await runOn((req) => (req.url === '/metrics' ? { status: 200, headers: { 'content-type': 'text/plain' }, body: BIG_BODY }
    : LEAKY_TWO(req)));
  const d = await sinceReport(baseline, big);
  assert.deepEqual({ new: d.n.new, resolved: d.n.resolved, notComparable: d.n.notComparable }, { new: 0, resolved: 0, notComparable: 0 }, d.stdout);
  // v393 ruling (a): the oracle is DECLARED as well as computed — the health leak, /metrics, and six missing headers.
  assert.equal(actionable(baseline).length, 8, 'the declared baseline: 2 body-derived rows + 6 missing-header rows');
  assert.equal(d.n.unchanged, actionable(baseline).length, `every baseline row, /metrics included, is unchanged: ${d.stdout}`);
});

// ── (t-13d) v392 3: the RAW html shows the not-read state in the tribe-health row; it prints no gap ROW (stated limit) ─
test('(t-13d) the raw html: the tribe-health row carries "API probe incomplete" and the count; no total on the page counts the gap', async () => {
  const { buildAdminRawHtmlReport } = await import('../utils/raw_report_html.mjs');
  const s = await serve(CODED_200);
  try {
    const r = await run(s.port);
    const c = await concluder.run([{ id: '050', name: plugin.name, result: r }]);
    const html = await buildAdminRawHtmlReport({ host: '127.0.0.1', whenIso: '2026-11-25T00:00:00Z', summary: c.summary, services: c.services, evidence: c.evidence });
    const ALL = HEALTH.length + DEBUG.length + ERRORS.length;
    const row = html.match(/<tr data-key="tcp-8080">[\s\S]*?<\/tr>/)?.[0];
    assert.ok(row, 'the tribe-health row, under its record key 8080 (G-67)');
    assert.match(row, new RegExp(`API probe incomplete: the body of ${ALL} replies was not read`));
    // C4-R5 (v393 G-A): "no total counts the gap" is held as a DIFFERENTIAL of two built pages, never by reading one div
    // for two words (that check passed with a `Findings:` total outside the div, with "42 issues" inside it, and with the
    // div gone). The same run with its gap stripped builds a page that differs ONLY in the tribe-health row, so no total
    // anywhere on the page moves with the gap — whatever the total's wording or position.
    const strip = (x) => { const y = structuredClone(x); delete y.findings.coverage; y.details.notRead = []; return y; };
    const c0 = await concluder.run([{ id: '050', name: plugin.name, result: strip(r) }]);
    const html0 = await buildAdminRawHtmlReport({ host: '127.0.0.1', whenIso: '2026-11-25T00:00:00Z', summary: c0.summary, services: c0.services, evidence: c0.evidence });
    const outside = (h) => h.replace(/<tr data-key="tcp-8080">[\s\S]*?<\/tr>/, '');
    assert.notEqual(html, html0, 'positive control: the tribe-health row differs');
    assert.notEqual(outside(html), html, 'the row was cut, so the equality below compares the rest of the page');
    assert.equal(outside(html), outside(html0), 'nothing outside the tribe-health row moves with the gap');
    // Stated limit (v392 3), deliberately NOT asserted: the raw html prints no [COVERAGE GAP] row. A leg pinning that
    // absence would go red on the day a gap row is added.
  } finally { await s.close(); }
});

test('(t-14) the conclude comment says which fields carry the target\'s header text, and makes no ZDE claim it cannot keep', () => {
  assert.doesNotMatch(SRC, /ZDE: no response bodies or header values in conclude output/);
  assert.match(SRC, /serverInfo\.server/);
});

// ── G-71 F-050 (EE Z-1, architect RULINGS-v402 §4; board G-64): a probe that got NO REPLY while `/` replied ─────────────
// The checks that decide from that probe did not run, and their rows vanished under a record that said "API probe
// complete" — so `report --since` read a vanished /metrics CRITICAL as RESOLVED (drive arm 050-nr). 050 now writes a
// DECLARED gap row (gapOnly) naming each probe that got no reply by the plugin's own probe name, method and path, and the
// waist's error CODE — never a message, never anything the target sent. The row holds 050's rows on the host in the delta,
// as the not-read row does; the history reads the run as payload-partial.
// The no-reply list, in the order the groups are concatenated (health, debug, errors, headers, auth, methods). A headers
// probe that gets no reply sends no CORS probe; the auth probe with a token is sent only after a 401/403.
const AUTH = ['/api/v1/users', '/api/v1/scan', '/api/v1/results', '/api/v2/neural', '/api/v2/agents', '/api/v2/config', '/api/v1/admin', '/api/v1/plugins'];
// Only the OPTIONS reply is examined (O-3: DELETE, PUT and PATCH are sent and their replies are not), so only OPTIONS is listed.
const FUZZ = ['/', '/api/v1/health'].map((p) => [p, 'OPTIONS']);
const NO_REPLY_ALL = (code) => [
  ...HEALTH.map((p) => ({ probe: 'health', method: 'GET', path: p, code })),
  ...DEBUG.map((p) => ({ probe: 'debug', method: 'GET', path: p, code })),
  ...ERRORS.map((p) => ({ probe: 'errors', method: 'GET', path: p, code })),
  { probe: 'headers', method: 'GET', path: '/', code },
  ...AUTH.map((p) => ({ probe: 'auth', method: 'GET', path: p, code })),
  ...FUZZ.map(([p, m]) => ({ probe: 'methods', method: m, path: p, code })),
];
const WAIST_CODE = /^[A-Z][A-Z0-9_]{0,47}$/;
/** A real server: `mode(req, n)` (n = the request's 0-based index) returns 'reset' (destroy the socket), 'hang' (never
 *  answer) or nothing (answer with `reply(req)`, null → a 404). */
async function serveModes(reply, mode) {
  let n = 0;
  const server = http.createServer((req, res) => {
    req.resume();
    const m = mode(req, n++);
    if (m === 'reset') { req.socket.destroy(); return; }
    if (m === 'hang') return;
    const r = reply(req) ?? { status: 404, headers: { 'content-type': 'text/plain' }, body: 'not found' };
    res.writeHead(r.status, r.headers ?? {});
    res.end(r.body ?? '');
  });
  await new Promise((ok) => server.listen(0, '127.0.0.1', ok));
  return { port: server.address().port, close: () => { server.closeAllConnections(); return new Promise((ok) => server.close(ok)); } };
}
async function runModes(reply, mode, timeoutMs = 400) {
  const s = await serveModes(reply, mode);
  try { return await run(s.port, { timeoutMs }); } finally { await s.close(); }
}
const noReplyRows = (r) => (r.findings.coverage ?? []).filter((f) => f.check === 'tribe_probe_no_reply');
const METRICS_TITLE = '/metrics is accessible (HTTP 200) – Prometheus metrics — returns content without authentication';
const pageRows = (page) => {
  const at = page.indexOf('Since Last Scan');
  const sect = at < 0 ? '' : page.slice(at, page.indexOf('</table>', at));
  const strip = (x) => x.replace(/<[^>]+>/g, ' ').replace(/&quot;/g, '"').replace(/&amp;/g, '&').replace(/\s+/g, ' ').trim();
  return (sect.match(/<tr[\s\S]*?<\/tr>/g) ?? []).slice(1).map((tr) => (tr.match(/<td[\s\S]*?<\/td>/g) ?? []).map(strip));
};
const changeOf = (page, title) => pageRows(page).filter((r) => r[1] === title).map((r) => r[0]);

test('F-050 (accept, first): every probe replied — details.noReply is [], no no-reply row, the record says complete', async () => {
  const r = await runModes(LEAKY_TWO, () => undefined);
  assert.equal(r.up, true);
  assert.deepEqual(r.details.noReply, [], 'the stable key is present and empty when every probe replied');
  assert.deepEqual(noReplyRows(r), []);
  assert.equal('coverage' in r.findings, false);
  const [rec] = plugin.conclude({ result: r });
  assert.match(rec.info, /^API probe complete: /);
  assert.equal('noReply' in rec.tribeHealth, false);
  assert.equal(rowOf('tribeHealth').measured(rec), true);
});

test('F-050 (G-64): a server that answers `/` and resets every later connection — every probe is listed with its code, in ONE declared gap row', async () => {
  const r = await runModes(() => ({ status: 200, body: 'root' }), (req, n) => (n === 0 ? undefined : 'reset'));
  assert.equal(r.up, true, 'the ping replied');
  assert.deepEqual(r.details.noReply, NO_REPLY_ALL('ECONNRESET'));
  const rows = noReplyRows(r);
  assert.equal(rows.length, 1, 'one row');
  const [gap] = rows;
  assert.equal(gap.severity, 'info');
  assert.deepEqual(gap.details, { evidenceGap: true, gapOnly: true, noReply: r.details.noReply });
  assert.equal(gap.title, `[COVERAGE GAP] TRIBE API probe: ${NO_REPLY_ALL('x').length} probes on port ${gap.port} got no reply`);
  assert.match(gap.detail, /This is not a pass\./);
  assert.ok(gap.detail.includes('debug: GET /metrics (ECONNRESET)'), gap.detail);
  assert.ok(gap.detail.includes('methods: OPTIONS /api/v1/health (ECONNRESET)'), gap.detail);
  assert.ok(!/(DELETE|PUT|PATCH) \//.test(gap.detail), 'a probe whose reply no check examines is not listed');
  assert.ok(!gap.detail.includes('target request failed'), 'no error message text: the code only');
  assert.equal(r.findings.coverage.length, 1, 'nothing was replied to, so nothing is listed not-read');
  // Not counted, and it moves no severity.
  assert.equal(r.summary.totalChecks, actionable(r).length);
  // The record (conclude, the concluder), CE's report (the loader shapes it as a gap, uncounted) and the history.
  const [rec] = plugin.conclude({ result: r });
  assert.equal(rec.info, `API probe incomplete: ${NO_REPLY_ALL('x').length} probes got no reply; from the replies read, 0 critical, 0 high, 0 medium findings`);
  assert.deepEqual(rec.tribeHealth.noReply, r.details.noReply);
  assert.deepEqual(rec.tribeHealth.findings.filter((f) => f.check === 'tribe_probe_no_reply'), [{ ...gap, category: 'coverage' }]);
  const c = await concluder.run([{ id: '050', name: plugin.name, result: r }]);
  assert.deepEqual(c.services.find((x) => x.source === 'tribe-health').tribeHealth.noReply, r.details.noReply);
  const shaped = shapeHostFindings('192.0.2.10', { results: [{ id: '050', name: plugin.name, result: r }] });
  const gaps = shaped.filter((f) => f.evidenceGap === true);
  assert.deepEqual(gaps.map((f) => f.title), [gap.title]);
  assert.equal(countHostFindings(shaped).total ?? countHostFindings(shaped), countHostFindings(shaped.filter((f) => f.evidenceGap !== true)).total ?? countHostFindings(shaped.filter((f) => f.evidenceGap !== true)));
  assert.equal(rowOf('tribeHealth').measured(rec), 'payload-partial');
});

test('F-050: the second probe of a check — the CORS probe after `/` answered, the token probe after a 401 — is listed under its own probe name', async () => {
  const s = await serveModes((req) => (AUTH.includes(req.url) ? { status: 401, body: 'no' } : { status: 200, body: 'ok' }),
    (req) => (req.headers.origin || req.headers.authorization ? 'reset' : undefined));
  let r;
  try { r = await run(s.port, { timeoutMs: 400, authToken: 'tok-zq-canary' }); } finally { await s.close(); }
  assert.deepEqual(r.details.noReply, [{ probe: 'cors', method: 'GET', path: '/', code: 'ECONNRESET' },
    ...AUTH.map((p) => ({ probe: 'auth-token', method: 'GET', path: p, code: 'ECONNRESET' }))]);
  assert.ok(!JSON.stringify(r).includes('tok-zq-canary'), 'the token reaches no entry, row or result');
});

test('F-050: a probe that times out is listed ETIMEDOUT — the probe name, method, path and code, nothing else', async () => {
  const r = await runModes(LEAKY_TWO, (req) => (req.url === '/metrics' ? 'hang' : undefined));
  assert.deepEqual(r.details.noReply, [{ probe: 'debug', method: 'GET', path: '/metrics', code: 'ETIMEDOUT' }]);
  assert.ok(r.details.noReply.every((e) => WAIST_CODE.test(e.code)));
  const [gap] = noReplyRows(r);
  assert.equal(gap.title, `[COVERAGE GAP] TRIBE API probe: 1 probe on port ${gap.port} got no reply`);
  assert.ok(gap.detail.endsWith('debug: GET /metrics (ETIMEDOUT).'), gap.detail);
  assert.equal(r.findings.debug.some((f) => f.endpoint === '/metrics'), false, 'the row that probe decided is absent');
  assert.ok(r.findings.health.some((f) => f.check === 'health_info_leak'), 'every other check still decides');
});

test('F-050 report --since (control, first): /metrics answers as before — UNCHANGED, nothing held', async () => {
  const baseline = await runModes(LEAKY_TWO, () => undefined);
  const d = await sinceReport(baseline, await runModes(LEAKY_TWO, () => undefined));
  assert.deepEqual({ new: d.n.new, resolved: d.n.resolved, notComparable: d.n.notComparable, unchanged: d.n.unchanged },
    { new: 0, resolved: 0, notComparable: 0, unchanged: actionable(baseline).length }, d.stdout);
});

test('F-050 report --since (control): /metrics answers 404 now — its row reads RESOLVED (a measured removal)', async () => {
  const baseline = await runModes(LEAKY_TWO, () => undefined);
  const now = await runModes((req) => (req.url === '/metrics' ? null : LEAKY_TWO(req)), () => undefined);
  assert.deepEqual(now.details.noReply, [], 'premise: a 404 is a reply');
  const d = await sinceReport(baseline, now);
  assert.equal(d.n.resolved, 1, d.stdout);
  assert.equal(d.n.notComparable, 0, d.stdout);
  assert.deepEqual(changeOf(d.page, METRICS_TITLE), ['resolved']);
});

test('F-050 report --since (the red arm, 050-nr): /metrics never replies — its row reads NOT COMPARABLE, held by the no-reply gap', async () => {
  const baseline = await runModes(LEAKY_TWO, () => undefined);
  const d = await sinceReport(baseline, await runModes(LEAKY_TWO, (req) => (req.url === '/metrics' ? 'hang' : undefined)));
  assert.equal(d.n.resolved, 0, `a probe that got no reply fixed nothing: ${d.stdout}`);
  assert.equal(d.n.notComparable, 1, d.stdout);
  const row = d.stdout.split('\n').find((l) => l.includes(`NOT COMPARABLE (disappeared)  ${METRICS_TITLE} — evidence-gap: `));
  assert.ok(row, d.stdout);
  assert.match(row, /recorded an evidence gap on 192\.0\.2\.10\/.*\(050\): \[COVERAGE GAP\] TRIBE API probe: 1 probe on port \d+ got no reply/);
  assert.equal(d.n.unchanged, actionable(baseline).length - 1, 'every other row compares');
  assert.deepEqual(changeOf(d.page, METRICS_TITLE), ['not-comparable']);
});

test('F-050 report --since (control): `/` itself does not reply — today\'s plugin-not-measured reading, unchanged', async () => {
  const baseline = await runModes(LEAKY_TWO, () => undefined);
  const down = await runModes(LEAKY_TWO, () => 'reset');
  assert.equal(down.up, false);
  assert.equal('details' in down, false, 'a down run carries no no-reply list: the plugin did not measure');
  const d = await sinceReport(baseline, down, { afterStatus: 'error' });
  assert.equal(d.n.resolved, 0, d.stdout);
  assert.equal(d.n.notComparable, actionable(baseline).length, d.stdout);
  const held = d.stdout.split('\n').filter((l) => /NOT COMPARABLE/.test(l));
  assert.ok(held.every((l) => / — plugin-not-measured: /.test(l)), held.join('\n'));
});

test('F-050 history: /metrics never replies — the vanished finding is NOT COMPARED (payload-partial), never cleared', async () => {
  const prev = await line(await runModes(LEAKY_TWO, () => undefined));
  const curr = await line(await runModes(LEAKY_TWO, (req) => (req.url === '/metrics' ? 'hang' : undefined)));
  const metrics = prev.services.flatMap((x) => x.flags).find((cid) => /debug_endpoint_exposed/.test(cid));
  assert.ok(metrics, `the prior scan carries the /metrics finding: ${JSON.stringify(prev.services.map((x) => x.flags))}`);
  const d = tribeAt(computeDiff(curr, prev));
  assert.equal(d.cleared.includes(metrics), false, 'a vanished finding whose probe got no reply must not read as resolved');
  assert.deepEqual(d.notCompared.find((n) => n.id === metrics), { id: metrics, reason: NOT_COMPARED_REASONS['payload-partial']() });
  assert.match(NOT_COMPARED_REASONS['payload-partial'](), /did not get, or did not read the body of, every reply/);
});

// ── VERDICT-v405 R5: a not-read reply AND a no-reply probe in ONE run — both rows, both clauses, both lists ────────────
test('F-050 R5: /health answers with a body not read and /metrics never replies — two coverage rows, both clauses in order, both lists, payload-partial', async () => {
  const r = await runModes((req) => (req.url === '/health' ? CODED_200() : LEAKY_TWO(req)), (req) => (req.url === '/metrics' ? 'hang' : undefined));
  assert.deepEqual(r.details.notRead, [coded('/health')]);
  assert.deepEqual(r.details.noReply, [{ probe: 'debug', method: 'GET', path: '/metrics', code: 'ETIMEDOUT' }]);
  assert.deepEqual(r.findings.coverage.map((f) => f.check), ['tribe_probe_not_read', 'tribe_probe_no_reply'], 'both rows, each with its own check id');
  assert.deepEqual(r.findings.coverage.map((f) => f.details.gapOnly), [true, true]);
  const [rec] = plugin.conclude({ result: r });
  assert.equal(rec.info, `API probe incomplete: 1 probe got no reply; the body of 1 reply was not read; from the replies read, ${r.summary.critical} critical, ${r.summary.high} high, ${r.summary.medium} medium findings`);
  assert.deepEqual(rec.tribeHealth.notRead, r.details.notRead);
  assert.deepEqual(rec.tribeHealth.noReply, r.details.noReply);
  assert.deepEqual(rec.tribeHealth.findings.filter((f) => f.details?.evidenceGap === true).map((f) => f.check), ['tribe_probe_not_read', 'tribe_probe_no_reply']);
  assert.equal(rowOf('tribeHealth').measured(rec), 'payload-partial');
});

// ── VERDICT-v405 R6: the delta's two other directions for 050, accept first ─────────────────────────────────────────────
test('F-050 R6 (accept, first): a NEW finding beside an unrelated no-reply probe reads NEW', async () => {
  const baseline = await runModes(LEAKY_TWO, () => undefined);
  const now = await runModes((req) => (req.url === '/debug' ? { status: 200, headers: { 'content-type': 'text/plain' }, body: 'debug root' } : LEAKY_TWO(req)),
    (req) => (req.url === '/ping' ? 'hang' : undefined));
  assert.deepEqual(now.details.noReply, [{ probe: 'health', method: 'GET', path: '/ping', code: 'ETIMEDOUT' }], 'premise: the no-reply probe is unrelated');
  const d = await sinceReport(baseline, now);
  assert.deepEqual({ new: d.n.new, resolved: d.n.resolved, notComparable: d.n.notComparable }, { new: 1, resolved: 0, notComparable: 0 }, d.stdout);
});
test('F-050 R6: baseline /metrics got no reply, now it answers 200 — its row reads NOT COMPARABLE (appeared), never new, citing the baseline\'s gap', async () => {
  const baseline = await runModes(LEAKY_TWO, (req) => (req.url === '/metrics' ? 'hang' : undefined));
  assert.deepEqual(baseline.details.noReply, [{ probe: 'debug', method: 'GET', path: '/metrics', code: 'ETIMEDOUT' }]);
  const d = await sinceReport(baseline, await runModes(LEAKY_TWO, () => undefined));
  assert.equal(d.n.new, 0, `a row the baseline could not measure is not new: ${d.stdout}`);
  assert.equal(d.n.notComparable, 1, d.stdout);
  const row = d.stdout.split('\n').find((l) => l.includes(`NOT COMPARABLE (appeared)  ${METRICS_TITLE} — evidence-gap: `));
  assert.ok(row, d.stdout);
  assert.match(row, /the baseline run recorded an evidence gap on 192\.0\.2\.10\/.*\(050\): \[COVERAGE GAP\] TRIBE API probe: 1 probe on port \d+ got no reply/);
  assert.deepEqual(changeOf(d.page, METRICS_TITLE), ['not-comparable']);
});
