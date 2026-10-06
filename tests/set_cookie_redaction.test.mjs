// tests/set_cookie_redaction.test.mjs
// 1.3.0 — a scanned service's Set-Cookie VALUES never reach a record, an artifact or an AI prompt (the audit seat's
// ruling (A), at BOTH seams, the SNMP precedent).
//
// THE FINDING: the HTTP probe's (006) banner picked `set-cookie` among its fingerprinting headers since CE v0.1.3, so a
// scanned service's live session token reached the raw result and the scan artifacts; since 1.3.0 (a4) its adapter also
// puts that banner and the evidence rows on the service record, so it reached the conclusion and — the AI redactor did not
// know cookies — the AI prompt. The cookie NAME fingerprints a framework (PHPSESSID, JSESSIONID); the VALUE is the
// target's secret. Same for a Location header's query string, which can carry an SSO ticket or an OAuth code.
//
// PRODUCER seam: a REAL loopback server and a REAL 006 run (only the destination port of node's request is rewritten —
// 006 picks its scheme by port 80 / 443), asserted on the result, the record, its evidence rows and the conclusion.
// REDACTOR seam: redactSensitiveForAI over 006-shaped and 010-shaped records (010 still reflects its headers; its own fix
// is boarded) — so the AI path holds even where a producer does not.
import './helpers/no_operator_dotenv.mjs';
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import https from 'node:https';
import { execFileSync } from 'node:child_process';
import probe from '../plugins/http_probe.mjs';
import concluder from '../plugins/result_concluder.mjs';
import { setCookieValues } from '../utils/cookie_redaction.mjs';

const { redactSensitiveForAI } = await import('../cli.mjs');
const SECRETS = ['session-secret-1', 'theme-secret-2', 'ticket-secret-3'];
const leaks = (x) => SECRETS.filter((v) => JSON.stringify(x).includes(v));

let tls = null;
before(() => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-cookie-'));
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', path.join(dir, 'key.pem'),
    '-out', path.join(dir, 'cert.pem'), '-days', '1', '-subj', '/CN=localhost'], { stdio: 'ignore', env: { PATH: process.env.PATH } });
  tls = { key: fs.readFileSync(path.join(dir, 'key.pem')), cert: fs.readFileSync(path.join(dir, 'cert.pem')) };
});
const realHttps = https.request;
const realHttp = http.request;
after(() => { https.request = realHttps; http.request = realHttp; });

async function realRun(port) {
  const handler = (req, res) => {
    res.writeHead(302, { 'Set-Cookie': [`PHPSESSID=${SECRETS[0]}; Path=/; HttpOnly`, `theme=${SECRETS[1]}`],
      Location: `https://sso.example/login?ticket=${SECRETS[2]}#top`, Server: 'loopback', Allow: 'GET, OPTIONS' });
    res.end();
  };
  const srv = port === 443 ? https.createServer(tls, handler) : http.createServer(handler);
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  let hits = 0;
  const redirect = (real, from) => (opts, cb) => { if (Number(opts.port) === from) { hits++; opts = { ...opts, port: srv.address().port }; } return real.call(null, opts, cb); };
  https.request = redirect(realHttps, 443);
  http.request = redirect(realHttp, 80);
  try {
    const result = await probe.run('127.0.0.1', port, { insecureHttps: true });
    const conclusion = await concluder.run([{ id: '006', name: 'HTTP Probe', result }]);
    return { result, conclusion, record: conclusion.services.find((s) => s.port === port), hits };
  } finally {
    https.request = realHttps; http.request = realHttp;
    await new Promise((r) => srv.close(r));
  }
}

// ── PRODUCER ──────────────────────────────────────────────────────────────────────────────────────────────────────────
for (const port of [80, 443]) {
  test(`(fourth quadrant, first) port ${port}: the cookie NAMES and the redirect PATH survive — the fingerprint is kept`, { timeout: 20000 }, async () => {
    const { record, hits } = await realRun(port);
    assert.equal(hits, 2, 'the transport double carried the real path: GET and OPTIONS');
    assert.match(record.banner, /set-cookie: PHPSESSID=<redacted>; Path=\/; HttpOnly/);
    assert.match(record.banner, /set-cookie: theme=<redacted>/);
    assert.match(record.banner, /location: https:\/\/sso\.example\/login\?<redacted>/);
  });

  test(`port ${port}: no cookie VALUE and no Location query reaches the result, the record, its evidence or the conclusion`, { timeout: 20000 }, async () => {
    const { result, conclusion, record } = await realRun(port);
    assert.deepEqual(leaks(result), [], 'the raw result (what the artifacts are written from)');
    assert.deepEqual(leaks(record), [], 'the service record, banner and evidence rows');
    assert.deepEqual(leaks(conclusion), [], 'the whole conclusion');
  });
}

// ── REDACTOR ──────────────────────────────────────────────────────────────────────────────────────────────────────────
test('the AI redactor removes Set-Cookie values from a 006-shaped and a 010-shaped record, banner and evidence alike — names kept', () => {
  const s006 = { port: 443, banner: `200 OK\r\nserver: x\r\nset-cookie: PHPSESSID=${SECRETS[0]}; Path=/`,
    evidence: [{ response_banner: `200 OK\r\nset-cookie: theme=${SECRETS[1]}` },
      // Node lowercases header names, so no producer emits this spelling — a hand-shaped or composed string could, and
      // the redactor's match is case-insensitive for it (the audit seat's surviving mutant, /gi → /g).
      { probe_info: `relayed: SET-COOKIE: up=${SECRETS[2]}` }] };
  // 010 joins its banner lines with a literal backslash-r-backslash-n, and fetch merges several cookies into one value.
  const s010 = { port: 80, banner: `200\\r\\nserver: x\\r\\nset-cookie: sid=${SECRETS[0]}; Path=/, lang=${SECRETS[1]}; Expires=Wed, 21 Oct 2026 07:28:00 GMT\\r\\nx-powered-by: php, build=7` };
  const out = redactSensitiveForAI({ host: 'x', summary: '', services: [s006, s010], evidence: [] }, 'x');
  assert.deepEqual(leaks(out), [], JSON.stringify(out));
  const text = JSON.stringify(out);
  for (const name of ['PHPSESSID=<redacted>', 'theme=<redacted>', 'sid=<redacted>', 'lang=<redacted>']) assert.ok(text.includes(name), `${name} kept`);
  assert.ok(text.includes('Expires=Wed, 21 Oct 2026'), 'a cookie attribute is not a value to redact');
  assert.ok(text.includes('x-powered-by: php, build=7'), 'the line after a Set-Cookie line is left alone — 010 ends lines with a literal \\r\\n');
});

// ── CENSUS SIBLING: no set-cookie VALUE on any record any adapter lands ──────────────────────────────────────────────
test('setCookieValues finds an unredacted value anywhere in a structure, and nothing in a redacted one', () => {
  assert.deepEqual(setCookieValues({ a: [{ b: `set-cookie: sid=${SECRETS[0]}` }] }), [`sid=${SECRETS[0]}`], 'positive control: a planted value is found');
  assert.deepEqual(setCookieValues({ banner: 'set-cookie: sid=<redacted>; Path=/' }), []);
});
