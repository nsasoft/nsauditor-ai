// tests/http_probe_hsts.test.mjs
// 1.3.0 lane 4, item 1 — the HTTP probe (006) carries ONE response header, Strict-Transport-Security, on its HTTPS
// record, so Enterprise's crypto agent can say whether a 443 response lacked it. Until 1.3.0 no plugin supplied a
// header at all, so the Missing-HSTS check never fired.
//
// RULED: option (1) — the header rides 006's OWN record, the (https, 443) key where its adapter has always landed it;
// exactly one key (a header map is a channel; tests/service_flag_table.test.mjs holds the key set); and the
// no-response rule — a request that got no response carries NO `headers` key, because an empty map would fabricate
// "Missing HSTS". Port 80 never carries it: a user agent ignores the header over plain HTTP (RFC 6797 §8.1).
//
// DRIVEN against REAL loopback servers (an openssl self-signed certificate for TLS) through the REAL 006 run() and the
// REAL concluder. 006 decides HTTPS by port 443, which an unprivileged test cannot bind, so the test wraps the transport
// it already uses — `https.request` / `http.request` on the node:https / node:http objects — and changes ONLY the
// destination port (443 / 80 → the loopback server's ephemeral port). Nothing in the plugin is a test seam.
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

let tls = null;
before(() => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-hsts-'));
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', path.join(dir, 'key.pem'),
    '-out', path.join(dir, 'cert.pem'), '-days', '1', '-subj', '/CN=localhost'], { stdio: 'ignore', env: { PATH: process.env.PATH } });
  tls = { key: fs.readFileSync(path.join(dir, 'key.pem')), cert: fs.readFileSync(path.join(dir, 'cert.pem')) };
});
const realHttps = https.request;
const realHttp = http.request;
after(() => { https.request = realHttps; http.request = realHttp; });

const COOKIE = 'sid=loopback-session-value';
async function serve(kind, headers) {
  const handler = (req, res) => { res.writeHead(200, { ...headers, Allow: 'GET, OPTIONS' }); res.end('ok'); };
  const srv = kind === 'https' ? https.createServer(tls, handler) : http.createServer(handler);
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  return { port: srv.address().port, close: () => new Promise((r) => srv.close(r)) };
}
/** One real 006 run on `port` (443 or 80) against a loopback server, concluded by the real concluder. */
async function concluded(port, { serverKind = port === 443 ? 'https' : 'http', headers = {}, insecureHttps = true } = {}) {
  const srv = await serve(serverKind, headers);
  let hits = 0;
  const redirect = (real, from) => (opts, cb) => { if (Number(opts.port) === from) { hits++; opts = { ...opts, port: srv.port }; } return real.call(null, opts, cb); };
  https.request = redirect(realHttps, 443);
  http.request = redirect(realHttp, 80);
  try {
    const result = await probe.run('127.0.0.1', port, { insecureHttps });
    const c = await concluder.run([{ id: '006', name: 'HTTP Probe', result }]);
    assert.equal(hits, 2, 'the transport double carried the real path: GET and OPTIONS');
    return { result, record: c.services.find((s) => s.port === port), services: c.services };
  } finally {
    https.request = realHttps; http.request = realHttp;
    await srv.close();
  }
}

// ── FOURTH QUADRANT FIRST ─────────────────────────────────────────────────────────────────────────────────────────────
test('(fourth quadrant, first) a 443 response WITH Strict-Transport-Security carries exactly that one header — no cookie, no server', { timeout: 20000 }, async () => {
  const { result, record } = await concluded(443, { headers: { 'Strict-Transport-Security': 'max-age=31536000', 'Set-Cookie': COOKIE, Server: 'loopback' } });
  assert.equal(record?.protocol, 'https', 'positive control: 006\'s own (https, 443) record');
  assert.deepEqual(record.headers, { 'strict-transport-security': 'max-age=31536000' });
  assert.deepEqual(result.headers, { 'strict-transport-security': 'max-age=31536000' }, 'the RAW result too — artifacts are written from it, and the adapter\'s filter must not be the only one');
});

test('(fourth quadrant) a 443 request that got NO response carries no `headers` key — an empty map would fabricate "Missing HSTS"', { timeout: 20000 }, async () => {
  // A certificate the client rejects (self-signed, and --insecure-https off): the TLS handshake fails, no response.
  const { result, record } = await concluded(443, { headers: { 'Strict-Transport-Security': 'max-age=1' }, insecureHttps: false });
  assert.ok(record, 'positive control: the record exists');
  assert.equal('headers' in record, false, JSON.stringify(record));
  assert.equal('headers' in result, false, 'the RAW result too');
});

test('(fourth quadrant) port 80 never carries the header, even when the server sends it (RFC 6797 §8.1)', { timeout: 20000 }, async () => {
  const { result, record } = await concluded(80, { headers: { 'Strict-Transport-Security': 'max-age=1' } });
  assert.equal(record?.protocol, 'http', 'positive control: 006\'s own (http, 80) record');
  assert.equal('headers' in record, false);
  assert.equal('headers' in result, false, 'the RAW result too — not set and then filtered away');
});

// ── THE DEFECT ────────────────────────────────────────────────────────────────────────────────────────────────────────
test('a 443 response WITHOUT Strict-Transport-Security carries `headers` present and the header absent — what the check reads', { timeout: 20000 }, async () => {
  const { record } = await concluded(443, { headers: { 'Set-Cookie': COOKIE, Server: 'loopback' } });
  assert.deepEqual(record?.headers, {}, JSON.stringify(record));
});
