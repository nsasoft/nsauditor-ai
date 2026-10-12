// tests/webhook_proxy_credentials.test.mjs
// ─────────────────────────────────────────────────────────────────────────────
// sendWebhook UNDER NODE'S ENV PROXY (EE 2.0.0, measured 2026-10-11 on Node 24.12 while scoping R1).
//
// With NODE_USE_ENV_PROXY=1 and HTTP(S)_PROXY set, Node routes sendWebhook through the proxy and hands it the webhook's
// NAME (an absolute-URI request for http, CONNECT <name>:<port> for https): the proxy resolves the name, so the
// resolved-address pin governs only the hop to the proxy — stated in the README. And a failed tunnel's error message
// carries the proxy URL WITH its credentials, which sendWebhook used to return as `error` (printed to stderr by the
// watch loop; written into Enterprise's drift file). It is redacted now.
//
// The env proxy is read at process start, so the sender runs in a CHILD process; the proxy runs here and records what
// it is asked. The child's check resolver is stubbed for one RFC 6761 name, so nothing reaches a real resolver.
//
// FOURTH QUADRANT FIRST: the request really went through the proxy — or a clean error proves nothing.
// ─────────────────────────────────────────────────────────────────────────────
import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { spawn } from 'node:child_process';
import { redactUrlCredentials } from '../utils/webhook.mjs';

const WEBHOOK = pathToFileURL(path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'utils', 'webhook.mjs')).href;

/** A proxy that refuses every tunnel, recording what it was asked; the child posts once through it. */
async function viaProxy(scheme) {
  const seen = [];
  const proxy = http.createServer((req, res) => { seen.push({ method: req.method, url: req.url }); res.writeHead(502); res.end(); });
  proxy.on('connect', (req, sock) => { seen.push({ method: 'CONNECT', url: req.url }); sock.end('HTTP/1.1 502 Bad Gateway\r\n\r\n'); });
  await new Promise((r) => proxy.listen(0, '127.0.0.1', r));
  const proxyUrl = `http://proxyuser:PROXYSECRET@127.0.0.1:${proxy.address().port}`;
  const child = `
    import dnsP from 'node:dns/promises';
    const { sendWebhook } = await import(${JSON.stringify(WEBHOOK)});
    const orig = dnsP.lookup;
    dnsP.lookup = async (h, o) => (h === 'rebind.test' ? (o?.all ? [{ address: '203.0.113.10', family: 4 }] : { address: '203.0.113.10', family: 4 }) : orig(h, o));
    const r = await sendWebhook('${scheme}://rebind.test:8443/hook', { a: 1 }, { timeout: 3000, retries: 0, retryDelayMs: 0 });
    process.stdout.write(JSON.stringify(r));`;
  const env = { ...process.env, NODE_USE_ENV_PROXY: '1', HTTPS_PROXY: proxyUrl, HTTP_PROXY: proxyUrl, NO_PROXY: '' };
  // Asynchronous on purpose: a synchronous spawn would block this event loop, and the proxy here could not answer.
  const out = await new Promise((resolve, reject) => {
    const p = spawn(process.execPath, ['--input-type=module', '-e', child], { env });
    let stdout = ''; let stderr = '';
    p.stdout.on('data', (d) => { stdout += d; }); p.stderr.on('data', (d) => { stderr += d; });
    p.on('error', reject);
    p.on('close', () => resolve({ stdout, stderr }));
  });
  await new Promise((r) => proxy.close(r));
  return { seen, result: JSON.parse(out.stdout || '{}'), stderr: out.stderr };
}

test('(p1, first) under NODE_USE_ENV_PROXY the webhook really goes THROUGH the proxy, by NAME — the pin governs only that hop', async () => {
  const { seen, result } = await viaProxy('https');
  assert.deepEqual(seen, [{ method: 'CONNECT', url: 'rebind.test:8443' }], 'the proxy was not asked — this run says nothing about the proxy path');
  assert.equal(result.success, false);
});

test('(p2) a failed tunnel\'s error carries NO proxy credential — redacted before it can reach stderr or a drift file', async () => {
  const { seen, result } = await viaProxy('https');
  assert.equal(seen.length, 1, 'positive control: the request reached the proxy');
  assert.match(result.error, /tunnel/i, `not the tunnel error under test: ${result.error}`);
  assert.ok(!result.error.includes('PROXYSECRET'), `the proxy password reached the returned error: ${result.error}`);
  assert.ok(!result.error.includes('proxyuser'), 'the proxy user reached the returned error');
  assert.match(result.error, /<credentials>@127\.0\.0\.1/);
});

test('(p3) redactUrlCredentials replaces userinfo in any URL and leaves a URL without one untouched', () => {
  assert.equal(redactUrlCredentials('via http://u:p@h:1 and https://x@y/z'), 'via http://<credentials>@h:1 and https://<credentials>@y/z');
  assert.equal(redactUrlCredentials('connect ECONNREFUSED 203.0.113.10:443'), 'connect ECONNREFUSED 203.0.113.10:443');
  assert.equal(redactUrlCredentials('see https://hooks.example/a@b'), 'see https://hooks.example/a@b', 'an @ in the PATH is not userinfo');
});
