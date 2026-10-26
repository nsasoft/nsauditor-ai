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
// ⚠️ ON NODE v24.22.1 THE RUNTIME STRIPS IT FIRST — Node's own fix for CVE-2026-48615 (measured 2026-10-26 from each
// binary's embedded lib source and from upstream lib/internal/http.js by tag). The tunnel error quotes `ProxyConfig.href`.
// v24.14.0 sets `this.href = proxyUrl`, the userinfo kept; v24.22.1 sets
//     if (username || password) { parsedURL.username = ''; parsedURL.password = ''; this.href = parsedURL.href; }
//     else { this.href = proxyUrl; }
// and in both the Proxy-Authorization is built from the ORIGINAL username and password, so the proxy still receives the
// credential. Node fixed this as CVE-2026-48615 ("redact proxy credentials in tunnel errors", Medium) in the June 2026
// security releases — 24.17.0 and 22.23.0; upstream http.js keeps the userinfo at v24.16.0 and v22.22.2 and blanks it
// from v24.17.0 and v22.23.0. (This comment first said v22.23.4 still kept it; that read missed the overwrite.) On v24.22.1 the
// error reads `via http://127.0.0.1:<port>/`, so the old positive control here — the `<credentials>@` marker — could
// not appear, and the no-secret vetoes beside it passed with nothing to catch: a positive control that depended on an
// upstream leak vanishes when upstream closes it — here the leak was a CVE. The control is now the credential at the point it is SENT — the
// CONNECT's Proxy-Authorization, decoded and compared by value — and the error must carry exactly ONE of the two known
// proxy-URL shapes with the port the proxy bound (redacted, from a runtime that quotes the userinfo; or stripped), the
// run printing which. Redaction itself stays driven with credential-bearing strings by (p3) below.
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
async function viaProxy(scheme, secret = 'PROXYSECRET', { stubTunnelError = false } = {}) {
  const seen = []; const auths = [];
  const proxy = http.createServer((req, res) => { seen.push({ method: req.method, url: req.url }); res.writeHead(502); res.end(); });
  proxy.on('connect', (req, sock) => {
    seen.push({ method: 'CONNECT', url: req.url });
    auths.push(req.headers['proxy-authorization'] ?? null);
    sock.end('HTTP/1.1 502 Bad Gateway\r\n\r\n');
  });
  await new Promise((r) => proxy.listen(0, '127.0.0.1', r));
  const { port } = proxy.address();
  const proxyUrl = `http://proxyuser:${secret}@127.0.0.1:${port}`;
  // With stubTunnelError the CHILD replaces https.request before sendWebhook runs, so the request fails with the error an
  // older runtime gives — the proxy URL WITH its userinfo, as v24.16.0 and earlier quote it (CVE-2026-48615) — on EVERY
  // Node version. The child reports whether the stub ran and what it emitted, so a stub that never fires cannot pass.
  const child = `
    import dnsP from 'node:dns/promises';
    import https from 'node:https';
    import { EventEmitter } from 'node:events';
    const { sendWebhook } = await import(${JSON.stringify(WEBHOOK)});
    const orig = dnsP.lookup;
    dnsP.lookup = async (h, o) => (h === 'rebind.test' ? (o?.all ? [{ address: '203.0.113.10', family: 4 }] : { address: '203.0.113.10', family: 4 }) : orig(h, o));
    let stubCalls = 0; let emitted = null;
    if (${JSON.stringify(stubTunnelError)}) {
      https.request = () => {
        stubCalls += 1;
        const req = new EventEmitter();
        req.write = () => {}; req.destroy = () => {};
        req.end = () => {
          emitted = 'Failed to establish tunnel to rebind.test:8443 via ' + process.env.HTTPS_PROXY + ': HTTP/1.1 502 Bad Gateway';
          setImmediate(() => req.emit('error', new Error(emitted)));
        };
        return req;
      };
    }
    const r = await sendWebhook('${scheme}://rebind.test:8443/hook', { a: 1 }, { timeout: 3000, retries: 0, retryDelayMs: 0 });
    process.stdout.write(JSON.stringify({ result: r, stubCalls, emitted }));`;
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
  const sent = auths.map((a) => (a && a.startsWith('Basic ') ? Buffer.from(a.slice(6), 'base64').toString('utf8') : a));
  const parsed = JSON.parse(out.stdout || '{}');
  return { seen, sent, port, result: parsed.result ?? {}, stubCalls: parsed.stubCalls ?? 0, emitted: parsed.emitted ?? null, stderr: out.stderr };
}

/**
 * The checks every tunnel-error leg makes: the credential was really in play (the proxy RECEIVED it, compared by value),
 * the error carries exactly one of the two known proxy-URL shapes for the port the proxy bound, and no encoding of the
 * credential — plaintext, percent-encoded, or the Proxy-Authorization value itself — reaches the error or stderr.
 */
function assertTunnelErrorCarriesNoCredential(t, { sent, port, result, stderr }, secret, pieces = []) {
  assert.ok(sent.includes(`proxyuser:${secret}`),
    `positive control: the proxy did not receive this leg's credential (${JSON.stringify(secret)}); it received ${JSON.stringify(sent)}`);
  assert.match(result.error, /tunnel/i, `not the tunnel error under test: ${result.error}`);
  const FORMS = { redacted: `via http://<credentials>@127.0.0.1:${port}: `, stripped: `via http://127.0.0.1:${port}/: ` };
  const observed = Object.keys(FORMS).filter((k) => result.error.includes(FORMS[k]));
  assert.equal(observed.length, 1, `the error carries ${observed.length} of the two known proxy-URL shapes for port ${port}: ${result.error}`);
  t.diagnostic(`${JSON.stringify(secret)} on ${process.version}: the tunnel error's proxy URL is ${observed[0]}`);
  const secrets = [...new Set([secret, encodeURIComponent(secret), 'proxyuser',
    Buffer.from(`proxyuser:${secret}`, 'utf8').toString('base64'), ...pieces])];
  for (const s of secrets) {
    assert.ok(!result.error.includes(s), `the returned error carries ${JSON.stringify(s)}: ${result.error}`);
    assert.ok(!stderr.includes(s), `the sender's stderr carries ${JSON.stringify(s)}`);
  }
}

test('(p1, first) under NODE_USE_ENV_PROXY the webhook really goes THROUGH the proxy, by NAME — the pin governs only that hop', async () => {
  const { seen, result } = await viaProxy('https');
  assert.deepEqual(seen, [{ method: 'CONNECT', url: 'rebind.test:8443' }], 'the proxy was not asked — this run says nothing about the proxy path');
  assert.equal(result.success, false);
});

test('(p2) a failed tunnel\'s error carries NO proxy credential — redacted before it can reach stderr or a drift file', async (t) => {
  const run = await viaProxy('https');
  assert.equal(run.seen.length, 1, 'positive control: the request reached the proxy');
  assertTunnelErrorCarriesNoCredential(t, run, 'PROXYSECRET');
});

test('(p2b) a password carrying a RAW @ — which Node accepts and still routes through — is redacted WHOLE', async (t) => {
  // The background security review of the first cut (44c4586): a first-@ rule left "XYSECRET" of "PRO@XYSECRET" in the error.
  const run = await viaProxy('https', 'PRO@XYSECRET');
  assert.equal(run.seen.length, 1, 'positive control: Node took the raw-@ proxy URL and the request reached the proxy');
  assertTunnelErrorCarriesNoCredential(t, run, 'PRO@XYSECRET', ['XYSECRET', 'PRO']);
});

test('(p2c) a password carrying a RAW SPACE — which Node also accepts — is redacted whole, through the variable Node read', async (t) => {
  // Measured 2026-10-11 while answering the second background review: no URL-shaped pattern can bound a userinfo with a
  // space in it, and the first two cuts returned this error UNREDACTED.
  const run = await viaProxy('https', 'PRO XYSECRET');
  assert.equal(run.seen.length, 1, 'positive control: Node took the raw-space proxy URL and the request reached the proxy');
  assertTunnelErrorCarriesNoCredential(t, run, 'PRO XYSECRET', ['XYSECRET', 'PRO ']);
});

test('(p2d) sendWebhook REDACTS a credential-bearing tunnel error ITSELF, on every Node version — the transport is stubbed to hand it one', async (t) => {
  // On v24.22.1 the runtime strips the userinfo before sendWebhook sees the error (CVE-2026-48615), so (p2)-(p2c) no longer
  // reach sendWebhook's own redaction call: with that call removed they stay green there, and go red only on v24.16.0
  // or older. This leg feeds the call a credential-bearing error on any runtime, so removing it fails here.
  for (const secret of ['PROXYSECRET', 'PRO@XYSECRET', 'PRO XYSECRET']) {
    const run = await viaProxy('https', secret, { stubTunnelError: true });
    // POSITIVE CONTROL: the stub ran, and the error it emitted CARRIED the credential raw — otherwise the vetoes below
    // would be satisfied by an error that never had anything to leak.
    assert.equal(run.stubCalls, 1, `${JSON.stringify(secret)}: the stubbed https.request ran ${run.stubCalls} times — this leg measured nothing`);
    assert.ok(run.emitted?.includes(`proxyuser:${secret}@127.0.0.1:${run.port}`),
      `${JSON.stringify(secret)}: the stubbed error did not carry the credential: ${run.emitted}`);
    assert.equal(run.result.success, false);
    assert.ok(run.result.error.includes(`via http://<credentials>@127.0.0.1:${run.port}: `),
      `${JSON.stringify(secret)}: sendWebhook did not redact the stubbed error: ${run.result.error}`);
    const leaks = [...new Set([secret, encodeURIComponent(secret), 'proxyuser', Buffer.from(`proxyuser:${secret}`, 'utf8').toString('base64'),
      ...secret.split(/[@ ]/).filter((x) => x.length > 2)])];
    for (const s of leaks) {
      assert.ok(!run.result.error.includes(s), `${JSON.stringify(secret)}: the returned error carries ${JSON.stringify(s)}: ${run.result.error}`);
      assert.ok(!run.stderr.includes(s), `${JSON.stringify(secret)}: the sender's stderr carries ${JSON.stringify(s)}`);
    }
    t.diagnostic(`${JSON.stringify(secret)}: stubbed tunnel error redacted by sendWebhook — ${run.result.error}`);
  }
});

test('(p3) redactUrlCredentials replaces userinfo in any URL and leaves a URL without one untouched', () => {
  const env = { HTTPS_PROXY: 'http://u:pa ss@h:1' };
  assert.equal(redactUrlCredentials('via http://u:pa ss@h:1 ok', env), 'via http://<credentials>@h:1 ok', 'a raw space, removed through the variable');
  assert.equal(redactUrlCredentials('via http://u:pa%20ss@h:1 ok', { HTTPS_PROXY: 'http://u:pa%20ss@h:1' }), 'via http://<credentials>@h:1 ok');
  assert.equal(redactUrlCredentials('via http://u:p@ss@h:1 ok', {}), 'via http://<credentials>@h:1 ok', 'a raw @ inside the password');
  assert.equal(redactUrlCredentials('via http://u:p@h:1 and https://x@y/z', {}), 'via http://<credentials>@h:1 and https://<credentials>@y/z');
  assert.equal(redactUrlCredentials('connect ECONNREFUSED 203.0.113.10:443', {}), 'connect ECONNREFUSED 203.0.113.10:443');
  assert.equal(redactUrlCredentials('see https://hooks.example/a@b', {}), 'see https://hooks.example/a@b', 'an @ in the PATH is not userinfo');
});
