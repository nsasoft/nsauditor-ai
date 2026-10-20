// tests/webhook_own_agent.test.mjs
// ─────────────────────────────────────────────────────────────────────────────
// A WEBHOOK ALERT TRAVELS ON ITS OWN CONNECTION — NEVER ON ONE ANOTHER CALLER POOLED, AND NEVER LEFT FOR ONE TO REUSE.
//
// `sendWebhook` connects to the address its check resolved (a pinned lookup), but it requested through Node's default
// agent, which pools keep-alive sockets by host and port. So an idle socket another caller had opened to the webhook's
// host:port — by name, unpinned — could carry the alert, and the alert's own socket was left in the pool for any later
// request to that host:port. The README's pool limit described this for plugins; the webhook had the same exposure on a
// different connection. Now every send uses a dedicated agent with keep-alive off, configured like the default agent
// (its proxy settings included), so one POST is one connection and nothing is shared.
//
// DRIVEN: the real `sendWebhook` against a loopback server that counts the connections it accepts. The guard's checker
// is swapped through Community's own seam for loopback and restored.
//
// FOURTH QUADRANT FIRST: one alert is one connection, and it is delivered.
// ─────────────────────────────────────────────────────────────────────────────
import './helpers/no_operator_dotenv.mjs';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { sendWebhook, _setWebhookSafeChecker } from '../utils/webhook.mjs';

async function server() {
  let connections = 0;
  const bodies = [];
  const srv = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => { bodies.push(Buffer.concat(chunks).toString()); res.writeHead(200, { 'Content-Type': 'text/plain' }); res.end('ok'); });
  });
  srv.keepAliveTimeout = 10_000;   // the server would keep an idle socket open: reuse is the CLIENT's choice
  srv.on('connection', () => { connections += 1; });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const open = () => new Promise((r) => srv.getConnections((_e, n) => r(n)));
  return { url: `http://127.0.0.1:${srv.address().port}/hook`, port: srv.address().port, bodies, connections: () => connections, open,
    close: () => new Promise((r) => { srv.closeAllConnections?.(); srv.close(r); }) };
}
const send = (url, body = { a: 1 }) => sendWebhook(url, body, { timeout: 2000, retries: 0 });
/** A plain request through Node's DEFAULT agent — what any other caller (a plugin) does. */
const plainGet = (port) => new Promise((resolve, reject) => {
  http.get({ host: '127.0.0.1', port, path: '/other', agent: http.globalAgent }, (res) => { res.resume(); res.on('end', resolve); }).on('error', reject);
});
async function withLoopbackAllowed(fn) {
  _setWebhookSafeChecker(async () => true);
  try { return await fn(); } finally { _setWebhookSafeChecker(null); http.globalAgent.destroy(); }
}

test('(first) one alert is one connection, and it is delivered', async () => {
  const s = await server();
  try {
    await withLoopbackAllowed(async () => assert.equal((await send(s.url)).success, true));
    assert.deepEqual([s.connections(), s.bodies.length], [1, 1]);
  } finally { await s.close(); }
});
test('two alerts to one host:port open TWO connections — the first alert\'s socket is not pooled', async () => {
  const s = await server();
  try {
    await withLoopbackAllowed(async () => { await send(s.url); await send(s.url); });
    assert.equal(s.connections(), 2);
  } finally { await s.close(); }
});
test('an idle socket ANOTHER caller pooled to that host:port is never reused for the alert', async () => {
  const s = await server();
  try {
    await withLoopbackAllowed(async () => { await plainGet(s.port); await send(s.url); });
    assert.equal(s.connections(), 2);
  } finally { await s.close(); }
});
test('the alert\'s socket is never left for a later request to reuse', async () => {
  const s = await server();
  try {
    await withLoopbackAllowed(async () => { await send(s.url); await plainGet(s.port); });
    assert.equal(s.connections(), 2);
  } finally { await s.close(); }
});
test('the alert\'s connection is closed once it is delivered — nothing is left open', async () => {
  const s = await server();
  try {
    await withLoopbackAllowed(() => send(s.url));
    let open = await s.open();
    for (let i = 0; i < 20 && open > 0; i++) { await new Promise((r) => setTimeout(r, 25)); open = await s.open(); }
    assert.equal(open, 0);
  } finally { await s.close(); }
});
