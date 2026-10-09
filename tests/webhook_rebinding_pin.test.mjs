// tests/webhook_rebinding_pin.test.mjs
// ─────────────────────────────────────────────────────────────────────────────
// R1 FOR THE WEBHOOK SINK — sendWebhook connects to the address its SSRF check resolved (EE 2.0.0; the architect seat's
// F6: the drift notification added a new outbound sink on this guard, so the pin lands before 2.0.0 ships).
//
// DNS REBINDING, DRIVEN ON THE REAL PATHS. The check resolves through `node:dns/promises` (resolveAndValidate); a
// request that is not pinned resolves AGAIN at connect, through `node:dns`. Both are stubbed for one reserved name
// (`rebind.test`, RFC 6761 — it never reaches a real resolver): the check is answered with a PUBLIC address and the
// connect with LOOPBACK, where a receiver is listening. Unpinned, the request lands on loopback; pinned, it never does.
//
// The public answer is 203.0.113.10 (RFC 5737 documentation range — public to the guard, routed nowhere), so the
// pinned attempt fails on a short timeout; nothing else on the network sees it.
//
// FOURTH QUADRANT FIRST: the fixture CAN produce the defect — a request that resolves at connect reaches loopback.
// ─────────────────────────────────────────────────────────────────────────────
import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import dnsP from 'node:dns/promises';
import dnsCb from 'node:dns';
import { sendWebhook, resolveWebhookTarget, pinnedLookup } from '../utils/webhook.mjs';

const NAME = 'rebind.test';
const PUBLIC = '203.0.113.10';

async function receiver() {
  const got = [];
  const server = http.createServer((req, res) => { got.push({ url: req.url, host: req.headers.host }); res.writeHead(200); res.end(); });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  return { got, port: server.address().port, close: () => new Promise((r) => server.close(r)) };
}

/** The check's resolver answers PUBLIC for NAME, the connect's answers LOOPBACK; every other name is untouched. */
function rebinding() {
  const origP = dnsP.lookup;
  const origCb = dnsCb.lookup;
  const calls = { check: 0, connect: 0 };
  dnsP.lookup = async (host, opts) => {
    if (host !== NAME) return origP(host, opts);
    calls.check += 1;
    return opts?.all ? [{ address: PUBLIC, family: 4 }] : { address: PUBLIC, family: 4 };
  };
  dnsCb.lookup = (host, opts, cb) => {
    if (typeof opts === 'function') { cb = opts; opts = {}; }
    if (host !== NAME) return origCb(host, opts, cb);
    calls.connect += 1;
    return opts?.all ? cb(null, [{ address: '127.0.0.1', family: 4 }]) : cb(null, '127.0.0.1', 4);
  };
  return { calls, restore() { dnsP.lookup = origP; dnsCb.lookup = origCb; } };
}

test('(w1, first) the fixture CAN rebind: the check sees a public address, an unpinned request lands on loopback', async () => {
  const rx = await receiver();
  const dns = rebinding();
  try {
    const url = `http://${NAME}:${rx.port}/hook`;
    assert.deepEqual(await resolveWebhookTarget(url), { address: PUBLIC, family: 4 }, 'the check resolved the public answer');
    // The pre-pin shape: a request that resolves the name itself at connect.
    await new Promise((resolve, reject) => {
      const req = http.request({ hostname: NAME, port: rx.port, path: '/hook', method: 'POST' }, (res) => { res.resume(); res.on('end', resolve); });
      req.on('error', reject); req.end('{}');
    });
    assert.equal(rx.got.length, 1, 'positive control: an unpinned request reaches the loopback receiver');
    assert.ok(dns.calls.connect >= 1, 'the connect resolved through node:dns — the path the stub drives');
  } finally { dns.restore(); await rx.close(); }
});

test('(w2) sendWebhook is PINNED: the same rebinding never reaches loopback, and the name is never resolved again', async () => {
  const rx = await receiver();
  const dns = rebinding();
  try {
    const res = await sendWebhook(`http://${NAME}:${rx.port}/hook`, { a: 1 }, { timeout: 400, retries: 0, retryDelayMs: 0 });
    assert.equal(rx.got.length, 0, 'a rebinding answer reached the loopback receiver');
    assert.equal(dns.calls.check, 1, 'the check resolved the name once');
    assert.equal(dns.calls.connect, 0, 'the connect resolved the name again — the pin is gone');
    assert.equal(res.success, false, 'the documentation address answers nothing');
    assert.doesNotMatch(String(res.error), /ENOTFOUND|EAI_AGAIN/, `the connect went to a resolver, not to the pinned address: ${res.error}`);
  } finally { dns.restore(); await rx.close(); }
});

test('(w3) the pinned lookup answers BOTH shapes Node asks for with the checked address', () => {
  const look = pinnedLookup({ address: PUBLIC, family: 4 });
  let all; look(NAME, { all: true }, (e, a) => { all = a; });
  assert.deepEqual(all, [{ address: PUBLIC, family: 4 }], 'the autoSelectFamily shape');
  let one; look(NAME, { family: 0 }, (e, a, f) => { one = [a, f]; });
  assert.deepEqual(one, [PUBLIC, 4], 'the single-answer shape');
  let legacy; look(NAME, (e, a, f) => { legacy = [a, f]; });
  assert.deepEqual(legacy, [PUBLIC, 4], 'the two-argument call');
});
