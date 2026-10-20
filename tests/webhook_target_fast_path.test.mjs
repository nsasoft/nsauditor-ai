// tests/webhook_target_fast_path.test.mjs
// ─────────────────────────────────────────────────────────────────────────────
// THE WEBHOOK GUARD'S FAST PATH REFUSES BLOCKED IP LITERALS AND THE NAMES BLOCKED BY DEFINITION — NEVER A NAME THAT ONLY
// STARTS LIKE A PRIVATE ADDRESS.
//
// `resolveWebhookTarget` refused, with no lookup, any host whose NAME began `10.`, `0.`, `127.`, `192.168.`, `172.16–31.`,
// `169.254.` or `metadata.google` — so `10.example.com` or `metadata.googleapis.com` was a false refusal recorded as "URL
// rejected by SSRF guard", whatever it answered. The fast path now refuses an IP literal in a blocked range (the address
// classifier, in any spelling) and `localhost`, its subdomains and `metadata.google.internal`; every other name is
// resolved and its answers checked, as before. The MCP host check made the same move (board item (y)).
//
// DRIVEN: the real guard, names answered by a stubbed lookup on the object net_validation.mjs imports.
//
// FOURTH QUADRANT FIRST: a public literal and a public name still pass.
// ─────────────────────────────────────────────────────────────────────────────
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { resolveWebhookTarget } from '../utils/webhook.mjs';

async function withResolver(table, fn) {
  const dns = (await import('node:dns/promises')).default;
  const orig = dns.lookup;
  const calls = [];
  dns.lookup = async (name, opts) => {
    calls.push(name);
    const raw = table[name];
    if (raw === undefined) { const e = new Error(`getaddrinfo ENOTFOUND ${name}`); e.code = 'ENOTFOUND'; throw e; }
    const list = [].concat(raw).map((address) => ({ address, family: address.includes(':') ? 6 : 4 }));
    return opts && opts.all ? list : list[0];
  };
  try { return await fn(calls); } finally { dns.lookup = orig; }
}
const at = (host) => `https://${host}/hook`;

test('(first) a public literal and a public name pass', async () => {
  await withResolver({ '203.0.113.10': '203.0.113.10', 'hooks.example': '203.0.113.20' }, async () => {
    assert.equal((await resolveWebhookTarget(at('203.0.113.10')))?.address, '203.0.113.10');
    assert.equal((await resolveWebhookTarget(at('hooks.example')))?.address, '203.0.113.20');
  });
});

test('a NAME that only starts like a private address, answering public, passes — and was resolved', async () => {
  const PUBLIC = { '10.example.com': '203.0.113.30', '127.example.test': '203.0.113.31', '192.168.example.test': '203.0.113.32',
    '172.16.example.test': '203.0.113.33', '0.pool.ntp.org': '203.0.113.34', 'metadata.googleapis.com': '203.0.113.35' };
  await withResolver(PUBLIC, async (calls) => {
    for (const [h, a] of Object.entries(PUBLIC)) {
      assert.equal((await resolveWebhookTarget(at(h)))?.address, a, h);
      assert.ok(calls.includes(h), `${h} was refused without a lookup`);
    }
  });
});

test('the same names answering a private or loopback address are refused — by the check over the answer', async () => {
  await withResolver({ '10.example.com': '10.0.0.7', '127.example.test': '127.0.0.1' }, async () => {
    for (const h of ['10.example.com', '127.example.test']) assert.equal(await resolveWebhookTarget(at(h)), null, h);
  });
});

test('a blocked IP literal, in any spelling, and the names blocked by definition are refused with NO lookup', async () => {
  await withResolver({}, async (calls) => {
    for (const h of ['127.0.0.1', '10.0.0.1', '192.168.1.1', '172.16.0.1', '169.254.169.254', '0.0.0.0', '[::1]', '[fe80::1]',
      '[::ffff:7f00:1]', 'localhost', 'app.localhost', 'metadata.google.internal', 'localhost.', 'metadata.google.internal.']) {
      assert.equal(await resolveWebhookTarget(at(h)), null, h);
    }
    assert.deepEqual(calls, [], 'a blocked literal or a name blocked by definition is never resolved');
  });
});
