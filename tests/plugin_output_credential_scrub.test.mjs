// tests/plugin_output_credential_scrub.test.mjs
// ─────────────────────────────────────────────────────────────────────────────
// A PLUGIN'S RETURN AND ITS THROW ARE SCRUBBED WHERE THE PLUGIN MANAGER RECEIVES THEM (EE 2.2.0, I3).
//
// A cloud SDK that runs a customer-configured child (credential_process, a pluggable-auth executable, `az`) carries the
// child's stderr into the Error it throws, and a plugin writes a caught error's text into its result. From the plugin
// manager that text reaches every artifact: the raw conclusion, the compliance output, the drift file, the MCP response,
// a GRC push and the AI prompt. So it is scrubbed ONCE, at the receipt, with Community's credentialRedactor.
//
// The walk: strings, plain objects (keys and values) and arrays, an Error's message, stack, cause and own enumerable
// fields. A result with nothing to redact is returned BY REFERENCE, so no finding's identity can move. Stated limit,
// pinned below: a string inside a Map, a Set, a Buffer, a Date or another class instance is not walked.
//
// FOURTH QUADRANT FIRST.
// ─────────────────────────────────────────────────────────────────────────────
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { types } from 'node:util';
import * as S from '../utils/plugin_output_scrub.mjs';

const scrubPluginOutput = (...a) => S.scrubPluginOutput(...a);
const scrubThrown = (...a) => S.scrubThrown(...a);
const CANARY = 'B164I3SECRETpw';
const ENV = { HTTPS_PROXY: `http://proxyuser:${CANARY}@127.0.0.1:9` };
const FOURTH_QUADRANT = ['user@example.com', 'scanner@my-project.iam.gserviceaccount.com',
  'arn:aws:iam::123456789012:role/Admin@Path', 'https://host/path@x', 's3://bucket/key@v'];
const count = (v) => JSON.stringify(v).split(CANARY).length - 1;

test('(w0) fourth quadrant: a result with nothing to redact comes back BY REFERENCE and byte-identical', () => {
  const result = {
    up: true,
    findings: FOURTH_QUADRANT.map((s, i) => ({ id: `F${i}`, title: `Principal ${s} has access`, resource: s, tags: [s] })),
    evidenceGaps: [{ reason: 'AccessDenied for arn:aws:iam::123456789012:role/Admin@Path' }],
    [FOURTH_QUADRANT[0]]: { nested: [[FOURTH_QUADRANT[3]]] },
  };
  const before = JSON.stringify(result);
  for (const env of [{}, ENV]) {
    const { value, replaced } = scrubPluginOutput(result, { env });
    assert.equal(value, result, 'the same reference');
    assert.equal(replaced, 0);
    assert.equal(JSON.stringify(value), before);
  }
  for (const v of [null, undefined, 0, true, 'plain', 'user@example.com']) assert.equal(scrubPluginOutput(v, { env: ENV }).value, v);
});

test('(w1) the canary is removed from every string a result carries — values, keys, arrays, an Error — and the input is untouched', () => {
  const err = new Error(`Command failed: helper\nstderr: ${CANARY}`);
  const result = {
    up: false,
    evidenceGaps: [{ reason: `CredentialsProviderError: Command failed: helper\n${CANARY}` }],
    findings: [{ title: 'kept', details: { raw: [`via http://proxyuser:${CANARY}@127.0.0.1:9`, 'user@example.com'] } }],
    [`k-${CANARY}`]: 1,
    error: err,
  };
  const before = JSON.stringify(result);
  assert.ok(count(result) >= 3, 'positive control: the canary is in the input');
  const { value, replaced } = scrubPluginOutput(result, { env: ENV });
  assert.equal(count(value), 0, 'no canary in the scrubbed JSON');
  assert.ok(!String(value.error.message).includes(CANARY) && !String(value.error.stack).includes(CANARY), 'the Error is scrubbed');
  assert.ok(value.error instanceof Error, 'an Error stays an Error');
  assert.equal(value.findings[0].details.raw[1], 'user@example.com', 'a fourth-quadrant string beside the canary is byte-identical');
  assert.equal(value.findings[0].title, 'kept');
  assert.equal(JSON.stringify(result), before, 'the plugin\'s own object is not mutated');
  assert.ok(err.message.includes(CANARY), 'the plugin\'s own Error is not mutated');
  assert.equal(replaced, 5);
});

test('(w2) cycles and shared references terminate and keep their shape', () => {
  const shared = { reason: `x ${CANARY}` };
  const r = { a: shared, b: shared, list: [] };
  r.self = r; r.list.push(r.list);
  const { value } = scrubPluginOutput(r, { env: ENV });
  assert.equal(value.self, value, 'the cycle points at the copy');
  assert.equal(value.a, value.b, 'a shared reference stays shared');
  assert.equal(value.list[0], value.list);
  assert.equal(value.a.reason, 'x <credentials>');
});

test('(w3) STATED LIMIT: a string inside a Map, Set, Buffer, Date or class instance is not walked (passed by reference)', () => {
  class Box { constructor() { this.s = CANARY; } }
  const box = new Box();
  const m = new Map([['k', CANARY]]);
  const { value } = scrubPluginOutput({ m, box, reason: CANARY }, { env: ENV });
  assert.equal(value.m, m);
  assert.equal(value.box, box);
  assert.equal(value.reason, '<credentials>');
});

test('(w4) a thrown value is scrubbed: same class, message and stack and cause redacted, the original untouched', () => {
  const cause = new Error(`inner ${CANARY}`);
  const thrown = new TypeError(`outer via http://proxyuser:${CANARY}@127.0.0.1:9`, { cause });
  thrown.code = `E_${CANARY}`;
  const got = scrubThrown(thrown, { env: ENV });
  assert.ok(got instanceof TypeError);
  assert.ok(types.isNativeError(got), 'a REAL Error (the internal slot), not an object with an Error prototype');
  assert.equal(got.message, 'outer via http://<credentials>@127.0.0.1:9');
  assert.ok(!got.stack.includes(CANARY));
  assert.ok(!got.cause.message.includes(CANARY));
  assert.equal(got.code, 'E_<credentials>');
  assert.ok(thrown.message.includes(CANARY) && thrown.cause.message.includes(CANARY));
  assert.equal(scrubThrown(`string ${CANARY}`, { env: ENV }), 'string <credentials>');
  const clean = new Error('nothing here');
  assert.equal(scrubThrown(clean, { env: ENV }), clean, 'nothing to redact: the same reference');
});

test('(w9) an own `__proto__` key (JSON.parse makes one from API data) stays a KEY in the copy, never the prototype', () => {
  const r = JSON.parse(`{"__proto__": {"tag": "kept"}, "reason": "x ${CANARY}"}`);
  assert.ok(Object.prototype.hasOwnProperty.call(r, '__proto__'), 'positive control: the input carries the own key');
  const { value } = scrubPluginOutput(r, { env: ENV });
  assert.equal(Object.getPrototypeOf(value), Object.prototype, 'the copy\'s prototype did not move');
  assert.ok(Object.prototype.hasOwnProperty.call(value, '__proto__'), 'the key survived as an own property');
  assert.equal(JSON.stringify(value), `{"__proto__":{"tag":"kept"},"reason":"x <credentials>"}`);
});

test('(w10) a redacted key never overwrites another key: originals keep their names, a collision takes #n', () => {
  const { value } = scrubPluginOutput({ [`a ${CANARY}`]: 1, 'a <credentials>': 2 }, { env: ENV });
  assert.deepEqual(value, { 'a <credentials>': 2, 'a <credentials>#2': 1 });
  const urls = scrubPluginOutput({ 'http://a:x@h': 1, 'http://b:y@h': 2 }, { env: {} }).value;
  assert.deepEqual(Object.values(urls).sort(), [1, 2], 'a URL-keyed map keeps every entry');
  assert.deepEqual(Object.keys(urls), ['http://<credentials>@h', 'http://<credentials>@h#2']);
});

test('(w11) an Error whose message lives on its PROTOTYPE keeps a message, scrubbed', () => {
  class E extends Error {}
  E.prototype.message = `default msg ${CANARY}`;
  const got = scrubThrown(new E(), { env: ENV });
  assert.ok(got instanceof E);
  assert.equal(got.message, 'default msg <credentials>');
});

test('(w12) a value the walk cannot read is WITHHELD as a named error, never thrown and never passed on unchecked', () => {
  const getter = { reason: 'ok', get boom() { throw new Error(`getter ${CANARY}`); } };
  let deep = { reason: `x ${CANARY}` }; for (let i = 0; i < 20000; i++) deep = { n: deep };
  for (const [label, v] of [['a throwing getter', getter], ['nesting 20000 deep', deep]]) {
    let got;
    assert.doesNotThrow(() => { got = scrubPluginOutput(v, { env: ENV }); }, label);
    assert.equal(got.withheld, true, label);
    assert.equal(got.value.up, false);
    assert.match(got.value.error, /could not be checked for proxy credentials and was withheld/);
    assert.ok(!JSON.stringify(got.value).includes(CANARY));
  }
  // an Error's own throwing getter is SKIPPED (reading it throws everywhere, so it reaches no artifact); the rest is kept
  const g = new Error(`outer ${CANARY}`); Object.defineProperty(g, 'detail', { get() { throw new Error('x'); }, enumerable: true });
  assert.equal(scrubThrown(g, { env: ENV }).message, 'outer <credentials>');
  // a throw the walk cannot finish is withheld as a named Error
  const e = scrubThrown(new Error('outer', { cause: deep }), { env: ENV });
  assert.ok(e instanceof Error);
  assert.match(e.message, /error could not be checked for proxy credentials and was withheld \(RangeError\)/);
});

// ── THROUGH THE PLUGIN MANAGER — every receipt point (callPlugin and _runOne), every path that reaches them ─────────
import { PluginManager } from '../plugin_manager.mjs';

const FQ_RESULT = () => ({ title: FOURTH_QUADRANT.join(' | ') });
/** Two stubs: one RETURNS the canary in an evidence gap (the fleet pattern: a caught SDK error's text), one THROWS it. */
function stubs(extra = {}) {
  return [
    { id: 'RET', name: 'Returns a caught error', ...extra, protocols: [], ports: [],
      async run() { return { up: false, data: [], evidenceGaps: [{ reason: `CredentialsProviderError: Command failed: helper\nstderr: ${CANARY}` }], findings: [FQ_RESULT()] }; } },
    { id: 'THR', name: 'Throws a provider error', ...extra, protocols: [], ports: [],
      async run() { throw new Error(`Command failed: helper\nFailed to parse: http://proxyuser:${CANARY}@[::1`); } },
  ];
}
async function withProxyEnv(fn) {
  const prev = process.env.HTTPS_PROXY;
  process.env.HTTPS_PROXY = ENV.HTTPS_PROXY;
  const lines = []; const orig = console.error;
  console.error = (...a) => { lines.push(a.map(String).join(' ')); };
  try { return { out: await fn(), stderr: lines.join('\n') }; }
  finally { console.error = orig; if (prev === undefined) delete process.env.HTTPS_PROXY; else process.env.HTTPS_PROXY = prev; }
}
function assertScrubbed(t, label, out, stderr) {
  const json = JSON.stringify(out);
  t.diagnostic(`${label}: canary in output ${json.split(CANARY).length - 1}, in stderr ${stderr.split(CANARY).length - 1}`);
  assert.equal(json.split(CANARY).length - 1, 0, `${label}: the canary reached the plugin manager's output`);
  assert.equal(stderr.split(CANARY).length - 1, 0, `${label}: the canary reached stderr`);
  assert.ok(json.includes(JSON.stringify(FQ_RESULT().title).slice(1, -1)), `${label}: the fourth-quadrant title is byte-identical`);
  assert.ok(json.includes('<credentials>'), `${label}: positive control — the stubs ran and their text arrived, redacted`);
}

test('(w5) callPlugin — the ORCHESTRATED run (CLI scan, MCP scan_host): a returned and a thrown canary arrive redacted', async (t) => {
  const pm = await PluginManager.create({ plugins: stubs({ priority: 50, runStrategy: 'single' }) });
  const { out, stderr } = await withProxyEnv(() => pm.run('127.0.0.1', 'all', {}));
  assertScrubbed(t, 'orchestrated', out, stderr);
});

test('(w6) _runOne — the LEGACY run: a returned and a thrown canary arrive redacted, and verror does not print it', async (t) => {
  const pm = await PluginManager.create({ plugins: stubs({ runStrategy: 'single' }) });
  const { out, stderr } = await withProxyEnv(() => pm.run('127.0.0.1', 'all', {}));
  assertScrubbed(t, 'legacy', out, stderr);
});

test('(w7) _runOne called DIRECTLY (MCP probe_service): both stubs arrive redacted', async (t) => {
  const pm = await PluginManager.create({ plugins: stubs({ runStrategy: 'single' }) });
  const { out, stderr } = await withProxyEnv(async () => [await pm._runOne(pm.plugins[0], '127.0.0.1', 443), await pm._runOne(pm.plugins[1], '127.0.0.1', 443)]);
  assertScrubbed(t, 'probe_service', out, stderr);
});

test('(w8) callPlugin via runCloud (MCP scan_cloud, CLI --host aws): both stubs arrive redacted', async (t) => {
  const pm = await PluginManager.create({ plugins: stubs({ cloudProvider: 'aws', runStrategy: 'single' }) });
  const { out, stderr } = await withProxyEnv(() => pm.runCloud(['aws'], {}));
  assert.equal(out.results.length, 2, `both cloud stubs ran — manifest ${JSON.stringify(out.manifest)}`);
  assertScrubbed(t, 'runCloud', out, stderr);
});

test('(w13) a result the walk cannot read does not abort the batch: the other plugin\'s result arrives', async () => {
  const plugins = [
    { id: 'BAD', name: 'Throwing getter', priority: 50, runStrategy: 'single', protocols: [], ports: [],
      async run() { return { up: true, data: [], get boom() { throw new Error('getter'); } }; } },
    { id: 'GOOD', name: 'Ordinary', priority: 50, runStrategy: 'single', protocols: [], ports: [],
      async run() { return { up: true, data: [], findings: [{ title: 'kept' }] }; } },
  ];
  const pm = await PluginManager.create({ plugins });
  const { out } = await withProxyEnv(() => pm.run('127.0.0.1', 'all', {}));
  const good = out.results.find((r) => r.id === 'GOOD');
  assert.equal(good?.result?.findings?.[0]?.title, 'kept', 'the ordinary plugin\'s result survived');
  const bad = out.results.find((r) => r.id === 'BAD');
  assert.match(String(bad?.result?.error), /withheld/, 'the unreadable result is a named failure');
});
