import './helpers/no_operator_dotenv.mjs';
import './helpers/no_operator_keychain.mjs';   // FIRST: this file imports cli.mjs
// tests/ai_stage_fail_closed.test.mjs
// ─────────────────────────────────────────────────────────────────────────────
// A REDACTION THAT THROWS SENDS NOTHING — a claim about the STAGE, so it is driven through the stage (EE 2.0.0, the
// architect seat's ask when the retry and the external hook were deleted). The real scanSingleHost runs with a stand-in
// plugin manager, Enterprise held out, and a local server standing in for the provider; one evidence entry carries a
// getter that throws on a key only the redactor's walk reads (`findSerial` reads `banner` and `info`, so a getter there
// would throw BEFORE the redactor and prove nothing about it).
//
// THE EXIT SEMANTICS, stated rather than changed: the throw rejects scanSingleHost — the host's scan fails, as it did
// before 2.0.0 when the retry threw the same error a second time. A clean "AI stage skipped" record instead would be a UX
// change, and it is not made here.
// FOURTH QUADRANT FIRST: without the throwing getter the provider IS called and the payload IS written, or the zero below
// measures a stage that would never have sent anything.
// ─────────────────────────────────────────────────────────────────────────────
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';

const absent = () => { throw Object.assign(new Error('not installed'), { code: 'MODULE_NOT_FOUND' }); };
const SAVED = {};
const ENV = { AI_ENABLED: 'true', AI_PROVIDER: 'ollama', OPENAI_REDACT: undefined, CONFIDENTIAL_KEYWORDS: undefined,
  NSAUDITOR_LICENSE_KEY: 'not-a-licence', OPENAI_OUT_PATH: undefined, NSA_AI_TIMEOUT_MS: '20000' };
let server; let requests = []; let scanSingleHost;

before(async () => {
  server = http.createServer((req, res) => {
    let body = '';
    req.on('data', (c) => { body += c; });
    req.on('end', () => {
      requests.push({ method: req.method, url: req.url, bytes: body.length });
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ id: 'stand-in', object: 'chat.completion', created: 0, model: 'stand-in',
        choices: [{ index: 0, message: { role: 'assistant', content: 'stand-in assessment' }, finish_reason: 'stop' }] }));
    });
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  for (const k of [...Object.keys(ENV), 'OLLAMA_BASE_URL', 'SCAN_OUT_PATH']) SAVED[k] = process.env[k];
  for (const [k, v] of Object.entries(ENV)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
  process.env.OLLAMA_BASE_URL = `http://127.0.0.1:${server.address().port}/v1`;
  process.env.SCAN_OUT_PATH = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-ai-fail-closed-'));
  ({ scanSingleHost } = await import('../cli.mjs'));
});
after(async () => {
  await new Promise((r) => server.close(r));
  for (const [k, v] of Object.entries(SAVED)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
});

/** A plugin manager whose run returns a fixed conclusion carrying `evidence`. */
const pmWith = (evidence) => ({
  run: async () => ({ results: [], conclusion: { result: { summary: 'Host is UP', host: {}, services: [], evidence } }, manifest: [] }),
});
/** Every scan_response_ai_payload.json under the scratch output root for `host`. */
const payloadFiles = (host) => fs.readdirSync(process.env.SCAN_OUT_PATH).filter((d) => d.startsWith(host.replace(/\./g, '_')) || d.includes(host))
  .map((d) => path.join(process.env.SCAN_OUT_PATH, d, 'scan_response_ai_payload.json')).filter((f) => fs.existsSync(f));

test('(first) POSITIVE CONTROL — without the throwing getter the stage writes the payload and calls the provider', async () => {
  requests = [];
  const host = '203.0.113.96';
  await scanSingleHost(pmWith([{ info: 'peer answered', detail: 'plain' }]), host, 'all', { resolveEE: absent }, 'basic');
  assert.ok(requests.some((r) => r.method === 'POST' && /chat\/completions/.test(r.url)),
    `the stand-in provider was never called — this fixture cannot show a send being withheld: ${JSON.stringify(requests)}`);
  assert.equal(payloadFiles(host).length, 1, 'the payload file was written');
});

test('a redactor throw REJECTS the host\'s scan (the exit semantics) — no payload file is written and the provider is never called', async () => {
  requests = [];
  const host = '203.0.113.97';
  const ev = { info: 'peer answered', get detail() { throw new Error('getter: the redactor walked this entry'); } };
  const err = await scanSingleHost(pmWith([ev]), host, 'all', { resolveEE: absent }, 'basic').then(() => null, (e) => e);
  assert.ok(err, 'the scan resolved — a redaction failure must not let the stage go on');
  assert.match(String(err.message), /getter: the redactor walked this entry/);
  assert.match(String(err.stack), /buildAIPayload/, `the throw came from somewhere other than the payload pipeline:\n${err.stack}`);
  assert.deepEqual(requests, [], 'the provider was called');
  assert.deepEqual(payloadFiles(host), [], 'a payload file was written');
});
