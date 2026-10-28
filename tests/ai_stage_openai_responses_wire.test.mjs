import './helpers/no_operator_dotenv.mjs';
import './helpers/no_operator_keychain.mjs';   // FIRST: this file imports cli.mjs
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';

// B87 (2.1.1) — THE OPENAI PATH OVER THE WIRE, pinned before the SDK moves from openai@4 to openai@7.
// The AI-stage tests drove the real SDK only through the Ollama path (chat.completions). The OpenAI path — Responses
// first, chat.completions as the fallback — had no wire test, and it is the path a major SDK upgrade is likeliest to
// change: the route, the base-URL environment variable, the retry count, the per-request timeout and abort signal, the
// response's `output_text`. Each leg below drives the REAL installed SDK through scanSingleHost against a local server
// standing in for the OpenAI API (OPENAI_BASE_URL). They describe what 2.1.0 does on openai@4 and must hold unchanged on
// openai@7.
// FOURTH QUADRANT FIRST: a working provider produces the assessment from the Responses API's output, in one request.

const absent = () => { throw Object.assign(new Error('not installed'), { code: 'MODULE_NOT_FOUND' }); };
const SAVED = {};
const ENV = { AI_ENABLED: 'true', AI_PROVIDER: 'openai', OPENAI_API_KEY: 'sk-test-standin-not-a-key', OPENAI_MODEL: 'standin-model',
  OPENAI_REDACT: undefined, CONFIDENTIAL_KEYWORDS: undefined, NSAUDITOR_LICENSE_KEY: 'not-a-licence', OPENAI_OUT_PATH: undefined,
  NSA_AI_TIMEOUT_MS: '20000' };
let server; let requests = []; let status = 200; let delayMs = 0; let scanSingleHost;
const TEXT = 'stand-in responses assessment';

before(async () => {
  server = http.createServer((req, res) => {
    let body = '';
    req.on('data', (c) => { body += c; });
    req.on('end', () => {
      requests.push({ method: req.method, url: req.url, body, auth: req.headers.authorization ?? null });
      setTimeout(() => {
        if (res.writableEnded || req.socket.destroyed) return;
        if (status !== 200) { res.writeHead(status, { 'content-type': 'application/json' }); res.end(JSON.stringify({ error: { message: 'stand-in failure', type: 'server_error' } })); return; }
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ id: 'resp_standin', object: 'response', created_at: 0, status: 'completed', model: 'standin-model',
          output: [{ type: 'message', id: 'msg_standin', status: 'completed', role: 'assistant',
            content: [{ type: 'output_text', text: TEXT, annotations: [] }] }] }));
      }, delayMs);
    });
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  for (const k of [...Object.keys(ENV), 'OPENAI_BASE_URL', 'SCAN_OUT_PATH']) SAVED[k] = process.env[k];
  for (const [k, v] of Object.entries(ENV)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
  process.env.OPENAI_BASE_URL = `http://127.0.0.1:${server.address().port}/v1`;
  process.env.SCAN_OUT_PATH = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-ai-openai-wire-'));
  ({ scanSingleHost } = await import('../cli.mjs'));
});
after(async () => {
  server.closeAllConnections?.();
  await new Promise((r) => server.close(r));
  for (const [k, v] of Object.entries(SAVED)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
});

const pm = () => ({
  run: async () => ({ results: [], manifest: [],
    conclusion: { result: { summary: 'Host is UP', host: {}, services: [{ port: 443, banner: 'nginx' }], evidence: [{ info: 'peer answered' }] } } }),
});
const runDir = (host) => {
  const d = fs.readdirSync(process.env.SCAN_OUT_PATH).filter((x) => x.startsWith(host.replace(/\./g, '_')) || x.includes(host));
  assert.equal(d.length, 1, `expected one run directory for ${host}, found ${d}`);
  return path.join(process.env.SCAN_OUT_PATH, d[0]);
};

test('(first) the OpenAI path: ONE request to /v1/responses with the model and the system+user input; the assessment is the output text', async () => {
  requests = []; status = 200; delayMs = 0;
  const host = '203.0.113.120';
  await scanSingleHost(pm(), host, 'all', { resolveEE: absent }, 'basic');
  assert.equal(requests.length, 1, JSON.stringify(requests.map((r) => r.url)));
  const r = requests[0];
  assert.equal(r.method, 'POST');
  assert.equal(new URL(r.url, 'http://x').pathname, '/v1/responses', 'the Responses API is tried first');
  assert.equal(r.auth, `Bearer ${ENV.OPENAI_API_KEY}`);
  const body = JSON.parse(r.body);
  assert.equal(body.model, 'standin-model');
  assert.deepEqual(body.input.map((m) => m.role), ['system', 'user']);
  const dir = runDir(host);
  assert.equal(body.input[0].content, fs.readFileSync(path.join(dir, 'scan_response_ai_system_prompt.txt'), 'utf8'), 'the recorded system prompt is what was sent');
  assert.ok(fs.readFileSync(path.join(dir, 'scan_response_ai.txt'), 'utf8').includes(TEXT), 'the assessment is the Responses output text');
  assert.equal(fs.existsSync(path.join(dir, 'scan_response_ai_error.json')), false);
});

test('a 5xx is NOT retried (maxRetries 0): one request, and the failure is recorded', async () => {
  requests = []; status = 500; delayMs = 0;
  const host = '203.0.113.121';
  await scanSingleHost(pm(), host, 'all', { resolveEE: absent }, 'basic');
  assert.equal(requests.length, 1, `retried: ${requests.length} requests`);
  assert.ok(fs.existsSync(path.join(runDir(host), 'scan_response_ai_error.json')));
});

test('the per-request timeout aborts a provider that does not answer: one request, the failure recorded, well before the provider would have answered', async () => {
  requests = []; status = 200; delayMs = 4000;
  process.env.NSA_AI_TIMEOUT_MS = '500';
  const host = '203.0.113.122';
  const t0 = Date.now();
  try {
    await scanSingleHost(pm(), host, 'all', { resolveEE: absent }, 'basic');
  } finally { process.env.NSA_AI_TIMEOUT_MS = ENV.NSA_AI_TIMEOUT_MS; }
  const elapsed = Date.now() - t0;
  assert.equal(requests.length, 1, `retried after the timeout: ${requests.length} requests`);
  assert.ok(elapsed < 3500, `the stage waited ${elapsed} ms — the timeout did not abort the request`);
  assert.ok(fs.existsSync(path.join(runDir(host), 'scan_response_ai_error.json')));
});
