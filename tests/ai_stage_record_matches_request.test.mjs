import './helpers/no_operator_dotenv.mjs';
import './helpers/no_operator_keychain.mjs';   // FIRST: this file imports cli.mjs
// tests/ai_stage_record_matches_request.test.mjs
// ─────────────────────────────────────────────────────────────────────────────
// THE TWO FILES ARE WHAT LEFT THE MACHINE (EE 2.0.0, marketing task #204 finding 2). On Pro and Enterprise the intelligence
// block travels in the SYSTEM PROMPT, which no file recorded, so the payload file alone was not the record docs/openai.md
// called it. The AI stage now writes scan_response_ai_system_prompt.txt beside scan_response_ai_payload.json, both before the
// request. Asserted on the ARTIFACTS against what a stand-in provider RECEIVED, byte for byte — never against the strings
// the code meant to send.
// The real scanSingleHost runs with a stand-in plugin manager, Enterprise held out (the block is set on the conclusion, as
// the Enterprise hook sets it), and a local server standing in for an OpenAI-compatible provider (AI_PROVIDER=ollama).
// STATED LIMIT: the OpenAI and Claude request shapes are not driven here; the files are written before the provider
// branch, so the record is the same text whichever provider then sends it.
// FOURTH QUADRANT FIRST: without a block the system prompt is the mode's own prompt, and still recorded.
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
let server; let bodies = []; let status = 200; let scanSingleHost;

before(async () => {
  server = http.createServer((req, res) => {
    let body = '';
    req.on('data', (c) => { body += c; });
    req.on('end', () => {
      bodies.push(body);
      res.writeHead(status, { 'content-type': 'application/json' });
      res.end(status === 200
        ? JSON.stringify({ id: 'stand-in', object: 'chat.completion', created: 0, model: 'stand-in',
          choices: [{ index: 0, message: { role: 'assistant', content: 'stand-in assessment' }, finish_reason: 'stop' }] })
        : JSON.stringify({ error: { message: 'stand-in failure' } }));
    });
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  for (const k of [...Object.keys(ENV), 'OLLAMA_BASE_URL', 'SCAN_OUT_PATH']) SAVED[k] = process.env[k];
  for (const [k, v] of Object.entries(ENV)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
  process.env.OLLAMA_BASE_URL = `http://127.0.0.1:${server.address().port}/v1`;
  process.env.SCAN_OUT_PATH = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-ai-record-'));
  ({ scanSingleHost } = await import('../cli.mjs'));
});
after(async () => {
  await new Promise((r) => server.close(r));
  for (const [k, v] of Object.entries(SAVED)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
});

const BLOCK = '## Intelligence Enrichment (NSAuditor AI Pro)\n\n**1 finding** across 1 service.\n- **Target:** [target-1]:443 (https)';
const pmWith = (eeEnrichment) => ({
  run: async () => ({ results: [], manifest: [],
    conclusion: { result: { summary: 'Host is UP', host: {}, services: [{ port: 443, banner: 'nginx' }], evidence: [{ info: 'peer answered' }],
      ...(eeEnrichment ? { eeEnrichment } : {}) } } }),
});
/** The run directory scanSingleHost created for `host`. */
const runDir = (host) => {
  const d = fs.readdirSync(process.env.SCAN_OUT_PATH).filter((x) => x.startsWith(host.replace(/\./g, '_')) || x.includes(host));
  assert.equal(d.length, 1, `expected one run directory for ${host}, found ${d}`);
  return path.join(process.env.SCAN_OUT_PATH, d[0]);
};
/** What the stand-in received: [system content, user content]. */
const received = () => {
  assert.equal(bodies.length, 1, `expected one request, got ${bodies.length}`);
  const m = JSON.parse(bodies[0]).messages;
  assert.deepEqual(m.map((x) => x.role), ['system', 'user']);
  return [m[0].content, m[1].content];
};

test('(first) WITHOUT a block: the system-prompt file is the mode prompt, byte for byte what the provider received', async () => {
  bodies = []; status = 200;
  const host = '203.0.113.110';
  await scanSingleHost(pmWith(null), host, 'all', { resolveEE: absent }, 'basic');
  const dir = runDir(host);
  const [system, user] = received();
  assert.equal(fs.readFileSync(path.join(dir, 'scan_response_ai_system_prompt.txt'), 'utf8'), system);
  assert.equal(`Scan payload:\n${fs.readFileSync(path.join(dir, 'scan_response_ai_payload.json'), 'utf8')}`, user);
  assert.doesNotMatch(system, /Intelligence Enrichment/);
});

test('WITH the intelligence block: it is IN the recorded system prompt, which equals what the provider received', async () => {
  bodies = []; status = 200;
  const host = '203.0.113.111';
  await scanSingleHost(pmWith({ enrichedPrompt: BLOCK }), host, 'all', { resolveEE: absent }, 'pro');
  const dir = runDir(host);
  const [system, user] = received();
  const recorded = fs.readFileSync(path.join(dir, 'scan_response_ai_system_prompt.txt'), 'utf8');
  assert.equal(recorded, system);
  assert.ok(recorded.startsWith(`${BLOCK}\n\n---\n\n`), 'the block leads the system prompt');
  assert.equal(`Scan payload:\n${fs.readFileSync(path.join(dir, 'scan_response_ai_payload.json'), 'utf8')}`, user);
  assert.ok(!fs.readFileSync(path.join(dir, 'scan_response_ai_payload.json'), 'utf8').includes('Intelligence Enrichment'),
    'the block is NOT in the payload — which is why the payload file alone was not the record');
});

test('a provider that FAILS still leaves both files: they are written before the request', async () => {
  bodies = []; status = 500;
  const host = '203.0.113.112';
  await scanSingleHost(pmWith({ enrichedPrompt: BLOCK }), host, 'all', { resolveEE: absent }, 'basic');
  const dir = runDir(host);
  assert.equal(bodies.length >= 1, true, 'the stand-in was asked');
  assert.ok(fs.existsSync(path.join(dir, 'scan_response_ai_error.json')), 'the failure is recorded');
  assert.equal(fs.readFileSync(path.join(dir, 'scan_response_ai_system_prompt.txt'), 'utf8'), JSON.parse(bodies[0]).messages[0].content);
  assert.ok(fs.existsSync(path.join(dir, 'scan_response_ai_payload.json')));
});

test('the docs name the system-prompt file where they name the payload file, and no longer say the block is unrecorded', () => {
  const doc = fs.readFileSync(new URL('../docs/openai.md', import.meta.url), 'utf8');
  const readme = fs.readFileSync(new URL('../README.md', import.meta.url), 'utf8');
  assert.doesNotMatch(doc, /`scan_response_ai_payload\.json` does not record it/);
  assert.match(doc, /\| `scan_response_ai_system_prompt\.txt` \| From Community 1\.0\.0: the system prompt sent with it/);
  assert.match(doc, /keep `scan_response_ai_payload\.json` and `scan_response_ai_system_prompt\.txt` with it/);
  assert.match(readme, /\| `scan_response_ai_system_prompt\.txt` \| System prompt sent to AI/);
});
