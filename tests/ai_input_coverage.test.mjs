import './helpers/no_operator_dotenv.mjs';
import './helpers/no_operator_keychain.mjs';   // FIRST: this file imports cli.mjs
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';

import { aiInputCoverage, AI_INPUT_TRUNCATION_RATIO, aiSummaryLine } from '../utils/ai_stage.mjs';
import { newRunId, writeRunStart, readRunRecord } from '../utils/run_record.mjs';

// B113a (2.1.1) — AN ASSESSMENT OF PART OF THE SCAN MUST SAY SO.
// The B87 e2e (2026-10-28, EE tasks/release-2.1.1/b87-e2e-record.md) sent a ~63 KB payload to a local Ollama model. Ollama's
// default context window read 2,050 tokens of an input OpenAI counted at ~25,000, so the model assessed about a tenth of the
// scan, and nothing said so: not the assessment, not any artifact. After every response the stage now compares the
// provider's reported input tokens with the input's own size estimate (characters / 4). When the provider read less than
// AI_INPUT_TRUNCATION_RATIO of the estimate, the stage writes `nsauditorMeta.inputCoverage.inputTruncated: true`, with both
// numbers, beside the raw response in scan_response_ai.json, and ONE caveat line at the head of the TXT and the HTML. The
// run record mirrors it per host.
// FOURTH QUADRANT FIRST: a provider that reads the whole input writes NO caveat.

test('(fourth quadrant) the ratio, on the five real runs of the B87 e2e: the OpenAI runs are whole, the Ollama run is not', () => {
  // [run, reported input tokens, characters sent (system prompt + "Scan payload:\n" + payload)], read off the corpus.
  const REAL = [['N-basic', 25183, 79999, false], ['N-pro', 25989, 83798, false], ['N-optimized', 15650, 55802, false],
    ['A-ai-on', 11047, 39399, false], ['O-basic (Ollama, llama3.2)', 2050, 79965, true]];
  for (const [name, reported, chars, truncated] of REAL) {
    const cov = aiInputCoverage({ resp: { usage: { input_tokens: reported } }, promptText: 'x'.repeat(chars), userContent: '' });
    assert.equal(cov.inputTruncated, truncated, `${name}: ${reported} of ~${cov.estimatedInputTokens}`);
    assert.equal(cov.providerInputTokens, reported);
    assert.equal(cov.estimatedInputTokens, Math.ceil(chars / 4));
  }
  assert.ok(AI_INPUT_TRUNCATION_RATIO > 0.103 && AI_INPUT_TRUNCATION_RATIO < 1.122, 'the threshold sits in the measured gap');
});

test('both providers\' counters are read (Responses input_tokens, chat completions prompt_tokens); no usage is UNKNOWN, never "whole"', () => {
  const chat = aiInputCoverage({ resp: { usage: { prompt_tokens: 2050 } }, promptText: 'x'.repeat(80000), userContent: '' });
  assert.equal(chat.inputTruncated, true);
  assert.equal(aiInputCoverage({ resp: {}, promptText: 'x'.repeat(80000), userContent: '' }), null);
  assert.equal(aiInputCoverage({ resp: { usage: {} }, promptText: 'x', userContent: '' }), null);
});

test('the console summary line carries the caveat for a partial read, and only then', () => {
  const part = { providerInputTokens: 2050, estimatedInputTokens: 19992, inputTruncated: true };
  const whole = { providerInputTokens: 25183, estimatedInputTokens: 20000, inputTruncated: false };
  assert.equal(aiSummaryLine({ host: 'h', ai_status: 'ok', ai_input_coverage: whole }), 'AI conclusion: OK (h)');
  assert.equal(aiSummaryLine({ host: 'h', ai_status: 'ok' }), 'AI conclusion: OK (h)', 'no coverage: the line is unchanged');
  assert.match(aiSummaryLine({ host: 'h', ai_status: 'ok', ai_input_coverage: part }),
    /^AI conclusion: OK \(h\) — .*reading 2050 tokens of an input estimated at 19992; this assessment covers part of the scan\.$/);
});

// ── over the wire: the real SDK, a stand-in Ollama that reports a chosen prompt_tokens ──────────────────────────────────
const absent = () => { throw Object.assign(new Error('not installed'), { code: 'MODULE_NOT_FOUND' }); };
const SAVED = {};
const ENV = { AI_ENABLED: 'true', AI_PROVIDER: 'ollama', OLLAMA_MODEL: 'standin', OPENAI_REDACT: undefined, CONFIDENTIAL_KEYWORDS: undefined,
  NSAUDITOR_LICENSE_KEY: 'not-a-licence', OPENAI_OUT_PATH: undefined, NSA_AI_TIMEOUT_MS: '20000' };
// The stand-in reports either the honest count (ceil(sent / 4)) or a TENTH of it, the ratio O-basic measured (0.103).
// A fixed 2,050 does not work here: the basic payload this fixture builds is ~1,100 tokens, so 2,050 would read as whole.
let server; let reportTokens = 'honest'; let lastReported = null; let scanSingleHost;
before(async () => {
  server = http.createServer((req, res) => {
    let body = '';
    req.on('data', (c) => { body += c; });
    req.on('end', () => {
      const sent = JSON.parse(body).messages.reduce((n, m) => n + String(m.content).length, 0);
      const promptTokens = reportTokens === 'honest' ? Math.ceil(sent / 4) : Math.floor(Math.ceil(sent / 4) / 10);
      lastReported = promptTokens;
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ id: 'chatcmpl-standin', object: 'chat.completion', created: 0, model: 'standin',
        choices: [{ index: 0, message: { role: 'assistant', content: 'stand-in assessment' }, finish_reason: 'stop' }],
        usage: { prompt_tokens: promptTokens, completion_tokens: 3, total_tokens: promptTokens + 3 } }));
    });
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  for (const k of [...Object.keys(ENV), 'OLLAMA_BASE_URL', 'SCAN_OUT_PATH']) SAVED[k] = process.env[k];
  for (const [k, v] of Object.entries(ENV)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
  process.env.OLLAMA_BASE_URL = `http://127.0.0.1:${server.address().port}/v1`;
  process.env.SCAN_OUT_PATH = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-ai-coverage-'));
  ({ scanSingleHost } = await import('../cli.mjs'));
});
after(async () => {
  await new Promise((r) => server.close(r));
  fs.rmSync(process.env.SCAN_OUT_PATH, { recursive: true, force: true });
  for (const [k, v] of Object.entries(SAVED)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
});
const pm = () => ({ run: async () => ({ results: [], manifest: [],
  conclusion: { result: { summary: 'Host is UP', host: {}, services: [{ port: 443, banner: 'nginx' }], evidence: [{ info: 'x'.repeat(4000) }] } } }) });
const runDir = (host) => {
  const d = fs.readdirSync(process.env.SCAN_OUT_PATH).filter((x) => x.startsWith(host.replace(/\./g, '_')) || x.includes(host));
  assert.equal(d.length, 1);
  return path.join(process.env.SCAN_OUT_PATH, d[0]);
};
const CAVEAT = /the provider reports reading \d+ tokens of an input estimated at \d+; this assessment covers part of the scan/;
async function scan(host) {
  const runId = newRunId();
  await writeRunStart(process.env.SCAN_OUT_PATH, { runId, startedAt: new Date().toISOString(), hostsRequested: [host] });
  await scanSingleHost(pm(), host, 'all', { resolveEE: absent, runId }, 'basic');
  const dir = runDir(host);
  return { dir, record: await readRunRecord(process.env.SCAN_OUT_PATH, runId),
    json: JSON.parse(fs.readFileSync(path.join(dir, 'scan_response_ai.json'), 'utf8')),
    txt: fs.readFileSync(path.join(dir, 'scan_response_ai.txt'), 'utf8'),
    html: fs.readFileSync(path.join(dir, 'scan_response_ai.html'), 'utf8') };
}

test('(fourth quadrant) a provider that read the whole input: inputTruncated false, and NO caveat in the TXT or the HTML', async () => {
  reportTokens = 'honest';
  const r = await scan('203.0.113.130');
  const cov = r.json.nsauditorMeta?.inputCoverage;
  assert.equal(cov?.inputTruncated, false, JSON.stringify(r.json.nsauditorMeta));
  assert.equal(r.json.id, 'chatcmpl-standin', 'the raw response is kept beside the meta');
  assert.doesNotMatch(r.txt, CAVEAT);
  assert.doesNotMatch(r.html, CAVEAT);
});

test('a provider that read part of the input: inputTruncated with both numbers in the json, the caveat at the head of the TXT, in the HTML, and mirrored in the run record', async () => {
  reportTokens = 'tenth';
  const host = '203.0.113.131';
  const r = await scan(host);
  const cov = r.json.nsauditorMeta?.inputCoverage;
  assert.equal(cov?.inputTruncated, true);
  assert.equal(cov.providerInputTokens, lastReported, 'the number the provider reported, unchanged');
  assert.ok(cov.estimatedInputTokens > lastReported / AI_INPUT_TRUNCATION_RATIO, `estimate ${cov.estimatedInputTokens}`);
  assert.ok(r.txt.split('\n')[0].includes(`reading ${lastReported} tokens of an input estimated at ${cov.estimatedInputTokens}`), 'the caveat carries BOTH numbers');
  assert.match(r.txt.split('\n')[0], CAVEAT, 'the caveat is the FIRST line of the TXT');
  assert.match(r.html, CAVEAT, 'the caveat is in the HTML');
  assert.ok(r.html.indexOf('this assessment covers part of the scan') < r.html.indexOf('stand-in assessment'), 'it precedes the assessment');
  assert.deepEqual(r.record.aiInputCoverage?.[host], cov, 'the run record mirrors it for this host');
});
