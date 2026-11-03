import './helpers/no_operator_dotenv.mjs';
import './helpers/no_operator_keychain.mjs';   // FIRST: this file imports cli.mjs
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { newRunId, writeRunStart } from '../utils/run_record.mjs';

// B111 (EE board; the Community half, 2.1.2) — THE AI TXT REPORT CARRIES NO OPERATOR-LOCAL PATH.
// Every scan_response_ai.txt opened with `Payload path: /Users/…` and `Response path: /Users/…` (6 of 6 runs in the
// 2026-10-27 demo smoke; the HTML carried none). The TXT is a shareable artifact, so the header now names both files
// RELATIVE TO THE TXT'S OWN DIRECTORY — all four AI files are written into one output directory, so the name is the file
// name. FOURTH QUADRANT FIRST: the header still names both files, and each name resolves beside the TXT.
// Driven over the wire: the real SDK, a stand-in Ollama on loopback, the real stage writing the real TXT.

// Any absolute path, not only the one this file planted (the B106 review: a needle list passes a path it did not plant).
const ABSOLUTE_PATH = /(^|[\s'"(:=])\/(?:Users|home|private|var|tmp|opt|etc|Volumes|usr|root|srv|mnt|app|data|workspace)\//;

const absent = () => { throw Object.assign(new Error('not installed'), { code: 'MODULE_NOT_FOUND' }); };
const SAVED = {};
const ENV = { AI_ENABLED: 'true', AI_PROVIDER: 'ollama', OLLAMA_MODEL: 'standin', OPENAI_REDACT: undefined, CONFIDENTIAL_KEYWORDS: undefined,
  NSAUDITOR_LICENSE_KEY: 'not-a-licence', OPENAI_OUT_PATH: undefined, NSA_AI_TIMEOUT_MS: '20000' };
let server; let scanSingleHost;
before(async () => {
  server = http.createServer((req, res) => {
    let body = '';
    req.on('data', (c) => { body += c; });
    req.on('end', () => {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ id: 'chatcmpl-standin', object: 'chat.completion', created: 0, model: 'standin',
        choices: [{ index: 0, message: { role: 'assistant', content: 'stand-in assessment' }, finish_reason: 'stop' }],
        usage: { prompt_tokens: Math.ceil(body.length / 4), completion_tokens: 3, total_tokens: Math.ceil(body.length / 4) + 3 } }));
    });
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  for (const k of [...Object.keys(ENV), 'OLLAMA_BASE_URL', 'SCAN_OUT_PATH']) SAVED[k] = process.env[k];
  for (const [k, v] of Object.entries(ENV)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
  process.env.OLLAMA_BASE_URL = `http://127.0.0.1:${server.address().port}/v1`;
  // realpath: on macOS os.tmpdir() is a symlink, and the TXT must carry neither spelling.
  process.env.SCAN_OUT_PATH = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-ai-txt-path-')));
  ({ scanSingleHost } = await import('../cli.mjs'));
});
after(async () => {
  await new Promise((r) => server.close(r));
  fs.rmSync(process.env.SCAN_OUT_PATH, { recursive: true, force: true });
  for (const [k, v] of Object.entries(SAVED)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
});
const pm = () => ({ run: async () => ({ results: [], manifest: [],
  conclusion: { result: { summary: 'Host is UP', host: {}, services: [{ port: 443, banner: 'nginx' }], evidence: [] } } }) });

async function scanTxt(host) {
  const runId = newRunId();
  await writeRunStart(process.env.SCAN_OUT_PATH, { runId, startedAt: new Date().toISOString(), hostsRequested: [host] });
  await scanSingleHost(pm(), host, 'all', { resolveEE: absent, runId }, 'basic');
  const d = fs.readdirSync(process.env.SCAN_OUT_PATH).filter((x) => x.startsWith(host.replace(/\./g, '_')) || x.includes(host));
  assert.equal(d.length, 1, `one run directory for ${host}: ${d.join(', ')}`);
  const dir = path.join(process.env.SCAN_OUT_PATH, d[0]);
  return { dir, txt: fs.readFileSync(path.join(dir, 'scan_response_ai.txt'), 'utf8') };
}

test('(fourth quadrant) the header still names the payload and the response, and each name resolves beside the TXT', async () => {
  const { dir, txt } = await scanTxt('203.0.113.141');
  const payload = /^Payload path: (.+)$/m.exec(txt)?.[1];
  const response = /^Response path: (.+)$/m.exec(txt)?.[1];
  assert.ok(payload && response, `the header lost a line:\n${txt.slice(0, 400)}`);
  assert.equal(payload, 'scan_response_ai_payload.json');
  assert.equal(response, 'scan_response_ai.json');
  for (const name of [payload, response]) assert.ok(fs.existsSync(path.join(dir, name)), `${name} does not resolve beside the TXT`);
});

test('the TXT carries no absolute path: not the output directory, and no path of any kind', async () => {
  const { dir, txt } = await scanTxt('203.0.113.142');
  for (const needle of [process.env.SCAN_OUT_PATH, dir, os.tmpdir()]) assert.ok(!txt.includes(needle), `"${needle}" reached the TXT`);
  assert.doesNotMatch(txt, ABSOLUTE_PATH, `an absolute path reached the TXT:\n${txt.slice(0, 600)}`);
});
