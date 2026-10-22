// tests/mcp_response_persistence.test.mjs
// AN OPT-IN LOCAL COPY OF EACH MCP TOOL RESPONSE, SO `verify-call` WORKS WHEN THE CLIENT TRUNCATES.
//
// Every response carries a receipt: a call_id, logged with a digest of the body, that `nsauditor-ai mcp verify-call`
// checks against a saved copy. That needs the whole response, and Claude Desktop shows a long one truncated, in the app
// and in the browser view alike, while the server logs a digest, never the bytes. With NSA_MCP_RESPONSE_DIR set to an
// absolute directory, the server writes each response, exactly as returned, to `<call_id>.txt` there (directory 0700,
// file 0600, never over an existing file or through a planted link), and the footer says it did — only when it did.
//
// FOURTH QUADRANT FIRST: unset or blank, nothing is written and the response is the one it always was.
//
// Harness: HOME points at a scratch directory before the server loads (the call log path is computed at load), and
// every CLI spawn uses that HOME — the operator's receipt log is never written by this file.
import { withNoDotenv } from './helpers/no_operator_dotenv.mjs';
import './helpers/no_operator_home.mjs';
import { test, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { createServer, _setTier, _resetCloudScanCache, _persistResponse, MCP_RESPONSE_SAVED_LINE } from '../mcp_server.mjs';
import { RECEIPT_MARKER } from '../utils/mcp_call_digest.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const CLI = path.join(ROOT, 'cli.mjs');
const HOME = process.env.HOME;
let dir;
let stderr;
const realWrite = process.stderr.write.bind(process.stderr);

beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-resp-')); fs.rmSync(dir, { recursive: true }); // a path that does not exist yet
  stderr = [];
  process.stderr.write = (s, ...rest) => { stderr.push(String(s)); return true; };
  delete process.env.NSA_MCP_RESPONSE_DIR;
});
afterEach(() => {
  process.stderr.write = realWrite;
  delete process.env.NSA_MCP_RESPONSE_DIR;
  _setTier();
});

/** One real tool call through the server's own tools/call handler. */
async function call(name, args, tier) {
  _resetCloudScanCache(); _setTier(tier);
  const r = await createServer()._requestHandlers.get('tools/call')({ method: 'tools/call', params: { name, arguments: args } }, {});
  const text = r.content[0].text;
  const id = /call_id: ([0-9a-f-]{36})/.exec(text)?.[1];
  assert.ok(id, `the response carries a call_id: ${text.slice(-300)}`);
  return { text, id, isError: !!r.isError };
}
const NORMAL = ['get_findings', { provider: 'aws' }, 'enterprise'];              // a result (no cached scan)
const PRO_DENIAL = ['probe_service', { host: 'h', port: 1, pluginName: 'x' }, 'ce'];
const ENT_DENIAL = ['get_findings', { provider: 'aws' }, 'ce'];
const ERROR = ['probe_service', {}, 'pro'];                                       // the handler throws
const footerOf = (text) => text.slice(text.lastIndexOf(RECEIPT_MARKER));

test('(first) unset or blank: nothing is written, and the footer is the one it always was', async () => {
  for (const v of [undefined, '', '   ']) {
    if (v === undefined) delete process.env.NSA_MCP_RESPONSE_DIR; else process.env.NSA_MCP_RESPONSE_DIR = v;
    const { text, id } = await call(...NORMAL);
    assert.equal(footerOf(text), `${RECEIPT_MARKER}\ncall_id: ${id}\nTo check that this exact response came from this server, `
      + `save the whole response (footer included)\nto a file and run:\n  nsauditor-ai mcp verify-call ${id} --response <file>`);
    assert.equal(fs.existsSync(dir), false);
  }
  assert.deepEqual(stderr.filter((s) => /NSA_MCP_RESPONSE_DIR/.test(s)), [], 'off says nothing');
});

test('set: <call_id>.txt holds the response byte for byte, mode 0600, in a directory created 0700', async () => {
  process.env.NSA_MCP_RESPONSE_DIR = dir;
  const { text, id } = await call(...NORMAL);
  const file = path.join(dir, `${id}.txt`);
  assert.equal(fs.readFileSync(file, 'utf8'), text, 'the saved copy is exactly what the client received');
  assert.equal(fs.statSync(file).mode & 0o777, 0o600);
  assert.equal(fs.statSync(dir).mode & 0o777, 0o700);
  assert.ok(footerOf(text).includes(MCP_RESPONSE_SAVED_LINE(id)), 'the footer says it was saved');
  assert.doesNotMatch(text, new RegExp(dir.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')), 'and never names the path');
});

test('THE POINT: verify-call over the saved copy verifies, and a one-byte change to its body refutes', async () => {
  process.env.NSA_MCP_RESPONSE_DIR = dir;
  const { text, id } = await call(...NORMAL);
  const saved = path.join(dir, `${id}.txt`);
  const env = { ...process.env, HOME, XDG_CONFIG_HOME: path.join(HOME, '.config'),
    NSAUDITOR_LICENSE_KEY: 'not-a-licence', NSAUDITOR_LICENSE_STATE_FILE: path.join(HOME, 'licence-state.json'), NSA_VERBOSE: '' };
  const verify = (file) => spawnSync(process.execPath, [CLI, 'mcp', 'verify-call', id, '--response', file],
    { cwd: ROOT, env: withNoDotenv(env), encoding: 'utf8', timeout: 30000 });
  assert.equal(verify(saved).status, 0, 'the saved copy is the response the server returned');
  const at = text.indexOf('No cached scan');
  assert.ok(at > 0, 'the body has a word to change');
  const tampered = path.join(dir, 'tampered.txt');
  fs.writeFileSync(tampered, `${text.slice(0, at)}N0${text.slice(at + 2)}`);
  assert.equal(verify(tampered).status, 1);
});

test('a RELATIVE path is refused: no save, no footer line, one stderr line, and the call still answers', async () => {
  const rel = `nsa-relative-responses-${process.pid}`;   // a name no other run leaves behind
  process.env.NSA_MCP_RESPONSE_DIR = rel;
  try {
    const { text, id } = await call(...NORMAL);
    assert.ok(!text.includes(MCP_RESPONSE_SAVED_LINE(id)));
    assert.equal(stderr.filter((s) => /NSA_MCP_RESPONSE_DIR/.test(s)).length, 1);
    assert.equal(fs.existsSync(path.join(process.cwd(), rel)), false, 'nothing was created under the working directory');
  } finally {
    fs.rmSync(path.join(process.cwd(), rel), { recursive: true, force: true });
  }
});

test('a save that FAILS (the path is a regular file): no footer line, one stderr line, the call still answers', async () => {
  fs.writeFileSync(dir, 'not a directory');
  process.env.NSA_MCP_RESPONSE_DIR = dir;
  const { text, id } = await call(...NORMAL);
  assert.ok(!text.includes(MCP_RESPONSE_SAVED_LINE(id)), 'the line is present exactly when the file exists');
  assert.equal(stderr.filter((s) => /NSA_MCP_RESPONSE_DIR/.test(s)).length, 1);
  fs.rmSync(dir);
});

test('a SYMLINKED directory is the operator\'s choice and is used as is', async () => {
  const real = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-resp-real-'));
  fs.symlinkSync(real, dir);
  process.env.NSA_MCP_RESPONSE_DIR = dir;
  const { text, id } = await call(...NORMAL);
  assert.equal(fs.readFileSync(path.join(real, `${id}.txt`), 'utf8'), text);
  fs.unlinkSync(dir); fs.rmSync(real, { recursive: true });
});

test('never over an existing file, never through a planted link — refused, and neither is touched', () => {
  fs.mkdirSync(dir, { mode: 0o700 });
  const id = '11111111-2222-4333-8444-555555555555';
  fs.writeFileSync(path.join(dir, `${id}.txt`), 'already here');
  assert.equal(_persistResponse(dir, id, 'new text').saved, false);
  assert.equal(fs.readFileSync(path.join(dir, `${id}.txt`), 'utf8'), 'already here');
  const id2 = '66666666-7777-4888-9999-aaaaaaaaaaaa';
  const target = path.join(dir, 'target');
  fs.writeFileSync(target, 'untouched');
  fs.symlinkSync(target, path.join(dir, `${id2}.txt`));
  assert.equal(_persistResponse(dir, id2, 'new text').saved, false);
  assert.equal(fs.readFileSync(target, 'utf8'), 'untouched');
});

test('a write that fails after the file opened leaves NO partial file behind', () => {
  fs.mkdirSync(dir, { mode: 0o700 });
  const id = 'bbbbbbbb-cccc-4ddd-8eee-ffffffffffff';
  assert.equal(_persistResponse(dir, id, Symbol('not text')).saved, false);
  assert.equal(fs.existsSync(path.join(dir, `${id}.txt`)), false);
});

test('denials and an error response are saved too — each is a response an operator may need to verify', async () => {
  process.env.NSA_MCP_RESPONSE_DIR = dir;
  for (const [label, c] of [['Pro denial', PRO_DENIAL], ['Enterprise denial', ENT_DENIAL], ['error response', ERROR]]) {
    const { text, id, isError } = await call(...c);
    assert.ok(isError, `${label}: precondition — the call is an error response`);
    assert.equal(fs.readFileSync(path.join(dir, `${id}.txt`), 'utf8'), text, label);
  }
});
