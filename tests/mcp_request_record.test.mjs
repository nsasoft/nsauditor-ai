// tests/mcp_request_record.test.mjs
// THE SAVED RESPONSE GETS ITS REQUEST BESIDE IT, AND verify-call CAN CHECK BOTH.
//
// With NSA_MCP_RESPONSE_DIR set, the server saves each response as <call_id>.txt so verify-call works when the client
// truncates. A response is only half a record: a client may show no request at all for a call (Claude Desktop 3.x shows
// none for scan_cloud), and no log holds the arguments. So the server also saves <call_id>.request.json — the call's
// tool and arguments, verbatim — and logs a digest of that file's bytes, read back after the write, beside the response
// digest. `verify-call <id> --response <file> --request <file>` checks both. Both files or neither: the footer names
// both only when both exist. The digest line does not follow that rule: the response digest is logged either way.
//
// Exit codes (unchanged): 0 verified · 1 refuted · 2 usage or an unreadable file · 3 indeterminate. A request with no
// recorded digest is "not bound" (3), never refuted.
//
// FOURTH QUADRANT FIRST: unset, nothing new is written, and a request cannot be bound.
//
// Harness: HOME points at a scratch directory before the server loads (the call log path is computed at load); every
// CLI spawn uses that HOME — the operator's receipt log is never written by this file.
import { withNoDotenv } from './helpers/no_operator_dotenv.mjs';
import './helpers/no_operator_home.mjs';
import { test, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import {
  createServer, _setTier, _resetCloudScanCache, _setPluginManager, _persistCall, _setRequestBytesSeam,
  MCP_RESPONSE_SAVED_LINE,
} from '../mcp_server.mjs';
import { requestDigest } from '../utils/mcp_call_digest.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const CLI = path.join(ROOT, 'cli.mjs');
const HOME = process.env.HOME;
const LOG = path.join(HOME, '.nsauditor', 'mcp-calls.log');
let dir;
const realWrite = process.stderr.write.bind(process.stderr);

beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-req-')); fs.rmSync(dir, { recursive: true });
  process.stderr.write = () => true;
  delete process.env.NSA_MCP_RESPONSE_DIR;
});
afterEach(() => {
  process.stderr.write = realWrite;
  delete process.env.NSA_MCP_RESPONSE_DIR;
  _setRequestBytesSeam(null); _setPluginManager(null); _setTier();
});

/** A scan_cloud call through the server's own tools/call handler, over a mock plugin manager. */
const cloudPM = () => ({
  plugins: [{ id: '1040', name: 'ct', cloudProvider: 'aws' }],
  runCloud: async () => ({ host: 'cloud:aws', results: [{ id: '1040', result: { findings: [] } }], conclusion: null,
    manifest: [{ id: '1040', name: 'ct', status: 'ran' }],
    providerStatus: { aws: { available: 1, ran: 1, skipped: 0, errored: 0 } }, auditedProviders: ['aws'] }),
});
const ARGS = { providers: ['aws'], regions: ['af-south-1'] };
async function call(name, args, tier) {
  _resetCloudScanCache(); _setTier(tier);
  if (name === 'scan_cloud') _setPluginManager(cloudPM());
  const r = await createServer()._requestHandlers.get('tools/call')({ method: 'tools/call', params: { name, arguments: args } }, {});
  const text = r.content[0].text;
  const id = /call_id: ([0-9a-f-]{36})/.exec(text)?.[1];
  assert.ok(id, 'the response carries a call_id');
  return { text, id };
}
const logged = (id) => fs.readFileSync(LOG, 'utf8').split('\n').filter((l) => l.includes(`"call_id":"${id}"`))
  .map((l) => JSON.parse(l)).find((e) => 'digest' in e);
function verify(args) {
  const env = { ...process.env, HOME, XDG_CONFIG_HOME: path.join(HOME, '.config'),
    NSAUDITOR_LICENSE_KEY: 'not-a-licence', NSAUDITOR_LICENSE_STATE_FILE: path.join(HOME, 'licence-state.json'), NSA_VERBOSE: '' };
  const r = spawnSync(process.execPath, [CLI, 'mcp', 'verify-call', ...args], { cwd: ROOT, env: withNoDotenv(env), encoding: 'utf8', timeout: 30000 });
  return { status: r.status, out: `${r.stdout}${r.stderr}` };
}
const scratch = (name, text) => { const p = path.join(HOME, name); fs.writeFileSync(p, text); return p; };

test('(first) unset: no request file, no request digest, and a request cannot be bound — "not bound", exit 3, never refuted', async () => {
  const { text, id } = await call('scan_cloud', ARGS, 'enterprise');
  assert.equal(fs.existsSync(dir), false);
  const line = logged(id);
  assert.ok(line.digest, 'the response digest is logged as before');
  assert.equal('request_digest' in line, false);
  const resp = scratch(`${id}.resp.txt`, text);
  const req = scratch(`${id}.req.json`, JSON.stringify({ call_id: id, tool: 'scan_cloud', arguments: ARGS }, null, 2) + '\n');
  const v = verify([id, '--response', resp, '--request', req]);
  assert.equal(v.status, 3, v.out);
  assert.match(v.out, /✓ This response text was produced/);
  assert.match(v.out, /not bound/);
  assert.doesNotMatch(v.out, /✗/);
});

test('(first) --response alone is unchanged: the output names no request', async () => {
  process.env.NSA_MCP_RESPONSE_DIR = dir;
  const { id } = await call('scan_cloud', ARGS, 'enterprise');
  const v = verify([id, '--response', path.join(dir, `${id}.txt`)]);
  assert.equal(v.status, 0, v.out);
  assert.doesNotMatch(v.out, /request/i);
});

test('set: the request file holds the call\'s tool and arguments VERBATIM, mode 0600, and the footer names both files', async () => {
  process.env.NSA_MCP_RESPONSE_DIR = dir;
  const { text, id } = await call('scan_cloud', ARGS, 'enterprise');
  const file = path.join(dir, `${id}.request.json`);
  assert.deepEqual(JSON.parse(fs.readFileSync(file, 'utf8')), { call_id: id, tool: 'scan_cloud', arguments: ARGS });
  assert.equal(fs.statSync(file).mode & 0o777, 0o600);
  assert.equal(fs.readFileSync(path.join(dir, `${id}.txt`), 'utf8'), text);
  assert.ok(text.includes(MCP_RESPONSE_SAVED_LINE(id)));
  assert.match(MCP_RESPONSE_SAVED_LINE(id), new RegExp(`${id}\\.txt, and its request as ${id}\\.request\\.json`));
});

test('THE POINT: verify-call checks both — ✓ exit 0; one byte changed in the request refutes, exit 1', async () => {
  process.env.NSA_MCP_RESPONSE_DIR = dir;
  const { id } = await call('scan_cloud', ARGS, 'enterprise');
  const resp = path.join(dir, `${id}.txt`);
  const req = path.join(dir, `${id}.request.json`);
  const ok = verify([id, '--response', resp, '--request', req]);
  assert.equal(ok.status, 0, ok.out);
  assert.match(ok.out, /✓ This request is the one the server recorded for that call/);
  const bad = scratch('tampered.request.json', fs.readFileSync(req, 'utf8').replace('af-south-1', 'af-south-2'));
  const v = verify([id, '--response', resp, '--request', bad]);
  assert.equal(v.status, 1, v.out);
  assert.match(v.out, /✗ The request does not match/);
});

test('the digest is over the FILE as written, never the text meant to be written', async () => {
  process.env.NSA_MCP_RESPONSE_DIR = dir;
  _setRequestBytesSeam((t) => t.replace('af-south-1', 'af-south-9'));   // the write seam changes one byte
  const { id } = await call('scan_cloud', ARGS, 'enterprise');
  const req = path.join(dir, `${id}.request.json`);
  assert.match(fs.readFileSync(req, 'utf8'), /af-south-9/, 'precondition: the seam reached the file');
  assert.equal(logged(id).request_digest, requestDigest(fs.readFileSync(req)));
  assert.equal(verify([id, '--response', path.join(dir, `${id}.txt`), '--request', req]).status, 0);
  const intended = scratch('intended.request.json', JSON.stringify({ call_id: id, tool: 'scan_cloud', arguments: ARGS }, null, 2) + '\n');
  assert.equal(verify([id, '--response', path.join(dir, `${id}.txt`), '--request', intended]).status, 1);
});

test('both files or neither: a request file already at that name leaves no response file and no footer line', () => {
  fs.mkdirSync(dir, { mode: 0o700 });
  const id = '11111111-2222-4333-8444-555555555555';
  fs.writeFileSync(path.join(dir, `${id}.request.json`), 'already here');
  assert.equal(_persistCall(dir, id, 'response text', '{}\n').saved, false);
  assert.equal(fs.existsSync(path.join(dir, `${id}.txt`)), false);
  assert.equal(fs.readFileSync(path.join(dir, `${id}.request.json`), 'utf8'), 'already here', 'the planted file is untouched');
});

test('both files or neither: a response that cannot be written takes its request file with it', () => {
  fs.mkdirSync(dir, { mode: 0o700 });
  const id = '22222222-3333-4444-8555-666666666666';
  fs.writeFileSync(path.join(dir, `${id}.txt`), 'already here');
  assert.equal(_persistCall(dir, id, 'response text', '{}\n').saved, false);
  assert.equal(fs.existsSync(path.join(dir, `${id}.request.json`)), false);
});

test('a request write that fails after the file opened leaves no partial file', () => {
  fs.mkdirSync(dir, { mode: 0o700 });
  const id = '33333333-4444-4555-8666-777777777777';
  assert.equal(_persistCall(dir, id, 'response text', Symbol('not text')).saved, false);
  assert.equal(fs.existsSync(path.join(dir, `${id}.request.json`)), false);
  assert.equal(fs.existsSync(path.join(dir, `${id}.txt`)), false);
});

test('the footer rule is not the digest rule: when the save fails, the response digest is logged and no request digest is', async () => {
  fs.writeFileSync(dir, 'not a directory');
  process.env.NSA_MCP_RESPONSE_DIR = dir;
  const { text, id } = await call('scan_cloud', ARGS, 'enterprise');
  assert.ok(!text.includes(MCP_RESPONSE_SAVED_LINE(id)));
  const line = logged(id);
  assert.ok(line.digest);
  assert.equal('request_digest' in line, false);
  fs.rmSync(dir);
});

test('denials and an error response save and BIND their request too', async () => {
  process.env.NSA_MCP_RESPONSE_DIR = dir;
  for (const [label, name, args, tier] of [
    ['Pro denial', 'probe_service', { host: 'h', port: 1, pluginName: 'x' }, 'ce'],
    ['Enterprise denial', 'get_findings', { provider: 'aws' }, 'ce'],
    ['error response', 'probe_service', {}, 'pro'],
  ]) {
    const { id } = await call(name, args, tier);
    const req = path.join(dir, `${id}.request.json`);
    assert.deepEqual(JSON.parse(fs.readFileSync(req, 'utf8')), { call_id: id, tool: name, arguments: args }, label);
    const v = verify([id, '--response', path.join(dir, `${id}.txt`), '--request', req]);
    assert.equal(v.status, 0, `${label}: ${v.out}`);
  }
});

test('an unreadable --request is a usage failure, exit 2', async () => {
  process.env.NSA_MCP_RESPONSE_DIR = dir;
  const { id } = await call('scan_cloud', ARGS, 'enterprise');
  const v = verify([id, '--response', path.join(dir, `${id}.txt`), '--request', path.join(HOME, 'no-such-file.json')]);
  assert.equal(v.status, 2, v.out);
});

test('the verification guide quotes the saved-copy line exactly as the server writes it', () => {
  const flat = (t) => t.split('\n').map((l) => l.replace(/^\s*>?\s*/, '')).join(' ').replace(/\s+/g, ' ');
  const doc = flat(fs.readFileSync(path.join(ROOT, 'docs', 'mcp-verification.md'), 'utf8'));
  assert.ok(doc.includes(MCP_RESPONSE_SAVED_LINE('<call_id>')), 'docs/mcp-verification.md does not quote the footer line the server writes');
});
