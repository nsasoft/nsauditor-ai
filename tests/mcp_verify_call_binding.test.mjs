// tests/mcp_verify_call_binding.test.mjs
// 1.2.1 lane 3, (s6) — `nsauditor-ai mcp verify-call` must not certify a response it never looked at.
//
// The MCP server appends a call_id to every tool response and logs it to ~/.nsauditor/mcp-calls.log; verify-call
// grepped the log and, on a hit, printed "✓ Verified MCP call … the response bearing it was a genuine tool call", exit
// 0. But the AI client has SEEN every earlier response's footer, so it can paste a real, logged id under a fabricated
// response: the id proves the server was called once, never that THIS text is what it returned. A digest printed in
// the footer would replay the same way, so the server LOGS a digest of the response body and verify-call RECOMPUTES it
// from the text the user saved.
//
// Exit codes (ruled): 0 verified · 1 refuted (not issued, or the text does not match) · 2 usage · 3 indeterminate
// (issued but no text supplied, or the call predates response binding).
//
// Canonicalisation (ruled): whitespace-insensitive, word-exact — a soft-wrapped or re-flowed copy of the raw output
// verifies; a changed word does not. STATED LIMIT, with its leg: a RENDERED copy (Markdown turned into bullets and
// bold) is a different text and refutes — re-copy the raw tool output; and code blocks lose indentation differences.
//
// Harness: the server module is imported after HOME points at a scratch directory (the call log path is computed at
// load); every CLI spawn uses that same HOME, a licence-state file and a dummy licence key there.

import { withNoDotenv } from './helpers/no_operator_dotenv.mjs';
import './helpers/no_operator_home.mjs';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { createServer, _setTier, _resetCloudScanCache } from '../mcp_server.mjs';
import { responseDigest, RECEIPT_MARKER } from '../utils/mcp_call_digest.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const CLI = path.join(ROOT, 'cli.mjs');
const HOME = process.env.HOME;
const LOG = path.join(HOME, '.nsauditor', 'mcp-calls.log');

function verify(args, input) {
  const env = { ...process.env, HOME, XDG_CONFIG_HOME: path.join(HOME, '.config'),
    NSAUDITOR_LICENSE_KEY: 'not-a-licence', NSAUDITOR_LICENSE_STATE_FILE: path.join(HOME, 'licence-state.json'), NSA_VERBOSE: '' };
  const r = spawnSync(process.execPath, [CLI, 'mcp', 'verify-call', ...args], { cwd: ROOT, env: withNoDotenv(env), encoding: 'utf8', timeout: 30000, input });
  return { status: r.status, out: `${r.stdout}${r.stderr}` };
}
function logLines(...entries) {
  fs.mkdirSync(path.dirname(LOG), { recursive: true });
  fs.appendFileSync(LOG, entries.map((e) => JSON.stringify(e)).join('\n') + '\n');
}
function saved(name, text) {
  const p = path.join(HOME, name);
  fs.writeFileSync(p, text);
  return p;
}
// A REAL tool call through the server's own tools/call handler (a CE-tier denial still carries its receipt).
async function realResponse() {
  _resetCloudScanCache(); _setTier('ce');
  const server = createServer();
  const r = await server._requestHandlers.get('tools/call')({ method: 'tools/call', params: { name: 'get_findings', arguments: { provider: 'aws' } } }, {});
  _setTier();
  const text = r.content[0].text;
  const id = /call_id: ([0-9a-f-]{36})/.exec(text)?.[1];
  assert.ok(id, `the response carries a call_id: ${text.slice(-300)}`);
  return { text, id };
}
const NEVER = '00000000-1111-4222-8333-444455556666';

// ── FOURTH QUADRANT ──────────────────────────────────────────────────────────────────────────────────────────────
test('(fourth quadrant, first) a UUID this server never issued is NOT issued — exit 1', () => {
  logLines({ call_id: '9a1b2c3d-4e5f-4a6b-8c7d-0e1f2a3b4c5d', tool: 'list_plugins', ts: '2026-09-01T00:00:00.000Z' });
  const r = verify([NEVER]);
  assert.equal(r.status, 1, r.out);
  assert.match(r.out, /NOT issued by this MCP server/);
});

test('(fourth quadrant) a REAL response, saved whole and verified with --response, is VERIFIED — exit 0, naming the tool and its age', async () => {
  const { text, id } = await realResponse();
  const r = verify([id, '--response', saved('real.txt', text)]);
  assert.equal(r.status, 0, r.out);
  assert.match(r.out, /✓ This response text was produced by this server for that call — get_findings, issued .* ago/);
});

test('(fourth quadrant) a SOFT-WRAPPED copy of the raw output still verifies — whitespace is not content', async () => {
  const { text, id } = await realResponse();
  const wrapped = text.replace(/ /g, (m, i) => (i % 37 === 0 ? '\r\n' : m)).replace(/\n/g, '\n  ');
  assert.notEqual(wrapped, text, 'positive control: the copy differs in whitespace');
  assert.equal(verify([id, '--response', saved('wrapped.txt', wrapped)]).status, 0);
});

test('the response can be piped in on stdin with --response -', async () => {
  const { text, id } = await realResponse();
  assert.equal(verify([id, '--response', '-'], text).status, 0);
});

// ── THE DEFECT ───────────────────────────────────────────────────────────────────────────────────────────────────
test('a REAL, logged id under DIFFERENT text is REFUTED — exit 1, naming both causes and the remedy', async () => {
  const { id } = await realResponse();
  const forged = `{"findings": [{"severity": "LOW", "title": "nothing to see"}]}\n\n${RECEIPT_MARKER}\ncall_id: ${id}\n`;
  const r = verify([id, '--response', saved('forged.txt', forged)]);
  assert.equal(r.status, 1, r.out);
  assert.match(r.out, /does not match what this server sent for that call/);
  assert.match(r.out, /altered after copying/);
  assert.match(r.out, /re-copy the RAW tool output/);
  assert.doesNotMatch(r.out, /genuine/);
});

test('a ONE-WORD edit of a real response is refuted — whitespace-insensitive, word-exact', async () => {
  const { text, id } = await realResponse();
  const edited = text.replace(/Enterprise/, 'Community');
  assert.notEqual(edited, text, 'positive control: a word changed');
  assert.equal(verify([id, '--response', saved('edited.txt', edited)]).status, 1);
});

test('a logged id with NO text supplied is INDETERMINATE — exit 3, never "genuine"', async () => {
  const { id } = await realResponse();
  const r = verify([id]);
  assert.equal(r.status, 3, r.out);
  assert.match(r.out, /issued by this server for get_findings .* ago/);
  assert.match(r.out, /does not verify the text/);
  assert.doesNotMatch(r.out, /genuine|✓/);
});

test('a call logged BEFORE response binding (no digest) is INDETERMINATE even with text — exit 3, "predates"', () => {
  const id = '7c6b5a49-3827-4615-9a0b-1c2d3e4f5a6b';
  logLines({ call_id: id, tool: 'scan_host', ts: '2026-08-01T00:00:00.000Z' });
  const r = verify([id, '--response', saved('old.txt', 'whatever the response said')]);
  assert.equal(r.status, 3, r.out);
  assert.match(r.out, /predates response binding/);
});

test('a VERBATIM replay of an OLD genuine response verifies — and says how old it is, so a stale answer reads as stale', () => {
  const id = '5e4d3c2b-1a09-4f8e-9d7c-6b5a49382716';
  const body = '{"plugins": 41, "tier": "ce"}';
  logLines({ call_id: id, tool: 'list_plugins', ts: '2026-01-02T00:00:00.000Z' }, { call_id: id, digest: responseDigest(body) });
  const r = verify([id, '--response', saved('replayed.txt', `${body}\n\n${RECEIPT_MARKER}\ncall_id: ${id}\n`)]);
  assert.equal(r.status, 0, r.out);
  assert.match(r.out, /list_plugins, issued \d+ days? ago/);
});

test('STATED LIMIT: a RENDERED copy (Markdown turned into bullets and bold) is a different text — it refutes', () => {
  const id = '1f2e3d4c-5b6a-4798-8a7b-6c5d4e3f2a1b';
  const body = '- **CRITICAL** anonymous FTP login on 21/tcp\n- **HIGH** SNMP default community';
  logLines({ call_id: id, tool: 'scan_host', ts: new Date().toISOString() }, { call_id: id, digest: responseDigest(body) });
  assert.equal(verify([id, '--response', saved('raw.txt', body)]).status, 0, 'positive control: the raw text verifies');
  const rendered = '• CRITICAL anonymous FTP login on 21/tcp\n• HIGH SNMP default community';
  assert.equal(verify([id, '--response', saved('rendered.txt', rendered)]).status, 1);
});

test('a body that itself CONTAINS the receipt marker still verifies — the footer is cut at the LAST marker', () => {
  // Host-chosen bytes reach tool output (an mDNS name, a page title), so a genuine body can carry the marker text.
  // Cutting at the FIRST marker would digest only the text before it and refute a response the server really sent.
  const id = '2a3b4c5d-6e7f-4a8b-9c0d-1e2f3a4b5c6d';
  const body = `{"host": "printer.local", "title": "${RECEIPT_MARKER} not a footer"}\n{"services": 3}`;
  assert.ok(body.includes(RECEIPT_MARKER), 'positive control: the body carries the marker');
  logLines({ call_id: id, tool: 'scan_host', ts: new Date().toISOString() }, { call_id: id, digest: responseDigest(body) });
  const r = verify([id, '--response', saved('marker-in-body.txt', `${body}\n\n${RECEIPT_MARKER}\ncall_id: ${id}\n`)]);
  assert.equal(r.status, 0, r.out);
});

// ── THE RECEIPT ──────────────────────────────────────────────────────────────────────────────────────────────────
test('the footer is a RECEIPT: it says how to verify, prints no digest, and does not call itself "Verified"', async () => {
  const { text, id } = await realResponse();
  const footer = text.slice(text.lastIndexOf(RECEIPT_MARKER));
  assert.match(footer, /^── MCP call receipt ──/);
  assert.match(footer, new RegExp(`nsauditor-ai mcp verify-call ${id} --response`));
  assert.doesNotMatch(text, /Verified MCP call/);
  const logged = fs.readFileSync(LOG, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l)).filter((e) => e.call_id === id && e.digest);
  assert.equal(logged.length, 1, 'the server logged the body digest');
  assert.equal(text.includes(logged[0].digest), false, 'the digest is never printed — a printed digest replays with the id');
});

// ── WHERE A USER LEARNS THE CONTRACT ─────────────────────────────────────────────────────────────────────────────────
test('the README, the verification doc and --help teach --response, say the id alone does not verify, and drop "genuine"', () => {
  const readme = fs.readFileSync(path.join(ROOT, 'README.md'), 'utf8');
  const doc = fs.readFileSync(path.join(ROOT, 'docs', 'mcp-verification.md'), 'utf8');
  const cli = fs.readFileSync(CLI, 'utf8');
  for (const [name, text] of [['README', readme], ['docs/mcp-verification.md', doc]]) {
    assert.match(text, /verify-call <(?:id|call_id)> --response/, `${name} teaches --response`);
    assert.match(text, /id alone (?:never verifies|does not verify) a response/, `${name} says the id alone does not verify`);
    assert.doesNotMatch(text, /to confirm a response is genuine|→ genuine, (?:the )?response is (?:real|trustworthy)/, `${name} drops the old verdict`);
    assert.doesNotMatch(text, /── Verified MCP call ──/, `${name} names the receipt, not a verdict`);
  }
  assert.match(doc, /RENDERED copy/, 'the doc states the rendered-copy limit');
  assert.match(cli, /verify-call <uuid> --response <file\|->/, '--help names --response');
  assert.doesNotMatch(cli, /not Claude hallucination\)|genuine tool call/, 'no unqualified verdict left in the CLI');
});
