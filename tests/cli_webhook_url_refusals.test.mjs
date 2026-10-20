// tests/cli_webhook_url_refusals.test.mjs
// ─────────────────────────────────────────────────────────────────────────────
// A WEBHOOK URL IS REFUSED FOR THE REASON THAT IS TRUE OF IT — NOT A URL, A SCHEME THE FLAG DOES NOT TAKE, OR AN
// ADDRESS THE GUARD BLOCKS — AND THE REFUSAL NEVER REPEATS THE VALUE.
//
// `--notify-webhook` and `--webhook-url` refused `ftp://…`, `file:///…`, `javascript:…` and a value that is not a URL at
// all, which is right, but each with "private/loopback/metadata addresses are not allowed": the scheme check runs inside
// the address guard, so the operator was told the address is internal when it is malformed. Each failure now has its own
// sentence — the scheme is named, the value is never echoed (a Slack or Teams webhook URL carries its own credential) —
// and `--webhook-url` throws EFLAGVALUE like every other flag refusal instead of exiting inside parseArgs.
//
// The URLs are RFC 5737 documentation addresses: public to the guard, never routed, and no DNS lookup.
//
// FOURTH QUADRANT FIRST: a public https URL parses for both flags, and `--webhook-url` still takes http — or the new
// checks could pass by refusing everything.
// ─────────────────────────────────────────────────────────────────────────────
import { withNoDotenv } from './helpers/no_operator_dotenv.mjs';
import './helpers/no_operator_keychain.mjs';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { parseArgs } from '../cli.mjs';

const BIN = join(dirname(fileURLToPath(import.meta.url)), '..', 'bin', 'nsauditor-ai.mjs');
const argv = (...a) => ['node', 'cli.mjs', 'scan', '--host', '127.0.0.1', ...a];
const refusal = async (args) => parseArgs(args).then(() => null, (e) => e);

// ── FOURTH QUADRANT FIRST ─────────────────────────────────────────────────────────────────────────────────────────────
test('(first) a public https URL parses for both flags; --webhook-url still takes a public http URL', async () => {
  assert.equal((await parseArgs(argv('--compliance', 'soc2', '--notify-webhook', 'https://203.0.113.10/hook'))).notifyWebhook,
    'https://203.0.113.10/hook');
  assert.equal((await parseArgs(argv('--webhook-url', 'https://203.0.113.10/hook'))).webhookUrl, 'https://203.0.113.10/hook');
  assert.equal((await parseArgs(argv('--webhook-url', 'http://203.0.113.10/hook'))).webhookUrl, 'http://203.0.113.10/hook');
});

// ── ONE SENTENCE PER REASON ────────────────────────────────────────────────────────────────────────────────────────────
const CASES = [
  // [flag, value, the exact message]
  ['--notify-webhook', 'ftp://203.0.113.10/hook', '--notify-webhook must be an https URL; got ftp:'],
  ['--notify-webhook', 'file:///etc/passwd', '--notify-webhook must be an https URL; got file:'],
  ['--notify-webhook', 'javascript:alert(1)', '--notify-webhook must be an https URL; got javascript:'],
  ['--notify-webhook', 'hooks.example/services/T0/B0/X', '--notify-webhook must be an https URL; the value given is not a URL'],
  ['--notify-webhook', 'not a url', '--notify-webhook must be an https URL; the value given is not a URL'],
  ['--notify-webhook', 'http://203.0.113.10/hook',
    '--notify-webhook must be an https URL: it carries its own credential, and the drift it sends is scan content'],
  ['--notify-webhook', 'https://127.0.0.1:9/hook', '--notify-webhook rejected: private/loopback/metadata addresses are not allowed'],
  ['--webhook-url', 'ftp://203.0.113.10/hook', '--webhook-url must be an http or https URL; got ftp:'],
  ['--webhook-url', 'file:///etc/passwd', '--webhook-url must be an http or https URL; got file:'],
  ['--webhook-url', 'hooks.example/services/T0/B0/X', '--webhook-url must be an http or https URL; the value given is not a URL'],
  ['--webhook-url', 'https://127.0.0.1:9/hook', 'Webhook URL rejected: private/loopback/metadata addresses are not allowed.'],
];
for (const [flag, value, message] of CASES) {
  test(`${flag} ${value} → "${message}"`, async () => {
    const extra = flag === '--notify-webhook' ? ['--compliance', 'soc2'] : [];
    const err = await refusal(argv(...extra, flag, value));
    assert.deepEqual([err?.code, err?.message], ['EFLAGVALUE', message]);
  });
}

test('no refusal repeats the value — a webhook URL carries its own credential', async () => {
  for (const [flag, value] of [['--notify-webhook', 'ftp://203.0.113.10/services/SECRETPATHTOKEN'],
    ['--notify-webhook', 'SECRETPATHTOKEN-not-a-url'], ['--webhook-url', 'gopher://203.0.113.10/SECRETPATHTOKEN'],
    ['--webhook-url', 'SECRETPATHTOKEN-not-a-url']]) {
    const err = await refusal(argv('--compliance', 'soc2', flag, value));
    assert.equal(err?.code, 'EFLAGVALUE', `${flag} ${value}`);
    assert.doesNotMatch(err.message, /SECRETPATHTOKEN/);
  }
});

// ── A PLAIN-HTTP --webhook-url IS ACCEPTED, AND SAYS WHAT IT COSTS (board item (ba), half 1) ───────────────────────────
// Whether it should be refused is the operator's decision (a documented, accepted value — a MAJOR-shaped change); until
// then the operator is told, once, that the watch alerts it receives leave in the clear.
async function warningsOf(args) {
  const lines = [];
  const real = console.warn;
  console.warn = (...a) => lines.push(a.join(' '));
  try { await parseArgs(args); } finally { console.warn = real; }
  return lines.filter((l) => /webhook/i.test(l));
}
test('(first) an https --webhook-url prints no warning', async () => {
  assert.deepEqual(await warningsOf(argv('--webhook-url', 'https://203.0.113.10/hook')), []);
});
test('a plain-http --webhook-url prints exactly ONE warning naming the consequence — and never the URL', async () => {
  const lines = await warningsOf(argv('--webhook-url', 'http://203.0.113.10/services/SECRETPATHTOKEN'));
  assert.equal(lines.length, 1, JSON.stringify(lines));
  assert.match(lines[0], /^\[WARN\] --webhook-url is a plain http URL: findings leave in the clear over plaintext HTTP/);
  assert.doesNotMatch(lines[0], /SECRETPATHTOKEN|203\.0\.113\.10/);
});

// ── THROUGH THE COMMAND npm INSTALLS: --webhook-url no longer exits inside parseArgs ───────────────────────────────────
test('--webhook-url refused through the bin: exit 2 and exactly one [ERROR] line', () => {
  const cwd = fs.mkdtempSync(join(os.tmpdir(), 'nsa-webhook-refusal-'));
  try {
    const env = { ...process.env };
    delete env.NSA_ALLOW_ALL_HOSTS;
    const r = spawnSync(process.execPath, [BIN, 'scan', '--host', '192.0.2.1', '--webhook-url', 'ftp://203.0.113.10/hook'],
      { cwd, env: withNoDotenv(env), encoding: 'utf8', timeout: 60_000 });
    assert.equal(r.status, 2, r.stderr.slice(0, 400));
    assert.equal(r.stderr.trim(), '[ERROR] --webhook-url must be an http or https URL; got ftp:');
  } finally { fs.rmSync(cwd, { recursive: true, force: true }); }
});
