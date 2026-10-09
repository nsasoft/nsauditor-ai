// tests/cli_notify_flags.test.mjs
// ─────────────────────────────────────────────────────────────────────────────
// THE DRIFT NOTIFICATION'S FLAGS, AND THE WATCH ALERT'S PAYLOAD MODE (EE 2.0.0, cargo 3 — D3/D5).
//
// Community parses and checks `--notify-webhook` / `--notify-format` / `--notify-severity` / `--notify-payload` at the
// boundary — the SSRF check `--webhook-url` gets, the vocabularies, and the combinations that would accept a flag and
// send nothing ever (no webhook, `--watch`, no framework) — then forwards them to Enterprise, which writes the drift
// file and sends. `--alert-payload minimal` is OFFERED on the watch alert; `full` stays the default (the architect
// seat's ruling: a relay parsing `details[]` must not break silently). The watch banner names the webhook's HOST: a
// Slack or Teams webhook URL carries its own credential.
//
// Forwarding and the watch alert are DRIVEN through `main()` with injected seams, never read off the source.
// The URLs are RFC 5737 documentation addresses: public to the SSRF guard, never routed, and no DNS lookup.
//
// FOURTH QUADRANT FIRST: no notify flag, no notification, and the alert payload unchanged.
// ─────────────────────────────────────────────────────────────────────────────
import { withNoDotenv } from './helpers/no_operator_dotenv.mjs';
import './helpers/no_operator_keychain.mjs';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { main, parseArgs, notifyRefusal } from '../cli.mjs';
import { buildAlertPayload } from '../utils/webhook.mjs';

const SECRET_URL = 'https://203.0.113.10/services/T0/B0/SECRETPATHTOKEN?sig=SECRETSIGTOKEN';
const argv = (...a) => ['node', 'cli.mjs', 'scan', '--host', '127.0.0.1', ...a];
const refusedWith = (re) => (err) => err?.code === 'EFLAGVALUE' && re.test(err.message);

// ── FOURTH QUADRANT FIRST ─────────────────────────────────────────────────────────────────────────────────────────────
test('(f1, first) no notify flag: nothing configured, and the watch alert payload stays FULL', async () => {
  const a = await parseArgs(argv());
  assert.deepEqual([a.notifyWebhook, a.notifyFormat, a.notifySeverity, a.notifyPayload], [null, null, null, null]);
  assert.equal(a.alertPayload, 'full');
  const full = buildAlertPayload('db.example', [{ port: 21, protocol: 'tcp', service: 'ftp', description: 'FTP anonymous login enabled', severity: 'critical' }]);
  assert.equal(full.host, 'db.example', 'the default alert must stay byte-compatible for relays that parse it');
  assert.equal(full.details[0].description, 'FTP anonymous login enabled');
});

// ── PARSING ───────────────────────────────────────────────────────────────────────────────────────────────────────────
test('(f2) a public notify webhook with every option parses, lower-cased', async () => {
  const a = await parseArgs(argv('--compliance', 'soc2', '--notify-webhook', SECRET_URL, '--notify-format', 'Teams',
    '--notify-severity', 'CRITICAL', '--notify-payload', 'full'));
  assert.deepEqual([a.notifyWebhook, a.notifyFormat, a.notifySeverity, a.notifyPayload], [SECRET_URL, 'teams', 'critical', 'full']);
});

test('(f3) every refusal THROWS EFLAGVALUE (exit 2 at the entry point) — never a silent no-op', async () => {
  const cases = [
    [argv('--notify-webhook', 'http://127.0.0.1:9/hook'), /rejected: private\/loopback/],
    [argv('--notify-webhook', 'http://169.254.169.254/latest'), /rejected: private\/loopback/],
    [argv('--notify-webhook'), /requires a URL/],
    [argv('--notify-webhook', SECRET_URL, '--notify-format', 'discord'), /--notify-format must be one of generic \| slack \| teams/],
    [argv('--notify-webhook', SECRET_URL, '--notify-severity', 'severe'), /--notify-severity must be one of/],
    [argv('--notify-webhook', SECRET_URL, '--notify-payload', 'some'), /--notify-payload must be one of minimal \| full/],
    [argv('--notify-format', 'slack'), /--notify-format configure the drift notification and need --notify-webhook/],
    [argv('--notify-severity', 'low', '--notify-payload', 'full'), /--notify-severity, --notify-payload configure/],
    [argv('--watch', '--notify-webhook', SECRET_URL), /ONE-SHOT scan, and --watch writes none/],
    [argv('--alert-payload', 'minimal'), /needs --webhook-url/],
    [argv('--watch', '--webhook-url', SECRET_URL, '--alert-payload', 'brief'), /--alert-payload must be one of full \| minimal/],
  ];
  for (const [args, re] of cases) await assert.rejects(parseArgs(args), refusedWith(re), args.slice(3).join(' '));
});

test('(f4) a notify webhook with no framework is refused — from --compliance or the environment either one satisfies it', () => {
  assert.match(notifyRefusal({ notifyWebhook: SECRET_URL }).message, /name a framework with --compliance/);
  assert.equal(notifyRefusal({ notifyWebhook: SECRET_URL }).code, 2);
  assert.equal(notifyRefusal({ notifyWebhook: SECRET_URL, compliance: 'soc2' }), null);
  assert.equal(notifyRefusal({ notifyWebhook: SECRET_URL, envCompliance: 'hipaa' }), null);
  assert.equal(notifyRefusal({}), null, 'no webhook, nothing to refuse');
});

// ── DRIVEN THROUGH main() ─────────────────────────────────────────────────────────────────────────────────────────────
async function withScanEnv(fn) {
  const outRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-notify-'));
  const savedArgv = process.argv;
  const savedEnv = { SCAN_OUT_PATH: process.env.SCAN_OUT_PATH, OPENAI_OUT_PATH: process.env.OPENAI_OUT_PATH,
    NSA_ALLOW_ALL_HOSTS: process.env.NSA_ALLOW_ALL_HOSTS, COMPLIANCE_FRAMEWORKS: process.env.COMPLIANCE_FRAMEWORKS };
  try {
    delete process.env.OPENAI_OUT_PATH;
    delete process.env.COMPLIANCE_FRAMEWORKS;
    process.env.SCAN_OUT_PATH = outRoot;
    process.env.NSA_ALLOW_ALL_HOSTS = '1';
    return await fn(outRoot);
  } finally {
    process.argv = savedArgv;
    for (const [k, v] of Object.entries(savedEnv)) { if (v == null) delete process.env[k]; else process.env[k] = v; }
    fs.rmSync(outRoot, { recursive: true, force: true });
  }
}
const captureEE = (sink) => async () => ({
  enrichScan: async (conclusion, opts) => {
    sink.push({ notifyWebhook: opts.notifyWebhook, notifyFormat: opts.notifyFormat, notifySeverity: opts.notifySeverity,
      notifyPayload: opts.notifyPayload, watch: opts.watch });
    return { enrichedPrompt: null, exploitIntel: { stores: { kev: null, epss: null } } };
  },
});

test('(f5) a one-shot scan FORWARDS the four notify options to Enterprise, and an unconfigured one forwards nulls', async () => {
  await withScanEnv(async () => {
    const sink = [];
    process.argv = argv('--plugins', '003', '--ports', '1-2', '--compliance', 'soc2', '--notify-webhook', SECRET_URL,
      '--notify-format', 'slack', '--notify-payload', 'full');
    await main({ importEE: captureEE(sink) });
    assert.equal(sink.length, 1, 'positive control: enrichScan was called');
    assert.deepEqual(sink[0], { notifyWebhook: SECRET_URL, notifyFormat: 'slack', notifySeverity: null, notifyPayload: 'full', watch: false });
  });
  await withScanEnv(async () => {
    const sink = [];
    process.argv = argv('--plugins', '003', '--ports', '1-2', '--compliance', 'soc2');
    await main({ importEE: captureEE(sink) });
    assert.deepEqual(sink[0], { notifyWebhook: null, notifyFormat: null, notifySeverity: null, notifyPayload: null, watch: false });
  });
});

/** One watch cycle through main(): the fake scheduler hands a conclusion with a Critical finding to onCycleComplete. */
async function watchAlert(extra) {
  return withScanEnv(async () => {
    const sent = [];
    const logs = [];
    const before = { int: process.listeners('SIGINT').slice(), term: process.listeners('SIGTERM').slice() };
    const savedLog = console.log;
    let cycle = null;
    const conclusion = { result: { services: [{ port: 21, protocol: 'tcp', service: 'ftp', anonymousLogin: true }], evidence: [] } };
    const fakeScheduler = (cfg) => ({ hosts: cfg.hosts, duplicatesDropped: 0,
      start() { cycle = cfg.onCycleComplete(new Map([['127.0.0.1', { conclusion }]])); }, async stop() {} });
    process.argv = argv('--watch', '--interval', '1', '--webhook-url', SECRET_URL, '--alert-every-cycle', ...extra);
    console.log = (...a) => { logs.push(a.join(' ')); };
    try {
      await main({ importEE: captureEE([]), _createScheduler: fakeScheduler,
        _sendWebhook: async (url, payload) => { sent.push({ url, payload }); return { success: true, statusCode: 200 }; } });
      await cycle;
    } finally {
      console.log = savedLog;
      for (const l of process.listeners('SIGINT')) if (!before.int.includes(l)) process.removeListener('SIGINT', l);
      for (const l of process.listeners('SIGTERM')) if (!before.term.includes(l)) process.removeListener('SIGTERM', l);
    }
    return { sent, logs };
  });
}

test('(f6) --alert-payload minimal: the watch alert carries no host, service or description — and full (the default) does', async () => {
  const dflt = await watchAlert([]);
  assert.equal(dflt.sent.length, 1, 'positive control: the cycle alerted');
  assert.equal(dflt.sent[0].payload.host, '127.0.0.1');
  assert.equal(dflt.sent[0].payload.details[0].service, 'ftp');
  const min = await watchAlert(['--alert-payload', 'minimal']);
  assert.equal(min.sent.length, 1);
  const body = JSON.stringify(min.sent[0].payload);
  for (const leak of ['127.0.0.1', 'ftp', 'anonymous']) assert.ok(!body.toLowerCase().includes(leak), `minimal carried '${leak}': ${body}`);
  assert.deepEqual(min.sent[0].payload.details, [{ port: 21, protocol: 'tcp', severity: 'critical' }]);
});

test('(f7) the watch banner names the webhook HOST — never its path or query, where the credential lives', async () => {
  const { logs } = await watchAlert([]);
  const banner = logs.find((l) => l.startsWith('[CTEM] Webhook'));
  assert.ok(banner, `positive control: the banner printed — ${JSON.stringify(logs)}`);
  assert.ok(banner.includes('203.0.113.10'), banner);
  for (const token of ['SECRETPATHTOKEN', 'SECRETSIGTOKEN']) assert.ok(!logs.join('\n').includes(token), `stdout carried ${token}`);
});

test('(f8) the refusal reaches the operator as EXIT 2 with the reason on stderr — the entry point, spawned', () => {
  // parseArgs is the first statement of main(), so a refused flag exits before any licence or network code runs.
  const cli = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'cli.mjs');
  const r = spawnSync(process.execPath, [cli, 'scan', '--host', '127.0.0.1', '--notify-format', 'slack'],
    { env: withNoDotenv(), encoding: 'utf8', timeout: 60_000 });
  assert.equal(r.status, 2, `exit ${r.status}; stderr: ${r.stderr?.slice(0, 300)}`);
  assert.match(r.stderr, /--notify-format configure the drift notification and need --notify-webhook/);
});
