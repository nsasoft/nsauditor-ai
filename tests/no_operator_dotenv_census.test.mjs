// tests/no_operator_dotenv_census.test.mjs
// THE SUITE MUST NOT READ THE OPERATOR'S .env — and so must never send a real AI request.
//
// cli.mjs line 2 is `import 'dotenv/config'`: importing the CLI loads `.env` from the process CWD. The operator's checkout
// carries an untracked `.env` that turns AI sending on with real provider keys, so every sequential suite run from the
// checkout sent 39 real requests to the provider (measured against a loopback counter: 31 printed by tests that import the
// CLI, 8 more from children whose output the tests capture), carrying redacted loopback-fixture scans and the operator's
// key. A worktree carries no `.env`, so it ran a different suite. tests/helpers/no_operator_dotenv.mjs neutralises it.
//
// CENSUS (deny-by-default, derived from every .mjs under tests/): a file that imports cli.mjs or bin/nsauditor-ai.mjs
// imports the helper FIRST — static imports are evaluated in source order, so ORDER is the rule, not presence — and in
// a file that names the CLI, every child process that runs node is handed an env built by withNoDotenv(). A spawn that
// merely spreads process.env does not count: covered is a property the call states.
//
// LIVENESS: two children scan 127.0.0.1 (plugin 003, ports 1-2, the run_record tests' drive) from a scratch CWD whose
// .env turns AI on with a FAKE key and points the provider at a LOOPBACK listener that answers 404 — nothing leaves the
// machine. Without the helper the send path is reached (the finding's own symptom, "AI conclusion: FAILED … 404"); with
// it the .env is never read and AI is off even when the child's own env switched it on.
import { withNoDotenv } from './helpers/no_operator_dotenv.mjs';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import { spawn } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const TESTS = path.join(ROOT, 'tests');
const rel = (f) => path.relative(ROOT, f);
const walk = (dir) => fs.readdirSync(dir, { withFileTypes: true }).flatMap((e) =>
  e.isDirectory() ? walk(path.join(dir, e.name)) : e.name.endsWith('.mjs') ? [path.join(dir, e.name)] : []);

// The instrument itself: its control arm spawns WITHOUT the neutraliser on purpose, into a scratch CWD.
const EXEMPT = new Map([['tests/no_operator_dotenv_census.test.mjs', 'the liveness control arm spawns un-neutralised by design']]);

const CLI_SPEC = /['"](?:\.\.\/)+(?:cli|bin\/nsauditor-ai)\.mjs['"]/g;
const HELPER_SPEC = /['"]\.\.?\/(?:\.\.\/)*helpers\/no_operator_dotenv\.mjs['"]/g;
const IN_IMPORT = /(?:\bfrom|\bimport\s*\(|\bimport)\s*$/;
/** Offset of the first module specifier matching `re` that sits in an import statement or import() call, or -1. */
function firstImport(src, re) {
  for (const m of src.matchAll(re)) if (IN_IMPORT.test(src.slice(Math.max(0, m.index - 40), m.index))) return m.index;
  return -1;
}
const CALL = /(?<![\w$.])(?:spawn|spawnSync|execFile|execFileSync|fork|exec|execSync)\s*\(|\b[A-Za-z_$][\w$]*\.(?:spawn|spawnSync|execFile|execFileSync|fork)\s*\(/g;
/** The text of a call's argument list, from its opening paren to the matching close (string literals skipped). */
function callText(src, open) {
  let depth = 0;
  for (let i = open; i < src.length; i++) {
    const c = src[i];
    if (c === '\'' || c === '"' || c === '`') {
      for (i++; i < src.length && src[i] !== c; i++) if (src[i] === '\\') i++;
    } else if (c === '(') depth++;
    else if (c === ')' && --depth === 0) return src.slice(open, i + 1);
  }
  return src.slice(open);
}
const lineOf = (src, i) => src.slice(0, i).split('\n').length;

function census() {
  const importers = [];
  const orderViolations = [];
  const spawners = [];
  const spawnViolations = [];
  for (const file of walk(TESTS)) {
    const name = rel(file);
    if (EXEMPT.has(name) || name === 'tests/helpers/no_operator_dotenv.mjs') continue;
    const src = fs.readFileSync(file, 'utf8');
    const cliAt = firstImport(src, CLI_SPEC);
    if (cliAt >= 0) {
      importers.push(name);
      const helperAt = firstImport(src, HELPER_SPEC);
      if (helperAt < 0 || helperAt > cliAt) orderViolations.push(`${name}:${lineOf(src, cliAt)}`);
    }
    if (!/cli\.mjs|nsauditor-ai\.mjs/.test(src) && cliAt < 0) continue;
    for (const m of src.matchAll(CALL)) {
      const text = callText(src, m.index + m[0].length - 1);
      if (!/process\.execPath|['"]node['"]/.test(text)) continue;
      spawners.push(`${name}:${lineOf(src, m.index)}`);
      if (!/\bwithNoDotenv\(/.test(text)) spawnViolations.push(`${name}:${lineOf(src, m.index)}`);
    }
  }
  return { importers, orderViolations, spawners, spawnViolations };
}

// ── FOURTH QUADRANT FIRST: the census sees the population it is about ─────────────────────────────────────────────────
test('(fourth quadrant, first) the census reaches the files it governs — a static importer, the dynamic importer, a bin spawn', () => {
  const c = census();
  for (const f of ['tests/run_record_kev_epss.test.mjs', 'tests/scan_history_finding_definition.test.mjs']) {
    assert.ok(c.importers.includes(f), `${f} imports the CLI and the census must see it`);
  }
  assert.ok(c.spawners.some((s) => s.startsWith('tests/run_record_abort.test.mjs:')), 'a bin/nsauditor-ai.mjs spawn is a CLI spawn');
  assert.ok(c.importers.length >= 20 && c.spawners.length >= 15, `population ${c.importers.length} importers / ${c.spawners.length} spawns`);
});

test('every test that imports the CLI imports the neutraliser BEFORE it (source order is evaluation order)', () => {
  assert.deepEqual(census().orderViolations, []);
});

test('every node child in a file that names the CLI is handed an env built by withNoDotenv()', () => {
  assert.deepEqual(census().spawnViolations, []);
});

test('the EXEMPT set is visible and live: each entry names a file that exists', () => {
  for (const [f, why] of EXEMPT) {
    assert.ok(fs.existsSync(path.join(ROOT, f)), `stale exemption ${f}`);
    assert.ok(why.length > 20, `${f}: an exemption states its reason`);
  }
});

// ── LIVENESS — loopback only ─────────────────────────────────────────────────────────────────────────────────────────
async function loopbackProvider() {
  const hits = [];
  const srv = http.createServer((req, res) => {
    req.resume();
    req.on('end', () => { hits.push(`${req.method} ${req.url}`); res.writeHead(404, { 'content-type': 'application/json' }); res.end('{"error":{"message":"loopback"}}'); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  return { hits, url: `http://127.0.0.1:${srv.address().port}`, close: () => new Promise((r) => srv.close(r)) };
}

async function driveChild({ withHelper, extraEnv = {} }) {
  const provider = await loopbackProvider();
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-dotenv-live-'));
  fs.writeFileSync(path.join(dir, '.env'), [
    'NSA_DOTENV_SENTINEL=loaded', 'AI_ENABLED=true', 'AI_PROVIDER=claude', 'ANTHROPIC_API_KEY=fake-key-loopback-only',
    `ANTHROPIC_BASE_URL=${provider.url}`, `OPENAI_BASE_URL=${provider.url}/v1`, ''].join('\n'));
  const url = (p) => pathToFileURL(path.join(ROOT, p)).href;
  fs.writeFileSync(path.join(dir, 'child.mjs'), [
    ...(withHelper ? [`import ${JSON.stringify(url('tests/helpers/no_operator_dotenv.mjs'))};`] : []),
    `import { main } from ${JSON.stringify(url('cli.mjs'))};`,
    `console.log('SENTINEL=' + (process.env.NSA_DOTENV_SENTINEL ?? 'absent'));`,
    `process.argv = ['node', 'cli', 'scan', '--host', '127.0.0.1', '--plugins', '003', '--ports', '1-2'];`,
    `const absent = () => { throw Object.assign(new Error('absent'), { code: 'ERR_MODULE_NOT_FOUND' }); };`,
    `await main({ resolveEE: absent, importEE: async () => absent() });`,
  ].join('\n'));
  // An explicit env built from nothing: the parent's (neutralised) env must not leak into either arm.
  const env = { PATH: process.env.PATH, HOME: dir, NSAUDITOR_LICENSE_KEY: 'not-a-licence',
    NSAUDITOR_LICENSE_STATE_FILE: path.join(dir, 'licence-state.json'), NSA_ALLOW_ALL_HOSTS: '1',
    SCAN_OUT_PATH: path.join(dir, 'out'), ...extraEnv };
  if (extraEnv.ANTHROPIC_BASE_URL === true) env.ANTHROPIC_BASE_URL = provider.url;
  const out = await new Promise((resolve) => {
    const child = spawn(process.execPath, [path.join(dir, 'child.mjs')], { cwd: dir, env });
    let text = '';
    child.stdout.on('data', (d) => { text += d; });
    child.stderr.on('data', (d) => { text += d; });
    const t = setTimeout(() => child.kill('SIGKILL'), 60_000);
    child.on('close', () => { clearTimeout(t); resolve(text); });
  });
  await provider.close();
  return { out, hits: provider.hits };
}

test('LIVENESS, control: WITHOUT the neutraliser the scratch .env is read and the AI send path is reached (loopback 404)', { timeout: 90_000 }, async () => {
  const { out, hits } = await driveChild({ withHelper: false });
  assert.match(out, /SENTINEL=loaded/, out.slice(-1500));
  assert.match(out, /AI conclusion: FAILED \(127\.0\.0\.1\) — 404/, out.slice(-1500));
  assert.ok(hits.length >= 1 && hits.every((h) => h === 'POST /v1/messages'), `loopback hits: ${hits}`);
});

test('LIVENESS: WITH the neutraliser the .env is never read, and AI is off even when the child\'s own env switched it on', { timeout: 90_000 }, async () => {
  // The child's env carries an AI switch, a key and a provider of its own — an operator's SHELL exports, which dotenv
  // could never override. The neutraliser must win over them too.
  const { out, hits } = await driveChild({ withHelper: true,
    extraEnv: { AI_ENABLED: 'true', AI_PROVIDER: 'claude', ANTHROPIC_API_KEY: 'fake-key-loopback-only', ANTHROPIC_BASE_URL: true } });
  assert.match(out, /SENTINEL=absent/, out.slice(-1500));
  assert.match(out, /AI conclusion: SKIPPED — AI_ENABLED not set \(127\.0\.0\.1\)/, out.slice(-1500));
  assert.deepEqual(hits, []);
});

test('withNoDotenv() hands a child a COPY carrying all three settings, and leaves the source env alone', () => {
  const src = { PATH: '/bin', AI_ENABLED: 'true', OPENAI_API_KEY: 'k', ANTHROPIC_API_KEY: 'k' };
  const env = withNoDotenv(src);
  assert.equal(env.AI_ENABLED, 'false');
  assert.ok(env.DOTENV_CONFIG_PATH && !fs.existsSync(env.DOTENV_CONFIG_PATH));
  assert.equal('OPENAI_API_KEY' in env || 'ANTHROPIC_API_KEY' in env, false);
  assert.equal(src.AI_ENABLED, 'true', 'the source is not mutated');
});
