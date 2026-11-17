// tests/working_directory_env_file_not_loaded.test.mjs
// THE CLI READS AN ENV FILE ONLY FROM A PLACE THE USER NAMED: the exported environment, or `--env <path>`.
// A `.env` in the working directory is not loaded; when one exists the CLI says so on stderr, once, and names
// `--env ./.env` with the trust condition. Custom plugin directories must be absolute; each directory loaded and each
// entry refused is named on stderr, never on stdout.
//
// Driven through the REAL binary (`bin/nsauditor-ai.mjs`) for `license --plugins` AND `scan`, in both directions,
// with a marker plugin that writes a file the moment it is IMPORTED — importing is what runs a plugin's code, so the
// marker answers "was this directory's code executed?", not "was it listed?".
//
// ⚠️ THE CHILDREN HERE ARE DELIBERATELY UN-NEUTRALISED (an EXEMPT entry in no_operator_dotenv_census.test.mjs): the
// helper's DOTENV_CONFIG_PATH would stop a working-directory load by itself, so a child built with withNoDotenv()
// could never show what the CLI does on its own. Each child gets an env built from NOTHING instead — no parent key
// leaks in — with AI switched off by an explicit export.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import { spawn, spawnSync } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const BIN = path.join(ROOT, 'bin', 'nsauditor-ai.mjs');
const HINT = /^nsauditor-ai: \.\/\.env was not loaded: a working-directory file is no longer read automatically\. To use it pass --env \.\/\.env, only for a file you wrote or trust\.$/m;
const ANNOUNCE_OR_HINT = /nsauditor-ai: (custom plugin|\.\/\.env was not loaded)/;

/** A fresh layout under a REALPATH'd temp root (macOS tmpdir is a symlink; the plugin rule compares realpaths with $HOME). */
function layout() {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-envsrc-')));
  const home = path.join(root, 'home');
  const work = path.join(home, 'work');            // the working directory: under HOME, as a clone usually is
  const okDir = path.join(home, 'okplugins');      // a directory the user names by an absolute path
  const marker = path.join(root, 'MARKER');
  for (const d of [home, work, okDir, path.join(work, 'p')]) fs.mkdirSync(d, { recursive: true });
  const src = `import fs from 'node:fs';\nfs.writeFileSync(${JSON.stringify(marker)}, 'imported');\n`
    + `export default { id: '9991', name: 'Env Source Marker', priority: 999, run: async () => ({ up: false }) };\n`;
  fs.writeFileSync(path.join(okDir, '9991_marker.mjs'), src);
  fs.writeFileSync(path.join(work, 'p', '9991_marker.mjs'), src);
  return { root, home, work, okDir, marker, done: () => fs.rmSync(root, { recursive: true, force: true }) };
}

const SUBCOMMANDS = {
  'license --plugins': ['license', '--plugins'],
  scan: ['scan', '--host', '127.0.0.1', '--plugins', '9991', '--ports', '1'],
};

function drive(L, args, extraEnv = {}) {
  const env = { PATH: process.env.PATH, HOME: L.home, AI_ENABLED: 'false', NSAUDITOR_LICENSE_KEY: 'not-a-licence',
    NSAUDITOR_LICENSE_STATE_FILE: path.join(L.root, 'licence-state.json'), NSA_ALLOW_ALL_HOSTS: '1',
    SCAN_OUT_PATH: path.join(L.root, 'out'), ...extraEnv };
  const r = spawnSync(process.execPath, [BIN, ...args], { cwd: L.work, env, encoding: 'utf8', timeout: 60_000 });
  return { ...r, imported: fs.existsSync(L.marker), listed: /^\s+9991\s/m.test(r.stdout ?? '') };
}

for (const [name, argv] of Object.entries(SUBCOMMANDS)) {
  // ── ACCEPT (fourth quadrant first) ──────────────────────────────────────────────────────────────────────────────────
  test(`${name}: an EXPORTED absolute plugin directory under HOME loads, and is named on stderr with its count`, { timeout: 90_000 }, () => {
    const L = layout();
    try {
      const r = drive(L, argv, { NSAUDITOR_PLUGIN_PATH: L.okDir });
      assert.ok(r.imported, `the named directory's plugin was not imported; stderr: ${r.stderr}`);
      if (name.startsWith('license')) assert.ok(r.listed, 'the plugin is not listed');
      assert.match(r.stderr, new RegExp(`^nsauditor-ai: custom plugins: 1 loaded from ${L.okDir.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`, 'm'));
      assert.doesNotMatch(r.stderr, HINT, 'no working-directory .env exists, so no hint');      // (iv)
      assert.doesNotMatch(r.stdout, ANNOUNCE_OR_HINT, 'announce text reached stdout');            // (v)
    } finally { L.done(); }
  });

  test(`${name}: an absolute plugin directory set in a file passed by --env loads`, { timeout: 90_000 }, () => {
    const L = layout();
    try {
      const envFile = path.join(L.root, 'named.env');
      fs.writeFileSync(envFile, `NSAUDITOR_PLUGIN_PATH=${L.okDir}\n`);
      const r = drive(L, [...argv, '--env', envFile]);
      assert.ok(r.imported, `--env did not reach plugin discovery; stderr: ${r.stderr}`);
      assert.doesNotMatch(r.stderr, HINT);
    } finally { L.done(); }
  });

  test(`${name}: --env ./.env whose plugin path is absolute loads it, and prints no hint — the hint's own instruction works`, { timeout: 90_000 }, () => {
    const L = layout();
    try {
      fs.writeFileSync(path.join(L.work, '.env'), `NSAUDITOR_PLUGIN_PATH=${L.okDir}\n`);
      const r = drive(L, [...argv, '--env', './.env']);
      assert.ok(r.imported, `stderr: ${r.stderr}`);
      assert.doesNotMatch(r.stderr, HINT, 'the file the hint names was passed, so the hint must not print');   // (ii)
      assert.doesNotMatch(r.stdout, ANNOUNCE_OR_HINT);                                                      // (v)
    } finally { L.done(); }
  });

  // ── REFUSE ──────────────────────────────────────────────────────────────────────────────────────────────────────────
  test(`${name}: a working-directory .env is not loaded — no plugin code from it runs, and stderr names --env ./.env`, { timeout: 90_000 }, () => {
    const L = layout();
    try {
      fs.writeFileSync(path.join(L.work, '.env'), 'NSAUDITOR_PLUGIN_PATH=./p\n');
      const r = drive(L, argv);
      assert.equal(r.imported, false, 'plugin code from a directory named only by a working-directory .env was imported');
      assert.equal(r.listed, false);
      assert.match(r.stderr, HINT);
      assert.equal((r.stderr.match(new RegExp(HINT.source, 'gm')) ?? []).length, 1, 'the hint prints once');
      assert.doesNotMatch(r.stdout, ANNOUNCE_OR_HINT);                                                      // (v)
    } finally { L.done(); }
  });

  test(`${name}: a working-directory .env naming an ABSOLUTE plugin directory is not loaded either — the file is not read at all`, { timeout: 90_000 }, () => {
    // The relative-path rule alone would refuse `./p`; this arm names a directory the rule ACCEPTS, so the only thing
    // standing between the file and the import is that the file is never read.
    const L = layout();
    try {
      fs.writeFileSync(path.join(L.work, '.env'), `NSAUDITOR_PLUGIN_PATH=${L.okDir}\n`);
      const r = drive(L, argv);
      assert.equal(r.imported, false, 'a plugin directory named only by a working-directory .env was imported');
      assert.match(r.stderr, HINT);
    } finally { L.done(); }
  });

  test(`${name}: a working-directory .env beside --env <another file> is still not loaded, and the hint prints`, { timeout: 90_000 }, () => {
    const L = layout();
    try {
      fs.writeFileSync(path.join(L.work, '.env'), 'NSAUDITOR_PLUGIN_PATH=./p\n');
      const other = path.join(L.root, 'other.env');
      fs.writeFileSync(other, 'NSA_UNRELATED_KEY=1\n');
      const r = drive(L, [...argv, '--env', other]);                                                       // (i)
      assert.equal(r.imported, false);
      assert.match(r.stderr, HINT);
    } finally { L.done(); }
  });

  test(`${name}: a RELATIVE plugin directory is refused even from a file passed by --env, and the refusal is named`, { timeout: 90_000 }, () => {
    const L = layout();
    try {
      fs.writeFileSync(path.join(L.work, '.env'), 'NSAUDITOR_PLUGIN_PATH=./p\n');
      const r = drive(L, [...argv, '--env', './.env']);                                                     // (iii)
      assert.equal(r.imported, false, 'a relative plugin directory was imported');
      assert.match(r.stderr, /^nsauditor-ai: custom plugin directory refused \(relative\): "\.\/p"/m);
      assert.doesNotMatch(r.stdout, ANNOUNCE_OR_HINT);
    } finally { L.done(); }
  });
}

// PINNED UNCHANGED: ~/.nsauditor/.env is read for single keys (the licence key, the MCP auth key), never loaded whole.
test('~/.nsauditor/.env is not loaded as an environment: a plugin directory set there is not used', { timeout: 90_000 }, () => {
  const L = layout();
  try {
    fs.mkdirSync(path.join(L.home, '.nsauditor'));
    fs.writeFileSync(path.join(L.home, '.nsauditor', '.env'), `NSAUDITOR_PLUGIN_PATH=${L.okDir}\n`, { mode: 0o600 });
    const r = drive(L, SUBCOMMANDS['license --plugins']);
    assert.equal(r.status, 0, `exit ${r.status}; stderr: ${r.stderr}`);
    assert.equal(r.imported, false);
  } finally { L.done(); }
});

// ── A non-code key from a working-directory .env sets nothing (AI, against a LOOPBACK provider; nothing leaves) ─────────
async function loopbackProvider() {
  const hits = [];
  const srv = http.createServer((req, res) => {
    req.resume();
    req.on('end', () => { hits.push(`${req.method} ${req.url}`); res.writeHead(404, { 'content-type': 'application/json' }); res.end('{"error":{"message":"loopback"}}'); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  return { hits, url: `http://127.0.0.1:${srv.address().port}`, close: () => new Promise((r) => srv.close(r)) };
}

async function driveAi({ where }) {
  const provider = await loopbackProvider();
  const dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-envsrc-ai-')));
  const body = ['NSA_ENV_SENTINEL=loaded', 'AI_ENABLED=true', 'AI_PROVIDER=claude', 'ANTHROPIC_API_KEY=fake-key-loopback-only',
    `ANTHROPIC_BASE_URL=${provider.url}`, `OPENAI_BASE_URL=${provider.url}/v1`, ''].join('\n');
  const named = path.join(dir, 'named.env');
  fs.writeFileSync(where === 'cwd' ? path.join(dir, '.env') : named, body);
  const url = (p) => pathToFileURL(path.join(ROOT, p)).href;
  const argv = ['node', 'cli', 'scan', '--host', '127.0.0.1', '--plugins', '003', '--ports', '1-2', ...(where === 'cwd' ? [] : ['--env', named])];
  fs.writeFileSync(path.join(dir, 'child.mjs'), [
    `process.on('exit', () => console.log('SENTINEL=' + (process.env.NSA_ENV_SENTINEL ?? 'absent')));`,
    `const { main } = await import(${JSON.stringify(url('cli.mjs'))});`,
    `process.argv = ${JSON.stringify(argv)};`,
    `const absent = () => { throw Object.assign(new Error('absent'), { code: 'ERR_MODULE_NOT_FOUND' }); };`,
    `await main({ resolveEE: absent, importEE: async () => absent() });`,
  ].join('\n'));
  const env = { PATH: process.env.PATH, HOME: dir, NSAUDITOR_LICENSE_KEY: 'not-a-licence',
    NSAUDITOR_LICENSE_STATE_FILE: path.join(dir, 'licence-state.json'), NSA_ALLOW_ALL_HOSTS: '1', SCAN_OUT_PATH: path.join(dir, 'out') };
  const out = await new Promise((resolve) => {
    const child = spawn(process.execPath, [path.join(dir, 'child.mjs')], { cwd: dir, env });
    let text = '';
    child.stdout.on('data', (d) => { text += d; });
    child.stderr.on('data', (d) => { text += d; });
    const t = setTimeout(() => child.kill('SIGKILL'), 60_000);
    child.on('close', () => { clearTimeout(t); resolve(text); });
  });
  await provider.close();
  fs.rmSync(dir, { recursive: true, force: true });
  return { out, hits: provider.hits };
}

test('AI keys in a file passed by --env reach the configured provider (the loopback is live)', { timeout: 90_000 }, async () => {
  const { out, hits } = await driveAi({ where: 'named' });
  assert.match(out, /SENTINEL=loaded/, out.slice(-1500));
  assert.ok(hits.length >= 1 && hits.every((h) => h === 'POST /v1/messages'), `loopback hits: ${hits}; ${out.slice(-800)}`);
});

test('the same AI keys in a working-directory .env set nothing: the provider is never called', { timeout: 90_000 }, async () => {
  const { out, hits } = await driveAi({ where: 'cwd' });
  assert.match(out, /SENTINEL=absent/, out.slice(-1500));
  assert.deepEqual(hits, []);
});
