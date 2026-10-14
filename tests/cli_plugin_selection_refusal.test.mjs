import { withNoDotenv } from './helpers/no_operator_dotenv.mjs';
import './helpers/no_operator_keychain.mjs';   // FIRST: this file imports cli.mjs
// tests/cli_plugin_selection_refusal.test.mjs
// ─────────────────────────────────────────────────────────────────────────────
// AN EXPLICIT --plugins LIST THAT NAMES NO PLUGIN IS REFUSED, BY NAME (Community 1.0.0).
//
// Until 1.0.0 a --plugins token that matched no plugin was dropped without a word, and a list that matched none ran ZERO
// plugins: exit 0, a full artifact set, "Security findings: 0", a Scope line still naming every counted audit, no "not
// tested" line, a run record reading `finished` with `pluginsRequested: []` — and, with --compliance, every in-scope control
// PASS at zero evidence. A typo did it, and so did the help text's own example (`001,003,020`: there is no plugin 020).
// Now every token that names no plugin is NAMED and the run is refused through the flag-refusal path (one [ERROR] line,
// exit 2) before anything is scanned or written; a list that names nothing is refused the same way.
//
// THE PUBLISHED BIN carries the exit code (bin/nsauditor-ai.mjs — the command npm installs), never cli.mjs alone.
// OFFLINE: the target is 192.0.2.1 (RFC 5737) and the one plugin a valid list runs is 060, which declines an IP literal
// without a query.
//
// FOURTH QUADRANT FIRST: a valid list runs exactly what it names, and `all` and an empty value keep their meaning.
// ─────────────────────────────────────────────────────────────────────────────
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const BIN = path.join(HERE, '..', 'bin', 'nsauditor-ai.mjs');
const WORK = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-plugin-selection-'));
after(() => fs.rmSync(WORK, { recursive: true, force: true }));

let n = 0;
/** Run the published bin's scan with `--plugins <spec>` into a fresh --out; return its exit, stderr and every file written. */
function scanWith(spec, extra = []) {
  const out = path.join(WORK, `out-${n += 1}`);
  const env = { ...process.env, AI_ENABLED: 'false' };
  delete env.NSA_ALLOW_ALL_HOSTS;
  delete env.NODE_TEST_CONTEXT;
  const r = spawnSync(process.execPath, [BIN, 'scan', '--host', '192.0.2.1', '--plugins', spec, '--out', out, ...extra],
    { cwd: WORK, env: withNoDotenv(env), encoding: 'utf8', timeout: 120_000 });
  const files = fs.existsSync(out) ? fs.readdirSync(out, { recursive: true }) : [];
  const record = files.find((f) => /^scan_run_.+\.json$/.test(path.basename(f)));
  return { status: r.status, stderr: r.stderr, stdout: r.stdout, files,
    record: record ? JSON.parse(fs.readFileSync(path.join(out, record), 'utf8')) : null };
}
const errorLines = (s) => s.split('\n').filter((l) => l.startsWith('[ERROR]'));
// Imported before the first test() is registered: a top-level await between test() calls lets the runner start, and its
// after() cleanup remove the work directory, before the later tests exist.
const { parseArgs, pluginSelectionRefusal } = await import('../cli.mjs');
const { PluginManager } = await import('../plugin_manager.mjs');
const pm = await PluginManager.create(path.join(HERE, '..', 'plugins'));

// ── FOURTH QUADRANT FIRST: what still runs ───────────────────────────────────────────────────────────────────────────
test('(first) a valid --plugins list runs exactly what it names — through the bin, exit 0, the run record lists it', () => {
  const r = scanWith('060');
  assert.equal(r.status, 0, `exit ${r.status}; stderr: ${r.stderr.slice(-400)}`);
  assert.deepEqual(errorLines(r.stderr), []);
  assert.deepEqual(r.record?.pluginsRequested, ['060'], 'the run record names the plugin the list selected');
  assert.equal(r.record?.status, 'finished');
});

/** parseArgs reads process.argv's shape: the node binary and the script come first. */
const pluginsOf = async (...flags) => (await parseArgs(['node', 'nsauditor-ai', 'scan', '--host', '192.0.2.1', ...flags])).plugins;
test('(first) `all`, the default and an EMPTY value keep their meaning: every plugin, never a refusal', async () => {
  assert.equal(await pluginsOf('--plugins', 'all'), 'all');
  assert.equal(await pluginsOf('--plugins', 'ALL'), 'all');
  // An empty value is read as the bare flag, so the default `all` stands — as before 1.0.0.
  assert.equal(await pluginsOf('--plugins', ''), 'all');
  assert.equal(await pluginsOf(), 'all');
  for (const spec of ['all', undefined]) assert.equal(pluginSelectionRefusal(spec, pm), null, String(spec));
  assert.equal(pluginSelectionRefusal(['060', 'dns security auditor', '003'], pm), null, 'ids and names, any case, all resolve');
});

// ── THE REFUSAL ──────────────────────────────────────────────────────────────────────────────────────────────────────
const REFUSED = [
  { spec: 'nonexistent-plugin', names: ['"nonexistent-plugin"'] },
  { spec: '001,003,020', names: ['"020"'], not: ['"001"', '"003"'] },   // the help text's own example, until 1.0.0
  { spec: '!060', names: ['"!060"'] },
  { spec: '-060', names: ['"-060"'] },
  { spec: 'all,-060', names: ['"-060"', 'alone'] },
  { spec: '003,all', names: ['"all"', 'alone'] },
];
for (const { spec, names, not = [] } of REFUSED) {
  test(`--plugins ${JSON.stringify(spec)} is refused through the bin: exit 2, ONE [ERROR] line naming it, nothing scanned or written`, () => {
    const r = scanWith(spec);
    assert.equal(r.status, 2, `exit ${r.status}; stderr: ${r.stderr.slice(-400)}`);
    const lines = errorLines(r.stderr);
    assert.equal(lines.length, 1, `stderr: ${r.stderr}`);
    for (const nm of names) assert.ok(lines[0].includes(nm), `the refusal does not name ${nm}: ${lines[0]}`);
    for (const nm of not) assert.ok(!lines[0].includes(nm), `the refusal names ${nm}, which resolves: ${lines[0]}`);
    assert.doesNotMatch(r.stderr, /\n\s+at /, 'an operator error printed a stack');
    assert.deepEqual(r.files, [], 'a refused run wrote artifacts');
  });
}

test('a list that names NO plugin at all — ` , ` — is refused through the bin with "no plugin", exit 2, nothing written', () => {
  const r = scanWith(' , ');
  assert.equal(r.status, 2, `exit ${r.status}; stderr: ${r.stderr.slice(-400)}`);
  const lines = errorLines(r.stderr);
  assert.equal(lines.length, 1, r.stderr);
  assert.match(lines[0], /no plugin/);
  assert.deepEqual(r.files, []);
});

test('the refusal also stands under --fail-on: a gate can no longer pass over a run that selected nothing', () => {
  const r = scanWith('nonexistent-plugin', ['--fail-on', 'low']);
  assert.equal(r.status, 2, `exit ${r.status}; stdout: ${r.stdout.slice(-300)}`);
  assert.doesNotMatch(r.stdout, /No findings at or above/);
});

// ── THE HELP TEXT'S OWN EXAMPLE IS A FIXTURE OF THE DEFECT ───────────────────────────────────────────────────────────
test('every plugin id in the --plugins help example names a real plugin', () => {
  const help = spawnSync(process.execPath, [BIN, '--help'], { cwd: WORK, env: withNoDotenv(), encoding: 'utf8' }).stdout;
  const line = help.split('\n').find((l) => /^\s+--plugins\b/.test(l));
  assert.ok(line, 'the help has a --plugins line');
  const example = /e\.g\.\s+([\w,]+)/.exec(line)?.[1];
  assert.ok(example, `the --plugins help line carries an example list: ${line}`);
  const unknown = example.split(',').filter((t) => !pm.findPlugin(t));
  assert.deepEqual(unknown, [], `the help example names no such plugin: ${line.trim()}`);
});
