// tests/env_file_sources_census.test.mjs
// TWO CENSUSES OVER WHAT THE TARBALL SHIPS (`npm pack --dry-run --json`), both deny-by-default with a VISIBLE exempt set:
//
// (1) NO SHIPPED CODE LOADS AN ENV FILE IMPLICITLY. Outside the exempt files, no shipped .mjs/.js/.cjs contains the
//     tokens `dotenv`, `loadEnvFile`, `env-file` or `DOTENV_CONFIG` at all — comments and strings included, because a
//     census keyed on the known-wrong spellings reports on its pattern list. Inside an exempt file the only allowed
//     uses are the default import and `dotenv.parse(` (a read of ONE file the user named, never a load into the
//     environment). Stated limit: code files only; package.json declares the dependency and markdown is census (2)'s.
//
// (2) NO SHIPPED LINE TELLS A USER TO RELY ON A BARE `.env`. Over the shipped files plus README.md, every line naming a
//     bare `.env` also names a way the CLI actually reads one: `--env`, `--env-file` (Node's own flag), `NSA_ENV_FILE`
//     (the MCP server's) or `~/.nsauditor/`. A shipped instruction that names a file the tool no longer reads is an
//     instruction that does not work.
//
// (3) EVERY QUOTED `.env`-FAMILY PATH IN SHIPPED CODE IS DECLARED. Census (2) blanks quoted paths before it reads a
//     line, and census (1) has no token for a hand-rolled loader (read '.env', assign each key into process.env), so
//     neither can see one. Each literal is declared by the line that carries it, with its reason: an identity ratchet.
//
// (4) THE MCP SERVER'S CUSTOM-PLUGIN BASE IS DECIDED BY IMPORT ORDER, so the order is pinned: plugin_discovery.mjs
//     captures HOME when it is first imported. The CLI imports it statically (before main() applies --env); the MCP
//     server imports it at its first tool call, AFTER NSA_ENV_FILE is applied — as at 1.1.1, whose prefixes were taken
//     at that same moment. An import added to mcp_server.mjs — static, or a dynamic one at module scope — would move
//     the MCP base silently; a behavioural row and a static walk from every bin entry pin it.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { execFileSync, spawnSync } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { withNoDotenv } from './helpers/no_operator_dotenv.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

let packList = null;
function shipped() {
  if (packList) return packList;
  const out = execFileSync('npm', ['pack', '--dry-run', '--json', '--ignore-scripts', '--loglevel=error'],
    { cwd: ROOT, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] });
  packList = JSON.parse(out)[0].files.map((f) => f.path);
  assert.ok(packList.length > 50 && packList.includes('cli.mjs'), `implausible pack list (${packList.length} files)`);
  return packList;
}

// ── (1) implicit env-file loading ─────────────────────────────────────────────────────────────────────────────────────
const CODE = /\.(?:mjs|js|cjs)$/;
const TOKENS = [/dotenv/g, /loadEnvFile/g, /env-file/g, /DOTENV_CONFIG/g];
export const LOADER_EXEMPT = new Map([
  ['utils/env_loader.mjs', 'parses the ONE file passed with --env (dotenv.parse); main() applies it'],
  ['utils/license.mjs', 'reads the single licence key from ~/.nsauditor/.env (dotenv.parse); writes that file on activation'],
  ['utils/mcp_auth.mjs', 'reads the single MCP auth key from ~/.nsauditor/.env (dotenv.parse)'],
  ['utils/mcp_env_file.mjs', 'parses the file the MCP server is given by NSA_ENV_FILE (dotenv.parse)'],
]);
const ALLOWED_IN_EXEMPT = [/import\s+dotenv\s+from\s+['"]dotenv['"]/g, /\bdotenv\.parse\(/g];

/** Hits for one file: [{ token, line }]. Exempt files have their two allowed forms blanked first. */
export function loaderTokenHits(rel, text, exempt = LOADER_EXEMPT) {
  let t = text;
  if (exempt.has(rel)) for (const re of ALLOWED_IN_EXEMPT) t = t.replace(re, (m) => ' '.repeat(m.length));
  const hits = [];
  for (const re of TOKENS) for (const m of t.matchAll(re)) hits.push({ token: m[0], line: t.slice(0, m.index).split('\n').length });
  return hits;
}

test('(1) ACCEPT first: an exempt file using only the default import and dotenv.parse( is clean', () => {
  const src = "import dotenv from 'dotenv';\nconst kv = dotenv.parse(buf);\n";
  assert.deepEqual(loaderTokenHits('utils/license.mjs', src), []);
});

for (const [label, rel, src] of [
  ["import 'dotenv/config'", 'cli.mjs', "import 'dotenv/config';\n"],
  ["require('dotenv').config()", 'x.cjs', "require('dotenv').config();\n"],
  ['a named config import', 'x.mjs', "import { config } from 'dotenv';\nconfig();\n"],
  ['process.loadEnvFile() — reads ./.env with no argument on Node 24', 'x.mjs', 'process.loadEnvFile();\n'],
  ['a --env-file shebang', 'bin/x.mjs', '#!/usr/bin/env -S node --env-file=.env\n'],
  // split so this FIXTURE string is not itself read as a child-process call by no_operator_dotenv_census
  ['a --env-file spawn argument', 'x.mjs', 'sp' + "awn(process.execPath, ['--env-file=.env', 'main.mjs']);\n"],
  ['DOTENV_CONFIG_PATH', 'x.mjs', 'process.env.DOTENV_CONFIG_PATH = p;\n'],
  ['dotenv.config( inside an EXEMPT file', 'utils/license.mjs', "import dotenv from 'dotenv';\ndotenv.config();\n"],
]) {
  test(`(1) a planted ${label} is a hit`, () => {
    assert.ok(loaderTokenHits(rel, src).length >= 1, `${label} read clean`);
  });
}

test('(1) the EXEMPT set is visible and live: each entry exists, ships, and states a reason', () => {
  for (const [f, why] of LOADER_EXEMPT) {
    assert.ok(fs.existsSync(path.join(ROOT, f)), `stale exemption ${f}`);
    assert.ok(shipped().includes(f), `${f} does not ship — drop it from the exempt set`);
    assert.ok(why.length > 20, `${f}: an exemption states its reason`);
  }
});

test('(1) no shipped code file loads an env file implicitly', () => {
  const files = shipped().filter((f) => CODE.test(f));
  const hits = files.flatMap((f) => loaderTokenHits(f, fs.readFileSync(path.join(ROOT, f), 'utf8')).map((h) => `${f}:${h.line} ${h.token}`));
  assert.deepEqual(hits, []);
});

// ── (2) bare `.env` instructions ──────────────────────────────────────────────────────────────────────────────────────
const BARE_ENV = /(?<![\w-])\.env(?![\w.-])/;
const NAMES_A_SOURCE = /--env\b|--env-file|NSA_ENV_FILE|\.nsauditor[\\/]/;   // ~/.nsauditor/ · %USERPROFILE%\.nsauditor\
// A quoted PATH LITERAL with no space in it ('.env' as a join() segment, "/.env" as a probed URL path) is code naming a
// path, not an instruction to a user; it is blanked before the line is read. Stated limit: what is blanked is EVERY
// quoted `.env` path, including one a loader would use and a one-word quoted instruction — census (3) declares each one
// in shipped code, so a new literal cannot hide behind this blanking.
const PATH_LITERAL = /(['"])[^'"\s]*\.env\1/g;
export const MENTION_EXEMPT = new Map([
  ['CHANGELOG.md', 'release history: records what earlier versions did, in the tense of those versions'],
]);

export function bareEnvLines(rel, text) {
  if (MENTION_EXEMPT.has(rel)) return [];
  return text.split('\n').flatMap((l, i) => {
    const t = l.replace(PATH_LITERAL, ' ');
    return BARE_ENV.test(t) && !NAMES_A_SOURCE.test(t) ? [`${rel}:${i + 1}`] : [];
  });
}

test('(2) ACCEPT first: a line naming .env beside --env, ~/.nsauditor/ or --env-file is clean; prod.env and .env.example are not bare', () => {
  for (const l of ['pass --env ./.env to load it', 'kept in ~/.nsauditor/.env (mode 0600)', 'node --env-file=.env cli.mjs',
    'a per-account file ~/envs/prod.env', 'copy .env.example', "return join(homedir(), '.nsauditor', '.env');",
    '{ path: "/.env", severity: CRITICAL }', 'Windows:  %USERPROFILE%\\.nsauditor\\.env (mode 0600)']) assert.deepEqual(bareEnvLines('README.md', l), [], l);
});

test('(2) a planted bare-.env instruction is a hit', () => {
  assert.deepEqual(bareEnvLines('README.md', 'ok\nSet X=true in .env\n'), ['README.md:2']);
  assert.deepEqual(bareEnvLines('x.mjs', '"Set X=true in .env to probe remote hosts."'), ['x.mjs:1'], 'a quoted SENTENCE is not a path literal');
});

test('(2) the EXEMPT set is visible: each entry exists and states a reason', () => {
  for (const [f, why] of MENTION_EXEMPT) {
    assert.ok(fs.existsSync(path.join(ROOT, f)), `stale exemption ${f}`);
    assert.ok(why.length > 20);
  }
});

test('(2) no shipped line (and no README line) tells a user to rely on a bare .env', () => {
  const files = [...new Set([...shipped(), 'README.md'])].filter((f) => /\.(?:mjs|js|cjs|md|json|txt)$/.test(f));
  const hits = files.flatMap((f) => bareEnvLines(f, fs.readFileSync(path.join(ROOT, f), 'utf8')));
  assert.deepEqual(hits, []);
});

// ── (3) quoted .env-family path literals: a DECLARED identity ratchet ─────────────────────────────────────────────────
// A literal is a quoted (' " `) token ending in `.env` plus any name suffix (`.env.local`, `.ENV`), case-insensitive; a
// template path such as `${dir}/.env` is the obvious variant of '.env', so backtick is a quote here and a comment code
// span counts too. `process.env.X` is the environment object, not a file, and is not a literal. IDENTITY, not a count:
// each literal is declared by the trimmed line that carries it, compared as a multiset, so rewording a declared line
// and adding a loader elsewhere in the same file is a difference. Stated limit: a path built by concatenation
// ('.e' + 'nv') or held in a variable is invisible here; the behavioural guard for that is the real-binary file
// (working_directory_env_file_not_loaded), and it covers the CLI only.
const ENV_PATH_LITERAL = /([`'"])[^`'"\s]*(?<!process)\.env[\w.-]*\1/gi;
const HOME_FILE = 'the home file ($XDG_CONFIG_HOME/nsauditor/.env or ~/.nsauditor/.env)';
export const ENV_PATH_LITERALS = new Map([
  ['cli.mjs', { reason: "the working-directory hint lstat()s path.join(cwd, '.env') and never opens it; two comment code spans name that file", lines: [
    '* The one stderr line for a working-directory `.env` (never read; only --env names a file), or null. Community 1.1.2.',
    "const candidate = path.join(cwd, '.env');",
    '// ON TOP (override-on) before license + dispatch. A working-directory `.env` is never read unless passed with --env',
  ] }],
  ['plugins/050_tribe_health.mjs', { reason: 'a URL path the plugin requests on a TARGET ("/.env" exposed over HTTP), not a local file', lines: [
    '{ path: "/.env",                 severity: SEVERITY.CRITICAL, desc: "Environment file" },',
  ] }],
  ['utils/license.mjs', { reason: `${HOME_FILE}: the licence key is read from it and written to it`, lines: [
    "return join(process.env.XDG_CONFIG_HOME, 'nsauditor', '.env');",
    "return join(homedir(), '.nsauditor', '.env');",
  ] }],
  ['utils/mcp_auth.mjs', { reason: `${HOME_FILE}: the MCP auth key is read from it`, lines: [
    "return join(process.env.XDG_CONFIG_HOME, 'nsauditor', '.env');",
    "return join(homedir(), '.nsauditor', '.env');",
  ] }],
]);

/** [file, text][] → Map(file → sorted trimmed lines, one per literal), files with none omitted. */
export function envPathLiteralLines(entries) {
  const m = new Map();
  for (const [f, text] of entries) {
    const lines = text.split('\n');
    const hits = [...text.matchAll(ENV_PATH_LITERAL)].map((x) => lines[text.slice(0, x.index).split('\n').length - 1].replace(/\r$/, '').trim());
    if (hits.length) m.set(f, hits.sort());
  }
  return m;
}
/** Multiset differences between measured and declared, as readable lines; [] when equal. */
export function envPathLiteralDiff(measured, declared = ENV_PATH_LITERALS) {
  const out = [];
  for (const f of [...new Set([...measured.keys(), ...declared.keys()])].sort()) {
    const have = [...(measured.get(f) ?? [])];
    const want = [...(declared.get(f)?.lines ?? [])];
    for (const l of [...have]) { const i = want.indexOf(l); if (i >= 0) { want.splice(i, 1); have.splice(have.indexOf(l), 1); } }
    for (const l of have) out.push(`${f}: undeclared literal on: ${l}`);
    for (const l of want) out.push(`${f}: declared literal not found: ${l}`);
  }
  return out;
}
const declaredAsEntries = () => [...ENV_PATH_LITERALS].map(([f, { lines }]) => [f, lines.join('\n')]);

test('(3) ACCEPT first: the declared lines, measured as files, read equal', () => {
  assert.deepEqual(envPathLiteralDiff(envPathLiteralLines(declaredAsEntries())), []);
});

test('(3) not literals: process.env.X in a code span or a string, and a .env word inside a sentence', () => {
  assert.deepEqual([...envPathLiteralLines([['x.mjs', "// reads `process.env.SCAN_OUT_PATH`\nconst k = 'process.env.HOME';\nconst s = \"put it in .env please\";\n"]])], []);
});

for (const [label, rel, src] of [
  ['hand-rolled loader in mcp_server.mjs', 'mcp_server.mjs',
    "for (const l of fs.readFileSync('.env', 'utf8').split('\\n')) { const [k, v] = l.split('='); process.env[k] = v; }"],
  ['template-literal path', 'utils/x.mjs', 'const t = fs.readFileSync(`${process.cwd()}/.env`, "utf8");'],
  ["'.env.local' loader", 'mcp_server.mjs', "const t = fs.readFileSync('.env.local', 'utf8');"],
  ["upper-case '.ENV'", 'utils/x.mjs', "const t = fs.readFileSync('./.ENV', 'utf8');"],
]) {
  test(`(3) a planted ${label} is an undeclared literal`, () => {
    assert.deepEqual(envPathLiteralDiff(envPathLiteralLines([...declaredAsEntries(), [rel, src]])), [`${rel}: undeclared literal on: ${src.trim()}`]);
  });
}

test('(3) a SWAP inside one file is a difference: a declared comment line reworded and a loader added keeps the count, not the identity', () => {
  const cli = ENV_PATH_LITERALS.get('cli.mjs').lines;
  const swapped = [cli[0].replace('`.env`', 'env file'), cli[1], cli[2], "process.loadEnvVars?.(fs.readFileSync('.env', 'utf8'));"];
  const entries = declaredAsEntries().map(([f, t]) => (f === 'cli.mjs' ? [f, swapped.join('\n')] : [f, t]));
  assert.deepEqual(envPathLiteralDiff(envPathLiteralLines(entries)), [
    "cli.mjs: undeclared literal on: process.loadEnvVars?.(fs.readFileSync('.env', 'utf8'));",
    `cli.mjs: declared literal not found: ${cli[0]}`,
  ]);
});

test('(3) the declared table is visible and live: each entry exists, ships and states a reason', () => {
  for (const [f, { lines, reason }] of ENV_PATH_LITERALS) {
    assert.ok(fs.existsSync(path.join(ROOT, f)) && shipped().includes(f), `stale entry ${f}`);
    assert.ok(lines.length > 0 && reason.length > 20, `${f}: lines and a reason`);
  }
});

test('(3) every quoted .env-family literal in shipped code is declared, by the line that carries it', () => {
  const files = shipped().filter((f) => CODE.test(f));
  assert.deepEqual(envPathLiteralDiff(envPathLiteralLines(files.map((f) => [f, fs.readFileSync(path.join(ROOT, f), 'utf8')]))), []);
});

// ── (4) when plugin_discovery.mjs captures HOME: the MCP path behaviourally, every bin statically ──────────────────────
// The behavioural row is the guard: a child sets HOME=A, imports the module, sets HOME=B, imports plugin_discovery.mjs
// and asks for a directory under B with the DEFAULT base. Stated limit: it covers MODULE EVALUATION only, not the
// stretch inside startStdioServer() before NSA_ENV_FILE is applied (that needs an authorised server process).
// The static walk, from every `bin` entry in package.json, is the row that NAMES which import did it. It follows
// `… from '…'` and `import '…'` with relative specifiers anywhere in the text (a comment saying `from './x'` is
// followed too — noise, never a miss); `import(` is dynamic and is not followed, which is the point.
function baseAfterImporting(first) {
  const dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-importorder-')));
  try {
    const A = path.join(dir, 'A');
    const B = path.join(dir, 'B');
    for (const d of [A, path.join(B, 'p')]) fs.mkdirSync(d, { recursive: true });
    fs.writeFileSync(path.join(dir, 'child.mjs'), [
      'const [first, disc, A, B, bp] = process.argv.slice(2);',
      'process.env.HOME = A;',
      "if (first !== 'none') await import(first);",
      'process.env.HOME = B;',
      'const d = await import(disc);',
      "process.stdout.write('DECISION=' + JSON.stringify(d.customPluginDirDecision(bp)) + '\\n');",
      'process.exit(0);',
    ].join('\n'));
    const url = (p) => pathToFileURL(path.join(ROOT, p)).href;
    const r = spawnSync(process.execPath, [path.join(dir, 'child.mjs'), first === 'none' ? 'none' : url(first), url('utils/plugin_discovery.mjs'), A, B, path.join(B, 'p')],
      { cwd: dir, env: withNoDotenv({ PATH: process.env.PATH, HOME: A, NSAUDITOR_LICENSE_STATE_FILE: path.join(dir, 'ls.json') }), encoding: 'utf8', timeout: 60_000 });
    const m = /^DECISION=(.*)$/m.exec(r.stdout ?? '');
    assert.ok(m, `the child did not report a decision (exit ${r.status}): ${(r.stderr ?? '').slice(-600)}`);
    return JSON.parse(m[1]);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
}

test('(4) ACCEPT first: importing the MCP server module leaves the base unset, so a HOME set after it is the base (as at 1.1.1)', { timeout: 90_000 }, () => {
  assert.equal(baseAfterImporting('mcp_server.mjs').ok, true,
    'importing mcp_server.mjs captured HOME: the MCP custom-plugin base moved to the HOME before NSA_ENV_FILE (stricter than 1.1.1, '
    + 'unannounced). If intended, it is a decision with its own CHANGELOG line; update this row with it.');
});

test('(4) positive control: importing cli.mjs first captures HOME, so the later HOME is NOT the base', { timeout: 90_000 }, () => {
  assert.deepEqual(baseAfterImporting('cli.mjs'), { ok: false, reason: 'outside home' });
});

const STATIC_SPECIFIER = /\b(?:from|import)\s*(['"])(\.{1,2}\/[^'"\n]+)\1/g;
export function staticClosure(entry, read = (f) => fs.readFileSync(path.join(ROOT, f), 'utf8')) {
  const seen = new Set();
  const stack = [entry];
  while (stack.length) {
    const f = stack.pop();
    if (seen.has(f)) continue;
    seen.add(f);
    let text;
    try { text = read(f); } catch { continue; }
    for (const m of text.matchAll(STATIC_SPECIFIER)) stack.push(path.posix.normalize(path.posix.join(path.posix.dirname(f), m[2])));
  }
  return seen;
}

test('(4) the walker follows bare, named, multi-line (with an apostrophe in a comment) and re-export forms, and ignores import()', () => {
  const files = { 'a.mjs': "import './b.mjs';\nimport { x } from \"./c.mjs\";\nexport { y } from './d/e.mjs';\nconst m = await import('./f.mjs');\n"
      + "import {\n  // don't drop\n  w,\n} from './h.mjs';\n",
    'b.mjs': '', 'c.mjs': '', 'd/e.mjs': "import z from '../g.mjs';\n", 'g.mjs': '', 'f.mjs': '', 'h.mjs': '' };
  assert.deepEqual([...staticClosure('a.mjs', (f) => { if (!(f in files)) throw new Error(f); return files[f]; })].sort(),
    ['a.mjs', 'b.mjs', 'c.mjs', 'd/e.mjs', 'g.mjs', 'h.mjs']);
});

// DECLARED per bin: does its static closure reach plugin_discovery.mjs? A new bin fails until it is declared here.
const BIN_REACHES_DISCOVERY = { 'nsauditor-ai': true, 'nsauditor-ai-mcp': false };
test('(4) each bin\'s static closure reaches plugin_discovery.mjs exactly as declared (the CLI yes, the MCP server no)', () => {
  const bins = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8')).bin;
  assert.deepEqual(Object.keys(bins).sort(), Object.keys(BIN_REACHES_DISCOVERY).sort(), 'a bin was added or removed: declare it');
  for (const [name, file] of Object.entries(bins)) {
    const c = staticClosure(path.posix.normalize(file));
    assert.ok(c.size > 3, `the walker saw ${c.size} files from ${file}`);
    assert.equal(c.has('utils/plugin_discovery.mjs'), BIN_REACHES_DISCOVERY[name],
      `${name} (${file}): static closure ${c.has('utils/plugin_discovery.mjs') ? 'reaches' : 'does not reach'} utils/plugin_discovery.mjs`);
  }
});
