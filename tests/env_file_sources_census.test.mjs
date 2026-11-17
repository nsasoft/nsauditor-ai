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
// (3) EVERY QUOTED `.env` PATH IN SHIPPED CODE IS DECLARED. Census (2) blanks quoted paths before it reads a line, and
//     census (1) has no token for a hand-rolled loader (read '.env', assign each key into process.env), so neither can
//     see one. Each quoted literal is therefore declared, file → count, with its reason: an equality ratchet.
//
// (4) THE MCP SERVER'S CUSTOM-PLUGIN BASE IS DECIDED BY IMPORT ORDER, so the order is pinned: plugin_discovery.mjs
//     captures HOME when it is first imported. The CLI imports it statically (before main() applies --env); the MCP
//     server imports it at its first tool call, AFTER NSA_ENV_FILE is applied — as at 1.1.1, whose prefixes were taken
//     at that same moment. A static import added to mcp_server.mjs would move the MCP base silently, with every
//     behavioural test still green.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

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

// ── (3) quoted .env path literals: a DECLARED equality ratchet ────────────────────────────────────────────────────────
// Quotes are ', " and ` (a template path such as `${dir}/.env` is the obvious variant of '.env'), so a comment code span
// counts too. Stated limit: a path built by concatenation ('.e' + 'nv') or held in a variable is invisible here; the
// behavioural guard for that is the real-binary file (working_directory_env_file_not_loaded), and it covers the CLI only.
const ENV_PATH_LITERAL = /([`'"])[^`'"\s]*\.env\1/g;
export const ENV_PATH_LITERALS = new Map([
  ['cli.mjs', [3, "the working-directory hint lstat()s path.join(cwd, '.env') and never opens it; two comment code spans name that file"]],
  ['plugins/050_tribe_health.mjs', [1, 'a URL path the plugin requests on a TARGET ("/.env" exposed over HTTP), not a local file']],
  ['utils/license.mjs', [2, 'the home file ($XDG_CONFIG_HOME/nsauditor/.env or ~/.nsauditor/.env): the licence key is read from it and written to it']],
  ['utils/mcp_auth.mjs', [2, 'the home file ($XDG_CONFIG_HOME/nsauditor/.env or ~/.nsauditor/.env): the MCP auth key is read from it']],
]);

/** [file, text][] → Map(file → count of quoted .env path literals), files with none omitted. */
export function envPathLiteralCounts(entries) {
  const m = new Map();
  for (const [f, text] of entries) { const n = [...text.matchAll(ENV_PATH_LITERAL)].length; if (n) m.set(f, n); }
  return m;
}
/** Differences between measured and declared, as readable lines; [] when equal. */
export function envPathLiteralDiff(measured, declared = ENV_PATH_LITERALS) {
  const out = [];
  for (const [f, n] of measured) {
    const d = declared.get(f)?.[0];
    if (d === undefined) out.push(`${f}: ${n} quoted .env path literal(s), none declared`);
    else if (d !== n) out.push(`${f}: ${n} quoted .env path literal(s), ${d} declared`);
  }
  for (const [f, [d]] of declared) if (!measured.has(f)) out.push(`${f}: 0 quoted .env path literals, ${d} declared`);
  return out;
}

test('(3) ACCEPT first: the declared literals measured from their own lines read equal', () => {
  const lines = [['cli.mjs', "lstatSync(path.join(cwd, '.env')); /* `.env` */ // `.env`"], ['plugins/050_tribe_health.mjs', '{ path: "/.env" }'],
    ['utils/license.mjs', "join(a, '.env'); join(b, '.env');"], ['utils/mcp_auth.mjs', "join(a, '.env'); join(b, '.env');"]];
  assert.deepEqual(envPathLiteralDiff(envPathLiteralCounts(lines)), []);
});

for (const [label, rel, src] of [
  ['hand-rolled loader in mcp_server.mjs', 'mcp_server.mjs',
    "for (const l of fs.readFileSync('.env', 'utf8').split('\\n')) { const [k, v] = l.split('='); process.env[k] = v; }\n"],
  ['template-literal path', 'utils/x.mjs', 'const t = fs.readFileSync(`${process.cwd()}/.env`, "utf8");\n'],
]) {
  test(`(3) a planted ${label} is an undeclared literal`, () => {
    assert.deepEqual(envPathLiteralDiff(new Map([...envPathLiteralCounts([[rel, src]])]), new Map()), [`${rel}: 1 quoted .env path literal(s), none declared`]);
    // and against the real table it is still a difference (it adds to a file, or names an undeclared one)
    assert.ok(envPathLiteralDiff(new Map([...ENV_PATH_LITERALS].map(([f, [n]]) => [f, n]).concat([[rel, 1]]))).length >= 1);
  });
}

test('(3) a declared literal that is gone, or a count that moved, is a difference too', () => {
  const m = new Map([...ENV_PATH_LITERALS].map(([f, [n]]) => [f, n]));
  m.delete('utils/mcp_auth.mjs');
  m.set('utils/license.mjs', 3);
  assert.deepEqual(envPathLiteralDiff(m), ['utils/license.mjs: 3 quoted .env path literal(s), 2 declared', 'utils/mcp_auth.mjs: 0 quoted .env path literals, 2 declared']);
});

test('(3) the declared table is visible and live: each entry exists, ships and states a reason', () => {
  for (const [f, [n, why]] of ENV_PATH_LITERALS) {
    assert.ok(fs.existsSync(path.join(ROOT, f)) && shipped().includes(f), `stale entry ${f}`);
    assert.ok(Number.isInteger(n) && n > 0 && why.length > 20, `${f}: a count and a reason`);
  }
});

test('(3) every quoted .env path literal in shipped code is declared, with its count', () => {
  const files = shipped().filter((f) => CODE.test(f));
  assert.deepEqual(envPathLiteralDiff(envPathLiteralCounts(files.map((f) => [f, fs.readFileSync(path.join(ROOT, f), 'utf8')]))), []);
});

// ── (4) the static import closure decides when plugin_discovery.mjs captures HOME ─────────────────────────────────────
// Static forms only (`import … from '…'`, `import '…'`, `export … from '…'`), relative specifiers only; `import(` is
// dynamic and is not followed — that is the point.
const STATIC_IMPORT = /^\s*(?:import|export)\s+(?:[^'"`;]*?\s+from\s+)?(['"])(\.{1,2}\/[^'"]+)\1/gm;
export function staticClosure(entry, read = (f) => fs.readFileSync(path.join(ROOT, f), 'utf8')) {
  const seen = new Set();
  const stack = [entry];
  while (stack.length) {
    const f = stack.pop();
    if (seen.has(f)) continue;
    seen.add(f);
    let text;
    try { text = read(f); } catch { continue; }
    for (const m of text.matchAll(STATIC_IMPORT)) stack.push(path.posix.normalize(path.posix.join(path.posix.dirname(f), m[2])));
  }
  return seen;
}

test('(4) ACCEPT first (positive control): the CLI reaches plugin_discovery.mjs by static imports, so it captures HOME before --env', () => {
  const c = staticClosure('cli.mjs');
  assert.ok(c.size > 10, `the walker saw ${c.size} files from cli.mjs; it is not reading imports`);
  assert.ok(c.has('utils/plugin_discovery.mjs'), 'cli.mjs no longer imports plugin discovery statically: its HOME capture would move after --env');
});

test('(4) the walker follows bare, named and re-export forms and ignores import()', () => {
  const files = { 'a.mjs': "import './b.mjs';\nimport { x } from \"./c.mjs\";\nexport { y } from './d/e.mjs';\nconst m = await import('./f.mjs');\n",
    'b.mjs': '', 'c.mjs': '', 'd/e.mjs': "import z from '../g.mjs';\n", 'g.mjs': '', 'f.mjs': '' };
  assert.deepEqual([...staticClosure('a.mjs', (f) => { if (!(f in files)) throw new Error(f); return files[f]; })].sort(),
    ['a.mjs', 'b.mjs', 'c.mjs', 'd/e.mjs', 'g.mjs']);
});

test('(4) the MCP server does NOT reach plugin_discovery.mjs by static imports: its base stays the post-NSA_ENV_FILE HOME, as at 1.1.1', () => {
  const c = staticClosure('mcp_server.mjs');
  assert.ok(c.size > 5, `the walker saw ${c.size} files from mcp_server.mjs`);
  assert.equal(c.has('utils/plugin_discovery.mjs'), false,
    'mcp_server.mjs now imports plugin discovery statically, so the MCP custom-plugin base moved to the HOME before NSA_ENV_FILE '
    + '(stricter than 1.1.1, unannounced). If that is intended, it is a decision with its own CHANGELOG line; update this row with it.');
});
