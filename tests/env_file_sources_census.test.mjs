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
// path, not an instruction to a user; it is blanked before the line is read. Stated limit: a one-word quoted
// instruction would be blanked with it.
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
