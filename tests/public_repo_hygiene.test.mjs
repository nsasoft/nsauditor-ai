// tests/public_repo_hygiene.test.mjs
// ─────────────────────────────────────────────────────────────────────────────
// THIS REPOSITORY IS PUBLIC (github.com/nsasoft/nsauditor-ai), AND WHAT IT TRACKS IS WHAT IT PUBLISHES. Found 2026-10-12 on
// the operator's question: a planning skill had written its spec and plan into docs/superpowers/ of the repo it was working
// in, and both rode to origin/main in d3e5d7d (2026-06-05) — process notes addressed to "agentic workers" and
// Enterprise-side design, in the Community repo, linked from nowhere. Removed from the tree (nothing in them warranted a
// history rewrite). Plans and specs for Community work are written under the Enterprise tasks/ area or a scratchpad.
//
// KEYED ON THE TRACKED LIST (`git ls-files`), NEVER ON .gitignore. A .gitignore rule does not untrack a file already
// tracked — the Enterprise repo's deploy/marketplace/.env was listed in .gitignore twice and pushed anyway.
// FOURTH QUADRANT FIRST: the tree as it stands passes, .env.example is allowed, and a TRACKED planning file fails by name
// even under a .gitignore rule that names it.
// ─────────────────────────────────────────────────────────────────────────────
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

/** What a public repo must never track: [rule, why]. */
export const NEVER_TRACKED = [
  [/^docs\/superpowers\//, 'a planning skill\'s specs and plans — process notes, not documentation'],
  [/^\.claude\//, 'a coding assistant\'s local settings'],
  [/^tasks\//, 'the Enterprise repo\'s working ledgers belong there, not here'],
  [/(^|\/)CLAUDE\.md$/, 'assistant instructions'],
  [/\.jsonl$/, 'session transcripts and scan-history logs'],
  [/(^|\/)\.env$/, 'a live environment file (.env.example is the documented template and is allowed)'],
];

/** The tracked paths that break a NEVER_TRACKED rule, each with its reason. */
export function forbiddenTracked(paths) {
  const out = [];
  for (const p of paths) for (const [re, why] of NEVER_TRACKED) if (re.test(p)) { out.push(`${p} — ${why}`); break; }
  return out;
}

/** `git ls-files` of `dir`, refusing (never skipping) when it is not a git work tree. */
function tracked(dir) {
  const r = spawnSync('git', ['-C', dir, 'ls-files', '-z'], { encoding: 'utf8' });
  assert.equal(r.status, 0, `git ls-files failed in ${dir} — this guard cannot measure, and it does not skip: ${r.stderr}`);
  return r.stdout.split('\0').filter(Boolean);
}

test('(first) the tree as it stands tracks nothing a public repo must not publish — and .env.example is allowed', () => {
  const list = tracked(ROOT);
  assert.ok(list.length > 100, `git ls-files returned ${list.length} paths — the reader is broken, not the repo`);
  assert.deepEqual(forbiddenTracked(list), []);
  assert.deepEqual(forbiddenTracked(['.env.example', 'docs/openai.md', 'README.md', 'tests/fixtures/x.json']), []);
});

test('each rule names its own shape — and only its own', () => {
  const planted = ['docs/superpowers/plans/2026-10-12-x.md', '.claude/settings.json', 'tasks/todo.md', 'docs/CLAUDE.md',
    'out/scan_history.jsonl', 'deploy/.env'];
  assert.equal(forbiddenTracked(planted).length, planted.length, `a planted path was not caught: ${forbiddenTracked(planted)}`);
  assert.deepEqual(forbiddenTracked(['docs/superpowers.md', 'claude.md.example', 'tasks.md', '.environment', 'x.json']), []);
});

test('a TRACKED planning file fails by name even when .gitignore names it — the list, not the ignore rules, is the subject', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-hygiene-'));
  try {
    const git = (...a) => {
      const r = spawnSync('git', ['-C', dir, ...a], { encoding: 'utf8', env: { ...process.env, GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_SYSTEM: '/dev/null' } });
      assert.equal(r.status, 0, `git ${a.join(' ')}: ${r.stderr}`);
    };
    git('init', '-q');
    fs.mkdirSync(path.join(dir, 'docs', 'superpowers', 'plans'), { recursive: true });
    fs.writeFileSync(path.join(dir, 'docs', 'superpowers', 'plans', 'p.md'), '# plan\n');
    fs.writeFileSync(path.join(dir, 'README.md'), '# r\n');
    git('add', '-A');
    fs.writeFileSync(path.join(dir, '.gitignore'), 'docs/superpowers/\n');   // added AFTER the file was tracked
    assert.deepEqual(forbiddenTracked(tracked(dir)).map((x) => x.split(' — ')[0]), ['docs/superpowers/plans/p.md']);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
