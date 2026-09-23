// EVERY TEST FILE RUNS, AND NOTHING ELSE IS COUNTED AS ONE — board item 20 (CE 0.2.55).
//
// `npm test` was bare `node --test`. Its default discovery never matched
// `tests/ftp_banner_check.test.verified.mjs`, so three real tests never ran — while the quoted
// `'tests/**/*.mjs'` form would have counted three helper modules as test files. Two procedures,
// two different suite figures, and neither said which it was. The script now states its glob
// (`tests/**/*.test.mjs`), the orphan's one unique case lives in the file that runs, and this census
// fails the day a file under tests/ is neither a test the glob runs nor a declared helper.
// ⚠️ FOURTH QUADRANT FIRST: the classifier is driven on a synthetic list before it judges the tree, so a
// classifier that calls everything a test cannot pass.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const GLOB = 'tests/**/*.test.mjs';

/** 'test' (the glob runs it) · 'helper' (declared: under tests/helpers/, or a leading underscore) · 'orphan'. */
function classify(rel) {
  if (/\.test\.mjs$/.test(rel)) return 'test';
  if (rel.startsWith('tests/helpers/') || path.basename(rel).startsWith('_')) return 'helper';
  return 'orphan';
}

test('FOURTH QUADRANT — the classifier tells a test, a helper and an orphan apart', () => {
  assert.equal(classify('tests/foo.test.mjs'), 'test');
  assert.equal(classify('tests/helpers/no_operator_keychain.mjs'), 'helper');
  assert.equal(classify('tests/_tls_stub.mjs'), 'helper');
  assert.equal(classify('tests/ftp_banner_check.test.verified.mjs'), 'orphan', 'the measured instance');
  assert.equal(classify('tests/notes.mjs'), 'orphan');
});

test('every .mjs under tests/ is a test the glob runs or a declared helper — no orphans', () => {
  const all = [];
  const walk = (d) => {
    for (const e of fs.readdirSync(d, { withFileTypes: true })) {
      const p = path.join(d, e.name);
      if (e.isDirectory()) walk(p); else if (e.name.endsWith('.mjs')) all.push(path.relative(ROOT, p).split(path.sep).join('/'));
    }
  };
  walk(path.join(ROOT, 'tests'));
  const orphans = all.filter((f) => classify(f) === 'orphan');
  assert.deepEqual(orphans, [], 'a file under tests/ that the suite never runs — rename it to *.test.mjs, or declare it a helper');
  assert.ok(all.filter((f) => classify(f) === 'test').length > 100, 'the census lost its subject');
});

test('the test script STATES its glob — a suite figure names the procedure that produced it', () => {
  const script = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8')).scripts.test;
  assert.equal(script, `node --test '${GLOB}'`, 'the glob is quoted so node, not the shell, expands it');
});
