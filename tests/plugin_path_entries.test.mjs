// tests/plugin_path_entries.test.mjs
// A CUSTOM PLUGIN DIRECTORY (NSAUDITOR_PLUGIN_PATH, colon-separated) LOADS ONLY WHEN IT IS: non-empty · absolute as
// written (`~/x` is relative — no expansion) · a real directory · strictly under $HOME (HOME itself and an unset HOME
// refuse; so does a sibling whose name merely extends HOME's). Every refusal is named on stderr with a reason from a
// CLOSED set and its advice; every loaded directory is named with its count. The base is the HOME the process STARTED
// with, captured when the module is imported, so an env file applied later cannot move it (the real-binary arm of that
// is in working_directory_env_file_not_loaded.test.mjs). These in-process tests pass `home` explicitly.
//
// Namespace import on purpose: a named import of an export the tree does not yet have fails the whole file at link
// time, and a before-fix run would then measure nothing.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import * as discovery from '../utils/plugin_discovery.mjs';

const REASONS = ['empty', 'relative', 'missing', 'not a directory', 'outside home'];

function fixture() {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-plugpath-')));
  const home = path.join(root, 'home');
  const ok = path.join(home, 'okplugins');
  const work = path.join(home, 'work');
  const outside = path.join(root, 'outside');
  const sibling = path.join(root, 'home-sibling', 'p');   // another home whose NAME extends this one's: `${home}-sibling`
  for (const d of [ok, work, outside, sibling]) fs.mkdirSync(d, { recursive: true });
  const plugin = (id, marker) => `import fs from 'node:fs';\nfs.writeFileSync(${JSON.stringify(marker)}, 'imported');\n`
    + `export default { id: '${id}', name: 'Fixture ${id}', priority: 999, run: async () => ({ up: false }) };\n`;
  const okMarker = path.join(root, 'OK_IMPORTED');
  const cwdMarker = path.join(root, 'CWD_IMPORTED');
  fs.writeFileSync(path.join(ok, '9981_ok.mjs'), plugin('9981', okMarker));
  fs.writeFileSync(path.join(work, '9982_cwd.mjs'), plugin('9982', cwdMarker));
  fs.writeFileSync(path.join(home, 'afile'), 'x');
  return { root, home, ok, work, outside, sibling, okMarker, cwdMarker, done: () => fs.rmSync(root, { recursive: true, force: true }) };
}

/** Run discoverPlugins(base, { home }) with the cwd and NSAUDITOR_PLUGIN_PATH set; capture stderr lines (console.error).
 *  process.env.HOME is NOT touched: the base comes only from the `home` passed, so a test that passes F.home and loads
 *  proves the parameter is honoured (the runner's own HOME is not an ancestor of the fixture). */
async function discover(F, pluginPath, { home = F.home } = {}) {
  const saved = { P: process.env.NSAUDITOR_PLUGIN_PATH, cwd: process.cwd() };
  const lines = [];
  const realErr = console.error;
  console.error = (...a) => { lines.push(a.join(' ')); };
  try {
    process.env.NSAUDITOR_PLUGIN_PATH = pluginPath;
    process.chdir(F.work);
    const plugins = await discovery.discoverPlugins(path.join(F.root, 'no-ce-base'), { home });
    return { plugins, lines, custom: plugins.filter((p) => p._source === 'custom').map((p) => p.id) };
  } finally {
    console.error = realErr;
    process.chdir(saved.cwd);
    if (saved.P === undefined) delete process.env.NSAUDITOR_PLUGIN_PATH; else process.env.NSAUDITOR_PLUGIN_PATH = saved.P;
  }
}

// ── the decision function ──────────────────────────────────────────────────────────────────────────────────────────────
test('ACCEPT first: an absolute directory strictly under HOME is accepted, as its realpath', () => {
  const F = fixture();
  try {
    assert.equal(typeof discovery.customPluginDirDecision, 'function', 'customPluginDirDecision is not exported');
    assert.deepEqual(discovery.customPluginDirDecision(F.ok, { home: F.home }), { ok: true, real: F.ok });
  } finally { F.done(); }
});

test('the refusal reasons are a CLOSED set, exported and pinned', () => {
  assert.deepEqual([...(discovery.CUSTOM_PLUGIN_DIR_REFUSALS ?? [])], REASONS);
  assert.ok(Object.isFrozen(discovery.CUSTOM_PLUGIN_DIR_REFUSALS));
});

test('every refusal reason has its advice: the advice map is exported, frozen and keyed exactly on the closed set', () => {
  const advice = discovery.CUSTOM_PLUGIN_DIR_ADVICE;
  assert.ok(advice && Object.isFrozen(advice), 'CUSTOM_PLUGIN_DIR_ADVICE is not exported frozen');
  assert.deepEqual(Object.keys(advice).sort(), [...REASONS].sort());
  for (const r of REASONS) assert.ok(typeof advice[r] === 'string' && advice[r].length > 10, `no advice for "${r}"`);
});

for (const [label, entry, home, reason] of [
  ['an empty entry', () => '', (F) => F.home, 'empty'],
  ['a relative entry that resolves inside the working directory', () => '9982_cwd_dir_does_not_matter', (F) => F.home, 'relative'],
  ['a dot-relative entry', () => './okplugins', (F) => F.home, 'relative'],
  ['a ~/ entry (no tilde expansion)', () => '~/okplugins', (F) => F.home, 'relative'],
  ['a missing absolute directory', (F) => path.join(F.home, 'nope'), (F) => F.home, 'missing'],
  ['an absolute FILE', (F) => path.join(F.home, 'afile'), (F) => F.home, 'not a directory'],
  ['an absolute directory outside HOME', (F) => F.outside, (F) => F.home, 'outside home'],
  ['HOME itself', (F) => F.home, (F) => F.home, 'outside home'],
  ['a directory in a SIBLING whose name extends HOME (<home>-sibling/p)', (F) => F.sibling, (F) => F.home, 'outside home'],
  // '' and not undefined: undefined takes the parameter default (the HOME this process started with), which would test
  // the runner's HOME, not an absent one. The real-binary arm with no HOME at all is in the end-to-end file.
  ['any entry when HOME is empty (home: "")', (F) => F.ok, () => '', 'outside home'],
]) {
  test(`REFUSE: ${label} → "${reason}"`, () => {
    const F = fixture();
    try {
      const d = discovery.customPluginDirDecision?.(entry(F), { home: home(F) });
      assert.deepEqual(d, { ok: false, reason });
      assert.ok(REASONS.includes(d.reason));
    } finally { F.done(); }
  });
}

// ── discoverPlugins, end to end ──────────────────────────────────────────────────────────────────────────────────────
test('ACCEPT first: discoverPlugins imports an absolute directory and names it on stderr with its count', async () => {
  const F = fixture();
  try {
    const r = await discover(F, F.ok);
    assert.deepEqual(r.custom, ['9981']);
    assert.ok(fs.existsSync(F.okMarker));
    assert.ok(r.lines.includes(`nsauditor-ai: custom plugins: 1 loaded from ${F.ok}`), r.lines.join('\n'));
  } finally { F.done(); }
});

test('a TRAILING COLON does not load the working directory: the empty entry is refused and named', async () => {
  const F = fixture();
  try {
    const r = await discover(F, `${F.ok}:`);
    assert.equal(fs.existsSync(F.cwdMarker), false, 'plugin code in the working directory was imported through an empty entry');
    assert.deepEqual(r.custom, ['9981']);
    assert.ok(r.lines.some((l) => l.startsWith('nsauditor-ai: custom plugin directory refused (empty): ""')), r.lines.join('\n'));
  } finally { F.done(); }
});

test('a relative entry naming the working directory is refused out loud, and its code is not imported', async () => {
  const F = fixture();
  try {
    const r = await discover(F, '.');
    assert.equal(fs.existsSync(F.cwdMarker), false);
    assert.deepEqual(r.custom, []);
    assert.ok(r.lines.some((l) => l.startsWith('nsauditor-ai: custom plugin directory refused (relative): "."')), r.lines.join('\n'));
  } finally { F.done(); }
});

test('every refusal line carries a reason from the closed set (no unannounced reason)', async () => {
  const F = fixture();
  try {
    const entries = ['', '.', '~/okplugins', path.join(F.home, 'nope'), path.join(F.home, 'afile'), F.outside, F.home];
    const r = await discover(F, entries.join(':'));
    const refused = r.lines.filter((l) => l.startsWith('nsauditor-ai: custom plugin directory refused'));
    assert.equal(refused.length, entries.length, r.lines.join('\n'));
    assert.deepEqual([...new Set(refused.map((l) => /refused \(([^)]+)\)/.exec(l)?.[1]))].sort(), [...REASONS].sort(),
      'the fixture no longer produces every reason, so the advice check below does not cover the closed set');
    for (const l of refused) {
      const m = /refused \(([^)]+)\)/.exec(l);
      assert.ok(m && REASONS.includes(m[1]), `reason outside the closed set: ${l}`);
      assert.ok(!l.includes('undefined'), `an announced line carries "undefined": ${l}`);
      assert.ok(l.endsWith(` — ${discovery.CUSTOM_PLUGIN_DIR_ADVICE?.[m[1]]}`), `the line does not end with its reason's advice: ${l}`);
    }
  } finally { F.done(); }
});

test('with no HOME (home: "") every entry is refused and named', async () => {
  const F = fixture();
  try {
    const r = await discover(F, F.ok, { home: '' });
    assert.deepEqual(r.custom, []);
    assert.ok(r.lines.some((l) => l.startsWith('nsauditor-ai: custom plugin directory refused (outside home)')), r.lines.join('\n'));
  } finally { F.done(); }
});
