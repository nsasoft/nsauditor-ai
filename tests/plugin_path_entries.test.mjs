// tests/plugin_path_entries.test.mjs
// A CUSTOM PLUGIN DIRECTORY (NSAUDITOR_PLUGIN_PATH, colon-separated) LOADS ONLY WHEN IT IS: non-empty · absolute as
// written (`~/x` is relative — no expansion) · a real directory · strictly under $HOME (HOME itself and an unset HOME
// refuse). Every refusal is named on stderr with a reason from a CLOSED set; every loaded directory is named with its
// count. The rule is read at CALL time, never captured when the module is imported.
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
  for (const d of [ok, work, outside]) fs.mkdirSync(d, { recursive: true });
  const plugin = (id, marker) => `import fs from 'node:fs';\nfs.writeFileSync(${JSON.stringify(marker)}, 'imported');\n`
    + `export default { id: '${id}', name: 'Fixture ${id}', priority: 999, run: async () => ({ up: false }) };\n`;
  const okMarker = path.join(root, 'OK_IMPORTED');
  const cwdMarker = path.join(root, 'CWD_IMPORTED');
  fs.writeFileSync(path.join(ok, '9981_ok.mjs'), plugin('9981', okMarker));
  fs.writeFileSync(path.join(work, '9982_cwd.mjs'), plugin('9982', cwdMarker));
  fs.writeFileSync(path.join(home, 'afile'), 'x');
  return { root, home, ok, work, outside, okMarker, cwdMarker, done: () => fs.rmSync(root, { recursive: true, force: true }) };
}

/** Run discoverPlugins with HOME, the cwd and NSAUDITOR_PLUGIN_PATH set; capture stderr lines written via console.error. */
async function discover(F, pluginPath, { home = F.home } = {}) {
  const saved = { HOME: process.env.HOME, P: process.env.NSAUDITOR_PLUGIN_PATH, cwd: process.cwd() };
  const lines = [];
  const realErr = console.error;
  console.error = (...a) => { lines.push(a.join(' ')); };
  try {
    if (home === undefined) delete process.env.HOME; else process.env.HOME = home;
    process.env.NSAUDITOR_PLUGIN_PATH = pluginPath;
    process.chdir(F.work);
    const plugins = await discovery.discoverPlugins(path.join(F.root, 'no-ce-base'));
    return { plugins, lines, custom: plugins.filter((p) => p._source === 'custom').map((p) => p.id) };
  } finally {
    console.error = realErr;
    process.chdir(saved.cwd);
    if (saved.HOME === undefined) delete process.env.HOME; else process.env.HOME = saved.HOME;
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

for (const [label, entry, home, reason] of [
  ['an empty entry', () => '', (F) => F.home, 'empty'],
  ['a relative entry that resolves inside the working directory', () => '9982_cwd_dir_does_not_matter', (F) => F.home, 'relative'],
  ['a dot-relative entry', () => './okplugins', (F) => F.home, 'relative'],
  ['a ~/ entry (no tilde expansion)', () => '~/okplugins', (F) => F.home, 'relative'],
  ['a missing absolute directory', (F) => path.join(F.home, 'nope'), (F) => F.home, 'missing'],
  ['an absolute FILE', (F) => path.join(F.home, 'afile'), (F) => F.home, 'not a directory'],
  ['an absolute directory outside HOME', (F) => F.outside, (F) => F.home, 'outside home'],
  ['HOME itself', (F) => F.home, (F) => F.home, 'outside home'],
  ['any entry when HOME is unset', (F) => F.ok, () => undefined, 'outside home'],
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
    assert.ok(r.lines.some((l) => l === 'nsauditor-ai: custom plugin directory refused (empty): ""'), r.lines.join('\n'));
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
    for (const l of refused) {
      const m = /refused \(([^)]+)\)/.exec(l);
      assert.ok(m && REASONS.includes(m[1]), `reason outside the closed set: ${l}`);
    }
  } finally { F.done(); }
});

test('HOME is read at CALL time: with HOME unset every entry is refused and named', async () => {
  const F = fixture();
  try {
    const r = await discover(F, F.ok, { home: undefined });
    assert.deepEqual(r.custom, []);
    assert.ok(r.lines.some((l) => l.startsWith('nsauditor-ai: custom plugin directory refused (outside home)')), r.lines.join('\n'));
  } finally { F.done(); }
});
