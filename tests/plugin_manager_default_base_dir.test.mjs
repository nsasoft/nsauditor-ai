// tests/plugin_manager_default_base_dir.test.mjs
// PluginManager.create() WITH NO baseDir DISCOVERS FROM THE PACKAGE ROOT, never from the working directory. Every
// shipped caller passes its own directory; this is the API default, and a default that read `<cwd>/plugins/*.mjs`
// would import code from wherever the process happens to run.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import PluginManager from '../plugin_manager.mjs';

function fixture() {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-pmbase-')));
  const marker = path.join(root, 'CWD_PLUGIN_IMPORTED');
  fs.mkdirSync(path.join(root, 'plugins'));
  fs.writeFileSync(path.join(root, 'plugins', '9992_cwd.mjs'), `import fs from 'node:fs';\nfs.writeFileSync(${JSON.stringify(marker)}, 'imported');\n`
    + `export default { id: '9992', name: 'Fixture CWD', priority: 999, run: async () => ({ up: false }) };\n`);
  return { root, marker, done: () => fs.rmSync(root, { recursive: true, force: true }) };
}

test('ACCEPT first: create({ baseDir }) discovers from that directory', async () => {
  const F = fixture();
  try {
    const mgr = await PluginManager.create({ baseDir: F.root });
    assert.ok(mgr.plugins.some((p) => String(p.id) === '9992'), 'the named base directory was not discovered');
  } finally { F.done(); }
});

test('create() with no baseDir does not import <cwd>/plugins, and still finds the package\'s own plugins', async () => {
  const F = fixture();
  const cwd = process.cwd();
  try {
    process.chdir(F.root);
    const mgr = await PluginManager.create();
    assert.equal(fs.existsSync(F.marker), false, 'a plugin in the working directory was imported by the default');
    assert.ok(!mgr.plugins.some((p) => String(p.id) === '9992'));
    assert.ok(mgr.plugins.some((p) => p._source === 'ce'), 'the default found no Community plugin — it discovered from the wrong place');
  } finally { process.chdir(cwd); F.done(); }
});
