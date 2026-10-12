// tests/plugin_status_produced_by.test.mjs
// ─────────────────────────────────────────────────────────────────────────────
// A pluginStatus ROW NAMES THE CODE THAT PRODUCED ITS DURATION (EE 2.0.0, the architect seat's ask). Enterprise's budget
// census binds each plugin's declared budget to the durations in the evidence tree; when a plugin's timing basis changes
// (1020's bounded pool) the older rows measure code that no longer ships, and nothing in a row said which code it measured.
// Each row of a plugin loaded from a file now carries `producedBy: "<package>@<version>"`, read from the nearest
// package.json above the plugin file. Driven through the real PluginManager.run on a plugin in a throwaway package.
// FOURTH QUADRANT FIRST: a plugin injected in code has no package, and its row carries no producedBy at all.
// ─────────────────────────────────────────────────────────────────────────────
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import PluginManager from '../plugin_manager.mjs';

const tmp = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-produced-by-')));
after(() => fs.rmSync(tmp, { recursive: true, force: true }));
const PLUGIN = `export default { id: '9901', name: 'Produced-by probe', priority: 1, protocols: [], ports: [], runStrategy: 'single',
  requirements: {}, run: async () => ({ up: true, probe: true }) };\n`;

test('(first) a plugin injected in code has no package: its row carries no producedBy', async () => {
  const pm = await PluginManager.create({ plugins: [{ id: '9902', name: 'Injected probe', priority: 1, protocols: [], ports: [],
    runStrategy: 'single', requirements: {}, dependencies: [], run: async () => ({ up: true }) }] });
  const { manifest } = await pm.run('127.0.0.1', ['9902']);
  const row = manifest.find((r) => r.id === '9902');
  assert.ok(row, `no row for the injected plugin: ${JSON.stringify(manifest)}`);
  assert.equal('producedBy' in row, false, 'a row with no known package must not claim one');
});

test('a plugin loaded from a file names the package that shipped it, from the nearest package.json above the file', async () => {
  fs.mkdirSync(path.join(tmp, 'plugins'), { recursive: true });
  fs.writeFileSync(path.join(tmp, 'package.json'), JSON.stringify({ name: 'produced-by-probe', version: '9.9.9', type: 'module' }));
  // A nameless package.json between the plugin and its package (a `"type"` marker) is walked past, not taken.
  fs.writeFileSync(path.join(tmp, 'plugins', 'package.json'), JSON.stringify({ type: 'module' }));
  fs.writeFileSync(path.join(tmp, 'plugins', '9901_produced_by_probe.mjs'), PLUGIN);
  const pm = await PluginManager.create({ baseDir: tmp });
  const { manifest } = await pm.run('127.0.0.1', ['9901']);
  const row = manifest.find((r) => r.id === '9901');
  assert.ok(row, `no row for the probe plugin: ${JSON.stringify(manifest.map((r) => r.id))}`);
  assert.equal(row.status, 'ran');
  assert.equal(row.producedBy, 'produced-by-probe@9.9.9');
  assert.equal(Object.keys(pm.plugins.find((p) => p.id === '9901')).includes('_file'), false, 'the plugin\'s shape is unchanged');
});
