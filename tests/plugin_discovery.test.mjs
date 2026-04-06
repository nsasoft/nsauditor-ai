import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, '..');

test('discoverPlugins loads CE plugins from ./plugins/', async () => {
  const { discoverPlugins } = await import('../utils/plugin_discovery.mjs');
  const plugins = await discoverPlugins(ROOT);
  assert.ok(plugins.length >= 20, `Expected 20+ CE plugins, got ${plugins.length}`);
  assert.ok(plugins.every(p => p.id && p.name && typeof p.run === 'function'),
    'Every plugin must have id, name, and run()');
});

test('all discovered plugins have unique IDs', async () => {
  const { discoverPlugins } = await import('../utils/plugin_discovery.mjs');
  const plugins = await discoverPlugins(ROOT);
  const ids = plugins.map(p => p.id);
  const unique = new Set(ids);
  assert.equal(unique.size, ids.length, `Duplicate plugin IDs: ${ids.filter((id, i) => ids.indexOf(id) !== i)}`);
});

test('plugins are sorted by priority ascending', async () => {
  const { discoverPlugins } = await import('../utils/plugin_discovery.mjs');
  const plugins = await discoverPlugins(ROOT);
  for (let i = 1; i < plugins.length; i++) {
    assert.ok(
      (plugins[i].priority ?? 0) >= (plugins[i - 1].priority ?? 0),
      `Plugin ${plugins[i].id} (priority ${plugins[i].priority}) is out of order after ${plugins[i - 1].id} (priority ${plugins[i - 1].priority})`
    );
  }
});

test('discoverPlugins handles missing NSAUDITOR_PLUGIN_PATH gracefully', async () => {
  process.env.NSAUDITOR_PLUGIN_PATH = '/nonexistent/path/12345';
  const { discoverPlugins } = await import('../utils/plugin_discovery.mjs');
  const plugins = await discoverPlugins(ROOT);
  assert.ok(plugins.length >= 20, 'Should still load CE plugins when custom path is missing');
  delete process.env.NSAUDITOR_PLUGIN_PATH;
});

test('EE package missing does not throw', async () => {
  const { discoverPlugins } = await import('../utils/plugin_discovery.mjs');
  // @nsasoft/nsauditor-ai-ee is not installed — this must not throw
  await assert.doesNotReject(() => discoverPlugins(ROOT), 'Missing EE package must not throw');
});
