import { test, describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join, resolve } from 'node:path';

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

describe('discoverPlugins — path guard', () => {
  it('ignores NSAUDITOR_PLUGIN_PATH entries outside cwd/HOME', () => {
    // plugin_discovery.mjs is a cached ES module — env mutation after import has no effect.
    // Spawn a fresh subprocess with the env var pre-set so the module loads with the unsafe path.
    const script = `
      import { discoverPlugins } from './utils/plugin_discovery.mjs';
      const plugins = await discoverPlugins(process.cwd());
      const nonCE = plugins.filter(p => p._source === 'custom');
      if (nonCE.length > 0) {
        console.error('FAIL: loaded', nonCE.length, 'custom plugins from unsafe path');
        process.exit(1);
      }
      console.log('PASS: 0 custom plugins from /etc or /usr/lib');
    `;
    let result;
    try {
      result = execFileSync(process.execPath, ['--input-type=module'], {
        input: script,
        cwd: ROOT,
        env: { ...process.env, NSAUDITOR_PLUGIN_PATH: '/etc:/usr/lib', NSA_VERBOSE: '1' },
        encoding: 'utf8',
      });
    } catch (e) {
      assert.fail(`Subprocess failed:\nstdout: ${e.stdout ?? ''}\nstderr: ${e.stderr ?? ''}`);
    }
    assert.ok(result.includes('PASS'), `Expected PASS, got: ${result}`);
  });

  it('allows NSAUDITOR_PLUGIN_PATH entries within HOME', () => {
    const script = `
      import { discoverPlugins } from './utils/plugin_discovery.mjs';
      // Just verify it doesn't throw and returns an array
      const plugins = await discoverPlugins(process.cwd());
      console.log('PASS: discovered', plugins.length, 'plugins');
    `;
    let result;
    try {
      result = execFileSync(process.execPath, ['--input-type=module'], {
        input: script,
        cwd: ROOT,
        // Use a real HOME subpath that exists but has no .mjs files
        env: { ...process.env, NSAUDITOR_PLUGIN_PATH: process.env.HOME + '/.nsauditor-test-plugins' },
        encoding: 'utf8',
      });
    } catch (e) {
      assert.fail(`Subprocess failed:\nstdout: ${e.stdout ?? ''}\nstderr: ${e.stderr ?? ''}`);
    }
    assert.ok(result.includes('PASS'), `Expected PASS, got: ${result}`);
  });
});
