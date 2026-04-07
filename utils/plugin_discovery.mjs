// utils/plugin_discovery.mjs
// Multi-path plugin loader: CE built-in, EE package (optional), custom (env var)

import { readdir } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { join, resolve, dirname } from 'node:path';
import { createRequire } from 'node:module';

const _require = createRequire(import.meta.url);

async function loadPluginsFromDir(dir, source) {
  let files;
  try {
    files = await readdir(dir);
  } catch {
    return [];
  }

  const plugins = [];
  for (const file of files.filter(f => f.endsWith('.mjs'))) {
    try {
      const mod = await import(join(dir, file));
      const plugin = mod.default;
      if (plugin?.id && plugin?.name && typeof plugin?.run === 'function') {
        // Attach conclude from named export or plugin default
        const conclude = mod.conclude ?? plugin.conclude;
        plugins.push({ ...plugin, _source: source, ...(conclude ? { conclude } : {}) });
      }
    } catch (e) {
      if (process.env.NSA_VERBOSE) {
        console.error(`[plugin_discovery] Failed to load ${file}: ${e.message}`);
      }
    }
  }
  return plugins;
}

export async function discoverPlugins(baseDir) {
  const plugins = [];

  // Source 1: CE built-in plugins
  plugins.push(...await loadPluginsFromDir(join(baseDir, 'plugins'), 'ce'));

  // Source 2: EE package (@nsasoft/nsauditor-ai-ee)
  try {
    const eePkgPath = _require.resolve('@nsasoft/nsauditor-ai-ee/package.json');
    const eePluginsDir = join(dirname(eePkgPath), 'plugins');
    if (existsSync(eePluginsDir)) {
      plugins.push(...await loadPluginsFromDir(eePluginsDir, 'ee'));
    }
  } catch {
    // EE not installed — CE operates standalone
  }

  // Source 3: Custom plugin paths (colon-separated)
  const customPaths = process.env.NSAUDITOR_PLUGIN_PATH;

  const SAFE_PREFIXES = [process.cwd(), process.env.HOME].filter(Boolean).map(p => p.endsWith('/') ? p : p + '/');

  function isSafePath(absPath) {
    return SAFE_PREFIXES.some(prefix => absPath.startsWith(prefix)) || absPath === process.cwd();
  }

  if (customPaths) {
    for (const dir of customPaths.split(':')) {
      const abs = resolve(dir);
      if (!isSafePath(abs)) {
        if (process.env.NSA_VERBOSE) console.warn(`[plugin_discovery] Skipping unsafe NSAUDITOR_PLUGIN_PATH entry: ${abs}`);
        continue;
      }
      if (existsSync(abs)) {
        plugins.push(...await loadPluginsFromDir(abs, 'custom'));
      }
    }
  }

  return plugins.sort((a, b) => (a.priority ?? 0) - (b.priority ?? 0));
}
