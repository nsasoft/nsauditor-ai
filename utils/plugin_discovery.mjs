// utils/plugin_discovery.mjs
// Multi-path plugin loader: CE built-in, EE package (optional), custom (env var)

import { readdir } from 'node:fs/promises';
import { existsSync, realpathSync, statSync } from 'node:fs';
import { join, dirname, isAbsolute } from 'node:path';
import { createRequire } from 'node:module';

const _require = createRequire(import.meta.url);

// ── Custom plugin directories (NSAUDITOR_PLUGIN_PATH) ──────────────────────────────────────────────────────────────
// Every .mjs in an accepted directory is import()ed, and importing a module runs its code — so an entry loads ONLY when
// it is: non-empty · absolute AS WRITTEN (no `~/` expansion: `~/x` is refused as relative) · a real directory ·
// strictly under $HOME by realpath ($HOME itself is refused; an unset HOME refuses every entry). The working directory
// is never a base.
// The base is the HOME this process started with, CAPTURED WHEN THIS MODULE IS FIRST IMPORTED — not one an env file
// sets later. The CLI imports it statically (cli.mjs → plugin_manager.mjs), before main() applies --env, so an --env file
// that sets HOME does not move the base. The MCP server imports it at its first tool call, which is AFTER NSA_ENV_FILE
// is applied, so there a HOME set in that file does move the base — as at 1.1.1, whose prefixes were captured at the
// same moment. The import order is pinned by env_file_sources_census (4).
// Stated limits: the list is split on ':' on every platform, so a Windows drive path cannot be named; a HOME that is
// itself behind a symlink refuses a correct directory (compare the realpath); an env file passed with --env is
// trusted like code — it can set this variable; the two entry points differ as above.
const HOME_AT_START = process.env.HOME;
export const CUSTOM_PLUGIN_DIR_REFUSALS = Object.freeze(['empty', 'relative', 'missing', 'not a directory', 'outside home']);
export const CUSTOM_PLUGIN_DIR_ADVICE = Object.freeze({
  empty: 'remove the empty entry (a leading, trailing or doubled ":")',
  relative: 'use an absolute path under your home directory',
  missing: 'the directory does not exist',
  'not a directory': 'name a directory, not a file',
  'outside home': 'custom plugin directories must be under your home directory',
});

/**
 * @param {string} entry  one NSAUDITOR_PLUGIN_PATH entry, as written
 * @param {{ home?: string }} [opts]  defaults to the HOME captured when this module was imported
 * @returns {{ ok: true, real: string } | { ok: false, reason: string }}
 */
export function customPluginDirDecision(entry, { home = HOME_AT_START } = {}) {
  if (!entry) return { ok: false, reason: 'empty' };
  if (!isAbsolute(entry)) return { ok: false, reason: 'relative' };
  let real;
  try { real = realpathSync(entry); } catch { return { ok: false, reason: 'missing' }; }
  try { if (!statSync(real).isDirectory()) return { ok: false, reason: 'not a directory' }; } catch { return { ok: false, reason: 'missing' }; }
  const h = home ? home.replace(/\/+$/, '') : '';
  if (!h || !real.startsWith(`${h}/`)) return { ok: false, reason: 'outside home' };
  return { ok: true, real };
}

// One line per directory loaded and per entry refused, on stderr (stdout carries --json and reports). Deduped per
// process for the same base home, cwd and line, because discovery can run more than once in a run.
const _announced = new Set();
function announce(line, home) {
  const key = `${home}\0${process.cwd()}\0${line}`;
  if (_announced.has(key)) return;
  _announced.add(key);
  console.error(line);
}

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
        // Attach conclude (and its authoritativePorts) from the named export or the plugin default
        const conclude = mod.conclude ?? plugin.conclude;
        const authoritativePorts = mod.authoritativePorts ?? plugin.authoritativePorts;
        const loaded = { ...plugin, _source: source, ...(conclude ? { conclude } : {}),
          ...(authoritativePorts ? { authoritativePorts } : {}) };
        // The file it came from, NON-ENUMERABLE so the plugin's shape is unchanged: PluginManager reads it to name the
        // package that shipped the plugin on every pluginStatus row (`producedBy`, EE 2.0.0).
        Object.defineProperty(loaded, '_file', { value: join(dir, file), enumerable: false });
        plugins.push(loaded);
      }
    } catch (e) {
      if (process.env.NSA_VERBOSE) {
        console.error(`[plugin_discovery] Failed to load ${file}: ${e.message}`);
      }
    }
  }
  return plugins;
}

/**
 * @param {string} baseDir  the package root whose plugins/ are the built-ins
 * @param {{ home?: string }} [opts]  the custom-plugin base; defaults to the HOME captured at import (tests pass it)
 */
export async function discoverPlugins(baseDir, { home = HOME_AT_START } = {}) {
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

  if (customPaths) {
    for (const entry of customPaths.split(':')) {
      const d = customPluginDirDecision(entry, { home });
      if (!d.ok) {
        announce(`nsauditor-ai: custom plugin directory refused (${d.reason}): ${JSON.stringify(entry)} — ${CUSTOM_PLUGIN_DIR_ADVICE[d.reason]}`, home);
        continue;
      }
      const loaded = await loadPluginsFromDir(d.real, 'custom');
      announce(`nsauditor-ai: custom plugins: ${loaded.length} loaded from ${d.real}`, home);
      plugins.push(...loaded);
    }
  }

  return plugins.sort((a, b) => (a.priority ?? 0) - (b.priority ?? 0));
}
