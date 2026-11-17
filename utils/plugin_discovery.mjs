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
// is never a base: a relative or empty entry used to resolve against it. The rule reads HOME at CALL time.
// Stated limits: the list is split on ':' on every platform, so a Windows drive path cannot be named; a HOME that is
// itself behind a symlink refuses a correct directory (compare the realpath); an env file passed with --env is
// trusted like code — it can set this variable.
export const CUSTOM_PLUGIN_DIR_REFUSALS = Object.freeze(['empty', 'relative', 'missing', 'not a directory', 'outside home']);
const REFUSAL_ADVICE = Object.freeze({
  empty: 'remove the empty entry (a leading, trailing or doubled ":")',
  relative: 'use an absolute path under your home directory',
  missing: 'the directory does not exist',
  'not a directory': 'name a directory, not a file',
  'outside home': 'custom plugin directories must be under your home directory',
});

/**
 * @param {string} entry  one NSAUDITOR_PLUGIN_PATH entry, as written
 * @param {{ home?: string }} [opts]  defaults to process.env.HOME, read now
 * @returns {{ ok: true, real: string } | { ok: false, reason: string }}
 */
export function customPluginDirDecision(entry, { home = process.env.HOME } = {}) {
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
// process for the same HOME, cwd and line, because discovery can run more than once in a run.
const _announced = new Set();
function announce(line) {
  const key = `${process.env.HOME}\0${process.cwd()}\0${line}`;
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

  if (customPaths) {
    for (const entry of customPaths.split(':')) {
      const d = customPluginDirDecision(entry);
      if (!d.ok) {
        announce(`nsauditor-ai: custom plugin directory refused (${d.reason}): ${JSON.stringify(entry)} — ${REFUSAL_ADVICE[d.reason]}`);
        continue;
      }
      const loaded = await loadPluginsFromDir(d.real, 'custom');
      announce(`nsauditor-ai: custom plugins: ${loaded.length} loaded from ${d.real}`);
      plugins.push(...loaded);
    }
  }

  return plugins.sort((a, b) => (a.priority ?? 0) - (b.priority ?? 0));
}
