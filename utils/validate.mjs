// utils/validate.mjs
//
// Pre-flight environment validation for the `nsauditor-ai validate` CLI command.
// Verifies that the runtime environment is correctly configured WITHOUT running
// a scan: plugins load, license JWT is valid (if set), at least one AI provider
// is configured, output dir is writable with adequate free space, and DNS
// resolution works.
//
// Designed to:
//   - Complete in <2s end-to-end (each check has its own timeout)
//   - Run hermetically in CI (no real network required — uses 'localhost')
//   - Be Docker HEALTHCHECK friendly (exit code 0/1/2)
//   - Support both human-readable and JSON output modes (CLI handles formatting)
//
// Each check returns a CheckResult: { name, status, message, details? }
//   status:  'ok' | 'warn' | 'error' | 'skip'
//
// Dependencies are injectable via opts so tests can substitute fakes.

import fsp from 'node:fs/promises';
import path from 'node:path';
import dnsP from 'node:dns/promises';
import { resolveBaseOutDir } from './output_dir.mjs';

export const STATUSES = Object.freeze({
  OK:    'ok',
  WARN:  'warn',
  ERROR: 'error',
  SKIP:  'skip',
});

const FREE_SPACE_WARN_MB = 100;
const DEFAULT_NETWORK_TIMEOUT_MS = 1500;
const DEFAULT_NETWORK_HOST = 'localhost'; // hermetic — no external dependency

/**
 * Verify all installed plugins load without error.
 *
 * @param {object} [opts]
 * @param {Function} [opts.discover] - Override for testing.
 */
export async function checkPlugins({ discover } = {}) {
  try {
    const fn = discover || (await import('./plugin_discovery.mjs')).discoverPlugins;
    const result = await fn(process.cwd());
    const plugins = Array.isArray(result) ? result : (result?.plugins ?? []);
    return {
      name: 'plugins',
      status: STATUSES.OK,
      message: `${plugins.length} plugin${plugins.length === 1 ? '' : 's'} loaded`,
      details: { count: plugins.length },
    };
  } catch (err) {
    return {
      name: 'plugins',
      status: STATUSES.ERROR,
      message: `Plugin discovery failed: ${err.message}`,
      details: { error: err.message },
    };
  }
}

/**
 * If NSAUDITOR_LICENSE_KEY is set, verify the JWT and report the resolved tier.
 * Otherwise, skip (CE works fine without a license).
 */
export async function checkLicense({ loadFn, env = process.env } = {}) {
  const key = env.NSAUDITOR_LICENSE_KEY;
  if (!key) {
    return {
      name: 'license',
      status: STATUSES.SKIP,
      message: 'No license key set — running as Community Edition',
      details: { tier: 'ce' },
    };
  }
  try {
    const fn = loadFn || (await import('./license.mjs')).loadLicense;
    const result = await fn(key);
    if (!result.valid) {
      return {
        name: 'license',
        status: STATUSES.ERROR,
        message: `License invalid: ${result.reason || 'unknown reason'}`,
        details: { tier: result.tier ?? 'ce', reason: result.reason },
      };
    }
    // Warn if expiring within 7 days
    const days = Number(result.daysUntilExpiry);
    if (Number.isFinite(days) && days <= 7) {
      return {
        name: 'license',
        status: STATUSES.WARN,
        message: `License valid (${result.tier}) but expires in ${days} day${days === 1 ? '' : 's'}`,
        details: { tier: result.tier, daysUntilExpiry: days, expiresAt: result.expiresAt },
      };
    }
    return {
      name: 'license',
      status: STATUSES.OK,
      message: `License valid (${result.tier}, ${result.org || 'unknown org'})`,
      details: { tier: result.tier, org: result.org, expiresAt: result.expiresAt },
    };
  } catch (err) {
    return {
      name: 'license',
      status: STATUSES.ERROR,
      message: `License verification threw: ${err.message}`,
      details: { error: err.message },
    };
  }
}

/**
 * Verify at least one AI provider is configured. Warn if none — AI is optional
 * but most users want it.
 */
export function checkAiProviders({ env = process.env } = {}) {
  const providers = [];
  if (env.OPENAI_API_KEY)    providers.push('openai');
  if (env.ANTHROPIC_API_KEY) providers.push('claude');
  // Ollama is host-based, not key-based — presence of OLLAMA_HOST or default localhost both count
  if (env.OLLAMA_HOST || env.AI_PROVIDER === 'ollama') providers.push('ollama');

  if (providers.length === 0) {
    return {
      name: 'ai_providers',
      status: STATUSES.WARN,
      message: 'No AI provider configured — AI analysis will be skipped (set OPENAI_API_KEY, ANTHROPIC_API_KEY, or AI_PROVIDER=ollama)',
      details: { providers: [] },
    };
  }
  return {
    name: 'ai_providers',
    status: STATUSES.OK,
    message: `${providers.length} provider${providers.length === 1 ? '' : 's'} configured: ${providers.join(', ')}`,
    details: { providers },
  };
}

/**
 * Verify the resolved output directory is writable. Warn if free space is below
 * the configured threshold (100 MB by default).
 *
 * @param {object} [opts]
 * @param {string} [opts.dir] - Override resolved dir for testing.
 * @param {object} [opts.fsApi] - Override fsp for testing.
 */
export async function checkOutputDir({ dir, fsApi = fsp, freeSpaceWarnMB = FREE_SPACE_WARN_MB } = {}) {
  const target = dir ?? resolveBaseOutDir();
  try {
    await fsApi.mkdir(target, { recursive: true });
    // Round-trip a tiny file to prove writability
    const probe = path.join(target, `.nsauditor-validate-${process.pid}`);
    await fsApi.writeFile(probe, 'ok', 'utf8');
    await fsApi.unlink(probe);
  } catch (err) {
    return {
      name: 'output_dir',
      status: STATUSES.ERROR,
      message: `Output dir not writable (${target}): ${err.message}`,
      details: { dir: target, error: err.message },
    };
  }
  // Free-space check — fs.promises.statfs is Node 19+ (project requires Node 20+).
  // If the API throws (rare; some filesystems don't support it), surface as a warn,
  // not an error — writability already proved.
  let freeBytes = null;
  try {
    if (typeof fsApi.statfs === 'function') {
      const st = await fsApi.statfs(target);
      // bavail is blocks available to non-root user; bsize is block size
      freeBytes = Number(st.bavail) * Number(st.bsize);
    }
  } catch { /* statfs unsupported — skip the free-space portion */ }

  if (freeBytes != null) {
    const freeMB = Math.floor(freeBytes / (1024 * 1024));
    if (freeMB < freeSpaceWarnMB) {
      return {
        name: 'output_dir',
        status: STATUSES.WARN,
        message: `Output dir writable (${target}) but only ${freeMB} MB free (threshold ${freeSpaceWarnMB} MB)`,
        details: { dir: target, freeMB, threshold: freeSpaceWarnMB },
      };
    }
    return {
      name: 'output_dir',
      status: STATUSES.OK,
      message: `Output dir writable (${target}), ${freeMB} MB free`,
      details: { dir: target, freeMB },
    };
  }
  return {
    name: 'output_dir',
    status: STATUSES.OK,
    message: `Output dir writable (${target})`,
    details: { dir: target },
  };
}

/**
 * Verify DNS resolution works. Defaults to 'localhost' for hermetic CI runs;
 * override via `host` for environments where the user wants to test external
 * resolution.
 *
 * @param {object} [opts]
 * @param {string} [opts.host] - Hostname to resolve.
 * @param {number} [opts.timeoutMs]
 * @param {Function} [opts.lookup] - Override dnsP.lookup for testing.
 */
export async function checkNetwork({
  host = DEFAULT_NETWORK_HOST,
  timeoutMs = DEFAULT_NETWORK_TIMEOUT_MS,
  lookup = dnsP.lookup,
} = {}) {
  let timer;
  const lookupP = lookup(host).then((res) => {
    // dns.lookup returns { address, family }
    return res?.address || (Array.isArray(res) ? res[0]?.address : null);
  });
  const timeoutP = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error(`DNS timeout after ${timeoutMs}ms`)), timeoutMs);
  });
  try {
    const address = await Promise.race([lookupP, timeoutP]);
    return {
      name: 'network',
      status: STATUSES.OK,
      message: `DNS resolution OK (${host} → ${address})`,
      details: { host, address },
    };
  } catch (err) {
    return {
      name: 'network',
      status: STATUSES.WARN,
      message: `DNS resolution failed (${host}): ${err.message}`,
      details: { host, error: err.message },
    };
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Run all validation checks in parallel and aggregate results.
 *
 * Exit-code mapping (computed here for the CLI):
 *   - any 'error' → exit 2
 *   - any 'warn'  → exit 1
 *   - else        → exit 0
 *
 * @param {object} [opts] - Forwarded to individual check functions for testability.
 * @returns {Promise<{ overall: 'ok'|'warn'|'error', checks: object[], exitCode: 0|1|2 }>}
 */
export async function runValidation(opts = {}) {
  const checks = await Promise.all([
    checkPlugins(opts.plugins ?? {}),
    checkLicense(opts.license ?? {}),
    Promise.resolve(checkAiProviders(opts.ai ?? {})),
    checkOutputDir(opts.outputDir ?? {}),
    checkNetwork(opts.network ?? {}),
  ]);

  let overall = STATUSES.OK;
  for (const c of checks) {
    if (c.status === STATUSES.ERROR) { overall = STATUSES.ERROR; break; }
    if (c.status === STATUSES.WARN && overall !== STATUSES.ERROR) overall = STATUSES.WARN;
  }
  const exitCode = overall === STATUSES.ERROR ? 2 : overall === STATUSES.WARN ? 1 : 0;
  return { overall, checks, exitCode };
}

// Internal constants exposed for testing.
export const _internals = {
  FREE_SPACE_WARN_MB,
  DEFAULT_NETWORK_TIMEOUT_MS,
  DEFAULT_NETWORK_HOST,
};
