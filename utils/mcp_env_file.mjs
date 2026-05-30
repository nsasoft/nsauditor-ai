// utils/mcp_env_file.mjs
//
// Loads the per-environment dotenv file named by NSA_ENV_FILE into env for the
// MCP server, reusing the CLI's resolveScanEnv() (same dotenv parse, tilde-
// expansion, INI-detection, fail-fast). Called from startStdioServer() AFTER
// auth + license are resolved, so the file carries SCAN-TARGET vars only (cloud
// creds / CLOUD_PROVIDER / scan tuning) and can neither bypass the auth gate nor
// escalate the license tier. NSA_MCP_AUTH_KEY / NSAUDITOR_LICENSE_KEY in the file
// are intentionally ignored (they resolve before the file is read).

import { resolveScanEnv } from './env_loader.mjs';

// Resolved before NSA_ENV_FILE loads → stripped if present in the file.
const RESERVED_KEYS = new Set(['NSA_MCP_AUTH_KEY', 'NSAUDITOR_LICENSE_KEY']);

/**
 * @param {object} a
 * @param {Record<string,string>} a.env  process.env (mutated in place; file wins)
 * @param {(p:string)=>boolean} a.fileExists
 * @param {(p:string)=>string}  a.readFile
 * @param {(m:string)=>void}    [a.log]  stderr sink — key NAMES only, never values
 * @returns {{applied: string[], ignored: string[]}}
 * @throws if NSA_ENV_FILE points at a missing file or an INI/credentials file
 */
export function applyScanEnvFile({ env, fileExists, readFile, log = () => {} }) {
  const envPath = env.NSA_ENV_FILE;
  if (typeof envPath !== 'string' || envPath.length === 0) {
    return { applied: [], ignored: [] };
  }

  // Only envPath is set → resolveScanEnv reduces to: resolve + tilde-expand →
  // fail-fast if missing → reject INI → dotenv.parse → { set, unset: [] }.
  const { set } = resolveScanEnv({ envPath, env, fileExists, readFile });

  const ignored = Object.keys(set).filter((k) => RESERVED_KEYS.has(k));
  for (const k of ignored) delete set[k];

  const applied = Object.keys(set);
  Object.assign(env, set); // override-on — the file is the environment selector

  if (ignored.length) {
    log(
      `ignored ${ignored.join(', ')} from NSA_ENV_FILE — auth/license resolve ` +
      `before the file; set them inline or in ~/.nsauditor/.env`,
    );
  }
  log(
    `Loaded scan environment from ${envPath} ` +
    `(${applied.length} keys: ${applied.join(', ') || 'none'})`,
  );

  return { applied, ignored };
}
