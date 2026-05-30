// utils/mcp_env_file.mjs
//
// Loads the per-environment dotenv file named by NSA_ENV_FILE into env for the
// MCP server, reusing the CLI's resolveScanEnv() (same dotenv parse, tilde-
// expansion, INI-detection, fail-fast). Called from startStdioServer() AFTER
// auth + license are resolved, so the file carries SCAN-TARGET vars only (cloud
// creds / CLOUD_PROVIDER / scan tuning) and can neither bypass the auth gate nor
// escalate the license tier. NSA_MCP_AUTH_KEY / NSAUDITOR_LICENSE_KEY in the file
// are intentionally ignored (they resolve before the file is read).
//
// The file is the AUTHORITATIVE scan-target selector: any explicit provider
// credential present in the ambient env but NOT set by the file is "leftover"
// (e.g. a previous account's keys still in the Claude Desktop env block) and is
// CLEARED — otherwise a partial file would let the scan silently run against the
// wrong account and report "clean" (the worst outcome an audit tool can produce).
// Instance-role / ADC identity (which has no env var) is untouched. This mirrors
// how the CLI --aws-profile path already clears the explicit AWS keys.

import { resolveScanEnv } from './env_loader.mjs';

// Resolved before NSA_ENV_FILE loads → stripped if present in the file.
const RESERVED_KEYS = new Set(['NSA_MCP_AUTH_KEY', 'NSAUDITOR_LICENSE_KEY']);

// Explicit per-provider credential env vars. Cleared if the file does not set them.
const PROVIDER_CRED_KEYS = [
  'AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN', 'AWS_PROFILE',
  'GOOGLE_APPLICATION_CREDENTIALS', 'GOOGLE_CLOUD_PROJECT', 'GOOGLE_CLOUD_PROJECT_ID', 'GCLOUD_PROJECT',
  'AZURE_CLIENT_ID', 'AZURE_TENANT_ID', 'AZURE_CLIENT_SECRET', 'AZURE_SUBSCRIPTION_ID',
];

/**
 * @param {object} a
 * @param {Record<string,string>} a.env  process.env (mutated in place; file wins)
 * @param {(p:string)=>boolean} a.fileExists
 * @param {(p:string)=>string}  a.readFile
 * @param {(m:string)=>void}    [a.log]  stderr sink — key NAMES only, never values
 * @returns {{applied: string[], ignored: string[], cleared: string[]}}
 * @throws if NSA_ENV_FILE is set-but-empty, or points at a missing/INI file
 */
export function applyScanEnvFile({ env, fileExists, readFile, log = () => {} }) {
  const envPath = env.NSA_ENV_FILE;
  if (envPath == null) return { applied: [], ignored: [], cleared: [] }; // truly unset → no-op
  if (typeof envPath !== 'string' || envPath.trim() === '') {
    // set-but-empty (e.g. an unresolved config-template var): the operator
    // clearly intended a file. Fail-fast rather than silently scan ambient creds.
    throw new Error(
      'NSA_ENV_FILE is set but empty — refusing to start; unset it or give a real path ' +
      '(an empty value would silently scan ambient credentials)',
    );
  }

  // Only envPath is set → resolveScanEnv reduces to: resolve + tilde-expand →
  // fail-fast if missing → reject INI → dotenv.parse → { set, unset: [] }.
  const { set } = resolveScanEnv({ envPath, env, fileExists, readFile });

  const ignored = Object.keys(set).filter((k) => RESERVED_KEYS.has(k));
  for (const k of ignored) delete set[k];

  const applied = Object.keys(set);
  Object.assign(env, set); // override-on — the file is the environment selector

  // Anti-false-clean: clear leftover ambient provider creds the file did NOT set.
  const cleared = [];
  for (const k of PROVIDER_CRED_KEYS) {
    if (!(k in set) && env[k] != null && env[k] !== '') {
      delete env[k];
      cleared.push(k);
    }
  }

  if (ignored.length) {
    log(
      `ignored ${ignored.join(', ')} from NSA_ENV_FILE — auth/license resolve ` +
      `before the file; set them inline or in ~/.nsauditor/.env`,
    );
  }
  if (cleared.length) {
    log(
      `cleared ambient ${cleared.join(', ')} not set by NSA_ENV_FILE ` +
      `(the file is the authoritative scan target — refusing to use leftover credentials)`,
    );
  }
  log(
    `Loaded scan environment from ${envPath} ` +
    `(${applied.length} keys: ${applied.join(', ') || 'none'})`,
  );

  return { applied, ignored, cleared };
}
