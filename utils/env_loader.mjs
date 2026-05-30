// utils/env_loader.mjs
//
// Pure resolver for the per-scan environment selection flags (--env / --aws-profile)
// and the sentinel-host implied CLOUD_PROVIDER. Returns an env "patch"
// ({ set, unset }) that the CLI applies to process.env. Fail-fast: throws on a
// missing --env file or an INI/credentials file mistakenly passed to --env.
//
// fs is injected (readFile/fileExists) so the precedence + error rules unit-test
// without a real filesystem.

import os from 'node:os';
import path from 'node:path';
import dotenv from 'dotenv';

const CLOUD_SENTINELS = new Set(['aws', 'gcp', 'azure']);
const AWS_EXPLICIT_KEYS = ['AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN'];

function expandTilde(p) {
  if (typeof p !== 'string') return p;
  if (p === '~') return os.homedir();
  if (p.startsWith('~/')) return path.join(os.homedir(), p.slice(2));
  return p;
}

// INI signature: a [section] header line, OR no KEY=value line at all.
function looksLikeIni(content) {
  const hasSection = /^\s*\[[^\]]+\]\s*$/m.test(content);
  const hasKeyValue = /^\s*(?:export\s+)?[A-Za-z_][A-Za-z0-9_]*\s*=/m.test(content);
  return hasSection || !hasKeyValue;
}

function providerAlreadySet(set, env) {
  const v = set.CLOUD_PROVIDER ?? env.CLOUD_PROVIDER;
  return v != null && String(v).trim() !== '';
}

// The effective CLOUD_PROVIDER after merging the --env file (set) + shell env.
function effectiveProvider(set, env) {
  const v = set.CLOUD_PROVIDER ?? env.CLOUD_PROVIDER;
  return v == null ? '' : String(v).trim().toLowerCase();
}

// Lenient match (mirrors awsScanSkipReason CSV semantics): the effective provider
// matches the host if it equals the host OR is a CSV that includes the host.
function providerMatchesHost(effective, hostProvider) {
  if (!effective) return true; // unset → no contradiction
  const tokens = effective.split(',').map((t) => t.trim()).filter(Boolean);
  return tokens.includes(hostProvider);
}

/**
 * @param {object} args
 * @param {string} [args.envPath]     value of --env
 * @param {string} [args.awsProfile]  value of --aws-profile
 * @param {string} [args.host]        --host value (for sentinel CLOUD_PROVIDER implication)
 * @param {object} args.env           snapshot of current process.env (read-only)
 * @param {(p:string)=>boolean} args.fileExists
 * @param {(p:string)=>string}  args.readFile
 * @returns {{set: Record<string,string>, unset: string[]}}
 */
export function resolveScanEnv({ envPath, awsProfile, host, env = {}, fileExists, readFile }) {
  const set = {};
  const unset = [];

  // 1. --env dotenv file (override-on applied by caller via Object.assign).
  if (typeof envPath === 'string' && envPath.length) {
    const resolved = path.resolve(expandTilde(envPath));
    if (!fileExists(resolved)) {
      throw new Error(`--env file not found: ${resolved} (fail-fast: refusing to fall back to ambient credentials)`);
    }
    const content = readFile(resolved);
    if (looksLikeIni(content)) {
      throw new Error(
        `${resolved} looks like an AWS credentials / INI file (has [section] headers / no KEY=value lines), ` +
        `not a dotenv file. Use --aws-profile <name> instead (with AWS_SHARED_CREDENTIALS_FILE in an --env file ` +
        `if the path is non-default).`,
      );
    }
    Object.assign(set, dotenv.parse(content));
  }

  // 2. --aws-profile: AWS_PROFILE wins; clear explicit keys; load ~/.aws/config; imply aws.
  if (typeof awsProfile === 'string' && awsProfile.length) {
    set.AWS_PROFILE = awsProfile;
    set.AWS_SDK_LOAD_CONFIG = '1';
    for (const k of AWS_EXPLICIT_KEYS) {
      delete set[k];      // a key from the --env file must not survive the profile
      unset.push(k);
    }
    if (!providerAlreadySet(set, env)) set.CLOUD_PROVIDER = 'aws';
  }

  // 3. Sentinel host implies its provider when CLOUD_PROVIDER is still unset.
  //    Fail-fast on a host vs CLOUD_PROVIDER contradiction: if the effective
  //    provider (--env file + shell env) is set to a cloud that does NOT match
  //    the host, scoping would select host-plugins that then all self-skip on
  //    the awsScanSkipReason gate → ZERO plugins run → a silent "clean" report.
  if (typeof host === 'string' && CLOUD_SENTINELS.has(host.trim().toLowerCase())) {
    const hostProvider = host.trim().toLowerCase();
    const effective = effectiveProvider(set, env);
    if (effective && !providerMatchesHost(effective, hostProvider)) {
      throw new Error(
        `--host '${hostProvider}' conflicts with CLOUD_PROVIDER='${effective}': the host and the ` +
        `effective cloud provider do not match, which would silently skip every plugin (an empty ` +
        `"clean" report). Resolve by dropping the conflicting CLOUD_PROVIDER, or scan the matching host ` +
        `(--host ${effective.split(',')[0].trim()}).`,
      );
    }
    if (!providerAlreadySet(set, env)) set.CLOUD_PROVIDER = hostProvider;
  }

  return { set, unset };
}
