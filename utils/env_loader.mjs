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

// The distinct cloud-sentinel legs implied by the scan target, in first-appearance
// order, lowercased + deduped. Mirrors the CLI's host-file-XOR-host dispatch
// precedence: a pre-resolved `hosts` array (the --host-file path) is the
// authoritative source when present; otherwise the `--host` string (single 'aws'
// or a CSV 'aws,gcp,azure') is used. The two are NEVER unioned — the scan
// dispatches exactly one source, so reconciling both would over-widen
// CLOUD_PROVIDER and could false-throw on a leg that is never dispatched.
// Non-sentinel tokens (IPs / CIDRs / hostnames) are ignored; [] means no cloud
// leg (a pure network scan needs no CLOUD_PROVIDER).
function sentinelLegs(host, hosts) {
  const tokens = Array.isArray(hosts)
    ? hosts.slice()
    : (typeof host === 'string' ? host.split(',') : []);
  const legs = [];
  for (const raw of tokens) {
    const t = String(raw).trim().toLowerCase();
    if (CLOUD_SENTINELS.has(t) && !legs.includes(t)) legs.push(t);
  }
  return legs;
}

/**
 * @param {object} args
 * @param {string} [args.envPath]     value of --env
 * @param {string} [args.awsProfile]  value of --aws-profile
 * @param {string} [args.host]        --host value: a single sentinel ('aws'), a
 *                                    CSV of sentinels ('aws,gcp,azure'), or a
 *                                    network host — for CLOUD_PROVIDER implication
 * @param {string[]} [args.hosts]     pre-resolved host list (the --host-file path,
 *                                    where `host` is undefined); reconciled the
 *                                    same way as a CSV `host`
 * @param {object} args.env           snapshot of current process.env (read-only)
 * @param {(p:string)=>boolean} args.fileExists
 * @param {(p:string)=>string}  args.readFile
 * @returns {{set: Record<string,string>, unset: string[]}}
 */
export function resolveScanEnv({ envPath, awsProfile, host, hosts, env = {}, fileExists, readFile }) {
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

  // Capture whether the OPERATOR (not the tool) pinned CLOUD_PROVIDER — from the
  // --env file (step 1) or the shell env — BEFORE the --aws-profile implication
  // in step 2. This is what decides throw-vs-imply for sentinel legs (step 3):
  //  • operator-pinned provider that misses a host leg → conflict → fail-fast;
  //  • unpinned (or only tool/profile-implied) → imply the UNION of the legs.
  // Without this snapshot, --aws-profile's implied bare 'aws' (step 2) would look
  // like an operator pin and wrongly THROW on a `--host aws,gcp,azure` run.
  const operatorPinned = providerAlreadySet(set, env);
  const operatorProvider = operatorPinned ? effectiveProvider(set, env) : '';

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

  // 3. Sentinel host leg(s) imply their provider(s) when the operator hasn't
  //    pinned CLOUD_PROVIDER; fail-fast when a pinned provider does NOT cover
  //    every leg. Handles a single sentinel ('aws'), a CSV ('aws,gcp,azure'),
  //    AND a --host-file resolved list (`hosts`) uniformly — each is a set of
  //    legs. A leg that the effective provider does not cover would silently
  //    self-skip on the awsScanSkipReason/gcpScanSkipReason gate → ZERO plugins
  //    run on that leg → a silent "clean" report for a whole cloud.
  const legs = sentinelLegs(host, hosts);
  if (legs.length) {
    if (operatorPinned) {
      const uncovered = legs.filter((leg) => !providerMatchesHost(operatorProvider, leg));
      if (uncovered.length) {
        throw new Error(
          `--host '${legs.join(',')}' conflicts with CLOUD_PROVIDER='${operatorProvider}': the host ` +
          `leg(s) [${uncovered.join(', ')}] are not covered by the effective cloud provider, so every ` +
          `plugin on ${uncovered.length > 1 ? 'those legs' : 'that leg'} would silently self-skip (an ` +
          `empty "clean" report). Resolve by dropping the conflicting CLOUD_PROVIDER, or set ` +
          `CLOUD_PROVIDER to include ${uncovered.join(',')} (e.g. CLOUD_PROVIDER=${legs.join(',')}).`,
        );
      }
      // pinned provider covers every leg → leave the operator's value untouched
    } else {
      // Unpinned (or only tool/profile-implied): imply the UNION of the legs so
      // each cloud leg runs. This overrides a bare 'aws' that step 2's
      // --aws-profile implication may have written — 'aws' ⊆ the union, and the
      // aws leg still resolves the profile via AWS_PROFILE.
      set.CLOUD_PROVIDER = legs.join(',');
    }
  }

  return { set, unset };
}
