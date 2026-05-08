// utils/license.mjs
// JWT license verification for NSAuditor AI.
// Uses ES256 (ECDSA P-256) public key embedded below — no file I/O needed.
//
// KEY ROTATION: If the private key is compromised, generate a new EC P-256 key
// pair, update PUBLIC_KEY_PEM below, and ship a CE update. All existing JWTs
// become invalid. See license-manager docs/architecture.md for full procedure.

import { jwtVerify, importSPKI } from 'jose';
import { promises as fsp } from 'node:fs';
import { homedir, platform } from 'node:os';
import { join } from 'node:path';
import dotenv from 'dotenv';
import { keychainGet } from './keychain.mjs';

// ES256 public key — embedded directly so it works in npm package (no file read).
// Corresponding private key is in the license-manager service (NEVER shipped here).
const PUBLIC_KEY_PEM = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEDMDuTDV5dPqNafE473AIlCCdbLX7
u8cSY2dN6mfevYnOydP0SXLHCfWHr+SlpZpA2BiU6GKEk+QdIlWXOgGZsA==
-----END PUBLIC KEY-----`;

// Set by loadLicense(), read by getTierFromEnv().
// Starts null — before loadLicense() runs, getTierFromEnv() returns 'ce' (safe default).
// CE (Community Edition) is free and always works without a license.
let _verifiedTier = null;

/**
 * Synchronous tier detection.
 * Returns 'pro' | 'enterprise' | 'ce'.
 *
 * Before loadLicense() runs: returns 'ce' (Community Edition — safe default).
 * After loadLicense() runs: returns the cryptographically verified tier.
 *
 * CE is the free default — licensed features only activate after loadLicense()
 * confirms the JWT signature. This prevents prefix spoofing from granting
 * elevated privileges during the startup window.
 *
 * MUST remain synchronous — called in hot paths (cli.mjs, plugin_manager, mcp_server).
 */
export function getTierFromEnv() {
  if (_verifiedTier !== null) return _verifiedTier;

  // Not yet verified — CE is the safe default.
  // Call loadLicense() at startup to enable Pro/Enterprise.
  return 'ce';
}

/**
 * CE-0.1.30.2 — multi-source license-key resolution chain.
 *
 * Resolution order (first non-empty wins):
 *   1. process.env.NSAUDITOR_LICENSE_KEY   — CI/CD takes precedence
 *   2. macOS Keychain (service=nsauditor-ai, account=NSAUDITOR_LICENSE_KEY)
 *      — set by `nsauditor-ai license install <KEY>` on macOS
 *   3. $XDG_CONFIG_HOME/nsauditor/.env (or ~/.nsauditor/.env) — universal
 *      file fallback; set by `license install` on Linux/Windows OR
 *      manually edited by the operator. Mode 0600 expected; permissive
 *      mode triggers a warning (still loaded — operator's choice).
 *
 * @param {object} [opts]
 * @param {string} [opts._homeFileOverride]  — test seam. Path to a .env-format
 *   file to read instead of ~/.nsauditor/.env. Bypasses XDG resolution.
 * @param {Function} [opts._keychainGet]      — test seam. Replaces the macOS
 *   Keychain reader.
 * @returns {Promise<string|null>} The license key string, or null if no
 *   source had one.
 */
export async function resolveLicenseKey(opts = {}) {
  // 1. env var
  if (process.env.NSAUDITOR_LICENSE_KEY) return process.env.NSAUDITOR_LICENSE_KEY;

  // 2. platform secret store (macOS Keychain today; Linux/Windows skip)
  const kget = opts._keychainGet ?? keychainGet;
  try {
    const fromKeychain = await kget('NSAUDITOR_LICENSE_KEY');
    if (fromKeychain) return fromKeychain;
  } catch { /* keychain unavailable — fall through */ }

  // 3. ~/.nsauditor/.env (or $XDG_CONFIG_HOME/nsauditor/.env)
  const filePath = opts._homeFileOverride ?? defaultLicenseFilePath();
  try {
    const stat = await fsp.stat(filePath);
    // Warn (non-fatal) if mode is more permissive than 0600 on POSIX.
    // Windows has no concept of POSIX file mode; skip the check there.
    // Reviewer M10 fold: only warn once per path per process to avoid
    // spamming the console under repeated CLI invocations.
    if (platform() !== 'win32' && stat.isFile() && (stat.mode & 0o077) !== 0) {
      if (!_permissiveWarnedPaths.has(filePath)) {
        const modeStr = (stat.mode & 0o777).toString(8).padStart(3, '0');
        console.warn(`⚠  ${filePath} has permissive mode ${modeStr} — recommend chmod 0600`);
        _permissiveWarnedPaths.add(filePath);
      }
    }
    const buf = await fsp.readFile(filePath, 'utf8');
    const parsed = dotenv.parse(buf);
    if (parsed.NSAUDITOR_LICENSE_KEY) return parsed.NSAUDITOR_LICENSE_KEY;
  } catch { /* file missing / unreadable — fall through */ }

  return null;
}

// CE-0.1.30.2 reviewer M10: one-shot permissive-mode warning per path per
// process. Without this, every `loadLicense()` call against a 0644 file
// emits a console.warn — and CE re-resolves on every CLI invocation
// (plus the `cmd === 'license'` branch double-calls today, see reviewer
// M7 follow-up). Module-scoped Set keeps memory bounded (~1 path per
// install) and silences the noise without hiding the message from
// operators who haven't seen it yet.
const _permissiveWarnedPaths = new Set();

function defaultLicenseFilePath() {
  // Honor $XDG_CONFIG_HOME (Linux convention; some macOS users set it).
  // Falls back to ~/.nsauditor/.env which is what the existing README
  // method-2 docs already promise.
  if (process.env.XDG_CONFIG_HOME) {
    return join(process.env.XDG_CONFIG_HOME, 'nsauditor', '.env');
  }
  return join(homedir(), '.nsauditor', '.env');
}

/**
 * Full async JWT verification. Call once at startup.
 * On success, caches verified tier so subsequent getTierFromEnv() calls
 * return the cryptographically validated result.
 *
 * Never throws — degrades to 'ce' on any failure.
 *
 * @param {string} [keyStr] - License key; if omitted, runs the multi-source
 *   resolution chain (env var → Keychain → ~/.nsauditor/.env). See
 *   resolveLicenseKey() above.
 * @returns {Promise<{valid: boolean, tier: string, org?: string, seats?: number,
 *   licenseId?: string, capabilities?: string[], expiresAt?: string, reason?: string}>}
 */
export async function loadLicense(keyStr) {
  // Explicit keyStr argument wins (preserves the existing behavior for
  // callers like the `license --status` subcommand which passes the env
  // var directly). When omitted, run the multi-source resolution chain.
  const raw = keyStr ?? (await resolveLicenseKey());
  if (!raw) return { valid: false, tier: 'ce', reason: 'no key provided' };

  // Strip tier prefix
  let token = raw;
  let prefixTier = null;
  if (raw.startsWith('pro_'))        { token = raw.slice(4);  prefixTier = 'pro'; }
  else if (raw.startsWith('enterprise_')) { token = raw.slice(11); prefixTier = 'enterprise'; }
  else return { valid: false, tier: 'ce', reason: 'unknown key format' };

  try {
    const publicKey = await importSPKI(PUBLIC_KEY_PEM, 'ES256');
    const { payload } = await jwtVerify(token, publicKey, {
      issuer: 'nsasoft',
      audience: 'nsauditor-ai',
      subject: 'license',
      algorithms: ['ES256'],
      clockTolerance: 120,
    });

    // Cross-check: prefix must match JWT tier claim
    if (payload.tier !== prefixTier) {
      return { valid: false, tier: 'ce', reason: 'tier mismatch' };
    }

    // Cache verified tier for synchronous access
    _verifiedTier = payload.tier;

    // Compute days until expiry for renewal warnings (air-gapped VPC support)
    const expiresAt = new Date(payload.exp * 1000);
    const daysUntilExpiry = Math.max(0, Math.floor((expiresAt - Date.now()) / 86_400_000));

    let expiryWarning = null;
    if (daysUntilExpiry <= 1) {
      expiryWarning = 'License expires tomorrow — update NSAUDITOR_LICENSE_KEY now';
    } else if (daysUntilExpiry <= 7) {
      expiryWarning = `License expires in ${daysUntilExpiry} days — check email for renewal key`;
    }

    if (expiryWarning) {
      console.warn(`\u26A0  ${expiryWarning}`);
    }

    return {
      valid: true,
      tier: payload.tier,
      org: payload.org,
      seats: payload.seats,
      licenseId: payload.licenseId,
      capabilities: payload.capabilities,
      expiresAt: expiresAt.toISOString(),
      daysUntilExpiry,
      expiryWarning,
    };
  } catch {
    // Verification failure — actively downgrade to CE (prevents prefix spoofing).
    // Generic reason to avoid leaking jose internals to end users.
    _verifiedTier = 'ce';
    return { valid: false, tier: 'ce', reason: 'invalid license key' };
  }
}

/**
 * @internal Test-only. Reset cached verified tier between tests.
 * Disabled in production to prevent accidental tier cache clearing.
 */
export function _resetCache() {
  if (process.env.NODE_ENV === 'production') {
    throw new Error('_resetCache is test-only and disabled in production');
  }
  _verifiedTier = null;
  _permissiveWarnedPaths.clear();
}
