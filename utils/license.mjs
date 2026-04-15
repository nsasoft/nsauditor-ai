// utils/license.mjs
// JWT license verification for NSAuditor AI.
// Uses ES256 (ECDSA P-256) public key embedded below — no file I/O needed.
//
// KEY ROTATION: If the private key is compromised, generate a new EC P-256 key
// pair, update PUBLIC_KEY_PEM below, and ship a CE update. All existing JWTs
// become invalid. See license-manager docs/architecture.md for full procedure.

import { jwtVerify, importSPKI } from 'jose';

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
 * Full async JWT verification. Call once at startup.
 * On success, caches verified tier so subsequent getTierFromEnv() calls
 * return the cryptographically validated result.
 *
 * Never throws — degrades to 'ce' on any failure.
 *
 * @param {string} [keyStr] - License key; defaults to NSAUDITOR_LICENSE_KEY env var.
 * @returns {Promise<{valid: boolean, tier: string, org?: string, seats?: number,
 *   licenseId?: string, capabilities?: string[], expiresAt?: string, reason?: string}>}
 */
export async function loadLicense(keyStr) {
  const raw = keyStr ?? process.env.NSAUDITOR_LICENSE_KEY;
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
}
