// utils/license.mjs
// CE stub implementation. Full ES256 JWT validation added in Phase 2 (roadmap).

/**
 * Parse tier from NSAUDITOR_LICENSE_KEY environment variable.
 * Stub uses key prefix: pro_* → 'pro', enterprise_* → 'enterprise'.
 * Phase 2 roadmap replaces this with offline jose ES256 JWT verification.
 */
export function getTierFromEnv() {
  const key = process.env.NSAUDITOR_LICENSE_KEY;
  if (!key) return 'ce';
  if (key.startsWith('pro_')) return 'pro';
  if (key.startsWith('enterprise_')) return 'enterprise';
  return 'ce';
}

/**
 * Validate a license key string.
 * Phase 2 roadmap: replace with jose.jwtVerify() against embedded ECDSA P-256 public key.
 * Gracefully degrades to CE on any failure — never throws.
 *
 * @param {string|undefined} keyStr
 * @returns {Promise<{valid: boolean, tier: string, reason: string}>}
 */
export async function loadLicense(keyStr) {
  if (!keyStr) return { valid: false, tier: 'ce', reason: 'no key provided' };
  // TODO (Phase 2): implement jose.jwtVerify with embedded public key
  return { valid: false, tier: 'ce', reason: 'JWT validation not yet implemented' };
}
