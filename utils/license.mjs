// utils/license.mjs
// CE stub — full license validation coming in a future release.

/**
 * Parse tier from NSAUDITOR_LICENSE_KEY environment variable.
 * Stub uses key prefix: pro_* → 'pro', enterprise_* → 'enterprise'.
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
 * Gracefully degrades to CE on any failure — never throws.
 *
 * @param {string|undefined} keyStr
 * @returns {Promise<{valid: boolean, tier: string, reason: string}>}
 */
export async function loadLicense(keyStr) {
  if (!keyStr) return { valid: false, tier: 'ce', reason: 'no key provided' };
  // TODO: implement full license validation
  return { valid: false, tier: 'ce', reason: 'license validation not yet implemented' };
}
