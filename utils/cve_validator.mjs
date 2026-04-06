// utils/cve_validator.mjs
// Post-processes LLM output to validate CVE IDs against NVD.

import { createNvdClient } from './nvd_client.mjs';

const CVE_RE = /\bCVE-\d{4}-\d{4,}\b/g;

/**
 * Extract deduplicated CVE IDs from text.
 * @param {string} text — LLM response text (markdown, plain, etc.)
 * @returns {string[]}
 */
export function extractCveIds(text) {
  if (!text) return [];
  const matches = String(text).match(CVE_RE);
  if (!matches) return [];
  return [...new Set(matches)];
}

/**
 * Validate an array of CVE IDs against NVD.
 * @param {string[]} cveIds
 * @param {{ apiKey?: string, cacheDir?: string }} [options]
 * @returns {Promise<Map<string, { exists: boolean|null, cvssScore?: number, severity?: string }>>}
 */
export async function validateCves(cveIds, options) {
  const client = options?.client ?? createNvdClient(options);
  const results = new Map();

  for (const id of cveIds) {
    try {
      const res = await client.validateCveId(id);
      results.set(id, {
        exists: res.exists,
        ...(res.cvssScore != null && { cvssScore: res.cvssScore }),
        ...(res.severity != null && { severity: res.severity }),
      });
    } catch {
      // NVD unreachable — mark as unknown
      results.set(id, { exists: null });
    }
  }

  return results;
}

/**
 * Annotate CVE IDs in text with verification markers.
 * - Verified:   {{CVE_VERIFIED:CVE-XXXX-XXXXX}}
 * - Unverified: {{CVE_UNVERIFIED:CVE-XXXX-XXXXX}}
 * - Unknown (exists: null): left as-is
 * @param {string} text
 * @param {Map<string, { exists: boolean|null }>} validationMap
 * @returns {string}
 */
export function annotateCveText(text, validationMap) {
  if (!text) return text;
  return String(text).replace(CVE_RE, (match) => {
    const info = validationMap.get(match);
    if (!info || info.exists === null) return match;
    if (info.exists) return `{{CVE_VERIFIED:${match}}}`;
    return `{{CVE_UNVERIFIED:${match}}}`;
  });
}
