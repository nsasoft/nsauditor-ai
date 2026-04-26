// utils/finding_schema.mjs
import { v4 as uuidv4 } from 'uuid';

export const FINDING_CATEGORIES = ['AUTH', 'CRYPTO', 'CONFIG', 'SERVICE', 'EXPOSURE', 'CVE'];
export const FINDING_STATUSES   = ['UNVERIFIED', 'VERIFIED', 'POTENTIAL', 'FALSE_POSITIVE'];
export const FINDING_SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
export const FINDING_EFFORTS    = ['LOW', 'MEDIUM', 'HIGH'];

const CWE_ID_PATTERN = /^CWE-\d+$/;

/**
 * Validate a finding object against the schema.
 *
 * Optional evidence fields (validated only when present):
 *   - evidence.cwe   string[] of CWE-NNN identifiers, e.g. ['CWE-326', 'CWE-200']
 *   - evidence.owasp string[] of OWASP categories, e.g. ['A02:2021-Cryptographic Failures']
 *
 * @param {object} f
 * @returns {string[]} Array of error messages; empty = valid
 */
export function validateFinding(f) {
  const errors = [];
  if (!FINDING_CATEGORIES.includes(f?.category))
    errors.push(`invalid category: ${f?.category}`);
  if (!FINDING_STATUSES.includes(f?.status))
    errors.push(`invalid status: ${f?.status}`);
  if (!FINDING_SEVERITIES.includes(f?.severity))
    errors.push(`invalid severity: ${f?.severity}`);
  if (!f?.title || typeof f.title !== 'string')
    errors.push('title required');
  if (!f?.target?.host)
    errors.push('target.host required');

  if (f?.evidence?.cwe !== undefined) {
    if (!Array.isArray(f.evidence.cwe)) {
      errors.push('evidence.cwe must be an array');
    } else {
      for (const id of f.evidence.cwe) {
        if (typeof id !== 'string' || !CWE_ID_PATTERN.test(id))
          errors.push(`invalid cwe id: ${id}`);
      }
    }
  }

  if (f?.evidence?.owasp !== undefined) {
    if (!Array.isArray(f.evidence.owasp)) {
      errors.push('evidence.owasp must be an array');
    } else {
      for (const ent of f.evidence.owasp) {
        if (typeof ent !== 'string')
          errors.push(`invalid owasp entry: ${ent}`);
      }
    }
  }

  return errors;
}

/**
 * Generate a globally unique finding ID.
 * Format: F-<uuid-v4> (e.g. F-3d7e4b2a-91f0-4c3e-b8a6-7f2d5e9c1a04)
 * UUID-based — no counter to reset, no collision risk across restarts.
 */
export function generateFindingId() {
  return `F-${uuidv4()}`;
}
