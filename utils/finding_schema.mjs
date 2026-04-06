// utils/finding_schema.mjs

export const FINDING_CATEGORIES = ['AUTH', 'CRYPTO', 'CONFIG', 'SERVICE', 'EXPOSURE', 'CVE'];
export const FINDING_STATUSES   = ['UNVERIFIED', 'VERIFIED', 'POTENTIAL', 'FALSE_POSITIVE'];
export const FINDING_SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
export const FINDING_EFFORTS    = ['LOW', 'MEDIUM', 'HIGH'];

/**
 * Validate a finding object against the schema.
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
  return errors;
}

let _counter = 0;

/**
 * Generate a unique finding ID in the format F-YYYY-NNNN.
 * Counter is process-scoped and resets on restart.
 */
export function generateFindingId() {
  const year = new Date().getFullYear();
  return `F-${year}-${String(++_counter).padStart(4, '0')}`;
}
