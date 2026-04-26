// utils/path_helpers.mjs
//
// Small, generic path-handling helpers used across cli.mjs and the output-dir
// resolution logic. Extracted from cli.mjs and utils/output_dir.mjs so both
// consumers share a single implementation (Task N.20).
//
// Pure synchronous functions, no I/O — safe to import from any context.

/**
 * Trim surrounding whitespace and strip surrounding quote characters
 * (single or double, possibly stacked) from a path-like string.
 *
 * Useful when shells (especially Windows cmd.exe / PowerShell) pass paths
 * with embedded quotes intact, or when env-var values arrive with stray
 * outer whitespace.
 *
 * Examples:
 *   toCleanPath('"/tmp/foo"')   → '/tmp/foo'
 *   toCleanPath("'/tmp/bar'")   → '/tmp/bar'
 *   toCleanPath('  /a b/c  ')   → '/a b/c'    (internal whitespace preserved)
 *   toCleanPath(null)           → ''
 *   toCleanPath(42)             → '42'
 *
 * @param {*} s - Any value; coerced to string before processing.
 * @returns {string} Cleaned string. Empty if input is nullish or all-quote.
 */
export function toCleanPath(s) {
  return String(s ?? '').trim().replace(/^['"]+|['"]+$/g, '');
}
