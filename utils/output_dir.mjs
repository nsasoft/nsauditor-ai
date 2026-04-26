// utils/output_dir.mjs
//
// Single source of truth for resolving the base output directory used by
// CLI scan-output writers (main scan, SARIF, CSV, Markdown).
//
// Why a dedicated module:
//   - The CLI's `--out <dir>` flag is parsed and stamped onto
//     `process.env.SCAN_OUT_PATH`. Multiple writers in cli.mjs read that
//     env var to compute their target path.
//   - Prior to v0.1.18, the SARIF/CSV/MD output blocks hardcoded `'out'`,
//     ignoring `--out`. This helper centralizes the resolution so the bug
//     can't recur in a new format writer (Task N.17).
//   - `OPENAI_OUT_PATH` is honored as a legacy fallback.

import path from 'node:path';
import { toCleanPath } from './path_helpers.mjs';

/**
 * Resolve the base output directory.
 *
 * Source priority:
 *   1. `process.env.SCAN_OUT_PATH` (set by `--out <dir>`)
 *   2. `process.env.OPENAI_OUT_PATH` (legacy fallback)
 *   3. `'out'` (default)
 *
 * If the resolved value points at a file (has an extension), returns its
 * parent directory. This handles the "user passed --out report.json" case
 * — we use the file's containing directory rather than crashing.
 *
 * Read fresh each call so callers see the latest env state (important
 * because the CLI sets SCAN_OUT_PATH during arg parsing, after module load).
 *
 * @returns {string} A directory path; never empty (defaults to `'out'`).
 */
export function resolveBaseOutDir() {
  const raw = toCleanPath(
    process.env.SCAN_OUT_PATH || process.env.OPENAI_OUT_PATH || 'out'
  );
  const parsed = path.parse(raw);
  // If env var pointed at a file (has an extension), use its parent dir.
  // Otherwise treat the whole value as a directory.
  return parsed.ext ? (parsed.dir || 'out') : (raw || 'out');
}

// (toCleanPath moved to utils/path_helpers.mjs in v0.1.20 — no _internals export needed.)
