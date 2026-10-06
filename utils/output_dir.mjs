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

import fsp from 'node:fs/promises';
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
  // If env var pointed at a FILE, use its parent dir; otherwise treat the whole
  // value as a directory.
  //
  // ⚠️ "Has a dot" is NOT the same as "is a file", and reading it that way was a
  // silent evidence-misplacement bug (found by the EE 0.32.8 pre-publish smoke
  // gate). `path.parse('ee-0.32.8').ext` is `'.8'`, so `--out .../ee-0.32.8`
  // resolved to `.../` and every artifact landed in the PARENT folder — exit 0,
  // no warning, evidence scattered into a directory shared with other runs. It
  // hit the naming convention this project uses for its own evidence archives,
  // and the same shape breaks `v1.2.3` and `release-2026.07`.
  //
  // A file extension starts with a LETTER (`.json`, `.html`, `.csv`, `.sarif`).
  // A trailing `.8` / `.07` / `.28` is a version or date component. Keying on the
  // first character distinguishes them without guessing at a list of known
  // extensions — and keeps the documented `--out report.json` affordance working.
  const isFileExtension = /^\.[A-Za-z]/.test(parsed.ext);
  return isFileExtension ? (parsed.dir || 'out') : (raw || 'out');
}

// (toCleanPath moved to utils/path_helpers.mjs in v0.1.20 — no _internals export needed.)

// A per-host directory's timestamp: YYYYMMDD_HHMMSS in LOCAL time, second granularity. Moved here from cli.mjs
// unchanged, beside the helper that uses it, so the directory name has ONE definition.
export function nowStamp(d = new Date()) {
  const pad = (n) => String(n).padStart(2, '0');
  return (
    d.getFullYear().toString() +
    pad(d.getMonth() + 1) +
    pad(d.getDate()) + '_' +
    pad(d.getHours()) +
    pad(d.getMinutes()) +
    pad(d.getSeconds())
  );
}

// The host as a directory-name component. Moved here from cli.mjs unchanged — the per-host report filenames
// (`scan_<host>.sarif.json` / `.csv` / `.md`) use it too, so both import it from here.
export const safeHost = (h) => String(h ?? 'unknown').replace(/[\/\\?%*:|"<>]/g, '_');

/**
 * Create a FRESH per-host output directory and return its path.
 *
 * ⚠️ AN EXCLUSIVE CREATE, NEVER `recursive: true` ON THE LEAF (1.1.1 board — Gate 3-B on build 12). The name is
 * `${safeHost(host)}_${nowStamp()}`, second-granular, so two scans of one host reaching this line in the same
 * second computed the SAME name, and a recursive mkdir said yes to both: measured, three localhost scans wrote TWO
 * directories and run 2's `scan_conclusion_raw.json` was overwritten by run 3's, exit 0, no warning. It is worse when
 * the later run's finding queue is EMPTY — Enterprise writes `scan_finding_queue.json` only when there is something
 * to write, so the earlier run's queue stayed in the shared directory and the later run's seal covered it as its own.
 * The same second is reachable three ways: back-to-back runs, one run naming a host twice (`--host X,X`), and the
 * repeated hour when daylight saving ends (the stamp is local time).
 *
 * So the leaf is created with `recursive: false`, which fails with EEXIST instead of reusing a directory, and a
 * collision takes the next free suffix (`_2`, `_3`, …) — a COUNTER, not the run id: the run id is shared by every
 * host of one run (so it cannot separate `--host X,X`) and is unset in watch mode. A WARNING naming both directories
 * goes to STDOUT, where a scan's own progress lines go.
 *
 * ⚠️ When the seconds differ nothing changes: the name is byte-identical to the one this code has always written,
 * because every reader, every run record's `hostsWritten[].dir` and every manifest keys on it.
 *
 * @param {string} baseOutDir   created if absent (recursively — the BASE may already exist; the leaf may not)
 * @param {string} host
 * @param {{ stamp?: () => string, log?: (line: string) => void, max?: number }} [opts]
 *        `stamp` and `log` are seams; every real invocation takes the defaults.
 * @returns {Promise<string>} the directory created
 */
export async function createHostOutDir(baseOutDir, host, { stamp = nowStamp, log = console.log, max = 100 } = {}) {
  await fsp.mkdir(baseOutDir, { recursive: true });
  // The stamp is taken ONCE: a suffix always belongs to the second it collided with.
  const first = `${safeHost(host)}_${stamp()}`;
  for (let n = 1; n <= max; n += 1) {
    const dir = path.join(baseOutDir, n === 1 ? first : `${first}_${n}`);
    try {
      await fsp.mkdir(dir, { recursive: false });
    } catch (e) {
      if (e?.code === 'EEXIST') continue;
      throw e;
    }
    if (n > 1) {
      // v77-8 (1.3.0): the directory is stamped after the plugin runs, so the collision is two runs that FINISHED in the same
      // second — they may have started minutes apart (README: "whose plugin runs finished in the same second").
      log(`[scan] WARNING: ${path.join(baseOutDir, first)} already exists — another scan of ${host} finished its plugin runs in `
        + `the same second — so this scan writes to ${dir} instead. Neither run's evidence overwrites the other's.`);
    }
    return dir;
  }
  // ⚠️ NEVER fall back to reusing an existing directory: that is the overwrite this function exists to prevent.
  throw new Error(`could not create a fresh output directory for ${host} under ${baseOutDir}: `
    + `${first} and ${max - 1} suffixed names already exist`);
}
