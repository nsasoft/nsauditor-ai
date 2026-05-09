// utils/mcp_auth.mjs
// ─────────────────────────────────────────────────────────────────────────────
// EE-SEC.1 — MCP server authentication.
//
// The MCP server (`mcp_server.mjs`) uses stdio transport, which means the
// server runs as a subprocess of whatever client launched it (Claude
// Desktop, Claude Code, custom IDE integration). Pre-EE-SEC.1, ANY
// process running as the operator could `child_process.spawn('node',
// ['mcp_server.mjs'])` and call the Pro/Enterprise tools — including
// the AWS-talking shadow-admin path detectors that ship in EE 0.3.4.
//
// Threat model the gap enables:
//   - Code-execution-as-operator escalation: a malicious npm post-install,
//     a compromised browser extension, a hostile dev tool can spawn the
//     server and use its tools to scan the operator's AWS account,
//     mutate finding queues, or exfiltrate license-gated SOC 2 evidence.
//   - Multi-user shared machines: any user on a shared dev box / CI
//     runner can launch the MCP server as themselves.
//   - Future HTTP transport risk: if SSE/HTTP is ever added, the same
//     gap becomes network-exposed.
//
// Mitigation: shared-secret authentication. The operator runs
// `nsauditor-ai mcp install-key` once, which generates a 256-bit
// random key, persists it via the same multi-source storage chain
// already used for license keys (env → macOS Keychain → ~/.nsauditor/.env),
// and prints a Claude Desktop config snippet that places the key in
// the spawned-process env. The MCP server resolves the EXPECTED key
// at startup from storage, reads the PRESENTED key from
// process.env.NSA_MCP_AUTH_KEY, and refuses to start unless they
// match (constant-time compare).
//
// What this defends, what it doesn't:
//   ✅ Defends against malicious code running as the operator that tries
//      to spawn the MCP server — the attacker doesn't have the key
//      because reading it requires Keychain GUI prompt approval (macOS)
//      or read-access to ~/.nsauditor/.env (which is mode 0600).
//   ✅ Defends against shared-machine other-user attacks — the key is
//      per-operator in their Keychain, not in a world-readable file.
//   ⚠ Does NOT defend against an attacker with full operator-level code
//      execution AND the ability to suppress macOS Keychain prompts.
//      Recent macOS versions log Keychain-access denial events; SIEM
//      pipelines should alarm on those.
//   ⚠ Does NOT defend against debugger-attach memory snooping — the
//      resolved key lives in MCP server process memory. Out of scope
//      for v1; same fundamental limitation as any shared-secret auth.
// ─────────────────────────────────────────────────────────────────────────────

import { promises as fsp } from 'node:fs';
import { homedir, platform } from 'node:os';
import { dirname, join } from 'node:path';
import { randomBytes, timingSafeEqual } from 'node:crypto';
import dotenv from 'dotenv';

import { keychainGet, keychainSet, keychainGetDetailed, resolveSecret } from './keychain.mjs';

// ── Constants ────────────────────────────────────────────────────────────────

// Storage key name. Kept distinct from NSAUDITOR_LICENSE_KEY so the two
// secrets are independently rotatable and the env-var pollution in
// `ps -ef` listings (Linux) is named explicitly enough that operators
// understand what it is.
export const MCP_AUTH_ENV_VAR = 'NSA_MCP_AUTH_KEY';

// Escape hatch env var. When set to "1", the MCP server skips the auth
// check entirely (with a stderr warning). For CI/dev environments where
// the operator accepts the risk.
export const MCP_AUTH_DISABLE_ENV_VAR = 'NSA_MCP_AUTH_DISABLE';

// Keychain account name (under service=nsauditor-ai). Same value as the
// env var name — keeps the storage and resolution paths symmetrically
// named so operators don't have to remember two strings.
const MCP_AUTH_KEYCHAIN_ACCOUNT = MCP_AUTH_ENV_VAR;

// EE-SEC.1.1: created-at timestamp companion. Stored alongside the key
// so `mcp status` and the server-startup stderr can emit a soft warning
// when the key has been in use for more than ROTATION_WARNING_DAYS.
// SOC 2 CC6.1 / CC6.7 reviewers expect a credential rotation cadence;
// an unrotated MCP auth key is a finding the same way an unrotated
// IAM access key is a finding.
export const MCP_AUTH_CREATED_ENV_VAR = 'NSA_MCP_AUTH_KEY_CREATED';
const MCP_AUTH_CREATED_KEYCHAIN_ACCOUNT = MCP_AUTH_CREATED_ENV_VAR;
export const ROTATION_WARNING_DAYS = 90;
// EE-SEC.1.1 MEDIUM #4 fold (post-review): operator override env var.
// SOC 2 doesn't fix a number — common interpretations span 30/60/90/180.
// PCI-DSS pushes for 90d hard; NIST SP 800-63B prefers event-based rotation.
// An operator whose customer auditor demands 60 days needs a knob; clamping
// to [7, 365] prevents pathological values (sub-week = constant-warn-noise;
// > 1 year = effectively no rotation).
export const ROTATION_WARNING_DAYS_ENV_VAR = 'NSA_MCP_AUTH_KEY_ROTATION_DAYS';

/**
 * Resolve the effective rotation-warning threshold. Reads
 * NSA_MCP_AUTH_KEY_ROTATION_DAYS from the env (or `opts._env`),
 * clamps to [7, 365], falls back to ROTATION_WARNING_DAYS (90).
 *
 * @param {object} [opts]
 * @param {Record<string, string|undefined>} [opts._env]
 * @returns {number}
 */
export function getRotationWarningDays(opts = {}) {
  const env = opts._env ?? process.env;
  const raw = env[ROTATION_WARNING_DAYS_ENV_VAR];
  if (!raw) return ROTATION_WARNING_DAYS;
  const parsed = Number.parseInt(raw, 10);
  if (!Number.isFinite(parsed)) return ROTATION_WARNING_DAYS;
  return Math.max(7, Math.min(365, parsed));
}

const MS_PER_DAY = 24 * 60 * 60 * 1000;

// Key prefix. Lets operators distinguish from license keys (`pro_eyJ...`,
// `enterprise_eyJ...`) at a glance. 32 bytes of entropy → 43 chars
// base64url after the prefix.
export const MCP_AUTH_KEY_PREFIX = 'nsa_mcp_';

// Entropy width. 32 bytes = 256 bits, matches AES-256 / SHA-256 strength.
const MCP_AUTH_KEY_ENTROPY_BYTES = 32;

// One-shot permissive-mode warning per file path per process. Same
// pattern as license.mjs so a license + MCP-auth resolution in the
// same run doesn't double-warn on the shared file.
const _permissiveWarnedPaths = new Set();

// ── Key generation ───────────────────────────────────────────────────────────

/**
 * Generate a fresh MCP auth key.
 *
 * Format: `nsa_mcp_<43-char-base64url>`. 256 bits of entropy from
 * crypto.randomBytes() — same entropy class as Anthropic's session
 * tokens. URL-safe (no padding) so it's safe to paste into JSON
 * config files and shell quoted strings without escaping.
 *
 * @returns {string} The new key.
 */
export function generateMcpAuthKey() {
  const raw = randomBytes(MCP_AUTH_KEY_ENTROPY_BYTES).toString('base64url');
  return `${MCP_AUTH_KEY_PREFIX}${raw}`;
}

/**
 * Validate that a key has the expected shape. Used by the install
 * command to reject typos before persisting them. Does NOT validate
 * cryptographic provenance — there is none; the key is a shared
 * secret, not a JWT.
 *
 * @param {string} key
 * @returns {{ ok: true } | { ok: false, reason: string }}
 */
export function validateMcpAuthKeyShape(key) {
  if (typeof key !== 'string') {
    return { ok: false, reason: 'key must be a string' };
  }
  if (!key.startsWith(MCP_AUTH_KEY_PREFIX)) {
    return { ok: false, reason: `key must start with "${MCP_AUTH_KEY_PREFIX}"` };
  }
  const body = key.slice(MCP_AUTH_KEY_PREFIX.length);
  // base64url body should be ~43 chars for 32 bytes (no padding).
  // Accept 40-50 to allow for future entropy bumps; reject obvious typos.
  if (body.length < 40 || body.length > 50) {
    return { ok: false, reason: `key body length ${body.length} not in 40..50 (expected ~43 for 256-bit entropy)` };
  }
  if (!/^[A-Za-z0-9_-]+$/.test(body)) {
    // Reviewer 1 MEDIUM #4 fold: the most common cause of this error
    // in practice is paste-mistakes (trailing newline from a wrapped
    // Slack message, surrounding quotes, leading whitespace). Call
    // those out specifically so the operator doesn't go hunting for
    // a base64url problem.
    const hint = /\s/.test(body) || /[\r\n]/.test(body)
      ? ' (likely a copy-paste issue: trailing newline or surrounding whitespace)'
      : /["']/.test(body)
        ? ' (likely a copy-paste issue: surrounding quotes)'
        : '';
    return { ok: false, reason: `key body must be base64url (A-Z, a-z, 0-9, _, -)${hint}` };
  }
  return { ok: true };
}

// ── Resolver chain ───────────────────────────────────────────────────────────

/**
 * Resolve the MCP auth key from storage. Mirrors the license-key
 * resolver (license.mjs:resolveLicenseKey) — same env → Keychain →
 * file precedence so operators can use the same mental model and
 * the same dotfile/keychain entries for both secrets.
 *
 * Resolution order (first non-empty wins):
 *   1. process.env.NSA_MCP_AUTH_KEY     — CI/CD takes precedence
 *   2. macOS Keychain (service=nsauditor-ai, account=NSA_MCP_AUTH_KEY)
 *      — set by `nsauditor-ai mcp install-key` on macOS
 *   3. $XDG_CONFIG_HOME/nsauditor/.env (or ~/.nsauditor/.env)
 *      — universal file fallback
 *
 * @param {object} [opts]
 * @param {string} [opts._homeFileOverride] — test seam.
 * @param {Function} [opts._keychainGet] — test seam.
 * @returns {Promise<string|null>} The key, or null if no source had one.
 */
export async function resolveMcpAuthKey(opts = {}) {
  // 1. env var
  if (process.env[MCP_AUTH_ENV_VAR]) return process.env[MCP_AUTH_ENV_VAR];

  // 2. macOS Keychain
  const kget = opts._keychainGet ?? keychainGet;
  try {
    const fromKeychain = await kget(MCP_AUTH_KEYCHAIN_ACCOUNT);
    if (fromKeychain) return fromKeychain;
  } catch { /* keychain unavailable — fall through */ }

  // 3. ~/.nsauditor/.env
  const filePath = opts._homeFileOverride ?? defaultMcpAuthFilePath();
  try {
    const stat = await fsp.stat(filePath);
    if (platform() !== 'win32' && stat.isFile() && (stat.mode & 0o077) !== 0) {
      if (!_permissiveWarnedPaths.has(filePath)) {
        const modeStr = (stat.mode & 0o777).toString(8).padStart(3, '0');
        // Use stderr — stdio-MCP requires stdout to be JSON-RPC only.
        process.stderr.write(`⚠  ${filePath} has permissive mode ${modeStr} — recommend chmod 0600\n`);
        _permissiveWarnedPaths.add(filePath);
      }
    }
    const buf = await fsp.readFile(filePath, 'utf8');
    const parsed = dotenv.parse(buf);
    if (parsed[MCP_AUTH_ENV_VAR]) return parsed[MCP_AUTH_ENV_VAR];
  } catch { /* file missing / unreadable — fall through */ }

  return null;
}

/**
 * Report which source the resolver currently honors WITHOUT printing
 * the key value. Used by `nsauditor-ai mcp status` so operators can
 * verify their setup without exposing the secret to shell history /
 * tmux scrollback / screen-share.
 *
 * EE-SEC.1.1: extended with `ageDays` (when a created-at timestamp is
 * available) so `mcp status` and the server-startup stderr can emit a
 * soft warning when the key has been in use for more than
 * ROTATION_WARNING_DAYS. Also distinguishes Keychain-locked from
 * Keychain-empty so headless macOS / SSH-only CI runners get an
 * actionable error rather than a generic "unconfigured" fallthrough.
 *
 * @param {object} [opts] — same test seams as resolveMcpAuthKey, plus
 *   `_keychainGetDetailed` for the lock-state distinction and `_now`
 *   for hermetic age computation.
 * @returns {Promise<{
 *   source: 'env'|'keychain'|'file'|'unconfigured'|'keychain-locked',
 *   detail?: string,
 *   ageDays?: number|null,
 *   createdAt?: string|null,
 * }>}
 */
export async function reportMcpAuthSource(opts = {}) {
  const now = opts._now ? new Date(opts._now).getTime() : Date.now();

  if (process.env[MCP_AUTH_ENV_VAR]) {
    // No createdAt available for env-supplied keys — operator-managed,
    // we don't know the rotation history. EE-SEC.1.1 CRITICAL #1 fold:
    // surface a `legacyTimestampMissing: false` here so callers don't
    // mis-interpret env-supplied as "old install missing timestamp".
    return {
      source: 'env',
      detail: MCP_AUTH_ENV_VAR,
      ageDays: null,
      createdAt: null,
      legacyTimestampMissing: false,
    };
  }

  // EE-SEC.1.1: use detailed Keychain lookup so lock-state is preserved.
  // Backward-compat: legacy callers (and EE-SEC.1 tests) supply
  // _keychainGet which returns just `string|null`. Wrap it into the
  // detailed shape so the resolver works for both APIs.
  let kgetDetailed;
  if (opts._keychainGetDetailed) {
    kgetDetailed = opts._keychainGetDetailed;
  } else if (opts._keychainGet) {
    const legacyKget = opts._keychainGet;
    kgetDetailed = async (account) => {
      try {
        const value = await legacyKget(account);
        return value
          ? { value, state: 'ok' }
          : { value: null, state: 'not-found' };
      } catch (err) {
        return { value: null, state: 'unavailable', raw: err && err.message ? err.message : String(err) };
      }
    };
  } else {
    kgetDetailed = keychainGetDetailed;
  }
  let detailedResult = null;
  try {
    detailedResult = await kgetDetailed(MCP_AUTH_KEYCHAIN_ACCOUNT);
  } catch { /* defensive — should never throw, but tolerate test seams that do */ }
  if (detailedResult && detailedResult.state === 'ok' && detailedResult.value) {
    // Read the companion timestamp (best-effort; old installs may not
    // have it). EE-SEC.1.1: skip the timestamp lookup when the caller
    // only supplied the legacy `_keychainGet` seam — that seam returns
    // the same value for any account name (it's a single-account stub),
    // so calling it for the timestamp contaminates the result with the
    // key value. Real `keychainGetDetailed` properly distinguishes by
    // account.
    let createdAt = null;
    const usedLegacySeam = !opts._keychainGetDetailed && opts._keychainGet;
    if (!usedLegacySeam) {
      try {
        const ts = await kgetDetailed(MCP_AUTH_CREATED_KEYCHAIN_ACCOUNT);
        if (ts && ts.state === 'ok' && ts.value) createdAt = ts.value;
      } catch { /* fall through */ }
    }
    return {
      source: 'keychain',
      detail: 'macOS Keychain (service=nsauditor-ai)',
      createdAt,
      ageDays: _ageDaysFromIso(createdAt, now),
      // EE-SEC.1.1 CRITICAL #1 fold: existing CE 0.1.31 operators
      // upgrading to 0.1.32 have a key but no NSA_MCP_AUTH_KEY_CREATED
      // companion — `getMcpAuthKeyAge` returns null and the rotation
      // warning silently never fires. The auditor evidence story is
      // broken until the operator happens to rotate. Distinguish
      // "legacy install missing timestamp" from "env-supplied (no
      // history known)" so cli.mjs `mcp status` and the server-startup
      // stderr can prompt operators to backfill via `mcp install-key
      // <existing-key>` (which preserves the key but writes the
      // timestamp companion).
      legacyTimestampMissing: createdAt === null,
    };
  }
  if (detailedResult && detailedResult.state === 'locked') {
    // Keychain has the entry but the security daemon refused to
    // unlock — operator's GUI is unavailable (SSH / headless CI /
    // login-keychain not unlocked yet).
    return {
      source: 'keychain-locked',
      detail: 'macOS Keychain (service=nsauditor-ai) — entry exists but interaction not allowed',
      ageDays: null,
      createdAt: null,
    };
  }

  const filePath = opts._homeFileOverride ?? defaultMcpAuthFilePath();
  try {
    const buf = await fsp.readFile(filePath, 'utf8');
    const parsed = dotenv.parse(buf);
    if (parsed[MCP_AUTH_ENV_VAR]) {
      const createdAt = parsed[MCP_AUTH_CREATED_ENV_VAR] || null;
      return {
        source: 'file',
        detail: filePath,
        createdAt,
        ageDays: _ageDaysFromIso(createdAt, now),
        // CRITICAL #1 fold: same legacy-install signal as the keychain
        // branch above.
        legacyTimestampMissing: createdAt === null,
      };
    }
  } catch { /* fall through */ }
  return { source: 'unconfigured', ageDays: null, createdAt: null };
}

/**
 * Get the age of the configured MCP auth key, in days. Returns null
 * when no key is configured or the timestamp is missing/unparseable
 * (older installs predating EE-SEC.1.1 won't have the timestamp).
 *
 * @param {object} [opts] — same test seams as reportMcpAuthSource.
 * @returns {Promise<number|null>}
 */
export async function getMcpAuthKeyAge(opts = {}) {
  const status = await reportMcpAuthSource(opts);
  return status.ageDays ?? null;
}

// Internal: parse an ISO-8601 timestamp and return age in days from
// the reference time. Returns null on parse failure or future dates.
function _ageDaysFromIso(isoString, nowMs) {
  if (typeof isoString !== 'string' || isoString.length === 0) return null;
  const ms = Date.parse(isoString);
  if (Number.isNaN(ms)) return null;
  if (ms > nowMs) return null; // clock skew — don't emit a misleading negative
  return Math.floor((nowMs - ms) / MS_PER_DAY);
}

function defaultMcpAuthFilePath() {
  if (process.env.XDG_CONFIG_HOME) {
    return join(process.env.XDG_CONFIG_HOME, 'nsauditor', '.env');
  }
  return join(homedir(), '.nsauditor', '.env');
}

// ── Persistence ──────────────────────────────────────────────────────────────

/**
 * Persist an MCP auth key to platform-appropriate storage. Mirrors
 * persistLicenseKey in license.mjs — same Keychain-first-on-darwin
 * routing with file fallback, same mode-0600 file write, same merge
 * semantics that preserve other env vars in the dotenv file.
 *
 * @param {string} key — full prefixed key (`nsa_mcp_...`).
 * @param {object} [opts]
 * @param {string} [opts._platform]         — test seam.
 * @param {Function} [opts._keychainSet]    — test seam.
 * @param {string} [opts._homeFileOverride] — test seam.
 * @returns {Promise<{ok: true, location: string, warning?: string} | {ok: false, error: string}>}
 */
export async function persistMcpAuthKey(key, opts = {}) {
  const validation = validateMcpAuthKeyShape(key);
  if (!validation.ok) {
    return { ok: false, error: `persistMcpAuthKey: ${validation.reason}` };
  }

  const plat = opts._platform ?? platform();
  const kset = opts._keychainSet ?? keychainSet;
  // EE-SEC.1.1: timestamp the key for rotation cadence tracking.
  // ISO-8601 UTC for unambiguous parsing across timezones / locales.
  // Test seam allows hermetic injection of "now".
  // Reviewer 1 MEDIUM #1 fold (post-EE-SEC.1.1): normalize _now via
  // `new Date(...).toISOString()` so callers passing an epoch-ms
  // number (valid in reportMcpAuthSource via `new Date(opts._now).getTime()`)
  // don't write an unparseable literal. Production callers always
  // omit _now; this guards the hermetic-test path symmetrically.
  const createdAt = opts._now
    ? new Date(opts._now).toISOString()
    : new Date().toISOString();

  // 1. macOS: try Keychain first.
  let keychainFallbackReason = null;
  if (plat === 'darwin') {
    try {
      // Reviewer 2 MEDIUM #2 fold (post-EE-SEC.1.1): write timestamp
      // FIRST, then key. A half-write where the timestamp succeeds
      // but the key fails leaves no usable key — auth check refuses
      // the next startup → fail-CLOSED. Pre-fold the order was
      // reversed: a half-write left a usable key with no timestamp,
      // silently disabling rotation-cadence warnings forever.
      // Companion writes use the same kset; if the FIRST one fails
      // we fall through to file storage (full reset) rather than
      // leaving partial state.
      await kset(MCP_AUTH_CREATED_KEYCHAIN_ACCOUNT, createdAt);
      await kset(MCP_AUTH_KEYCHAIN_ACCOUNT, key);
      return { ok: true, location: 'macOS Keychain (service=nsauditor-ai)', createdAt };
    } catch (err) {
      keychainFallbackReason = err && err.message ? err.message : String(err);
    }
  }

  // 2. File-based storage (Linux, Windows, macOS Keychain fallback).
  try {
    const filePath = opts._homeFileOverride ?? defaultMcpAuthFilePath();
    const dir = dirname(filePath);
    await fsp.mkdir(dir, { recursive: true, mode: 0o700 });
    // Reviewer 2 MEDIUM #1 fold: `mkdir mode` only applies on FIRST
    // creation (Node mirrors POSIX semantics). If the dir already
    // existed (e.g., license-key flow created it as 0755), the 0700
    // mode is silently ignored. Explicit chmod after mkdir guarantees
    // the secret-bearing parent dir is operator-only on POSIX.
    if (plat !== 'win32') {
      try {
        await fsp.chmod(dir, 0o700);
      } catch { /* best effort; some FSes (NFS) reject chmod */ }
    }

    let existingContent = '';
    try {
      existingContent = await fsp.readFile(filePath, 'utf8');
    } catch { /* missing file — create one */ }

    // EE-SEC.1.1: write BOTH the key and the created-at timestamp.
    // Same merge semantics — preserves other env-vars, replaces
    // existing values, drops duplicates. The two writes are atomic
    // at the file level (single writeFile call after merging both
    // into the new content).
    //
    // Reviewer 2 MEDIUM #1 fold (post-EE-SEC.1.1): write to a
    // sibling .tmp file first, then rename() — POSIX rename is
    // atomic, so concurrent readers see either the OLD file or the
    // NEW file, never a truncated mid-write state. Fixes the race
    // where `mcp status` running simultaneously with `mcp install-key`
    // could observe an empty file → "unconfigured" → operator
    // confusion. Also defends against host-crash mid-write losing
    // both the key AND the timestamp.
    let newContent = mergeMcpAuthIntoEnvFile(existingContent, key);
    newContent = mergeMcpAuthCreatedIntoEnvFile(newContent, createdAt);
    const tmpPath = `${filePath}.tmp`;
    await fsp.writeFile(tmpPath, newContent, { mode: 0o600 });
    if (plat !== 'win32') {
      await fsp.chmod(tmpPath, 0o600);
    }
    await fsp.rename(tmpPath, filePath);
    if (plat !== 'win32') {
      // rename preserves source mode on POSIX, but a chmod after is
      // belt-and-suspenders if the source mode was somehow changed.
      await fsp.chmod(filePath, 0o600);
    }

    const result = { ok: true, location: filePath, createdAt };
    if (keychainFallbackReason !== null) {
      result.warning =
        `macOS Keychain unavailable (${keychainFallbackReason}); fell back to file storage. ` +
        `Re-run after granting Keychain access for stronger protection.`;
    }
    return result;
  } catch (err) {
    return { ok: false, error: err.message };
  }
}

/**
 * Merge an MCP auth key into a dotenv-format file content, preserving
 * every OTHER line. Mirrors mergeLicenseIntoEnvFile (license.mjs:242)
 * — same multi-occurrence safety and CRLF preservation.
 *
 * - If a NSA_MCP_AUTH_KEY line already exists, replace the first
 *   occurrence and remove duplicates (corrupted-file defense).
 * - If the file is empty, write a header comment.
 * - Otherwise append.
 *
 * Exported for test coverage.
 * @internal
 */
export function mergeMcpAuthIntoEnvFile(existingContent, key) {
  return mergeKeyValueIntoEnvFile(
    existingContent,
    MCP_AUTH_ENV_VAR,
    key,
    `# NSAuditor AI MCP auth key — set via \`nsauditor-ai mcp install-key\``,
  );
}

/**
 * Merge a created-at timestamp companion line. EE-SEC.1.1 — used by
 * persistMcpAuthKey to write `NSA_MCP_AUTH_KEY_CREATED=<ISO-8601>`
 * alongside the auth key for rotation-cadence tracking.
 *
 * Exported for test coverage.
 * @internal
 */
export function mergeMcpAuthCreatedIntoEnvFile(existingContent, createdAt) {
  return mergeKeyValueIntoEnvFile(
    existingContent,
    MCP_AUTH_CREATED_ENV_VAR,
    createdAt,
    null, // no header — already present from the key line
  );
}

/**
 * Generic dotenv-format merge: replace `${name}=...` line if present
 * (collapsing duplicates per the corrupted-file defense), append at
 * end if absent, write a header for empty input.
 *
 * EE-SEC.1.1 (Thread I refactor): the original merge logic was
 * copy-pasted between the auth-key and (now) created-at lines; this
 * factor-out also addresses Reviewer 2 LOW #2 from EE-SEC.1 (the
 * universal-exclusion + sentinel-string duplication concern — both
 * are now contained in a single helper).
 *
 * Reviewer 1 MEDIUM #5 fold (preserved): regex metacharacters in
 * `name` are escaped before interpolation. Today the names are
 * `NSA_MCP_AUTH_KEY` and `NSA_MCP_AUTH_KEY_CREATED` (no specials),
 * so this is defense-in-depth — but a future rename containing
 * `.+?^${}()|[]\\` would silently break the merge without this guard.
 *
 * @param {string} existingContent — current dotenv file content.
 * @param {string} name — env-var name to write/replace.
 * @param {string} value — value to assign.
 * @param {string|null} headerComment — optional header to write when
 *   the file is empty (e.g., `# NSAuditor AI MCP auth key — ...`).
 * @internal
 */
export function mergeKeyValueIntoEnvFile(existingContent, name, value, headerComment = null) {
  const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const KEY_LINE_RE = new RegExp(
    `^[ \\t]*${escaped}[ \\t]*=[^\\r\\n]*$`,
    'gm',
  );
  const newLine = `${name}=${value}`;
  // Sentinel includes the env-var name to avoid the (astronomical
  // but possible) collision concern Reviewer 2 LOW #2 raised — the
  // sentinel is now per-key rather than global.
  const PURGE_SENTINEL = `__NSAUDITOR_PURGE_${name}__`;

  const matches = existingContent.match(KEY_LINE_RE);
  if (matches && matches.length > 0) {
    let firstReplaced = false;
    let merged = existingContent.replace(KEY_LINE_RE, () => {
      if (firstReplaced) return PURGE_SENTINEL;
      firstReplaced = true;
      return newLine;
    });
    const sentinelRe = new RegExp(
      PURGE_SENTINEL.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\r?\\n?',
      'g',
    );
    merged = merged.replace(sentinelRe, '');
    return merged;
  }

  if (existingContent.trim().length === 0) {
    const header = headerComment ? `${headerComment}\n` : '';
    return `${header}${newLine}\n`;
  }

  const sep = existingContent.endsWith('\n') ? '' : '\n';
  return `${existingContent}${sep}${newLine}\n`;
}

// ── Constant-time comparison ─────────────────────────────────────────────────

/**
 * Compare two MCP auth keys in constant time. Prevents timing-channel
 * attacks where an attacker measures comparison duration to learn
 * shared-secret bytes. For stdio transport the timing channel is
 * already noisy (IPC pipe scheduling) but this is free correctness
 * and matters for the future HTTP transport branch.
 *
 * Returns false (not an exception) if either argument is not a string
 * or lengths differ — same shape as a normal mismatch from the
 * caller's perspective.
 *
 * @param {string} expected
 * @param {string} presented
 * @returns {boolean}
 */
export function constantTimeMcpKeyEquals(expected, presented) {
  if (typeof expected !== 'string' || typeof presented !== 'string') return false;
  if (expected.length !== presented.length) return false;
  // Buffer.byteLength is needed because timingSafeEqual requires
  // equal-byte-length buffers; for ASCII keys (which ours always are
  // — base64url charset is ASCII) byteLength === length. Belt-and-
  // suspenders: encode explicitly.
  const a = Buffer.from(expected, 'utf8');
  const b = Buffer.from(presented, 'utf8');
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}

// ── Server-side enforcement ──────────────────────────────────────────────────

/**
 * Determine whether the MCP server should accept incoming requests.
 * Called once at startup from mcp_server.mjs — if the result is
 * `{ ok: false }`, the caller MUST exit before connecting transport.
 *
 * Routing:
 *   - NSA_MCP_AUTH_DISABLE=1 → ok: true with `bypassed: true`. The
 *     `bypassedReason` field distinguishes operator-acknowledged
 *     bypass-with-key (`'configured'`) from bypass-without-any-key
 *     (`'unconfigured'`) so the server stderr can flag the latter
 *     loudly — that's the case where an operator forgot they had
 *     DISABLE=1 in their shell rc and never ran install-key
 *     (Reviewer 1 CRITICAL #2 fold).
 *   - Storage has no key → ok: false with actionable error pointing
 *     at `nsauditor-ai mcp install-key`. Refuse to start.
 *   - Storage has key, NSA_MCP_AUTH_KEY env unset → ok: false with
 *     "did you forget to update Claude Desktop config" hint.
 *   - Storage has key, NSA_MCP_AUTH_KEY env set, mismatch → ok: false
 *     with "did you forget to update after `mcp rotate-key`" hint.
 *   - Match → ok: true.
 *
 * EE-SEC.1.1 fold (Reviewer 2 CRITICAL #2): the presented env value
 * is passed through `resolveSecret()` so the operator can use the
 * `keychain:LABEL` indirection in their Claude Desktop config —
 * keeping the secret in the Keychain instead of baking it into the
 * world-readable config file. macOS-only feature; on Linux/Windows
 * the env var holds the literal key as before.
 *
 * @param {object} [opts]
 * @param {string} [opts._homeFileOverride] — test seam.
 * @param {Function} [opts._keychainGet] — test seam.
 * @param {Function} [opts._resolveSecret] — test seam for keychain: prefix resolution.
 * @param {Record<string, string|undefined>} [opts._env] — test seam (default process.env).
 * @returns {Promise<{ ok: true, bypassed?: boolean, bypassedReason?: 'configured'|'unconfigured' } | { ok: false, error: string }>}
 */
export async function authorizeMcpServerStartup(opts = {}) {
  const env = opts._env ?? process.env;

  // Resolve EXPECTED key from storage FIRST so the bypass branch can
  // tell whether a key was ever installed. We deliberately do NOT use
  // resolveMcpAuthKey here: that includes the env-var branch, but we
  // want env-var to participate ONLY for the PRESENTED key, never for
  // the "configured" baseline (using env for both would let an
  // attacker self-validate by setting NSA_MCP_AUTH_KEY in the spawned
  // server's env).
  let expected = null;
  const kget = opts._keychainGet ?? keychainGet;
  try {
    const fromKeychain = await kget(MCP_AUTH_KEYCHAIN_ACCOUNT);
    if (fromKeychain) expected = fromKeychain;
  } catch { /* keychain unavailable */ }

  if (!expected) {
    const filePath = opts._homeFileOverride ?? defaultMcpAuthFilePath();
    try {
      const buf = await fsp.readFile(filePath, 'utf8');
      const parsed = dotenv.parse(buf);
      // MEDIUM #1 fold (Reviewer 1): treat empty-string parsed value
      // ("NSA_MCP_AUTH_KEY=") as "no key configured" — consistent with
      // the env-var branch in resolveMcpAuthKey which uses falsy check.
      if (parsed[MCP_AUTH_ENV_VAR]) expected = parsed[MCP_AUTH_ENV_VAR];
    } catch { /* file missing — leaves expected null */ }
  }

  // CRITICAL #2 fold (Reviewer 1): bypass routing now distinguishes
  // bootstrap-state (no key has ever been installed) from operational
  // bypass (operator has a key but explicitly disabled). The server
  // emits a different stderr warning for each case so an operator
  // who forgot DISABLE=1 in their shell rc sees a louder signal.
  if (env[MCP_AUTH_DISABLE_ENV_VAR] === '1') {
    return {
      ok: true,
      bypassed: true,
      bypassedReason: expected ? 'configured' : 'unconfigured',
    };
  }

  if (!expected) {
    return {
      ok: false,
      error:
        `MCP authentication is not configured. Run \`nsauditor-ai mcp install-key\` ` +
        `to generate a key, then add it to your Claude Desktop config under ` +
        `env: { "${MCP_AUTH_ENV_VAR}": "..." }. ` +
        `If you intentionally want to run without auth (e.g., in CI), set ` +
        `${MCP_AUTH_DISABLE_ENV_VAR}=1 — note that anyone with code execution ` +
        `as your user can then call MCP tools.`,
    };
  }

  const presentedRaw = env[MCP_AUTH_ENV_VAR];
  if (!presentedRaw) {
    return {
      ok: false,
      error:
        `MCP authentication failed: ${MCP_AUTH_ENV_VAR} env var is not set, but a key ` +
        `is configured in storage. Did you forget to update your Claude Desktop config? ` +
        `Run \`nsauditor-ai mcp print-key --confirm\` to retrieve the configured key, ` +
        `or use the keychain: indirection (see \`nsauditor-ai mcp install-key\` output).`,
    };
  }

  // EE-SEC.1.1: resolve `keychain:LABEL` prefix in the presented env
  // value so operators can keep the secret in Keychain (macOS) and
  // reference it from the world-readable Claude Desktop config file.
  // For literal-string env values, resolveSecret returns the string
  // unchanged. _resolveSecret test seam allows hermetic injection.
  const _resolve = opts._resolveSecret ?? resolveSecret;
  let presented;
  try {
    presented = await _resolve(presentedRaw);
  } catch {
    presented = null;
  }
  if (!presented) {
    // The keychain: prefix was used but the Keychain entry is missing
    // / locked / inaccessible. Distinguish from plain mismatch so the
    // operator can debug.
    if (typeof presentedRaw === 'string' && presentedRaw.startsWith('keychain:')) {
      return {
        ok: false,
        error:
          `MCP authentication failed: ${MCP_AUTH_ENV_VAR} uses keychain: indirection ` +
          `but the referenced Keychain entry could not be read. ` +
          `Run \`nsauditor-ai mcp status\` to verify the entry exists. ` +
          `On a headless macOS / CI runner, replace the indirection with the literal ` +
          `key value or move auth to ~/.nsauditor/.env.`,
      };
    }
    return {
      ok: false,
      error: `MCP authentication failed: ${MCP_AUTH_ENV_VAR} env var resolved to empty.`,
    };
  }

  if (!constantTimeMcpKeyEquals(expected, presented)) {
    return {
      ok: false,
      error:
        `MCP authentication failed: the ${MCP_AUTH_ENV_VAR} env var does not match the ` +
        `key configured in storage. Did you forget to update Claude Desktop config after ` +
        `\`nsauditor-ai mcp rotate-key\`? ` +
        `Run \`nsauditor-ai mcp status\` to see which storage source is active.`,
    };
  }

  return { ok: true };
}
