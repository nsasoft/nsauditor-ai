// utils/license.mjs
// JWT license verification for NSAuditor AI.
// Uses ES256 (ECDSA P-256) public key embedded below — no file I/O needed.
//
// KEY ROTATION: If the private key is compromised, generate a new EC P-256 key
// pair, update PUBLIC_KEY_PEM below, and ship a CE update. All existing JWTs
// become invalid. See license-manager docs/architecture.md for full procedure.
//
// CE 0.1.70 (EE 0.9.1 paired) — air-gap operational hardening per external
// audit 2026-05-22:
//   • D-HIGH-1: per-host licenseId replay defense (persisted on first
//     activation; subsequent loads with a different licenseId fail-closed
//     to CE). Closes the seat-cloning class — a `seats:N` token cannot be
//     installed on N+1 machines without operator-noticeable rejection.
//   • D-HIGH-2: signed revocation blocklist baked into the package
//     (`data/license-revocations.json`). The license-manager service
//     signs the envelope with the production ES256 key; this verifier
//     validates the signature before honoring the revocation list.
//     Vendors can revoke individual licenses via CE patch bump without
//     PUBLIC_KEY_PEM rotation (which would invalidate ALL licenses).
//   • D-HIGH-3: monotonic-clock anchor — persisted `last_seen_unix_ts`
//     is checked on each load; a wall-clock rewind beyond CLOCK_ROLLBACK
//     _TOLERANCE_S fails-closed to CE. Defeats `faketime`-style attacks
//     against the JWT `exp` claim in air-gap deployments where NTP cannot
//     be consulted at verification time.

import { jwtVerify, importSPKI } from 'jose';
import { promises as fsp } from 'node:fs';
import * as fsSync from 'node:fs';
import { homedir, platform } from 'node:os';
import { dirname, join } from 'node:path';
import { createPublicKey, createVerify } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import dotenv from 'dotenv';
import { keychainGet, keychainSet, resolveSecret } from './keychain.mjs';

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

// ── CE 0.1.70 — Air-gap hardening constants ──────────────────────────────────
//
// Wall-clock rewind tolerance: a 5-minute slack covers NTP step adjustments,
// DST transitions on misconfigured systems, and brief clock skew between
// suspend/resume cycles. Beyond this, treat as clock-rollback attempt.
// Tunable via NSAUDITOR_LICENSE_CLOCK_TOLERANCE_S for support-only use.
const CLOCK_ROLLBACK_TOLERANCE_S = 5 * 60;

// Persisted state file basename. Lives at:
//   • Linux:   $XDG_STATE_HOME/nsauditor/license-state.json
//              (falls back to ~/.local/state/nsauditor/license-state.json,
//              then ~/.nsauditor/license-state.json)
//   • Windows: %LOCALAPPDATA%\nsauditor\license-state.json
//   • macOS:   ~/.nsauditor/license-state.json (licenseId ALSO persisted in
//              Keychain via service=nsauditor-ai account=NSAUDITOR_LICENSE_ID;
//              Keychain wins on read when both exist).
const LICENSE_STATE_BASENAME = 'license-state.json';
const LICENSE_ID_KEYCHAIN_ACCOUNT = 'NSAUDITOR_LICENSE_ID';

// Shipped revocation blocklist. ES256-signed envelope at this path; updated
// by the license-manager service and shipped in each CE patch via the
// package.json `files` array. Verifier reads, validates signature against
// the same PUBLIC_KEY_PEM above, and returns the `revoked` array.
const REVOCATION_BLOCKLIST_PATH = fileURLToPath(
  new URL('../data/license-revocations.json', import.meta.url),
);

// Escape-hatch env vars — DOCUMENTED AS SUPPORT-ONLY. Operators with edge-
// case deployment requirements (hardware migration without vendor support,
// emergency clock rollback for a stuck system, etc.) can disable individual
// defenses. Accepted disable values per `_envDisabled` are case-insensitive:
// `0` / `false` / `no` / `off` / `disabled`. Default ENABLED for all three.
//
// Persistent audit trail (operator-visible record of which defenses were
// disabled across loadLicense calls) is deferred to CE 0.1.71 — see
// `tasks/external-audit-findings-2026-05-22.md` next-cycle item. For 0.9.1
// the disables are runtime-only; operators concerned about defense hygiene
// should grep their env for these names at deployment time.
const ENV_REPLAY_DEFENSE = 'NSAUDITOR_LICENSE_ID_REPLAY_DEFENSE';
const ENV_REVOCATION_CHECK = 'NSAUDITOR_LICENSE_REVOCATION_CHECK';
const ENV_CLOCK_ANCHOR = 'NSAUDITOR_LICENSE_CLOCK_ANCHOR';

// P1.D R2-HIGH fold: accept all common falsy notations + normalize case
// per [[aws_string_case_normalization]] discipline. Operators who set
// `=False` (capital F) or `=off` or `=no` previously left the defense
// enabled — silently broke the support-only docstring promise.
const _ENV_DISABLE_VALUES = new Set(['0', 'false', 'no', 'off', 'disabled']);
function _envDisabled(name) {
  const raw = process.env[name];
  if (raw === undefined || raw === null) return false;
  return _ENV_DISABLE_VALUES.has(String(raw).trim().toLowerCase());
}

function _resolveClockToleranceS() {
  const v = parseInt(process.env.NSAUDITOR_LICENSE_CLOCK_TOLERANCE_S ?? '', 10);
  if (!Number.isFinite(v) || v < 0) return CLOCK_ROLLBACK_TOLERANCE_S;
  // P1.D R2-MED fold: cap at 24h. Anything beyond a day is not a "clock
  // skew" — it's a backdoor disable of D-HIGH-3 without going through the
  // documented NSAUDITOR_LICENSE_CLOCK_ANCHOR=0 escape hatch. Cap surfaces
  // the abuse via the more-visible explicit env var.
  return Math.min(v, 24 * 60 * 60);
}

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
 * CE-0.1.30.2 — multi-source license-key resolution chain.
 *
 * Resolution order (first non-empty wins):
 *   1. process.env.NSAUDITOR_LICENSE_KEY   — CI/CD takes precedence
 *   2. macOS Keychain (service=nsauditor-ai, account=NSAUDITOR_LICENSE_KEY)
 *      — set by `nsauditor-ai license install <KEY>` on macOS
 *   3. $XDG_CONFIG_HOME/nsauditor/.env (or ~/.nsauditor/.env) — universal
 *      file fallback; set by `license install` on Linux/Windows OR
 *      manually edited by the operator. Mode 0600 expected; permissive
 *      mode triggers a warning (still loaded — operator's choice).
 *
 * @param {object} [opts]
 * @param {string} [opts._homeFileOverride]  — test seam. Path to a .env-format
 *   file to read instead of ~/.nsauditor/.env. Bypasses XDG resolution.
 * @param {Function} [opts._keychainGet]      — test seam. Replaces the macOS
 *   Keychain reader.
 * @returns {Promise<string|null>} The license key string, or null if no
 *   source had one.
 */
export async function resolveLicenseKey(opts = {}) {
  // 1. env var
  if (process.env.NSAUDITOR_LICENSE_KEY) return process.env.NSAUDITOR_LICENSE_KEY;

  // 2. platform secret store (macOS Keychain today; Linux/Windows skip)
  const kget = opts._keychainGet ?? keychainGet;
  try {
    const fromKeychain = await kget('NSAUDITOR_LICENSE_KEY');
    if (fromKeychain) return fromKeychain;
  } catch { /* keychain unavailable — fall through */ }

  // 3. ~/.nsauditor/.env (or $XDG_CONFIG_HOME/nsauditor/.env)
  const filePath = opts._homeFileOverride ?? defaultLicenseFilePath();
  try {
    const stat = await fsp.stat(filePath);
    // Warn (non-fatal) if mode is more permissive than 0600 on POSIX.
    // Windows has no concept of POSIX file mode; skip the check there.
    // Reviewer M10 fold: only warn once per path per process to avoid
    // spamming the console under repeated CLI invocations.
    if (platform() !== 'win32' && stat.isFile() && (stat.mode & 0o077) !== 0) {
      if (!_permissiveWarnedPaths.has(filePath)) {
        const modeStr = (stat.mode & 0o777).toString(8).padStart(3, '0');
        console.warn(`⚠  ${filePath} has permissive mode ${modeStr} — recommend chmod 0600`);
        _permissiveWarnedPaths.add(filePath);
      }
    }
    const buf = await fsp.readFile(filePath, 'utf8');
    const parsed = dotenv.parse(buf);
    if (parsed.NSAUDITOR_LICENSE_KEY) return parsed.NSAUDITOR_LICENSE_KEY;
  } catch { /* file missing / unreadable — fall through */ }

  return null;
}

// CE-0.1.30.2 reviewer M10: one-shot permissive-mode warning per path per
// process. Without this, every `loadLicense()` call against a 0644 file
// emits a console.warn — and CE re-resolves on every CLI invocation
// (plus the `cmd === 'license'` branch double-calls today, see reviewer
// M7 follow-up). Module-scoped Set keeps memory bounded (~1 path per
// install) and silences the noise without hiding the message from
// operators who haven't seen it yet.
const _permissiveWarnedPaths = new Set();

function defaultLicenseFilePath() {
  // Honor $XDG_CONFIG_HOME (Linux convention; some macOS users set it).
  // Falls back to ~/.nsauditor/.env which is what the existing README
  // method-2 docs already promise.
  if (process.env.XDG_CONFIG_HOME) {
    return join(process.env.XDG_CONFIG_HOME, 'nsauditor', '.env');
  }
  return join(homedir(), '.nsauditor', '.env');
}

/**
 * CE-0.1.30.4 — persist a verified license key to a platform-appropriate
 * location so subsequent `loadLicense()` calls find it via the resolver
 * chain (CE-0.1.30.2).
 *
 * Platform routing:
 *   - macOS:    keychainSet('NSAUDITOR_LICENSE_KEY', key) via the existing
 *               utils/keychain.mjs helper. If Keychain is unavailable
 *               (e.g., headless mac without `security` daemon, user
 *               denied the prompt), falls back to the file path so
 *               install does not silently fail.
 *   - Linux:    write $XDG_CONFIG_HOME/nsauditor/.env (or ~/.nsauditor/.env)
 *               with mode 0600 (parent dir 0700). Preserves any OTHER
 *               env-vars the operator has in the file — only the
 *               NSAUDITOR_LICENSE_KEY line is replaced/added.
 *   - Windows:  same file path (%USERPROFILE%\.nsauditor\.env). No DPAPI
 *               yet — defer to a future release; the file ACL inherits
 *               from the user profile which is typically restrictive
 *               enough on Windows 10+.
 *
 * The caller MUST verify the key via loadLicense() BEFORE calling
 * persistLicenseKey() — this function does not validate. Persisting an
 * invalid or expired key would store garbage and the next loadLicense()
 * call would just reject it again, but doing so silently undermines the
 * `install` command's contract ("we only persist verified keys").
 *
 * @param {string} key - The full prefixed key (`pro_eyJ...` or `enterprise_eyJ...`).
 * @param {object} [opts]
 * @param {string} [opts._platform]         - Test seam (override Node's platform()).
 * @param {Function} [opts._keychainSet]    - Test seam (replace Keychain writer).
 * @param {string} [opts._homeFileOverride] - Test seam (override the file path).
 * @returns {Promise<{ok: true, location: string} | {ok: false, error: string}>}
 *   On success, `location` is a human-readable string ("macOS Keychain
 *   (service=nsauditor-ai)" or the filesystem path). The `install`
 *   command surfaces this so the operator knows where the key landed.
 */
export async function persistLicenseKey(key, opts = {}) {
  if (typeof key !== 'string' || key.length === 0) {
    return { ok: false, error: 'persistLicenseKey: key must be a non-empty string' };
  }

  const plat = opts._platform ?? platform();
  const kset = opts._keychainSet ?? keychainSet;

  // 1. macOS: try Keychain first.
  // Reviewer M1 fold: track Keychain-fallback reason so the caller can
  // surface it to the operator. Pre-fix, the fallback was silent — the
  // operator only learned about it implicitly via the `location` line
  // showing a filesystem path instead of "macOS Keychain (...)".
  let keychainFallbackReason = null;
  if (plat === 'darwin') {
    try {
      await kset('NSAUDITOR_LICENSE_KEY', key);
      return { ok: true, location: 'macOS Keychain (service=nsauditor-ai)' };
    } catch (err) {
      // Fall through to file-based storage. Examples: `security` daemon
      // unavailable on headless mac; user denied the Keychain prompt;
      // SIP-restricted environment.
      keychainFallbackReason = err && err.message ? err.message : String(err);
    }
  }

  // 2. File-based storage (Linux, Windows, macOS Keychain fallback).
  try {
    const filePath = opts._homeFileOverride ?? defaultLicenseFilePath();
    const dir = dirname(filePath);
    // Create dir with 0700 if missing (recursive=true is a no-op if it
    // already exists; mode is only applied to NEW dirs along the path).
    await fsp.mkdir(dir, { recursive: true, mode: 0o700 });

    // Preserve other env-vars in an existing file. Read-modify-write
    // pattern: parse current contents, replace/add the
    // NSAUDITOR_LICENSE_KEY line, write back.
    let existingContent = '';
    try {
      existingContent = await fsp.readFile(filePath, 'utf8');
    } catch { /* missing file — fine, we'll create one */ }

    const newContent = mergeLicenseIntoEnvFile(existingContent, key);
    await fsp.writeFile(filePath, newContent, { mode: 0o600 });

    // Re-chmod in case the file pre-existed with a more permissive mode
    // (writeFile only sets mode on CREATE, not overwrite).
    if (plat !== 'win32') {
      await fsp.chmod(filePath, 0o600);
    }

    const result = { ok: true, location: filePath };
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
 * Merge a license key into the existing dotenv-format file content,
 * preserving every OTHER line. If a NSAUDITOR_LICENSE_KEY line already
 * exists, replace it; otherwise append. If the file was empty/new,
 * write a header comment.
 *
 * Reviewer M2 / M2b folds:
 *  - **Multi-occurrence safety**: a corrupted file with TWO+ existing
 *    `NSAUDITOR_LICENSE_KEY=` lines previously had only the first
 *    replaced. dotenv parses last-wins, so `--status` would show the
 *    OLD value while install reported success. Now we replace the first
 *    occurrence and remove the rest, collapsing blank lines.
 *  - **CRLF preservation**: the regex anchors on `[ \t]*` (not `\s*`,
 *    which matches `\r`) and the value-tail uses `[^\r\n]*` so Windows-
 *    style line endings are not mangled. The replacement line itself
 *    uses `\n` regardless — Notepad and dotenv both accept mixed
 *    endings, but this avoids producing them from `\r`-stripped tails.
 *
 * Exported for test coverage of the merge semantics specifically.
 * @internal
 */
export function mergeLicenseIntoEnvFile(existingContent, key) {
  const KEY_LINE_RE = /^[ \t]*NSAUDITOR_LICENSE_KEY[ \t]*=[^\r\n]*$/gm;
  const newLine = `NSAUDITOR_LICENSE_KEY=${key}`;

  // Count matches (regex needs the global flag for matchAll-equivalence).
  const matches = existingContent.match(KEY_LINE_RE);
  if (matches && matches.length > 0) {
    // Replace the first occurrence in place; remove any duplicates
    // (corrupted-file defense). Collapse the blank lines that result.
    let firstReplaced = false;
    let merged = existingContent.replace(KEY_LINE_RE, () => {
      if (firstReplaced) return '__NSAUDITOR_PURGE__';   // sentinel for removal
      firstReplaced = true;
      return newLine;
    });
    // Drop sentinel lines + their trailing newline.
    merged = merged.replace(/__NSAUDITOR_PURGE__\r?\n?/g, '');
    return merged;
  }

  if (existingContent.trim().length === 0) {
    // Empty/new file — write a header.
    return `# NSAuditor AI license — set via \`nsauditor-ai license install\`\n${newLine}\n`;
  }

  // Append to existing content (with a separating newline if needed).
  const sep = existingContent.endsWith('\n') ? '' : '\n';
  return `${existingContent}${sep}${newLine}\n`;
}

// ── CE 0.1.70 — Air-gap hardening helpers (D-HIGH-1, D-HIGH-2, D-HIGH-3) ─────

/**
 * Resolve the platform-appropriate path to the persisted license-state file.
 * Tracks `licenseId` (replay defense) and `lastSeenUnixTs` (clock anchor).
 *
 * The state file is mode 0600 (POSIX) or profile-ACL-restricted (Windows).
 * macOS additionally persists `licenseId` to the Keychain via the
 * keychainGet/keychainSet helpers; the state file is the source of truth
 * for `lastSeenUnixTs` on every platform.
 *
 * Exported for test inspection.
 * @internal
 */
export function _getLicenseStateFilePath(opts = {}) {
  if (opts._stateFile) return opts._stateFile;
  // Env-var override (test infra + advanced operators who want a custom path).
  // Honors the same NSAUDITOR_LICENSE_STATE_FILE shape used by existing
  // tests to redirect to a temp directory during test runs.
  if (process.env.NSAUDITOR_LICENSE_STATE_FILE) {
    return process.env.NSAUDITOR_LICENSE_STATE_FILE;
  }
  const plat = opts._platform ?? platform();
  if (plat === 'win32') {
    const base = process.env.LOCALAPPDATA
      ?? join(homedir(), 'AppData', 'Local');
    return join(base, 'nsauditor', LICENSE_STATE_BASENAME);
  }
  // Linux: prefer XDG_STATE_HOME; fall back to ~/.local/state; finally
  // co-locate with the existing ~/.nsauditor/.env for operators who
  // already know that directory.
  const xdgState = process.env.XDG_STATE_HOME;
  if (xdgState) {
    return join(xdgState, 'nsauditor', LICENSE_STATE_BASENAME);
  }
  return join(homedir(), '.nsauditor', LICENSE_STATE_BASENAME);
}

/**
 * Read the persisted license-state file. Returns `{ licenseId, lastSeenUnixTs }`
 * or `null` when the file does not exist or cannot be parsed.
 *
 * On macOS we additionally consult the Keychain for `licenseId`; when both
 * exist and disagree, Keychain wins (it's the more tamper-resistant store).
 * @internal
 */
export async function _readLicenseState(opts = {}) {
  const statePath = _getLicenseStateFilePath(opts);
  let state = null;
  try {
    const text = await fsp.readFile(statePath, 'utf8');
    const parsed = JSON.parse(text);
    if (parsed && typeof parsed === 'object') {
      state = {
        licenseId: typeof parsed.licenseId === 'string' ? parsed.licenseId : null,
        lastSeenUnixTs: Number.isFinite(parsed.lastSeenUnixTs)
          ? parsed.lastSeenUnixTs
          : null,
      };
    }
  } catch { /* missing or malformed — treat as no state */ }

  const plat = opts._platform ?? platform();
  // Skip Keychain when the state-file env override is set: that's the
  // test-mode signal (no test should write to the operator's real
  // Keychain, and no test should read from it either — bleeds state
  // across test cases via a side channel).
  if (plat === 'darwin' && !process.env.NSAUDITOR_LICENSE_STATE_FILE) {
    const kget = opts._keychainGet ?? keychainGet;
    try {
      const kcId = await kget(LICENSE_ID_KEYCHAIN_ACCOUNT);
      if (kcId) {
        state = state ?? { licenseId: null, lastSeenUnixTs: null };
        state.licenseId = kcId; // Keychain wins
      }
    } catch { /* keychain unavailable — keep state-file value */ }
  }
  return state;
}

/**
 * Persist license state (licenseId + lastSeenUnixTs) atomically.
 * Writes to `${path}.tmp` then renames; survives partial-crash without
 * leaving an in-flight half-written state file.
 *
 * On macOS the licenseId is ALSO written to the Keychain (best-effort;
 * a Keychain failure does not abort the file write since the file is the
 * cross-platform fallback path).
 *
 * @internal
 */
export async function _writeLicenseState(state, opts = {}) {
  const statePath = _getLicenseStateFilePath(opts);
  const dir = dirname(statePath);
  await fsp.mkdir(dir, { recursive: true, mode: 0o700 });
  const body = JSON.stringify({
    schema_version: 1,
    licenseId: state.licenseId ?? null,
    lastSeenUnixTs: Number.isFinite(state.lastSeenUnixTs) ? state.lastSeenUnixTs : null,
  }, null, 2);
  const tmp = `${statePath}.tmp`;
  await fsp.writeFile(tmp, body, { mode: 0o600 });
  await fsp.rename(tmp, statePath);
  // Re-chmod on overwrite (writeFile honors mode only on CREATE).
  const plat = opts._platform ?? platform();
  if (plat !== 'win32') {
    try { await fsp.chmod(statePath, 0o600); } catch { /* not fatal */ }
  }
  // Skip Keychain when the state-file env override is set: matches the
  // read-side test-mode-skip in _readLicenseState so the test suite's
  // per-case file-path isolation isn't bypassed by the macOS Keychain
  // side channel.
  if (plat === 'darwin' && state.licenseId && !process.env.NSAUDITOR_LICENSE_STATE_FILE) {
    const kset = opts._keychainSet ?? keychainSet;
    try { await kset(LICENSE_ID_KEYCHAIN_ACCOUNT, state.licenseId); } catch { /* not fatal */ }
  }
}

/**
 * Load and verify the shipped revocation blocklist. Returns the list of
 * revoked licenseId strings on success, or `[]` on ANY failure (file
 * missing, malformed JSON, invalid signature, unsupported schema version).
 *
 * Fail-open posture on tampering is deliberate: the blocklist lives in the
 * package's `data/` directory, which is only writable by parties who
 * already have the privilege to swap binaries (i.e., supply-chain
 * attackers); for those, tampering provides no additional escalation. A
 * fail-closed posture (refuse ALL licenses when the blocklist is corrupt)
 * would brick legitimate customers via a single bad CE patch.
 *
 * Test seam: `opts._blocklistData` short-circuits the file load and
 * returns a pre-loaded array. `opts._publicKeyPem` overrides the embedded
 * production key for signature-verification unit tests.
 *
 * @internal
 */
export async function _loadAndVerifyBlocklist(opts = {}) {
  if (Array.isArray(opts._blocklistData)) {
    return opts._blocklistData;
  }
  // Env-var override mirrors the state-file env override pattern; lets
  // existing tests redirect to a temp file without touching loadLicense
  // call sites.
  const path = opts._blocklistPath
    ?? process.env.NSAUDITOR_LICENSE_REVOCATIONS_FILE
    ?? REVOCATION_BLOCKLIST_PATH;
  let raw;
  try {
    raw = await fsp.readFile(path, 'utf8');
  } catch { return []; }

  let envelope;
  try {
    envelope = JSON.parse(raw);
  } catch { return []; }

  if (!envelope || typeof envelope !== 'object') return [];
  if (envelope.schema_version !== 1) return [];
  if (!Array.isArray(envelope.revoked)) return [];

  const publicKeyPem = opts._publicKeyPem ?? PUBLIC_KEY_PEM;
  if (!_verifyBlocklistSignature(envelope, publicKeyPem)) return [];

  return envelope.revoked.filter((s) => typeof s === 'string' && s.length > 0);
}

/**
 * Verify the ES256 detached signature over the blocklist envelope. The
 * signature covers the canonical JSON of the envelope MINUS the
 * `signature` field itself: `JSON.stringify({schema_version, issued_at, revoked})`
 * with stable key order.
 *
 * Signature is base64-encoded over the SHA-256-of-canonical-JSON,
 * verified against the ES256 (P-256) public key.
 *
 * Returns `true` only on cryptographic match; any error returns `false`
 * (fail-open at the blocklist layer is documented in _loadAndVerifyBlocklist).
 *
 * @internal
 */
export function _verifyBlocklistSignature(envelope, publicKeyPem) {
  if (!envelope || typeof envelope.signature !== 'string') return false;
  if (envelope.signature.length === 0) return false;
  const canonical = _canonicalizeBlocklistForSigning(envelope);
  if (!canonical) return false;
  try {
    const sigBuf = Buffer.from(envelope.signature, 'base64');
    const pub = createPublicKey({ key: publicKeyPem, format: 'pem' });
    // P1.D R2-HIGH fold: pin to ES256 (EC P-256) algorithm explicitly.
    // Without this assertion, a future PUBLIC_KEY_PEM rotation to an RSA
    // key would silently enable RS256 forgery of the blocklist (the
    // verify code path is generic over algorithm). Mirror of the audit's
    // own canonical-JWT-verifier hardening pattern.
    if (pub.asymmetricKeyType !== 'ec') return false;
    const details = pub.asymmetricKeyDetails;
    if (!details || details.namedCurve !== 'prime256v1') return false;
    const verifier = createVerify('SHA256');
    verifier.update(canonical, 'utf8');
    verifier.end();
    return verifier.verify({ key: pub, dsaEncoding: 'der' }, sigBuf);
  } catch {
    return false;
  }
}

/**
 * Canonical signing input: stable key order, no signature field.
 * @internal
 */
export function _canonicalizeBlocklistForSigning(envelope) {
  if (!envelope || typeof envelope !== 'object') return null;
  const canonical = {
    schema_version: envelope.schema_version,
    issued_at: envelope.issued_at,
    revoked: Array.isArray(envelope.revoked) ? [...envelope.revoked] : [],
  };
  // Deterministic stringification: sort revoked alphabetically to remove
  // ordering ambiguity from the signing input.
  canonical.revoked.sort();
  return JSON.stringify(canonical);
}

/**
 * Full async JWT verification. Call once at startup.
 * On success, caches verified tier so subsequent getTierFromEnv() calls
 * return the cryptographically validated result.
 *
 * Never throws — degrades to 'ce' on any failure.
 *
 * @param {string} [keyStr] - License key; if omitted, runs the multi-source
 *   resolution chain (env var → Keychain → ~/.nsauditor/.env). See
 *   resolveLicenseKey() above.
 * @param {object} [opts] - Test seams (see internal helpers). All options
 *   prefixed with `_` are documented as test-only.
 * @returns {Promise<{valid: boolean, tier: string, org?: string, seats?: number,
 *   licenseId?: string, capabilities?: string[], expiresAt?: string, reason?: string}>}
 */
export async function loadLicense(keyStr, opts = {}) {
  // Explicit keyStr argument wins (preserves the existing behavior for
  // callers like the `license --status` subcommand which passes the env
  // var directly). When omitted, run the multi-source resolution chain.
  let raw = keyStr ?? (await resolveLicenseKey());
  if (!raw) return { valid: false, tier: 'ce', reason: 'no key provided' };

  // Thread K (CE 0.1.32): support `keychain:LABEL` indirection on the
  // resolved value. Mirrors the EE-SEC.1 MCP-auth pattern — operators
  // can put `"NSAUDITOR_LICENSE_KEY": "keychain:NSAUDITOR_LICENSE_KEY"`
  // in their Claude Desktop config env block; the literal JWT never
  // lands in the world-readable config file. resolveSecret is a no-op
  // (returns input unchanged) for non-`keychain:` strings, so literal
  // JWT keys continue to work for backward compat.
  if (typeof raw === 'string' && raw.startsWith('keychain:')) {
    const resolved = await resolveSecret(raw);
    if (!resolved) {
      return { valid: false, tier: 'ce', reason: 'license keychain: indirection could not be resolved (entry missing or Keychain locked)' };
    }
    raw = resolved;
  }

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

    // ── CE 0.1.70 air-gap hardening: 3 fail-closed checks ────────────────
    // Order matters. (1) Revocation runs first — a revoked license should
    // be rejected even before the per-host bind. (2) Replay defense second
    // — a non-revoked but mismatched-host install is the next-most-likely
    // abuse path. (3) Clock anchor third — only relevant if the prior two
    // pass; a clock-rollback attack against a legitimately installed
    // license is the least-common case. Each check has an env-var escape
    // hatch documented as support-only.

    const now = (opts._now ?? Date.now)();

    // (1) D-HIGH-2: signed revocation blocklist.
    if (!_envDisabled(ENV_REVOCATION_CHECK)) {
      try {
        const revoked = await _loadAndVerifyBlocklist(opts);
        if (payload.licenseId && revoked.includes(payload.licenseId)) {
          _verifiedTier = 'ce';
          return { valid: false, tier: 'ce', reason: 'license_revoked' };
        }
      } catch { /* fail-open per _loadAndVerifyBlocklist contract */ }
    }

    // Read prior persisted state once for checks (2) + (3) + first-activation write.
    let persistedState = null;
    try { persistedState = await _readLicenseState(opts); } catch { /* missing fine */ }

    // (2) D-HIGH-1: per-host licenseId replay defense.
    if (!_envDisabled(ENV_REPLAY_DEFENSE)) {
      if (persistedState && persistedState.licenseId
          && payload.licenseId
          && persistedState.licenseId !== payload.licenseId) {
        _verifiedTier = 'ce';
        return { valid: false, tier: 'ce', reason: 'license_id_mismatch' };
      }
    }

    // (3) D-HIGH-3: monotonic-clock anchor.
    if (!_envDisabled(ENV_CLOCK_ANCHOR)) {
      if (persistedState && Number.isFinite(persistedState.lastSeenUnixTs)) {
        const tolerance = _resolveClockToleranceS() * 1000;
        if (now < persistedState.lastSeenUnixTs - tolerance) {
          _verifiedTier = 'ce';
          return { valid: false, tier: 'ce', reason: 'clock_rollback_detected' };
        }
      }
    }

    // All checks passed — update state (first-activation persist + heartbeat).
    try {
      await _writeLicenseState({
        licenseId: payload.licenseId ?? persistedState?.licenseId ?? null,
        lastSeenUnixTs: now,
      }, opts);
    } catch { /* state write failure must not block a verified license */ }

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
 *
 * Clears in-memory state only (`_verifiedTier` + permissive-warned-paths).
 * Does NOT touch the persisted license-state file — tests that need that
 * cleared should either rotate the state-file path via beforeEach OR call
 * `_clearLicenseStateFileForTests()` explicitly.
 */
export function _resetCache() {
  if (process.env.NODE_ENV === 'production') {
    throw new Error('_resetCache is test-only and disabled in production');
  }
  _verifiedTier = null;
  _permissiveWarnedPaths.clear();
}

/**
 * @internal Test-only. Remove the persisted license-state file at the path
 * resolved by the env var or platform default. Refuses to touch the real
 * platform-default path (only honors NSAUDITOR_LICENSE_STATE_FILE override)
 * so a production process that accidentally imports this helper cannot
 * wipe operator state.
 */
export function _clearLicenseStateFileForTests() {
  if (process.env.NODE_ENV === 'production') {
    throw new Error('_clearLicenseStateFileForTests is test-only');
  }
  const override = process.env.NSAUDITOR_LICENSE_STATE_FILE;
  if (!override) return; // refuse to touch platform default
  try { fsSync.unlinkSync(override); } catch { /* not fatal — file may not exist */ }
}
