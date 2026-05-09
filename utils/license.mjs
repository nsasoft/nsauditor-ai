// utils/license.mjs
// JWT license verification for NSAuditor AI.
// Uses ES256 (ECDSA P-256) public key embedded below — no file I/O needed.
//
// KEY ROTATION: If the private key is compromised, generate a new EC P-256 key
// pair, update PUBLIC_KEY_PEM below, and ship a CE update. All existing JWTs
// become invalid. See license-manager docs/architecture.md for full procedure.

import { jwtVerify, importSPKI } from 'jose';
import { promises as fsp } from 'node:fs';
import { homedir, platform } from 'node:os';
import { dirname, join } from 'node:path';
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
 * @returns {Promise<{valid: boolean, tier: string, org?: string, seats?: number,
 *   licenseId?: string, capabilities?: string[], expiresAt?: string, reason?: string}>}
 */
export async function loadLicense(keyStr) {
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
 */
export function _resetCache() {
  if (process.env.NODE_ENV === 'production') {
    throw new Error('_resetCache is test-only and disabled in production');
  }
  _verifiedTier = null;
  _permissiveWarnedPaths.clear();
}
