// utils/keychain.mjs
// macOS Keychain integration for secure credential storage.
// Falls back gracefully on non-macOS platforms.

import { execFile } from 'node:child_process';
import { platform } from 'node:os';

const SERVICE = 'nsauditor-ai';
const isMac = platform() === 'darwin';

function exec(cmd, args) {
  return new Promise((resolve, reject) => {
    execFile(cmd, args, { timeout: 5000 }, (err, stdout, stderr) => {
      if (err) return reject(new Error(stderr?.trim() || err.message));
      resolve(stdout.trim());
    });
  });
}

/**
 * Read a secret from the macOS Keychain.
 * @param {string} account - Key name (e.g., 'ANTHROPIC_API_KEY')
 * @returns {Promise<string|null>} The secret value, or null if not found
 */
export async function keychainGet(account) {
  if (!isMac) return null;
  try {
    return await exec('security', [
      'find-generic-password', '-s', SERVICE, '-a', account, '-w'
    ]);
  } catch {
    return null;
  }
}

/**
 * Store a secret in the macOS Keychain.
 * Updates existing entry if present.
 * @param {string} account - Key name
 * @param {string} secret - The secret value
 */
export async function keychainSet(account, secret) {
  if (!isMac) throw new Error('Keychain storage is only supported on macOS');
  // Delete existing entry first (ignore errors if not found)
  try {
    await exec('security', ['delete-generic-password', '-s', SERVICE, '-a', account]);
  } catch { /* not found — fine */ }
  await exec('security', [
    'add-generic-password', '-s', SERVICE, '-a', account, '-w', secret
  ]);
}

/**
 * Delete a secret from the macOS Keychain.
 * @param {string} account - Key name
 * @returns {Promise<boolean>} true if deleted, false if not found
 */
export async function keychainDelete(account) {
  if (!isMac) throw new Error('Keychain storage is only supported on macOS');
  try {
    await exec('security', ['delete-generic-password', '-s', SERVICE, '-a', account]);
    return true;
  } catch {
    return false;
  }
}

/**
 * List all nsauditor-ai entries in the Keychain.
 * @returns {Promise<string[]>} Array of account names
 */
export async function keychainList() {
  if (!isMac) return [];
  try {
    const raw = await exec('security', ['dump-keychain']);
    const entries = [];
    const lines = raw.split('\n');
    let inOurService = false;
    for (const line of lines) {
      const trimmed = line.trim();
      // Match both formats: 0x00000007 <blob>="nsauditor-ai" and "svce"<blob>="nsauditor-ai"
      if (trimmed.includes(`="${SERVICE}"`)) {
        inOurService = true;
      } else if (inOurService && trimmed.includes('"acct"<blob>="')) {
        const m = trimmed.match(/"acct"<blob>="([^"]+)"/);
        if (m) entries.push(m[1]);
        inOurService = false;
      } else if (trimmed.startsWith('keychain:') || trimmed.startsWith('class:')) {
        inOurService = false;
      }
    }
    return [...new Set(entries)];
  } catch {
    return [];
  }
}

/**
 * Resolve a value that may be a keychain reference.
 * If the value starts with 'keychain:', read from Keychain.
 * Otherwise return the value as-is.
 * @param {string|undefined} value - Raw env var value
 * @returns {Promise<string|null>} Resolved secret
 */
export async function resolveSecret(value) {
  if (!value) return null;
  const str = String(value).trim();
  if (!str) return null;
  if (str.startsWith('keychain:')) {
    const label = str.slice('keychain:'.length).trim();
    if (!label) return null;
    const secret = await keychainGet(label);
    if (!secret) {
      console.error(`[keychain] No entry found for "${label}" in Keychain (service: ${SERVICE})`);
      console.error(`[keychain] Store it with: nsauditor-ai security set ${label}`);
    }
    return secret;
  }
  return str;
}
