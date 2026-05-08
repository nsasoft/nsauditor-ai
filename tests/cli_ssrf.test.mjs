import assert from 'node:assert/strict';
import test from 'node:test';
import { isBlockedIp, resolveAndValidate } from '../utils/net_validation.mjs';

/**
 * Mirrors the SSRF guard in scanSingleHost() from cli.mjs.
 * The guard itself is not exported, so we replicate the exact logic for focused tests.
 *
 * EE-0.3.2.5: cloud-provider sentinel hosts ('aws' / 'gcp' / 'azure',
 * case-insensitive) bypass the guard — they're scoping tokens routed
 * to EE cloud-scanner plugins, not network addresses, and previously
 * required NSA_ALLOW_ALL_HOSTS=1 to scan (which dangerously also
 * disabled the guard for legitimate IP / hostname targets).
 */
const CLOUD_SENTINEL_HOSTS = new Set(['aws', 'gcp', 'azure']);

async function applySsrfGuard(host, allowAllHosts = false) {
  if (allowAllHosts) return; // NSA_ALLOW_ALL_HOSTS=1 bypass

  // Cloud sentinels bypass without requiring the env-var.
  if (typeof host === 'string' && CLOUD_SENTINEL_HOSTS.has(host.toLowerCase())) return;

  if (isBlockedIp(host)) {
    throw new Error(`Scanning blocked address range is not allowed: ${host}`);
  }

  // Hostname (not literal IP) — resolve and validate the resolved address
  if (!/^[\d.:[\]]+$/.test(host)) {
    try {
      await resolveAndValidate(host);
    } catch (err) {
      throw new Error(`Host rejected by SSRF guard: ${err.message}`);
    }
  }
}

// ---------------------------------------------------------------------------
// Literal blocked IPs
// ---------------------------------------------------------------------------

test('SSRF guard: rejects loopback 127.0.0.1', async () => {
  await assert.rejects(() => applySsrfGuard('127.0.0.1'), /blocked address range/);
});

test('SSRF guard: rejects cloud metadata endpoint 169.254.169.254', async () => {
  await assert.rejects(() => applySsrfGuard('169.254.169.254'), /blocked address range/);
});

test('SSRF guard: rejects RFC 1918 address 10.0.0.1', async () => {
  await assert.rejects(() => applySsrfGuard('10.0.0.1'), /blocked address range/);
});

test('SSRF guard: rejects RFC 1918 address 192.168.1.1', async () => {
  await assert.rejects(() => applySsrfGuard('192.168.1.1'), /blocked address range/);
});

test('SSRF guard: rejects IPv6 loopback ::1', async () => {
  await assert.rejects(() => applySsrfGuard('::1'), /blocked address range/);
});

// ---------------------------------------------------------------------------
// NSA_ALLOW_ALL_HOSTS bypass
// ---------------------------------------------------------------------------

test('SSRF guard: bypasses blocked IP when allowAllHosts=true', async () => {
  // Should not throw
  await assert.doesNotReject(() => applySsrfGuard('127.0.0.1', true));
});

test('SSRF guard: bypasses RFC 1918 when allowAllHosts=true', async () => {
  await assert.doesNotReject(() => applySsrfGuard('10.0.0.1', true));
});

// ---------------------------------------------------------------------------
// Hostname resolution
// ---------------------------------------------------------------------------

test('SSRF guard: rejects hostname resolving to loopback (localhost)', async () => {
  await assert.rejects(() => applySsrfGuard('localhost'), /SSRF guard/);
});

test('SSRF guard: allows public hostname (dns.google)', async () => {
  await assert.doesNotReject(() => applySsrfGuard('dns.google'));
});

// ---------------------------------------------------------------------------
// EE-0.3.2.5: cloud-sentinel hosts bypass the SSRF guard
// ---------------------------------------------------------------------------

test('SSRF guard (EE-0.3.2.5): cloud sentinel "aws" passes without NSA_ALLOW_ALL_HOSTS', async () => {
  // Pre-fix this threw "Host rejected by SSRF guard: getaddrinfo ENOTFOUND aws"
  // because resolveAndValidate() couldn't resolve "aws" as a DNS name.
  await assert.doesNotReject(() => applySsrfGuard('aws'));
});

test('SSRF guard (EE-0.3.2.5): cloud sentinel "gcp" passes without NSA_ALLOW_ALL_HOSTS', async () => {
  await assert.doesNotReject(() => applySsrfGuard('gcp'));
});

test('SSRF guard (EE-0.3.2.5): cloud sentinel "azure" passes without NSA_ALLOW_ALL_HOSTS', async () => {
  await assert.doesNotReject(() => applySsrfGuard('azure'));
});

test('SSRF guard (EE-0.3.2.5): cloud sentinels are case-insensitive ("AWS" / "Azure")', async () => {
  await assert.doesNotReject(() => applySsrfGuard('AWS'));
  await assert.doesNotReject(() => applySsrfGuard('Azure'));
  await assert.doesNotReject(() => applySsrfGuard('GCP'));
});

test('SSRF guard (EE-0.3.2.5): unrecognized cloud-shaped strings still go through resolution', async () => {
  // "azurex" / "amazon" / "aws-foo" are NOT sentinels — they should still
  // trigger DNS resolution. Without that, an attacker who guessed at the
  // sentinel list could coerce the scanner into bypassing SSRF for any
  // string they wanted.
  await assert.rejects(() => applySsrfGuard('azurex'), /SSRF guard/);
  await assert.rejects(() => applySsrfGuard('aws-foo'), /SSRF guard/);
});

test('SSRF guard (EE-0.3.2.5): non-string host does not crash the sentinel check', async () => {
  // Defensive: if host arrives as null/undefined/number, the sentinel
  // typeof guard short-circuits and the guard falls through to the
  // existing isBlockedIp / resolve logic.
  await assert.rejects(() => applySsrfGuard(null), /Cannot read|invalid|reject/i);
});
