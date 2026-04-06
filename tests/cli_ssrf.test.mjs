import assert from 'node:assert/strict';
import test from 'node:test';
import { isBlockedIp, resolveAndValidate } from '../utils/net_validation.mjs';

/**
 * Mirrors the SSRF guard in scanSingleHost() from cli.mjs.
 * The guard itself is not exported, so we replicate the exact logic for focused tests.
 */
async function applySsrfGuard(host, allowAllHosts = false) {
  if (allowAllHosts) return; // NSA_ALLOW_ALL_HOSTS=1 bypass

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
