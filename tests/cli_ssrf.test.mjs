import './helpers/no_operator_keychain.mjs';   // FIRST: the driven legs below load a licence through main()
import assert from 'node:assert/strict';
import test from 'node:test';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { isBlockedIp, resolveAndValidate } from '../utils/net_validation.mjs';
import { main } from '../cli.mjs';

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

// ---------------------------------------------------------------------------
// 1.2.1 lane 1 C — DRIVEN through the real cli.mjs main(), not the mirror above: only an explicit
// truthy word lifts the CLI guard. Before 1.2.1, `NSA_ALLOW_ALL_HOSTS=0` and `=false` lifted it,
// because the check was plain truthiness. LOOPBACK ONLY: plugin 003 against 127.0.0.1 ports 1-2.
// ---------------------------------------------------------------------------
async function driveScan(host, allowValue) {
  const outRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-cli-ssrf-'));
  const savedArgv = process.argv;
  const saved = { SCAN_OUT_PATH: process.env.SCAN_OUT_PATH, OPENAI_OUT_PATH: process.env.OPENAI_OUT_PATH, NSA_ALLOW_ALL_HOSTS: process.env.NSA_ALLOW_ALL_HOSTS };
  try {
    delete process.env.OPENAI_OUT_PATH;
    process.env.SCAN_OUT_PATH = outRoot;
    if (allowValue === undefined) delete process.env.NSA_ALLOW_ALL_HOSTS; else process.env.NSA_ALLOW_ALL_HOSTS = allowValue;
    process.argv = ['node', 'cli', 'scan', '--host', host, '--plugins', '003', '--ports', '1-2'];
    const notInstalled = () => { throw Object.assign(new Error("Cannot find package '@nsasoft/nsauditor-ai-ee'"), { code: 'ERR_MODULE_NOT_FOUND' }); };
    try { await main({ importEE: async () => { throw new Error('injected: EE not installed'); }, resolveEE: notInstalled }); return null; } catch (e) { return e; }
  } finally {
    process.argv = savedArgv;
    for (const [k, v] of Object.entries(saved)) { if (v == null) delete process.env[k]; else process.env[k] = v; }
    fs.rmSync(outRoot, { recursive: true, force: true });
  }
}

test('(fourth quadrant, first) C: NSA_ALLOW_ALL_HOSTS="true" still lifts the CLI guard — a loopback scan completes', async () => {
  assert.equal(await driveScan('127.0.0.1', 'true'), null);
});

test('C: "0", "false", "no" and "off" do NOT lift the CLI guard — loopback is refused', async () => {
  for (const v of ['0', 'false', 'no', 'off']) {
    const err = await driveScan('127.0.0.1', v);
    assert.match(String(err && err.message), /blocked address range/, `NSA_ALLOW_ALL_HOSTS=${v} must not lift the guard`);
  }
});
