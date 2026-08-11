/**
 * THE NVD CACHE MUST NOT LIVE IN THE CALLER'S CURRENT DIRECTORY.
 *
 * ── THE DEFECT, found by Gate 3 on 2026-08-10 and verified in code and empirically ──────
 * `get_vulnerabilities` was DEAD under the Claude Desktop MCP server, failing with
 * `mkdir '/.nvd_cache'`. Root cause: `NvdCache` defaulted to the relative `'.nvd_cache'` and
 * `path.resolve` made it CWD-RELATIVE, while `mcp_server.mjs` constructs its client with no
 * `cacheDir` at all. The Desktop server runs from `/`, so the write target was `/.nvd_cache`
 * — measured: `mkdir` there returns **EROFS**.
 *
 * ⚠️ THIS IS THE SAME CLASS AS THE PORT-SCANNER FIX IN THIS SAME RELEASE (CE 0.2.39,
 * `b98d407`), ONE MODULE OVER, ON A *WRITE* PATH. There, `config/services.json` was resolved
 * from `process.cwd()` under a globally installed binary and the scanner silently probed zero
 * ports. Fixing the named instance and leaving the class is how this returns wearing a
 * different filename — so this test pins the PROPERTY ("package data and package state are
 * located relative to the user, never to the caller's cwd"), not the one path that broke.
 * [[guard_the_hazard_class_not_the_named_instance]]
 *
 * ── THE SECOND HALF: DEGRADE, DON'T THROW ───────────────────────────────────────────────
 * A cache is an optimisation. A read-only or hostile environment should cost CACHING, never
 * the TOOL — the Desktop failure turned an unavailable cache into an unavailable feature, and
 * that asymmetry is the actual harm.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import fs from 'node:fs';
import { NvdCache } from '../utils/nvd_cache.mjs';

describe('NvdCache location — relative to the USER, never to the caller cwd', () => {
  test('the default cache path is NOT inside the current working directory', () => {
    const cwd0 = process.cwd();
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-nvdcwd-'));
    try {
      process.chdir(tmp);
      const c = new NvdCache();
      assert.ok(path.isAbsolute(c.cacheFile), 'the cache path must be absolute');
      assert.ok(!c.cacheFile.startsWith(fs.realpathSync(tmp) + path.sep),
        `the cache resolved INSIDE the caller's cwd (${c.cacheFile}). Under a globally ` +
        'installed binary that is wherever the operator happens to stand: the cache never ' +
        'persists between directories, and under the Desktop MCP server (cwd "/") the write ' +
        'target is /.nvd_cache, which fails EROFS and kills get_vulnerabilities outright.');
    } finally {
      process.chdir(cwd0);
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  test('the default is the SAME path regardless of where the caller stands', () => {
    // The property a per-user cache must have, and the one a cwd-relative default cannot:
    // two runs from two directories share one cache instead of silently re-fetching.
    const cwd0 = process.cwd();
    const a = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-nvda-'));
    const b = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-nvdb-'));
    try {
      process.chdir(a); const fromA = new NvdCache().cacheFile;
      process.chdir(b); const fromB = new NvdCache().cacheFile;
      assert.equal(fromA, fromB,
        'the default cache location moved with the caller, so a scan run from a different ' +
        'directory silently re-fetches everything it already had');
    } finally {
      process.chdir(cwd0);
      for (const d of [a, b]) fs.rmSync(d, { recursive: true, force: true });
    }
  });

  test('an EXPLICIT cacheDir still wins — the documented override is preserved', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-nvdx-'));
    try {
      const c = new NvdCache(tmp);
      assert.equal(c.cacheFile, path.resolve(tmp, 'nvd_cache.json'));
    } finally { fs.rmSync(tmp, { recursive: true, force: true }); }
  });

  test('an UNWRITABLE cache location costs CACHING, not the TOOL', async () => {
    // The Desktop failure was not that the cache was unavailable — it was that an unavailable
    // cache took `get_vulnerabilities` down with it. A cache is an optimisation; losing it
    // must never be fatal.
    const c = new NvdCache('/proc/nsauditor-cannot-write-here');
    await assert.doesNotReject(async () => {
      await c.get('CPE:NOT-PRESENT');
      await c.set('CPE:NOT-PRESENT', { cves: [] });
    }, 'an unwritable cache directory must degrade to no-caching, never throw at the caller');
  });
});
