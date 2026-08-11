// utils/nvd_cache.mjs
// File-based cache for NVD API responses to respect rate limits.

import fsp from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';

const DEFAULT_TTL_DAYS = 7;
const MAX_ENTRIES = 10000;

/**
 * Where the cache lives when the caller does not say.
 *
 * ⚠️ NOT `'.nvd_cache'`, AND THE REASON IS A MEASURED OUTAGE. That default was CWD-RELATIVE
 * (`path.resolve` below), and `mcp_server.mjs` constructs its client with no `cacheDir` — so
 * under the Claude Desktop MCP server, which runs from `/`, the write target was
 * `/.nvd_cache` and `mkdir` returned EROFS. `get_vulnerabilities` was DEAD for every Desktop
 * user (Gate 3, 2026-08-10). For CLI users it was quieter and still wrong: the cache lived
 * wherever the operator happened to stand, so it never persisted between directories and
 * every run re-fetched what it already had.
 *
 * ⚠️ SAME CLASS AS THE PORT-SCANNER FIX IN THIS SAME RELEASE (CE 0.2.39), one module over, on
 * a WRITE path: package data and package state resolved against the CALLER's cwd under a
 * globally installed binary. That fix addressed `config/services.json` and did not touch this
 * — the named instance, not the class. [[guard_the_hazard_class_not_the_named_instance]]
 *
 * Per-user, not per-directory, and overridable by the env var an operator can point at a
 * writable volume in a container.
 */
export function defaultCacheDir() {
  const fromEnv = process.env.NSAUDITOR_NVD_CACHE_DIR;
  if (fromEnv && String(fromEnv).trim()) return String(fromEnv).trim();
  try {
    const home = os.homedir();
    if (home) return path.join(home, '.nsauditor', 'nvd_cache');
  } catch { /* no home in this environment — fall through */ }
  return path.join(os.tmpdir(), 'nsauditor-nvd-cache');
}

export class NvdCache {
  constructor(cacheDir = defaultCacheDir()) {
    this.cacheFile = path.resolve(cacheDir, 'nvd_cache.json');
    this.ttlMs = (Number(process.env.NVD_CACHE_TTL_DAYS) || DEFAULT_TTL_DAYS) * 86400000;
    this._data = null;
    this._writeQueue = Promise.resolve();
  }

  async _load() {
    if (this._data) return;
    try {
      const raw = await fsp.readFile(this.cacheFile, 'utf8');
      this._data = JSON.parse(raw);
    } catch {
      this._data = {};
    }
    this._sweepExpired();
  }

  _sweepExpired() {
    const now = Date.now();
    for (const key of Object.keys(this._data)) {
      if (now - this._data[key].timestamp > this.ttlMs) {
        delete this._data[key];
      }
    }
  }

  _evictOldest() {
    const entries = Object.entries(this._data);
    entries.sort((a, b) => a[1].timestamp - b[1].timestamp);
    const excess = entries.length - MAX_ENTRIES;
    for (let i = 0; i < excess; i++) {
      delete this._data[entries[i][0]];
    }
  }

  async _save() {
    // ⚠️ A CACHE IS AN OPTIMISATION: AN UNWRITABLE LOCATION COSTS CACHING, NEVER THE TOOL.
    // The Desktop outage was not that the cache was unavailable — it was that an unavailable
    // cache took `get_vulnerabilities` down with it. A read-only or hostile environment now
    // loses persistence and keeps the feature; the in-memory `_data` still serves the run.
    try {
      await fsp.mkdir(path.dirname(this.cacheFile), { recursive: true });
      await fsp.writeFile(this.cacheFile, JSON.stringify(this._data, null, 2), 'utf8');
    } catch (err) {
      if (!this._warnedUnwritable) {
        this._warnedUnwritable = true;
        // Said ONCE, and said out loud: a silently non-persisting cache is the quieter
        // half of this very defect.
        console.error(`[nsauditor] NVD cache not persisted (${err.code || err.message}) at ` +
          `${path.dirname(this.cacheFile)} — continuing without caching. Set ` +
          'NSAUDITOR_NVD_CACHE_DIR to a writable path to restore it.');
      }
    }
  }

  async get(key) {
    await this._load();
    const entry = this._data[key];
    if (!entry) return null;
    if (Date.now() - entry.timestamp > this.ttlMs) {
      delete this._data[key];
      return null;
    }
    return entry.data;
  }

  async set(key, data) {
    this._writeQueue = this._writeQueue.then(async () => {
      await this._load();
      this._data[key] = { data, timestamp: Date.now() };
      if (Object.keys(this._data).length > MAX_ENTRIES) {
        this._sweepExpired();
        if (Object.keys(this._data).length > MAX_ENTRIES) {
          this._evictOldest();
        }
      }
      await this._save();
    });
    return this._writeQueue;
  }
}
