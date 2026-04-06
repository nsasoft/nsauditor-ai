// utils/nvd_cache.mjs
// File-based cache for NVD API responses to respect rate limits.

import fsp from 'node:fs/promises';
import path from 'node:path';

const DEFAULT_TTL_DAYS = 7;
const MAX_ENTRIES = 10000;

export class NvdCache {
  constructor(cacheDir = '.nvd_cache') {
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
    await fsp.mkdir(path.dirname(this.cacheFile), { recursive: true });
    await fsp.writeFile(this.cacheFile, JSON.stringify(this._data, null, 2), 'utf8');
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
