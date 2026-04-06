// utils/nvd_client.mjs
// NVD 2.0 API client with rate limiting and caching.

import { NvdCache } from './nvd_cache.mjs';

const NVD_BASE = 'https://services.nvd.nist.gov/rest/json/cves/2.0';

// --- Rate limiter (sliding window) ---

export class RateLimiter {
  constructor(maxRequests, windowMs) {
    this.max = maxRequests;
    this.windowMs = windowMs;
    this.timestamps = [];
  }

  async wait() {
    const now = Date.now();
    this.timestamps = this.timestamps.filter(t => now - t < this.windowMs);
    if (this.timestamps.length >= this.max) {
      const waitMs = this.windowMs - (now - this.timestamps[0]);
      if (waitMs > 0) await new Promise(r => setTimeout(r, waitMs));
    }
    this.timestamps.push(Date.now());
  }
}

// --- Helpers ---

function extractCvss(metrics) {
  const m31 = metrics?.cvssMetricV31?.[0]?.cvssData;
  if (m31) return m31;
  const m30 = metrics?.cvssMetricV30?.[0]?.cvssData;
  return m30 || null;
}

function parseCve(vuln) {
  const { cve } = vuln;
  const cvss = extractCvss(cve.metrics);
  const enDesc = cve.descriptions?.find(d => d.lang === 'en');
  return {
    cveId: cve.id,
    description: enDesc?.value ?? '',
    cvssScore: cvss?.baseScore ?? null,
    severity: cvss?.baseSeverity ?? null,
    vectorString: cvss?.vectorString ?? null,
    published: cve.published,
    lastModified: cve.lastModified,
  };
}

// --- Client ---

class NvdClient {
  constructor({ apiKey, cacheDir } = {}) {
    this.apiKey = apiKey || process.env.NVD_API_KEY || null;
    this.cache = new NvdCache(cacheDir);
    // With API key: 50 req / 30s. Without: 5 req / 30s.
    const max = this.apiKey ? 50 : 5;
    this.limiter = new RateLimiter(max, 30_000);
  }

  async _fetch(url) {
    await this.limiter.wait();
    const headers = {};
    if (this.apiKey) headers.apiKey = this.apiKey;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 15_000);
    try {
      const res = await fetch(url, { headers, signal: controller.signal });
      if (!res.ok) {
        const text = await res.text().catch(() => '');
        throw new Error(`NVD API ${res.status}: ${text}`);
      }
      return res.json();
    } finally {
      clearTimeout(timer);
    }
  }

  async queryCvesByCpe(cpeString) {
    const cacheKey = `cpe:${cpeString}`;
    const cached = await this.cache.get(cacheKey);
    if (cached) return cached;

    const url = `${NVD_BASE}?cpeName=${encodeURIComponent(cpeString)}`;
    const body = await this._fetch(url);
    const results = (body.vulnerabilities || []).map(parseCve);

    await this.cache.set(cacheKey, results);
    return results;
  }

  async validateCveId(cveId) {
    const cacheKey = `cve:${cveId}`;
    const cached = await this.cache.get(cacheKey);
    if (cached) return cached;

    let result;
    try {
      const url = `${NVD_BASE}?cveId=${encodeURIComponent(cveId)}`;
      const body = await this._fetch(url);
      const vulns = body.vulnerabilities || [];
      if (vulns.length === 0) {
        result = { exists: false, cveId };
      } else {
        const parsed = parseCve(vulns[0]);
        result = {
          exists: true,
          cveId: parsed.cveId,
          cvssScore: parsed.cvssScore,
          severity: parsed.severity,
          description: parsed.description,
        };
      }
    } catch {
      // Transient failure — don't cache, return unknown
      return { exists: false, cveId, transient: true };
    }

    await this.cache.set(cacheKey, result);
    return result;
  }
}

// --- Factory ---

export function createNvdClient(options) {
  return new NvdClient(options);
}
