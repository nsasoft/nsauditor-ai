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

/**
 * EE board B160 (the release paired with Enterprise 2.1.2): the CVE list an NVD answer carries, or a throw. Both lookups
 * read `body.vulnerabilities || []`, so a 200 whose body carried no such list — malformed, a proxy's page, another host's
 * answer — read as "no CVEs" (or as a CVE that does not exist) and was CACHED that way for the cache's lifetime. Now an
 * answer whose `vulnerabilities` is absent, null or not a list is a FAILED LOOKUP: it throws, so the caller caches
 * nothing — Enterprise reports it as its lookup-failure gap, a CVE check reads transient. Scoped to that one key; an
 * empty list is still a real answer of zero. Stated limit: an empty list beside `totalResults > 0` is read as zero.
 */
function vulnerabilitiesOf(body) {
  const list = body?.vulnerabilities;
  if (!Array.isArray(list)) {
    throw new Error('NVD API answer carried no vulnerabilities list — a failed lookup, not "no CVEs"; nothing was cached');
  }
  return list;
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
      // EE board B158 (the Community release paired with Enterprise 2.1.2): the lookup goes ONLY to the NVD API. `fetch`
      // follows a redirect by default, and Node FORWARDS a custom header such as `apiKey` wherever a cross-origin one
      // points — measured: the key and the CPE reached another host, whose empty answer was returned and cached as "no
      // CVEs". So a 3xx is refused, naming the status and the HOST only (this message reaches Enterprise's lookup-failure
      // gap, its AI payload and a GRC push), and nothing is cached. Enterprise's egress register anchors on this call.
      const res = await fetch(url, { headers, signal: controller.signal, redirect: 'manual' });
      if (res.status >= 300 && res.status < 400) {
        const location = res.headers?.get?.('location');
        let to = 'no Location header';
        if (location) {
          try { to = new URL(location, url).host; } catch { to = 'an unparseable Location header'; }
        }
        throw new Error(`NVD API ${res.status} → ${to}: the NVD API redirected the request, and a redirect is never followed`);
      }
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
    const results = vulnerabilitiesOf(body).map(parseCve);

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
      const vulns = vulnerabilitiesOf(body);
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
