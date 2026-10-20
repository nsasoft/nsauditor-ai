// utils/webhook.mjs
// Webhook notification utilities — pure Node.js, no external deps.

import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import { isBlockedIp, resolveAndValidate } from './net_validation.mjs';

/**
 * Validate that a URL is http or https.
 * @param {string} url
 * @returns {boolean}
 */
function isValidWebhookUrl(url) {
  try {
    const parsed = new URL(url);
    return parsed.protocol === 'http:' || parsed.protocol === 'https:';
  } catch {
    return false;
  }
}

/**
 * Resolve a webhook URL to the ONE address the request will connect to, or null when the URL is unsafe (blocks SSRF
 * targets). The fast path refuses obvious loopback, link-local, metadata and private spellings; DNS resolution then
 * refuses a name ANY of whose answers is blocked (rebinding, decimal/octal IPs, IPv6-mapped addresses).
 *
 * ⚠️ THE ADDRESS IS THE POINT (EE 2.0.0, R1 for the webhook sink — the architect seat's F6). The check used to answer
 * yes/no and the request then resolved the NAME AGAIN at connect, so a name answering a public address to the check
 * and loopback to the connect passed the guard and reached loopback (DNS rebinding). `sendWebhook` now connects to the
 * address returned here, and the name still rides as the Host header and the TLS server name.
 * @param {string} url
 * @returns {Promise<{ address: string, family: 4|6 } | null>}
 */
export async function resolveWebhookTarget(url) {
  if (!isValidWebhookUrl(url)) return null;
  const host = new URL(url).hostname.toLowerCase();
  // Fast-path: block obvious loopback, link-local, cloud metadata, and private ranges
  if (/^(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[0-1])\.|169\.254\.|0\.|localhost$|metadata\.google)/i.test(host)) {
    return null;
  }
  if (host === '::1' || host === '[::1]' || /^fe80:/i.test(host)) return null;

  // DNS resolution check — catches rebinding at the check, decimal/octal IPs, IPv6-mapped addrs
  let address;
  try {
    address = await resolveAndValidate(host);
  } catch {
    return null;
  }
  const family = net.isIP(address);
  return family ? { address, family } : null;
}

/**
 * Validate that a webhook URL is safe for external use (blocks SSRF targets). Apply this at the CLI/user-input
 * boundary; `sendWebhook` resolves again itself and PINS what it resolved.
 * @param {string} url
 * @returns {Promise<boolean>}
 */
export async function isSafeWebhookUrl(url) {
  return (await resolveWebhookTarget(url)) !== null;
}

/**
 * A `lookup` for http(s).request that answers the address the check already resolved — in both shapes Node asks for
 * (`{ all: true }` under autoSelectFamily, and the single-answer form) — so the connect never resolves the name again.
 */
export function pinnedLookup({ address, family }) {
  return (hostname, options, callback) => {
    if (typeof options === 'function') { callback = options; options = {}; }
    if (options?.all) callback(null, [{ address, family }]);
    else callback(null, address, family);
  };
}

/**
 * The userinfo (`user:password`) of every proxy variable Node's env-proxy support reads, exactly as written and decoded.
 * Measured on Node 24.12 (2026-10-11): Node ACCEPTS a raw space or a raw `@` inside a proxy password and still routes
 * through the proxy, and its tunnel error then prints the URL verbatim — no URL-shaped pattern can bound a userinfo that
 * contains whitespace. Reading the variables Node itself reads removes the exact string, whatever it contains.
 * @param {Record<string, string|undefined>} [env]
 * @returns {string[]} longest first
 */
export function proxyUserinfo(env = process.env) {
  const out = new Set();
  for (const k of ['HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'http_proxy', 'https_proxy', 'all_proxy']) {
    const v = typeof env[k] === 'string' ? env[k].trim() : '';
    const m = /^[a-z][a-z0-9+.-]*:\/\/([\s\S]*)@[^@]*$/i.exec(v);   // the userinfo runs to the LAST @
    if (!m || !m[1]) continue;
    out.add(m[1]);
    try { out.add(decodeURIComponent(m[1])); } catch { /* not percent-encoded */ }
  }
  return [...out].sort((a, b) => b.length - a.length);
}

/**
 * Credentials replaced, wherever they appear in a message. Measured on Node 24.12 (2026-10-11): with NODE_USE_ENV_PROXY and
 * an HTTPS_PROXY carrying `user:password@`, a failed tunnel's error reads "Failed to establish tunnel to <host> via
 * http://user:password@proxy:port", and that string is what this module returns as `error` — which callers print to stderr
 * and Enterprise writes into the drift file. Every error this module returns passes through here. Two passes: the EXACT
 * userinfo of the proxy variables (any characters, a raw space included), then any URL's userinfo up to the last `@`
 * before the path (an `@` in a PATH is not userinfo: the userinfo segment ends at the first `/`, `?` or `#`).
 */
export function redactUrlCredentials(message, env = process.env) {
  let out = String(message ?? '');
  for (const info of proxyUserinfo(env)) out = out.split(`${info}@`).join('<credentials>@');
  return out.replace(/([a-z][a-z0-9+.-]*:\/\/)[^\s/?#]*@/gi, '$1<credentials>@');
}

// Injectable SSRF checker — overridable in tests only (see _setWebhookSafeChecker).
let _safeChecker = isSafeWebhookUrl;

/**
 * Override the SSRF checker used by sendWebhook. Test-only — throws in production.
 * @internal
 */
export function _setWebhookSafeChecker(fn) {
  if (process.env.NODE_ENV === 'production') throw new Error('_setWebhookSafeChecker is not available in production');
  _safeChecker = fn ?? isSafeWebhookUrl;
}

/**
 * Send a JSON payload to a webhook URL via HTTP POST.
 * @param {string} url - webhook endpoint (http or https)
 * @param {object} payload - JSON-serializable data
 * @param {object} [opts]
 * @param {number} [opts.timeout=10000] - request timeout in ms
 * @param {number} [opts.retries=2] - retry count on failure
 * @param {number} [opts.retryDelayMs=1000] - delay between retries in ms
 * @returns {Promise<{ success: boolean, statusCode: number, error?: string }>}
 */
export async function sendWebhook(url, payload, opts = {}) {
  // Enforce SSRF safety at the function level — covers scheduler, programmatic,
  // and any other callers that bypass CLI parseArgs validation. The production check RESOLVES and the request is
  // PINNED to what it resolved (R1); a test-only checker override decides yes/no and connects as the URL says.
  let target = null;
  if (_safeChecker === isSafeWebhookUrl) {
    target = await resolveWebhookTarget(url);
    if (!target) return { success: false, statusCode: 0, error: 'URL rejected by SSRF guard' };
  } else if (!(await _safeChecker(url))) {
    return { success: false, statusCode: 0, error: 'URL rejected by SSRF guard' };
  }

  const timeout = opts.timeout ?? 10000;
  const retries = opts.retries ?? 2;
  const retryDelayMs = opts.retryDelayMs ?? 1000;

  const body = JSON.stringify(payload);
  const parsed = new URL(url);
  const transport = parsed.protocol === 'https:' ? https : http;

  const requestOptions = {
    method: 'POST',
    hostname: parsed.hostname,
    port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
    path: parsed.pathname + parsed.search,
    headers: {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(body),
    },
    timeout,
    // Every attempt, retries included, connects to the checked address; the name stays the Host header and TLS name.
    ...(target ? { lookup: pinnedLookup(target) } : {}),
    // Its OWN agent, keep-alive off: the default agent pools sockets by host and port, so an idle socket another caller
    // opened to this host:port (by name, unpinned) could carry the alert, and the alert's socket would be left for the
    // next request. Configured like the default agent — its proxy settings (NODE_USE_ENV_PROXY) included.
    agent: new transport.Agent({ ...transport.globalAgent.options, keepAlive: false }),
  };

  let lastError = null;
  const maxAttempts = 1 + retries;

  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    if (attempt > 0 && retryDelayMs > 0) {
      await new Promise((r) => setTimeout(r, retryDelayMs));
    }

    try {
      const result = await new Promise((resolve, reject) => {
        const req = transport.request(requestOptions, (res) => {
          // Consume response body to free socket
          const chunks = [];
          res.on('data', (c) => chunks.push(c));
          res.on('end', () => {
            const statusCode = res.statusCode;
            const success = statusCode >= 200 && statusCode < 300;
            resolve({ success, statusCode });
          });
        });

        req.on('timeout', () => {
          req.destroy();
          reject(new Error('Request timed out'));
        });

        req.on('error', (err) => {
          reject(err);
        });

        req.write(body);
        req.end();
      });

      if (result.success) return result;
      // 4xx = client error, won't succeed on retry
      if (result.statusCode >= 400 && result.statusCode < 500) {
        return { success: false, statusCode: result.statusCode, error: `HTTP ${result.statusCode}` };
      }
      // 5xx or other: retry
      lastError = `HTTP ${result.statusCode}`;
      if (attempt === maxAttempts - 1) {
        return { success: false, statusCode: result.statusCode, error: lastError };
      }
    } catch (err) {
      lastError = redactUrlCredentials(err?.message || String(err));
      if (attempt === maxAttempts - 1) {
        return { success: false, statusCode: 0, error: lastError };
      }
    }
  }

  // Should not reach here, but safety net
  return { success: false, statusCode: 0, error: lastError || 'Unknown error' };
}

/** The watch alert's payload modes (`--alert-payload`). `full` is the default and is unchanged. */
export const ALERT_PAYLOADS = Object.freeze(['full', 'minimal']);

/**
 * The drift notification's vocabularies (`--notify-format` / `--notify-payload` / `--notify-severity`, EE 2.0.0). Kept
 * HERE, in a module with no side effects, so Enterprise's suite can hold its own copy equal to these without loading
 * cli.mjs (which loads the operator's .env). Enterprise validates every value again before it sends.
 */
export const NOTIFY_FORMATS = Object.freeze(['generic', 'slack', 'teams']);
export const NOTIFY_PAYLOADS = Object.freeze(['minimal', 'full']);
export const NOTIFY_SEVERITIES = Object.freeze(['critical', 'high', 'medium', 'low', 'info']);

/**
 * Build a standardised alert payload for webhook delivery.
 * @param {string} host - scanned host
 * @param {object[]} findings - array of finding objects
 * @param {string} [severity='high'] - alert severity level
 * @param {{ payload?: 'full'|'minimal' }} [opts] - `minimal` (EE 2.0.0, offered, NOT the default — the architect seat's
 *   ruling: a relay parsing `details[]` must not break silently) drops the host, the service and the description: a
 *   count, the alert severity, and per finding its port, protocol and severity only.
 * @returns {object} alert payload
 */
export function buildAlertPayload(host, findings, severity = 'high', { payload = 'full' } = {}) {
  const items = Array.isArray(findings) ? findings : [];

  if (payload === 'minimal') {
    return {
      timestamp: new Date().toISOString(),
      payload: 'minimal',
      severity,
      findingsCount: items.length,
      summary: `${items.length} finding(s) detected at severity ${severity} or above`,
      details: items.map((f) => ({
        port: f.port ?? null,
        protocol: f.protocol === null ? null : (f.protocol ?? 'tcp'),
        severity: f.severity ?? severity,
      })),
    };
  }

  return {
    timestamp: new Date().toISOString(),
    host,
    severity,
    findingsCount: items.length,
    summary: `${items.length} finding(s) detected on ${host} at severity ${severity} or above`,
    details: items.map((f) => ({
      port: f.port ?? null,
      // A finding with no port (a domain's DNS posture) carries protocol null — no transport — and keeps it.
      protocol: f.protocol === null ? null : (f.protocol ?? 'tcp'),
      service: f.service ?? null,
      description: f.description ?? f.summary ?? null,
      severity: f.severity ?? severity,
    })),
  };
}
