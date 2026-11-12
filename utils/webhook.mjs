// utils/webhook.mjs
// Webhook notification utilities — pure Node.js, no external deps.

import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import { isBlockedIp, resolveAndValidate, canonicalIp } from './net_validation.mjs';

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
  // Fast path, without a lookup: an IP LITERAL in a blocked range (the address classifier, in any spelling) and the names
  // that are loopback or metadata by definition — `localhost`, its subdomains (RFC 6761), the GCP metadata name. A NAME
  // that merely starts like a private literal (10.example.com, metadata.googleapis.com) is resolved and checked below.
  const bare = host.replace(/\.$/, '');
  if (bare === 'localhost' || bare.endsWith('.localhost') || bare === 'metadata.google.internal') return null;
  if (canonicalIp(host) && isBlockedIp(host)) return null;

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

const PROXY_VARIABLES = Object.freeze(['HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'http_proxy', 'https_proxy', 'all_proxy']);
/** The userinfo of each proxy variable as written, or none. The userinfo runs to the LAST @. */
function writtenUserinfo(env) {
  const out = [];
  for (const k of PROXY_VARIABLES) {
    const v = typeof env[k] === 'string' ? env[k].trim() : '';
    const m = /^[a-z][a-z0-9+.-]*:\/\/([\s\S]*)@[^@]*$/i.exec(v);
    if (m && m[1]) out.push(m[1]);
  }
  return out;
}
const tryDecode = (s) => { try { return decodeURIComponent(s); } catch { return s; } };   // not percent-encoded
const longestFirst = (set) => [...set].sort((a, b) => b.length - a.length);

/**
 * The userinfo (`user:password`) of every proxy variable Node's env-proxy support reads, exactly as written and decoded.
 * Measured on Node 24.12 (2026-10-11): Node ACCEPTS a raw space or a raw `@` inside a proxy password and still routes
 * through the proxy, and its tunnel error then prints the URL verbatim — no URL-shaped pattern can bound a userinfo that
 * contains whitespace. Reading the variables Node itself reads removes the exact string, whatever it contains.
 * (The raw-space routing was NOT re-measured on 24.22.x; the 2026-11-11 re-measurement below covers the tunnel message.)
 * @param {Record<string, string|undefined>} [env]
 * @returns {string[]} longest first
 */
export function proxyUserinfo(env = process.env) {
  const out = new Set();
  for (const info of writtenUserinfo(env)) { out.add(info); out.add(tryDecode(info)); }
  return longestFirst(out);
}

/**
 * The shortest proxy password replaced BARE (EE 2.2.0, I3). A shorter one would shred ordinary text wherever its
 * characters happen to occur, so it is removed only inside a URL's userinfo (the first two passes), never on its own.
 */
export const PROXY_SECRET_MIN_LENGTH = 8;

/**
 * The secret of every proxy variable, as written and percent-decoded, longest first, each at least
 * PROXY_SECRET_MIN_LENGTH characters. The secret is the password: the userinfo after its FIRST `:` (a `:` inside the
 * password is kept, and the split is made on the written form, so an encoded `%3A` is never a separator). A user name
 * is not a secret, with or without a password: a userinfo with no `:` yields none, and is removed only inside a URL.
 *
 * Why (EE 2.2.0, I3, measured 2026-11-11 on Node 24.22.3): @aws-sdk/credential-provider-process carries a configured
 * child's full stderr into the CredentialsProviderError it throws, and a child can print the proxy password alone or
 * percent-decoded, where no `@` follows it. google-auth-library's pluggable-auth handler and @azure/identity's
 * AzureCliCredential carry a child's stderr into their errors the same way (read from code; `az` was not measured).
 * @param {Record<string, string|undefined>} [env]
 * @returns {string[]} longest first
 */
export function proxySecrets(env = process.env) {
  const out = new Set();
  for (const info of writtenUserinfo(env)) {
    const colon = info.indexOf(':');
    if (colon < 0) continue;   // a user name alone is not a secret: replaced bare it would shred host names and banners
    const secret = info.slice(colon + 1);
    for (const s of [secret, tryDecode(secret)]) if (s.length >= PROXY_SECRET_MIN_LENGTH) out.add(s);
  }
  return longestFirst(out);
}

/**
 * Credentials replaced, wherever they appear in a message. Measured on Node 24.12 (2026-10-11): with NODE_USE_ENV_PROXY and
 * an HTTPS_PROXY carrying `user:password@`, a failed tunnel's error reads "Failed to establish tunnel to <host> via
 * http://user:password@proxy:port", and that string is what this module returns as `error` — which callers print to stderr
 * and Enterprise writes into the drift file. Re-measured on Node 24.22.1 and 24.22.3 (2026-11-11, the 24.22.3 floor's C1):
 * the tunnel error no longer carries the userinfo, and neither the drift file nor the returned errors carried the password
 * in any shape tried; the two passes stay for a runtime that prints it and for any other message that does. Every error this module returns passes through here. Two passes: the EXACT
 * userinfo of the proxy variables (any characters, a raw space included), then any URL's userinfo up to the last `@`
 * before the path (an `@` in a PATH is not userinfo: the userinfo segment ends at the first `/`, `?` or `#`).
 */
export function redactUrlCredentials(message, env = process.env) {
  return credentialRedactor(env)(message);
}

/**
 * redactUrlCredentials with the environment read ONCE, for a caller that redacts many strings (the plugin manager walks
 * every string a plugin returns or throws). Three passes, in order: the EXACT userinfo of the proxy variables followed by
 * `@`; any URL's userinfo; then each proxy secret (proxySecrets) wherever it appears, replaced by `<credentials>`.
 * A string with no `@` that contains no secret is returned as it came — every pass needs one or the other.
 * @param {Record<string, string|undefined>} [env]
 * @returns {(message: unknown) => string}
 */
const PLACEHOLDER = '<credentials>';
export function credentialRedactor(env = process.env) {
  const infos = proxyUserinfo(env);
  const secrets = proxySecrets(env);
  return (message) => {
    let out = String(message ?? '');
    if (!out.includes('@') && !secrets.some((s) => out.includes(s))) return out;
    for (const info of infos) out = out.split(`${info}@`).join('<credentials>@');
    out = out.replace(/([a-z][a-z0-9+.-]*:\/\/)[^\s/?#]*@/gi, '$1<credentials>@');
    // Each secret is replaced BETWEEN placeholders, never inside one: a password such as `credentials` would otherwise
    // rewrite `<credentials>` itself, and redacting twice would not give the same text.
    for (const s of secrets) out = out.split(PLACEHOLDER).map((seg) => seg.split(s).join(PLACEHOLDER)).join(PLACEHOLDER);
    return out;
  };
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
