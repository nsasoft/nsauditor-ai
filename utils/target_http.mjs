// utils/target_http.mjs
// ─────────────────────────────────────────────────────────────────────────────
// THE TARGET HTTP WAIST (EE Z-1, architect v381 C-1/C-2). One way to send an HTTP request to a host under scan.
//
// WHY NOT THE GLOBAL fetch. Node's fetch (undici) decodes a reply's Content-Encoding itself, whatever was asked for, and
// node bundles its own zstd. Measured on Node 24.22.3 (undici 7.30.2, zstd 1.5.7), on the host and inside the 2.2.0 image
// (../audit-evidence-samples/ee-2.2.1/z1/m-fetch-zstd-reach-v335): a zstd reply has already been FED to the bundled
// decoder by the first line after `await fetch(...)` — before any caller code can look at the header and cancel — and
// asking for `accept-encoding: identity` changes nothing. node:http never constructs a decoder.
//
// WHAT THIS DOES. Built on node:http/https.request with `agent: false` (one connection per request, never pooled), it:
//   - asks for `accept-encoding: identity`, which no caller can override;
//   - DECODES NOTHING. A reply carrying any Content-Encoding other than absent, empty or identity (every header line,
//     every token), or any transfer coding other than chunked, is NOT READ: the response is destroyed before a data
//     listener exists and the socket closes;
//   - never follows a redirect: a 3xx is returned as it came;
//   - holds the whole exchange (connect, headers, body) to ONE deadline, `timeoutMs`;
//   - caps the body at `maxBodyBytes` (default 1 MiB). A body over the cap is not read: no partial body is handed back,
//     so nothing can conclude absence from a truncated one.
//
// THE OUTCOMES. A response that began resolves; one that did not rejects.
//   resolved: { url, status, headers, setCookie, text?, notRead }
//     notRead === null      → `text` is the body, decoded as fetch's text() decodes it.
//     notRead = { reason }  → reason is one of NOT_READ_REASONS; `text` is absent. For `encoded-body` it also carries
//                             `encoding`, the reply's coding tokens (Content-Encoding, and any transfer coding other than
//                             chunked) mapped to the IANA content-coding registry, anything else `other`, at most four.
//   The reply's Content-Encoding text appears nowhere in an outcome. EVERY OTHER HEADER IS THE TARGET'S OWN TEXT —
//   `headers` and `setCookie` carry it as received, the raw Transfer-Encoding value included — and each site redacts
//   what it prints. A 204 or 304 is read as empty whatever coding it names: no body can exist there.
//   rejected (no response): TargetHttpError { code } — the code sanitized, the message fixed — or, at the deadline, an
//     AbortError (code ETIMEDOUT), so a caller that reads `err.name === 'AbortError'` as a timeout keeps doing so. Node's
//     own error messages are NOT passed on: a TLS name mismatch, for one, quotes the target's certificate names.
//   `headers` joins repeated fields as fetch does (", "; "; " for cookie). `setCookie` is every Set-Cookie line, in order.
//
// DENY BY DEFAULT. Options are exactly { method, headers, timeoutMs, maxBodyBytes }; anything else throws, so no caller
// can hand in an agent, a lookup, a TLS override or a redirect mode. Methods are ALLOWED_METHODS — what the four former
// fetch sites send, less CONNECT/TRACE/TRACK (tests/target_http.test.mjs derives the set from the sites' source).
//
// THE PIN. Name resolution goes through node:dns `lookup`, which utils/scan_pin.mjs pins inside a scan, so a request to a
// checked name goes to the checked address with the name as Host and SNI. agent:false means no idle connection opened
// earlier is reused for it.
// ─────────────────────────────────────────────────────────────────────────────
import http from 'node:http';
import https from 'node:https';

export const ALLOWED_METHODS = Object.freeze(['GET', 'OPTIONS', 'DELETE', 'PUT', 'PATCH']);
export const FORBIDDEN_METHODS = Object.freeze(['CONNECT', 'TRACE', 'TRACK']);
export const NOT_READ_REASONS = Object.freeze(['encoded-body', 'body-timeout', 'body-error', 'body-cap']);
export const DEFAULT_MAX_BODY_BYTES = 1024 * 1024;
// A ceiling on timeoutMs: past 2^31-1 ms node clamps a timer to 1 ms, and a live host would read as one that never answered.
export const MAX_TIMEOUT_MS = 120000;
const BODILESS_STATUSES = new Set([204, 304]);

const OPTION_KEYS = new Set(['method', 'headers', 'timeoutMs', 'maxBodyBytes']);
// Headers the waist owns: the coding it asks for, and the framing of a one-shot request.
const CALLER_FORBIDDEN_HEADERS = new Set([
  'accept-encoding', 'connection', 'content-length', 'transfer-encoding', 'host', 'te', 'trailer', 'upgrade',
  'keep-alive', 'proxy-connection', 'expect',
]);
// The IANA HTTP Content Coding Registry. A token outside it is reported as `other`: an attacker-chosen token is never
// echoed, not even one that fits a safe charset (`refused` would match the concluder's re-label regex).
const CODING_REGISTRY = new Set([
  'aes128gcm', 'br', 'compress', 'dcb', 'dcz', 'deflate', 'exi', 'gzip', 'identity', 'pack200-gzip', 'x-compress', 'x-gzip', 'zstd',
]);
const MAX_ENCODING_TOKENS = 4;
// fetch's request defaults other than its accept-encoding, keep-alive and `user-agent: node` (measured on Node 24.22.3;
// tests/target_http.test.mjs holds the per-method parity). The waist sends no default user-agent: every site sends its own.
const DEFAULT_HEADERS = Object.freeze({ accept: '*/*', 'accept-language': '*', 'sec-fetch-mode': 'cors' });

export class TargetHttpError extends Error {
  constructor(code) {
    super(`target request failed (${code})`);
    this.name = 'TargetHttpError';
    this.code = code;
  }
}

const safeCode = (c) => (typeof c === 'string' && /^[A-Z][A-Z0-9_]{0,47}$/.test(c) ? c : 'EOTHER');

function timeoutError() {
  const e = new Error('target request timed out');
  e.name = 'AbortError';
  e.code = 'ETIMEDOUT';
  return e;
}

function isPlainObject(v) {
  return v !== null && typeof v === 'object' && Object.getPrototypeOf(v) === Object.prototype;
}

function validate(url, options) {
  if (!isPlainObject(options)) throw new TypeError('requestTarget: options must be a plain object');
  for (const k of Object.keys(options)) {
    if (!OPTION_KEYS.has(k)) throw new TypeError(`requestTarget: option "${k}" is not accepted`);
  }
  let u;
  try { u = new URL(String(url)); } catch { throw new TypeError('requestTarget: url is not a URL'); }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') throw new TypeError('requestTarget: only http and https');
  // node:http would SEND these as an Authorization header (fetch throws on such a URL).
  if (u.username || u.password) throw new TypeError('requestTarget: a URL carrying credentials is not accepted');

  const method = options.method ?? 'GET';
  if (typeof method !== 'string' || !ALLOWED_METHODS.includes(method)) {
    throw new TypeError(`requestTarget: method ${JSON.stringify(method)} is not accepted`);
  }
  const { timeoutMs } = options;
  if (!Number.isInteger(timeoutMs) || timeoutMs <= 0 || timeoutMs > MAX_TIMEOUT_MS) {
    throw new TypeError(`requestTarget: timeoutMs must be an integer in 1..${MAX_TIMEOUT_MS}`);
  }
  const maxBodyBytes = options.maxBodyBytes ?? DEFAULT_MAX_BODY_BYTES;
  if (!Number.isInteger(maxBodyBytes) || maxBodyBytes <= 0 || maxBodyBytes > DEFAULT_MAX_BODY_BYTES) {
    throw new TypeError(`requestTarget: maxBodyBytes must be an integer in 1..${DEFAULT_MAX_BODY_BYTES}`);
  }
  const headers = { ...DEFAULT_HEADERS };
  if (options.headers !== undefined) {
    if (!isPlainObject(options.headers)) throw new TypeError('requestTarget: headers must be a plain object');
    for (const [name, value] of Object.entries(options.headers)) {
      if (typeof value !== 'string') throw new TypeError(`requestTarget: header "${name}" must be a string`);
      const lower = name.toLowerCase();
      if (CALLER_FORBIDDEN_HEADERS.has(lower)) throw new TypeError(`requestTarget: header "${name}" is owned by the waist`);
      headers[lower] = value;
    }
  }
  headers['accept-encoding'] = 'identity';
  headers.connection = 'close';
  return { u, method, timeoutMs, maxBodyBytes, headers };
}

/** Read every header line: fetch-style joined fields, Set-Cookie in order, and the coding tokens. */
function readHeaders(rawHeaders) {
  const headers = {};
  const setCookie = [];
  const codings = [];
  for (let i = 0; i + 1 < rawHeaders.length; i += 2) {
    const name = String(rawHeaders[i]).toLowerCase();
    const value = String(rawHeaders[i + 1]);
    if (name === 'set-cookie') { setCookie.push(value); continue; }
    if (name === 'content-encoding') {
      for (const t of value.split(',')) { const tok = t.trim().toLowerCase(); if (tok) codings.push(tok); }
      continue;
    }
    if (name === 'transfer-encoding') {
      // node:http removes the chunked framing and decodes nothing else, so any other transfer coding leaves a body that
      // cannot be interpreted. It is not read either. The header itself stays visible, as fetch shows it.
      for (const t of value.split(',')) { const tok = t.trim().toLowerCase(); if (tok && tok !== 'chunked') codings.push(tok); }
    }
    // Own properties only: a field named `constructor` or `__proto__` must not meet Object.prototype.
    const joined = Object.hasOwn(headers, name) ? `${headers[name]}${name === 'cookie' ? '; ' : ', '}${value}` : value;
    Object.defineProperty(headers, name, { value: joined, writable: true, enumerable: true, configurable: true });
  }
  const encoded = codings.some((t) => t !== 'identity');
  let encoding = codings.map((t) => (CODING_REGISTRY.has(t) ? t : 'other'));
  if (encoding.length > MAX_ENCODING_TOKENS) encoding = [...encoding.slice(0, MAX_ENCODING_TOKENS - 1), 'other'];
  return { headers, setCookie, encoded, encoding };
}

/**
 * Send one request to a host under scan. See the header of this file for the outcomes and what is refused.
 * @param {string|URL} url
 * @param {{ method?: string, headers?: Record<string,string>, timeoutMs: number, maxBodyBytes?: number }} options
 */
export async function requestTarget(url, options = {}) {
  const { u, method, timeoutMs, maxBodyBytes, headers } = validate(url, options);
  const transport = u.protocol === 'https:' ? https : http;

  return new Promise((resolve, reject) => {
    let settled = false;
    let req = null;
    let res = null;
    let meta = null;

    const outcome = (extra) => ({ url: u.href, status: res.statusCode, headers: meta.headers, setCookie: meta.setCookie, ...extra });
    const shut = () => { try { res?.destroy(); } catch {} try { req?.destroy(); } catch {} };
    const settle = (fn, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(deadline);
      fn(value);
    };
    const notRead = (reason, extra = {}) => { shut(); settle(resolve, outcome({ notRead: { reason, ...extra } })); };

    const deadline = setTimeout(() => {
      if (res) notRead('body-timeout');
      else { shut(); settle(reject, timeoutError()); }
    }, timeoutMs);

    try {
      req = transport.request(u, { method, headers, agent: false }, (response) => {
        res = response;
        meta = readHeaders(response.rawHeaders);
        if (BODILESS_STATUSES.has(response.statusCode)) {
          // Settled here, before any listener: bytes a server sends after a 204/304 are not a body and surface nowhere.
          settle(resolve, outcome({ text: '', notRead: null }));
          return shut();
        }
        if (meta.encoded) return notRead('encoded-body', { encoding: meta.encoding });
        const chunks = [];
        let size = 0;
        response.on('data', (chunk) => {
          if (settled) return;
          size += chunk.length;
          if (size > maxBodyBytes) return notRead('body-cap');
          chunks.push(chunk);
        });
        response.on('end', () => {
          if (settled) return;
          const text = new TextDecoder('utf-8').decode(Buffer.concat(chunks));
          settle(resolve, outcome({ text, notRead: null }));
          shut();
        });
        response.on('error', () => notRead('body-error'));
        response.on('close', () => { if (!response.complete) notRead('body-error'); });
      });
    } catch (err) {
      settle(reject, err instanceof TypeError ? err : new TargetHttpError(safeCode(err?.code)));
      return;
    }
    req.on('error', (err) => {
      if (res) notRead('body-error');
      else { shut(); settle(reject, new TargetHttpError(safeCode(err?.code))); }
    });
    req.end();
  });
}
