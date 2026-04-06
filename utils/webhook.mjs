// utils/webhook.mjs
// Webhook notification utilities — pure Node.js, no external deps.

import http from 'node:http';
import https from 'node:https';
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
 * Validate that a webhook URL is safe for external use (blocks SSRF targets).
 * Apply this at the CLI/user-input boundary, not inside sendWebhook itself.
 * Performs DNS resolution to defeat rebinding / encoded-IP bypasses.
 * @param {string} url
 * @returns {Promise<boolean>}
 */
export async function isSafeWebhookUrl(url) {
  if (!isValidWebhookUrl(url)) return false;
  const host = new URL(url).hostname.toLowerCase();
  // Fast-path: block obvious loopback, link-local, cloud metadata, and private ranges
  if (/^(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[0-1])\.|169\.254\.|0\.|localhost$|metadata\.google)/i.test(host)) {
    return false;
  }
  if (host === '::1' || host === '[::1]' || /^fe80:/i.test(host)) return false;

  // DNS resolution check — catches rebinding, decimal/octal IPs, IPv6-mapped addrs
  try {
    await resolveAndValidate(host);
  } catch {
    return false;
  }
  return true;
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
  if (!isValidWebhookUrl(url)) {
    return { success: false, statusCode: 0, error: 'Invalid URL: must be http or https' };
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
      lastError = err?.message || String(err);
      if (attempt === maxAttempts - 1) {
        return { success: false, statusCode: 0, error: lastError };
      }
    }
  }

  // Should not reach here, but safety net
  return { success: false, statusCode: 0, error: lastError || 'Unknown error' };
}

/**
 * Build a standardised alert payload for webhook delivery.
 * @param {string} host - scanned host
 * @param {object[]} findings - array of finding objects
 * @param {string} [severity='high'] - alert severity level
 * @returns {object} alert payload
 */
export function buildAlertPayload(host, findings, severity = 'high') {
  const items = Array.isArray(findings) ? findings : [];

  return {
    timestamp: new Date().toISOString(),
    host,
    severity,
    findingsCount: items.length,
    summary: `${items.length} finding(s) detected on ${host} at severity ${severity} or above`,
    details: items.map((f) => ({
      port: f.port ?? null,
      protocol: f.protocol ?? 'tcp',
      service: f.service ?? null,
      description: f.description ?? f.summary ?? null,
      severity: f.severity ?? severity,
    })),
  };
}
