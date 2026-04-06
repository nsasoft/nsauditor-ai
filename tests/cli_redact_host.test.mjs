import assert from 'node:assert/strict';
import test from 'node:test';
import { resolveCapabilities, hasCapability } from '../utils/capabilities.mjs';

/**
 * Mirrors the redactSensitiveForAI + top-level host/summary redaction
 * sequence from cli.mjs's maybeSendToOpenAI().
 *
 * The function itself is defined inline in cli.mjs and not exported,
 * so we replicate the exact logic here for focused unit testing.
 */

function redactSensitiveForAI(input) {
  const DROP_KEYS = new Set([
    'ip6', 'deviceWebPage', 'deviceWebPageInstruction',
    'hardwareVersion', 'firmwareVersion'
  ]);
  const SERIAL_KEY_RE = /^(serial(number)?|sn)$/i;
  const isPrivateV4 = (ip) =>
    /^10\./.test(ip) ||
    /^172\.(1[6-9]|2\d|3[0-1])\./.test(ip) ||
    /^192\.168\./.test(ip);

  const scrubString = (str) => {
    let s = String(str);
    s = s.replace(/\bSerial\s*[:=]\s*[A-Za-z0-9._-]+/gi, 'Serial=[REDACTED_HIDDEN]');
    s = s.replace(/\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b/gi, '[MAC]');
    s = s.replace(/\bfe80::[0-9a-f:]+\b/gi, '[FE80::/64]');
    s = s.replace(/\b(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{1,4}\b/gi, '[IPv6]');
    s = s.replace(/\b(?:(?:\d{1,3}\.){3}\d{1,3})\b/g, (ip) => (isPrivateV4(ip) ? ip : '[IP]'));
    return s;
  };

  const walk = (val) => {
    if (Array.isArray(val)) return val.map((v) => walk(v));
    if (val && typeof val === 'object') {
      const out = {};
      for (const [k, v] of Object.entries(val)) {
        if (DROP_KEYS.has(k)) continue;
        if (SERIAL_KEY_RE.test(k)) { out[k] = '[REDACTED_HIDDEN]'; continue; }
        out[k] = walk(v);
      }
      return out;
    }
    if (typeof val === 'string') return scrubString(val);
    return val;
  };

  return walk(input);
}

/**
 * Simulates the full redaction sequence from maybeSendToOpenAI():
 *   1. redactSensitiveForAI(payloadForAI)
 *   2. payloadForAI.host = '[REDACTED_HOST]'
 *   3. payloadForAI.summary IPs → '[REDACTED_HOST]'
 *   4. scrubPrivateIps on services/evidence
 */
function applyFullRedaction(payloadForAI) {
  let p = redactSensitiveForAI(payloadForAI);

  if (typeof p.host === 'string') {
    p.host = '[REDACTED_HOST]';
  }

  if (typeof p.summary === 'string') {
    p.summary = p.summary
      .replace(/\b(?:(?:\d{1,3}\.){3}\d{1,3})\b/g, '[REDACTED_HOST]');
  }

  const privateIpRe = /\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b/g;
  function scrubPrivateIps(obj) {
    if (typeof obj === 'string') return obj.replace(privateIpRe, '[REDACTED_IP]');
    if (Array.isArray(obj)) return obj.map(scrubPrivateIps);
    if (obj && typeof obj === 'object') {
      const out = {};
      for (const [k, v] of Object.entries(obj)) out[k] = scrubPrivateIps(v);
      return out;
    }
    return obj;
  }
  p.services = scrubPrivateIps(p.services);
  p.evidence = scrubPrivateIps(p.evidence);

  return p;
}

// --- Tests ---

test('host field is redacted to [REDACTED_HOST] for private IP', () => {
  const payload = {
    host: '192.168.1.1',
    summary: 'Some summary',
    services: [],
    evidence: [],
  };
  const result = applyFullRedaction(payload);
  assert.equal(result.host, '[REDACTED_HOST]');
});

test('host field is redacted to [REDACTED_HOST] for public IP', () => {
  const payload = {
    host: '8.8.8.8',
    summary: 'Some summary',
    services: [],
    evidence: [],
  };
  const result = applyFullRedaction(payload);
  assert.equal(result.host, '[REDACTED_HOST]');
});

test('host field with port suffix is redacted', () => {
  const payload = {
    host: '192.168.1.1:53/udp',
    summary: 'Scan results',
    services: [],
    evidence: [],
  };
  const result = applyFullRedaction(payload);
  assert.equal(result.host, '[REDACTED_HOST]');
});

test('summary field has IPs redacted', () => {
  const payload = {
    host: '10.0.0.5',
    summary: 'Host 10.0.0.5 has 3 open ports and 192.168.1.100 responded',
    services: [],
    evidence: [],
  };
  const result = applyFullRedaction(payload);
  assert.equal(result.host, '[REDACTED_HOST]');
  assert.equal(result.summary, 'Host [REDACTED_HOST] has 3 open ports and [REDACTED_HOST] responded');
});

test('summary field with public IPs also redacted', () => {
  const payload = {
    host: '203.0.113.5',
    summary: 'Scanned 203.0.113.5 - found services on 203.0.113.10',
    services: [],
    evidence: [],
  };
  const result = applyFullRedaction(payload);
  assert.equal(result.host, '[REDACTED_HOST]');
  // Public IPs are first replaced by scrubString → '[IP]', then the IP regex
  // in the top-level summary pass won't match '[IP]' (no dots), so scrubString
  // handles public IPs in summary already.
  assert.ok(!result.summary.includes('203.0.113.5'));
  assert.ok(!result.summary.includes('203.0.113.10'));
});

test('original payload is not mutated', () => {
  const payload = {
    host: '192.168.1.1',
    summary: 'Host 192.168.1.1 scanned',
    services: [],
    evidence: [],
  };
  applyFullRedaction(payload);
  assert.equal(payload.host, '192.168.1.1', 'original host must not be mutated');
  assert.equal(payload.summary, 'Host 192.168.1.1 scanned', 'original summary must not be mutated');
});

test('non-string host is left alone', () => {
  const payload = {
    host: undefined,
    summary: 'No host',
    services: [],
    evidence: [],
  };
  const result = applyFullRedaction(payload);
  assert.equal(result.host, undefined);
});

test('summary without IPs is unchanged', () => {
  const payload = {
    host: '192.168.1.1',
    summary: 'Found 3 open ports with DNS service running',
    services: [],
    evidence: [],
  };
  const result = applyFullRedaction(payload);
  assert.equal(result.host, '[REDACTED_HOST]');
  assert.equal(result.summary, 'Found 3 open ports with DNS service running');
});

test('private IPs in nested services info/banner are redacted', () => {
  const payload = {
    host: '192.168.1.1',
    summary: 'Scan complete',
    services: [
      { port: 80, info: 'HTTP on 192.168.1.1', banner: 'Server at 10.0.0.5' },
      { port: 443, info: 'TLS endpoint 172.16.0.1', banner: 'OK' },
    ],
    evidence: [
      { info: 'Found 192.168.100.50 responding', banner: 'ARP reply from 10.255.0.1' },
    ],
  };
  const result = applyFullRedaction(payload);
  // services
  assert.equal(result.services[0].info, 'HTTP on [REDACTED_IP]');
  assert.equal(result.services[0].banner, 'Server at [REDACTED_IP]');
  assert.equal(result.services[1].info, 'TLS endpoint [REDACTED_IP]');
  assert.equal(result.services[1].banner, 'OK');
  // evidence
  assert.equal(result.evidence[0].info, 'Found [REDACTED_IP] responding');
  assert.equal(result.evidence[0].banner, 'ARP reply from [REDACTED_IP]');
});

test('public IPs in nested services are NOT redacted by scrubPrivateIps', () => {
  const payload = {
    host: '8.8.8.8',
    summary: 'Scan complete',
    services: [
      { port: 53, info: 'DNS at 8.8.8.8' },
    ],
    evidence: [],
  };
  const result = applyFullRedaction(payload);
  // scrubString already replaced 8.8.8.8 → [IP], scrubPrivateIps won't touch it further
  assert.ok(!result.services[0].info.includes('8.8.8.8'));
});

// ---------------------------------------------------------------------------
// globalThis.redactSensitiveForAI gate — mirrors the condition in cli.mjs:
//   if (hasCapability(redactCaps, 'enhancedRedaction') && typeof globalThis.redactSensitiveForAI === 'function')
// Tests here use the actual imported resolveCapabilities/hasCapability so that
// a rename of the capability key or a change to resolveCapabilities breaks these tests.
// ---------------------------------------------------------------------------

test('globalThis.redactSensitiveForAI gate: CE tier blocks external override', () => {
  const caps = resolveCapabilities('ce');
  const allowed = hasCapability(caps, 'enhancedRedaction');
  assert.equal(allowed, false, 'CE must not have enhancedRedaction');

  // Simulate the gate: spy must not be invoked when allowed === false
  let spyCalled = false;
  const prev = globalThis.redactSensitiveForAI;
  globalThis.redactSensitiveForAI = () => { spyCalled = true; return {}; };
  try {
    if (allowed && typeof globalThis.redactSensitiveForAI === 'function') {
      globalThis.redactSensitiveForAI({});
    }
    assert.equal(spyCalled, false, 'external override must not be called on CE tier');
  } finally {
    globalThis.redactSensitiveForAI = prev;
  }
});

test('globalThis.redactSensitiveForAI gate: Pro tier allows external override', () => {
  const caps = resolveCapabilities('pro');
  const allowed = hasCapability(caps, 'enhancedRedaction');
  assert.equal(allowed, true, 'Pro must have enhancedRedaction');

  let spyCalled = false;
  const prev = globalThis.redactSensitiveForAI;
  globalThis.redactSensitiveForAI = () => { spyCalled = true; return {}; };
  try {
    if (allowed && typeof globalThis.redactSensitiveForAI === 'function') {
      globalThis.redactSensitiveForAI({});
    }
    assert.equal(spyCalled, true, 'external override must be called on Pro tier');
  } finally {
    globalThis.redactSensitiveForAI = prev;
  }
});

test('globalThis.redactSensitiveForAI gate: Enterprise tier allows external override', () => {
  const caps = resolveCapabilities('enterprise');
  const allowed = hasCapability(caps, 'enhancedRedaction');
  assert.equal(allowed, true, 'Enterprise must have enhancedRedaction');
});
