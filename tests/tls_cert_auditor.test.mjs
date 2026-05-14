// tests/tls_cert_auditor.test.mjs
// Pins the per-port emission noise fix for plugin 040.
// Pre-fix the plugin manager fanned out 10 invocations (one per port in
// plugin.ports) and each failed port emitted its own "no_tls_detected" INFO,
// leaving downstream renderers with 10 empty top-level plugin results on hosts
// that only run HTTPS on 443. Post-fix the plugin declares runStrategy: 'single'
// and conclude() collapses failed ports into one rollup INFO with
// details.failedPorts preserved.

import { test } from 'node:test';
import assert from 'node:assert/strict';

const { default: plugin } = await import('../plugins/040_tls_cert_auditor.mjs');

// ── Helpers ────────────────────────────────────────────────────────────────

function fakeActivePort(port, overrides = {}) {
  return {
    port,
    service: 'https',
    up: true,
    latencyMs: 12,
    severity: 'pass',
    certificate: {
      subject: { CN: 'example.com' },
      issuer: { CN: 'Test CA' },
      validFrom: '2025-01-01T00:00:00Z',
      validTo: '2027-01-01T00:00:00Z',
      daysToExpiry: 365,
      expired: false,
      notYetValid: false,
      selfSigned: false,
      hostnameValid: true,
      names: ['example.com'],
      signatureAlgorithm: 'sha256WithRSAEncryption',
      keyType: 'RSA',
      keyBits: 2048,
      fingerprint256: 'AA:BB',
      serialNumber: '01',
    },
    chain: { depth: 2, entries: [] },
    negotiation: {
      protocol: 'TLSv1.3',
      cipher: 'TLS_AES_256_GCM_SHA384',
      cipherVersion: 'TLSv1.3',
      forwardSecrecy: true,
      isWeakCipher: false,
    },
    authorized: true,
    authError: null,
    issues: [],
    ...overrides,
  };
}

// ── Plugin metadata pins ───────────────────────────────────────────────────

test('plugin 040: declares runStrategy "single" so callPlugin does not fan out per-port', () => {
  assert.equal(plugin.runStrategy, 'single',
    'runStrategy must be "single" — otherwise plugin_manager.callPlugin invokes run() once per entry in plugin.ports, defeating the failedPorts rollup');
});

test('plugin 040: id is in CE range (001-099, reserved for CE; EE owns 1000+)', () => {
  assert.equal(plugin.id, '040');
  const n = Number(plugin.id);
  assert.ok(n >= 1 && n <= 999, `plugin id must be < 1000 for CE; got ${plugin.id}`);
});

test('plugin 040: ports list unchanged (10 well-known TLS ports)', () => {
  assert.deepEqual(plugin.ports, [443, 465, 587, 636, 853, 993, 995, 8443, 8883, 9443]);
});

// ── conclude() contract ────────────────────────────────────────────────────

test('conclude(): no probed ports at all → single "no_tls_detected" INFO (defensive path)', () => {
  const items = plugin.conclude({
    host: 'example.com',
    result: { portResults: [], failedPorts: [] },
  });

  assert.equal(items.length, 1);
  assert.equal(items[0].status, 'no_tls_detected');
  assert.equal(items[0].severity, 'info');
  assert.equal(items[0].source, 'tls-cert-auditor');
});

test('conclude(): all-failed (no active ports, N failed) → single rollup INFO, no per-port placeholders', () => {
  const failedPorts = [
    { port: 443,  error: 'ECONNREFUSED' },
    { port: 465,  error: 'ECONNREFUSED' },
    { port: 587,  error: 'ETIMEDOUT' },
    { port: 636,  error: 'ECONNREFUSED' },
    { port: 853,  error: 'ENETDOWN' },
    { port: 993,  error: 'ECONNREFUSED' },
    { port: 995,  error: 'ECONNREFUSED' },
    { port: 8443, error: 'ECONNREFUSED' },
    { port: 8883, error: 'ECONNREFUSED' },
    { port: 9443, error: 'ECONNREFUSED' },
  ];

  const items = plugin.conclude({
    host: '192.168.1.1',
    result: { portResults: [], failedPorts },
  });

  assert.equal(items.length, 1, 'all-failed must produce exactly ONE rollup (was 10 in the pre-fix shape)');
  const rollup = items[0];
  assert.equal(rollup.status, 'tls-not-responding');
  assert.equal(rollup.severity, 'info');
  assert.equal(rollup.port, 0, 'rollup uses port=0 so concluder routes it to evidence, not services');
  assert.equal(rollup.protocol, 'tcp');
  assert.equal(rollup.service, 'tls');
  assert.deepEqual(rollup.details.failedPorts, failedPorts, 'failedPorts array preserved verbatim');
  assert.deepEqual(rollup.details.activePorts, []);
  assert.match(rollup.info, /10\/10/, 'rollup info advertises N/total');
  assert.match(rollup.info, /443: ECONNREFUSED/);
  assert.match(rollup.info, /853: ENETDOWN/);
});

test('conclude(): all-active (N active, zero failed) → N substantive findings, no rollup', () => {
  const portResults = [fakeActivePort(443), fakeActivePort(8443)];

  const items = plugin.conclude({
    host: 'example.com',
    result: { portResults, failedPorts: [] },
  });

  assert.equal(items.length, 2);
  assert.equal(items[0].port, 443);
  assert.equal(items[1].port, 8443);
  assert.ok(items.every((i) => i.status !== 'tls-not-responding'), 'no rollup when failedPorts is empty');
});

test('conclude(): mixed (1 active, 9 failed) → 1 substantive + 1 rollup, matches operator smoke-scan shape', () => {
  const portResults = [fakeActivePort(443)];
  const failedPorts = [
    { port: 465,  error: 'ECONNREFUSED' },
    { port: 587,  error: 'ECONNREFUSED' },
    { port: 636,  error: 'ECONNREFUSED' },
    { port: 853,  error: 'ECONNREFUSED' },
    { port: 993,  error: 'ECONNREFUSED' },
    { port: 995,  error: 'ECONNREFUSED' },
    { port: 8443, error: 'ECONNREFUSED' },
    { port: 8883, error: 'ECONNREFUSED' },
    { port: 9443, error: 'ECONNREFUSED' },
  ];

  const items = plugin.conclude({
    host: 'example.com',
    result: { portResults, failedPorts },
  });

  assert.equal(items.length, 2,
    'mixed shape must collapse from pre-fix 10 emissions to 2 (1 substantive + 1 rollup)');

  const substantive = items.find((i) => i.port === 443);
  const rollup = items.find((i) => i.port === 0);

  assert.ok(substantive, 'substantive finding for active port 443 present');
  assert.equal(substantive.status, 'open');
  assert.equal(substantive.service, 'https');

  assert.ok(rollup, 'rollup present');
  assert.equal(rollup.status, 'tls-not-responding');
  assert.equal(rollup.details.failedPorts.length, 9);
  assert.deepEqual(rollup.details.activePorts, [443]);
  assert.match(rollup.info, /9\/10/);
});

test('conclude(): result-shape defenses — missing portResults / failedPorts arrays do not throw', () => {
  // Defensive: pre-fix run() always set both arrays, but `Array.isArray(result?.X)`
  // guards keep conclude() safe if a future caller hands a malformed envelope.
  const items = plugin.conclude({ host: 'example.com', result: {} });
  assert.equal(items.length, 1);
  assert.equal(items[0].status, 'no_tls_detected');

  const items2 = plugin.conclude({ host: 'example.com', result: { portResults: null, failedPorts: null } });
  assert.equal(items2.length, 1);
  assert.equal(items2[0].status, 'no_tls_detected');
});

test('conclude(): substantive emission preserves per-port classification (status label transitions)', () => {
  const expired = fakeActivePort(443, {
    severity: 'critical',
    certificate: { ...fakeActivePort(443).certificate, expired: true, daysToExpiry: -3 },
  });
  const expiringCritical = fakeActivePort(8443, {
    severity: 'critical',
    certificate: { ...fakeActivePort(8443).certificate, daysToExpiry: 5 },
  });
  const expiringSoon = fakeActivePort(465, {
    severity: 'medium',
    certificate: { ...fakeActivePort(465).certificate, daysToExpiry: 20 },
  });

  const items = plugin.conclude({
    host: 'example.com',
    result: { portResults: [expired, expiringCritical, expiringSoon], failedPorts: [] },
  });

  assert.match(items[0].info, /^expired/);
  assert.match(items[1].info, /^expiring-critical/);
  assert.match(items[2].info, /^expiring-soon/);
});
