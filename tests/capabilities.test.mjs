import { test } from 'node:test';
import assert from 'node:assert/strict';
import { resolveCapabilities, hasCapability, CAPABILITIES } from '../utils/capabilities.mjs';

test('CE tier enables only CE capabilities', () => {
  const caps = resolveCapabilities('ce');
  assert.ok(caps.coreScanning, 'coreScanning enabled in CE');
  assert.ok(caps.basicMCP, 'basicMCP enabled in CE');
  assert.ok(!caps.intelligenceEngine, 'intelligenceEngine disabled in CE');
  assert.ok(!caps.cloudScanners, 'cloudScanners disabled in CE');
});

test('Pro tier enables CE + Pro capabilities', () => {
  const caps = resolveCapabilities('pro');
  assert.ok(caps.coreScanning);
  assert.ok(caps.intelligenceEngine);
  assert.ok(caps.riskScoring);
  assert.ok(!caps.cloudScanners, 'cloudScanners disabled in Pro');
});

test('Enterprise tier enables all capabilities', () => {
  const caps = resolveCapabilities('enterprise');
  assert.ok(caps.coreScanning);
  assert.ok(caps.cloudScanners);
  assert.ok(caps.zeroTrust);
  assert.ok(caps.enterpriseMCP);
});

test('unknown tier falls back to CE', () => {
  const caps = resolveCapabilities('unknown_tier');
  assert.ok(caps.coreScanning);
  assert.ok(!caps.intelligenceEngine);
});

test('hasCapability returns false for missing cap', () => {
  const caps = resolveCapabilities('ce');
  assert.ok(!hasCapability(caps, 'intelligenceEngine'));
  assert.ok(hasCapability(caps, 'coreScanning'));
});

test('globalThis.redactSensitiveForAI is ignored on CE tier (enhancedRedaction absent)', () => {
  let called = false;
  const orig = globalThis.redactSensitiveForAI;
  globalThis.redactSensitiveForAI = () => { called = true; return {}; };
  try {
    const caps = resolveCapabilities('ce');
    const allowed = hasCapability(caps, 'enhancedRedaction');
    assert.equal(allowed, false, 'CE tier must not have enhancedRedaction');
    // Simulate the gate: if !allowed, the globalThis fn must not be called
    if (allowed && typeof globalThis.redactSensitiveForAI === 'function') {
      globalThis.redactSensitiveForAI();
    }
    assert.equal(called, false, 'globalThis.redactSensitiveForAI must not be called on CE');
  } finally {
    globalThis.redactSensitiveForAI = orig;
  }
});

test('globalThis.redactSensitiveForAI is allowed on Pro tier (enhancedRedaction present)', () => {
  const caps = resolveCapabilities('pro');
  assert.equal(hasCapability(caps, 'enhancedRedaction'), true, 'Pro tier must have enhancedRedaction');
});

test('globalThis.redactSensitiveForAI is allowed on Enterprise tier (enhancedRedaction present)', () => {
  const caps = resolveCapabilities('enterprise');
  assert.equal(hasCapability(caps, 'enhancedRedaction'), true, 'Enterprise tier must have enhancedRedaction');
});

test('CAPABILITIES covers all expected keys', () => {
  const expected = [
    'coreScanning', 'aiAnalysis', 'basicCTEM', 'basicRedaction', 'basicMCP', 'findingQueue',
    'intelligenceEngine', 'riskScoring', 'proAI', 'analysisAgents',
    'advancedCTEM', 'enhancedRedaction', 'proMCP', 'pdfExport',
    'cloudScanners', 'zeroTrust', 'complianceEngine', 'enterpriseMCP', 'airGapped',
  ];
  for (const key of expected) {
    assert.ok(key in CAPABILITIES, `CAPABILITIES missing: ${key}`);
  }

  // Removed 2026-07-21 (capability claim audit): these named flags no longer exist —
  // verificationEngine/brandedReports/usageMetering/dockerIsolation had no implementation,
  // and zdePolicyEngine/enterpriseCTEM had no distinct engine/datastore behind the name
  // (their real cores ship + are claimed in prose). Assert they are GONE so the map cannot
  // silently regain a phantom flag.
  for (const key of ['verificationEngine', 'brandedReports', 'usageMetering', 'dockerIsolation', 'zdePolicyEngine', 'enterpriseCTEM']) {
    assert.ok(!(key in CAPABILITIES), `CAPABILITIES must not re-add removed phantom flag: ${key}`);
  }
});
