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
    'advancedCTEM', 'enhancedRedaction', 'proMCP',
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

// ── 0.32.11 — N3e: A CLAIM SURFACE WITH NO TEXT TO SWEEP ─────────────────────────
//
// Gate-3 measured this end to end. `license --capabilities` printed bare identifiers
// (`✓ airGapped`, `✓ pdfExport`), an assistant read the list, and — having no description to
// quote — EXPANDED the identifier: "air-gapped deployment" (the exact phrase withdrawn from
// the README, the skill, six web surfaces and the Marketplace listing) and "the output is
// auditor-consumable via pdfExport" (a capability that throws 'Not implemented').
//
// No text sweep can catch that, because at sweep time the claim exists only as an
// identifier. The countermeasure is to give the reader reviewed text to quote instead.
test('every capability carries a description — an identifier alone is a claim generator', () => {
  const missing = Object.entries(CAPABILITIES)
    .filter(([, v]) => !v.desc || typeof v.desc !== 'string' || v.desc.trim().length < 20)
    .map(([k]) => k);
  assert.deepEqual(missing, [],
    'these capabilities ship as bare identifiers, so a reader will expand the NAME: ' + missing.join(', '));
});

test('no capability description re-asserts a withdrawn claim', () => {
  // The register is the reviewed one. `airGapped` is the live trap: offline OPERATION ships;
  // "air-gapped deployment" (a delivery mechanism — an offline tarball, an install script)
  // was withdrawn. A description written by expanding the identifier would re-mint it.
  const WITHDRAWN = [
    /air[- ]?gapped (?:deployment|install|installation)/i,
    /offline (?:installation )?tarball/i,
    /\brfc[- ]?3161\b/i,
    /\bed25519\b/i,
    /verification engine|active (?:safe )?probe/i,
    /\bpdf export\b|\bbranded report/i,
  ];
  const hits = [];
  for (const [name, v] of Object.entries(CAPABILITIES)) {
    for (const re of WITHDRAWN) {
      if (re.test(v.desc || '')) hits.push(`${name}: ${re}`);
    }
  }
  assert.deepEqual(hits, [], 'a withdrawn claim was re-introduced through a capability description:\n' + hits.join('\n'));
  // POSITIVE CONTROL — the pattern list must be able to fire, or the zero above means nothing.
  assert.ok(WITHDRAWN.some((re) => re.test('supports air-gapped deployment via an offline tarball')),
    'the withdrawn-claim patterns match nothing — this assertion is vacuous');
});

test('pdfExport is gone from the registry', () => {
  assert.ok(!('pdfExport' in CAPABILITIES),
    'pdfExport is registered again — it has no reader, no implementation, and Gate-3 caught it ' +
    'being retold to a customer as a shipped capability');
});
