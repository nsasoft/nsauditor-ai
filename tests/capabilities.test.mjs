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
  //
  // ⚠️ EACH ENTRY CARRIES ITS OWN PROBE, and every probe is asserted to fire (added at review).
  // The first version hand-wrote six patterns and gave them ONE positive control, which
  // exercised two of the six — so four could have been dead and the clean result would have
  // read identically. This is a hand-written twin of EE scripts/claim_surface_patterns.mjs;
  // when a family is withdrawn THERE, port it HERE, because these descriptions are printed to
  // customers by `license --capabilities` and no other guard reads them (EE's honesty test is
  // scoped to six hand-listed docs, and gate:claims sweeps web roots).
  const WITHDRAWN = [
    { id: 'airgap-deployment', re: /air[- ]?gapped (?:deployment|install|installation|delivery)/i,
      probe: 'supports air-gapped deployment' },
    { id: 'offline-install-tarball', re: /offline (?:installation |install )?tarball/i,
      probe: 'ships an offline installation tarball' },
    { id: 'install-script', re: /air[- ]?gapped install script|offline install script/i,
      probe: 'an air-gapped install script is provided' },
    { id: 'rfc-3161', re: /\brfc[- ]?3161\b/i, probe: 'RFC 3161 timestamps on every report' },
    { id: 'trusted-timestamp', re: /trusted timestamp|timestamp authority|\bTSA\b/i,
      probe: 'trusted timestamping via a Time-Stamp Authority' },
    { id: 'ed25519', re: /\bed25519\b/i, probe: 'Ed25519 attestation of every artifact' },
    { id: 'suppression-signing', re: /suppression[ -](?:signing|signature)|signed suppressions?\b/i,
      probe: 'cryptographically signed suppressions' },
    { id: 'clock-attestation', re: /(?:NTP )?clock attestation/i, probe: 'NTP clock attestation on every report' },
    { id: 'verification-engine', re: /verification engine|verification probe|active (?:safe )?probe|probe[- ]confirmed/i,
      probe: 'runs a safe verification probe per finding' },
    { id: 'branded-reports', re: /branded report|\bpdf export\b|white[- ]?label/i,
      probe: 'branded reports and PDF export' },
    { id: 'docker-isolation', re: /docker isolation|per[- ]scan (?:container|isolation)|read-only filesystem/i,
      probe: 'per-scan Docker isolation' },
    { id: 'nvd-feed-bundles', re: /monthly (?:NVD )?feed bundles?|feed bundle/i,
      probe: 'monthly NVD feed bundles' },
    { id: 'arm64-image', re: /\barm64\b/i, probe: 'arm64 images are published' },
    { id: 'multi-tenant', re: /multi[- ]tenant|native push|live sync/i,
      probe: 'multi-tenant safe with native push and live sync' },
  ];

  // POSITIVE CONTROL, PER ENTRY. A pattern that matches nothing is an exemption nobody
  // exercises, and that is how a real claim gets waved through later.
  const dead = WITHDRAWN.filter((w) => !w.re.test(w.probe)).map((w) => w.id);
  assert.deepEqual(dead, [], 'these withdrawn-claim patterns match their own probe: ' + dead.join(', '));

  const hits = [];
  for (const [name, v] of Object.entries(CAPABILITIES)) {
    for (const w of WITHDRAWN) {
      if (w.re.test(v.desc || '')) hits.push(`${name} {${w.id}}: ${v.desc}`);
    }
  }
  assert.deepEqual(hits, [],
    'a withdrawn claim was re-introduced through a capability description:\n' + hits.join('\n'));
});

test('pdfExport is gone from the registry', () => {
  assert.ok(!('pdfExport' in CAPABILITIES),
    'pdfExport is registered again — it has no reader, no implementation, and Gate-3 caught it ' +
    'being retold to a customer as a shipped capability');
});
