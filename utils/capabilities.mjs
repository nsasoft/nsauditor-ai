// utils/capabilities.mjs

export const CAPABILITIES = {
  // CE (always available)
  coreScanning:       { tier: 'ce' },
  aiAnalysis:         { tier: 'ce' },  // Any provider (OpenAI/Claude/Ollama), basic prompts
  basicCTEM:          { tier: 'ce' },
  basicRedaction:     { tier: 'ce' },
  basicMCP:           { tier: 'ce' },
  findingQueue:       { tier: 'ce' },

  // Pro
  intelligenceEngine: { tier: 'pro' },
  riskScoring:        { tier: 'pro' },
  proAI:              { tier: 'pro' },
  analysisAgents:     { tier: 'pro' },
  advancedCTEM:       { tier: 'pro' },
  enhancedRedaction:  { tier: 'pro' },
  proMCP:             { tier: 'pro' },
  pdfExport:          { tier: 'pro' },

  // Enterprise
  cloudScanners:      { tier: 'enterprise' },
  zeroTrust:          { tier: 'enterprise' },
  complianceEngine:   { tier: 'enterprise' },
  enterpriseMCP:      { tier: 'enterprise' },
  airGapped:          { tier: 'enterprise' },
  // Removed 2026-07-21 (capability claim audit): verificationEngine / brandedReports /
  // usageMetering / dockerIsolation (no implementation) + zdePolicyEngine / enterpriseCTEM
  // (real cores ship + are claimed in prose; no distinct engine/datastore behind the flag).
  // Keep in lockstep with EE index.mjs EE_CAPABILITIES + license-manager keygen.mjs.
};

const TIER_CAPS = {
  ce:         new Set(['ce']),
  pro:        new Set(['ce', 'pro']),
  enterprise: new Set(['ce', 'pro', 'enterprise']),
};

export function resolveCapabilities(tier = 'ce') {
  const allowed = TIER_CAPS[tier] ?? TIER_CAPS.ce;
  const caps = {};
  for (const [key, def] of Object.entries(CAPABILITIES)) {
    caps[key] = allowed.has(def.tier);
  }
  return caps;
}

export function hasCapability(capabilities, cap) {
  return Boolean(capabilities?.[cap]);
}

// CE-0.1.30.3 reviewer M2 fold: derive the highest tier among a plugin's
// required capabilities. Used by `license --plugins` to render
// "✗ requires: <tier>" accurately when a plugin doesn't declare a `tier`
// field. Pre-fold the CLI fell back to `'pro'` for plugins like 021/022/023
// (no `tier` field, but require `cloudScanners` which is enterprise-gated)
// — which misled customers about what license they needed.
//
// Returns 'ce' / 'pro' / 'enterprise' (the highest tier among all required
// caps), or null when the plugin has no requiredCapabilities.
const _TIER_RANK = { ce: 0, pro: 1, enterprise: 2 };
const _RANK_TO_TIER = ['ce', 'pro', 'enterprise'];

export function inferRequiredTier(requiredCapabilities) {
  if (!Array.isArray(requiredCapabilities) || requiredCapabilities.length === 0) {
    return null;
  }
  let maxRank = 0;
  for (const cap of requiredCapabilities) {
    const def = CAPABILITIES[cap];
    if (!def) continue;
    const rank = _TIER_RANK[def.tier] ?? 0;
    if (rank > maxRank) maxRank = rank;
  }
  return _RANK_TO_TIER[maxRank];
}
