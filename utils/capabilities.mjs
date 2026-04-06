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
  verificationEngine: { tier: 'pro' },
  advancedCTEM:       { tier: 'pro' },
  enhancedRedaction:  { tier: 'pro' },
  proMCP:             { tier: 'pro' },
  pdfExport:          { tier: 'pro' },
  brandedReports:     { tier: 'pro' },

  // Enterprise
  cloudScanners:      { tier: 'enterprise' },
  zeroTrust:          { tier: 'enterprise' },
  complianceEngine:   { tier: 'enterprise' },
  zdePolicyEngine:    { tier: 'enterprise' },
  enterpriseCTEM:     { tier: 'enterprise' },
  enterpriseMCP:      { tier: 'enterprise' },
  usageMetering:      { tier: 'enterprise' },
  airGapped:          { tier: 'enterprise' },
  dockerIsolation:    { tier: 'enterprise' },
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
