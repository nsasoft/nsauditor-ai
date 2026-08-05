// utils/capabilities.mjs

/**
 * The capability registry.
 *
 * ⚠️ EVERY FLAG CARRIES A `desc`, AND THAT IS A CLAIM-HONESTY MECHANISM, NOT DOCUMENTATION.
 * Until 0.32.11 the product shipped bare flag NAMES: `license --capabilities` printed
 * `✓ airGapped` and nothing else. An assistant asked what the product does then EXPANDS the
 * identifier — and "airGapped" expands to "air-gapped deployment", the exact phrase withdrawn
 * from the README, the skill, six web surfaces and the Marketplace listing. That is a claim
 * surface with NO TEXT TO SWEEP: at sweep time the claim exists only as an identifier, so no
 * gate can see it, and it is regenerated fresh on every reading. A `desc` written in the
 * reviewed register is what a reader quotes INSTEAD of inventing one — Gate-3 prompt 7
 * demonstrated the converse, where reviewed text survived retelling verbatim.
 *
 * So: when adding a flag, write its `desc` in the register the claim guards allow, and say
 * what the code DOES, not what the name suggests.
 *
 * Keep in lockstep with EE index.mjs EE_CAPABILITIES + license-manager keygen.mjs +
 * licensing/api.sls.licensing keygenclass.js (the DEPLOYED signer — a flag left there is
 * still minted into customer JWTs, which is what an assistant actually reads).
 */
export const CAPABILITIES = {
  // CE (always available)
  coreScanning:       { tier: 'ce', desc: 'Network and host scanning plugins (ports, protocols, TLS, OS fingerprinting).' },
  aiAnalysis:         { tier: 'ce', desc: 'AI analysis of scan output via any configured provider (OpenAI / Claude / Ollama), basic prompts.' },
  basicCTEM:          { tier: 'ce', desc: 'Continuous watch mode: interval re-scan, delta report, webhook alert. An ALERTING loop — it adds no evidence retention or cross-run aggregation.' },
  basicRedaction:     { tier: 'ce', desc: 'Redaction of secrets and identifiers from AI prompt payloads before egress.' },
  basicMCP:           { tier: 'ce', desc: 'MCP tools scan_host and list_plugins.' },
  findingQueue:       { tier: 'ce', desc: 'Structured finding queue written alongside the scan output.' },

  // Pro
  intelligenceEngine: { tier: 'pro', desc: 'Offline CPE generation and NVD CVE matching against detected services.' },
  riskScoring:        { tier: 'pro', desc: 'Risk weighting applied to intelligence-engine findings.' },
  proAI:              { tier: 'pro', desc: 'Pro analysis prompts (deeper context than the CE prompt set).' },
  analysisAgents:     { tier: 'pro', desc: 'Auth, crypto, config and service analysis agents over scan evidence. Analysis of collected evidence — NOT active exploitation probes.' },
  advancedCTEM:       { tier: 'pro', desc: 'Extended scan-history retention beyond the CE window.' },
  enhancedRedaction:  { tier: 'pro', desc: 'Additional redaction patterns over the CE set for AI prompt payloads.' },
  proMCP:             { tier: 'pro', desc: 'MCP tools probe_service and get_vulnerabilities.' },

  // Enterprise
  cloudScanners:      { tier: 'enterprise', desc: 'AWS / Azure / GCP cloud posture audit plugins (Enterprise plugin pack).' },
  zeroTrust:          { tier: 'enterprise', desc: 'Zero-trust posture checks over collected identity and network evidence.' },
  complianceEngine:   { tier: 'enterprise', desc: 'Maps findings to SOC 2, HIPAA, NIST CSF 2.0, PCI DSS, ISO 27001, CIS v8 and GDPR Art. 32 controls, and renders the report artifacts.' },
  enterpriseMCP:      { tier: 'enterprise', desc: 'MCP tools scan_cloud and get_findings.' },
  airGapped:          { tier: 'enterprise', desc: 'Offline OPERATION: licence validation is local (ES256 against an embedded key, no callback, no phone-home) and CVE matching runs against a local feed. This describes how the software RUNS, not how it is delivered or installed.' },
  // Removed 2026-07-21 (capability claim audit): verificationEngine / brandedReports /
  // usageMetering / dockerIsolation (no implementation) + zdePolicyEngine / enterpriseCTEM
  // (real cores ship + are claimed in prose; no distinct engine/datastore behind the flag).
  // Removed 2026-08-05 (0.32.11): pdfExport — registered, minted into licences and printed
  // to customers as `✓ pdfExport`, while renderBrandedReport() throws 'Not implemented',
  // puppeteer is not a dependency, and NO code read the flag. Gate-3 caught it generating a
  // claim end to end: an assistant read the flag list and wrote "the output is auditor-
  // consumable via pdfExport" into a customer-facing document. HTML reports remain
  // printable from a browser; that is the browser's capability, not a licensed one.
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
