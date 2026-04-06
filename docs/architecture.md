# architecture.md (v2)

**NSAuditor AI — Architecture**
**Nsasoft US LLC**
**Privacy-First Security Intelligence Platform**
*AI-Assisted • Verified Vulnerabilities • Continuous Threat Exposure Management • Zero Data Exfiltration*

**Last updated:** April 2026

---

## 1. Vision & Principles

NSAuditor AI is a **self-hosted, AI-assisted security intelligence platform** that delivers:

> **Scan → Verify → Prioritize → Track → Act**
> **without ever requiring customer data to leave their infrastructure.**

**Core principles:**

- **Zero Data Exfiltration (ZDE)** — fully functional air-gapped; no customer data ever touches Nsasoft infrastructure
- **Local-First Intelligence** — all analysis runs inside the customer environment
- **Verified Findings** — vulnerabilities are confirmed through active probing, not just version matching. If it can't be verified, it's flagged as "potential" not "confirmed"
- **Explicit Opt-In** — any external call (AI APIs, NVD updates) must be manually enabled
- **Verifiable Security** — CE source is MIT and fully auditable; every external attempt is logged

---

## 2. Two-Repository Architecture

NSAuditor AI uses a **consumer pattern** — the EE repository is a plugin package that depends on the CE platform, not a fork.

### 2.1 Repository Structure

```
REPOSITORY 1: nsauditor-ai (Public, MIT)
THE PLATFORM — scanning engine, plugin loader, CLI, MCP server
────────────────────────────────────────────────────────────────
nsauditor-ai/
├── LICENSE                           # MIT Expat
├── CONTRIBUTING.md                   # DCO-based contribution guide
├── package.json                      # name: "nsauditor-ai"
├── cli.mjs                           # CLI entry point + orchestrator
├── plugin_manager.mjs                # Plugin lifecycle engine (v2)
├── mcp_server.mjs                    # MCP server (CE tools)
├── index.mjs                         # Programmatic API
├── plugins/                          # CE scanner plugins (20+)
│   ├── 001_ping_checker.mjs
│   ├── 002_ssh_scanner.mjs
│   ├── 003_port_scanner.mjs
│   ├── ...
│   └── 024_syn_scanner.mjs
├── utils/
│   ├── capabilities.mjs              # Capability definitions + resolution
│   ├── license.mjs                   # JWT license validator (offline)
│   ├── plugin_discovery.mjs          # Multi-path plugin loader
│   ├── finding_schema.mjs            # Structured finding format (NEW)
│   ├── finding_queue.mjs             # Finding queue manager (NEW)
│   ├── prompts.mjs                   # AI prompt templates (basic)
│   ├── report_html.mjs              # AI report renderer
│   ├── raw_report_html.mjs          # Admin RAW HTML
│   ├── redact.mjs                   # Redaction pipeline
│   ├── scan_history.mjs             # JSONL scan history
│   ├── scheduler.mjs               # Basic CTEM scheduler
│   ├── delta_reporter.mjs          # Delta detection
│   ├── webhook.mjs                  # Webhook alerts
│   ├── attack_map.mjs              # Basic MITRE ATT&CK mapping
│   ├── sarif.mjs                   # SARIF output
│   ├── export_csv.mjs             # CSV export
│   ├── host_iterator.mjs          # CIDR expansion
│   └── nvd_client.mjs             # NVD API client
├── config/
│   └── services.json               # Port definitions
└── tests/                           # 439+ tests


REPOSITORY 2: nsauditor-ai-ee (Private, Proprietary)
PLUGIN PACKAGE — EE plugins, intelligence engines, Pro AI
────────────────────────────────────────────────────────────────
nsauditor-ai-ee/
├── LICENSE                           # Nsasoft Proprietary
├── IP_ASSIGNMENT.md                  # CLA for contributors
├── package.json                      # peerDependencies: { "nsauditor-ai": "^2.x" }
├── index.mjs                         # EE registration + plugin export
├── plugins/
│   ├── 020_aws_cloud_scanner.mjs
│   ├── 021_gcp_cloud_scanner.mjs
│   ├── 022_azure_cloud_scanner.mjs
│   ├── 023_zero_trust_checker.mjs
│   └── 025_compliance_scanner.mjs
├── agents/                           # Parallel analysis agents (NEW)
│   ├── agent_runner.mjs             # Agent orchestrator
│   ├── auth_agent.mjs               # Authentication vulnerability analysis
│   ├── crypto_agent.mjs             # TLS/crypto weakness analysis
│   ├── config_agent.mjs             # Configuration audit agent
│   ├── service_agent.mjs            # Service-specific CVE analysis
│   └── exposure_agent.mjs           # Network exposure analysis
├── verifiers/                        # Verification probes (NEW)
│   ├── verifier_runner.mjs          # Verification orchestrator
│   ├── ssh_verifier.mjs             # SSH vulnerability verification
│   ├── tls_verifier.mjs             # TLS/SSL verification
│   ├── http_verifier.mjs            # HTTP vulnerability verification
│   ├── default_creds_verifier.mjs   # Default credential testing
│   └── service_verifier.mjs         # Generic service verification
├── utils/
│   ├── intelligence_engine.mjs      # CVE matching + MITRE mapping
│   ├── risk_scoring.mjs             # Priority scoring
│   ├── ctem_engine.mjs              # Advanced CTEM
│   ├── ai_proxy.mjs                 # Pro AI pipelines
│   ├── compliance_engine.mjs        # Framework mapping
│   ├── data_boundary.mjs            # ZDE policy engine
│   └── report_templates.mjs         # Branded reports + PDF
├── mcp/
│   ├── workflow_tools.mjs           # Enterprise MCP tools
│   └── metering.mjs                 # Usage tracking
├── feeds/
│   └── nvd_feed_processor.mjs       # Offline NVD feed import
└── tests/
```

### 2.2 Why Consumer Pattern

| Approach | Problem | NSAuditor AI |
|---|---|---|
| Monorepo (Onyx-style) | CE code leaks into EE; boundary policing | ✗ Rejected |
| Fork | Sync nightmare | ✗ Rejected |
| Consumer (peer dep) | Clean separation; independent versioning; marketplace-ready | ✓ Adopted |

---

## 3. Pipeline Architecture

### 3.1 Five-Phase Pipeline

NSAuditor AI operates as a phased pipeline with conditional execution. Phases 1–2 always run. Phases 3–5 are capability-gated and run only when the user's license tier enables them.

```
┌─────────────────────────────────────────────────────────────────┐
│                                                                  │
│  PHASE 1: DISCOVERY (CE — always runs)                           │
│  ──────────────────────────────────                              │
│  License validation → Plugin discovery → PluginManager.run()     │
│  27 scanner plugins execute in priority order with gating        │
│  Result Concluder fuses all outputs into unified view            │
│                                                                  │
│  Output: Concluded scan → {summary, host, services, evidence}   │
│                                                                  │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  PHASE 2: BASIC ANALYSIS (CE — always runs)                      │
│  ──────────────────────────────────                              │
│  Basic redaction pipeline                                        │
│  Basic MITRE ATT&CK tagging (per-plugin)                         │
│  Local AI analysis (Ollama, if configured)                       │
│  Output generation: JSON, HTML, SARIF, CSV                       │
│                                                                  │
│  Output: Admin RAW + AI reports + scan history entry             │
│                                                                  │
├────────────────────── CAPABILITY GATE ──────────────────────────┤
│                                                                  │
│  PHASE 3: INTELLIGENCE (Pro — requires license)                  │
│  ──────────────────────────────────                              │
│  3a. CVE Matching: CPE auto-generation → offline NVD lookup      │
│  3b. Parallel Analysis Agents (NEW):                             │
│      ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐       │
│      │  Auth     │ │  Crypto  │ │  Config  │ │  Service │       │
│      │  Agent    │ │  Agent   │ │  Agent   │ │  Agent   │       │
│      │          │ │          │ │          │ │          │       │
│      │ Weak     │ │ TLS 1.0  │ │ Default  │ │ CVE-     │       │
│      │ auth,    │ │ weak     │ │ configs, │ │ specific │       │
│      │ default  │ │ ciphers, │ │ exposed  │ │ probes   │       │
│      │ creds    │ │ expired  │ │ admin    │ │ per svc  │       │
│      │          │ │ certs    │ │ panels   │ │          │       │
│      └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘       │
│           │             │            │             │              │
│           └─────────────┴────────────┴─────────────┘              │
│                              │                                    │
│                              ▼                                    │
│                    ┌──────────────────┐                           │
│                    │  Finding Queue   │                           │
│                    │  (structured     │                           │
│                    │   JSON format)   │                           │
│                    └────────┬─────────┘                           │
│                              │                                    │
├──────────────────────────────┼───────────────────────────────────┤
│                              │                                    │
│  PHASE 4: VERIFICATION (Pro — conditional, NEW)                  │
│  ──────────────────────────────────                              │
│  For each finding in the queue:                                  │
│  - Run a SAFE verification probe against the target              │
│  - Classify as: VERIFIED | POTENTIAL | FALSE_POSITIVE            │
│  - Only VERIFIED and POTENTIAL findings advance                  │
│  - FALSE_POSITIVE findings are logged but not reported           │
│                                                                  │
│  "If it can't be verified, it's flagged, not confirmed."         │
│                                                                  │
│  Output: Verified finding queue + verification evidence          │
│                                                                  │
├────────────────────── CAPABILITY GATE ──────────────────────────┤
│                                                                  │
│  PHASE 5: SCORING, REPORTING & COMPLIANCE (Pro/Enterprise)       │
│  ──────────────────────────────────                              │
│  Risk Scoring Engine: severity × exploitability × impact         │
│  Pro AI Pipeline: executive reports via OpenAI/Claude            │
│  Compliance Mapping: NIST/HIPAA/GDPR/PCI (Enterprise)            │
│  CTEM Integration: store to DB, delta detection, trends          │
│                                                                  │
│  Output: Risk report + AI report + compliance report + PDF       │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### 3.2 Conditional Phase Execution

Phases are skipped when unnecessary, saving time and API costs:

| Condition | Phases Skipped |
|---|---|
| No license key | Phases 3, 4, 5 skipped (CE mode) |
| Pro license, no AI configured | Phase 5 AI reporting skipped |
| No findings in queue after Phase 3 | Phase 4 verification skipped entirely |
| No compliance frameworks configured | Phase 5 compliance mapping skipped |
| Agent finds nothing in its category | That agent's verifier is skipped |

### 3.3 Phase 1: Discovery (CE) — Detail

This is the existing NSAuditor scanning engine. No changes to the proven architecture:

```
License Validator → capabilities = {CE | Pro | Enterprise}
        │
Plugin Discovery → CE plugins + EE plugins (if installed) + custom path
        │
PluginManager.run()
        │
  For each plugin (priority-sorted):
    ├── Check requirements (host up, ports open, capabilities)
    ├── Execute plugin.run(host, port, opts)
    ├── Update shared context (hostUp, tcpOpen, udpOpen, os, mac)
    └── Merge results (multi-port coalescing)
        │
Result Concluder (plugin 008, priority 100000)
    ├── Import each plugin's conclude() adapter
    ├── Merge services by (protocol, port) with authority precedence
    ├── Select best OS (detector → hints → TTL fallback)
    └── Produce: { summary, host, services, evidence }
```

---

## 4. Structured Finding Format (NEW)

### 4.1 Finding Schema

All intelligence components — CVE matching, analysis agents, and verifiers — produce findings in a common structured format. This decouples analysis from reporting and enables pipeline composition.

```javascript
// utils/finding_schema.mjs (CE repo — shared format)

export const FindingSchema = {
  id: "string",             // Unique finding ID (e.g., "F-2026-0001")
  category: "enum",         // AUTH | CRYPTO | CONFIG | SERVICE | EXPOSURE | CVE
  status: "enum",           // UNVERIFIED | VERIFIED | POTENTIAL | FALSE_POSITIVE

  // What was found
  title: "string",          // "SSH server allows password authentication"
  description: "string",    // Detailed description
  severity: "enum",         // CRITICAL | HIGH | MEDIUM | LOW | INFO
  cvss: "number|null",      // CVSS v3.1 score if applicable

  // Where it was found
  target: {
    host: "string",         // IP or hostname
    port: "number",
    protocol: "string",     // tcp | udp
    service: "string",      // ssh | http | tls | ...
    program: "string|null", // OpenSSH | nginx | ...
    version: "string|null"  // 8.2p1 | 1.24.0 | ...
  },

  // Evidence
  evidence: {
    source: "string",       // Plugin or agent that found it
    cve: "string[]",        // CVE IDs if applicable
    mitre: "string[]",      // MITRE ATT&CK technique IDs
    raw: "object|null",     // Raw probe response / banner data
    verification: {         // Set by Phase 4 verifier
      method: "string",     // How it was verified
      result: "string",     // Probe response
      timestamp: "string",  // When verification ran
      safe: true            // Confirms probe was non-destructive
    }
  },

  // Remediation
  remediation: {
    summary: "string",      // "Disable password auth, use key-based"
    effort: "enum",         // LOW | MEDIUM | HIGH
    references: "string[]"  // URLs to advisories, docs
  },

  // Compliance mapping (Enterprise)
  compliance: {
    nist: "string[]",       // NIST CSF control IDs
    cis: "string[]",        // CIS Controls
    hipaa: "string[]",      // HIPAA Security Rule references
    pci: "string[]"         // PCI DSS requirements
  }
};
```

### 4.2 Finding Queue

The finding queue is a JSON array of findings that flows between phases:

```
Phase 3 (agents) → finding_queue.json → Phase 4 (verifiers) → verified_queue.json → Phase 5 (reporting)
```

```javascript
// utils/finding_queue.mjs (CE repo)

export class FindingQueue {
  constructor() { this.findings = []; }

  add(finding)           { /* validate against schema, assign ID, push */ }
  getByCategory(cat)     { /* filter by category */ }
  getByStatus(status)    { /* filter by verification status */ }
  getUnverified()        { /* findings awaiting verification */ }
  markVerified(id, evidence) { /* update status + verification evidence */ }
  markFalsePositive(id, reason) { /* update status, log reason */ }
  prioritize()           { /* sort by severity × exploitability */ }
  toJSON()               { /* serialize for file output */ }
  toSARIF()              { /* convert to SARIF 2.1.0 format */ }
}
```

---

## 5. Parallel Analysis Agents (NEW — Pro/EE)

### 5.1 Agent Architecture

Inspired by multi-agent pentesting architectures, the intelligence engine runs specialized analysis agents in parallel. Each agent focuses on a vulnerability category, analyzes the concluded scan results, and produces structured findings for its domain.

```javascript
// ee/agents/agent_runner.mjs

export async function runAnalysisAgents(conclusion, nvdData, capabilities) {
  const queue = new FindingQueue();

  // Define agents based on capabilities
  const agents = [
    { name: 'auth',     module: './auth_agent.mjs',     cap: 'intelligenceEngine' },
    { name: 'crypto',   module: './crypto_agent.mjs',    cap: 'intelligenceEngine' },
    { name: 'config',   module: './config_agent.mjs',    cap: 'intelligenceEngine' },
    { name: 'service',  module: './service_agent.mjs',   cap: 'intelligenceEngine' },
    { name: 'exposure', module: './exposure_agent.mjs',  cap: 'enterpriseMCP' },
  ];

  // Filter to enabled agents
  const enabled = agents.filter(a => capabilities[a.cap]);

  // Run all enabled agents in parallel
  const results = await Promise.allSettled(
    enabled.map(async (agent) => {
      const mod = await import(agent.module);
      return mod.analyze(conclusion, nvdData);
    })
  );

  // Collect findings from all agents
  for (const result of results) {
    if (result.status === 'fulfilled' && result.value) {
      for (const finding of result.value) {
        queue.add(finding);
      }
    }
  }

  return queue;
}
```

### 5.2 Agent Responsibilities

| Agent | Category | What It Analyzes |
|---|---|---|
| **Auth Agent** | AUTH | SSH password auth enabled, anonymous FTP, default credentials, missing auth on admin panels, weak auth protocols |
| **Crypto Agent** | CRYPTO | TLS versions < 1.2, weak cipher suites, expired certificates, self-signed certs in production, missing HSTS |
| **Config Agent** | CONFIG | Default SNMP communities, exposed admin interfaces, debug modes enabled, directory listing, verbose error pages |
| **Service Agent** | SERVICE | CVE matching by CPE, known-vulnerable service versions, end-of-life software, backport detection |
| **Exposure Agent** | EXPOSURE | Internet-facing services that should be internal, lateral movement paths, unnecessary open ports (Enterprise only) |

### 5.3 Agent Output

Each agent produces an array of findings conforming to the FindingSchema:

```javascript
// Example: crypto_agent.mjs output
[
  {
    category: "CRYPTO",
    status: "UNVERIFIED",
    title: "TLS 1.0 enabled on HTTPS service",
    severity: "MEDIUM",
    target: { host: "10.0.0.5", port: 443, protocol: "tcp", service: "https" },
    evidence: {
      source: "crypto_agent",
      mitre: ["T1557"],
      raw: { tlsVersions: ["TLSv1", "TLSv1.2", "TLSv1.3"] }
    },
    remediation: {
      summary: "Disable TLS 1.0 and 1.1. Enforce TLS 1.2+ minimum.",
      effort: "LOW",
      references: ["https://www.rfc-editor.org/rfc/rfc8996"]
    }
  }
]
```

---

## 6. Verification Engine (NEW — Pro/EE)

### 6.1 Philosophy: "Verified, Not Just Matched"

Traditional scanners match service versions against CVE databases. This produces false positives when vendors backport patches (e.g., Ubuntu's OpenSSH 8.2p1 may be patched for CVE-2023-38408 even though the version string still says 8.2p1).

NSAuditor AI's verification engine sends **safe, non-destructive probes** against findings to confirm they're actually exploitable. Findings that can't be verified are flagged as `POTENTIAL` rather than `VERIFIED`, giving the user honest confidence levels.

### 6.2 Verification Flow

```
Finding Queue (from Phase 3)
        │
        ▼
  For each UNVERIFIED finding:
        │
        ├── Select appropriate verifier (by category + service)
        │
        ├── Execute safe verification probe
        │     │
        │     ├── Probe succeeds → status = VERIFIED
        │     │     (evidence.verification populated)
        │     │
        │     ├── Probe inconclusive → status = POTENTIAL
        │     │     (finding reported with caveat)
        │     │
        │     └── Probe confirms NOT vulnerable → status = FALSE_POSITIVE
        │           (finding logged but not reported)
        │
        └── Rate limiting: max 1 probe per service per 2 seconds
            (prevent accidental DoS against target)
        │
        ▼
  Verified Finding Queue → Phase 5 (Reporting)
```

### 6.3 Verification Probe Examples

All probes are **safe and non-destructive** — they test for the vulnerability's preconditions without exploiting them:

| Finding | Verification Probe | What It Checks |
|---|---|---|
| SSH password auth enabled | Connect, check `SSH-2.0` banner for `password` in auth methods | KEXINIT response contains password auth |
| TLS 1.0 enabled | Attempt TLSv1.0 handshake with `minVersion=maxVersion` | Handshake succeeds = verified |
| Default SNMP community `public` | SNMP GET for sysDescr with community `public` | Response received = verified |
| Anonymous FTP access | FTP connect, `USER anonymous`, `PASS test@test` | `230` response = verified |
| HTTP directory listing | GET request to common paths (`/`, `/images/`) | HTML response contains directory index patterns |
| Expired TLS certificate | Connect, parse certificate `notAfter` field | Date comparison against current time |
| Missing HSTS header | HTTP GET, check response headers | `Strict-Transport-Security` header absent |
| CVE with known safe test | Send specific non-destructive probe per CVE advisory | Response matches vulnerable pattern |

### 6.4 Safety Constraints

```javascript
// ee/verifiers/verifier_runner.mjs

const SAFETY_RULES = {
  maxProbesPerHost: 50,          // Never exceed 50 probes to one host
  probeIntervalMs: 2000,         // Minimum 2 seconds between probes to same host
  timeoutMs: 5000,               // Individual probe timeout
  noPayloads: true,              // NEVER send exploit payloads
  noAuthentication: false,       // May test default creds (configurable)
  noDataModification: true,      // NEVER write, delete, or modify data
  noDoS: true,                   // NEVER send flood/amplification traffic
  abortOnError: false,           // Continue on individual probe failure
  logAllProbes: true,            // Every probe attempt is audit-logged
};
```

---

## 7. Capabilities System

### 7.1 Capability Definitions

```javascript
// utils/capabilities.mjs (CE repo)

export const CAPABILITIES = {
  // CE (always available)
  coreScanning:       { tier: 'ce' },
  localAI:            { tier: 'ce' },
  basicCTEM:          { tier: 'ce' },
  basicRedaction:     { tier: 'ce' },
  basicMCP:           { tier: 'ce' },
  findingQueue:       { tier: 'ce' },  // Schema is CE, agents are Pro

  // Pro
  intelligenceEngine: { tier: 'pro' },
  riskScoring:        { tier: 'pro' },
  proAI:              { tier: 'pro' },
  analysisAgents:     { tier: 'pro' },  // NEW: parallel agents
  verificationEngine: { tier: 'pro' },  // NEW: probe verification
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
  dockerIsolation:    { tier: 'enterprise' },  // NEW: per-scan containers
};
```

### 7.2 Plugin Capability Gating

```javascript
// In plugin_manager.mjs
_canRunPlugin(plugin, context) {
  if (!this._checkRequirements(plugin, context)) return false;
  if (plugin.requiredCapabilities) {
    for (const cap of plugin.requiredCapabilities) {
      if (!context.capabilities[cap]) return false;
    }
  }
  return true;
}
```

---

## 8. License Server & Activation

### 8.1 Architecture

```
Nsasoft Infrastructure:              Customer Infrastructure:
┌──────────────────────┐            ┌───────────────────────────┐
│ Stripe Billing       │            │ License Key (.env)         │
│     ↓                │            │     ↓                     │
│ JWT Generator        │            │ JWT Validator (offline)    │
│ (ES256 signing)      │  ── key →  │ (embedded public key)     │
│     ↓                │            │     ↓                     │
│ Email Delivery       │            │ context.capabilities      │
│                      │            │     ↓                     │
│ ⚠ NO SCAN DATA      │            │ Everything else runs here │
└──────────────────────┘            └───────────────────────────┘
```

### 8.2 JWT License Key Format

```javascript
{
  "alg": "ES256", "typ": "JWT", "kid": "nsauditor-2026-001",
  // Payload:
  "iss": "license.nsauditor.com",
  "sub": "org_abc123",
  "aud": "nsauditor-ai",
  "exp": 1743724800,
  "tier": "pro",              // "trial" | "pro" | "enterprise"
  "org": "Acme Corp",
  "seats": 1,
  "capabilities": ["intelligenceEngine", "riskScoring", "proAI", ...]
}
```

### 8.3 Validation

Offline — ES256 signature verified against public key embedded in npm package. No phone-home. Graceful degradation to CE on any failure.

---

## 9. Plugin Discovery

### 9.1 Multi-Path Loading

```javascript
// utils/plugin_discovery.mjs
async function discoverPlugins(baseDir) {
  const plugins = [];

  // Source 1: CE built-in (./plugins/)
  plugins.push(...await loadPluginsFromDir(join(baseDir, 'plugins'), 'ce'));

  // Source 2: EE package (@nsasoft/nsauditor-ai-ee)
  try {
    const eePkg = require.resolve('@nsasoft/nsauditor-ai-ee');
    const eeDir = join(eePkg, '..', 'plugins');
    if (existsSync(eeDir)) plugins.push(...await loadPluginsFromDir(eeDir, 'ee'));
  } catch { /* EE not installed — CE works standalone */ }

  // Source 3: Custom path (marketplace / user plugins)
  if (process.env.NSAUDITOR_PLUGIN_PATH) {
    for (const dir of process.env.NSAUDITOR_PLUGIN_PATH.split(':')) {
      if (existsSync(dir)) plugins.push(...await loadPluginsFromDir(resolve(dir), 'custom'));
    }
  }

  return plugins.sort((a, b) => (a.priority || 0) - (b.priority || 0));
}
```

---

## 10. Docker Isolation (NEW — Enterprise)

### 10.1 Per-Scan Container Isolation

For Enterprise deployments, each scan runs in an ephemeral Docker container. This provides scan isolation (one target can't affect another's scan), security (container is destroyed after use), and parallelism (concurrent scans without resource contention).

```
Enterprise CLI or MCP request
        │
        ▼
┌────────────────────────┐
│  Scan Orchestrator      │
│  Creates ephemeral      │
│  Docker container       │
│  per scan target        │
└──────────┬─────────────┘
           │
    ┌──────┴──────┐
    │             │
    ▼             ▼
┌─────────┐ ┌─────────┐
│ Scan    │ │ Scan    │
│ Target A│ │ Target B│  (parallel, isolated)
│ (ephem) │ │ (ephem) │
└────┬────┘ └────┬────┘
     │            │
     └─────┬──────┘
           ▼
┌────────────────────────┐
│  Results Aggregation    │
│  Merge finding queues   │
│  Cross-host risk rank   │
└────────────────────────┘
```

### 10.2 Container Spec

```yaml
# docker-compose.scan.yml (Enterprise)
services:
  scan:
    image: nsasoft/nsauditor-ai:enterprise
    read_only: true
    tmpfs: /tmp
    network_mode: host    # Needs access to target network
    environment:
      - NSAUDITOR_LICENSE_KEY=${NSAUDITOR_LICENSE_KEY}
      - SCAN_TARGET=${TARGET}
    volumes:
      - ./output:/output  # Results written here
    deploy:
      resources:
        limits:
          memory: 512M
          cpus: '1.0'
```

---

## 11. MCP Server Architecture

### 11.1 Tool Registry with Schema Validation

```javascript
// CE tools (always available)
const CE_TOOLS = [
  { name: 'scan_host',     schema: ScanHostSchema },
  { name: 'list_plugins',  schema: ListPluginsSchema },
];

// Pro tools (requires license)
const PRO_TOOLS = [
  { name: 'probe_service',       schema: ProbeServiceSchema },
  { name: 'get_vulnerabilities', schema: GetVulnsSchema },
  { name: 'risk_summary',        schema: RiskSummarySchema },
  { name: 'scan_compare',        schema: ScanCompareSchema },
  { name: 'save_finding',        schema: SaveFindingSchema },  // NEW: validated finding save
];

// Enterprise tools
const ENTERPRISE_TOOLS = [
  { name: 'start_assessment',    schema: AssessmentSchema },
  { name: 'prioritize_risks',    schema: PrioritizeSchema },
  { name: 'compliance_check',    schema: ComplianceSchema },
  { name: 'export_report',       schema: ExportSchema },
];
```

### 11.2 save_finding Tool (NEW)

The `save_finding` MCP tool validates findings against the FindingSchema before persisting. This ensures AI assistants using NSAuditor AI via MCP produce consistently structured output:

```javascript
// Validates finding structure, assigns ID, adds to queue
tools.register('save_finding', SaveFindingSchema, async (input) => {
  const errors = validateFinding(input);
  if (errors.length > 0) return { success: false, errors };

  const finding = { ...input, id: generateFindingId() };
  queue.add(finding);
  return { success: true, id: finding.id };
});
```

---

## 12. Data Flow Summary

### CE Flow (no key)

```
CLI → Plugins → Concluder → Basic Analysis → JSON/HTML/SARIF output
```

### Pro Flow (Pro key)

```
CLI → Plugins → Concluder → Parallel Agents → Finding Queue → Verifiers → Verified Queue → Risk Scoring → Pro AI Report → PDF
```

### Enterprise Flow (Enterprise key)

```
CLI → Docker Container → Plugins (CE+EE+Cloud+ZT) → Concluder → Parallel Agents → Finding Queue → Verifiers → Verified Queue → Risk Scoring → Compliance Mapping → Pro AI Report → Compliance Report → PDF → PostgreSQL CTEM
```

---

## 13. Security & Privacy

### 13.1 Zero Data Exfiltration Model

Nsasoft infrastructure handles ONLY: license keys, billing (via Stripe), email addresses, npm downloads. Customer scan data, findings, reports, network information, and credentials NEVER touch Nsasoft infrastructure.

### 13.2 Legal Posture

Nsasoft US LLC is NOT a data processor, data controller, or business associate under any regulation. No DPAs, BAAs, or SOC 2 required for the scanning product.

---

## 14. Technology Stack

| Component | Technology |
|---|---|
| Runtime | Node.js 20+ (ES Modules, .mjs) |
| License | ECDSA P-256 (ES256) JWT, offline validation |
| AI | OpenAI SDK + Anthropic SDK + Ollama |
| CE storage | JSONL files |
| Pro storage | SQLite (better-sqlite3) |
| EE storage | PostgreSQL (pg) |
| MCP | @modelcontextprotocol/sdk, stdio transport |
| Billing | Stripe |
| License server | Node.js + Express (Railway/Vercel) |
| EE containers | Docker (per-scan isolation) |

---

**End of architecture.md (v2)**
