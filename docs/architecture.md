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
├── index.mjs                         # Programmatic API (exports: PluginManager, buildHtmlReport)
├── plugins/                          # CE scanner plugins (26)
│   ├── 040_tls_cert_auditor.mjs       # TLS Certificate & Cipher Auditor
│   ├── 050_tribe_health.mjs           # TRIBE v2 Neural API Security Probe
│   ├── 060_dns_sec_auditor.mjs        # DNS Security Auditor
│   ├── ping_checker.mjs
│   ├── ssh_scanner.mjs
│   ├── port_scanner.mjs
│   ├── ftp_banner_check.mjs
│   ├── host_up_check.mjs
│   ├── http_probe.mjs
│   ├── snmp_scanner.mjs
│   ├── result_concluder.mjs
│   ├── dns_scanner.mjs
│   ├── webapp_detector.mjs
│   ├── tls_scanner.mjs
│   ├── opensearch_scanner.mjs
│   ├── os_detector.mjs
│   ├── netbios_scanner.mjs
│   ├── sunrpc_scanner.mjs
│   ├── wsd_scanner.mjs
│   ├── arp_scanner.mjs
│   ├── mdns_scanner.mjs
│   ├── upnp_scanner.mjs
│   ├── dnssd-scanner.mjs
│   ├── llmnr_scanner.mjs
│   ├── db_scanner.mjs
│   └── syn_scanner.mjs
├── utils/
│   ├── capabilities.mjs              # Capability definitions + resolution
│   ├── license.mjs                   # JWT license validator (offline)
│   ├── plugin_discovery.mjs          # Multi-path plugin loader
│   ├── finding_schema.mjs            # Structured finding format
│   ├── finding_queue.mjs             # Finding queue manager
│   ├── prompts.mjs                   # AI prompt templates (basic)
│   ├── report_html.mjs              # AI report renderer
│   ├── raw_report_html.mjs          # Admin RAW HTML
│   ├── redact.mjs                   # Redaction pipeline
│   ├── scan_history.mjs             # JSONL scan history
│   ├── scheduler.mjs               # Basic CTEM scheduler
│   ├── delta_reporter.mjs          # Delta detection
│   ├── webhook.mjs                  # Webhook alerts + isSafeWebhookUrl
│   ├── attack_map.mjs              # Basic MITRE ATT&CK mapping
│   ├── sarif.mjs                   # SARIF output
│   ├── export_csv.mjs             # CSV export
│   ├── host_iterator.mjs          # CIDR expansion
│   ├── nvd_client.mjs             # NVD API client
│   ├── net_validation.mjs         # SSRF validation (isBlockedIp, isPrivateLike, resolveAndValidate)
│   ├── conclusion_utils.mjs       # Conclusion helper functions
│   ├── cpe.mjs                    # CPE string generation
│   ├── cve_validator.mjs          # CVE ID validation
│   ├── cvss.mjs                   # CVSS scoring utilities
│   ├── nvd_cache.mjs              # NVD response caching
│   ├── oui.mjs                    # OUI/MAC vendor lookup
│   ├── tool_version.mjs           # TOOL_VERSION/TOOL_NAME from package.json (npm-context-independent)
│   ├── output_dir.mjs             # resolveBaseOutDir — honors --out across all writers
│   ├── path_helpers.mjs           # toCleanPath — quote/whitespace strip for path-like strings
│   ├── report_md.mjs              # GitHub-flavored Markdown scan report
│   └── validate.mjs               # Pre-flight environment validation (`nsauditor-ai validate`)
├── config/
│   └── services.json               # Port definitions
└── tests/                           # 652 tests


REPOSITORY 2: nsauditor-ai-ee (Private, Proprietary)
PLUGIN PACKAGE — Pro/Enterprise capabilities as a peer dependency
────────────────────────────────────────────────────────────────
Private npm package (@nsasoft/nsauditor-ai-ee). Extends CE through
the plugin discovery system. Requires a valid license key to activate.
See the private EE repository for full documentation.
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
│  AI analysis via any provider (OpenAI/Claude/Ollama, basic prompts) │
│  Output generation: JSON, HTML, SARIF, CSV, Markdown             │
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
│  Pro AI Prompts: intelligence-enriched prompts (any provider)    │
│  Compliance Mapping: NIST/HIPAA/GDPR/PCI (Enterprise)            │
│  CTEM Integration: store to DB, delta detection, trends          │
│                                                                  │
│  Output: Risk report + AI report + compliance report + PDF       │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### 3.2 AI Provider Model (CRITICAL DISTINCTION)

**All AI providers (OpenAI, Claude, Ollama) work in ALL tiers.** CE users are not locked to Ollama. The API call is the same — what differs is the prompt content:

| Tier | AI Providers | Prompt Content |
|---|---|---|
| **CE** | OpenAI, Claude, Ollama | Basic scan summary: services, ports, versions |
| **Pro** | OpenAI, Claude, Ollama | Intelligence-enriched: scan data + CVE matches + MITRE techniques + risk scores + verification status |
| **Enterprise** | OpenAI, Claude, Ollama | Pro content + compliance context + cross-host correlation |

Higher tiers receive richer prompt content — CE sends a basic scan summary, while Pro and Enterprise include enriched findings with CVE matches, MITRE techniques, risk scores, and verification status.

### 3.3 Conditional Phase Execution

Phases are skipped when unnecessary, saving time and API costs:

| Condition | Phases Skipped |
|---|---|
| No license key | Phases 3, 4, 5 skipped (CE mode) |
| Pro license, no AI configured | Phase 5 AI reporting skipped |
| No findings in queue after Phase 3 | Phase 4 verification skipped entirely |
| No compliance frameworks configured | Phase 5 compliance mapping skipped |
| Agent finds nothing in its category | That agent's verifier is skipped |

### 3.4 Phase 1: Discovery (CE) — Detail

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
// IDs generated via uuid v4: generateFindingId() → "F-<uuid-v4>"

export const FindingSchema = {
  id: "string",             // Unique finding ID (e.g., "F-3d7e4b2a-91f0-4c3e-b8a6-7f2d5e9c1a04")
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
    cwe: "string[]",        // CWE IDs (e.g. ['CWE-326', 'CWE-200']) — optional
    owasp: "string[]",      // OWASP categories (e.g. ['A02:2021-Cryptographic Failures']) — optional
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
  aiAnalysis:         { tier: 'ce' },  // Any provider (OpenAI/Claude/Ollama), basic prompts
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
_hasCapabilities(plugin, capabilities) {
  if (!plugin.requiredCapabilities?.length) return true;
  const caps = capabilities ?? this._resolvedCapabilities ?? {};
  return plugin.requiredCapabilities.every(cap => Boolean(caps[cap]));
}
```

---

## 8. Licensing

Pro and Enterprise features require a valid license key set via `NSAUDITOR_LICENSE_KEY`. The key is a signed JWT verified offline by `utils/license.mjs` — no phone-home, no network calls.

Without a key (or with an expired/invalid key), all features gracefully degrade to Community Edition. CE is never crippled.

Purchase at [nsauditor.com/ai/pricing](https://www.nsauditor.com/ai/pricing). License key architecture is documented in the private repositories.

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
CLI → Plugins → Concluder → Basic Analysis → AI (basic prompts, any provider) → JSON/HTML/SARIF output
```

### Pro Flow (Pro key)

```
CLI → Plugins → Concluder → Parallel Agents → Finding Queue → Verifiers → Verified Queue → Risk Scoring → AI (intelligence-enriched prompts) → PDF
```

### Enterprise Flow (Enterprise key)

```
CLI → Docker Container → Plugins (CE+EE+Cloud+ZT) → Concluder → Parallel Agents → Finding Queue → Verifiers → Verified Queue → Risk Scoring → Compliance Mapping → Pro AI Report → Compliance Report → PDF → PostgreSQL CTEM
```

---

## 13. Security & Privacy

### 13.1 Zero Data Exfiltration Model

Nsasoft infrastructure handles ONLY: license keys, billing (via Stripe), email addresses, npm downloads. Customer scan data, findings, reports, network information, and credentials NEVER touch Nsasoft infrastructure.

### 13.2 SSRF Defense-in-Depth

SSRF protection is applied at every boundary where external addresses are accepted:

| Boundary | Guard | Scope |
|---|---|---|
| CLI scan entry (`scanSingleHost`) | `isBlockedIp()` + `resolveAndValidate()` | Blocks RFC 1918, loopback, fc00::/7, ::127.x, link-local, cloud metadata |
| MCP `scan_host` tool | `validateHost()` | Same ranges; separate code path |
| Webhook (`sendWebhook`) | `isSafeWebhookUrl()` + DNS resolution | Enforced inside the function — covers scheduler and programmatic callers |
| Plugin discovery | `realpathSync` + `isSafePath` | Symlink traversal blocked before `import()` |

`NSA_ALLOW_ALL_HOSTS=1` bypasses the CLI guard for legitimate local-network audits.

### 13.3 Legal Posture

Nsasoft US LLC is NOT a data processor, data controller, or business associate under any regulation. No DPAs, BAAs, or SOC 2 required for the scanning product.

---

## 14. Technology Stack

| Component | Technology |
|---|---|
| Runtime | Node.js 20+ (ES Modules, .mjs) |
| License | Signed JWT, offline validation |
| AI | OpenAI SDK + Anthropic SDK + Ollama |
| CE storage | JSONL files |
| MCP | @modelcontextprotocol/sdk, stdio transport |

---

**End of architecture.md (v2)**
