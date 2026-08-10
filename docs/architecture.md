# architecture.md (v2)

**NSAuditor AI — Architecture**
**Nsasoft US LLC**
**Privacy-First Security Intelligence Platform**
*AI-Assisted • Offline CVE Matching • Continuous Threat Exposure Management • Zero Data Exfiltration*

**Last updated:** 2026-08-07 — capability-status sweep. §6, §10 and §11.2 are stamped
**WITHDRAWN**: they documented designs that were never built, and each stamp carries the
measurement it rests on rather than an assertion.

---

## 1. Vision & Principles

NSAuditor AI is a **self-hosted, AI-assisted security intelligence platform** that delivers:

> **Scan → Analyze → Prioritize → Track → Act**
> **without ever requiring customer data to leave their infrastructure.**

**Core principles:**

- **Zero Data Exfiltration (ZDE)** — no customer data ever touches Nsasoft infrastructure; air-gappable once configured for it (a default run queries the public NVD CVE API — see the egress register in the EE `docs/architecture.md` §14.1.1 for the full enumeration)
- **Local-First Intelligence** — all analysis runs inside the customer environment
- **Conservatively Labelled Findings** — every finding is emitted with status `UNVERIFIED` and is labelled from banner-grab and configuration evidence, never from an exploit attempt. The re-probing layer that would promote a finding past `UNVERIFIED` is **WITHDRAWN** (see §6) — nothing in either package runs it, so read a finding as "matched", not as "confirmed"
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
├── plugins/                          # CE scanner plugins (27)
│   ├── 040_tls_cert_auditor.mjs       # TLS Certificate & Cipher Auditor
│   ├── 050_tribe_health.mjs           # TRIBE v2 Neural API Security Probe
│   ├── 060_dns_sec_auditor.mjs        # DNS Security Auditor
│   ├── mcp_scanner.mjs                # MCP Scanner (id 070) — detects MCP servers + audits per research checklist
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
└── tests/                           # 734 tests


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
│  PHASE 4: VERIFICATION — WITHDRAWN at EE 0.32.7, never shipped   │
│  ──────────────────────────────────                              │
│  WITHDRAWN: no code runs a verification probe against a target.  │
│  The status field and its four values ship and are real; what    │
│  was withdrawn is the layer that would POPULATE them, so every   │
│  finding leaves Phase 3 stamped UNVERIFIED and is never          │
│  re-stamped. Nothing is filtered out here and nothing advances    │
│  differently. §6 keeps the design as a record.                   │
│                                                                  │
│  Output: the Phase 3 finding queue, unchanged                    │
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

## 6. Verification Engine — WITHDRAWN at EE 0.32.7 (design record)

> ⚠️ **WITHDRAWN. Every paragraph below describes a design that was never built**, and it is
> kept — stamped rather than deleted — because a reader arriving from a search engine lands on
> a subsection, not on this header, and would otherwise read the design as shipped code. That
> is exactly how the capability survived four releases in the agent-skill after the flag was
> removed. Measured 2026-08-07: the EE `verifiers/` modules (`verifier_runner.mjs`,
> `tls_verifier.mjs`, `ssh_verifier.mjs`, `http_verifier.mjs`, `service_verifier.mjs`,
> `default_creds_verifier.mjs`) have **zero import statements anywhere in either repo** — the
> only mention outside the modules themselves is one comment line in `utils/ctem_engine.mjs`.
> The `verificationEngine` capability flag was deleted from `utils/capabilities.mjs` on
> 2026-07-21 for the same reason. What ships is the finding-status FIELD: real, and permanently
> reading `UNVERIFIED`.

### 6.1 Philosophy: "Verified, Not Just Matched" — the goal, not the state

Traditional scanners match service versions against CVE databases. This produces false positives when vendors backport patches (e.g., Ubuntu's OpenSSH 8.2p1 may be patched for CVE-2023-38408 even though the version string still says 8.2p1). **That problem is real and NSAuditor AI does not solve it** — findings are labelled from banner-grab and configuration evidence and stamped `UNVERIFIED`.

**WITHDRAWN — the following describes the intended design only.** The verification engine was to send safe non-destructive probes against findings to confirm they are actually exploitable; nothing does. No finding is ever re-classified after Phase 3.

### 6.2 Verification Flow (as designed; never executed)

```
Finding Queue (from Phase 3)
        │
        ▼
  For each UNVERIFIED finding:
        │
        ├── Select appropriate verifier (by category + service)
        │
        ├── Execute safe verification probe   ← WITHDRAWN: no code does this
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

### 6.3 Verification Probe Examples — WITHDRAWN, none of these ever ran

**WITHDRAWN.** The table is the design's probe catalogue and no entry in it is implemented or
called; it is retained so that a future implementation has the safety envelope it was specified
against. Probes were to be safe and non-destructive — testing for a vulnerability's
preconditions without exploiting them:

| Finding | Probe that was DESIGNED (WITHDRAWN — never ran) | What It Would Have Checked |
|---|---|---|
| SSH password auth enabled | Connect, check `SSH-2.0` banner for `password` in auth methods | KEXINIT response contains password auth |
| TLS 1.0 enabled | Attempt TLSv1.0 handshake with `minVersion=maxVersion` | Handshake succeeds = verified |
| Default SNMP community `public` | SNMP GET for sysDescr with community `public` | Response received = verified |
| Anonymous FTP access | FTP connect, `USER anonymous`, `PASS test@test` | `230` response = verified |
| HTTP directory listing | GET request to common paths (`/`, `/images/`) | HTML response contains directory index patterns |
| Expired TLS certificate | Connect, parse certificate `notAfter` field | Date comparison against current time |
| Missing HSTS header | HTTP GET, check response headers | `Strict-Transport-Security` header absent |
| CVE with known safe test | Send specific non-destructive probe per CVE advisory | Response matches vulnerable pattern |

### 6.4 Safety Constraints (of the withdrawn design)

**WITHDRAWN.** The path below was `ee/verifiers/verifier_runner.mjs`, which has never existed;
the module that does exist is `verifiers/verifier_runner.mjs` in the EE package, and it has zero
importers. Nothing reads `SAFETY_RULES`.

```javascript
// verifiers/verifier_runner.mjs (EE package) — module exists, ZERO importers

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
  analysisAgents:     { tier: 'pro' },  // parallel agents
  advancedCTEM:       { tier: 'pro' },
  enhancedRedaction:  { tier: 'pro' },
  proMCP:             { tier: 'pro' },

  // Enterprise
  cloudScanners:      { tier: 'enterprise' },
  zeroTrust:          { tier: 'enterprise' },
  complianceEngine:   { tier: 'enterprise' },
  enterpriseMCP:      { tier: 'enterprise' },
  airGapped:          { tier: 'enterprise' },
  // Capability flags are printed to licensees (`license --capabilities`) and must name
  // only capabilities that SHIP. Six were removed 2026-07-21 (capability-claim audit):
  // verificationEngine / brandedReports / usageMetering / dockerIsolation had no
  // implementation; zdePolicyEngine / enterpriseCTEM named no distinct engine or
  // datastore (their real cores ship and are described in prose).
  // A seventh followed at 0.32.11: pdfExport is WITHDRAWN — it was registered and
  // minted into licences while renderBrandedReport() threw 'Not implemented' and no
  // code read the flag. Its absence is pinned by tests/capabilities.test.mjs.
  // Shipped set, DERIVED from utils/capabilities.mjs rather than transcribed:
  // 7 pro + 5 enterprise (+6 CE = 18 on an Enterprise license). Re-derive with
  //   node -e "import('./utils/capabilities.mjs').then(m=>{const t={};for(const[k,v]of
  //   Object.entries(m.CAPABILITIES))(t[v.tier]??=[]).push(k);console.log(t)})"
  // This doc mirrors utils/capabilities.mjs — keep both in lockstep with the EE +
  // licensing keygens.
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

## 10. Docker Isolation — WITHDRAWN (design record)

> ⚠️ **WITHDRAWN. Per-scan container isolation was never built.** The `dockerIsolation`
> capability flag was deleted from `utils/capabilities.mjs` on 2026-07-21 in the same audit that
> removed `verificationEngine`, for the same reason: no implementation. Measured 2026-08-07: no
> `docker-compose.scan.yml` exists in either repo, and neither repo contains a container
> orchestrator (`dockerode`, `docker run` or `createContainer` appear in zero `.mjs` files). A
> scan runs in the process you started it in. Stamped rather than deleted, because a search
> engine delivers §10.2 without this header.
>
> ONE container image is real, and it is a different thing: the AWS Marketplace image, which
> bakes CE + EE and is pushed by `deploy/marketplace/build-scan-push.sh` to the
> Marketplace-provisioned ECR repository, tagged with the EE version.

### 10.1 Per-Scan Container Isolation (as designed; never built)

For Enterprise deployments, each scan was to run in an ephemeral Docker container. This would provide scan isolation (one target can't affect another's scan), security (container is destroyed after use), and parallelism (concurrent scans without resource contention).

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

### 10.2 Container Spec — WITHDRAWN, this file does not exist

**WITHDRAWN.** No pipeline produces `nsasoft/nsauditor-ai:enterprise` and no such compose file
ships; the tag below is illustrative and was never published. The real image tag is
`${REPO_URI}:${VERSION}` against the Marketplace ECR repository — see the stamp on §10.

```yaml
# docker-compose.scan.yml — WITHDRAWN example, not a shipped file
services:
  scan:
    image: <marketplace-ecr-repo>:<EE version>   # WITHDRAWN illustration only
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

> ⚠️ **This section previously showed a `CE_TOOLS` / `PRO_TOOLS` / `ENTERPRISE_TOOLS`
> registry that does not exist**, naming seven tools that are not registered anywhere.
> It read as shipped code because it was written as shipped code. What follows is derived
> from `mcp_server.mjs`'s exported `TOOLS` array and its dispatch-layer gates.

There is **one** registry, not three. All seven tools are listed to every client; the
licence gate is applied at DISPATCH, so an unlicensed call returns a `🔒` refusal naming
the required tier rather than an empty result:

```javascript
// mcp_server.mjs — one exported array, served verbatim by the ListTools handler
export const TOOLS = [
  { name: 'scan_host',          /* … */ },   // every tier
  { name: 'scan_cloud',         /* … */ },   //   gated: Enterprise
  { name: 'get_findings',       /* … */ },   //   gated: Enterprise
  { name: 'compliance_matrix',  /* … */ },   // every tier
  { name: 'probe_service',      /* … */ },   //   gated: Pro
  { name: 'get_vulnerabilities',/* … */ },   //   gated: Pro
  { name: 'list_plugins',       /* … */ },   // every tier
];

// …and the gate is in the CallTool handler, not in the listing:
if (name === 'probe_service' || name === 'get_vulnerabilities') { /* requireProCapability */ }
if (['scan_cloud', 'get_findings'].includes(name))              { /* requireEnterpriseCapability */ }
```

Why the listing is not filtered: a tool that vanishes from the list is indistinguishable
from a tool that does not exist, so an assistant simply routes around it and the operator
never learns a licence would have answered their question. A refusal that names the tier
is the actionable form.

### 11.2 save_finding Tool — WITHDRAWN (never registered)

> ⚠️ **WITHDRAWN.** This section previously showed a `tools.register('save_finding', …)` call
> as shipped code. It is WITHDRAWN and always was: `save_finding` appears in **zero `.mjs`
> files in this repo** (measured 2026-08-07), and there is no `tools.register` API — the real
> registry is the single exported `TOOLS` array in §11.1, whose seven members are the complete
> set an MCP client can call. WITHDRAWN on the same evidence: `risk_summary` and `scan_compare`
> are implemented in an EE `registerProTools` that has no caller in either repo and that calls
> `server.tool()` — a method the `Server` object CE constructs does not have. Implemented and
> unreachable is still unreachable.
>
> The code sample is removed rather than stamped in place, because it was fabricated: it named
> an API (`tools.register`, `SaveFindingSchema`, `validateFinding`, `generateFindingId`) that
> has never existed, so there is nothing for a future implementer to inherit. What *is* worth
> keeping is the requirement it was written for — an MCP write path should validate against the
> finding schema before persisting — and that is recorded here, not shown as code.
>
> To restore: register the tool on the shipped MCP server, validate it from Claude Desktop, and
> remove its name from `scripts/claim_surface_patterns.mjs`'s `phantom-mcp-tools` pattern in the
> **same commit** that wires it.

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
