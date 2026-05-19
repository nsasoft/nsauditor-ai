# NSAuditor AI

**Security Intelligence Without Data Exposure.**

A modular, AI-assisted network security audit platform that scans, understands, prioritizes, and tracks vulnerabilities — without ever requiring your data to leave your infrastructure.

[![npm](https://img.shields.io/npm/v/nsauditor-ai.svg)](https://www.npmjs.com/package/nsauditor-ai)
[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Node.js 20+](https://img.shields.io/badge/node-20%2B-green.svg)](https://nodejs.org)
[![Tests](https://img.shields.io/badge/tests-925%20passing-brightgreen.svg)](#tests)

---

NSAuditor AI is the open-source core of a privacy-first security intelligence platform built by [Nsasoft US LLC](https://www.nsauditor.com/ai/). It orchestrates 27 specialized scanning plugins against target hosts, fuses their results through an intelligent concluder, and optionally produces AI-powered vulnerability reports — all running entirely on your machine.

**Zero Data Exfiltration by design.** NSAuditor AI works fully offline. AI analysis, CVE correlation, and continuous monitoring all happen locally. External calls (to AI APIs, NVD, etc.) are opt-in and use your own API keys. We never see your scan data.

## What's New

- **CE 0.1.63** (current) — paired with **EE 0.6.9** (May 2026). **23 enterprise plugins** across AWS / Azure / GCP, mapped to 10 fully-covered + 4 partial AICPA TSC controls. Cycle is a patch-level EE-RT.21 v2 R2 reviewer-deferred-items cleanup for plugin 1024 GCP Cloud Storage Auditor: Appendix A "Cloud Bucket Exposure Attestation" extended from AWS-S3-only to multi-cloud (AWS S3 + GCS); evidence-gap emissions get explicit CC6.6 + C1.1 dual-mapped soc2.json routing. **NEW institutional pre-publish doc-consistency gate** introduced this cycle.

For prior releases, see [CHANGELOG.md](./CHANGELOG.md).

### Try Enterprise

→ **[See a sample scan walk-through](https://www.nsauditor.com/ai/docs/sample-scan/)** — full EE 0.6.7 output against a fictional Acme Corp AWS account + home-office router. Real engine output, synthetic data, no signup required.

→ **[NSAuditor AI Enterprise Edition](https://www.nsauditor.com/ai/enterprise/)** — 22 cloud plugins, signed SOC 2 evidence with RFC 3161 timestamps, native Vanta / Drata / Secureframe push, runs entirely inside your infrastructure (zero data exfiltration by architecture). Pricing from **$2k/yr (5 seats)** to **$10k+/yr (unlimited + custom SLA)**.

---


## What It Does

```
Scan → Verify → Prioritize → Track → Act
```

- **27 scanner plugins** probe networks across ICMP, TCP, UDP, HTTP, TLS, SNMP, DNS, SMB, RPC, mDNS, UPnP, WS-Discovery, MCP (Model Context Protocol), and more
- **Smart result fusion** — the Result Concluder merges all plugin outputs into a normalized view with OS detection, service fingerprinting, and evidence linking
- **Structured finding format** — all findings use a common schema with category, severity, evidence, and remediation — enabling consistent SARIF export and MCP integration
- **AI-powered analysis** — send redacted scan results to OpenAI or Claude (your keys, your choice) for vulnerability assessments and remediation guidance
- **Verified vulnerabilities (Pro)** — safe, non-destructive probes confirm findings are real, not just version-matched guesses. If it can't be verified, it's flagged as "potential" not "confirmed"
- **Continuous monitoring (CTEM)** — watch mode rescans on a schedule, diffs against previous results, and fires webhook alerts on changes
- **MCP integration** — expose scanning tools to AI assistants like Claude Code via Model Context Protocol
- **CI/CD ready** — SARIF output with `--fail-on` severity gating for pipeline integration

## Editions

NSAuditor AI is available in three editions:

| | Community (Free) | Pro ($49/mo) | Enterprise ($2k+/yr) |
|---|:---:|:---:|:---:|
| 27 scanner plugins | ✅ | ✅ | ✅ |
| AI analysis (OpenAI, Claude, Ollama) | ✅ (basic prompts) | ✅ (enriched) | ✅ (enriched) |
| Structured finding format | ✅ | ✅ | ✅ |
| CTEM watch mode | ✅ | ✅ | ✅ |
| SARIF + CSV export | ✅ | ✅ | ✅ |
| CVE matching + MITRE ATT&CK | — | ✅ | ✅ |
| Parallel analysis agents | — | ✅ | ✅ |
| Verified vulnerabilities (safe probes) | — | ✅ | ✅ |
| Risk scoring + prioritization | — | ✅ | ✅ |
| Intelligence-enriched AI prompts | — | ✅ | ✅ |
| Advanced CTEM + trend analysis | — | ✅ | ✅ |
| Cloud scanners (AWS/GCP/Azure) | — | — | ✅ |
| Zero Trust assessment | — | — | ✅ |
| SOC 2 compliance (10 covered + 4 partial controls post-EE 0.3.9; AWS + Azure + GCP evidence streams; PI1.5 stored-items partial via DynamoDB audit-the-auditor) | — | — | ✅ |
| SLA/MTTR tracking + compensating controls | — | — | ✅ |
| Recurring-scan attestation (Type II evidence) | — | — | ✅ |
| GRC platform connector (Vanta) | — | — | ✅ |
| WORM evidence storage (S3 Object Lock) | — | — | ✅ |
| Tabletop simulation + SIEM correlation | — | — | ✅ |
| Docker per-scan isolation | — | — | ✅ |
| Air-gapped deployment | — | — | ✅ |

**This repository is the Community Edition** — fully functional, MIT-licensed, no restrictions. Pro and Enterprise features are available via the [`@nsasoft/nsauditor-ai-ee`](https://www.nsauditor.com/ai/pricing) package.

→ [Get Pro or Enterprise](https://www.nsauditor.com/ai/pricing/)

---

## Quick Start

```bash
# Install globally
npm install -g nsauditor-ai

# See all flags, subcommands, and worked examples
nsauditor-ai --help

# Configure (optional — scans work fully offline without AI)
cat > .env << 'EOF'
AI_ENABLED=true
AI_PROVIDER=ollama              # openai | claude | ollama
OLLAMA_MODEL=llama3             # For local AI (no API key needed)
# OPENAI_API_KEY=sk-...         # Or use OpenAI
# ANTHROPIC_API_KEY=sk-ant-...  # Or use Claude
OPENAI_REDACT=true
EOF

# Scan a host with all plugins
nsauditor-ai scan --host 192.168.1.1 --plugins all

# Scan a subnet in parallel
nsauditor-ai scan --host 192.168.1.0/24 --plugins all --parallel 10

# Start the MCP server for AI assistants
nsauditor-ai-mcp
```

Or run without installing:

```bash
npx nsauditor-ai scan --host 192.168.1.1 --plugins all
```

Or clone and run from source:

```bash
git clone https://github.com/nsasoft/nsauditor-ai.git
cd nsauditor-ai
npm install
node --env-file=.env cli.mjs scan --host 192.168.1.1 --plugins all
```

Results land in `./out/<host>_<timestamp>/`:

| File | Contents |
|---|---|
| `scan_conclusion_raw.json` | Full unredacted conclusion (admin reference) |
| `scan_conclusion_raw.html` | Admin RAW HTML with filters and full detail |
| `scan_response_ai_payload.json` | Redacted payload sent to AI |
| `scan_response_ai.json` | Raw AI API response |
| `scan_response_ai.txt` | AI conclusion (markdown) |
| `scan_response_ai.html` | Styled HTML report with CVE links and badges |
| `scan_results.sarif.json` | SARIF 2.1 — only with `--output-format sarif` (renamed `scan_<host>.sarif.json` for multi-host runs) |
| `scan_results.csv` | CSV — only with `--output-format csv` |
| `scan_report.md` | GitHub-flavored Markdown report — only with `--output-format md` (or `markdown`) |

> Works on Node 20+ (tested on Node 22).

---

## Plugins

### Core Scanners

| ID | Name | Protocols | Purpose |
|---|---|---|---|
| 001 | Ping Checker | ICMP/ARP | Reachability + TTL-based OS hints |
| 002 | SSH Scanner | TCP:22 | Banner, version fingerprinting, timeout policy |
| 003 | Port Scanner | TCP/UDP | Bulk open port detection (populates context for downstream plugins) |
| 004 | FTP Banner Check | TCP:21 | FTP daemon version detection |
| 005 | Host Up Check | TCP/UDP | Quick multi-probe reachability confirmation |
| 006 | HTTP Probe | TCP:80/443 | Headers, server token, vendor hints |
| 007 | SNMP Scanner | UDP:161 | sysDescr, OIDs, serial/hardware/firmware extraction |
| 008 | Result Concluder | Meta | Fuses all plugin outputs (always runs last) |
| 009 | DNS Scanner | TCP/UDP:53 | `version.bind` CHAOS/TXT + A record lookup |
| 010 | Webapp Detector | HTTP | Technology stack fingerprinting via wappalyzer |
| 011 | TLS Scanner | TCP:443+ | TLS version + cipher enumeration per port |
| 012 | OpenSearch Scanner | HTTP:9200+ | OpenSearch/Dashboards version + Linux/Node.js hints |
| 013 | OS Detector | Meta | Derives distro/OS from all prior banners with TTL fallback |
| 014 | NetBIOS Scanner | UDP:137/TCP:445 | NetBIOS/SMB enumeration + SMB2 null session probe |
| 015 | SUN RPC Scanner | TCP/UDP:111 | RPC portmapper service discovery (NFS, mountd) |
| 016 | WS-Discovery | UDP:3702 | Multicast device discovery with XML metadata |
| 024 | TCP SYN Scanner | TCP (Nmap) | SYN half-open scan via Nmap wrapper (optional) |
| 040 | TLS Certificate & Cipher Auditor | TCP:443+ | Cert expiry, chain integrity, hostname mismatch, weak ciphers, deprecated protocols, key strength |
| 050 | TRIBE v2 Neural API Security Probe | TCP/HTTP:8080 | Debug leak detection, stack traces in errors, header security, CORS misconfiguration, unauthenticated routes |
| 060 | DNS Security Auditor | DNS/UDP:53 | SPF/DKIM/DMARC, dangling CNAMEs, DNSSEC, NS delegation, zone transfer exposure, MX security, CAA records |
| 070 | MCP Scanner | TCP/HTTP+SSE | Detects MCP (Model Context Protocol) servers on candidate ports (1967, 3000, 3005, 5173, 6274, 6277, 8000, 8090). Audits for cleartext transport (HTTP not HTTPS), missing/anonymous auth, anonymous tool enumeration, deprecated protocol versions, and Inspector exposure on non-loopback. Maps findings to CWE/OWASP/MITRE per the FindingSchema. STDIO-transport MCP servers are out of scope (no network port). |

### Discovery Plugins

| Name | Purpose |
|---|---|
| ARP Scanner | MAC resolution + OUI vendor lookup + OS hints |
| mDNS/Bonjour Scanner | Local service discovery + friendly names from TXT records |
| UPnP/SSDP Scanner | Device discovery + description XML parsing |
| DNS-SD Scanner | DNS Service Discovery announcements |
| LLMNR Scanner | Link-local multicast name resolution |
| DB Scanner | Database service detection (MySQL, PostgreSQL, Redis, etc.) |

### Pro/Enterprise Plugins (via @nsasoft/nsauditor-ai-ee)

**23 enterprise plugins** across AWS, GCP, and Azure substrate audits — all mapped to AICPA Trust Services Criteria 2017 (10 covered + 4 partial controls). EE plugins live in the disjoint 1000+ ID range; CE reserves 001-099. Once licensed, the EE package installs alongside the CE binary and discovers automatically.

→ **[Watch a sample scan run end-to-end](https://www.nsauditor.com/ai/docs/sample-scan/)** — synthetic Acme Corp AWS account + home-office router. Real EE 0.6.7 output, no signup required. See the transitive SG chain reachability finding, the multi-region GuardDuty audit, the dnsmasq CVE detection, and what the signed evidence pack actually looks like.

→ **[Buy NSAuditor AI Enterprise Edition](https://www.nsauditor.com/ai/enterprise/)** · $2k / $5k / $10k+ per year · 5 / 25 / unlimited seats · onboarding call included.

**All EE plugins follow the same institutional plumbing pattern:**

- **Thread H `_instrumentSdkClient` wrap** — per-API AccessDenied counter + ZDE structural guard (verb-prefix denylist regex blocks `Get*` / `Retrieve*` / `Read*` value-reading APIs at SDK boundary) + idempotency sentinel
- **Throttle-retry** — exponential-backoff retry on `Throttling*` / `RequestLimitExceeded` / `TooManyRequestsException` with per-command wall-clock budget
- **Thread F `conclude()` field-selection allowlist** — structured-data ZDE: only AWS-public-namespace identifiers + integer counts flow through to findings; customer policy content / key material / encrypted payloads NEVER propagate
- **`conservative_classifier_principle`** — emit INFO+evidenceGap with verification prompt when ARN-shape disambiguation needs a follow-up API call; vacuous PASS on partial substrate evidence is treated as the worst SOC 2 reporting outcome
- **`aws_string_case_normalization`** — trim + lowercase AWS-returned strings at SDK-helper boundary; protects against the 7+ recurrent classes of case-sensitivity fail-open (IAM Condition keys, Lambda runtimes, KMS aliases, Effect/Action discriminators, FULL_ADMIN sentinel, S3 region)

| ID | Name | Tier | What it audits |
|---|---|---|---|
| 1020 | AWS S3 Security | Enterprise | Bucket hardening: public-access block, encryption at rest, versioning, Object Lock COMPLIANCE-mode, MFA Delete, access logging. **CC6.1 / C1.1 / C1.2** |
| 1021 | GCP Cloud Scanner | Enterprise | Firewall rules + IAM bindings + Storage bucket public-access. **CC6.1 / CC6.6 / C1.1** |
| 1022 | Azure Cloud Scanner | Enterprise | NSG rules + RBAC role assignments + Storage account hardening. **CC6.1 / CC6.6 / C1.1** |
| 1023 | Zero Trust Checker | Enterprise | Segmentation, encryption, identity, lateral-movement scoring across the network surface. **CC6.1 / CC6.6** |
| 1024 | GCP Cloud Storage Auditor | Enterprise | Multi-cloud parity sister of plugin 1020 AWS S3. 6 dimensions: bucket-level IAM public bindings (allUsers = CRITICAL, allAuthenticatedUsers = HIGH), Uniform Bucket-Level Access (closes legacy bucket-ACL false-PASS class), Object Versioning, Bucket Lock retention policy (SEC 17a-4 / FINRA 4511 WORM-alignment), CMEK via Cloud KMS (four-tier custody ladder), bucket-level access logging. **CC6.1 / CC6.6 / CC7.1 / C1.1 / C1.2 / A1.2** |
| 1030 | AWS IAM Deep Auditor | Enterprise | Shadow-admin path detection via BFS over PassRole / AssumeRole / federated trust. Restrictive-Condition allowlist for Auth0 / Okta / Cognito OIDC patterns. **CC6.1** |
| 1040 | AWS CloudTrail Operational Integrity | Enterprise | Trail health + CloudWatch alarm coverage against CIS AWS Benchmark §3.1–3.14 + AWS Config + cross-account S3 trail-destination WORM verification (SEC 17a-4 / FINRA 4511). **CC7.2 / CC7.3** |
| 1050 | AWS API Gateway Assurance | Enterprise | Per-route authz classifier (`NONE`=CRITICAL), custom-domain TLS policy, stage-level access logging + WAF, public-endpoint exposure. Entry-point evidence for serverless deployments. **CC6.1 / CC6.6 / CC6.7 / CC7.1 / A1.2** |
| 1060 | AWS DynamoDB Audit Integrity | Enterprise | First "audit-the-auditor" plugin. PITR + deletion protection + KMS-CMK custody + resource-policy presence + CloudTrail data-event cross-reference. **CC6.6 / CC7.1 / C1.1 / PI1.5** |
| 1070 | AWS KMS Auditor | Enterprise | Per-key rotation + wildcard-Principal classifier across 5 severity tiers (covers `Principal.AWS` / Federated / Service / CanonicalUser + NotPrincipal-Allow + NotAction-Allow + glob actions). **CC6.3 / C1.1** |
| 1080 | AWS Lambda Security | Enterprise | Runtime EOL detection (CRITICAL on `nodejs16.x` / `python3.7` etc.), public function URLs, resource-policy wildcards, env-var secret-name detection (ZDE-safe), VPC config, KMS custody, DLQ. **CC6.1 / CC6.6 / CC7.1 / C1.1** |
| 1090 | AWS Secrets Manager + SSM Parameter Store | Enterprise | Rotation cadence + KMS-CMK custody + SecureString classification + secret-name detection. **ZDE-critical**: never calls `GetSecretValue` / `GetParameter` — metadata only. Verb-prefix denylist blocks `Get*` / `Retrieve*` / `Read*` at the SDK boundary. **CC6.1 / CC6.6 / C1.1** |
| 1100 | AWS CodePipeline + CodeBuild | Enterprise | Source-stage encryption, `privilegedMode` detection, buildspec drift, secrets-via-env vs Secrets-Manager, IAM wildcard-Action, artifact-store encryption, stale-execution detection. **CC6.1 / CC7.1 / CC8.1 / C1.1** |
| 1110 | IAM Effective Decrypt-Path Auditor | Enterprise | Cross-plugin reconciler — walks IAM policies for `kms:Decrypt` / `ReEncrypt*` / `GenerateDataKey` grants and cross-references against KMS key policies to compute the effective decrypt path. Closes the NotAction-implicit-decrypt false-PASS class. **CC6.1 / CC6.6 / C1.1 / C1.2** |
| 1120 | AWS S3 Lifecycle + Cross-Region Replication | Enterprise | Lifecycle policy enumeration + cross-region replication topology. Cross-region destination-bucket reachability check closes silent-PASS where replication FAILED but emitted clean. **C1.1 / C1.2 / A1.2** |
| 1130 | AWS Backup Auditor | Enterprise | The flagship plugin — 12-dimension air-gapped vault attestation arc for `LogicallyAirGappedBackupVault` resources. Audits Plans + Vaults + Recovery Points + Frameworks + Restore Testing + Legal Holds + vault Access Policy. SEC 17a-4 / FINRA 4511 ransomware-defense substrate. **CC6.3 / CC6.6 / CC7.1 / CC8.1 / C1.1 / C1.2 / A1.2** |
| 1140 | AWS RDS Auditor | Enterprise | 10 dimensions: Multi-AZ, storage encryption + KMS custody, parameter-group SSL, backup retention, public accessibility, IAM database auth, snapshot encryption, **pgAudit + SPL cross-check**, CloudWatch Logs exports (engine-dispatched), log retention. **A1.2 / CC6.1 / CC6.6 / C1.1 / CC7.2 / CC7.3** |
| 1150 | AWS SQS/SNS Auditor | Enterprise | 7 dimensions across both services: encryption at rest + KMS custody, transit-encryption policy, topic-policy wildcards (CRITICAL on unconditional + NotPrincipal-Allow), DLQ presence, CloudWatch alarm coverage on `ApproximateAgeOfOldestMessage` + `NumberOfNotificationsFailed`. **C1.1 / CC6.6 / A1.2 / CC7.1 / CC7.2** |
| 1160 | AWS VPC Endpoints / PrivateLink | Enterprise | Endpoint-policy wildcards (CRITICAL on PrivateLink-breaking unconditional), PrivateDNS enabled (silent-bypass class), endpoint state (`failed` = silent failure), type substrate disclosure. **CC6.6 / A1.2 / CC7.2** |
| 1170 | AWS EC2 SG Perimeter | Enterprise | RESTRICTED_PORTS (23 ports per CIS AWS Foundations v3.0) wildcard ingress + IPv6 ::/0 + all-protocol-from-wildcard + orphan SG detection. **SG→SG transitive chain reachability**: BFS from public-CIDR roots through `UserIdGroupPairs` — 2-hop = HIGH, 3+ hop = CRITICAL. Catches the ALB → app → database exposure that per-SG audits silently miss. **CC6.6 / CC6.2** |
| 1180 | AWS ElastiCache Redis | Enterprise | 6 dimensions: transit encryption, at-rest + KMS custody (four-tier ladder), Redis AUTH / IAM user groups (Redis 7+ ACL), Multi-AZ, snapshot retention cadence, subnet placement. Cross-plugin sister to plugin 1170 for cache-tier perimeter. **CC6.1 / CC6.2 / CC6.6 / A1.2 / C1.1** |
| 1190 | AWS SES Email Integrity | Enterprise | 6 dimensions: DKIM enablement + CNAME DNS resolution + key-fingerprint pin, DMARC TXT parsing + alignment classifier, custom MailFrom alignment, config-set TLS enforcement, sending-auth policy wildcards, dedicated IP pool, suppression list (count-only — ZDE invariant: never reads addresses). **CC6.1 / CC6.6 / C1.1 / CC7.1 / Privacy** |
| 1200 | AWS Inspector2 / GuardDuty Enablement | Enterprise | 4 dimensions across all opted-in regions (17+ incl. GovCloud / ISO): GuardDuty Detector + protection features (S3 / EKS / EBS-malware / RDS-login / Lambda / RuntimeMonitoring), Inspector2 enablement, scan-target coverage. Plus alerting-destination dim (EventBridge or SecurityHub) and per-target liveness probes for Lambda / SNS / SQS / IAM / API destination / CloudWatch Logs. **CC7.1 / CC7.2** |
| — | SOC 2 Compliance Engine | Enterprise | AICPA TSC 2017 mapping (10 covered + 4 partial controls), chain-of-custody, RFC 3161 timestamps, suppression workflow with Ed25519 signing. |
| — | SLA & MTTR Tracking | Enterprise | Per-severity SLA targets, compensating-control flow, finding lifecycle, Type II rolling-quarter cadence. |
| — | Recurring-Scan Attestation | Enterprise | Multi-scan chronological matrix, cadence gap detection, scope-drift surface (CC8.1). |
| — | GRC Platform Connector | Enterprise | Native API push to Vanta / Drata / Secureframe with retry/backoff, idempotency, rate-limit handling, per-tenant token rotation. |
| — | WORM Evidence Storage | Enterprise | S3 Object Lock COMPLIANCE-mode + resource redaction + SHA-256 manifest. SEC 17a-4 / FINRA 4511 retention-compatible. |
| — | Tabletop Simulation | Enterprise | Probe-event manifest + SIEM detection correlation, configurable coverage bands (Type II / High-Assurance presets). |

**Running EE plugins** (after `nsauditor-ai license install <key>`):

```bash
# Run a single EE plugin
nsauditor-ai scan --host aws --plugins 1130 --compliance soc2 --out evidence.json

# Run multiple EE plugins
nsauditor-ai scan --host aws --plugins 1030,1040,1070,1130 --compliance soc2

# Run all EE plugins (auto-discovered via plugin manager)
nsauditor-ai scan --host aws --plugins all --compliance soc2

# Tune plugin parameters (e.g., raise VPC-endpoint PAGE_CAP for large-fleet customers)
nsauditor-ai scan --host aws --plugins 1130 --plugin-opts '{"1130":{"vpcEndpointsPageCap":50}}'
```

The auditor evidence pack is emitted under `out/` — cover-page Scope Attestation, SHA-256 chain-of-custody sidecars, RFC 3161 trusted-timestamps, suppression workflow, identity verification. EE is available at [`www.nsauditor.com/ai/pricing`](https://www.nsauditor.com/ai/pricing).

---

## How Results Are Fused

The Result Concluder (plugin 008) merges all plugin outputs into a normalized structure:

1. **Imports** each plugin's `conclude()` adapter to get normalized `ServiceRecord` objects
2. **Merges** services by `(protocol, port)`, preferring authoritative records
3. **Selects OS** — OS Detector result first, then high-signal hints (Windows services, HTTP tokens), finally TTL fallback
4. **Produces** a unified `{ summary, host, services, evidence }` output
5. **Enriches** host details with names from mDNS, UPnP, NetBIOS; MAC + vendor from ARP

---

## AI Analysis

NSAuditor AI supports three AI providers for vulnerability analysis. **All providers work in all tiers** — CE, Pro, and Enterprise. AI is optional; the platform is fully functional without it.

**Providers:** OpenAI (GPT-4o), Anthropic Claude (Sonnet/Opus), Ollama (fully local)

**What changes by tier is the prompt content, not the provider:**

- **CE** — basic scan-summary prompts (services, ports, versions detected). Local MITRE ATT&CK mapping via `utils/attack_map.mjs`: service-context-aware CVE→technique mapping (`mapCveToAttack`, `mapServiceToAttack`), plus a CWE→technique fallback (`cweToMitre`, `cwesToMitre`) covering ~30 common CWEs (auth, crypto, injection, memory safety, info disclosure, privilege escalation, web). The CWE fallback fires only when CVE-derived mapping returns no techniques — useful for findings annotated with `evidence.cwe[]` (per FindingSchema v0.1.13+) but no CVE context, such as agent-detected misconfigurations and compliance-flagged weaknesses
- **Pro** — intelligence-enriched prompts (CVE matches, MITRE techniques, risk scores, verification status injected into the prompt). Same API call, vastly better output
- **Enterprise** — Pro prompts + compliance context

**Redaction:** Before any data reaches an AI API, the redaction pipeline masks IP addresses, MAC addresses, serial numbers, and configurable confidential keywords. Admin RAW reports retain full detail for internal review.

```ini
# .env
AI_PROVIDER=claude
ANTHROPIC_API_KEY=sk-ant-...        # Your key — never sent to Nsasoft
ANTHROPIC_MODEL=claude-sonnet-4-6
OPENAI_PROMPT_MODE=optimized
OPENAI_REDACT=true
```

For fully local AI (no external API calls), use [Ollama](https://ollama.ai):

```ini
AI_PROVIDER=ollama
OLLAMA_MODEL=llama3
```

---

## Continuous Monitoring (CTEM)

Watch mode enables periodic rescanning with delta detection and webhook alerts:

```bash
nsauditor-ai scan --host 192.168.1.0/24 --plugins all \
  --watch --interval 15 \
  --webhook-url https://hooks.example.com/security \
  --alert-severity high
```

- **Scheduling** with configurable intervals and concurrency control
- **Delta detection** — new, removed, and changed services highlighted between cycles
- **Webhook alerts** — JSON POST with retry (exponential backoff, no retry on 4xx)
- **SSRF protection** — private, loopback, and cloud metadata addresses blocked at the scan entry point and inside `sendWebhook()`. Set `NSA_ALLOW_ALL_HOSTS=1` to scan RFC 1918 ranges (local network auditing)
- **Scan history** stored in `.scan_history/` (JSONL format, 7-day retention in CE)

---

## MCP Server

> **Heads-up on AI-client fabrication.** Some MCP clients (notably Claude Desktop) can silently substitute AI-generated responses if a `tools/call` times out, instead of surfacing the failure. Every response from this server now ends with a `── Verified MCP call ──` footer and a UUID. Run `nsauditor-ai mcp verify-call <id>` to confirm a response is genuine before acting on it. Full background and workflow: [docs/mcp-verification.md](./docs/mcp-verification.md). When in doubt, generate compliance evidence via the CLI (`nsauditor-ai scan ...`), which has no MCP client in the path.

Expose scanning capabilities to AI assistants via [Model Context Protocol](https://modelcontextprotocol.io):

```bash
nsauditor-ai-mcp
# or
npx nsauditor-ai-mcp
```

**CE Tools:**

| Tool | Purpose |
|---|---|
| `scan_host` | Run full scan against a host with plugin selection |
| `list_plugins` | List available scanner plugins with metadata |

**Pro Tools** (requires license key + `@nsasoft/nsauditor-ai-ee`):

| Tool | Purpose |
|---|---|
| `probe_service` | Deep scan a specific port/service |
| `get_vulnerabilities` | Query CVEs by CPE string |
| `risk_summary` | Prioritized risk overview from last scan |
| `scan_compare` | Diff two scan results with risk weighting |
| `save_finding` | Save a validated finding to the finding queue (schema-checked) |

**Enterprise Tools** (requires Enterprise license):

| Tool | Purpose |
|---|---|
| `start_assessment` | Multi-host orchestrated assessment workflow |
| `prioritize_risks` | Cross-host risk prioritization |
| `compliance_check` | Compliance mapping with gap analysis |
| `export_report` | Generate formatted compliance report |

Security: SSRF protection on all host inputs (blocks RFC 1918, loopback, fc00::/7, cloud metadata), port validation (1–65535), CPE format enforcement, dependency injection for test isolation. **Server-startup authentication is required** — see next section.

### Authentication (required)

The MCP server uses stdio transport, which means it runs as a child process of whatever client launches it. Without authentication, **any process running as your user could spawn the server and use its tools** — including the Pro/Enterprise tools that talk to AWS, generate compliance reports, and access your scan history. A per-operator shared-secret check at server startup closes this gap.

**One-time setup** (run once per machine after `npm install -g nsauditor-ai`):

```bash
nsauditor-ai mcp install-key
```

This generates a 256-bit auth key, stores it in the macOS Keychain (or `~/.nsauditor/.env` mode 0600 on Linux/Windows), and prints the Claude Desktop config snippet for you to paste. **The MCP server refuses to start unless the env-presented key matches the stored key** (constant-time compare; mismatch produces an actionable error pointing at this command).

**Inspect / verify**:

```bash
nsauditor-ai mcp status                  # shows storage source WITHOUT printing the key
nsauditor-ai mcp print-key --confirm     # reveals the key (use sparingly; refuses non-TTY output)
nsauditor-ai mcp rotate-key --confirm    # generates a new key (invalidates old one immediately)
```

**Why the Claude Desktop config snippet uses `keychain:` indirection on macOS**: the printed snippet looks like `"NSA_MCP_AUTH_KEY": "keychain:NSA_MCP_AUTH_KEY"` rather than the literal key value. The MCP server resolves the placeholder from your Keychain at startup. Net effect: **the secret never lands in `~/Library/Application Support/Claude/claude_desktop_config.json`** (which is mode 0644 by default — readable by other local users and any macOS app with Documents/Application Support entitlement). On Linux/Windows where there's no Keychain equivalent, the snippet uses the literal key with an explicit `chmod 600` warning.

**Threat model — what this defends, what it doesn't**:

| Threat | Defended? |
|---|---|
| Malicious npm post-install / browser extension running as you spawning the server | ✅ — attacker cannot read your Keychain without GUI prompt |
| Other users on a shared dev box / CI runner | ✅ — key is per-operator |
| Future HTTP/SSE transport network exposure | ✅ — key gates server startup, not network |
| Attacker with full operator code-exec AND can suppress macOS Keychain prompts | ⚠ partial — recent macOS versions log Keychain-access denial events |
| Debugger-attach memory snooping | ⚠ out of scope (any shared-secret auth has this limit) |
| Linux env-var visibility in `/proc/<pid>/environ` | ⚠ partial — see Linux note below |

**Linux note (`/proc/<pid>/environ`)**: on modern Linux, `/proc/<pid>/environ` is readable only by the process owner (the same user that spawned the MCP server). Other users on a multi-user system **cannot** read your MCP auth key from `/proc` under default kernel settings. The realistic remaining risks are:

- Container scenarios where multiple "users" share the same kernel UID (e.g., a Docker container running as root, with multiple processes inside) — the secret is visible to any process in the same UID namespace. Mitigation: run the MCP server in its own container / user.
- Audit/SIEM agents with broad read access (e.g., `auditd` configured to log child-process env). Mitigation: review your `auditd` rules; modern setups exclude env from logs by default.
- The legacy `ps eww` command on older POSIX systems (modern `ps` respects `/proc` permissions).

A shell-wrapper indirection script (read key from `~/.nsauditor/.env` at exec time, pass to child) was considered for v1 but does NOT solve the underlying issue: the spawned MCP server still needs the key in its env to perform the auth check, so it appears in `/proc/<server-pid>/environ` regardless of how the parent process obtained it. v2 may add libsecret integration on Linux to mirror the macOS Keychain indirection model.

**Rotation cadence**: keys older than 90 days emit a soft warning at every server startup AND in `nsauditor-ai mcp status` output. SOC 2 CC6.1 / CC6.7 reviewers expect a credential-rotation cadence; rotate with `nsauditor-ai mcp rotate-key --confirm` and update Claude Desktop config with the new key.

**Escape hatch for CI / dev** (operator-acknowledged risk; emits a stderr warning every startup):

```bash
NSA_MCP_AUTH_DISABLE=1 nsauditor-ai-mcp
```

### Claude Desktop Setup

First install the package globally:

```bash
npm install -g nsauditor-ai
nsauditor-ai mcp install-key   # required before MCP server will start
```

Then add this to your `claude_desktop_config.json` (Settings → Developer → Edit Config):

```json
{
  "mcpServers": {
    "nsauditor-ai": {
      "command": "nsauditor-ai-mcp",
      "env": {
        "NSA_MCP_AUTH_KEY": "keychain:NSA_MCP_AUTH_KEY",
        "AI_PROVIDER": "claude",
        "ANTHROPIC_API_KEY": "keychain:ANTHROPIC_API_KEY",
        "NSA_ALLOW_ALL_HOSTS": "1",
        "PLUGIN_TIMEOUT_MS": "5000"
      }
    }
  }
}
```

The exact `NSA_MCP_AUTH_KEY` value to paste is printed by `nsauditor-ai mcp install-key` — on macOS it's the `keychain:NSA_MCP_AUTH_KEY` placeholder shown above; on Linux/Windows it's the literal key value (and you should `chmod 600` your config file).

- `NSA_MCP_AUTH_KEY` — **required** (see Authentication section above)
- `NSA_ALLOW_ALL_HOSTS=1` — required to scan private/RFC 1918 addresses (e.g., `192.168.x.x`)
- `PLUGIN_TIMEOUT_MS=5000` — reduces per-plugin timeout to 5s so the full scan completes within Claude Desktop's 60s MCP limit
- `AI_PROVIDER` and API key — optional, enables AI-powered analysis of scan results

### Claude Code Setup

```bash
nsauditor-ai mcp install-key   # required before MCP server will start
claude mcp add nsauditor-ai \
  --env NSA_MCP_AUTH_KEY=keychain:NSA_MCP_AUTH_KEY \
  -- npx nsauditor-ai-mcp
```

(On Linux/Windows, replace the `keychain:NSA_MCP_AUTH_KEY` placeholder with the literal key printed by `install-key`.)

### Troubleshooting MCP authentication

**"MCP authentication is not configured"** at server startup → run `nsauditor-ai mcp install-key`. If you set `NSA_MCP_AUTH_DISABLE=1` in CI by intent, that's fine — but check that you didn't forget it in your shell rc.

**"NSA_MCP_AUTH_KEY env var is not set, but a key is configured in storage"** → the server found a key in your Keychain (or `~/.nsauditor/.env`) but the spawning client didn't pass `NSA_MCP_AUTH_KEY` in the env block. Update your Claude Desktop / Claude Code config to include the env value (use `nsauditor-ai mcp install-key` output as a reference snippet).

**"NSA_MCP_AUTH_KEY env var does not match the key configured in storage"** → most often means you ran `nsauditor-ai mcp rotate-key --confirm` but didn't update Claude Desktop config with the new key. Run `nsauditor-ai mcp status` to confirm storage source, then either re-paste the new key or use `keychain:NSA_MCP_AUTH_KEY` indirection (macOS only) so future rotations don't require a config change.

**"MCP_AUTH uses keychain: indirection but the referenced Keychain entry could not be read"** → typically a headless macOS / SSH-only CI runner where there's no GUI session to approve Keychain access. Replace the `keychain:` placeholder with the literal key value (or move auth to `~/.nsauditor/.env` with mode 0600).

**`mcp status` reports `keychain-locked`** → distinct from `unconfigured`: the Keychain entry exists but the security daemon refused to unlock without a GUI prompt. Same workarounds as the previous error: approve a Keychain GUI prompt, replace `keychain:` indirection with the literal key, or move auth to `~/.nsauditor/.env`.

**`mcp status` shows `⚠ Created: ... — > 90d threshold`** → key is older than the 90-day rotation cadence. Run `nsauditor-ai mcp rotate-key --confirm` and update Claude Desktop config with the new key. Server emits the same warning to stderr at every startup.

**Claude Desktop reports "Current tier: CE" despite `nsauditor-ai license --status` showing Enterprise** → first run `nsauditor-ai mcp tier` to get the ground-truth tier the MCP server actually resolves at startup. If `mcp tier` reports `enterprise` but Claude Desktop's `list_plugins` says CE, the AI client is synthesizing the response without actually calling the tool — see [docs/mcp-verification.md](./docs/mcp-verification.md) and verify any suspicious response with `nsauditor-ai mcp verify-call <id>`.

If `mcp tier` itself reports CE → genuine resolution failure. Inspect the license storage:

```bash
nsauditor-ai license --status
security find-generic-password -s nsauditor-ai -a NSAUDITOR_LICENSE_KEY -w 2>&1 | head -c 30
```

If license is in `~/.nsauditor/.env` but not in Keychain on macOS, re-run `nsauditor-ai mcp install-key` — the auto-mirror writes the license to Keychain so Claude Desktop's child process can read it via the `keychain:` indirection.

---

## Secure Credential Storage

Store API keys in the macOS Keychain instead of plaintext `.env` files:

```bash
# Store keys
nsauditor-ai security set ANTHROPIC_API_KEY
nsauditor-ai security set OPENAI_API_KEY

# List stored keys (masked)
nsauditor-ai security list

# Delete a key
nsauditor-ai security delete OPENAI_API_KEY
```

Then reference them with the `keychain:` prefix in `.env` or Claude Desktop config:

```env
ANTHROPIC_API_KEY=keychain:ANTHROPIC_API_KEY
```

```json
"env": {
  "ANTHROPIC_API_KEY": "keychain:ANTHROPIC_API_KEY"
}
```

The `keychain:` prefix works anywhere an API key is read — CLI, MCP server, or programmatic API.

---

## CLI Reference

```
nsauditor-ai scan [options]
nsauditor-ai license install <KEY>
nsauditor-ai license <--status | --capabilities | --plugins>
nsauditor-ai security <set|delete|list|get> <KEY>
nsauditor-ai validate
nsauditor-ai --help        (or -h, or `help`)
nsauditor-ai --version     (or -v, or `version`)
```

> Run `nsauditor-ai --help` (or `-h`, or just `nsauditor-ai help`) for a quick reference of subcommands, flags, env vars, and worked examples — works without a license key configured. `--version` / `-v` prints `nsauditor-ai <version>` and exits 0.

| Flag | Description | Default |
|---|---|---|
| `--host <target>` | Target: IP, hostname, CIDR, dash range. Aliases: `--ip`, `--target` | *required*\* |
| `--host-file <path>` | File with one host per line (`#` comments, blank lines OK) | — |
| `--plugins <list>` | Comma-separated plugin IDs or `all` | `all` |
| `--ports <list>` | **Additional** ports to scan, merged into the default config-derived list. Comma-separated. Optional `/tcp` or `/udp` suffix per entry (default: `tcp`). Examples: `8090` · `8090,9090` · `8090/tcp,5353/udp`. Use this to scan custom services on non-standard ports (e.g. MCP servers on `8090`, dev servers on `3000–9000`) | — |
| `--out <dir>` | Custom output directory — applies to the per-scan folder *and* to alternate-format files (SARIF/CSV/Markdown) | `out/` |
| `--parallel <n>` | Concurrent host scans | `1` |
| `--output-format <fmt>` | Additional output format: `sarif` (CI/CD) · `csv` (spreadsheet) · `md` or `markdown` (chat/PR/Slack quotable) | — |
| `--fail-on <sev>` | Exit code 2 if findings ≥ severity: `critical\|high\|medium\|low\|info` | — |
| `--insecure-https` | Accept self-signed TLS certificates | `false` |
| `--watch` | Enable CTEM continuous scanning | `false` |
| `--interval <min>` | Rescan interval in minutes (requires `--watch`) | `60` |
| `--webhook-url <url>` | Webhook URL for delta alerts | — |
| `--alert-severity <sev>` | Minimum severity for webhook alerts | `high` |
| `--compliance <fw>` | Compliance framework to map findings into (e.g. `soc2`). **Enterprise license required.** See `@nsasoft/nsauditor-ai-ee` README for supported frameworks | — |
| `--compliance-scope <path>` | Optional JSON file describing the assessment scope (passed to the compliance engine for cover-page attestation) | — |
| `--help`, `-h` | Print usage block (subcommands, flags, env vars, examples) and exit 0 | — |
| `--version`, `-v` | Print `nsauditor-ai <version>` and exit 0 | — |

\* Either `--host` or `--host-file` is required.

### Host Formats

| Format | Example | Description |
|---|---|---|
| Single IP | `192.168.1.1` | Scan one host |
| Hostname | `example.com` | Resolved via DNS |
| CIDR | `192.168.1.0/24` | All usable hosts (min prefix: /16) |
| Dash range (short) | `192.168.1.1-50` | Last-octet range |
| Dash range (full) | `10.0.0.1-10.0.1.254` | IP-to-IP range (max 65534) |
| Host file | `--host-file targets.txt` | One host/CIDR/range per line |

### Examples

```bash
# Full scan with self-signed cert tolerance
nsauditor-ai scan --host 192.168.1.1 --plugins all --insecure-https

# Parallel subnet scan
nsauditor-ai scan --host 192.168.1.0/24 --plugins all --parallel 10

# Targeted scan: TLS + HTTP + DNS + OS detection
nsauditor-ai scan --host 192.168.1.8 --plugins 011,006,009,013,008

# SARIF output for CI/CD, fail on high+ findings
nsauditor-ai scan --host 10.0.0.5 --plugins all --output-format sarif --fail-on high

# Markdown report — paste straight into a GitHub issue, Slack thread, or chat
nsauditor-ai scan --host 10.0.0.5 --plugins all --output-format md

# Scan custom non-standard ports (e.g. an MCP server on 8090, dev service on 5000)
# Uses --ports to add to the default scan list — additive, not replacing
nsauditor-ai scan --host 192.168.1.28 --plugins all --ports 8090,5000/tcp

# Continuous monitoring with webhook alerts
nsauditor-ai scan --host 192.168.1.0/24 --plugins all \
  --watch --interval 30 \
  --webhook-url https://hooks.example.com/alerts \
  --alert-severity high

# Hosts from file with 4 parallel scans
nsauditor-ai scan --host-file targets.txt --plugins all --parallel 4
```

### Pre-flight `validate` command

`nsauditor-ai validate` runs a fast (<2s) environment check without scanning anything. Useful for CI/CD setups, Docker `HEALTHCHECK` probes, and first-time-user diagnosis. Each check returns a status; the overall exit code is 0 (all OK), 1 (warnings), or 2 (errors).

Checks: plugin discovery, license JWT validation (if key set), AI provider configuration, output-directory writability + free space, DNS resolution.

```bash
# Human-readable output
nsauditor-ai validate

# Machine-readable JSON for CI parsing
nsauditor-ai validate --json
```

Docker HEALTHCHECK example:

```dockerfile
HEALTHCHECK --interval=60s --timeout=5s --start-period=10s --retries=3 \
  CMD nsauditor-ai validate --json | grep -q '"overall": "ok"' || exit 1
```

---

## Configuration

### Environment Variables (.env)

**AI configuration:**

```ini
AI_ENABLED=false                     # Set to true to enable AI analysis
AI_PROVIDER=openai                   # openai | claude | ollama
OPENAI_API_KEY=sk-...               # Your OpenAI key
OPENAI_MODEL=gpt-4o-mini
ANTHROPIC_API_KEY=sk-ant-...        # Your Claude key
ANTHROPIC_MODEL=claude-sonnet-4-6
OPENAI_PROMPT_MODE=optimized        # basic | pro | optimized
OPENAI_REDACT=true                  # Redact before sending to AI
CONFIDENTIAL_KEYWORDS=serial,password,token,secret
```

**Plugin-specific:**

```ini
TLS_SCANNER_TIMEOUT_MS=8000
TLS_SCANNER_VERSIONS=TLSv1,TLSv1.1,TLSv1.2,TLSv1.3
TLS_SCANNER_PORTS=443:https,465:smtps,563:nntps,993:imaps,995:pop3s
OPENSEARCH_SCANNER_TIMEOUT_MS=6000
OPENSEARCH_SCANNER_INSECURE_TLS=false
DNS_TIMEOUT_MS=800
HTTP_PROBE_TIMEOUT_MS=6000
WEBAPP_DETECTOR_TIMEOUT_MS=6000
SMB_NULL_SESSION=false
SMB_NULL_SESSION_TIMEOUT=5000
ENABLE_SYN_SCAN=false
SYN_SCAN_PORTS=
SYN_SCAN_TIMEOUT=30000
PING_FALLBACK=true
PING_FALLBACK_TIMEOUT=2000
```

**Licensing (Pro/Enterprise):**

```ini
NSAUDITOR_LICENSE_KEY=pro_eyJhbGci...   # Pro or Enterprise license key
NSAUDITOR_PLUGIN_PATH=                   # Additional plugin directories (colon-separated)
```

**Security overrides:**

```ini
NSA_ALLOW_ALL_HOSTS=1    # Allow scanning private/RFC 1918 ranges (local network auditing)
NSA_AI_TIMEOUT_MS=120000 # AI provider call timeout in ms (default: 120000 = 2 min)
```

**Debug:**

```ini
NSA_VERBOSE=true      # Verbose PluginManager logging
DEBUG_MODE=true       # Plugin-level debug output
```

---

## Developing Plugins

NSAuditor AI uses a plug-and-play plugin system. Plugins are auto-discovered from `./plugins/` — no registration needed.

### Plugin Interface

```javascript
// plugins/0xx_my_scanner.mjs
export default {
  id: "0xx",
  name: "My Scanner",
  description: "What it probes",
  priority: 300,                    // Lower runs first; Concluder is 100000
  protocols: ["tcp"],
  ports: [1234],

  requirements: {                   // All optional
    host: "up",                     //   Skip if host unreachable
    tcp_open: [1234],               //   Skip if port not open
  },

  // requiredCapabilities: ["enterprise"],  // EE plugins only

  async run(host, port, opts = {}) {
    const { context } = opts;       // Shared state + OUI helpers
    return {
      up: true,
      program: "my-service",
      version: "1.0.0",
      data: [{
        probe_protocol: "tcp",
        probe_port: 1234,
        probe_info: "OK",
        response_banner: "my-service/1.0.0"
      }]
    };
  },

  // Adapter for Result Concluder
  conclude({ result, host }) {
    return [{
      port: 1234,
      protocol: "tcp",
      service: "my-service",
      program: result.program,
      version: result.version,
      status: "open",
      info: null,
      banner: result.data?.[0]?.response_banner || null,
      source: "my-scanner",
      evidence: result.data || [],
      authoritative: true
    }];
  },

  authoritativePorts: new Set(["tcp:1234"])
};
```

### Plugin Tips

- Use env-driven timeouts for all network calls
- Always close sockets on all code paths with a small post-banner linger
- Keep `probe_info` and `response_banner` concise — full detail goes in evidence
- Use `authoritativePorts` to take precedence over other plugins for the same port
- Plugins can also be loaded from external npm packages via `NSAUDITOR_PLUGIN_PATH`

---

## Pro & Enterprise Activation

After purchasing at [nsauditor.com/ai/pricing](https://www.nsauditor.com/ai/pricing), you'll receive an email with your license key and an npm install command. Two steps:

```bash
# 1. Install EE package (one-time, token included in email)
npm install -g @nsasoft/nsauditor-ai-ee --//registry.npmjs.org/:_authToken=npm_xxxxx

# 2. Set your license key
export NSAUDITOR_LICENSE_KEY=pro_eyJhbGci...
```

Verify:

```bash
nsauditor-ai license --status
# ✓ Pro license active | Expires: 2027-04-04

nsauditor-ai license --capabilities
# ✓ intelligenceEngine  ✓ riskScoring  ✓ proAI  ✓ advancedCTEM ...
```

License keys are delivered automatically via Stripe webhook — no manual processing. Subscription renewals generate a fresh key and email it to you before the current one expires.

No license key? Everything in this repository works perfectly without one. The CE is not crippled — it's a complete, production-ready security scanner.

→ [Pricing](https://www.nsauditor.com/ai/pricing/) · [Enterprise contact](https://www.nsauditor.com/ai/enterprise)

---

## Tests

Run all 925+ tests:

```bash
npm test
```

Run a specific suite:

```bash
node --test tests/tls_scanner.test.mjs
node --test tests/port_scanner.test.mjs
node --test tests/result_concluder.test.mjs
node --test tests/os_detector.test.mjs
node --test tests/mcp_server.test.mjs
node --test tests/attack_map.test.mjs
```

Tests use Node.js built-in `--test` runner with the `assert` module — no external test framework. Each test is self-contained with inline fixtures and lightweight network stubs.

---

## Troubleshooting

| Issue | Solution |
|---|---|
| No DNS banner | Provider may block CHAOS/TXT (`version.bind`) or UDP/53 |
| OpenSearch over self-signed TLS | Set `OPENSEARCH_SCANNER_INSECURE_TLS=true` |
| TLS shows "closed" | Service may require SNI — set `TLS_SCANNER_SNI=hostname` |
| RPC not detected | Ensure port 111 is accessible and RPC portmapper is running |
| WS-Discovery timeout | Check network config and firewall for multicast on UDP 3702 |
| SYN scan requires root | Run with `sudo` or use TCP connect scanner (plugin 003) instead |
| Webhook URL rejected | Private/loopback/cloud metadata blocked by SSRF guard. Use `NSA_ALLOW_ALL_HOSTS=1` to allow RFC 1918 scan targets |
| EE plugins not loading | Verify `@nsasoft/nsauditor-ai-ee` is installed and license key is set |

---

## Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

**Quick version:**

1. Fork the repo and create a feature branch
2. Add a `Signed-off-by` line to your commits (`git commit -s`)
3. Include tests for any new or changed behavior
4. Submit a PR

**All contributions to this repository are under the MIT license.** For Enterprise Edition contributions, see the [nsauditor-ai-ee](https://www.nsauditor.com/ai/enterprise) repository which requires a signed IP Assignment Agreement.

**What we won't accept:** Code that phones home, transmits scan data externally, or weakens the Zero Data Exfiltration boundary.

### Requesting or Contributing Plugins

Check `./plugins/` first. If a plugin doesn't exist:

- **Request it:** Open an issue with scope, target ports, protocols, and example banners
- **Build it:** Follow the plugin interface above, include tests, and update this README

Commonly requested plugins: RDP, VNC, SMTP/POP3/IMAP, MySQL/PostgreSQL/MSSQL/MongoDB/Redis, LDAP, RabbitMQ/Kafka/MQTT, SIP, NTP, Modbus/S7/DNP3/BACnet, WordPress/Jenkins/GitLab detectors.

---

## Architecture

For the full technical architecture, see [ARCHITECTURE.md](docs/architecture.md).

**Tech stack:** Node.js 20+ · ES Modules (.mjs) · OpenAI + Anthropic SDKs · Node.js built-in test runner · MCP stdio transport

**Design patterns:** Factory (PluginManager.create) · Strategy (orchestrated/legacy execution) · Context (shared state) · Adapter (plugin conclude()) · Guard Clause (requirement gating) · Capability gating (CE/Pro/EE) · Semaphore (concurrency control) · Delta (scan history diff) · Boundary Guard (SSRF/injection protection) · Finding Queue (structured intermediate format) · Parallel Agents (concurrent specialized analysis) · Verification Probes (safe non-destructive confirmation)

---

## Privacy & Security

NSAuditor AI is built on a **Zero Data Exfiltration (ZDE)** architecture:

- **No telemetry.** No analytics. No usage tracking. No phone-home.
- **No data processing.** Nsasoft US LLC never sees, stores, or processes your scan results.
- **AI is opt-in.** External AI calls use your own API keys. Redaction runs locally first.
- **License validation is offline.** JWT signature verified locally with an embedded public key.
- **Fully air-gappable.** Every feature works without internet access (Enterprise includes offline NVD feeds).

Nsasoft US LLC is not a data processor, data controller, or business associate under any data protection regulation. You own and control all data produced by NSAuditor AI.

---

## License

**MIT** — see [LICENSE](LICENSE) for the full text.

© 2024-present Nsasoft US LLC. "NSAuditor" and "NSAuditor AI" are trademarks of Nsasoft US LLC.

The Pro and Enterprise features available via `@nsasoft/nsauditor-ai-ee` are licensed under a separate proprietary license. See [www.nsauditor.com/ai/pricing](https://www.nsauditor.com/ai/pricing) for details.
