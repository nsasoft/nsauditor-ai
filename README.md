# NSAuditor AI

**Security Intelligence Without Data Exposure.**

A modular, AI-assisted network security audit platform that scans, understands, prioritizes, and tracks vulnerabilities — without ever requiring your data to leave your infrastructure.

[![npm](https://img.shields.io/npm/v/nsauditor-ai.svg)](https://www.npmjs.com/package/nsauditor-ai)
[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Node.js 20+](https://img.shields.io/badge/node-20%2B-green.svg)](https://nodejs.org)
[![Tests](https://img.shields.io/badge/tests-493%20passing-brightgreen.svg)](#tests)

---

NSAuditor AI is the open-source core of a privacy-first security intelligence platform built by [Nsasoft US LLC](https://www.nsauditor.com/ai/). It orchestrates 20+ specialized scanning plugins against target hosts, fuses their results through an intelligent concluder, and optionally produces AI-powered vulnerability reports — all running entirely on your machine.

**Zero Data Exfiltration by design.** NSAuditor AI works fully offline. AI analysis, CVE correlation, and continuous monitoring all happen locally. External calls (to AI APIs, NVD, etc.) are opt-in and use your own API keys. We never see your scan data.

## What It Does

```
Scan → Verify → Prioritize → Track → Act
```

- **27 scanner plugins** probe networks across ICMP, TCP, UDP, HTTP, TLS, SNMP, DNS, SMB, RPC, mDNS, UPnP, WS-Discovery, and more
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
| 20+ scanner plugins | ✅ | ✅ | ✅ |
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
| Compliance (NIST/HIPAA/GDPR/PCI) | — | — | ✅ |
| Docker per-scan isolation | — | — | ✅ |
| Air-gapped deployment | — | — | ✅ |

**This repository is the Community Edition** — fully functional, MIT-licensed, no restrictions. Pro and Enterprise features are available via the [`@nsasoft/nsauditor-ai-ee`](https://www.nsauditor.com/ai/pricing) package.

→ [Start a free 14-day Pro trial](https://www.nsauditor.com/ai/trial) (no credit card)

---

## Quick Start

```bash
# Install globally
npm install -g nsauditor-ai

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

| ID | Name | Tier | Purpose |
|---|---|---|---|
| 020 | AWS Cloud Scanner | Enterprise | Security group + IAM policy analysis |
| 021 | GCP Cloud Scanner | Enterprise | Firewall rules + IAM bindings |
| 022 | Azure Cloud Scanner | Enterprise | NSG rules + RBAC analysis |
| 023 | Zero Trust Checker | Enterprise | Segmentation, encryption, identity, lateral movement scoring |

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

- **CE** — basic scan-summary prompts (services, ports, versions detected)
- **Pro** — intelligence-enriched prompts (CVE matches, MITRE techniques, risk scores, verification status injected into the prompt). Same API call, vastly better output
- **Enterprise** — Pro prompts + compliance context

**Redaction:** Before any data reaches an AI API, the redaction pipeline masks IP addresses, MAC addresses, serial numbers, and configurable confidential keywords. Admin RAW reports retain full detail for internal review.

```ini
# .env
AI_PROVIDER=claude
ANTHROPIC_API_KEY=sk-ant-...        # Your key — never sent to Nsasoft
ANTHROPIC_MODEL=claude-sonnet-4-20250514
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

Security: SSRF protection on all host inputs (blocks RFC 1918, loopback, fc00::/7, cloud metadata), port validation (1–65535), CPE format enforcement, dependency injection for test isolation.

### Claude Desktop Setup

First install the package globally:

```bash
npm install -g nsauditor-ai
```

Then add this to your `claude_desktop_config.json` (Settings → Developer → Edit Config):

```json
{
  "mcpServers": {
    "nsauditor-ai": {
      "command": "node",
      "args": ["/path/to/global/node_modules/nsauditor-ai/mcp_server.mjs"],
      "env": {
        "AI_PROVIDER": "claude",
        "ANTHROPIC_API_KEY": "your-key-here",
        "NSA_ALLOW_ALL_HOSTS": "1",
        "PLUGIN_TIMEOUT_MS": "5000"
      }
    }
  }
}
```

Find your global install path with `npm root -g`, then append `/nsauditor-ai/mcp_server.mjs`.

- `NSA_ALLOW_ALL_HOSTS=1` — required to scan private/RFC 1918 addresses (e.g., `192.168.x.x`)
- `PLUGIN_TIMEOUT_MS=5000` — reduces per-plugin timeout to 5s so the full scan completes within Claude Desktop's 60s MCP limit
- `AI_PROVIDER` and API key — optional, enables AI-powered analysis of scan results

### Claude Code Setup

```bash
claude mcp add nsauditor-ai -- npx nsauditor-ai-mcp
```

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
```

| Flag | Description | Default |
|---|---|---|
| `--host <target>` | Target: IP, hostname, CIDR, dash range. Aliases: `--ip`, `--target` | *required*\* |
| `--host-file <path>` | File with one host per line (`#` comments, blank lines OK) | — |
| `--plugins <list>` | Comma-separated plugin IDs or `all` | `all` |
| `--ports <list>` | Comma-separated ports to pass to plugins | — |
| `--out <dir>` | Custom output directory | `out/` |
| `--parallel <n>` | Concurrent host scans | `1` |
| `--output-format <fmt>` | Output format: `sarif` for CI/CD | — |
| `--fail-on <sev>` | Exit code 2 if findings ≥ severity: `critical\|high\|medium\|low\|info` | — |
| `--insecure-https` | Accept self-signed TLS certificates | `false` |
| `--watch` | Enable CTEM continuous scanning | `false` |
| `--interval <min>` | Rescan interval in minutes (requires `--watch`) | `60` |
| `--webhook-url <url>` | Webhook URL for delta alerts | — |
| `--alert-severity <sev>` | Minimum severity for webhook alerts | `high` |

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

# Continuous monitoring with webhook alerts
nsauditor-ai scan --host 192.168.1.0/24 --plugins all \
  --watch --interval 30 \
  --webhook-url https://hooks.example.com/alerts \
  --alert-severity high

# Hosts from file with 4 parallel scans
nsauditor-ai scan --host-file targets.txt --plugins all --parallel 4
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
ANTHROPIC_MODEL=claude-sonnet-4-20250514
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

Install the EE package alongside the CE platform:

```bash
npm install -g @nsasoft/nsauditor-ai-ee
```

Set your license key:

```bash
echo "NSAUDITOR_LICENSE_KEY=pro_eyJhbGci..." >> ~/.nsauditor/.env
# or export directly
export NSAUDITOR_LICENSE_KEY=pro_eyJhbGci...
```

Verify:

```bash
nsauditor-ai license --status
# ✓ Pro license active | Expires: 2027-04-04

nsauditor-ai license --capabilities
# ✓ intelligenceEngine  ✓ riskScoring  ✓ proAI  ✓ advancedCTEM ...
```

No license key? Everything in this repository works perfectly without one. The CE is not crippled — it's a complete, production-ready security scanner.

→ [Pricing](https://www.nsauditor.com/ai/pricing) · [Start free trial](https://www.nsauditor.com/ai/trial) · [Enterprise contact](https://www.nsauditor.com/ai/enterprise)

---

## Tests

Run all 487 tests:

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
