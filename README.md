# NSAuditor AI

**Security Intelligence Without Data Exposure.**

A modular, AI-assisted network security audit platform that scans, understands, prioritizes, and tracks vulnerabilities — without ever requiring your data to leave your infrastructure.

[![npm](https://img.shields.io/npm/v/nsauditor-ai.svg)](https://www.npmjs.com/package/nsauditor-ai)
[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Node.js 20+](https://img.shields.io/badge/node-20%2B-green.svg)](https://nodejs.org)
[![Tests](https://img.shields.io/badge/tests-1582%20passing-brightgreen.svg)](#tests)

---

NSAuditor AI is the open-source core of a privacy-first security intelligence platform built by [Nsasoft US LLC](https://www.nsauditor.com/ai/). It orchestrates 27 specialized scanning plugins against target hosts, fuses their results through an intelligent concluder, and optionally produces AI-powered vulnerability reports — all running entirely on your machine.

**Zero Data Exfiltration by design — and stated precisely.** We never see your scan data: no customer data is collected, transmitted, or stored by Nsasoft US LLC, and the product has no telemetry or phone-home endpoint. Scanning, analysis, license verification and report generation all run on your machine. Two clarifications that matter operationally: AI enrichment is **opt-in** and uses your own API keys (point it at a local Ollama and nothing leaves the host), while **CVE correlation queries NIST's public NVD API by default** — set `NSAUDITOR_OFFLINE_ONLY=1` with a local NVD store to make it fully local, which reports an explicit coverage gap instead of a silent clean.

## What's New

**Latest: CE 0.2.55 + Enterprise 1.1.0 — *what changed since the last scan*.**
`nsauditor-ai report --from <dir> --since <runId|prior>` (Pro/Enterprise) compares two scan runs:
what is new, what is resolved, what changed severity — and, above all, **what could NOT be compared
and why**. "Resolved" is the dangerous verdict: a finding that disappeared because the host was not
scanned, the plugin did not run, the scanner lost permission, or the framework enumeration moved is
reported as NOT COMPARABLE **with its reason**, never as remediation. Run records are sealed with a
SHA-256 chain, so an altered baseline REFUSES the comparison instead of producing verdicts from it —
tamper-EVIDENT against corruption, partial restore and unsophisticated edits, **not tamper-proof
against host-level access and not non-repudiation**, and the report says so in the body. The delta
renders into the client-facing HTML report, not only to stdout. Plugin counts UNCHANGED at 27
Community + 29 Enterprise; every coverage matrix UNCHANGED; the Enterprise peer floor stays
`>= 0.2.49`. The free last-vs-current webhook alerting delta is untouched and stays free.

For the full per-release history — every prior cycle, in detail — see [CHANGELOG.md](./CHANGELOG.md). This README keeps only the current release headline.

## What It Does

```
Scan → Analyze → Prioritize → Track → Act
```

- **27 scanner plugins** probe networks across ICMP, TCP, UDP, HTTP, TLS, SNMP, DNS, SMB, RPC, mDNS, UPnP, WS-Discovery, MCP (Model Context Protocol), and more
- **Smart result fusion** — the Result Concluder merges all plugin outputs into a normalized view with OS detection, service fingerprinting, and evidence linking
- **Structured finding format** — all findings use a common schema with category, severity, evidence, and remediation — enabling consistent SARIF export and MCP integration
- **AI-powered analysis** — send redacted scan results to OpenAI or Claude (your keys, your choice) for vulnerability assessments and remediation guidance
- **Risk-scored prioritization (Pro/Enterprise)** — findings carry a composite risk score (CVSS weighted by verification status, with an uplift for initial-access techniques) and a status field, and an operator suppression workflow (accepted-risk / false-positive with expiry) keeps triaged findings out of the report until they expire
- **Continuous monitoring (CTEM)** — watch mode rescans on a schedule, diffs against previous results, and fires webhook alerts on changes
- **MCP integration** — expose scanning tools to AI assistants like Claude Code via Model Context Protocol
- **CI/CD ready** — SARIF output with `--fail-on` severity gating for pipeline integration

## Editions

NSAuditor AI is available in three editions: Community (free, MIT-licensed, no restrictions), Pro ($49/mo), and Enterprise ($2k+/yr).

**→ [What Pro and Enterprise add](./docs/editions.md)** — the long-form comparison behind the table below.

### Feature comparison

| | Community (Free) | Pro ($49/mo) | Enterprise ($2k+/yr) |
|---|:---:|:---:|:---:|
| **Network scanning** | | | |
| 27 scanner plugins (SSH, HTTP, TLS, DNS, SMB, RPC, mDNS, etc.) | ✅ | ✅ | ✅ |
| AI analysis (OpenAI, Claude, Ollama — your keys) | ✅ basic | ✅ enriched | ✅ enriched |
| Structured findings + SARIF + CSV export | ✅ | ✅ | ✅ |
| CTEM watch mode | ✅ basic | ✅ advanced | ✅ advanced |
| **Pro features** | | | |
| CVE matching + MITRE ATT&CK mapping | — | ✅ | ✅ |
| Risk scoring + prioritization | — | ✅ | ✅ |
| Exploit intelligence — **CISA KEV** + **FIRST EPSS** joined onto the CVE matches, exploit-first ordering (a KEV-listed MEDIUM outranks an unexploited CRITICAL); stores are operator-populated — no feed data ships | — | ✅ | ✅ |
| Parallel analysis agents | — | ✅ | ✅ |
| **Client reporting** — `report --format executive` renders a completed run as a self-contained, print-ready HTML report with optional cover-page branding (`--brand`); `--format jira` writes a Jira-importer CSV. ⚠️ The Jira import mapping is done in Jira and has **not been verified against a live Jira instance**. | — | ✅ | ✅ |
| **Enterprise — cloud scanning** | | | |
| 29 enterprise plugins — 28 cloud (AWS / Azure / GCP) + 1 network-scan zero-trust check | — | — | ✅ |
| Zero Trust assessment | — | — | ✅ |
| **Enterprise — compliance (8 frameworks)** | | | |
| SOC 2 (AICPA TSC 2017) — 10 covered + 4 partial controls | — | — | ✅ |
| HIPAA Security Rule §164.312 — Zero BAA required | — | — | ✅ |
| NIST CSF 2.0 Core — Subcategory-level mapping (106 of 107 Subcategories) | — | — | ✅ |
| PCI DSS v4.0.1 — Sub-requirement-level mapping for QSA RoC | — | — | ✅ |
| ISO/IEC 27001:2022 — per-Annex-A-code mapping + SoA discipline (93 Annex A controls) | — | — | ✅ |
| CIS Critical Security Controls v8 — per-Safeguard mapping + IG-cumulative discipline (153 Safeguards / 18 Controls) | — | — | ✅ |
| **GDPR Article 32 (Security of Processing)** — Art. 32 infrastructure substrate (4 covered + 5 partial + 2 OOS / 11 sub-measure units); **not GDPR compliance** · Art. 83(4) lower fine tier | — | — | ✅ |
| **NIST SP 800-171 Rev 2** — evidence substrate for **CMMC Level 2 preparation**; all 110 Rev 2 requirements enumerated (2 covered + 49 partial + 59 OOS). **Not a certification, not a FedRAMP authorization, no MET/NOT MET verdict, no SPRS score** | — | — | ✅ |
| Multi-framework `--compliance soc2,hipaa,nist-csf,pci-dss,iso-27001,cis-v8,gdpr,nist-800-171` from one scan | — | — | ✅ |
| **Enterprise — auditor-grade evidence** | | | |
| Evidence packs with SHA-256 chain-of-custody (RFC 3161 timestamps opt-in via `NSAUDITOR_TSA_URL`, exercised against a live TSA on both the npm path and the `:0.33.0` container image; retained images `:0.32.11` and earlier carry no `openssl`) | — | — | ✅ |
| Suppression workflow with approver identity verification (Ed25519 SIGNING reachable 0.35.0, proven 0.36.0, verified per approver holding **key material**) | — | — | ✅ |
| **Ed25519 evidence-pack signing** — `compliance sign-pack` signs the chain-of-custody envelope at an approval station with an **operator-held** key, so the scanning fleet stays keyless and authorship is relative to your own key custody, never a vendor attestation. `compliance verify-pack` establishes authorship from that operator-held key and re-hashes every artifact the envelope names, covering one framework envelope and the artifacts it enumerates — not the pack, not the directory. Verifiable offline with `openssl` alone. | — | — | ✅ |
| Chain-of-custody manifests | — | — | ✅ |
| SLA / MTTR tracking + compensating controls | — | — | ✅ |
| Recurring-scan attestation (Type II operating-effectiveness) | — | — | ✅ |
| WORM POSTURE VALIDATION on your own buckets (S3 Object Lock — SEC 17a-4 / FINRA 4511 substrate). The engine WRITING into the immutable store is built, **not reachable** | — | — | ✅ |
| **Enterprise — integration + deployment** | | | |
| GRC connectors — Vanta + Drata + Secureframe push (scan-time, opt-in) | — | — | ✅ |
| Tabletop simulation + SIEM correlation — built, **not reachable** (no caller) | — | — | 🚧 |
| Air-gapped **operation** once installed — offline licence validation (local ES256, no callback, every tier) and offline CVE matching under `NSAUDITOR_OFFLINE_ONLY=1`, which is the **Pro** intelligence engine. The `feed bundle` / `feed import` hand-carry pipeline (EE 0.37.0) moves the NVD feeds **you downloaded**; it needs the Enterprise **package** installed but is not licence-gated, so a Pro licensee can run it. | — | ✅ | ✅ |
| Air-gapped **DELIVERY** — the dependency-complete offline installation tarball, install script and checksums (EE 0.37.0), distributed **restricted**, amd64 only. No container image bundle ships and arm64 images remain WITHDRAWN. | — | — | ✅ |

**This repository is the Community Edition** — fully functional, MIT-licensed, no restrictions, no telemetry. Pro and Enterprise features ship via the [`@nsasoft/nsauditor-ai-ee`](https://www.nsauditor.com/ai/pricing) package and install alongside the CE binary once licensed.

→ **[Get Pro or Enterprise →](https://www.nsauditor.com/ai/pricing/)**

---

### Prefer to buy through AWS Marketplace?

Enterprise Edition is also available as an **[AWS Marketplace container listing](https://aws.amazon.com/marketplace/pp?sku=etar8knc8dx7bshizrrnnjbzi)** — same product, same local ES256 license key, billed through your AWS account (consolidated billing / EDP drawdown, procurement-friendly; custom Enterprise terms via AWS Private Offers). *The listing is public. If it doesn't resolve in your AWS region or account, [contact us](https://www.nsauditor.com/support.html) and we'll extend a Private Offer directly.*

How Marketplace fulfillment works (ZDE and air-gap preserved — no runtime AWS dependency at scan time):

1. **Subscribe** on the listing (tiers `base` / `growth` / `scale` mirror the 5 / 25 / unlimited-seat plans).
2. **Register** your email + AWS account ID at the URL shown in the listing's usage instructions — your **ES256 license key arrives by email**.
3. **Pull and run** the Docker image from the Marketplace registry (commands in the listing's usage instructions and your license email) with `NSAUDITOR_LICENSE_KEY=<your key>`. One tier-agnostic image — upgrades are just a new license key, never a new image. The container runs fully offline after that; billing lives in AWS, enforcement is your local key.

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

## MCP Server

> **Heads-up on AI-client fabrication.** Some MCP clients (notably Claude Desktop) can silently substitute AI-generated responses if a `tools/call` times out, instead of surfacing the failure. Every response from this server now ends with a `── Verified MCP call ──` footer and a UUID. Run `nsauditor-ai mcp verify-call <id>` to confirm a response is genuine before acting on it. Full background and workflow: [docs/mcp-verification.md](./docs/mcp-verification.md). When in doubt, generate compliance evidence via the CLI (`nsauditor-ai scan ...`), which has no MCP client in the path.

Expose scanning capabilities to AI assistants via [Model Context Protocol](https://modelcontextprotocol.io):

```bash
nsauditor-ai-mcp
# or
npx nsauditor-ai-mcp
```

The server registers **seven** tools and lists all seven to every client. The licence is
checked when a tool is CALLED, not when the list is served — so an unlicensed call returns
an explicit 🔒 refusal naming the tier it needs, never an empty result that reads as "nothing
found". A higher tier does not add tools; it unlocks the ones already in the list.

**Available on every tier:**

| Tool | Purpose |
|---|---|
| `scan_host` | Run a full plugin scan against a host — service detection, OS fingerprint, structured findings |
| `list_plugins` | List available scanner plugins with their IDs, priorities and requirements |
| `compliance_matrix` | Return the shipped coverage matrix for a framework — Covered / Partial / Out of scope, with the per-group out-of-scope reasons. **Needs the Enterprise pack installed**: the matrices are its data, so on a Community-only install this fails closed with an install instruction rather than returning an empty matrix (an empty matrix is what gets filled in with a guess) |

**Unlocked by Pro** (licence key + `@nsasoft/nsauditor-ai-ee`):

| Tool | Purpose |
|---|---|
| `probe_service` | Run one specific plugin against a single `host:port` |
| `get_vulnerabilities` | Look up known CVEs for a CPE (Common Platform Enumeration) string via the NVD API |

**Unlocked by Enterprise:**

| Tool | Purpose |
|---|---|
| `scan_cloud` | Audit one or more cloud accounts (AWS / GCP / Azure) using server-configured credentials; no network host. "Audit my AWS account" / "Audit my AWS and Azure accounts". |
| `get_findings` | Drill into the findings of the most recent `scan_cloud` run (per-provider session cache — not live state) |

> `scan_cloud` runs the requested clouds' plugins **concurrently** (default up to 20 at once, 25s per-plugin
> timeout) so a full multi-service cloud audit completes within Claude Desktop's ~60s tool-call limit. Tune with
> `CLOUD_SCAN_CONCURRENCY` (default 20) and `CLOUD_PLUGIN_TIMEOUT_MS` (default 25000) in the server env. The
> network `PLUGIN_TIMEOUT_MS` still governs `scan_host` / network scans. Read the result's **`findingsSummary`**
> (per-provider severity counts + a CRITICAL/HIGH list) for the findings; `audited:false` / `notes` / `pluginsRan:0`
> still mean a cloud was NOT audited (never a clean pass). Pass `providers:["aws"]` to audit only the cloud named.

> **Full all-region AWS coverage fits Desktop's limit automatically.** When you ask for "all regions" / "full
> coverage", the agent scans the enabled regions in small **region-group batches** (each within the ~60s window)
> rather than one long `regions:["all"]` call — so it completes without timing out, and you do **not** raise any
> timeout for it. Keep `CLOUD_PLUGIN_TIMEOUT_MS` **under** Desktop's ~60s tool-call cap (default `25000`; raise to
> ~`45000` only for very large accounts — a higher per-plugin cap can let one plugin run past Desktop's wall and
> cause a hard timeout). For unbounded multi-region scans use the **CLI** (`nsauditor-ai scan … --aws-region all`),
> which has no MCP tool-call cap — there you can raise `PLUGIN_TIMEOUT_MS` (e.g. `90000`) freely.

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
        "NSA_ENV_FILE": "~/envs/prod-aws.env",
        "AI_PROVIDER": "claude",
        "ANTHROPIC_API_KEY": "keychain:ANTHROPIC_API_KEY"
      }
    }
  }
}
```

The exact `NSA_MCP_AUTH_KEY` value to paste is printed by `nsauditor-ai mcp install-key` — on macOS it's the `keychain:NSA_MCP_AUTH_KEY` placeholder shown above; on Linux/Windows it's the literal key value (and you should `chmod 600` your config file).

- `NSA_MCP_AUTH_KEY` — **required** (see Authentication section above)
- `NSA_ALLOW_ALL_HOSTS=1` — required to scan private/RFC 1918 addresses (e.g., `192.168.x.x`)
- `PLUGIN_TIMEOUT_MS=5000` — reduces per-plugin timeout to 5s so the full scan completes within Claude Desktop's 60s MCP limit
- `CLOUD_SCAN_CONCURRENCY` — max cloud plugins run at once by `scan_cloud` (default 20).
- `CLOUD_PLUGIN_TIMEOUT_MS` — per-plugin timeout for `scan_cloud` (default 25000; independent of the network `PLUGIN_TIMEOUT_MS`). Keep it **under** Desktop's ~60s tool-call cap (raise to ~`45000` only for very large accounts); full all-region coverage is delivered by automatic region-batching, so it needs **no** timeout increase.
- `AI_PROVIDER` and API key — optional, enables AI-powered analysis of scan results

#### `NSA_ENV_FILE` — point the MCP server at an environment file

Instead of inlining every scan variable in the config above, set **`NSA_ENV_FILE`** to a
dotenv file and keep the cloud credentials, `CLOUD_PROVIDER`, and scan tuning there. To scan
a different account or cloud, change the one path (or swap the file) and restart Claude Desktop —
no JSON editing.

```bash
# ~/envs/prod-aws.env   (chmod 600 — this holds credentials)
CLOUD_PROVIDER=aws
AWS_ACCESS_KEY_ID=AKIA...
AWS_SECRET_ACCESS_KEY=...
NSA_ALLOW_ALL_HOSTS=1
PLUGIN_TIMEOUT_MS=5000
```

- The file is loaded at server startup; values in it **override** the same keys in the config `env` block.
- **Fail-fast:** if the path is missing or points at an AWS credentials/INI file, the server refuses
  to start (it will not silently fall back to ambient credentials and scan the wrong account). The
  error is written to the MCP server's stderr log.
- **The file is the authoritative scan target:** ambient provider credentials (e.g. an old account's
  `AWS_*` keys still in the config `env` block) that the file does **not** set are cleared, so a partial
  file can't silently scan a leftover account. Instance-role / ADC identity is untouched.
- `NSA_MCP_AUTH_KEY` and `NSAUDITOR_LICENSE_KEY` are resolved **before** the file and must stay
  inline (or in `~/.nsauditor/.env`); if present in `NSA_ENV_FILE` they are ignored.

### Claude Code Setup

```bash
nsauditor-ai mcp install-key   # required before MCP server will start
claude mcp add nsauditor-ai \
  --env NSA_MCP_AUTH_KEY=keychain:NSA_MCP_AUTH_KEY \
  -- npx nsauditor-ai-mcp
```

To target an environment via the file, add it as an env value:

```bash
claude mcp add nsauditor-ai \
  --env NSA_MCP_AUTH_KEY=keychain:NSA_MCP_AUTH_KEY \
  --env NSA_ENV_FILE=~/envs/prod-aws.env \
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
nsauditor-ai feed bundle --from <dir-of-NVD-feeds> --out <bundle.json.gz> [--kev <f>] [--epss <f>]
nsauditor-ai feed import --file <feed-or-bundle> [--cache-dir <d>] [--extras-dir <d>] [--append]   # the feeds you downloaded
nsauditor-ai compliance <attest|suppress|review|renew|keygen|sign-pack|verify-pack>   (Enterprise)
nsauditor-ai report --from <dir> --format executive|jira [--run <id>] [--brand <brand.json>] [--out <path>] [--allow-partial]   (Pro/Enterprise)
nsauditor-ai mcp
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
| `--watch` | CTEM continuous **alerting** loop — re-scan on `--interval`, diff, webhook on `--alert-severity`. Not an evidence cadence: no retention, no cross-run aggregation, skips SARIF/CSV/Markdown + `--fail-on`, dies with the process. Use a scheduler for SOC 2 Type II history. | `false` |
| `--interval <min>` | Rescan interval in minutes (requires `--watch`) | `60` |
| `--webhook-url <url>` | Webhook URL for delta alerts | — |
| `--alert-severity <sev>` | Minimum severity for webhook alerts | `high` |
| `--compliance <fw>` | Compliance framework to map findings into. Accepts CSV for multi-framework runs (e.g. `soc2`, `hipaa`, `nist-csf`, `pci-dss`, `iso-27001`, `cis-v8`, `gdpr`, `nist-800-171`, or any combination like `soc2,hipaa,nist-csf,pci-dss,iso-27001,cis-v8,gdpr,nist-800-171` — `all` expands to the same eight). **Enterprise license required.** Supported frameworks as of EE 0.40.0 — **eight**: `soc2` (AICPA TSC 2017) + `hipaa` (HIPAA Security Rule §164.312 Technical Safeguards) + `nist-csf` (NIST Cybersecurity Framework 2.0 Core, CSWP 29 Feb 2024) + `pci-dss` (PCI DSS v4.0.1, PCI SSC June 2024 errata) + `iso-27001` (ISO/IEC 27001:2022, ISO + IEC October 2022) + `cis-v8` (CIS Critical Security Controls v8, CIS May 2021 / v8.1 errata June 2024) + `gdpr` (GDPR Article 32 / Security of Processing, Regulation (EU) 2016/679 — Art. 32 infrastructure substrate, **not** GDPR compliance) + `nist-800-171` (NIST SP 800-171 Rev 2 — evidence substrate for **CMMC Level 2 preparation**, **not** a CMMC certification, **not** a FedRAMP authorization, and no MET/NOT MET determination or SPRS score). See `@nsasoft/nsauditor-ai-ee` README for per-framework coverage details. | — |
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

### `report` command (Pro/Enterprise)

`nsauditor-ai report --from <dir> --format executive|jira` turns a completed scan run under `--from` into a client-facing deliverable — an HTML report a consultant sends to their customer, or a Jira-importer CSV.

**What it reads.** A scan record keeps findings in more than one place, and the report reads all of them: each plugin's `result.findings` (an array, or a dict of categories as the DNS auditor emits), zero-trust dimension findings, per-port TLS issues, and the **finding queue** (`scan_finding_queue.json`) that carries the CVE/KEV/EPSS-enriched entries. `result.data` is deliberately NOT read — on a network scan it holds probe telemetry, not findings. The container inventory is enforced by a census: a container holding findings that no reader opens fails the build rather than rendering as a clean report.

| Flag | Description | Default |
|---|---|---|
| `--from <dir>` | The scan `--out` directory holding the run's record and per-host evidence | *required* |
| `--format executive` | Self-contained, print-ready HTML report; no external network reference other than an `http(s)`/`mailto` `<a href>` | — |
| `--format jira` | Jira-importer CSV (`Summary`/`Description`/`Priority`/`Labels`/`External ID`); the import mapping is done in Jira and has not been verified against a live Jira instance. **`pass`-tier records are EXCLUDED** — a Jira issue is a work item and a passing check is not work; every other tier is kept, INFO included, because INFO carries the evidence gaps and scope boundaries. Passing checks appear in the `executive` report under their own **PASS** tier. | — |
| `--run <id>` | Report a specific run id instead of the newest one under `--from` | newest run |
| `--brand <brand.json>` | Cover-page branding (company name, prepared-by, contact, logo) — `--format executive` only | unbranded |
| `--out <path>` | Write to this path instead of `report_<runId>.<ext>` beside the run record | `report_<runId>.<ext>` |
| `--allow-partial` | Render even if some requested hosts were never written, or the run never recorded completion — the caveat is stated on the cover, never hidden | `false` |

A value-less `--from`/`--brand`/`--run`/`--out` (nothing after the flag, or a shell glob that swallowed the argument) is a fatal error, not a silent default.

**Exit contract** — `0` a report was rendered · `1` fix the RUN (no run record under `--from`, or an
incomplete run without `--allow-partial`) · `2` fix the REQUEST or its environment (an unknown or
missing flag value, an unwritable `--out`, a `--brand` file that is refused).

⚠️ `--brand` with `--format jira` is **refused**, not ignored: a Jira CSV has nowhere to put branding,
and silently dropping a flag the caller passed is how a report goes out unbranded without anyone
noticing.

```bash
nsauditor-ai report --from out/2026-08-26 --format executive --brand brand.json --out report.html
nsauditor-ai report --from out/2026-08-26 --format jira
```

#### The `brand.json` file

`--brand` takes a small JSON object. Every field is optional; omit the file entirely and the report
renders unbranded with the default title.

```json
{
  "title": "Q3 External Perimeter Review",
  "companyName": "Acme Manufacturing GmbH",
  "preparedBy": "J. Rivera, Security Consulting LLC",
  "contact": "security@example.com",
  "logoPath": "acme-logo.png"
}
```

| field | type | default | notes |
|---|---|---|---|
| `title` | string | `Network Scan Report` | Replaces the report's headline. |
| `companyName` | string | *(empty)* | The client the report is prepared **for**. |
| `preparedBy` | string | *(empty)* | The consultant or firm preparing it. |
| `contact` | string | *(empty)* | Free text — an address, an email, a phone number. |
| `logoPath` | string | *(none)* | A **local** PNG or JPEG, resolved relative to the brand file's own directory. Embedded into the HTML as a data URI. |

**`logoPath` is deliberately restrictive, and each refusal protects the report's core promise —
that it opens with no external network reference of any kind:**

- **A URL is refused and never fetched.** A remote logo is egress at render time and a tracking
  pixel every time your client opens the file.
- **A UNC share (`\\host\share\...`) is refused** for the same reason: it is a network reference.
- **SVG is refused.** SVG is markup and can carry a script, which would break the report's
  no-script guarantee from inside the image. Use PNG or JPEG.
- **The path must stay inside the brand file's own directory** — `../` escapes are refused, checked
  both as typed and again after symlinks are resolved.
- **2 MB maximum**, and the format is detected by **magic bytes, not by file extension** — renaming
  `logo.svg` to `logo.png` does not get it past the check.
- **An empty string is read as "no logo"**, the same as omitting the key, so a generated
  `brand.json` that emits `""` is not an error.

A brand file that cannot be read, is not valid JSON, is not a JSON object, or whose `logoPath` is
refused is a **fatal error** — the report is not written. A flag you passed is never silently
dropped, because that is how a report goes out unbranded without anyone noticing.

⚠️ `--brand` applies to `--format executive` only. Passing it with `--format jira` is **refused**,
not ignored: a CSV has nowhere to put a cover page.

---

## Pro & Enterprise Activation

After purchasing at [nsauditor.com/ai/pricing](https://www.nsauditor.com/ai/pricing), you'll receive an email with your license key and an npm install command. Two steps:

```bash
# 1. Install both packages (one-time, token included in email — the base package carries the CLI)
npm install -g nsauditor-ai
npm install -g @nsasoft/nsauditor-ai-ee --//registry.npmjs.org/:_authToken=npm_xxxxx

# 2. Install your license key — identical on macOS, Linux and Windows, no environment variable needed
nsauditor-ai license install "pro_eyJhbGci..."
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

### Pro/Enterprise Plugins

Pro and Enterprise add 29 cloud and posture auditors on top of the Community scanners — AWS, Azure and GCP, mapped to eight compliance frameworks. They require `@nsasoft/nsauditor-ai-ee` and a licence.

**→ [Pro / Enterprise plugin catalog](./docs/enterprise-plugins.md)** — every plugin with its id, what it audits, and the AWS region-scoping rules for the regional auditors (`--aws-region <one|csv|all>`).

See [Pro & Enterprise Activation](#pro--enterprise-activation) to install a licence.

## GRC Connectors (Vanta, Drata, Secureframe)

*Enterprise feature. Requires `@nsasoft/nsauditor-ai-ee`.*

Every compliance scan already produces a GRC-ready JSON evidence artifact. The **GRC connectors** take the next step: they map each NSAuditor compliance finding to your GRC platform's own evidence/test records and **push them at scan time** — so your Vanta, Drata, or Secureframe workspace reflects the latest cloud posture without a manual export/import round-trip.

**Opt-in, and Zero-Data-Exfiltration by default.** The push is off unless you set the environment variables below. When it runs, egress is redaction-gated: resource identifiers can be hashed or removed, the persisted audit log stores a body **fingerprint** (never the raw payload), and your API token is never written to any artifact. Nothing leaves your infrastructure that you didn't opt into.

```bash
# Enable the scan-time push (Enterprise)
COMPLIANCE_GRC_PROVIDER=vanta        # or: drata | secureframe
COMPLIANCE_GRC_TOKEN=<your API key>  # never serialized to artifacts
# Optional:
# COMPLIANCE_GRC_REDACTION=hash      # off | hash | remove  (egress identifier redaction)
# COMPLIANCE_GRC_CONTROL_MAP=/path/to/config.json  # provider config: Vanta control→test map, Drata connection ({connectionId, resourceId, schemaMap}), or Secureframe ({workspaceId, collectionId, schemaMap})
```

| Platform | Status | Model |
|---|---|---|
| **Vanta** | Connector + scan-time activation shipped | Maps findings to Vanta test results; suppression-aware outcome mapping (pass / fail / passed-with-compensating-control), framework-dimensioned idempotency keys, retry with rate-limit backoff, circuit breaker |
| **Drata** | Connector library shipped | Pushes structured records via Drata **Custom Connections**; your Drata **Test Builder** rules (Advanced/Enterprise plans) evaluate them — the connector delivers evidence, your rules do the evaluation |
| **Secureframe** | Connector library shipped (early-access) | Pushes structured records to a workspace evidence collection; **your** Secureframe rules evaluate them — the connector carries the control `status` verbatim, it does not compute pass/fail. API shape published-assumed; live-tenant validation deferred (partner intake) |

**Reliability + audit-integrity built in:** idempotent retries (a network-timed-out push won't create duplicate records), per-attempt + total-duration timeout caps, a consecutive-failure circuit breaker, token redaction across every log and error path, and a durable per-control push audit log written next to your scan artifacts.

> **Honest status.** The Vanta, Drata, and Secureframe connectors are shipped, opt-in, and covered by an extensive test suite. **Live validation against production Vanta / Drata / Secureframe tenants is in progress** as partner onboarding proceeds — until it completes, treat production use as early-access and validate against your own tenant first. This is a single-workspace, operator-configured connector; it is not a multi-tenant managed sync. (Secureframe's API shape is published-assumed pending partner intake; its idempotency keys are SENT but vendor-side dedup is unverified.)

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
- **Pro** — intelligence-enriched prompts (CVE matches, MITRE ATT&CK technique annotations, composite risk scores injected into the prompt). Same API call, better-grounded output
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

## Configuration

Configuration is entirely environment-based — a `.env` file, `--env <file>`, or the shell. No config is required for a default scan.

**→ [Configuration reference](./docs/configuration.md)** — every environment variable, its default and its effect.

The two that change behaviour most: `NSAUDITOR_OFFLINE_ONLY=1` forbids outbound CVE lookups and reads a local NVD store instead (reporting an explicit coverage gap rather than a silent clean), and `OPENAI_API_KEY` / `ANTHROPIC_API_KEY` / a local Ollama endpoint enable the opt-in AI analysis pass.

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

## Tests

Run all 1582 tests:

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

**Design patterns:** Factory (PluginManager.create) · Strategy (orchestrated/legacy execution) · Context (shared state) · Adapter (plugin conclude()) · Guard Clause (requirement gating) · Capability gating (CE/Pro/EE) · Semaphore (concurrency control) · Delta (scan history diff) · Boundary Guard (SSRF/injection protection) · Finding Queue (structured intermediate format) · Parallel Agents (concurrent specialized analysis)

---

## Privacy & Security

NSAuditor AI is built on a **Zero Data Exfiltration (ZDE)** architecture:

- **No telemetry.** No analytics. No usage tracking. No phone-home.
- **No data processing.** Nsasoft US LLC never sees, stores, or processes your scan results.
- **AI is opt-in.** External AI calls use your own API keys. Redaction runs locally first.
- **License validation is offline.** JWT signature verified locally with an embedded public key.
- **Air-gappable, once configured for it.** Scanning, analysis, license verification and evidence-pack generation all run with no outbound network access; Enterprise adds offline CVE matching from a local NVD store under `NSAUDITOR_OFFLINE_ONLY=1`, which emits an explicit coverage gap rather than a silent clean when the store cannot answer. Stated precisely because it matters operationally: a **default** scan still attempts NVD egress unless that variable is set. The other outbound paths — AI enrichment, the GRC push, the continuous-monitoring webhook, the opt-in RFC 3161 timestamping path (`NSAUDITOR_TSA_URL`, no default ever), and the AWS KMS signing path that ships but is not yet wired — are opt-in and off by default; the paths that are *not* optional are the scan target itself, your own cloud provider's APIs during a cloud scan, and DNS resolution of the target. All of them are enumerated with their trigger and default state in the egress register (EE `docs/architecture.md` §14.1.1), which is generated from code and guarded in both directions — deliberately, so this sentence never again has to carry a completeness claim that prose alone cannot keep true. Populating the local NVD store is the operator's; no feed data is delivered with the product. The prior absolute form of this bullet — *"Fully air-gappable. Every feature works without internet access (Enterprise includes offline NVD feeds)"* — is **WITHDRAWN** (CE 0.2.33): quoted here so the withdrawal record stays on this page now that release history lives in the [CHANGELOG](./CHANGELOG.md).

Nsasoft US LLC is not a data processor, data controller, or business associate under any data protection regulation. You own and control all data produced by NSAuditor AI.

---

## License

**MIT** — see [LICENSE](LICENSE) for the full text.

© 2024-present Nsasoft US LLC. "NSAuditor" and "NSAuditor AI" are trademarks of Nsasoft US LLC.

The Pro and Enterprise features available via `@nsasoft/nsauditor-ai-ee` are licensed under a separate proprietary license. See [www.nsauditor.com/ai/pricing](https://www.nsauditor.com/ai/pricing) for details.
