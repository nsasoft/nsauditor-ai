# NSAuditor AI

**Security Intelligence Without Data Exposure.**

A modular, AI-assisted network security audit platform that scans, understands, prioritizes, and tracks vulnerabilities — without ever requiring your data to leave your infrastructure.

[![npm](https://img.shields.io/npm/v/nsauditor-ai.svg)](https://www.npmjs.com/package/nsauditor-ai)
[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Node.js 20+](https://img.shields.io/badge/node-20%2B-green.svg)](https://nodejs.org)
[![Tests](https://img.shields.io/badge/tests-506%20passing-brightgreen.svg)](#tests)

---

NSAuditor AI is the open-source core of a privacy-first security intelligence platform built by [Nsasoft US LLC](https://www.nsauditor.com/ai/). It orchestrates 20+ specialized scanning plugins against target hosts, fuses their results through an intelligent concluder, and optionally produces AI-powered vulnerability reports — all running entirely on your machine.

**Zero Data Exfiltration by design.** NSAuditor AI works fully offline. AI analysis, CVE correlation, and continuous monitoring all happen locally. External calls (to AI APIs, NVD, etc.) are opt-in and use your own API keys. We never see your scan data.

## What's New (0.1.36) — cryptographic per-call sentinel UUID (hallucination becomes mathematically detectable)

The version-block comparison shipped in 0.1.34/0.1.35 catches lazy hallucinations, but a sufficiently capable AI client can still copy a previously-seen version block from chat context and pass off a fabricated response. **0.1.36 closes that gap** with a per-call cryptographic sentinel that the AI cannot fake.

**How it works:**
- Each `tools/call` invocation mints a fresh server-side UUID via Node's `crypto.randomUUID()`.
- The UUID is appended to the response text under a `── Verified MCP call ──` footer.
- The same UUID is persisted to `~/.nsauditor/mcp-calls.log` (mode 0600, JSON-per-line) **before** the response is returned.
- A new CLI subcommand `nsauditor-ai mcp verify-call <uuid>` greps the log:
  - **Found** → the UUID was issued by your local MCP server, so the response bearing it is genuine.
  - **Not found** → the UUID was never issued, so the entire response was fabricated by the AI client.

**Customer verification workflow (10 seconds):**

```bash
# 1. In Claude Desktop, ask Claude to use any MCP tool (e.g., list_plugins).
# 2. The response ends with:
#       ── Verified MCP call ──
#       call_id: 3f8a1b22-7e44-4c91-9d62-12bd0a4f5e91
#       Verify: nsauditor-ai mcp verify-call 3f8a1b22-7e44-4c91-9d62-12bd0a4f5e91
# 3. Run that exact verify command in your terminal:
nsauditor-ai mcp verify-call 3f8a1b22-7e44-4c91-9d62-12bd0a4f5e91
# ✓ Verified MCP call → genuine
# ✗ call_id not found  → fabricated (response was AI-generated, not from the MCP server)
```

This makes the hallucination detection unfakeable in principle: the AI client has no access to your local Node `crypto.randomUUID()` output, and the sentinel is generated **at the moment the call hits the server** — there's no way to forge a UUID that will appear in a log file the client cannot read or write.

The 0.1.34/0.1.35 version-block check remains as the first line of defense (instant visual mismatch). The 0.1.36 UUID is the cryptographic ground truth for any response you'd act on.

`scan_host`, `probe_service`, `get_vulnerabilities`, and `list_plugins` all mint sentinels — even Pro-tier denials carry a UUID so customers can prove the call reached the server.

```bash
npm install -g nsauditor-ai@0.1.36
```

---

## What's New (0.1.35) — CLI provenance footer matches MCP response (so the comparison actually works)

0.1.34 added the version-provenance block to the MCP server's `list_plugins` response, but **the CLI baseline (`license --plugins` / `license --status`) didn't show versions** — so customers couldn't easily compare. 0.1.35 fixes that asymmetry.

Both CLI commands now emit an identical provenance block:

```
── Installation provenance ──
  nsauditor-ai (CE):              0.1.35
  @nsasoft/nsauditor-ai-ee (EE):  0.3.4 (loaded)
```

**Customer hallucination-detection workflow (5 seconds, no log archeology):**

1. In Claude Desktop: ask "list plugins" → receive a response that should end with the provenance block
2. In your terminal: run `nsauditor-ai license --plugins`
3. Compare the two `── Installation provenance ──` blocks character-for-character
4. **Match** → real MCP `tools/call` happened, response is trustworthy
5. **Mismatch / missing block** → Claude fabricated the response (see CE 0.1.33 advisory)

This is the v1 mitigation; the v2 (Thread L Phase 2) adds per-call cryptographic sentinel UUIDs that the customer can grep against the server log directly. v1 catches the common case where Claude either omits the block entirely (unlikely to fabricate the new structure verbatim) or includes a stale version pulled from training data.

---

## What's New (0.1.34) — list_plugins now embeds CE+EE versions for hallucination detection

Companion to the 0.1.33 advisory. The `list_plugins` MCP tool's response now appends the actual installed CE + EE version numbers, so customers can verify a Claude Desktop response in **5 seconds** without log archeology:

```
── Installation provenance (verify against your shell) ──
nsauditor-ai (CE):              0.1.34
@nsasoft/nsauditor-ai-ee (EE):  0.3.4 (loaded)
Verify: nsauditor-ai --version  &&  npm list -g @nsasoft/nsauditor-ai-ee
If versions in this response don't match your shell, the response was
AI-generated rather than retrieved from the MCP server (see CE 0.1.33 advisory).
```

How it works as a hallucination detector:
- The MCP server reads `process.execPath`'s package.json + tries to resolve `@nsasoft/nsauditor-ai-ee/package.json` at request time. Both are real machine-specific values.
- Claude Desktop fabricated responses in the wild have shown stale version numbers from training data, missing version lines entirely, or different counts each time the same question is asked (observed 32→32→31 plugin counts in three consecutive hallucinations on 2026-05-10).
- A real tool response will exactly match `nsauditor-ai --version` + `npm list -g @nsasoft/nsauditor-ai-ee`. Mismatch = hallucinated.

This is a v1 mitigation — the v2 (Thread L in `tasks/todo.md`) adds per-call cryptographic sentinel UUIDs that the customer can grep against the server log.

---

## What's New (0.1.33) — ⚠ MCP integration with Claude Desktop is unreliable

**Critical advisory for customers using NSAuditor AI through Claude Desktop's MCP integration.** During the maintainer's own integration test on 2026-05-10, we discovered that **Claude Desktop's AI fabricates scan results, plugin lists, vulnerability findings, and tier information without actually invoking the MCP tools** for our specific server. Other MCP servers in the same Claude Desktop config receive real `tools/call` invocations; ours does not.

**Empirical evidence**:
- `~/Library/Logs/Claude/main.log` shows multiple permission grants for `mcp__nsauditor-ai__list_plugins` and `mcp__nsauditor-ai__scan_host` on 2026-05-10
- `~/Library/Logs/Claude/mcp-server-nsauditor-ai.log` shows **zero** `"method":"tools/call"` entries on the same day
- Other servers in the same config logged real calls (ns-ftp:29, wp-publisher-netsecmag:14, ai-pr-distribution:6, sendgrid:3)
- When asked to scan 1.1.1.1, Claude Desktop returned a detailed report with plugin breakdown + Zero Trust score — entirely fabricated

**Likely cause**: Claude Desktop's MCP client appears to time out our server (which loads PluginManager + 32 plugins + license verify before responding). Claude (the AI) silently substitutes fabricated responses from training rather than surfacing the timeout. The hallucinations are convincingly formatted and indistinguishable from real output without log inspection.

**Mandatory verification — for any output you'd act on**:

```bash
# Tier check (ground truth bypassing Claude AI synthesis):
nsauditor-ai mcp tier

# Real plugin scan (always hits the network):
nsauditor-ai scan --host <X> --plugins all --out <dir>

# Confirm Claude Desktop actually called the MCP server:
grep '"method":"tools/call"' ~/Library/Logs/Claude/mcp-server-nsauditor-ai.log | tail -5
# If main.log shows recent permission grants for nsauditor-ai tools but
# THIS file shows no matching tools/call entries, the responses you saw
# in Claude Desktop were AI-generated, NOT real.
```

**SOC 2 evidence and any compliance report MUST be generated via the CLI** — never via the Claude Desktop MCP integration — until this is resolved upstream. We're working on it (Thread L in `tasks/todo.md`): a per-call cryptographic sentinel, lazy-loaded plugin discovery to reduce startup latency, a `mcp verify-recent-call` diagnostic, and a bug report to Anthropic.

This advisory will be removed when the upstream Claude Desktop MCP routing issue is fixed and we ship a CE release whose `tools/call` invocations land reliably.

---

## What's New (0.1.32) — Claude Desktop integration overhaul + ground-truth diagnostics

The 0.1.32 line bundles three operational improvements driven by real customer-onboarding friction surfaced during the developer's own Claude Desktop integration test (2026-05-10):

- **`nsauditor-ai mcp install-key` now auto-generates a machine-specific Claude Desktop config snippet.** Reads `process.execPath` (the Node binary actually running) and derives the script path from `import.meta.url` — the printed JSON has absolute paths that work whether you're on system Node, homebrew, nvm, fnm, local-project install, Linux, or Windows. No install-type detective work, no PATH-misalignment failures. On macOS, the snippet uses `keychain:` indirection for **both** auth and license — secrets never land in the world-readable Claude Desktop config file.
- **License `keychain:` indirection.** `loadLicense()` and `resolveLicenseKey()` honor the `keychain:LABEL` prefix on the env-supplied value (mirrors the EE-SEC.1 MCP-auth pattern). Operators can put `"NSAUDITOR_LICENSE_KEY": "keychain:NSAUDITOR_LICENSE_KEY"` in their Claude Desktop env block; the JWT stays in macOS Keychain. Backward-compat: literal JWTs continue to work unchanged.
- **`nsauditor-ai mcp tier` ground-truth subcommand.** Customer-side check that prints the EXACT tier the spawned MCP server resolves to. We discovered Claude Desktop reports of "Current tier: CE" despite verified Pro/Enterprise license were caused by Claude (the AI) **synthesizing the tier text from training data + context** instead of actually calling `list_plugins` via MCP. The MCP server's resolution was always correct. `mcp tier` bypasses Claude's interpretive layer — paste the output into a support ticket to distinguish "MCP genuinely broken" from "Claude misreading."
- **MCP key rotation cadence (Thread I).** Optional 90-day rotation soft warning at server startup + `mcp status` (override via `NSA_MCP_AUTH_KEY_ROTATION_DAYS`, clamped to [7, 365]). SOC 2 CC6.1/CC6.7 reviewers expect a credential-rotation cadence; an unrotated MCP auth key is treated the same way as an unrotated IAM access key.
- **Keychain-locked vs Keychain-empty distinction.** New `keychain-locked` source variant in `mcp status` for headless macOS / SSH-only CI runners — instead of falling through silently to "unconfigured", operators get an actionable error with three GUI-free workarounds.
- **Atomic file writes** for `~/.nsauditor/.env` (`.tmp` + POSIX-rename) so concurrent readers + crash recovery never observe a truncated file.
- **Auto-mirror license file→Keychain on `mcp install-key`** (macOS) when the license is configured in `~/.nsauditor/.env` but absent from Keychain. Lets the printed snippet's `keychain:` indirection actually resolve, with original storage location preserved unchanged.

**Breaking change for existing 0.1.31 operators**: nothing breaks, but the recommended Claude Desktop config snippet has changed. Re-run `nsauditor-ai mcp install-key` after upgrading to get the new auto-generated snippet with absolute paths + license indirection. Old configs continue to work.

```bash
npm install -g nsauditor-ai@0.1.32
nsauditor-ai mcp install-key   # prints the new snippet — paste into Claude Desktop config
nsauditor-ai mcp tier          # confirm the actual MCP server tier (ground truth)
```

See [Authentication](#authentication-required-new-in-0131) and [Troubleshooting MCP authentication](#troubleshooting-mcp-authentication) for full setup + diagnostics.

---

## What's New (0.1.31) — security release

**MCP server authentication is now required.** Pre-0.1.31, the local MCP server (stdio transport) accepted any incoming JSON-RPC frames — any process running as your user could spawn it and use the Pro/Enterprise tools (which include the AWS-talking shadow-admin path detectors that ship in `@nsasoft/nsauditor-ai-ee@0.3.4`). 0.1.31 closes this gap with a per-operator shared-secret check at startup.

**Breaking change for existing operators**: after upgrading, run `nsauditor-ai mcp install-key` once. Without this step, the MCP server refuses to start and Claude Desktop will report a connection failure. The error message points back at this command.

```bash
npm install -g nsauditor-ai@0.1.31
nsauditor-ai mcp install-key   # generates a 256-bit key, persists it, prints Claude Desktop config snippet
```

**What's in the box (EE-SEC.1):**

- `nsauditor-ai mcp install-key` — generates a 256-bit auth key, stores it in macOS Keychain (or `~/.nsauditor/.env` mode 0600 elsewhere), prints a paste-ready Claude Desktop config snippet. Run once per machine.
- `nsauditor-ai mcp status` / `print-key --confirm` / `rotate-key --confirm` — inspect, reveal (TTY-only by default), and rotate the key.
- **`keychain:` indirection on macOS** — the printed config snippet uses `"NSA_MCP_AUTH_KEY": "keychain:NSA_MCP_AUTH_KEY"` instead of the literal key. The MCP server resolves the placeholder at startup; **the secret never lands in your `claude_desktop_config.json`** (which is mode 0644 on macOS by default — readable by other local users and any sandboxed app). On Linux/Windows where there's no Keychain equivalent, the snippet falls back to the literal key with a `chmod 600` warning.
- **`NSA_MCP_AUTH_DISABLE=1`** escape hatch for CI / dev — emits a stderr warning every startup so you don't forget; a louder warning fires when DISABLE is set AND no key was ever installed.
- Multi-source resolver mirrors the existing license-key pattern: env → Keychain → file. Constant-time key comparison via `crypto.timingSafeEqual`. Two-reviewer cycle (general code review + network-security-audit lens) caught and folded 2 CRITICAL + 5 MEDIUM findings same-session before commit; full threat model documented in [`utils/mcp_auth.mjs`](./utils/mcp_auth.mjs).

See the [MCP Server § Authentication section](#authentication-required-new-in-0131) for the full setup walkthrough, troubleshooting, and the threat-model table.

---

## What's New in Enterprise Edition (0.3.3)

The Enterprise Edition (`@nsasoft/nsauditor-ai-ee`) shipped a 0.3.3 point release on 2026-05-08. CE stays at 0.1.30 — no bump required, the EE upgrade is single-line: `npm install -g @nsasoft/nsauditor-ai-ee@latest`. The release closes a Critical false-clean SOC 2 reporting bug that mirrored the AWS-side bug fixed in 0.3.2 — this time in the Azure cloud scanner — and extends mapped SOC 2 coverage to multi-cloud:

- **Azure plugin (022) finding-shape rewrite** — the EE-0.3.2.1 cloud-finding harvester only recognized one canonical shape (`{resource, severity, issues[]}`); plugin 022 was emitting `{severity, finding, resource}` (singular `finding`). Findings reached the engine but were silently dropped — Azure customers running `--compliance soc2` saw "6/6 covered controls passing" against subscriptions with real RBAC + NSG + Storage issues. Caught at internal dogfood against a live Azure subscription.
- **GCP plugin (021) preventive shape port** — plugin 021 had the same `{finding}` singular shape; pre-emptively migrated to the canonical shape so the same bug doesn't re-emerge for GCP customers in v0.4.0 when GCP `mapsToFindings` rules ship.
- **Azure → SOC 2 mapping rules added** — RBAC `Owner | Contributor | User Access Administrator at subscription scope` → CC6.1 (3 patterns); NSG `0.0.0.0/0 → port` anchored regex → CC6.6; Storage `allowBlobPublicAccess` + `enableHttpsTrafficOnly` → C1.1. CC6.1, CC6.6, and C1.1 now have *both* AWS-side and Azure-side evidence rows — actual multi-cloud SOC 2 evidence.
- **Drift detector extended to all three cloud plugins** — every `azure-cloud-scanner` `titlePattern` in `soc2.json` is now asserted to match at least one canonical issue string the plugin emits, and vice versa. The class-of-bug that produced two false-clean variants in successive releases is now structurally closed.
- **Pre-publish gate fixes** — `@azure/arm-authorization` peer-dep was pinned at `^10.0.0` (latest published is 9.0.0; clean installs would have failed); `@azure/arm-storage` was missing from `optionalDependencies` (Storage audit silently no-op'd on clean install). Both caught at the pre-publish clean-tarball smoke and corrected before ship.

See [EE README](https://www.npmjs.com/package/@nsasoft/nsauditor-ai-ee) for the full 0.3.3 changelog and Azure scan walkthrough.

---

## What's New (0.1.30)

The 0.1.30 line is a paired release with `@nsasoft/nsauditor-ai-ee@0.3.2` that closes the customer-onboarding gap and a critical false-clean SOC 2 reporting bug:

- **`nsauditor-ai license install <KEY>`** — verifies the JWT *before* persisting; writes to macOS Keychain or `~/.nsauditor/.env` (mode 0600) depending on platform. Three-line install flow: `npm install -g` → `license install` → `license --status`. No more shell-rc edits.
- **Multi-source license loader** — `loadLicense()` resolves keys from env var → platform Keychain → `~/.nsauditor/.env`, in that order. CI/CD env-var override still wins.
- **`nsauditor-ai license --plugins`** — real enumeration of discovered plugins, grouped by source (CE / EE / custom), with active-or-required-tier status.
- **`nsauditor-ai --version` / `-v`** — prints version and exits 0 (parallel to `--help`'s discovery-flag UX).
- **Cloud-sentinel SSRF bypass** — `--host aws|gcp|azure` no longer requires `NSA_ALLOW_ALL_HOSTS=1`. The sentinel literals route to EE cloud-scanner plugins via the provider's API; the SSRF guard's RFC 1918 / loopback protection is preserved for real network targets.
- **EE-0.3.2.1 hard dep** — CE forwards the per-plugin `results` array to `enrichScan()`. Without this, EE 0.3.2's cloud-finding harvester sees nothing and produces false-clean SOC 2 reports against AWS accounts. EE emits a runtime version-skew warning when this opt is missing.

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
| SOC 2 compliance (8 covered + 5 partial controls; AWS + Azure evidence streams) | — | — | ✅ |
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

| ID | Name | Tier | Purpose |
|---|---|---|---|
| 020 | AWS Cloud Scanner | Enterprise | Security group + IAM policy analysis |
| 021 | GCP Cloud Scanner | Enterprise | Firewall rules + IAM bindings |
| 022 | Azure Cloud Scanner | Enterprise | NSG rules + RBAC role assignments + Storage account hardening; SOC 2 mapping (CC6.1, CC6.6, C1.1) shipped in EE 0.3.3 |
| 023 | Zero Trust Checker | Enterprise | Segmentation, encryption, identity, lateral movement scoring |
| — | SOC 2 Compliance Engine | Enterprise | AICPA TSC 2017 control mapping, chain-of-custody, RFC 3161 timestamps, suppression workflow |
| — | SLA & MTTR Tracking | Enterprise | Per-severity SLA targets, compensating-control flow, finding lifecycle |
| — | Recurring-Scan Attestation | Enterprise | Multi-scan chronological matrix, cadence gap detection, scope drift (CC8.1) |
| — | GRC Platform Connector | Enterprise | Native API push to Vanta with retry/backoff, idempotency, rate-limit handling |
| — | WORM Evidence Storage | Enterprise | S3 Object Lock COMPLIANCE-mode, resource redaction, SHA-256 manifest |
| — | Tabletop Simulation | Enterprise | Probe-event manifest + SIEM detection correlation, configurable coverage bands |

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

> ## ⚠ CRITICAL ADVISORY (2026-05-10) — Claude Desktop hallucinates responses for this MCP server
>
> When you use NSAuditor AI through **Claude Desktop's** MCP integration, the AI may **fabricate scan results, plugin lists, vulnerability findings, and tier information without actually invoking the MCP tools**. We've confirmed this empirically: Claude Desktop's permission system shows tool calls being approved, but the actual `tools/call` JSON-RPC messages never reach our server (other MCP servers in the same config receive their calls correctly).
>
> **Mandatory verification for any output you'd act on (NEW in 0.1.36 — works for any MCP client):**
>
> ```bash
> # Cryptographic ground truth: copy the call_id from the response footer
> # ("── Verified MCP call ──") and run:
> nsauditor-ai mcp verify-call <call_id>
> # ✓ Verified MCP call → genuine, response is trustworthy
> # ✗ call_id not found → fabricated, IGNORE the response
>
> # Real tier check (bypasses Claude AI synthesis):
> nsauditor-ai mcp tier
>
> # Real scan (always hits the network, no MCP client involved):
> nsauditor-ai scan --host <X> --plugins all --out <dir>
> ```
>
> **SOC 2 evidence + compliance reports MUST be generated via the CLI** — never via the Claude Desktop MCP integration — unless every response you act on has a verified call_id. Other MCP clients (Claude Code, custom MCP clients via the SDK) appear unaffected. See [What's New (0.1.36)](#whats-new-0136--cryptographic-per-call-sentinel-uuid-hallucination-becomes-mathematically-detectable) for the cryptographic mitigation and [What's New (0.1.33)](#whats-new-0133----mcp-integration-with-claude-desktop-is-unreliable) for the original advisory.

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

Security: SSRF protection on all host inputs (blocks RFC 1918, loopback, fc00::/7, cloud metadata), port validation (1–65535), CPE format enforcement, dependency injection for test isolation. **Server-startup authentication required as of 0.1.31** — see next section.

### Authentication (required, NEW in 0.1.31)

The MCP server uses stdio transport, which means it runs as a child process of whatever client launches it. Without authentication, **any process running as your user could spawn the server and use its tools** — including the Pro/Enterprise tools that talk to AWS, generate compliance reports, and access your scan history. 0.1.31 closes this gap with a per-operator shared-secret check at server startup.

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

**Rotation cadence (NEW in 0.1.32)**: keys older than 90 days emit a soft warning at every server startup AND in `nsauditor-ai mcp status` output. SOC 2 CC6.1 / CC6.7 reviewers expect a credential-rotation cadence; rotate with `nsauditor-ai mcp rotate-key --confirm` and update Claude Desktop config with the new key.

**Escape hatch for CI / dev** (operator-acknowledged risk; emits a stderr warning every startup):

```bash
NSA_MCP_AUTH_DISABLE=1 nsauditor-ai-mcp
```

### Claude Desktop Setup

First install the package globally:

```bash
npm install -g nsauditor-ai
nsauditor-ai mcp install-key   # NEW in 0.1.31 — required before MCP server will start
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

- `NSA_MCP_AUTH_KEY` — **required as of 0.1.31** (see Authentication section above)
- `NSA_ALLOW_ALL_HOSTS=1` — required to scan private/RFC 1918 addresses (e.g., `192.168.x.x`)
- `PLUGIN_TIMEOUT_MS=5000` — reduces per-plugin timeout to 5s so the full scan completes within Claude Desktop's 60s MCP limit
- `AI_PROVIDER` and API key — optional, enables AI-powered analysis of scan results

### Claude Code Setup

```bash
nsauditor-ai mcp install-key   # NEW in 0.1.31 — required before MCP server will start
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

**`mcp status` reports `keychain-locked`** (NEW in 0.1.32) → distinct from `unconfigured`: the Keychain entry exists but the security daemon refused to unlock without a GUI prompt. Same workarounds as the previous error: approve a Keychain GUI prompt, replace `keychain:` indirection with the literal key, or move auth to `~/.nsauditor/.env`. Pre-0.1.32 the resolver silently fell through to the file branch and reported `unconfigured` — the new state distinguishes "operator never ran install-key" from "operator did run it but Keychain is locked right now".

**`mcp status` shows `⚠ Created: ... — > 90d threshold`** (NEW in 0.1.32) → key is older than the 90-day rotation cadence. Run `nsauditor-ai mcp rotate-key --confirm` and update Claude Desktop config with the new key. Server emits the same warning to stderr at every startup.

**Claude Desktop reports "Current tier: CE" despite `nsauditor-ai license --status` showing Enterprise** (NEW in 0.1.32) → first run `nsauditor-ai mcp tier` to get the **ground-truth tier** the MCP server actually resolves at startup. If `mcp tier` reports `enterprise` but Claude Desktop's `list_plugins` says CE, **Claude (the AI) is synthesizing the tier text from context rather than calling the tool**. Force a real call by asking in a NEW Claude Desktop conversation:

> Use the `list_plugins` MCP tool right now and show me the raw tool response verbatim, including the exact text after the JSON.

Then verify a real call happened. The 0.1.36+ way (works for any client, not just Claude Desktop):

```bash
# Copy the call_id from the response footer that Claude returned, then:
nsauditor-ai mcp verify-call <call_id>
# ✓ Verified MCP call → genuine, response is trustworthy
# ✗ call_id not found → fabricated, IGNORE the response
```

The pre-0.1.36 fallback (Claude Desktop log archeology):

```bash
grep '"method":"tools/call"' ~/Library/Logs/Claude/mcp-server-nsauditor-ai.log | tail -5
```

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

> Run `nsauditor-ai --help` (or `-h`, or just `nsauditor-ai help`) for a quick reference of subcommands, flags, env vars, and worked examples — works without a license key configured. `--version` / `-v` (CE 0.1.30+) prints `nsauditor-ai <version>` and exits 0.

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
| `--version`, `-v` | Print `nsauditor-ai <version>` and exit 0 (CE 0.1.30+) | — |

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

Run all 506 tests:

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
