# Changelog

Release notes for **`nsauditor-ai`** (Community Edition). The main [README](./README.md) focuses on features and usage — this file is the per-release history, kept for upgrade triage and audit reference.

For Enterprise Edition release notes, see [`@nsasoft/nsauditor-ai-ee`](https://www.npmjs.com/package/@nsasoft/nsauditor-ai-ee).

---

## 0.1.38 — docs-only: README cleanup + CHANGELOG split

No code changes. The README on the npm package page used to lead with eight stacked "What's New" release-note blocks for 0.1.30 → 0.1.37 (plus an EE 0.3.3 paired note), which buried features and usage below ~220 lines of release narrative. 0.1.38 ships the same code as 0.1.37 with the README rewritten to be feature-and-usage focused on the first screen and the per-release history moved to this CHANGELOG. A new `docs/mcp-verification.md` page carries the previously-inline forensics on Claude Desktop response fabrication and the `nsauditor-ai mcp verify-call <id>` workflow.

If you're already on 0.1.37, this upgrade carries no functional difference. Upgrade only if you want the new README on a freshly-installed copy or you're a contributor looking at the source. The 0.1.37 security fix (MCP bin shim auth/license bypass) is the most recent functional change — see below.

```bash
npm install -g nsauditor-ai@0.1.38
```

---

## 0.1.37 — 🛑 SECURITY FIX: bin shim bypassed auth + license verification

**Affects all installations using Claude Desktop (or any MCP client invoking the published `nsauditor-ai-mcp` binary).** Pre-0.1.37, the bin shim at `bin/nsauditor-ai-mcp.mjs` directly called `createServer() + server.connect()` and never invoked the startup block in `mcp_server.mjs` that runs:

1. **`authorizeMcpServerStartup()`** — the `NSA_MCP_AUTH_KEY` enforcement we shipped in EE-SEC.1 (CE 0.1.31). Skipped means **any process with stdio access to the spawned MCP child could call the tools without supplying the auth key**.
2. **`await loadLicense()`** — JWT verification of the operator's license key. Skipped means `_tier` stuck at the module-load CE default, so paid Pro/Enterprise customers saw "Current tier: CE" responses and lost MCP access to gated tools entirely.
3. Rotation cadence warnings, keychain-locked diagnostics — all silent.

**Root cause**: an `argv[1].endsWith('mcp_server.mjs')` guard in `mcp_server.mjs` only matched when the server was invoked directly as `node mcp_server.mjs`. Claude Desktop spawns via the published bin (`nsauditor-ai-mcp`), so the guard was always false in production. The guard existed so that test imports of the module wouldn't auto-start the server — but the fix should have been to extract the startup into a function the bin shim explicitly calls.

**Detection**: in 0.1.36 you could spot this if you noticed your MCP responses said `Current tier: Community Edition (CE)` despite `nsauditor-ai mcp tier` from the shell saying `enterprise`. The disagreement was the 0.1.37 bug surfacing.

**Fix**:
- Extracted the entire startup sequence into `export async function startStdioServer()` in `mcp_server.mjs`.
- `bin/nsauditor-ai-mcp.mjs` now imports and awaits `startStdioServer()`. Every Claude Desktop spawn now runs the auth check and license verification it always should have.
- Regression test (`tests/mcp_bin_startup.test.mjs`) spawns the bin shim with no auth key in env and asserts the auth check refuses startup. If the bin shim ever regresses to bypassing startup again, this test fails.

**Action required**: upgrade immediately.

```bash
npm install -g nsauditor-ai@0.1.37
# Restart Claude Desktop. Verify with:
# - Real MCP call from Claude → response should say "Current tier: Enterprise" (or Pro)
# - nsauditor-ai mcp verify-call <uuid>  ← the 0.1.36 sentinel still works
```

**Threat model note**: a process needing stdio access to your Claude Desktop MCP child already had to be running as your user (or able to write to your `~/Library/Application Support/Claude/` config). The auth-bypass exposure is *defense-in-depth degradation*, not "anyone on the internet can call your scanner." But the tier-stuck-at-CE bug definitely cost paying customers actual functionality, and SOC 2 evidence generated from MCP-routed CE-tier responses would fail audit because it lacked enterprise-tier checks.

Thanks to the customer who caught this in the wild while we were chasing what looked like a Claude Desktop hallucination — turned out the bug was on our side.

---

## 0.1.36 — cryptographic per-call sentinel UUID (hallucination becomes mathematically detectable)

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

## 0.1.35 — CLI provenance footer matches MCP response (so the comparison actually works)

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
5. **Mismatch / missing block** → Claude fabricated the response (see 0.1.33 advisory)

This is the v1 mitigation; the v2 (0.1.36) adds per-call cryptographic sentinel UUIDs that the customer can grep against the server log directly. v1 catches the common case where Claude either omits the block entirely (unlikely to fabricate the new structure verbatim) or includes a stale version pulled from training data.

---

## 0.1.34 — list_plugins now embeds CE+EE versions for hallucination detection

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

This is a v1 mitigation — 0.1.36 adds per-call cryptographic sentinel UUIDs that the customer can grep against the server log.

---

## 0.1.33 — ⚠ MCP integration with Claude Desktop is unreliable

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

**SOC 2 evidence and any compliance report MUST be generated via the CLI** — never via the Claude Desktop MCP integration — until this is resolved upstream. The 0.1.36 per-call cryptographic sentinel ships the structural mitigation: see [docs/mcp-verification.md](./docs/mcp-verification.md).

---

## 0.1.32 — Claude Desktop integration overhaul + ground-truth diagnostics

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

---

## 0.1.31 — security release

**MCP server authentication is now required.** Pre-0.1.31, the local MCP server (stdio transport) accepted any incoming JSON-RPC frames — any process running as your user could spawn it and use the Pro/Enterprise tools (which include the AWS-talking shadow-admin path detectors that ship in `@nsasoft/nsauditor-ai-ee`). 0.1.31 closes this gap with a per-operator shared-secret check at startup.

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
- Multi-source resolver mirrors the existing license-key pattern: env → Keychain → file. Constant-time key comparison via `crypto.timingSafeEqual`. Full threat model documented in [`utils/mcp_auth.mjs`](./utils/mcp_auth.mjs).

---

## Enterprise Edition 0.3.3 (paired note)

The Enterprise Edition (`@nsasoft/nsauditor-ai-ee`) shipped a 0.3.3 point release on 2026-05-08. CE stays at 0.1.30 — no CE bump required, the EE upgrade is single-line: `npm install -g @nsasoft/nsauditor-ai-ee@latest`. The release closes a Critical false-clean SOC 2 reporting bug that mirrored the AWS-side bug fixed in 0.3.2 — this time in the Azure cloud scanner — and extends mapped SOC 2 coverage to multi-cloud:

- **Azure plugin (022) finding-shape rewrite** — the EE-0.3.2.1 cloud-finding harvester only recognized one canonical shape (`{resource, severity, issues[]}`); plugin 022 was emitting `{severity, finding, resource}` (singular `finding`). Findings reached the engine but were silently dropped — Azure customers running `--compliance soc2` saw "6/6 covered controls passing" against subscriptions with real RBAC + NSG + Storage issues. Caught at internal dogfood against a live Azure subscription.
- **GCP plugin (021) preventive shape port** — plugin 021 had the same `{finding}` singular shape; pre-emptively migrated to the canonical shape so the same bug doesn't re-emerge for GCP customers in v0.4.0 when GCP `mapsToFindings` rules ship.
- **Azure → SOC 2 mapping rules added** — RBAC `Owner | Contributor | User Access Administrator at subscription scope` → CC6.1 (3 patterns); NSG `0.0.0.0/0 → port` anchored regex → CC6.6; Storage `allowBlobPublicAccess` + `enableHttpsTrafficOnly` → C1.1. CC6.1, CC6.6, and C1.1 now have *both* AWS-side and Azure-side evidence rows — actual multi-cloud SOC 2 evidence.
- **Drift detector extended to all three cloud plugins** — every `azure-cloud-scanner` `titlePattern` in `soc2.json` is now asserted to match at least one canonical issue string the plugin emits, and vice versa. The class-of-bug that produced two false-clean variants in successive releases is now structurally closed.
- **Pre-publish gate fixes** — `@azure/arm-authorization` peer-dep was pinned at `^10.0.0` (latest published is 9.0.0; clean installs would have failed); `@azure/arm-storage` was missing from `optionalDependencies` (Storage audit silently no-op'd on clean install). Both caught at the pre-publish clean-tarball smoke and corrected before ship.

See the [EE package on npm](https://www.npmjs.com/package/@nsasoft/nsauditor-ai-ee) for the full EE changelog.

---

## 0.1.30

Paired release with `@nsasoft/nsauditor-ai-ee@0.3.2` that closes the customer-onboarding gap and a critical false-clean SOC 2 reporting bug:

- **`nsauditor-ai license install <KEY>`** — verifies the JWT *before* persisting; writes to macOS Keychain or `~/.nsauditor/.env` (mode 0600) depending on platform. Three-line install flow: `npm install -g` → `license install` → `license --status`. No more shell-rc edits.
- **Multi-source license loader** — `loadLicense()` resolves keys from env var → platform Keychain → `~/.nsauditor/.env`, in that order. CI/CD env-var override still wins.
- **`nsauditor-ai license --plugins`** — real enumeration of discovered plugins, grouped by source (CE / EE / custom), with active-or-required-tier status.
- **`nsauditor-ai --version` / `-v`** — prints version and exits 0 (parallel to `--help`'s discovery-flag UX).
- **Cloud-sentinel SSRF bypass** — `--host aws|gcp|azure` no longer requires `NSA_ALLOW_ALL_HOSTS=1`. The sentinel literals route to EE cloud-scanner plugins via the provider's API; the SSRF guard's RFC 1918 / loopback protection is preserved for real network targets.
- **EE-0.3.2.1 hard dep** — CE forwards the per-plugin `results` array to `enrichScan()`. Without this, EE 0.3.2's cloud-finding harvester sees nothing and produces false-clean SOC 2 reports against AWS accounts. EE emits a runtime version-skew warning when this opt is missing.
