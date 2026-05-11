# Verifying MCP Responses

When you use NSAuditor AI through an AI assistant that speaks the Model Context Protocol (MCP) — Claude Desktop, Claude Code, Cursor, custom MCP clients — there is one subtle failure mode you should know about: **the AI can return convincingly-formatted scan results that were never actually produced by the MCP server**.

This page explains what that looks like, why it happens, and how to detect it in seconds.

---

## The problem in one sentence

If an MCP client times out, drops the connection, or otherwise fails to deliver a `tools/call` invocation to a running MCP server, some clients (notably Claude Desktop, observed 2026-05-10) will silently substitute a fabricated response synthesized by the AI rather than surface the failure to you.

The substituted response is indistinguishable from a real one to the naked eye — same formatting, same plugin names, same severity badges — but the numbers and findings are AI-generated, not from your actual scan.

If you act on a fabricated response, you may file a compliance report with phantom evidence or trust a clean result against a host that was never actually probed.

## The mitigation: per-call cryptographic sentinel (shipped in 0.1.36)

Every MCP tool call now mints a fresh server-side UUID via Node's `crypto.randomUUID()` **at the moment the call hits the server**. The UUID is:

1. Appended to the response text under a `── Verified MCP call ──` footer.
2. Persisted to `~/.nsauditor/mcp-calls.log` (mode 0600, JSON-per-line) **before** the response returns.

You can then verify any response in your terminal:

```bash
nsauditor-ai mcp verify-call <call_id>
# ✓ Verified MCP call → genuine, response is trustworthy
# ✗ call_id not found → fabricated, IGNORE the response
```

The AI client cannot forge a valid UUID because it has no access to your local `crypto.randomUUID()` output and no way to write to a log file you control. A UUID that doesn't appear in `~/.nsauditor/mcp-calls.log` was never issued by your MCP server.

`scan_host`, `probe_service`, `get_vulnerabilities`, and `list_plugins` all mint sentinels — even Pro-tier denials carry a UUID so you can prove the call reached the server.

## Customer verification workflow (10 seconds)

```text
1. In your MCP client, ask the assistant to use any nsauditor-ai tool
   (e.g., "list plugins" or "scan 1.1.1.1").

2. The response ends with:
       ── Verified MCP call ──
       call_id: 3f8a1b22-7e44-4c91-9d62-12bd0a4f5e91
       Verify: nsauditor-ai mcp verify-call 3f8a1b22-7e44-4c91-9d62-12bd0a4f5e91

3. Run that exact command in your terminal:
       nsauditor-ai mcp verify-call 3f8a1b22-7e44-4c91-9d62-12bd0a4f5e91

4. Reading the output:
       ✓ → genuine, the response is real
       ✗ → fabricated, ignore the response
```

## When you'd use this in practice

- **SOC 2 evidence pulls.** Any compliance report generated via the MCP path needs a verified call_id, or generate it via the CLI instead. The fabricated-response failure mode means MCP-routed reports cannot be trusted without verification.
- **Pro / Enterprise tier checks.** If the response says "Current tier: Community Edition (CE)" but `nsauditor-ai license --status` says enterprise, run `verify-call` on the response — if it's ✗, the AI fabricated the tier. Also run `nsauditor-ai mcp tier` for a ground-truth read that bypasses the MCP path entirely.
- **High-impact remediation calls.** Before paging a developer on a "critical finding" surfaced through MCP, verify the call_id.

## Defense in depth: provenance footer (since 0.1.34/0.1.35)

`list_plugins` also emits a CE/EE version provenance block that you can cross-check against your shell:

```
── Installation provenance ──
  nsauditor-ai (CE):              0.1.37
  @nsasoft/nsauditor-ai-ee (EE):  0.3.6 (loaded)
```

Compare character-for-character against `nsauditor-ai license --plugins` (which prints the same block from the CLI). Mismatch or missing block = fabricated.

The provenance block catches lazy hallucinations instantly without needing to copy a UUID. The cryptographic sentinel is the fallback for sophisticated fabrications that copy a real-looking provenance block from chat context.

## Bypass via direct CLI

If you need authoritative ground truth and don't want to think about MCP verification at all:

```bash
# Real tier (bypasses MCP entirely):
nsauditor-ai mcp tier

# Real plugin scan (always hits the network, no MCP client involved):
nsauditor-ai scan --host <X> --plugins all --out <dir>

# Real plugin inventory:
nsauditor-ai license --plugins
```

The CLI doesn't go through an AI client at any point, so the fabrication failure mode does not apply.

## Background — how we discovered this

During internal Claude Desktop integration testing on 2026-05-10:

- `~/Library/Logs/Claude/main.log` showed multiple permission grants for `mcp__nsauditor-ai__list_plugins` and `mcp__nsauditor-ai__scan_host`.
- `~/Library/Logs/Claude/mcp-server-nsauditor-ai.log` showed **zero** `"method":"tools/call"` entries on the same day.
- Other MCP servers in the same Claude Desktop config received and logged real calls (ns-ftp:29, wp-publisher-netsecmag:14, ai-pr-distribution:6, sendgrid:3 over the same period).
- When asked to scan 1.1.1.1, Claude Desktop returned a detailed report with plugin breakdown and a Zero Trust score — entirely fabricated by the AI.

The likely root cause is timeout: the NSAuditor AI MCP server loads PluginManager + 32 plugins + verifies the license JWT before responding to the first call, which can exceed Claude Desktop's per-call MCP timeout. The AI then silently substitutes a fabricated response from training context rather than surfacing the timeout.

The cryptographic sentinel shipped in 0.1.36 makes this failure mode mathematically detectable from the user's side. The underlying upstream-client behavior is outside our control and may apply to other MCP servers as well — verifying with a server-issued sentinel is a generally good practice when an MCP response will be acted on.

## Related changelog entries

- **0.1.36** — per-call cryptographic sentinel UUID (the primary mitigation)
- **0.1.35** — CLI provenance footer matches MCP response
- **0.1.34** — `list_plugins` embeds CE+EE versions
- **0.1.33** — original advisory

See [CHANGELOG.md](../CHANGELOG.md) for the full release history.
