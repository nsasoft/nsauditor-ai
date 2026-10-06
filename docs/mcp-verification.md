# Verifying MCP Responses

When you use NSAuditor AI through an AI assistant that speaks the Model Context Protocol (MCP) — Claude Desktop, Claude Code, Cursor, custom MCP clients — there is one subtle failure mode you should know about: **the AI can return convincingly-formatted scan results that were never actually produced by the MCP server**.

This page explains what that looks like, why it happens, and how to detect it in seconds.

---

## The problem in one sentence

If an MCP client times out, drops the connection, or otherwise fails to deliver a `tools/call` invocation to a running MCP server, some clients (notably Claude Desktop, observed 2026-05-10) will silently substitute a fabricated response synthesized by the AI rather than surface the failure to you.

The substituted response is indistinguishable from a real one to the naked eye — same formatting, same plugin names, same severity badges — but the numbers and findings are AI-generated, not from your actual scan.

If you act on a fabricated response, you may file a compliance report with phantom evidence or trust a clean result against a host that was never actually probed.

## The mitigation: a per-call receipt, bound to the response text (0.1.36; text binding 1.2.1)

Every MCP tool call mints a fresh server-side UUID via Node's `crypto.randomUUID()` **at the moment the call hits the server**. The UUID is:

1. Persisted to `~/.nsauditor/mcp-calls.log` (mode 0600, JSON-per-line) **before** the response returns.
2. Appended to the response text under an `── MCP call receipt ──` footer.
3. Since 1.2.1, bound to the response: the server also logs a SHA-256 digest of the response body (the text the footer is appended to). The digest is never printed — a printed digest would replay together with the id.

**The id alone does not verify a response.** An AI client that has seen an earlier response in its context can paste that response's real, logged id under a fabricated one. Until 1.2.1, `verify-call <id>` called any logged id "genuine"; it now recomputes the digest from the text you saved:

```bash
nsauditor-ai mcp verify-call <call_id> --response response.txt   # or: pbpaste | ... --response -
# exit 0 ✓ this exact text came from that call — the line names the tool and how long ago it was issued
# exit 1 ✗ the text does not match what the server sent for that call, or the id was never issued
# exit 3 ? the id was issued, but nothing bound the text to it (no --response, or a call logged before 1.2.1)
# exit 2   usage error
```

Matching ignores whitespace and is exact on words: a copy your client soft-wrapped or re-flowed still verifies; a changed word does not. **Limits, stated:** a RENDERED copy — Markdown turned into bullets and bold by the client's display — is a different text and will not verify, so copy the RAW tool output (many clients let you expand the tool call to see its raw result); and differences inside code blocks that are whitespace only (indentation) are not seen. A verbatim copy of an OLD genuine response verifies too — which is why the ✓ line says how long ago the call was issued: a stale answer reads as stale.

`scan_host`, `probe_service`, `get_vulnerabilities`, and `list_plugins` all carry a receipt — even Pro-tier denials, so you can show the call reached the server.

## Customer verification workflow

```text
1. In your MCP client, ask the assistant to use any nsauditor-ai tool
   (e.g., "list plugins" or "scan 1.1.1.1").

2. The response ends with:
       ── MCP call receipt ──
       call_id: 3f8a1b22-7e44-4c91-9d62-12bd0a4f5e91
       To check that this exact response came from this server, save the whole response (footer included)
       to a file and run:
         nsauditor-ai mcp verify-call 3f8a1b22-7e44-4c91-9d62-12bd0a4f5e91 --response <file>

3. Copy the RAW tool result (not the assistant's rendered summary) into response.txt and run that command.

4. Reading the output:
       ✓ (exit 0) → this text is what the server produced for that call; note how long ago
       ✗ (exit 1) → not produced by this call (or altered after copying) — re-copy the raw output and retry;
                    if it still fails, ignore the response
       ? (exit 3) → the id is real but the text is unverified — supply --response
```

## When you'd use this in practice

- **SOC 2 evidence pulls.** Any compliance report generated via the MCP path needs its response verified with `--response`, or generate it via the CLI instead. The fabricated-response failure mode means MCP-routed reports cannot be trusted without verification.
- **Pro / Enterprise tier checks.** If the response says "Current tier: Community Edition (CE)" but `nsauditor-ai license --status` says enterprise, run `verify-call <id> --response <file>` on the response — if it's ✗, the AI fabricated the tier. Also run `nsauditor-ai mcp tier` for a ground-truth read that bypasses the MCP path entirely.
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

The per-call receipt shipped in 0.1.36 made a fabricated id detectable; since 1.2.1 the receipt is bound to the response text, so a fabricated response carrying a REAL id copied from an earlier one is detectable too. The underlying upstream-client behavior is outside our control and may apply to other MCP servers as well — verifying with a server-issued sentinel is a generally good practice when an MCP response will be acted on.

## Related changelog entries

- **0.1.36** — per-call cryptographic sentinel UUID (the primary mitigation)
- **0.1.35** — CLI provenance footer matches MCP response
- **0.1.34** — `list_plugins` embeds CE+EE versions
- **0.1.33** — original advisory

See [CHANGELOG.md](../CHANGELOG.md) for the full release history.
