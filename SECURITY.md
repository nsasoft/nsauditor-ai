# Security & Dependency Transparency — nsauditor-ai

NSAuditor AI Community Edition runs entirely on your infrastructure.

## Known `npm audit` notices

| Advisory | Where | Status |
|---|---|---|
| GHSA-p7fg-763f-g4gf (`@anthropic-ai/sdk` Filesystem Memory Tool permissions) | `@anthropic-ai/sdk` | **Resolved in 0.1.86** — bumped to ^0.100.0, above the affected 0.79.0–0.91.0 range. The Memory Tool is never used (we call `messages.create` only). |
| `node-domexception@1.0.0` (deprecation notice, not a CVE) | `openai@4` → `formdata-node@4` → `node-domexception`. | Non-exploitable — a now-redundant `DOMException` polyfill. **Fix available on our side** (not upstream-gated): `openai@6` dropped `formdata-node` entirely, so a bump clears it. Scheduled for a tested CE patch — the `openai` client also backs the Ollama provider (`responses.create` / `chat.completions.create`), so those paths get re-verified on the major bump. |

The abandoned `wappalyzer-core` (via `simple-wappalyzer`) was replaced by an in-house
zero-dependency fingerprinter in 0.1.86. The direct `uuid` dependency was dropped in
favor of the native `crypto.randomUUID()`.

Report security issues: security@nsasoft.us
