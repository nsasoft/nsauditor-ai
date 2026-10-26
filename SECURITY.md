# Security & Dependency Transparency — nsauditor-ai

NSAuditor AI Community Edition runs entirely on your infrastructure.

## The Node.js runtime: 24.22.1 or newer

The supported runtime floor is **Node.js 24.22.1** (`engines.node >=24.22.1`), the security release of 2026-10-21
(https://nodejs.org/en/blog/vulnerability/october-2026-security-releases): of the ten CVEs that advisory lists, eight
name the 24.x line, four of them high. One of them, CVE-2026-111497 (a Brotli decoder out-of-bounds write), is
reachable from a scanned host: the web-application detector, the UPnP device-description fetch and plugin 050 read
response bodies through Node's `fetch`, which decodes `content-encoding: br` itself. Reachable is not exploited; the
trigger conditions are the advisory's. npm only warns on an older runtime (`EBADENGINE`), so check `node --version`.

## Known `npm audit` notices

| Advisory | Where | Status |
|---|---|---|
| GHSA-p7fg-763f-g4gf (`@anthropic-ai/sdk` Filesystem Memory Tool permissions) | `@anthropic-ai/sdk` | **Resolved in 0.1.86** — bumped to ^0.100.0, above the affected 0.79.0–0.91.0 range. The Memory Tool is never used (we call `messages.create` only). |
| GHSA-mrhx-c7xc-m3w5 (`zod` < 4.6.6, memory exhaustion validating oversized constrained collections) | `openai@4` (optional peer) and the MCP SDK → `zod` | **Resolved in 1.1.0 for `npm install -g`, a source checkout and the air-gap carrier** — `zod ^4.6.6` is a direct dependency, and each of those installs holds one `zod`, 4.6.7 at release. **Still open where `nsauditor-ai` is installed as a dependency of another project, and under `npx`:** npm keeps `zod` 3.25.76 at that project's root, beside the 4.6.7 this package declares, because `openai@4`'s optional `zod` peer (`^3.23.8`) applies there, and the MCP SDK at that root resolves the 3.x. Such a project can add `"overrides": { "zod": "^4.6.6" }` to its own `package.json`, which installs one `zod` 4.6.7. The `openai@6` bump scheduled in the `node-domexception` row below closes it for every install, because `openai@6` admits `zod` 4. This package imports `zod` nowhere; of its two commands only `nsauditor-ai-mcp` imports the MCP SDK, the module here that loads `zod`. |
| GHSA-27r3-jxmh-p828 (`body-parser` >= 2.0.0 < 2.4.0, denial of service on trailing bytes after compressed data) | the MCP SDK → `express` → `body-parser` (the lockfile, which the air-gap carrier installs) | **Resolved in 1.1.0** — the lockfile resolves `body-parser` 2.4.0. A fresh install already resolved 2.4.0. |
| `node-domexception@1.0.0` (deprecation notice, not a CVE) | `openai@4` → `formdata-node@4` → `node-domexception`. | Non-exploitable — a now-redundant `DOMException` polyfill. **Fix available on our side** (not upstream-gated): `openai@6` dropped `formdata-node` entirely, so a bump clears it. Scheduled for a tested CE patch — the `openai` client also backs the Ollama provider (`responses.create` / `chat.completions.create`), so those paths get re-verified on the major bump. |

The abandoned `wappalyzer-core` (via `simple-wappalyzer`) was replaced by an in-house
zero-dependency fingerprinter in 0.1.86. The direct `uuid` dependency was dropped in
favor of the native `crypto.randomUUID()`.

Report security issues: security@nsasoft.us
