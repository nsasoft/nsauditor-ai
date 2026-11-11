# Security & Dependency Transparency — nsauditor-ai

NSAuditor AI Community Edition runs entirely on your infrastructure.

## The Node.js runtime: 24.22.3 or newer

From Community 1.2.0 the supported runtime floor is **Node.js 24.22.3** (`engines.node >=24.22.3`), the security release
of 2026-11-10 (https://nodejs.org/en/blog/vulnerability/november-2026-security-releases); 24.22.2 (2026-10-27) was
not a security release. npm only warns on an older runtime (`EBADENGINE`), so check `node --version`. What we assessed
against that advisory, measured 2026-11-11:

- **Proxy credentials at startup.** With `NODE_USE_ENV_PROXY=1`, a malformed proxy URL stops Node.js before any NSAuditor
  code runs, and Node.js prints the URL, password included, on stderr. On 24.22.3 every malformed `HTTPS_PROXY` /
  `https_proxy` value we tried still prints it; for `HTTP_PROXY` / `http_proxy`, 24.22.3 redacts three of the four shapes we
  tried, where 24.22.1 redacted none. The raise does not close this: keep credentials out of proxy URLs, or keep that
  process's stderr out of shared logs. A well-formed proxy URL that fails when the request runs is printed without its
  credentials, and the webhook and drift-notification redactors strip them as well.
- **Proxy schemes.** `NODE_USE_ENV_PROXY` honours `http://` and `https://` proxy URLs. A `socks5://` URL is ignored and the
  request goes direct, with no error (measured on 24.22.1 and 24.22.3). Use an HTTP(S) proxy where egress must pass one.
- **Child processes.** Two shipped paths in this package keep a child process's stderr: the host check's `ping` error and
  the SYN scan's `nmap` error land in `scan_conclusion_raw.json`. Neither is a Node.js process; driven under
  `NODE_USE_ENV_PROXY=1` with a password in every proxy variable, their output carried none.
- **Servers.** No shipped code in the Enterprise, Community or agent-skill packages creates an HTTP/2 or TLS server (their
  own `.mjs`/`.js`/`.cjs` outside tests and `node_modules` were searched for `createServer`, `createSecureServer`, `http2`,
  `addContext` and `SNICallback`). Dependencies under `node_modules` were not searched, and the HTTP/2 client that the
  gRPC-based Google Cloud SDKs use was not assessed against the advisory's peer-frame issues: there we rely on the 24.22.3
  runtime itself.
- **TLS session reuse.** No `https.Agent` or TLS session is shared across certificate-verification policies in shipped
  Community code: each TLS probe opens its own connection.

From Community 1.1.0 until 1.2.0 the supported runtime floor was **Node.js 24.22.1** (`engines.node >=24.22.1`), the security release of 2026-10-21
(https://nodejs.org/en/blog/vulnerability/october-2026-security-releases): of the ten CVEs that advisory lists, eight
name the 24.x line, four of them high. One of them, CVE-2026-111497 (a Brotli decoder out-of-bounds write), is
reachable from a scanned host: the web-application detector, the UPnP device-description fetch and plugin 050 read
response bodies through Node's `fetch`, which decodes `content-encoding: br` itself. Reachable is not exploited; the
trigger conditions are the advisory's. npm only warns on an older runtime (`EBADENGINE`), so check `node --version`.

## Known `npm audit` notices

| Advisory | Where | Status |
|---|---|---|
| GHSA-p7fg-763f-g4gf (`@anthropic-ai/sdk` Filesystem Memory Tool permissions) | `@anthropic-ai/sdk` | **Resolved in 0.1.86** — bumped to ^0.100.0, above the affected 0.79.0–0.91.0 range. The Memory Tool is never used (we call `messages.create` only). |
| GHSA-mrhx-c7xc-m3w5 (`zod` < 4.6.6, memory exhaustion validating oversized constrained collections) | `openai` (optional peer) and the MCP SDK → `zod` | **Resolved for every install shape in 1.1.1.** Community 1.1.1 moves the OpenAI client to `openai` 7, whose optional `zod` peer is `^3.25 \|\| ^4.0`, so the direct `zod ^4.6.6` satisfies it everywhere. This package imports `zod` nowhere; of its two commands only `nsauditor-ai-mcp` imports the MCP SDK, the module here that loads `zod`.<br>- **What 1.1.0 left open (measured 2026-10-28).** It resolved `npm install -g`, a source checkout and the air-gap carrier, but a project that listed `nsauditor-ai@1.1.0` as a dependency, and `npx`, still got `zod` 3.25.76 (four copies) beside 4.6.7, because `openai@4`'s optional peer was `^3.23.8`.<br>- **What 1.1.1 holds.** The same project on 1.1.1 holds one `zod`, 4.6.7, and so does Enterprise installed beside it at one root with no `overrides`.<br>- **The `overrides.zod` is retired.** This package's lockfile is identical without it. |
| GHSA-27r3-jxmh-p828 (`body-parser` >= 2.0.0 < 2.4.0, denial of service on trailing bytes after compressed data) | the MCP SDK → `express` → `body-parser` (the lockfile, which the air-gap carrier installs) | **Resolved in 1.1.0** — the lockfile resolves `body-parser` 2.4.0. A fresh install already resolved 2.4.0. |
| `node-domexception@1.0.0` (deprecation notice, not a CVE) | `openai@4` → `formdata-node@4` → `node-domexception` | **Resolved in 1.1.1** — `openai` 7 does not depend on `formdata-node`, and a project depending on Community 1.1.1 holds no `node-domexception` (measured 2026-10-28). The Ollama and OpenAI paths were driven end to end on `openai` 7 against the live providers before the release. Enterprise's Google Cloud SDKs bring their own copy; Enterprise's `SECURITY.md` covers it. |

The abandoned `wappalyzer-core` (via `simple-wappalyzer`) was replaced by an in-house
zero-dependency fingerprinter in 0.1.86. The direct `uuid` dependency was dropped in
favor of the native `crypto.randomUUID()`.

Report security issues: security@nsasoft.us
