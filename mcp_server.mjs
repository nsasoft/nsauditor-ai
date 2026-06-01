#!/usr/bin/env node
// mcp_server.mjs
// MCP (Model Context Protocol) server for nsauditor plugin manager.
// Exposes scan, probe, vulnerability lookup, and plugin listing tools.
//
// Usage:
//   node mcp_server.mjs          — starts stdio transport
//   import { createServer, toolHandlers } from './mcp_server.mjs'  — for testing

import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { homedir } from 'node:os';
import { randomUUID } from 'node:crypto';
import { appendFile, mkdir, chmod } from 'node:fs/promises';

const __dirname = dirname(fileURLToPath(import.meta.url));
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { resolveAndValidate } from './utils/net_validation.mjs';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import { buildRegionIntent } from './utils/region_intent.mjs';
import { getTierFromEnv, loadLicense } from './utils/license.mjs';
import { resolveCapabilities } from './utils/capabilities.mjs';
import { buildMarkdownReport } from './utils/report_md.mjs';
import { summarizeCloudFindings, renderCloudFindingsMarkdown } from './utils/cloud_finding_summary.mjs';
import { authorizeMcpServerStartup, getMcpAuthKeyAge, getRotationWarningDays, reportMcpAuthSource } from './utils/mcp_auth.mjs';

const _require = createRequire(import.meta.url);
const { version: TOOL_VERSION } = _require('./package.json');

// ---------------------------------------------------------------------------
// License tier & capability resolution (module-level, overridable for tests)
// ---------------------------------------------------------------------------

// Module-level: prefix-based tier for immediate use. loadLicense() runs async
// at server startup (below) and upgrades _tier to the cryptographically verified value.
let _tier = getTierFromEnv();
let _capabilities = resolveCapabilities(_tier);

/**
 * @internal Test-only. Override tier without touching env vars.
 */
export function _setTier(tier) {
  if (process.env.NODE_ENV === 'production') throw new Error('_setTier is test-only and disabled in production');
  _tier = tier ?? getTierFromEnv();
  _capabilities = resolveCapabilities(_tier);
}

/** @internal Test-only. Returns the Pro-gate denial object (or null if allowed). */
export function _requireProCapability(toolName) {
  if (process.env.NODE_ENV === 'production') throw new Error('_requireProCapability is test-only and disabled in production');
  return requireProCapability(toolName);
}

/** @internal Test-only. Returns the Enterprise-gate denial object (or null if allowed). */
export function _requireEnterpriseCapability(toolName) {
  if (process.env.NODE_ENV === 'production') throw new Error('_requireEnterpriseCapability is test-only and disabled in production');
  return requireEnterpriseCapability(toolName);
}

function requireProCapability(toolName) {
  if (_capabilities.proMCP) return null; // Pro/Enterprise: allow
  return {
    content: [{
      type: 'text',
      text: `🔒 **${toolName}** requires a Pro license.\n\nView Pro/Enterprise pricing at https://www.nsauditor.com/ai/pricing/\n\n**CE tools available:** scan_host, list_plugins`,
    }],
    isError: true,
  };
}

function requireEnterpriseCapability(toolName) {
  if (_capabilities.enterpriseMCP) return null; // Enterprise: allow
  return {
    content: [{
      type: 'text',
      text: `🔒 **${toolName}** (cloud account auditing) requires an Enterprise license.\n\nView Enterprise pricing at https://www.nsauditor.com/ai/pricing/\n\n**CE tools available:** scan_host, list_plugins`,
    }],
    isError: true,
  };
}

// ---------------------------------------------------------------------------
// Lazy singletons — initialised on first use, overridable for tests
// ---------------------------------------------------------------------------

let _pluginManager = null;
let _nvdClient = null;

async function getPluginManager() {
  if (_pluginManager) return _pluginManager;
  const { default: PluginManager } = await import('./plugin_manager.mjs');
  _pluginManager = await PluginManager.create(`${__dirname}/plugins`);
  return _pluginManager;
}

async function getNvdClient() {
  if (_nvdClient) return _nvdClient;
  const { createNvdClient } = await import('./utils/nvd_client.mjs');
  _nvdClient = createNvdClient();
  return _nvdClient;
}

/** Allow tests to inject mocks without touching the real modules. */
export function _setPluginManager(pm) {
  if (process.env.NODE_ENV === 'production') throw new Error('_setPluginManager is test-only and disabled in production');
  _pluginManager = pm;
}
export function _setNvdClient(client) {
  if (process.env.NODE_ENV === 'production') throw new Error('_setNvdClient is test-only and disabled in production');
  _nvdClient = client;
}

let _validateHostFn = validateHost;
export function _setValidateHost(fn) {
  if (process.env.NODE_ENV === 'production') throw new Error('_setValidateHost is test-only and disabled in production');
  _validateHostFn = fn ?? validateHost;
}

/**
 * Build a RegionIntent for the MCP scan_cloud `regions` argument.
 *
 * DIVERGENT DEFAULT vs CLI: omitting `regions` (undefined/null) returns null
 * so the plugins fall back to the server-configured AWS_REGION (single-region
 * or env-driven). The caller must pass ["all"] EXPLICITLY to fan out to every
 * enabled region — an implicit fan-out could blow Claude Desktop's tool timeout.
 *
 * @param {string[]|undefined|null} regions  Tool arg value
 * @returns {{ kind: 'all'|'list', explicit: true }|null}
 */
export function buildScanCloudRegionIntent(regions) {
  if (regions === undefined || regions === null) return null; // divergent default: do NOT fan out
  if (!Array.isArray(regions)) throw new Error('regions must be an array of region codes or ["all"]');
  if (regions.length === 1 && String(regions[0]).trim().toLowerCase() === 'all') return buildRegionIntent('all');
  return buildRegionIntent(regions.join(','));
}

// ---------------------------------------------------------------------------
// Per-call cryptographic sentinel (CE 0.1.36 — Thread L Phase 2)
// ---------------------------------------------------------------------------
//
// Why this exists: even after CE 0.1.34 embedded the resolved tier and CE 0.1.35
// added a CLI provenance footer, Claude Desktop was empirically observed
// (operator session, 2026-05-09) fabricating list_plugins responses
// WITHOUT routing to this server (per-server log: 0 tools/call entries
// while other configured MCP servers received 50+ in the same session).
// A fabricated response can copy any text it has seen — including version
// numbers from the CLI footer. The only thing it cannot copy is a
// random UUID generated server-side AT THE MOMENT of the call.
//
// Each tool invocation gets a fresh UUID. The UUID is:
//   1. Embedded in the response text (Claude cannot omit; it's the payload)
//   2. Persisted to ~/.nsauditor/mcp-calls.log (append-only, mode 0600)
//
// Customer verification: paste the UUID from Claude into
//   nsauditor-ai mcp verify-call <uuid>
// If it appears in the local log → real call. If not → hallucinated.
// (See cli.mjs `verify-call` subcommand.)
const MCP_CALL_LOG_PATH = join(homedir(), '.nsauditor', 'mcp-calls.log');

async function recordToolCall(toolName) {
  const callId = randomUUID();
  const ts = new Date().toISOString();
  // Best-effort: a log-write failure must not break the customer's tool
  // call. Verification will simply fail-closed (UUID-not-found → treat as
  // unverifiable rather than as proof-of-fake).
  try {
    await mkdir(dirname(MCP_CALL_LOG_PATH), { recursive: true });
    const line = JSON.stringify({ call_id: callId, tool: toolName, ts }) + '\n';
    await appendFile(MCP_CALL_LOG_PATH, line, { encoding: 'utf8' });
    // Tighten on first write; chmod is idempotent so cheap to repeat.
    try { await chmod(MCP_CALL_LOG_PATH, 0o600); } catch { /* non-fatal on Windows */ }
  } catch (err) {
    process.stderr.write(`[nsauditor-mcp] call-log write failed: ${err.message}\n`);
  }
  return callId;
}

function appendCallSentinel(text, callId) {
  return (
    `${text}\n\n── Verified MCP call ──\n` +
    `call_id: ${callId}\n` +
    `Verify (proves Claude actually called this server, not hallucinated):\n` +
    `  nsauditor-ai mcp verify-call ${callId}`
  );
}

// ---------------------------------------------------------------------------
// Tool definitions (JSON Schema for input validation)
// ---------------------------------------------------------------------------

const TOOLS = [
  {
    name: 'scan_host',
    description:
      'Run a full plugin scan on a target host and return structured results including service detection, OS fingerprinting, and security findings.',
    inputSchema: {
      type: 'object',
      properties: {
        host: {
          type: 'string',
          description: 'Target hostname or IP address to scan',
        },
        timeout: {
          type: 'number',
          description: 'Per-plugin timeout in milliseconds (default: 30000)',
        },
      },
      required: ['host'],
    },
  },
  {
    name: 'scan_cloud',
    description:
      'Audit one or more cloud accounts (AWS / GCP / Azure) for security & compliance posture using the credentials configured in the server environment. No network host required. Requires an Enterprise license. Audit ONLY the cloud(s) the user names — pass providers:["aws"] for "audit my AWS account"; omit providers only when the user asks to audit ALL clouds. Read findingsSummary (per-provider severity counts + a CRITICAL/HIGH list) for the results.',
    inputSchema: {
      type: 'object',
      properties: {
        providers: {
          type: 'array',
          items: { type: 'string', enum: ['aws', 'gcp', 'azure'] },
          description: 'Which cloud(s) to audit. Omit to audit all clouds the server is configured for.',
        },
        regions: {
          type: 'array',
          items: { type: 'string' },
          description: 'AWS region codes (e.g. ["us-east-1","eu-west-1"]) or ["all"] to scan every enabled region. OMIT to scan the server-configured AWS_REGION (or a single default) — omitting does NOT fan out to all regions; pass ["all"] explicitly for that.',
        },
      },
      required: [],
    },
  },
  {
    name: 'probe_service',
    description:
      'Run a specific plugin against a host:port combination to probe a single service.',
    inputSchema: {
      type: 'object',
      properties: {
        host: {
          type: 'string',
          description: 'Target hostname or IP address',
        },
        port: {
          type: 'number',
          description: 'Target port number',
        },
        pluginName: {
          type: 'string',
          description: 'Plugin name or ID to run (e.g. "ssh_scanner" or "002")',
        },
      },
      required: ['host', 'port', 'pluginName'],
    },
  },
  {
    name: 'get_vulnerabilities',
    description:
      'Look up known CVEs for a given CPE (Common Platform Enumeration) string using the NVD API.',
    inputSchema: {
      type: 'object',
      properties: {
        cpe: {
          type: 'string',
          description:
            'CPE 2.3 string, e.g. "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"',
        },
        maxResults: {
          type: 'number',
          description: 'Maximum number of CVE results to return (default: all)',
        },
      },
      required: ['cpe'],
    },
  },
  {
    name: 'list_plugins',
    description:
      'Return the list of available audit plugins with their IDs, names, priorities, and requirements.',
    inputSchema: {
      type: 'object',
      properties: {},
      required: [],
    },
  },
];

// ---------------------------------------------------------------------------
// Input validation (trust boundary — MCP clients are external)
// ---------------------------------------------------------------------------

/**
 * Validate host to prevent SSRF via loopback, link-local, or cloud metadata.
 * Performs DNS resolution to defeat rebinding / encoded-IP bypasses.
 * @param {string} host
 * @returns {Promise<string>} normalised hostname
 */
export async function validateHost(host) {
  const h = String(host).trim().toLowerCase();
  if (!h) throw new Error('Empty host');
  // Fast-path: reject decimal-encoded loopback IPs (127.0.0.0/8).
  // Other private/link-local ranges (RFC 1918, 169.254.x.x) are caught by the regex below
  // and by the DNS resolveAndValidate() layer for all encoding forms.
  const _isAllDigits = /^\d+$/.test(h);
  const _n = _isAllDigits && h.length <= 10 ? Number(h) : -1;
  const isDecimalLoopback = _n >= 0x7F000000 && _n <= 0x7FFFFFFF;
  if (isDecimalLoopback || /^(localhost|127\.|0\.|::1|0\.0\.0\.0|169\.254\.|fe80:|metadata\.google)/i.test(h)) {
    throw new Error('Scanning loopback, link-local, or metadata addresses is not allowed via MCP');
  }

  // DNS resolution check — catches rebinding, decimal/octal IPs, IPv6-mapped addrs.
  // NSA_ALLOW_ALL_HOSTS=1 bypasses RFC 1918 checks for local network auditing.
  if (!process.env.NSA_ALLOW_ALL_HOSTS) {
    try {
      await resolveAndValidate(h);
    } catch (err) {
      throw new Error('Scanning loopback, link-local, or metadata addresses is not allowed via MCP');
    }
  }
  return h;
}

/** Validate port is an integer in 1-65535 range. */
function validatePort(port) {
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error('port must be an integer between 1 and 65535');
  }
  return port;
}

// ---------------------------------------------------------------------------
// Tool handler implementations (exported for direct testing)
// ---------------------------------------------------------------------------

export async function handleScanHost(args) {
  if (!args?.host || typeof args.host !== 'string') {
    throw new Error('Missing required parameter: host');
  }
  const host = await _validateHostFn(args.host);

  const pm = await getPluginManager();
  // Note: timeout is controlled via PLUGIN_TIMEOUT_MS env var at startup.
  // Runtime override is not supported to avoid process-global state mutation.
  const output = await pm.run(host, 'all');

  // Render a Markdown summary of the scan so AI assistants get a ready-to-quote
  // report alongside the structured fields. Failure to render must not break the
  // scan response (defensive: any conclusion-shape surprise should degrade to
  // markdown=null, not error out the whole tool call).
  let markdown = null;
  try {
    if (output.conclusion) {
      markdown = buildMarkdownReport({
        host: output.host,
        conclusion: output.conclusion,
        toolVersion: TOOL_VERSION,
      });
    }
  } catch { /* swallow — markdown is best-effort */ }

  return {
    host: output.host,
    conclusion: output.conclusion ?? null,
    manifest: output.manifest ?? [],
    pluginsRan: output.results?.length ?? 0,
    markdown,
  };
}

const VALID_PROVIDERS = ['aws', 'gcp', 'azure'];

export async function handleScanCloud(args) {
  // Validate providers; default → all three.
  let providers = VALID_PROVIDERS.slice();
  if (args && args.providers != null) {
    if (!Array.isArray(args.providers)) {
      throw new Error('providers must be an array of "aws" | "gcp" | "azure"');
    }
    const requested = args.providers.map((p) => String(p).trim().toLowerCase());
    for (const p of requested) {
      if (!VALID_PROVIDERS.includes(p)) {
        throw new Error(`unknown provider '${p}' (valid: ${VALID_PROVIDERS.join(', ')})`);
      }
    }
    if (requested.length > 0) providers = requested;
  }

  // Validate regions BEFORE the scan runs so a bad region rejects cleanly.
  // buildScanCloudRegionIntent throws on unknown regions; returns null when
  // omitted (divergent default: does NOT fan out — explicit ["all"] required).
  const awsRegionIntent = buildScanCloudRegionIntent(args && args.regions);

  const pm = await getPluginManager();

  // Save/set/restore CLOUD_PROVIDER so the per-plugin .includes() gates pass and
  // the cross-cloud bleed gate is satisfied — restored in finally so the tool
  // never leaves the long-lived server's env mutated for the next call.
  const savedProvider = process.env.CLOUD_PROVIDER;
  let output;
  try {
    process.env.CLOUD_PROVIDER = providers.join(',');
    output = await pm.runCloud(providers, awsRegionIntent ? { awsRegionIntent } : {});
  } finally {
    if (savedProvider === undefined) delete process.env.CLOUD_PROVIDER;
    else process.env.CLOUD_PROVIDER = savedProvider;
  }

  // Build the caller-visible findings surface DIRECTLY from the raw results — the
  // network-host concluder (result_concluder.mjs) doesn't understand cloud
  // compliance findings and silently drops them (the false-clean this fixes).
  const providerOf = (id) => (pm.plugins || []).find((p) => String(p.id) === String(id))?.cloudProvider || null;
  const findingsSummary = summarizeCloudFindings(output.results || [], providerOf);

  // Render Markdown FROM the findings summary (NOT the host renderer, which is
  // empty for a cloud conclusion). Best-effort.
  let markdown = null;
  try {
    markdown = renderCloudFindingsMarkdown(findingsSummary, providers);
  } catch { /* swallow — markdown is best-effort */ }

  // Anti-false-clean: a requested cloud is "audited" ONLY if >=1 of its plugins
  // actually completed (manifest status 'ran'). Surface every NOT-effectively-
  // audited provider with a specific reason — never a silent empty "clean".
  const providerStatus = output.providerStatus || {};
  const auditedProviders = output.auditedProviders || [];
  const notes = [];
  for (const p of providers) {
    const s = providerStatus[p] || { available: 0, ran: 0, skipped: 0, errored: 0 };
    if (s.ran > 0) continue; // effectively audited (clean or not)
    if (s.available === 0) {
      notes.push(`${p}: no cloud plugins available — Enterprise EE plugins not installed (an empty result is NOT a clean pass)`);
    } else if (s.errored > 0) {
      notes.push(`${p}: ${s.errored} plugin(s) ran but errored (e.g. credentials not configured) — NOT audited (an empty result is NOT a clean pass)`);
    } else {
      notes.push(`${p}: ${s.skipped} plugin(s) present but skipped (requirements/capability not met) — NOT audited`);
    }
  }

  // Honest count: completed audits, NOT error/skip envelopes.
  const pluginsRan = (output.manifest || []).filter((m) => m.status === 'ran').length;

  return {
    providers,
    audited: auditedProviders.length > 0,
    auditedProviders,
    findingsSummary,
    manifest: output.manifest ?? [],
    pluginsRan,
    markdown,
    ...(notes.length ? { notes } : {}),
  };
}

export async function handleProbeService(args) {
  if (!args?.host || typeof args.host !== 'string') {
    throw new Error('Missing required parameter: host');
  }
  if (args.port == null || typeof args.port !== 'number') {
    throw new Error('Missing required parameter: port');
  }
  if (!args?.pluginName || typeof args.pluginName !== 'string') {
    throw new Error('Missing required parameter: pluginName');
  }
  const host = await _validateHostFn(args.host);
  validatePort(args.port);

  const pm = await getPluginManager();
  const plugin = pm.findPlugin(args.pluginName);
  if (!plugin) {
    throw new Error(`Unknown plugin: ${args.pluginName}`);
  }

  const result = await pm._runOne(plugin, host, args.port);
  return result;
}

export async function handleGetVulnerabilities(args) {
  if (!args?.cpe || typeof args.cpe !== 'string') {
    throw new Error('Missing required parameter: cpe');
  }
  if (!/^cpe:2\.3:[aho]:/.test(args.cpe)) {
    throw new Error('Invalid CPE 2.3 format. Expected: cpe:2.3:{a|h|o}:vendor:product:...');
  }
  if (args.cpe.length > 500) {
    throw new Error('CPE string too long (max 500 characters)');
  }

  const client = await getNvdClient();
  let cves = await client.queryCvesByCpe(args.cpe);

  if (args.maxResults && typeof args.maxResults === 'number' && args.maxResults > 0) {
    cves = cves.slice(0, args.maxResults);
  }

  return { cpe: args.cpe, totalResults: cves.length, cves };
}

export async function handleListPlugins() {
  const pm = await getPluginManager();
  const meta = pm.getAllPluginsMetadata();
  return meta.map((p) => ({
    id: p.id,
    name: p.name,
    priority: p.priority ?? null,
    requirements: p.requirements ?? {},
  }));
}

/** Map tool name to handler. Exported for testing. */
export const toolHandlers = {
  scan_host: handleScanHost,
  scan_cloud: handleScanCloud,
  probe_service: handleProbeService,
  get_vulnerabilities: handleGetVulnerabilities,
  list_plugins: handleListPlugins,
};

// ---------------------------------------------------------------------------
// Server factory (exported for testing without starting transport)
// ---------------------------------------------------------------------------

export function createServer() {
  const server = new Server(
    {
      name: 'nsauditor-mcp',
      version: TOOL_VERSION,
    },
    {
      capabilities: {
        tools: {},
      },
    },
  );

  // --- List tools ---
  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: TOOLS,
  }));

  // --- Call tool ---
  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;

    const handler = toolHandlers[name];
    if (!handler) {
      return {
        content: [{ type: 'text', text: JSON.stringify({ error: `Unknown tool: ${name}` }) }],
        isError: true,
      };
    }

    // CE 0.1.36 (Thread L Phase 2): mint a per-call sentinel UUID and
    // log it BEFORE the Pro-gate so even denials prove the call hit
    // the server. Fabricated responses cannot include a UUID that
    // exists in the customer's local log file.
    const callId = await recordToolCall(name);

    // Gate Pro-tier tools at the MCP dispatch layer
    if (name === 'probe_service' || name === 'get_vulnerabilities') {
      const denied = requireProCapability(name);
      if (denied) {
        return {
          ...denied,
          content: denied.content.map((c) =>
            c.type === 'text' ? { ...c, text: appendCallSentinel(c.text, callId) } : c,
          ),
        };
      }
    }

    // Gate the Enterprise cloud-audit tool at the MCP dispatch layer.
    if (name === 'scan_cloud') {
      const denied = requireEnterpriseCapability(name);
      if (denied) {
        return {
          ...denied,
          content: denied.content.map((c) =>
            c.type === 'text' ? { ...c, text: appendCallSentinel(c.text, callId) } : c,
          ),
        };
      }
    }

    try {
      const result = await handler(args ?? {});

      // Append tier info + version provenance to list_plugins response.
      //
      // CE 0.1.34 (Thread L MITIGATION): the response now embeds the
      // ACTUAL versions of CE + EE (when EE is loaded) so customers
      // can detect Claude Desktop hallucinations. Background: Claude
      // Desktop has been observed (2026-05-10) silently fabricating
      // list_plugins responses without invoking the MCP server (per-
      // server log shows zero `tools/call` while Claude reports
      // detailed plugin lists). With version numbers in the response,
      // a hallucinated answer will either omit the version line OR
      // include a stale/wrong version pulled from training data.
      // Customer verification (5 seconds, no log archeology):
      //   nsauditor-ai --version
      //   npm list -g @nsasoft/nsauditor-ai-ee
      // If the versions in Claude Desktop's output don't match these
      // commands, the response was AI-generated, not a real tool call.
      if (name === 'list_plugins') {
        const tierLabel = { ce: 'Community Edition (CE)', pro: 'Pro', enterprise: 'Enterprise' };

        // Detect EE version (best-effort; absent on CE-only installs).
        let eeVersion = 'not installed';
        try {
          const eeManifest = _require('@nsasoft/nsauditor-ai-ee/package.json');
          eeVersion = eeManifest && eeManifest.version
            ? `${eeManifest.version} (loaded)`
            : 'unknown (loaded)';
        } catch {
          // EE package not installed or not resolvable — common for CE-only customers.
          eeVersion = 'not installed';
        }

        const versionLines =
          `\n\n── Installation provenance (verify against your shell) ──\n` +
          `nsauditor-ai (CE):              ${TOOL_VERSION}\n` +
          `@nsasoft/nsauditor-ai-ee (EE):  ${eeVersion}\n` +
          `Verify: nsauditor-ai --version  &&  npm list -g @nsasoft/nsauditor-ai-ee\n` +
          `If versions in this response don't match your shell, the response was\n` +
          `AI-generated rather than retrieved from the MCP server (see CE 0.1.33 advisory).`;

        const tierSuffix = `\n\nCurrent tier: ${tierLabel[_tier] ?? _tier}. ${_capabilities.proMCP ? '' : 'Upgrade to Pro for probe_service, get_vulnerabilities, risk_summary, and more.'}`;

        return {
          content: [{ type: 'text', text: appendCallSentinel(JSON.stringify(result, null, 2) + tierSuffix + versionLines, callId) }],
        };
      }

      return {
        content: [{ type: 'text', text: appendCallSentinel(JSON.stringify(result, null, 2), callId) }],
      };
    } catch (err) {
      return {
        content: [{ type: 'text', text: appendCallSentinel(JSON.stringify({ error: err.message }), callId) }],
        isError: true,
      };
    }
  });

  return server;
}

// ---------------------------------------------------------------------------
// Stdio entry point — used by bin/nsauditor-ai-mcp.mjs AND `node mcp_server.mjs`
// ---------------------------------------------------------------------------
//
// CE 0.1.37 (SECURITY): this used to be guarded by a brittle
// `process.argv[1].endsWith('mcp_server.mjs')` check. The bin shim
// (which Claude Desktop spawns) sets argv[1] to `nsauditor-ai-mcp.mjs`,
// so the guard was false and the entire startup block — auth check,
// license verification, rotation warnings — was SKIPPED. Result: Claude
// Desktop's MCP child ran unauthenticated, with _tier stuck at the CE
// default, regardless of the operator's installed license. Customers
// paying for Pro/Enterprise saw "Current tier: CE" responses and lost
// MCP access to gated tools entirely.
//
// Fix: extract the startup into an exported function. The bin shim now
// calls it explicitly, so the auth + license path runs every time.
export async function startStdioServer() {
  // EE-SEC.1: enforce MCP server authentication BEFORE accepting any
  // tool calls. Pre-fold any process running as the operator could
  // spawn the server and call Pro/Enterprise tools — including the
  // AWS-talking shadow-admin path detectors that ship in EE 0.3.4.
  // Now: refuse to start unless the env-provided NSA_MCP_AUTH_KEY
  // matches the operator's configured key (set via
  // `nsauditor-ai mcp install-key`). Constant-time compare; honors
  // NSA_MCP_AUTH_DISABLE=1 escape hatch with stderr warning.
  //
  // Stdio-MCP: stdout is reserved for JSON-RPC frames, so all
  // operator-facing diagnostic text MUST go to stderr.
  const authResult = await authorizeMcpServerStartup();
  if (!authResult.ok) {
    process.stderr.write(`✗ ${authResult.error}\n`);
    process.exit(1);
  }
  if (authResult.bypassed) {
    if (authResult.bypassedReason === 'unconfigured') {
      // CRITICAL #2 fold (Reviewer 1): louder signal when DISABLE=1
      // is set but no key was ever installed — this is almost always
      // an operator who set DISABLE in their shell rc and forgot.
      process.stderr.write(
        `⚠  MCP authentication disabled via NSA_MCP_AUTH_DISABLE=1, ` +
        `AND no key has ever been installed. This is almost certainly ` +
        `unintentional. Either run \`nsauditor-ai mcp install-key\` to set up ` +
        `auth properly, or remove the DISABLE env var if you didn't mean to set it. ` +
        `Anyone with code-execution as $USER can call MCP tools right now.\n`,
      );
    } else {
      process.stderr.write(
        `⚠  MCP authentication disabled via NSA_MCP_AUTH_DISABLE=1. ` +
        `Anyone with code-execution as $USER can call MCP tools.\n`,
      );
    }
  }

  // EE-SEC.1.1 (Thread I): rotation-cadence soft warning. SOC 2 CC6.1 /
  // CC6.7 reviewers expect a credential-rotation cadence; an unrotated
  // shared secret is treated the same way as an unrotated IAM access
  // key.
  //
  // Design note (LOW #1 from Reviewer 2): soft warning, not hard
  // refusal. Hard-refuse would break Claude Desktop integration mid-
  // session for operators who haven't seen 30 days of warnings (Claude
  // Desktop buries MCP server stderr in a log file most operators
  // never check). Soft warning + `mcp status` operator-runnable
  // evidence path is the right SOC 2 posture — auditor sees the warning
  // fires AND that the operator chose to defer rotation.
  //
  // Reviewer 2 CRITICAL #1 fold: when a key is configured but the
  // NSA_MCP_AUTH_KEY_CREATED companion is missing (operator upgraded
  // from CE 0.1.31 without re-installing), we surface a DIFFERENT
  // stderr message pointing at `mcp install-key <existing-key>` to
  // backfill the timestamp. Without this hint, EE-SEC.1.1 ships dark
  // for the entire installed base of CE 0.1.31 deployments.
  try {
    const status = await reportMcpAuthSource();
    const threshold = getRotationWarningDays();
    if (status.legacyTimestampMissing) {
      process.stderr.write(
        `⚠  MCP auth key is configured but the rotation-cadence timestamp ` +
        `is missing (likely a pre-0.1.32 install). Rotation warnings will ` +
        `not fire until you backfill the timestamp. Either:\n` +
        `   (1) re-run \`nsauditor-ai mcp install-key <KEY>\` with your existing key ` +
        `(use \`mcp print-key --confirm\` to retrieve it), OR\n` +
        `   (2) rotate to a fresh key with \`nsauditor-ai mcp rotate-key --confirm\` ` +
        `and update Claude Desktop config.\n`,
      );
    } else if (typeof status.ageDays === 'number' && status.ageDays > threshold) {
      process.stderr.write(
        `⚠  MCP auth key is ${status.ageDays} days old (> ${threshold}d threshold). ` +
        `Consider \`nsauditor-ai mcp rotate-key --confirm\` and update Claude Desktop config. ` +
        `SOC 2 CC6.1 / CC6.7 reviewers flag unrotated shared secrets.\n`,
      );
    }
  } catch { /* age check is non-fatal — never block startup on it */ }

  // Verify license JWT before accepting MCP requests — upgrades _tier from
  // prefix-based to cryptographically verified.
  await loadLicense();
  _tier = getTierFromEnv();
  _capabilities = resolveCapabilities(_tier);

  // NSA_ENV_FILE: load the per-environment dotenv file AFTER auth + license
  // (so it carries scan-target vars only and can alter neither) and BEFORE
  // createServer()/connect. plugin_manager.mjs captures PLUGIN_TIMEOUT_MS in a
  // module-level const at import (first tool call), so the file MUST be applied
  // before any tool call can import it. Fail-fast: a missing / INI file refuses
  // startup rather than silently scanning ambient credentials (wrong-account →
  // a false "clean"). stdout is JSON-RPC, so diagnostics go to stderr.
  try {
    const fsm = await import('node:fs');
    const { applyScanEnvFile } = await import('./utils/mcp_env_file.mjs');
    applyScanEnvFile({
      env: process.env,
      fileExists: (p) => fsm.existsSync(p),
      readFile: (p) => fsm.readFileSync(p, 'utf8'),
      log: (m) => process.stderr.write(`[nsauditor-mcp] ${m}\n`),
    });
  } catch (err) {
    process.stderr.write(`✗ NSA_ENV_FILE: ${err.message}\n`);
    process.exit(1);
  }

  const server = createServer();
  const transport = new StdioServerTransport();
  await server.connect(transport);
  return server;
}

// Backward-compat: still callable as `node mcp_server.mjs` directly.
const isMainModule =
  typeof process !== 'undefined' &&
  process.argv[1] &&
  (process.argv[1].endsWith('mcp_server.mjs') ||
    process.argv[1].endsWith('mcp_server'));

if (isMainModule) {
  await startStdioServer();
}
