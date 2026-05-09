#!/usr/bin/env node
// mcp_server.mjs
// MCP (Model Context Protocol) server for nsauditor plugin manager.
// Exposes scan, probe, vulnerability lookup, and plugin listing tools.
//
// Usage:
//   node mcp_server.mjs          — starts stdio transport
//   import { createServer, toolHandlers } from './mcp_server.mjs'  — for testing

import { createRequire } from 'node:module';
import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { resolveAndValidate } from './utils/net_validation.mjs';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import { getTierFromEnv, loadLicense } from './utils/license.mjs';
import { resolveCapabilities } from './utils/capabilities.mjs';
import { buildMarkdownReport } from './utils/report_md.mjs';
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

function requireProCapability(toolName) {
  if (_capabilities.proMCP) return null; // Pro/Enterprise: allow
  return {
    content: [{
      type: 'text',
      text: `🔒 **${toolName}** requires a Pro license.\n\nUpgrade at https://www.nsauditor.com/ai/pricing or start a free 14-day trial (no credit card) at https://www.nsauditor.com/ai/trial\n\n**CE tools available:** scan_host, list_plugins`,
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

    // Gate Pro-tier tools at the MCP dispatch layer
    if (name === 'probe_service' || name === 'get_vulnerabilities') {
      const denied = requireProCapability(name);
      if (denied) return denied;
    }

    try {
      const result = await handler(args ?? {});

      // Append tier info to list_plugins response
      if (name === 'list_plugins') {
        const tierLabel = { ce: 'Community Edition (CE)', pro: 'Pro', enterprise: 'Enterprise' };
        const tierSuffix = `\n\nCurrent tier: ${tierLabel[_tier] ?? _tier}. ${_capabilities.proMCP ? '' : 'Upgrade to Pro for probe_service, get_vulnerabilities, risk_summary, and more.'}`;
        return {
          content: [{ type: 'text', text: JSON.stringify(result, null, 2) + tierSuffix }],
        };
      }

      return {
        content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
      };
    } catch (err) {
      return {
        content: [{ type: 'text', text: JSON.stringify({ error: err.message }) }],
        isError: true,
      };
    }
  });

  return server;
}

// ---------------------------------------------------------------------------
// Standalone entry point
// ---------------------------------------------------------------------------

const isMainModule =
  typeof process !== 'undefined' &&
  process.argv[1] &&
  (process.argv[1].endsWith('mcp_server.mjs') ||
    process.argv[1].endsWith('mcp_server'));

if (isMainModule) {
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

  const server = createServer();
  const transport = new StdioServerTransport();
  await server.connect(transport);
}
