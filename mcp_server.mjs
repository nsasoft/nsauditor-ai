#!/usr/bin/env node
// mcp_server.mjs
// MCP (Model Context Protocol) server for nsauditor plugin manager.
// Exposes scan, probe, vulnerability lookup, and plugin listing tools.
//
// Usage:
//   node mcp_server.mjs          — starts stdio transport
//   import { createServer, toolHandlers } from './mcp_server.mjs'  — for testing

import { createRequire } from 'node:module';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { resolveAndValidate } from './utils/net_validation.mjs';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import { getTierFromEnv } from './utils/license.mjs';
import { resolveCapabilities } from './utils/capabilities.mjs';

const _require = createRequire(import.meta.url);
const { version: TOOL_VERSION } = _require('./package.json');

// ---------------------------------------------------------------------------
// License tier & capability resolution (module-level, overridable for tests)
// ---------------------------------------------------------------------------

let _tier = getTierFromEnv();
let _capabilities = resolveCapabilities(_tier);

/** Allow tests to override tier without touching env vars. */
export function _setTier(tier) {
  _tier = tier ?? getTierFromEnv();
  _capabilities = resolveCapabilities(_tier);
}

function requireProCapability(toolName) {
  if (_capabilities.proMCP) return null; // Pro/Enterprise: allow
  return {
    content: [{
      type: 'text',
      text: `🔒 **${toolName}** requires a Pro license.\n\nUpgrade at https://www.nsauditor.com/ai/pricing or start a free 14-day trial (no credit card) at https://www.nsauditor.com/ai/trial\n\n**CE tools available:** scan_host, list_plugins`,
    }],
    isError: false,
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
  _pluginManager = await PluginManager.create('./plugins');
  return _pluginManager;
}

async function getNvdClient() {
  if (_nvdClient) return _nvdClient;
  const { createNvdClient } = await import('./utils/nvd_client.mjs');
  _nvdClient = createNvdClient();
  return _nvdClient;
}

/** Allow tests to inject mocks without touching the real modules. */
export function _setPluginManager(pm) { _pluginManager = pm; }
export function _setNvdClient(client) { _nvdClient = client; }

let _validateHostFn = validateHost;
export function _setValidateHost(fn) { _validateHostFn = fn ?? validateHost; }

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
  // Fast-path regex check
  if (/^(localhost|127\.|0\.|::1|0\.0\.0\.0|169\.254\.|fe80:|metadata\.google)/i.test(h)) {
    throw new Error('Scanning loopback, link-local, or metadata addresses is not allowed via MCP');
  }

  // DNS resolution check — catches rebinding, decimal/octal IPs, IPv6-mapped addrs
  try {
    await resolveAndValidate(h);
  } catch (err) {
    throw new Error('Scanning loopback, link-local, or metadata addresses is not allowed via MCP');
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
  return {
    host: output.host,
    conclusion: output.conclusion ?? null,
    manifest: output.manifest ?? [],
    pluginsRan: output.results?.length ?? 0,
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
  const server = createServer();
  const transport = new StdioServerTransport();
  await server.connect(transport);
}
