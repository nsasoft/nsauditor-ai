// plugins/mcp_scanner.mjs
//
// MCP (Model Context Protocol) server detection and security audit.
//
// Detects HTTP/SSE-transport MCP servers on the target host by sending a safe,
// canonical JSON-RPC `initialize` request to a curated set of candidate paths
// on candidate ports. Identifies the MCP server's transport (HTTP vs SSE),
// protocol version, server info, auth requirement, and (when no auth is
// required) enumerates the exposed tools.
//
// Maps observations to the audit checklist in `tasks/mcp-server-audit-research.md`
// §5 and produces structured findings via per-service flags consumed by the
// concluder, AI prompt, Markdown report, and SARIF/CSV exporters.
//
// SAFETY: All probes are read-only at the application layer:
//   - GET  → for SSE Content-Type detection (no body sent)
//   - POST → only the canonical JSON-RPC `initialize` and `tools/list` calls
//            (defined by the MCP spec as introspection operations, equivalent
//            to a "what protocol are you" handshake — not exploitation)
//   - No tool/X invocation is ever attempted (would actually call MCP tools)
//   - No payload variations or fuzzing
//
// LIMITATIONS:
//   - STDIO-transport MCP servers do NOT bind ports → invisible to network
//     scanning. Per research §2.1, stdio is the dominant local pattern. This
//     plugin only catches HTTP/SSE transport. STDIO audit requires file-system
//     inspection of MCP host configs (e.g. claude_desktop_config.json) — a
//     different scope, not covered here.
//
// Reference: tasks/mcp-server-audit-research.md (in-tree research file).

import http from 'node:http';
import https from 'node:https';

/* ------------------------------ constants ------------------------------ */

// Per research §2.2 — common MCP-server ports (plus 8090 from real-world
// SSE deployment observed during N.27 verification).
export const MCP_CANDIDATE_PORTS = [1967, 3000, 3005, 5173, 6274, 6277, 8000, 8090];

// Per research §2.2 + 7.4 — Inspector dev tooling that should NEVER be
// network-reachable. Detection on a non-loopback target = MEDIUM finding.
export const MCP_INSPECTOR_PORTS = new Set([5173, 6274, 6277]);

// MCP RPC method paths (in priority order — try canonical mountpoints first)
export const MCP_PROBE_PATHS = ['/', '/mcp', '/jsonrpc', '/sse', '/messages'];

// Standard HTTPS-conventional ports — try TLS first on these
const HTTPS_CONVENTIONAL = new Set([443, 8443]);

// Latest stable MCP protocol version at time of writing. Anything older
// than this in a server's initialize response → HIGH finding (deprecated).
// Update this constant when MCP spec advances.
const CURRENT_PROTOCOL_VERSION = '2025-03-26';

// JSON-RPC body templates (built once; both calls are safe + read-only)
const INITIALIZE_BODY = JSON.stringify({
  jsonrpc: '2.0',
  id: 1,
  method: 'initialize',
  params: {
    protocolVersion: '2024-11-05',
    capabilities: {},
    clientInfo: { name: 'nsauditor-mcp-probe', version: '1.0' },
  },
});

const TOOLS_LIST_BODY = JSON.stringify({
  jsonrpc: '2.0', id: 2, method: 'tools/list', params: {},
});

const DEBUG = /^(1|true|yes|on)$/i.test(String(process.env.DEBUG_MODE || process.env.MCP_SCANNER_DEBUG || ''));
function dlog(...a) { if (DEBUG) console.log('[mcp-scanner]', ...a); }

/* ------------------------------ helpers ------------------------------ */

/**
 * Single HTTP/HTTPS request. Always-resolves Promise (never rejects).
 * Returns { ok, status, headers, body, error } where ok=false means the
 * connection failed entirely.
 */
function httpRequest({ host, port, path, method, body, headers, timeoutMs, isHttps, allowInsecure }) {
  return new Promise((resolve) => {
    const mod = isHttps ? https : http;
    const agent = isHttps ? new https.Agent({ rejectUnauthorized: !allowInsecure }) : undefined;
    const reqHeaders = {
      'User-Agent': 'nsauditor-mcp-probe/0.1',
      Accept: 'application/json, text/event-stream',
      ...(body ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) } : {}),
      ...(headers || {}),
    };
    const req = mod.request({ host, port, method, path, headers: reqHeaders, agent }, (res) => {
      let buf = '';
      let cancelled = false;
      // Cap response body to avoid OOM on a hostile server that streams forever
      const MAX_BODY = 32 * 1024;
      res.on('data', (chunk) => {
        if (cancelled) return;
        buf += chunk.toString('utf8');
        if (buf.length > MAX_BODY) {
          cancelled = true;
          buf = buf.slice(0, MAX_BODY);
          req.destroy();
        }
      });
      res.on('end', () => {
        resolve({ ok: true, status: res.statusCode, headers: res.headers, body: buf, error: null });
      });
      res.on('error', (err) => resolve({ ok: false, status: 0, headers: {}, body: '', error: err.message }));
    });
    req.setTimeout(timeoutMs, () => {
      req.destroy(new Error('timeout'));
    });
    req.on('error', (err) => resolve({ ok: false, status: 0, headers: {}, body: '', error: err.message }));
    if (body) req.write(body);
    req.end();
  });
}

/**
 * Try to extract a parsed JSON-RPC response from an arbitrary HTTP response body.
 * Returns null if it doesn't look like a JSON-RPC payload.
 */
function tryParseJsonRpc(body) {
  if (!body || typeof body !== 'string') return null;
  const trimmed = body.trim();
  if (!trimmed.startsWith('{') && !trimmed.startsWith('[')) return null;
  try {
    const parsed = JSON.parse(trimmed);
    if (parsed?.jsonrpc === '2.0') return parsed;
    return null;
  } catch { return null; }
}

/**
 * Determine if an HTTP response looks like a valid MCP `initialize` reply.
 * Returns { mcp: true, protocolVersion, serverInfo, capabilities } or null.
 */
function detectMcpInitialize(parsed) {
  if (!parsed?.result) return null;
  const r = parsed.result;
  if (typeof r.protocolVersion !== 'string') return null;
  return {
    mcp: true,
    protocolVersion: r.protocolVersion,
    serverInfo: r.serverInfo || null,
    capabilities: r.capabilities || {},
  };
}

/**
 * Try to extract tool list (names) from a JSON-RPC `tools/list` reply.
 */
function extractToolNames(parsed) {
  const tools = parsed?.result?.tools;
  if (!Array.isArray(tools)) return [];
  return tools.map((t) => t?.name).filter((n) => typeof n === 'string').slice(0, 50);
}

/**
 * Compare two YYYY-MM-DD MCP protocol date strings. Returns true if `version`
 * is older (lexically less than) `current`.
 */
function isProtocolOlderThan(version, current) {
  // MCP protocol versions are dated strings. Lexical compare works for ISO-ish dates.
  // We require version to look like YYYY-MM-DD; otherwise treat as not-older
  // (don't penalize unknown-format responses).
  if (typeof version !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(version)) return false;
  return version < current;
}

/**
 * Check if a host is a loopback address (per RFC 5735 / RFC 4291).
 * Used to gate the "MCP bound to non-loopback" finding — we only flag if the
 * scan target is NOT loopback.
 */
function isLoopback(host) {
  const h = String(host || '').toLowerCase();
  if (h === 'localhost' || h === '::1') return true;
  // 127.0.0.0/8
  if (/^127\./.test(h)) return true;
  return false;
}

/* ------------------------------ probe ------------------------------ */

/**
 * Probe one (host, port, isHttps) combination for MCP. Returns a detection
 * record or null if not MCP.
 */
async function probePort({ host, port, isHttps, timeoutMs, allowInsecure }) {
  const evidence = [];
  const scheme = isHttps ? 'https' : 'http';

  // Try each candidate path with the JSON-RPC initialize call
  for (const path of MCP_PROBE_PATHS) {
    const initResp = await httpRequest({
      host, port, path, method: 'POST', body: INITIALIZE_BODY,
      timeoutMs, isHttps, allowInsecure,
    });

    if (!initResp.ok) {
      evidence.push({ path, status: 0, info: 'connection failed', error: initResp.error });
      continue;
    }

    // 401/403 with hint of auth → MCP server probable, auth required (good)
    if (initResp.status === 401 || initResp.status === 403) {
      const wwwAuth = initResp.headers['www-authenticate'];
      const looksAuth = !!wwwAuth || /unauthorized|forbidden|bearer/i.test(initResp.body || '');
      if (looksAuth) {
        evidence.push({
          path, status: initResp.status,
          info: `auth required (${initResp.status})`,
          wwwAuthenticate: Array.isArray(wwwAuth) ? wwwAuth.join('; ') : (wwwAuth || null),
        });
        return {
          mcp: true,
          path,
          scheme,
          authRequired: true,
          status: initResp.status,
          protocolVersion: null,
          serverInfo: null,
          capabilities: null,
          tools: [],
          ssePresent: false,
          evidence,
        };
      }
    }

    // 200 with parseable JSON-RPC `initialize` response → MCP confirmed
    if (initResp.status === 200) {
      const parsed = tryParseJsonRpc(initResp.body);
      const mcpInfo = detectMcpInitialize(parsed);
      if (mcpInfo) {
        evidence.push({
          path, status: 200,
          info: `MCP initialize succeeded (protocolVersion=${mcpInfo.protocolVersion})`,
          serverInfo: mcpInfo.serverInfo,
        });

        // Probe SSE: GET with Accept: text/event-stream — check if Content-Type is SSE
        const sseResp = await httpRequest({
          host, port, path, method: 'GET',
          headers: { Accept: 'text/event-stream' },
          timeoutMs: Math.min(timeoutMs, 1000),
          isHttps, allowInsecure,
        });
        const contentType = sseResp.headers?.['content-type'] || '';
        const ssePresent = /text\/event-stream/i.test(String(contentType));

        // Probe tools/list (anonymous tool enumeration — only if initialize
        // succeeded without auth, which it did here since status was 200)
        const toolsResp = await httpRequest({
          host, port, path, method: 'POST', body: TOOLS_LIST_BODY,
          timeoutMs, isHttps, allowInsecure,
        });
        const toolsParsed = tryParseJsonRpc(toolsResp.body);
        const toolNames = extractToolNames(toolsParsed);

        if (toolNames.length > 0) {
          evidence.push({ path, status: toolsResp.status, info: `tools/list returned ${toolNames.length} tool(s)`, tools: toolNames });
        }

        return {
          mcp: true,
          path,
          scheme,
          authRequired: false,
          status: 200,
          protocolVersion: mcpInfo.protocolVersion,
          serverInfo: mcpInfo.serverInfo,
          capabilities: mcpInfo.capabilities,
          tools: toolNames,
          ssePresent,
          evidence,
        };
      }
      evidence.push({ path, status: 200, info: 'HTTP 200 but no MCP-shaped response' });
    } else {
      evidence.push({ path, status: initResp.status, info: `unexpected status ${initResp.status}` });
    }
  }

  return null;
}

/* ------------------------------ findings ------------------------------ */

/**
 * Build per-port security flags from a detection record. Maps to research
 * §5 audit checklist + populates cwe/owasp/mitre fields per FindingSchema.
 */
function buildFindings({ host, port, detection }) {
  const flags = {};
  const cwe = [];
  const owasp = [];
  const mitre = [];

  // CRITICAL: MCP bound to non-loopback without auth (research §2.3, §3.3)
  if (!detection.authRequired && !isLoopback(host)) {
    flags.mcpAnonymousAccess = true;
    cwe.push('CWE-306'); // Missing Authentication
    owasp.push('A01:2021-Broken Access Control');
    mitre.push('T1190'); // Exploit Public-Facing Application
  }

  // CRITICAL: tools/list returned tools without auth (anonymous capability disclosure)
  if (!detection.authRequired && Array.isArray(detection.tools) && detection.tools.length > 0) {
    flags.mcpAnonymousToolList = detection.tools.slice(0, 20);
    if (!cwe.includes('CWE-306')) cwe.push('CWE-306');
    if (!mitre.includes('T1190')) mitre.push('T1190');
    mitre.push('T1059'); // Command and Scripting Interpreter (tools may execute)
  }

  // HIGH: HTTP not HTTPS — bearer tokens in cleartext (research §3.3)
  if (detection.scheme === 'http') {
    flags.mcpCleartextTransport = true;
    cwe.push('CWE-319'); // Cleartext Transmission
    owasp.push('A02:2021-Cryptographic Failures');
    mitre.push('T1040'); // Network Sniffing
  }

  // HIGH: deprecated protocol version
  if (detection.protocolVersion && isProtocolOlderThan(detection.protocolVersion, CURRENT_PROTOCOL_VERSION)) {
    flags.mcpDeprecatedProtocol = detection.protocolVersion;
    cwe.push('CWE-1395'); // Use of Outdated/Deprecated Component
  }

  // MEDIUM: MCP Inspector exposed on a non-loopback address
  if (MCP_INSPECTOR_PORTS.has(port) && !isLoopback(host)) {
    flags.mcpInspectorExposed = true;
    cwe.push('CWE-200'); // Information Exposure
    owasp.push('A05:2021-Security Misconfiguration');
  }

  return { flags, cwe: [...new Set(cwe)], owasp: [...new Set(owasp)], mitre: [...new Set(mitre)] };
}

/* ------------------------------ runner ------------------------------ */

export default {
  id: '070',
  name: 'MCP Scanner',
  description: 'Detects HTTP/SSE-transport MCP (Model Context Protocol) servers and audits them for cleartext transport, missing authentication, deprecated protocol versions, and Inspector exposure.',
  priority: 70,
  protocols: ['tcp'],
  ports: [],
  runStrategy: 'single',
  requirements: { host: 'up' },

  // run(host, _portIgnored, opts)
  async run(host, _port = 0, opts = {}) {
    const timeoutMs = parseInt(opts.timeoutMs ?? process.env.MCP_PROBE_TIMEOUT_MS ?? 2000, 10);
    const allowInsecure = !!(opts.insecureHttps ?? /^(1|true|yes|on)$/i.test(String(process.env.INSECURE_HTTPS || '')));

    // Build the candidate port list:
    //  - opts.candidatePorts (test injection / programmatic override) takes full precedence
    //  - Otherwise: static MCP_CANDIDATE_PORTS (research §2.2)
    //              + any open TCP ports from prior plugins' context that fall in
    //                the 3000-9000 MCP-likely range (also from research §2.2)
    let candidatePorts;
    if (Array.isArray(opts.candidatePorts) && opts.candidatePorts.length > 0) {
      candidatePorts = [...new Set(opts.candidatePorts.filter(Number.isInteger))];
    } else {
      const ctxOpen = (opts.context?.tcpOpen instanceof Set) ? [...opts.context.tcpOpen] : [];
      const dynamicPorts = ctxOpen.filter(p => p >= 3000 && p <= 9000);
      candidatePorts = [...new Set([...MCP_CANDIDATE_PORTS, ...dynamicPorts])];
    }

    dlog(`probing ${candidatePorts.length} candidate ports on ${host}: ${candidatePorts.join(',')}`);

    const detections = [];
    const data = [];

    for (const port of candidatePorts) {
      // Try HTTPS first on conventional HTTPS ports, otherwise HTTP
      const isHttps = HTTPS_CONVENTIONAL.has(port);
      const detection = await probePort({ host, port, isHttps, timeoutMs, allowInsecure });

      // Always-record probe attempt evidence (even when no MCP found) to aid debugging
      data.push({
        probe_protocol: 'tcp',
        probe_port: port,
        probe_info: detection ? `MCP server detected via ${detection.scheme} ${detection.path}` : 'no MCP response',
        response_banner: detection ? JSON.stringify({
          protocolVersion: detection.protocolVersion,
          authRequired: detection.authRequired,
          serverInfo: detection.serverInfo,
          tools: detection.tools.length,
          sse: detection.ssePresent,
        }) : null,
      });

      if (detection) {
        const { flags, cwe, owasp, mitre } = buildFindings({ host, port, detection });
        detections.push({ port, detection, flags, cwe, owasp, mitre });
      }
    }

    return {
      up: detections.length > 0,
      type: 'mcp-scan',
      program: detections.length > 0 ? 'MCP Server' : 'Unknown',
      version: detections[0]?.detection?.protocolVersion || 'Unknown',
      os: null,
      mcpDetections: detections,
      data,
    };
  },
};

/**
 * Concluder adapter — convert per-detection records into ServiceRecord
 * entries keyed by (protocol, port). Merges security flags into each
 * service record so downstream consumers (AI prompt, Markdown report,
 * SARIF, CSV) can surface them via the existing per-service flag pattern.
 *
 * Exported as a NAMED export (not on the default object) so that the
 * result_concluder's `mod.conclude` lookup at result_concluder.mjs:189
 * resolves correctly. Convention matches webapp_detector.mjs and other
 * plugins that ship a conclude adapter.
 */
export function conclude({ result }) {
  if (!Array.isArray(result?.mcpDetections) || result.mcpDetections.length === 0) return [];
  return result.mcpDetections.map(({ port, detection, flags, cwe, owasp, mitre }) => ({
    port,
    protocol: 'tcp',
    service: 'mcp',
    program: 'MCP Server',
    version: detection.protocolVersion || 'Unknown',
    status: 'open',
    banner: [
      `MCP/${detection.scheme}`,
      detection.serverInfo?.name ? `server=${detection.serverInfo.name}` : null,
      detection.serverInfo?.version ? `v${detection.serverInfo.version}` : null,
      `path=${detection.path}`,
      detection.authRequired ? 'auth=required' : 'auth=NONE',
      detection.ssePresent ? 'transport=sse' : 'transport=http',
      detection.tools.length ? `tools=${detection.tools.length}` : null,
    ].filter(Boolean).join(' '),
    authoritative: true,
    // Security flags (consumed by AI prompt / report renderer / SARIF)
    ...flags,
    // Evidence fields per N.5 FindingSchema
    evidence: { cwe, owasp, mitre },
  }));
}

// Internal helpers exported for testing
export const _internals = {
  tryParseJsonRpc,
  detectMcpInitialize,
  extractToolNames,
  isProtocolOlderThan,
  isLoopback,
  buildFindings,
  CURRENT_PROTOCOL_VERSION,
};
