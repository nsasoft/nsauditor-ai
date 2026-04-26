// tests/mcp_scanner.test.mjs
//
// Tests for the MCP server scanner plugin (Task N.30). Uses real localhost
// HTTP servers (no mocks) following the project's existing pattern.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';

import mcpScanner, {
  MCP_CANDIDATE_PORTS,
  MCP_INSPECTOR_PORTS,
  MCP_PROBE_PATHS,
  conclude as mcpConclude,
  _internals,
} from '../plugins/mcp_scanner.mjs';

const {
  tryParseJsonRpc,
  detectMcpInitialize,
  extractToolNames,
  isProtocolOlderThan,
  isLoopback,
  buildFindings,
  CURRENT_PROTOCOL_VERSION,
} = _internals;

/* ------------------------------ helpers ------------------------------ */

/**
 * Spin up a local HTTP server with a custom request handler. Returns
 * { port, close } — port is dynamically assigned.
 */
function startMockServer(handler) {
  return new Promise((resolve, reject) => {
    const server = http.createServer(handler);
    server.on('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      resolve({
        port,
        close: () => new Promise((r) => server.close(() => r())),
      });
    });
  });
}

// Run the plugin against an explicit port (mock server). Uses the test-injection
// opts.candidatePorts override since OS-assigned high ports (50000+) fall outside
// the production dynamic-port heuristic (3000-9000).
function runPluginAgainstPort(port, extraOpts = {}) {
  return mcpScanner.run('127.0.0.1', 0, {
    timeoutMs: 1500,
    candidatePorts: [port],
    ...extraOpts,
  });
}

/* ------------------------------ pure helpers ------------------------------ */

test('tryParseJsonRpc: returns null for non-JSON', () => {
  assert.equal(tryParseJsonRpc(''), null);
  assert.equal(tryParseJsonRpc(null), null);
  assert.equal(tryParseJsonRpc('not json'), null);
  assert.equal(tryParseJsonRpc('<html>nope</html>'), null);
});

test('tryParseJsonRpc: returns null when jsonrpc field is missing', () => {
  assert.equal(tryParseJsonRpc('{"id":1, "result":{}}'), null);
});

test('tryParseJsonRpc: returns parsed object for valid JSON-RPC 2.0', () => {
  const r = tryParseJsonRpc('{"jsonrpc":"2.0","id":1,"result":{"x":1}}');
  assert.equal(r.jsonrpc, '2.0');
  assert.equal(r.result.x, 1);
});

test('detectMcpInitialize: requires result.protocolVersion', () => {
  assert.equal(detectMcpInitialize({ result: {} }), null);
  assert.equal(detectMcpInitialize({ result: { protocolVersion: 42 } }), null);
});

test('detectMcpInitialize: returns full info on valid response', () => {
  const r = detectMcpInitialize({
    result: {
      protocolVersion: '2024-11-05',
      serverInfo: { name: 'test', version: '1' },
      capabilities: { tools: {} },
    },
  });
  assert.equal(r.mcp, true);
  assert.equal(r.protocolVersion, '2024-11-05');
  assert.deepEqual(r.serverInfo, { name: 'test', version: '1' });
});

test('extractToolNames: returns empty for non-list result', () => {
  assert.deepEqual(extractToolNames(null), []);
  assert.deepEqual(extractToolNames({ result: { tools: 'not array' } }), []);
});

test('extractToolNames: extracts and caps to 50 tools', () => {
  const tools = Array.from({ length: 100 }, (_, i) => ({ name: `tool_${i}` }));
  const names = extractToolNames({ result: { tools } });
  assert.equal(names.length, 50);
  assert.equal(names[0], 'tool_0');
});

test('extractToolNames: filters non-string names', () => {
  const r = extractToolNames({ result: { tools: [{ name: 'good' }, { name: 42 }, { other: 'no name' }] } });
  assert.deepEqual(r, ['good']);
});

test('isProtocolOlderThan: accepts YYYY-MM-DD lex compare', () => {
  assert.equal(isProtocolOlderThan('2024-11-05', '2025-03-26'), true);
  assert.equal(isProtocolOlderThan('2025-03-26', '2025-03-26'), false);
  assert.equal(isProtocolOlderThan('2025-12-01', '2025-03-26'), false);
});

test('isProtocolOlderThan: returns false for non-date strings (defensive)', () => {
  assert.equal(isProtocolOlderThan('latest', '2025-03-26'), false);
  assert.equal(isProtocolOlderThan(undefined, '2025-03-26'), false);
  assert.equal(isProtocolOlderThan('1.0.0', '2025-03-26'), false);
});

test('isLoopback: identifies loopback addresses', () => {
  assert.equal(isLoopback('localhost'), true);
  assert.equal(isLoopback('127.0.0.1'), true);
  assert.equal(isLoopback('127.255.255.255'), true);
  assert.equal(isLoopback('::1'), true);
  assert.equal(isLoopback('192.168.1.1'), false);
  assert.equal(isLoopback('10.0.0.1'), false);
  assert.equal(isLoopback('8.8.8.8'), false);
});

/* ------------------------------ buildFindings ------------------------------ */

test('buildFindings: anonymous + non-loopback + http → CRITICAL flags', () => {
  const r = buildFindings({
    host: '192.168.1.28',
    port: 8090,
    detection: { authRequired: false, scheme: 'http', tools: ['read_file', 'execute'], protocolVersion: '2025-03-26' },
  });
  assert.equal(r.flags.mcpAnonymousAccess, true);
  assert.deepEqual(r.flags.mcpAnonymousToolList, ['read_file', 'execute']);
  assert.equal(r.flags.mcpCleartextTransport, true);
  assert.ok(r.cwe.includes('CWE-306'));
  assert.ok(r.cwe.includes('CWE-319'));
  assert.ok(r.mitre.includes('T1190'));
  assert.ok(r.mitre.includes('T1059'));
  assert.ok(r.mitre.includes('T1040'));
});

test('buildFindings: auth required → no anonymous flags (positive observation)', () => {
  const r = buildFindings({
    host: '192.168.1.28',
    port: 8090,
    detection: { authRequired: true, scheme: 'http', tools: [], protocolVersion: null },
  });
  assert.equal(r.flags.mcpAnonymousAccess, undefined);
  assert.equal(r.flags.mcpAnonymousToolList, undefined);
  // Cleartext flag still fires (auth or not, HTTP transport leaks tokens)
  assert.equal(r.flags.mcpCleartextTransport, true);
});

test('buildFindings: localhost target does NOT get mcpAnonymousAccess', () => {
  // Anonymous + localhost = developer tool, not externally accessible — no finding
  const r = buildFindings({
    host: '127.0.0.1',
    port: 5173,
    detection: { authRequired: false, scheme: 'http', tools: [], protocolVersion: '2025-03-26' },
  });
  assert.equal(r.flags.mcpAnonymousAccess, undefined);
  // But Inspector port on loopback also doesn't fire (it's localhost — fine)
  assert.equal(r.flags.mcpInspectorExposed, undefined);
});

test('buildFindings: Inspector port (5173) on non-loopback → MEDIUM finding', () => {
  const r = buildFindings({
    host: '192.168.1.28',
    port: 5173,
    detection: { authRequired: true, scheme: 'http', tools: [], protocolVersion: '2025-03-26' },
  });
  assert.equal(r.flags.mcpInspectorExposed, true);
  assert.ok(r.cwe.includes('CWE-200'));
});

test('buildFindings: deprecated protocol version → mcpDeprecatedProtocol flag', () => {
  const r = buildFindings({
    host: '192.168.1.28',
    port: 8090,
    detection: { authRequired: true, scheme: 'https', tools: [], protocolVersion: '2024-11-05' },
  });
  assert.equal(r.flags.mcpDeprecatedProtocol, '2024-11-05');
  assert.ok(r.cwe.includes('CWE-1395'));
});

test('buildFindings: HTTPS + auth + current protocol → no findings (clean)', () => {
  const r = buildFindings({
    host: '192.168.1.28',
    port: 8443,
    detection: { authRequired: true, scheme: 'https', tools: [], protocolVersion: CURRENT_PROTOCOL_VERSION },
  });
  assert.deepEqual(r.flags, {});
  assert.deepEqual(r.cwe, []);
  assert.deepEqual(r.mitre, []);
});

test('buildFindings: cwe and mitre arrays are deduplicated', () => {
  // Anonymous + tools both push CWE-306 and T1190 — should appear once each
  const r = buildFindings({
    host: '192.168.1.28',
    port: 8090,
    detection: { authRequired: false, scheme: 'https', tools: ['x'], protocolVersion: '2025-03-26' },
  });
  assert.equal(r.cwe.filter((c) => c === 'CWE-306').length, 1);
  assert.equal(r.mitre.filter((m) => m === 'T1190').length, 1);
});

/* ------------------------------ end-to-end against mock servers ------------------------------ */

test('integration: clean MCP server (auth required) → detected, INFO-only', async () => {
  const server = await startMockServer((req, res) => {
    if (req.method === 'POST') {
      res.writeHead(401, { 'WWW-Authenticate': 'Bearer realm="mcp"' });
      res.end('Unauthorized');
    } else {
      res.writeHead(401); res.end();
    }
  });
  try {
    const out = await runPluginAgainstPort(server.port);
    assert.equal(out.up, true);
    assert.equal(out.mcpDetections.length, 1);
    const det = out.mcpDetections[0];
    assert.equal(det.detection.authRequired, true);
    // No anonymous-access flag (auth IS required)
    assert.equal(det.flags.mcpAnonymousAccess, undefined);
    // No anonymous tool list
    assert.equal(det.flags.mcpAnonymousToolList, undefined);
  } finally {
    await server.close();
  }
});

test('integration: anonymous MCP with exposed tools → CRITICAL findings', async () => {
  const server = await startMockServer((req, res) => {
    if (req.method !== 'POST') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end('{}');
      return;
    }
    let body = '';
    req.on('data', (c) => body += c);
    req.on('end', () => {
      const msg = JSON.parse(body);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      if (msg.method === 'initialize') {
        res.end(JSON.stringify({
          jsonrpc: '2.0', id: msg.id,
          result: { protocolVersion: '2024-11-05', serverInfo: { name: 'evil-mcp', version: '0.1' }, capabilities: {} },
        }));
      } else if (msg.method === 'tools/list') {
        res.end(JSON.stringify({
          jsonrpc: '2.0', id: msg.id,
          result: { tools: [{ name: 'execute_shell' }, { name: 'read_file' }, { name: 'write_file' }] },
        }));
      } else {
        res.end('{}');
      }
    });
  });
  try {
    const out = await runPluginAgainstPort(server.port);
    assert.equal(out.up, true);
    const det = out.mcpDetections[0];
    assert.equal(det.detection.authRequired, false);
    assert.deepEqual(det.detection.tools, ['execute_shell', 'read_file', 'write_file']);
    assert.equal(det.detection.protocolVersion, '2024-11-05');

    // localhost is loopback so mcpAnonymousAccess does NOT fire — but the tools list test
    // requires anonymous + tools (which it has) so mcpAnonymousToolList still fires
    assert.deepEqual(det.flags.mcpAnonymousToolList, ['execute_shell', 'read_file', 'write_file']);

    // HTTP cleartext + deprecated protocol both fire regardless of loopback
    assert.equal(det.flags.mcpCleartextTransport, true);
    assert.equal(det.flags.mcpDeprecatedProtocol, '2024-11-05');
  } finally {
    await server.close();
  }
});

test('integration: non-MCP HTTP server → NOT flagged as MCP (false-positive guard)', async () => {
  const server = await startMockServer((req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/html', 'Server': 'nginx/1.24.0' });
    res.end('<html><body>Just a regular web app</body></html>');
  });
  try {
    const out = await runPluginAgainstPort(server.port);
    assert.equal(out.up, false);
    assert.equal(out.mcpDetections.length, 0);
  } finally {
    await server.close();
  }
});

test('integration: SSE Content-Type detection populates ssePresent', async () => {
  const server = await startMockServer((req, res) => {
    if (req.method === 'GET' && /event-stream/i.test(req.headers.accept || '')) {
      res.writeHead(200, { 'Content-Type': 'text/event-stream' });
      res.write('data: hi\n\n');
      res.end();
      return;
    }
    if (req.method !== 'POST') { res.writeHead(404); res.end(); return; }
    let body = '';
    req.on('data', (c) => body += c);
    req.on('end', () => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        jsonrpc: '2.0', id: 1,
        result: { protocolVersion: '2025-03-26', serverInfo: { name: 'sse-mcp' }, capabilities: {} },
      }));
    });
  });
  try {
    const out = await runPluginAgainstPort(server.port);
    assert.equal(out.up, true);
    const det = out.mcpDetections[0];
    assert.equal(det.detection.ssePresent, true);
    // Current protocol version → no deprecated flag
    assert.equal(det.flags.mcpDeprecatedProtocol, undefined);
  } finally {
    await server.close();
  }
});

test('integration: server returns invalid JSON-RPC → not flagged as MCP', async () => {
  const server = await startMockServer((req, res) => {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end('{"id": 1, "result": "looks like rpc but no jsonrpc field"}');
  });
  try {
    const out = await runPluginAgainstPort(server.port);
    assert.equal(out.mcpDetections.length, 0);
  } finally {
    await server.close();
  }
});

test('integration: connection refused on candidate port → silent, no error', async () => {
  // Use a guaranteed-unbound port. Pick a low number unlikely to be bound.
  const out = await runPluginAgainstPort(1, { timeoutMs: 200 });
  assert.equal(out.up, false);
  assert.equal(out.mcpDetections.length, 0);
});

/* ------------------------------ conclude() adapter ------------------------------ */

test('conclude: produces ServiceRecord with security flags + evidence', () => {
  const result = {
    type: 'mcp-scan',
    mcpDetections: [{
      port: 8090,
      detection: {
        path: '/sse',
        scheme: 'http',
        authRequired: false,
        protocolVersion: '2024-11-05',
        serverInfo: { name: 'evil-mcp', version: '0.1' },
        capabilities: {},
        tools: ['execute_shell'],
        ssePresent: true,
      },
      flags: { mcpAnonymousToolList: ['execute_shell'], mcpCleartextTransport: true, mcpDeprecatedProtocol: '2024-11-05' },
      cwe: ['CWE-306', 'CWE-319', 'CWE-1395'],
      owasp: ['A02:2021-Cryptographic Failures'],
      mitre: ['T1190', 'T1059', 'T1040'],
    }],
  };
  const records = mcpConclude({ result });
  assert.equal(records.length, 1);
  const r = records[0];
  assert.equal(r.port, 8090);
  assert.equal(r.protocol, 'tcp');
  assert.equal(r.service, 'mcp');
  assert.equal(r.program, 'MCP Server');
  assert.equal(r.version, '2024-11-05');
  assert.equal(r.status, 'open');
  assert.equal(r.authoritative, true);
  assert.equal(r.mcpAnonymousToolList[0], 'execute_shell');
  assert.equal(r.mcpCleartextTransport, true);
  assert.equal(r.mcpDeprecatedProtocol, '2024-11-05');
  assert.deepEqual(r.evidence.cwe, ['CWE-306', 'CWE-319', 'CWE-1395']);
  assert.ok(r.banner.includes('MCP/http'));
  assert.ok(r.banner.includes('auth=NONE'));
  assert.ok(r.banner.includes('transport=sse'));
});

test('conclude: empty mcpDetections returns empty array', () => {
  assert.deepEqual(mcpConclude({ result: { mcpDetections: [] } }), []);
  assert.deepEqual(mcpConclude({ result: {} }), []);
  assert.deepEqual(mcpConclude({}), []);
});

/* ------------------------------ plugin contract ------------------------------ */

test('plugin contract: required fields are present and correctly typed', () => {
  assert.equal(mcpScanner.id, '070');
  assert.equal(mcpScanner.name, 'MCP Scanner');
  assert.equal(typeof mcpScanner.description, 'string');
  assert.equal(mcpScanner.priority, 70);
  assert.deepEqual(mcpScanner.protocols, ['tcp']);
  assert.deepEqual(mcpScanner.requirements, { host: 'up' });
  assert.equal(mcpScanner.runStrategy, 'single');
  assert.equal(typeof mcpScanner.run, 'function');
  assert.equal(typeof mcpConclude, 'function');
});

test('plugin contract: candidate port list includes the research-§2.2 references', () => {
  for (const p of [1967, 3000, 3005, 5173, 6274, 6277, 8000, 8090]) {
    assert.ok(MCP_CANDIDATE_PORTS.includes(p), `MCP candidate ports must include ${p}`);
  }
  for (const p of [5173, 6274, 6277]) {
    assert.ok(MCP_INSPECTOR_PORTS.has(p), `Inspector port ${p} must be flagged`);
  }
});

test('plugin contract: probe paths cover MCP convention mountpoints', () => {
  for (const p of ['/', '/mcp', '/jsonrpc', '/sse', '/messages']) {
    assert.ok(MCP_PROBE_PATHS.includes(p), `MCP probe paths must include ${p}`);
  }
});
