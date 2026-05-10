#!/usr/bin/env node
// CE 0.1.37 (SECURITY): delegate to startStdioServer() so the auth
// check + license verification + rotation warnings actually run.
// Pre-0.1.37 this file inlined `createServer() + server.connect()`,
// which silently bypassed the entire startup block in mcp_server.mjs
// (it was guarded by an argv[1].endsWith('mcp_server.mjs') check that
// only matched when invoked directly, never via this shim). Result:
// every Claude Desktop session ran unauthenticated and tier-stuck-at-CE.
import { startStdioServer } from '../mcp_server.mjs';

await startStdioServer();
