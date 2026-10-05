// KEEP A TEST FILE OUT OF THE OPERATOR'S REAL ~/.nsauditor.
//
// ⚠️ THE DEFECT THIS CLOSES, MEASURED 2026-10-05. mcp_server.mjs computes
// `MCP_CALL_LOG_PATH = join(homedir(), '.nsauditor', 'mcp-calls.log')` ONCE, at module load, and
// every tool handler appends a line to it. That file is the operator's provenance log — the one
// `nsauditor-ai mcp verify-call <id>` reads to prove a tool call really happened — and
// tests/mcp_get_findings.test.mjs appended 3 lines to the REAL one on every run (it was the only
// CE test file that did, measured by line count over each file run alone).
//
// os.homedir() reads $HOME first on POSIX, so pointing HOME at a scratch directory BEFORE
// mcp_server.mjs evaluates moves the log without a product change. Same reasoning as
// no_operator_keychain.mjs: an env var is inherited by any child the file spawns, and as the FIRST
// import this runs before any other module's top-level code — placing it in the test body would be
// too late, because the path is already computed by then.
//
// `??=` so an outer harness that has already chosen a scratch HOME keeps it.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

process.env.NSA_TEST_HOME ??= fs.mkdtempSync(path.join(os.tmpdir(), `nsa-home-test-${process.pid}-`));
process.env.HOME = process.env.NSA_TEST_HOME;
process.on('exit', () => { try { fs.rmSync(process.env.NSA_TEST_HOME, { recursive: true, force: true }); } catch { /* best effort */ } });
