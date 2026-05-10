import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(__dirname, '..');
const BIN_PATH = resolve(REPO_ROOT, 'bin/nsauditor-ai-mcp.mjs');

// CE 0.1.37 (SECURITY regression test): Pre-0.1.37 the bin shim called
// createServer() + server.connect() directly, bypassing the
// `if (isMainModule)` startup block that runs auth + loadLicense.
// Result: Claude Desktop's MCP child ran unauthenticated and tier-stuck-at-CE.
//
// Canary: spawn the bin shim with NSA_MCP_AUTH_DISABLE unset and NO
// NSA_MCP_AUTH_KEY env. The auth check MUST fire and refuse startup
// (exit code 1, error on stderr). If the bin shim regresses to bypassing
// startup again, the spawn will succeed and this test will fail.
describe('bin/nsauditor-ai-mcp.mjs — startup wiring', () => {
  it('runs the auth check on startup (refuses to start without a key)', async () => {
    const result = await new Promise((resolveProm) => {
      const child = spawn(process.execPath, [BIN_PATH], {
        env: {
          // Strip everything operator-related — auth check must trip.
          PATH: '/usr/bin:/bin',
          HOME: process.env.HOME ?? '/tmp',
          // Force the file-only resolver away from the real keychain
          // so this test works on any developer's machine regardless
          // of their installed key.
          NSA_MCP_AUTH_KEY_FILE: '/nonexistent/no-such-file',
        },
        stdio: ['pipe', 'pipe', 'pipe'],
      });
      let stderr = '';
      child.stderr.on('data', (d) => { stderr += d.toString('utf8'); });
      child.on('exit', (code) => resolveProm({ code, stderr }));
      // Send a no-op so child has stdin to read; close to force exit if it didn't already.
      child.stdin.end();
    });
    // Auth check ran and refused startup. The exact error text is
    // intentionally not asserted (will change with future copy edits);
    // the contract is "exit nonzero with a stderr message".
    assert.notEqual(result.code, 0,
      `Bin shim must refuse to start without auth — got exit ${result.code}. ` +
      `If this fails, the bin shim has regressed to bypassing startStdioServer().`);
    assert.ok(result.stderr.length > 0,
      `Auth-refusal stderr message expected; got empty stderr.`);
  });
});
