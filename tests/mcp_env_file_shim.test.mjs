import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { writeFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const BIN = fileURLToPath(new URL('../bin/nsauditor-ai-mcp.mjs', import.meta.url));

// NSA_MCP_AUTH_DISABLE=1 lets the server start without an installed key so the
// test exercises the NSA_ENV_FILE path itself, not auth.
function runShim(extraEnv, { killOnBreadcrumb = false } = {}) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [BIN], {
      env: { ...process.env, NSA_MCP_AUTH_DISABLE: '1', ...extraEnv },
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    let stderr = '';
    child.stderr.on('data', (d) => {
      stderr += d.toString();
      if (killOnBreadcrumb && stderr.includes('Loaded scan environment from')) {
        child.kill('SIGKILL');
      }
    });
    child.on('close', (code) => resolve({ code, stderr }));
    if (!killOnBreadcrumb) child.stdin.end(); // success path waits on stdin otherwise
  });
}

test('installed bin shim applies NSA_ENV_FILE (entrypoint actually runs the load)', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'nsa-env-'));
  const envFile = join(dir, 'scan.env');
  writeFileSync(envFile, 'CLOUD_PROVIDER=aws\nAWS_ACCESS_KEY_ID=AKIATEST\n');
  const { stderr } = await runShim({ NSA_ENV_FILE: envFile }, { killOnBreadcrumb: true });
  assert.ok(stderr.includes('Loaded scan environment from'), stderr);
  assert.ok(stderr.includes('CLOUD_PROVIDER'), stderr);
});

test('installed bin shim fail-fast: missing NSA_ENV_FILE → exit 1', async () => {
  const { code, stderr } = await runShim({ NSA_ENV_FILE: '/no/such/file.env' });
  assert.equal(code, 1);
  assert.ok(stderr.includes('NSA_ENV_FILE'), stderr);
});
