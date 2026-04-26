import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { TOOL_VERSION, TOOL_NAME } from '../utils/tool_version.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(__dirname, '..');
const PKG = JSON.parse(readFileSync(join(REPO_ROOT, 'package.json'), 'utf8'));

test('TOOL_VERSION is a non-empty string', () => {
  assert.equal(typeof TOOL_VERSION, 'string');
  assert.ok(TOOL_VERSION.length > 0, 'TOOL_VERSION must not be empty');
});

test('TOOL_VERSION matches package.json version', () => {
  assert.equal(TOOL_VERSION, PKG.version);
});

test('TOOL_VERSION matches semver-ish pattern', () => {
  assert.match(TOOL_VERSION, /^\d+\.\d+\.\d+/);
});

test('TOOL_NAME exposes the package name', () => {
  assert.equal(TOOL_NAME, PKG.name);
});

// ---------------------------------------------------------------------------
// Bug-class regression: resolution must work with no `npm_*` env vars.
//
// Pre-fix code used `process.env.npm_package_version` which is only set by
// `npm run`. When users invoke through the bin shim, that env var is
// undefined and the rendered Markdown silently dropped the version line.
// This subprocess spawn proves the new resolution path is independent of npm.
// ---------------------------------------------------------------------------

test('TOOL_VERSION resolves correctly in a subprocess with no npm env vars', () => {
  // Strip every npm_*-prefixed env var to simulate the bin-shim invocation.
  const cleanEnv = Object.fromEntries(
    Object.entries(process.env).filter(([k]) => !k.startsWith('npm_'))
  );

  const result = spawnSync(
    process.execPath,
    [
      '-e',
      `import('./utils/tool_version.mjs').then(m => process.stdout.write(m.TOOL_VERSION))`,
    ],
    { cwd: REPO_ROOT, env: cleanEnv, encoding: 'utf8' }
  );

  assert.equal(result.status, 0, `subprocess exited with ${result.status}: ${result.stderr}`);
  assert.equal(result.stdout, PKG.version, `expected "${PKG.version}", got "${result.stdout}"`);
});
