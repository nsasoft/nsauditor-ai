// tests/cli_license_plugins_requires_label.test.mjs
// ─────────────────────────────────────────────────────────────────────────────
// `license --plugins` — THE "✗ requires: <tier>" LABEL IS THE TIER THE GATE ENFORCES (CE 0.2.55).
//
// Measured 2026-09-28 (EE 1.1.0 build 11): at Community tier the list printed `✗ requires: pro` for
// EE 1020 (AWS S3) and 1030 (AWS IAM). Both require `cloudScanners`, which Pro does not grant — so the
// list told a Community user that a Pro licence unlocks two plugins it does not. The label read
// `plugin.tier ?? inferredTier ?? 'pro'`: the manifest's own `tier` word outranked the tier derived
// from the capabilities the plugin manager actually checks, and both plugins declared `tier: "pro"`.
// The earlier guard for this class (`cli_license_plugins.test.mjs`, reviewer M2) keyed on the ids
// 020 / 021 / 022 / 023 / 030; EE's ids have been 1020… since the renumbering, so it matched no line
// and passed over the defect it was written for.
//
// The label now derives from the required capabilities alone. These legs drive the REAL command over
// fixture plugins (NSAUDITOR_PLUGIN_PATH under a temporary HOME; a licence key that does not verify,
// so the tier is Community and the operator's Keychain is never read). Fourth quadrant first: the
// correct declaration, the Pro-capability case and the ungated case are green before and after.
// ─────────────────────────────────────────────────────────────────────────────

import './helpers/no_operator_keychain.mjs';   // FIRST: keeps this file off the operator's real Keychain
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const CLI_PATH = join(REPO_ROOT, 'cli.mjs');

const FIXTURES = {
  '9101_correct_enterprise.mjs': { id: '9101', name: 'Fixture Correct Enterprise', tier: 'enterprise', requiredCapabilities: ['cloudScanners'] },
  '9102_pro_capability.mjs': { id: '9102', name: 'Fixture Pro Capability', requiredCapabilities: ['intelligenceEngine'] },
  '9103_ungated.mjs': { id: '9103', name: 'Fixture Ungated' },
  '9104_declares_pro_needs_ent.mjs': { id: '9104', name: 'Fixture Declares Pro', tier: 'pro', requiredCapabilities: ['cloudScanners'] },
  '9105_unknown_capability.mjs': { id: '9105', name: 'Fixture Unknown Cap', requiredCapabilities: ['notACapability'] },
};

let cached = null;
function runPlugins() {
  if (cached) return cached;
  // realpath: discovery admits a plugin path only under $HOME, compared WITHOUT resolving symlinks,
  // and macOS tmpdir is a symlink (/var → /private/var).
  const home = fs.realpathSync(fs.mkdtempSync(join(os.tmpdir(), 'nsa-requires-label-')));
  const dir = join(home, 'plugins');
  fs.mkdirSync(dir);
  for (const [file, def] of Object.entries(FIXTURES)) {
    fs.writeFileSync(join(dir, file), `export default { ...${JSON.stringify(def)}, priority: 999, run: async () => ({ up: false }) };\n`);
  }
  const env = {
    ...process.env,
    HOME: home,
    XDG_CONFIG_HOME: join(home, '.config'),
    NSAUDITOR_PLUGIN_PATH: dir,
    NSAUDITOR_LICENSE_KEY: 'not-a-licence',
    NSAUDITOR_LICENSE_STATE_FILE: join(home, 'licence-state.json'),
    NSA_VERBOSE: '',
  };
  const r = spawnSync(process.execPath, [CLI_PATH, 'license', '--plugins'], { cwd: REPO_ROOT, env, encoding: 'utf8', timeout: 30000 });
  const line = (id) => (r.stdout.match(new RegExp(`^\\s+${id}\\s.*$`, 'm')) ?? [null])[0];
  cached = { r, line };
  return cached;
}

test('subject — the command ran at Community tier and listed every fixture under the custom group', () => {
  const { r, line } = runPlugins();
  assert.equal(r.status, 0, `exit ${r.status}; stderr: ${r.stderr}`);
  assert.match(r.stdout, /Custom plugins \(from NSAUDITOR_PLUGIN_PATH\):/);
  assert.match(r.stdout, /current tier:\s*ce\b/, 'the tier must be Community, or no line can be refused');
  for (const def of Object.values(FIXTURES)) assert.ok(line(def.id), `fixture ${def.id} is not listed — the harness measured nothing about it`);
});

test('declared "enterprise" + cloudScanners → "✗ requires: enterprise" (the correct declaration)', () => {
  assert.match(runPlugins().line('9101'), /✗ requires: enterprise\s*$/);
});

test('no declared tier + a Pro capability → "✗ requires: pro"', () => {
  assert.match(runPlugins().line('9102'), /✗ requires: pro\s*$/);
});

test('no capabilities → "✓ active" and no label', () => {
  const l = runPlugins().line('9103');
  assert.match(l, /✓ active\s*$/);
  assert.doesNotMatch(l, /requires/);
});

test('THE DEFECT — declared "pro" + cloudScanners → "✗ requires: enterprise": the gate, not the manifest word, names the tier', () => {
  const l = runPlugins().line('9104');
  assert.match(l, /✗ requires: enterprise\s*$/, `printed: ${JSON.stringify(l)} — Pro does not grant cloudScanners`);
});

test('a capability no licence grants is NAMED — never "requires: ce" (it would never load at any tier)', () => {
  const l = runPlugins().line('9105');
  assert.match(l, /✗ requires a capability no licence grants: notACapability\s*$/, `printed: ${JSON.stringify(l)}`);
});
