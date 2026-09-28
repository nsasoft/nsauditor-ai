// tests/cli_license_plugins.test.mjs
// ─────────────────────────────────────────────────────────────────────────────
// CE-0.1.30.3 — `nsauditor-ai license --plugins` enumeration tests.
//
// Output format (matches the EE README "Quick Start" example):
//
//   CE plugins (from nsauditor-ai):
//     001 Ping Checker                 ✓ active
//     002 SSH Scanner                  ✓ active
//     ...
//   EE plugins (from @nsasoft/nsauditor-ai-ee):
//     020 AWS Cloud Scanner            ✗ requires: enterprise
//     ...
//
//   N plugins total · current tier: <tier>
//
// Subprocess-driven so we exercise the actual cli.mjs dispatch + plugin
// discovery + tier resolution.
// ─────────────────────────────────────────────────────────────────────────────

import './helpers/no_operator_keychain.mjs';   // FIRST: keeps this file off the operator's real Keychain
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { readdirSync } from 'node:fs';
import { createRequire } from 'node:module';
import { pathToFileURL } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(__dirname, '..');
const CLI_PATH = join(REPO_ROOT, 'cli.mjs');

function runCli(args, env = {}) {
  const cleanEnv = {
    ...process.env,
    XDG_CONFIG_HOME: '/nonexistent-cli-license-plugins-test',
    ...env,
  };
  // A caller that passes a key keeps it (the M2 leg passes one that does not verify, to pin the tier
  // to Community); otherwise the key is removed as before.
  if (!Object.hasOwn(env, 'NSAUDITOR_LICENSE_KEY')) delete cleanEnv.NSAUDITOR_LICENSE_KEY;
  return spawnSync(process.execPath, [CLI_PATH, ...args], {
    cwd: REPO_ROOT,
    env: cleanEnv,
    encoding: 'utf8',
    timeout: 30000,
  });
}

// ── 1. Enumeration produces well-formed output ──────────────────────────────

test('CE-0.1.30.3: --plugins exits 0 + lists CE plugins under "CE plugins (from nsauditor-ai):" header', () => {
  const r = runCli(['license', '--plugins']);
  assert.equal(r.status, 0, `expected exit 0, got ${r.status}; stderr: ${r.stderr}`);
  assert.match(r.stdout, /CE plugins \(from nsauditor-ai\):/);
  // At least one well-known CE plugin must appear under the CE group.
  // Plugin 001 Ping Checker ships with CE since v0.1.0.
  assert.match(r.stdout, /^\s+001\s+Ping Checker/m);
});

test('CE-0.1.30.3: --plugins shows ✓ active for CE-tier-met plugins', () => {
  const r = runCli(['license', '--plugins']);
  // Any plugin without requiredCapabilities should be ✓ active even on CE.
  // 001 Ping Checker has no requiredCapabilities (it's universally CE).
  assert.match(r.stdout, /001\s+Ping Checker\s+✓ active/);
});

test('CE-0.1.30.3: --plugins prints total count + current tier footer', () => {
  const r = runCli(['license', '--plugins']);
  assert.match(r.stdout, /\d+ plugins? total · current tier: \w+/);
});

test('CE-0.1.30.3: --plugins format is exactly "  <id> <name>  ✓/✗ status"', () => {
  // Lock the visual format so future refactors don't accidentally break the
  // EE README example. Each plugin line should match the layout pattern.
  const r = runCli(['license', '--plugins']);
  // Every non-empty content line under a "X plugins" header should match.
  const lines = r.stdout.split('\n');
  let inGroup = false;
  let matchedLines = 0;
  for (const line of lines) {
    if (/^[A-Z]/.test(line) && line.endsWith(':')) {  // group header
      inGroup = true;
      continue;
    }
    if (line.trim().length === 0) {
      inGroup = false;
      continue;
    }
    if (line.startsWith('  ') && /^\s+\d+\s+\w+/.test(line) && (/✓ active$/.test(line) || /✗ requires:/.test(line))) {
      matchedLines += 1;
    } else if (inGroup && line.startsWith('  ')) {
      // A line under a group header that doesn't match the layout — fail.
      assert.fail(`line under group header doesn't match plugin layout: ${JSON.stringify(line)}`);
    }
  }
  assert.ok(matchedLines >= 5, `expected ≥5 plugin lines matching the layout, got ${matchedLines}`);
});

// ── 2. EE group surfaces only when EE is installed ──────────────────────────

test('CE-0.1.30.3: --plugins includes EE group header only when @nsasoft/nsauditor-ai-ee resolves', () => {
  const r = runCli(['license', '--plugins']);
  // On the dev box EE IS installed, so the EE header should appear.
  // On a CE-only customer install, the EE header would be absent.
  // We assert the conditional: IF the EE header appears, it MUST be the
  // exact documented form (matches EE README example).
  if (/EE plugins/.test(r.stdout)) {
    assert.match(r.stdout, /EE plugins \(from @nsasoft\/nsauditor-ai-ee\):/);
    // At least one EE plugin (020 AWS S3 / 030 IAM / etc.) should follow.
    // EE plugin ids reserve the 1000+ range (1020 S3 / 1030 IAM / …). This asserted the
    // 3-digit ids EE used before that move, and passed VACUOUSLY for as long as EE did
    // not resolve on the dev box — the `if` above skipped it entirely.
    assert.match(r.stdout, /^\s+(1020|1021|1022|1030)\s+/m);
  }
});

// ── 3. --help integration (CLI-flag visibility rule) ─────────────────────────

test('CE-0.1.30.3: --help documents the --plugins flag', () => {
  const r = runCli(['--help']);
  assert.equal(r.status, 0);
  assert.match(r.stdout, /license --plugins/, '--help must mention `license --plugins`');
  assert.match(r.stdout, /grouped by source/i, '--help should describe what --plugins does');
});

test('CE-0.1.30.3: bare `license` Usage line lists --plugins', () => {
  const r = runCli(['license']);
  assert.equal(r.status, 0);
  assert.match(r.stdout, /--plugins/, 'bare-`license` Usage should mention --plugins');
});

// ── 4. Tier-aware status: required-capabilities reflects current tier ───────

test('CE-0.1.30.3: capability-gated plugin shows ✗ requires: <tier> on CE-only tier', () => {
  // EE plugins like 020 AWS S3 Auditor declare requiredCapabilities:
  // ['cloudScanners'], which is gated to enterprise. Without a license,
  // the resolver chain may still find one in ~/.nsauditor/.env, so we
  // explicitly clear XDG_CONFIG_HOME (already done in runCli) AND set
  // NSAUDITOR_LICENSE_KEY to nothing so the tier definitively resolves
  // to CE.
  //
  // If EE plugins are NOT installed on this machine, the test is a
  // no-op (the EE group header doesn't appear). If they ARE, then on
  // CE tier they must show ✗ requires:.
  const r = runCli(['license', '--plugins']);
  if (!/EE plugins/.test(r.stdout)) return;   // CE-only install — nothing to gate
  // ⚠️ The resolved TIER decides which of the two shapes is correct, and the original
  // assertion only covered one of them. On a dev box where an enterprise license resolves
  // (from ~/.nsauditor, which runCli's env-clearing does not always reach), every EE plugin
  // is `✓ active` and NO `✗ requires:` line exists — so this failed the moment EE resolved.
  // Assert the gate BOTH ways: on CE tier the capability-gated plugins must be refused, and
  // on a paid tier they must be active. Either way the gating is exercised, never skipped.
  const tier = (r.stdout.match(/current tier:\s*(\w+)/) ?? [])[1] ?? 'ce';
  if (tier === 'ce') {
    assert.match(r.stdout, /✗ requires:\s+(pro|enterprise)/,
      'on CE tier the capability-gated EE plugins must show the tier they require');
  } else {
    assert.match(r.stdout, /^\s+1020\s+.*✓ active/m,
      `on tier "${tier}" the capability-gated EE plugins must be active`);
    assert.doesNotMatch(r.stdout, /✗ requires:\s+(pro|enterprise)/,
      `on tier "${tier}" nothing should still be refused for lack of tier`);
  }
});

// ── 5. Non-license-required: works without env var ──────────────────────────

test('CE-0.1.30.3: --plugins works without NSAUDITOR_LICENSE_KEY (CE-degraded info still useful)', () => {
  // Discovery is informational; should not require a paid license.
  // Same UX pattern as --status / --capabilities.
  const r = runCli(['license', '--plugins'], {});  // env already strips license
  assert.equal(r.status, 0);
  assert.match(r.stdout, /CE plugins/);
});

// ── 6. Stable sort: plugin IDs ordered ───────────────────────────────────────

test('CE-0.1.30.3 reviewer M1: --plugins stdout has no startup chatter on a clean install', () => {
  // The first non-empty line of stdout MUST be the "CE plugins" header.
  // Pre-fold, [oui.mjs] Successfully loaded oui-data module ... fired on
  // every invocation regardless of NSA_VERBOSE, polluting parser-friendly
  // commands. Now the chatter is gated behind NSA_VERBOSE (vlog).
  // Strip NSA_VERBOSE to simulate a fresh customer install (the dev box
  // has it set in a project-local .env).
  const r = runCli(['license', '--plugins'], { NSA_VERBOSE: '' });
  const firstNonEmpty = r.stdout.split('\n').find((l) => l.trim().length > 0);
  assert.ok(
    firstNonEmpty.startsWith('CE plugins'),
    `expected first stdout line to be "CE plugins ...", got: ${JSON.stringify(firstNonEmpty)}`
  );
  assert.doesNotMatch(r.stdout, /\[oui\.mjs\]/, 'stdout should not contain [oui.mjs] chatter');
});

test('CE-0.1.30.3 reviewer M2 (re-keyed 0.2.55): every EE row\'s status is what Community\'s own gate decides at Community tier', async (t) => {
  // ⚠️ THIS LEG WAS VACUOUS TWICE OVER UNTIL 0.2.55, AND PASSED OVER THE DEFECT IT WAS WRITTEN FOR.
  // It keyed on the ids 020 / 021 / 022 / 023 / 030; EE's ids are 1020… since the renumbering, so no
  // line matched. And it removed the licence key without replacing it, so on a box where the
  // operator's licence resolves the tier is enterprise and no `✗ requires:` line exists at all. Measured
  // 2026-09-28: at Community tier 1020 and 1030 printed "requires: pro" (Pro does not grant
  // cloudScanners) and 1021 / 1022 / 1023 / 1220 / 1221 / 1222 printed "✓ active" (they declared no
  // capability) — the leg was green throughout. Now: a key that does not verify pins the tier, and
  // EVERY EE row is judged against `PluginManager.prototype._hasCapabilities` over
  // `resolveCapabilities(tier)`, derived here — no id is listed.
  let eeRoot;
  try { eeRoot = dirname(createRequire(import.meta.url).resolve('@nsasoft/nsauditor-ai-ee/package.json')); }
  catch { t.skip('@nsasoft/nsauditor-ai-ee is not resolvable from this tree — there are no EE rows to judge'); return; }
  const r = runCli(['license', '--plugins'], { NSAUDITOR_LICENSE_KEY: 'not-a-licence', XDG_CONFIG_HOME: '/nonexistent-test' });
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /current tier:\s*ce\b/, 'the tier must be Community, or no row can be refused');
  const { PluginManager } = await import('../plugin_manager.mjs');
  const { resolveCapabilities, CAPABILITIES } = await import('../utils/capabilities.mjs');
  const gate = (p, tier) => PluginManager.prototype._hasCapabilities.call(Object.create(PluginManager.prototype), p, resolveCapabilities(tier));
  const expected = {};
  for (const f of readdirSync(join(eeRoot, 'plugins')).filter((x) => x.endsWith('.mjs'))) {
    const p = (await import(pathToFileURL(join(eeRoot, 'plugins', f)).href)).default;
    if (!p?.id || !p?.name || typeof p.run !== 'function') continue;
    const req = Array.isArray(p.requiredCapabilities) ? p.requiredCapabilities : [];
    const unknown = req.filter((c) => !Object.hasOwn(CAPABILITIES, c));
    const lowest = ['ce', 'pro', 'enterprise'].find((tier) => gate(p, tier));
    expected[String(p.id)] = lowest === 'ce' ? '✓ active'
      : unknown.length ? `✗ requires a capability no licence grants: ${unknown.join(', ')}` : `✗ requires: ${lowest}`;
  }
  const block = (r.stdout.split('EE plugins (from @nsasoft/nsauditor-ai-ee):')[1] ?? '').split(/\n\s*\n/)[0];
  const printed = {};
  for (const m of block.matchAll(/^\s+(\S+)\s.*?\s((?:✓|✗)\s.*?)\s*$/gm)) printed[m[1]] = m[2];
  t.diagnostic(`EE at ${eeRoot} · rows printed ${Object.keys(printed).length} · plugins derived ${Object.keys(expected).length}`);
  assert.ok(Object.keys(expected).length > 0, 'no EE plugin was loaded — the oracle judged nothing');
  assert.deepEqual(printed, expected);
});

test('CE-0.1.30.3: plugins within a group are sorted by id (stable order)', () => {
  const r = runCli(['license', '--plugins']);
  // Extract the ids from the CE group block.
  const ceBlock = r.stdout.split('CE plugins')[1] ?? '';
  const ids = [];
  for (const m of ceBlock.matchAll(/^\s+(\d+)\s+/gm)) {
    ids.push(m[1]);
    if (ids.length >= 8) break;  // first 8 ids is enough to assert sort
  }
  const sorted = [...ids].sort((a, b) => a.localeCompare(b));
  assert.deepEqual(ids, sorted, `plugins should be sorted by id: got ${ids.join(',')}`);
});
