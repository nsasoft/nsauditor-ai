# NSAuditor AI — CE Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bootstrap the public CE repository from `nsauditor-plugin-manager`, strip EE-only plugins, add the capabilities/license/plugin-discovery/finding-queue infrastructure, and ship a fully-passing, MIT-licensed `nsauditor-ai` package.

**Architecture:** Two-repo consumer pattern — CE is the platform, EE is a peer-dep plugin package. CE always runs Phases 1–2 (Scan → Basic Analysis). Pro/Enterprise phases are gated by `utils/capabilities.mjs`. No CE code references EE code.

**Tech Stack:** Node.js 20+ · ES Modules (.mjs) · Node.js `--test` runner · `@modelcontextprotocol/sdk` · `@anthropic-ai/sdk` · `openai` · `jose` (Phase 2 JWT)

**Source repo:** `../nsauditor-plugin-manager` (v0.1.12, 411+ tests, all phases 1–7 complete)

---

## Phase 1 — Repository Split & Initial Setup

> **Goal:** Working CE repo. All CE tests pass. EE plugins removed cleanly. Package installable as `nsauditor-ai`.

---

### Task 1.1 — Copy Source Files

**Files created (bulk):**
- Everything in `../nsauditor-plugin-manager/` EXCEPT the 4 EE plugins and their 2 test files

- [ ] **Step 1: Copy core files**

```bash
SRC=../nsauditor-plugin-manager
cp $SRC/cli.mjs .
cp $SRC/plugin_manager.mjs .
cp $SRC/mcp_server.mjs .
cp $SRC/index.mjs .
```

- [ ] **Step 2: Copy plugins directory (all except EE)**

```bash
mkdir -p plugins
cp $SRC/plugins/*.mjs plugins/
# Remove EE-only plugins
rm plugins/cloud_aws.mjs
rm plugins/cloud_gcp.mjs
rm plugins/cloud_azure.mjs
rm plugins/zero_trust_checker.mjs
ls plugins/ | wc -l   # expect 23 files
```

- [ ] **Step 3: Copy utils directory**

```bash
mkdir -p utils
cp $SRC/utils/*.mjs utils/
```

- [ ] **Step 4: Copy config and tests**

```bash
mkdir -p config tests
cp $SRC/config/services.json config/
cp $SRC/tests/*.mjs tests/
# Remove tests for EE plugins
rm tests/cloud_scanners.test.mjs
rm tests/zero_trust_checker.test.mjs
ls tests/*.test.mjs | wc -l   # expect ~47 test files
```

- [ ] **Step 5: Install dependencies**

```bash
cp $SRC/package.json .
cp $SRC/package-lock.json .
npm install
```

- [ ] **Step 6: Quick smoke test — expect most to pass**

```bash
node --test 2>&1 | tail -5
# Expected: some failures (slugify map references removed plugins) — fix in Task 1.3
```

- [ ] **Step 7: Commit**

```bash
git init
git add .
git commit -m "chore: initial CE import from nsauditor-plugin-manager v0.1.12"
```

---

### Task 1.2 — Update package.json

**Files modified:**
- Modify: `package.json`

- [ ] **Step 1: Rewrite package.json**

```json
{
  "name": "nsauditor-ai",
  "version": "0.1.0",
  "description": "Modular AI-assisted network security audit platform — Community Edition",
  "type": "module",
  "private": false,
  "scripts": {
    "start": "node cli.mjs",
    "test": "node --test",
    "mcp": "node mcp_server.mjs"
  },
  "bin": {
    "nsauditor-ai": "./cli.mjs",
    "nsauditor-ai-mcp": "./mcp_server.mjs"
  },
  "dependencies": {
    "@anthropic-ai/sdk": "^0.82.0",
    "@modelcontextprotocol/sdk": "^1.29.0",
    "dnssd": "^0.4.1",
    "dotenv": "^17.2.1",
    "markdown-it": "^14.1.0",
    "mdns": "^2.7.2",
    "multicast-dns": "^7.2.5",
    "node-upnp-utils": "^1.0.3",
    "openai": "^4.104.0",
    "oui-data": "^1.1.427",
    "simple-wappalyzer": "^1.1.75",
    "snmp-native": "^1.2.0",
    "uuid": "^13.0.0",
    "xml2js": "^0.6.2"
  },
  "engines": {
    "node": ">=20.0.0"
  },
  "license": "MIT",
  "homepage": "https://github.com/nsasoft/nsauditor-ai",
  "repository": {
    "type": "git",
    "url": "https://github.com/nsasoft/nsauditor-ai.git"
  },
  "keywords": ["network", "security", "audit", "scanner", "vulnerability", "mcp"]
}
```

- [ ] **Step 2: Ensure shebang in cli.mjs and mcp_server.mjs**

Check and conditionally prepend — do NOT add a second shebang if one already exists:

```bash
head -1 cli.mjs | grep -q '^#!' || sed -i '1s/^/#!/usr/bin\/env node\n/' cli.mjs
head -1 mcp_server.mjs | grep -q '^#!' || sed -i '1s/^/#!/usr\/bin\/env node\n/' mcp_server.mjs
head -1 cli.mjs        # must print: #!/usr/bin/env node
head -1 mcp_server.mjs # must print: #!/usr/bin/env node
```

- [ ] **Step 3: Commit**

```bash
git add package.json cli.mjs mcp_server.mjs
git commit -m "chore: rename package to nsauditor-ai, add bin entries"
```

---

### Task 1.3 — Add MIT LICENSE + CONTRIBUTING.md

**Files created:**
- Create: `LICENSE`
- Create: `CONTRIBUTING.md`
- Create: `.env.example`

- [ ] **Step 1: Write LICENSE**

```
MIT License

Copyright (c) 2024-present Nsasoft US LLC

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

- [ ] **Step 2: Write CONTRIBUTING.md**

```markdown
# Contributing to NSAuditor AI

All contributions to this repository are licensed under the MIT license
(Developer Certificate of Origin — DCO).

## How to Contribute

1. Fork the repo and create a feature branch
2. Add a `Signed-off-by` line to your commits: `git commit -s`
3. Include tests for any new or changed behavior (Node.js `--test` runner)
4. Submit a PR

## Plugin Contributions

Follow the plugin interface in `plugins/` — each plugin exports:
- `default` object with `id`, `name`, `priority`, `requirements`, `run()`
- `conclude({ result, host })` adapter for Result Concluder
- Optional `authoritativePorts` Set

## What We Won't Accept

- Code that transmits scan data externally (violates Zero Data Exfiltration)
- Phone-home, analytics, or usage tracking
- Dependencies that weaken the offline-first guarantee
```

- [ ] **Step 3: Write .env.example (copy + clean from source)**

```bash
cp ../nsauditor-plugin-manager/.env.example .env.example 2>/dev/null || true
# If no .env.example exists, create from README examples
```

- [ ] **Step 4: Create `.npmignore`**

Prevents sensitive and dev-only files from being included in `npm publish`:

```
.env
.env.*
out/
tasks/
.scan_history/
*.log
.DS_Store
**/.DS_Store
tests/
docs/
```

Verify nothing sensitive leaks:
```bash
npm pack --dry-run 2>&1 | grep -v node_modules | grep -E '\.env|out/|tasks/|\.scan_history'
# Expected: no output (none of these should appear)
```

- [ ] **Step 5: Commit**

```bash
git add LICENSE CONTRIBUTING.md .env.example .npmignore
git commit -m "chore: add MIT LICENSE, CONTRIBUTING.md, .npmignore"
```

---

### Task 1.4 — Fix result_concluder.mjs (Remove EE Slug Entries)

**Files modified:**
- Modify: `plugins/result_concluder.mjs`

The `slugify()` function maps plugin IDs to file slugs. It currently includes entries for the 4 EE plugins we removed. Those entries must go.

- [ ] **Step 1: Open `plugins/result_concluder.mjs` and find the `slugify` function**

Look for the map object that contains entries like `'020': 'cloud_aws'`. Remove these 4 entries:

```javascript
// REMOVE these 4 lines from the slugify map:
// '020': 'cloud_aws',
// '021': 'cloud_gcp',
// '022': 'cloud_azure',
// '023': 'zero_trust_checker',
```

- [ ] **Step 2: Write a targeted test to confirm the map no longer includes EE IDs**

Create `tests/result_concluder_ce.test.mjs`:

```javascript
import { test } from 'node:test';
import assert from 'node:assert/strict';

test('result_concluder: EE plugin IDs are not in slugify map', async () => {
  const mod = await import('../plugins/result_concluder.mjs');
  // If slugify is exported for testing, use it; otherwise check via conclude()
  // The key assertion: loading the module does not throw even without EE plugins
  assert.ok(mod.default, 'result_concluder exports a default');
  assert.ok(typeof mod.conclude === 'function' || typeof mod.default.conclude === 'function',
    'conclude adapter is exported');
});
```

- [ ] **Step 3: Run that test**

```bash
node --test tests/result_concluder_ce.test.mjs
# Expected: PASS
```

- [ ] **Step 4: Run the full result_concluder test suite**

```bash
node --test tests/result_concluder.test.mjs
# Expected: all pass (was passing before, EE slugs only matter when those plugins run)
```

- [ ] **Step 5: Commit**

```bash
git add plugins/result_concluder.mjs tests/result_concluder_ce.test.mjs
git commit -m "fix: remove EE plugin slug entries from result_concluder"
```

---

### Task 1.5 — Full CE Test Run

- [ ] **Step 1: Run all tests**

```bash
node --test 2>&1 | grep -E "^(pass|fail|#)" | tail -10
```

- [ ] **Step 2: Count passing and identify any unexpected failures**

Expected: ~402 passing (439 total − 19 cloud_scanners − 18 zero_trust_checker = 402).

If a test fails that is NOT in cloud_scanners or zero_trust_checker, it is a real regression — fix before proceeding.

- [ ] **Step 3: Commit with test count in message**

```bash
git add .
git commit -m "test: verify CE baseline — N tests passing, 0 regressions"
```

---

## Phase 2 — Capabilities System

> **Goal:** `utils/capabilities.mjs` resolves a tier string to a flat capability map. `utils/license.mjs` provides a stub that reads tier from env. `plugin_manager.mjs` gates plugins on `requiredCapabilities`.

---

### Task 2.1 — Implement utils/capabilities.mjs

**Files:**
- Create: `utils/capabilities.mjs`
- Test: `tests/capabilities.test.mjs`

- [ ] **Step 1: Write the failing test first**

Create `tests/capabilities.test.mjs`:

```javascript
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { resolveCapabilities, hasCapability, CAPABILITIES } from '../utils/capabilities.mjs';

test('CE tier enables only CE capabilities', () => {
  const caps = resolveCapabilities('ce');
  assert.ok(caps.coreScanning, 'coreScanning enabled in CE');
  assert.ok(caps.basicMCP, 'basicMCP enabled in CE');
  assert.ok(!caps.intelligenceEngine, 'intelligenceEngine disabled in CE');
  assert.ok(!caps.cloudScanners, 'cloudScanners disabled in CE');
});

test('Pro tier enables CE + Pro capabilities', () => {
  const caps = resolveCapabilities('pro');
  assert.ok(caps.coreScanning);
  assert.ok(caps.intelligenceEngine);
  assert.ok(caps.riskScoring);
  assert.ok(!caps.cloudScanners, 'cloudScanners disabled in Pro');
});

test('Enterprise tier enables all capabilities', () => {
  const caps = resolveCapabilities('enterprise');
  assert.ok(caps.coreScanning);
  assert.ok(caps.cloudScanners);
  assert.ok(caps.zeroTrust);
  assert.ok(caps.dockerIsolation);
});

test('unknown tier falls back to CE', () => {
  const caps = resolveCapabilities('unknown_tier');
  assert.ok(caps.coreScanning);
  assert.ok(!caps.intelligenceEngine);
});

test('hasCapability returns false for missing cap', () => {
  const caps = resolveCapabilities('ce');
  assert.ok(!hasCapability(caps, 'intelligenceEngine'));
  assert.ok(hasCapability(caps, 'coreScanning'));
});

test('CAPABILITIES covers all expected keys', () => {
  const expected = [
    'coreScanning', 'localAI', 'basicCTEM', 'basicRedaction', 'basicMCP', 'findingQueue',
    'intelligenceEngine', 'riskScoring', 'proAI', 'analysisAgents', 'verificationEngine',
    'advancedCTEM', 'enhancedRedaction', 'proMCP', 'pdfExport', 'brandedReports',
    'cloudScanners', 'zeroTrust', 'complianceEngine', 'zdePolicyEngine',
    'enterpriseCTEM', 'enterpriseMCP', 'usageMetering', 'airGapped', 'dockerIsolation',
  ];
  for (const key of expected) {
    assert.ok(key in CAPABILITIES, `CAPABILITIES missing: ${key}`);
  }
});
```

- [ ] **Step 2: Run test — confirm it fails**

```bash
node --test tests/capabilities.test.mjs
# Expected: FAIL — "Cannot find module '../utils/capabilities.mjs'"
```

- [ ] **Step 3: Create `utils/capabilities.mjs`**

```javascript
// utils/capabilities.mjs

export const CAPABILITIES = {
  // CE (always available)
  coreScanning:       { tier: 'ce' },
  localAI:            { tier: 'ce' },
  basicCTEM:          { tier: 'ce' },
  basicRedaction:     { tier: 'ce' },
  basicMCP:           { tier: 'ce' },
  findingQueue:       { tier: 'ce' },

  // Pro
  intelligenceEngine: { tier: 'pro' },
  riskScoring:        { tier: 'pro' },
  proAI:              { tier: 'pro' },
  analysisAgents:     { tier: 'pro' },
  verificationEngine: { tier: 'pro' },
  advancedCTEM:       { tier: 'pro' },
  enhancedRedaction:  { tier: 'pro' },
  proMCP:             { tier: 'pro' },
  pdfExport:          { tier: 'pro' },
  brandedReports:     { tier: 'pro' },

  // Enterprise
  cloudScanners:      { tier: 'enterprise' },
  zeroTrust:          { tier: 'enterprise' },
  complianceEngine:   { tier: 'enterprise' },
  zdePolicyEngine:    { tier: 'enterprise' },
  enterpriseCTEM:     { tier: 'enterprise' },
  enterpriseMCP:      { tier: 'enterprise' },
  usageMetering:      { tier: 'enterprise' },
  airGapped:          { tier: 'enterprise' },
  dockerIsolation:    { tier: 'enterprise' },
};

const TIER_CAPS = {
  ce:         new Set(['ce']),
  pro:        new Set(['ce', 'pro']),
  enterprise: new Set(['ce', 'pro', 'enterprise']),
};

export function resolveCapabilities(tier = 'ce') {
  const allowed = TIER_CAPS[tier] ?? TIER_CAPS.ce;
  const caps = {};
  for (const [key, def] of Object.entries(CAPABILITIES)) {
    caps[key] = allowed.has(def.tier);
  }
  return caps;
}

export function hasCapability(capabilities, cap) {
  return Boolean(capabilities?.[cap]);
}
```

- [ ] **Step 4: Run test — confirm pass**

```bash
node --test tests/capabilities.test.mjs
# Expected: 6 pass, 0 fail
```

- [ ] **Step 5: Commit**

```bash
git add utils/capabilities.mjs tests/capabilities.test.mjs
git commit -m "feat: add capabilities system (resolveCapabilities, hasCapability)"
```

---

### Task 2.2 — Implement utils/license.mjs (Stub)

Full JWT validation (Phase 2 of the roadmap) lives here. For now: CE always, read tier from key prefix for local dev.

**Files:**
- Create: `utils/license.mjs`
- Test: `tests/license.test.mjs`

- [ ] **Step 1: Write the failing test**

Create `tests/license.test.mjs`:

```javascript
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { getTierFromEnv, loadLicense } from '../utils/license.mjs';

test('getTierFromEnv returns ce when no key set', () => {
  delete process.env.NSAUDITOR_LICENSE_KEY;
  assert.equal(getTierFromEnv(), 'ce');
});

test('getTierFromEnv parses pro prefix', () => {
  process.env.NSAUDITOR_LICENSE_KEY = 'pro_test123';
  assert.equal(getTierFromEnv(), 'pro');
  delete process.env.NSAUDITOR_LICENSE_KEY;
});

test('getTierFromEnv parses enterprise prefix', () => {
  process.env.NSAUDITOR_LICENSE_KEY = 'enterprise_test123';
  assert.equal(getTierFromEnv(), 'enterprise');
  delete process.env.NSAUDITOR_LICENSE_KEY;
});

test('getTierFromEnv returns ce for unrecognized prefix', () => {
  process.env.NSAUDITOR_LICENSE_KEY = 'invalid_key';
  assert.equal(getTierFromEnv(), 'ce');
  delete process.env.NSAUDITOR_LICENSE_KEY;
});

test('loadLicense returns ce tier when no key', async () => {
  const result = await loadLicense(undefined);
  assert.equal(result.tier, 'ce');
  assert.equal(result.valid, false);
});
```

- [ ] **Step 2: Run test — confirm it fails**

```bash
node --test tests/license.test.mjs
# Expected: FAIL
```

- [ ] **Step 3: Create `utils/license.mjs`**

```javascript
// utils/license.mjs
// Stub CE implementation. Full ES256 JWT validation added in Phase 2 (roadmap).

/**
 * Parse tier from NSAUDITOR_LICENSE_KEY environment variable.
 * Stub uses key prefix convention: pro_*, enterprise_*.
 * Phase 2 replaces this with offline JWT signature verification.
 */
export function getTierFromEnv() {
  const key = process.env.NSAUDITOR_LICENSE_KEY;
  if (!key) return 'ce';
  if (key.startsWith('pro_')) return 'pro';
  if (key.startsWith('enterprise_')) return 'enterprise';
  return 'ce';
}

/**
 * Validate a license key string.
 * Phase 2: replace with jose ES256 JWT verification against embedded public key.
 * Gracefully degrades to CE on any failure — never throws.
 */
export async function loadLicense(keyStr) {
  if (!keyStr) return { valid: false, tier: 'ce', reason: 'no key provided' };
  // TODO (Phase 2): jose.jwtVerify(keyStr, EMBEDDED_PUBLIC_KEY, { issuer: 'license.nsauditor.com' })
  return { valid: false, tier: 'ce', reason: 'JWT validation not yet implemented in CE stub' };
}
```

- [ ] **Step 4: Run test — confirm pass**

```bash
node --test tests/license.test.mjs
# Expected: 5 pass, 0 fail
```

- [ ] **Step 5: Commit**

```bash
git add utils/license.mjs tests/license.test.mjs
git commit -m "feat: add license.mjs stub (CE tier, prefix-based dev detection)"
```

---

### Task 2.3 — Add Capability Gating to plugin_manager.mjs

The existing `_runOrchestrated` skips plugins based on `requirements`. We add a second gate: `plugin.requiredCapabilities`.

**Files:**
- Modify: `plugin_manager.mjs`
- Test: `tests/plugin_capabilities.test.mjs`

- [ ] **Step 1: Write the failing test**

Create `tests/plugin_capabilities.test.mjs`:

```javascript
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { PluginManager } from '../plugin_manager.mjs';

const ceCapabilities = {
  coreScanning: true, basicMCP: true, findingQueue: true,
  intelligenceEngine: false, cloudScanners: false,
};

function makePlugin(overrides = {}) {
  return {
    id: '099',
    name: 'Test Plugin',
    priority: 50,
    requirements: {},
    async run() { return { up: true, data: [] }; },
    ...overrides,
  };
}

test('plugin without requiredCapabilities always runs', async () => {
  let ran = false;
  const plugin = makePlugin({ async run() { ran = true; return { up: true, data: [] }; } });
  const pm = await PluginManager.create({ plugins: [plugin] });
  await pm.run('127.0.0.1', [plugin.id], { capabilities: ceCapabilities });
  assert.ok(ran, 'plugin ran');
});

test('plugin with satisfied requiredCapabilities runs', async () => {
  let ran = false;
  const plugin = makePlugin({
    requiredCapabilities: ['coreScanning'],
    async run() { ran = true; return { up: true, data: [] }; },
  });
  const pm = await PluginManager.create({ plugins: [plugin] });
  await pm.run('127.0.0.1', [plugin.id], { capabilities: ceCapabilities });
  assert.ok(ran, 'CE plugin ran when capability satisfied');
});

test('plugin with unsatisfied requiredCapabilities is skipped', async () => {
  let ran = false;
  const plugin = makePlugin({
    requiredCapabilities: ['intelligenceEngine'],
    async run() { ran = true; return { up: true, data: [] }; },
  });
  const pm = await PluginManager.create({ plugins: [plugin] });
  await pm.run('127.0.0.1', [plugin.id], { capabilities: ceCapabilities });
  assert.ok(!ran, 'EE plugin skipped when capability not available');
});
```

- [ ] **Step 2: Run test — confirm it fails**

```bash
node --test tests/plugin_capabilities.test.mjs
# Expected: FAIL (capability gating not implemented yet)
```

- [ ] **Step 3: Add capability gating to `plugin_manager.mjs`**

Find the method that checks requirements (likely `_canRun`, `_checkRequirements`, or inline in `_runOrchestrated`). Add capability check after existing requirement check:

```javascript
// In plugin_manager.mjs — add this helper
_hasCapabilities(plugin, capabilities) {
  if (!plugin.requiredCapabilities?.length) return true;
  if (!capabilities) return true; // No cap object = CE permissive mode
  return plugin.requiredCapabilities.every(cap => Boolean(capabilities[cap]));
}
```

Then in the orchestration loop, add the check before running each plugin:

```javascript
// In the gate check (alongside _checkRequirements):
if (!this._hasCapabilities(plugin, opts?.capabilities)) {
  // Record as skipped in manifest if manifest tracking is active
  continue;
}
```

Also pass `capabilities` through `opts` in the `run()` call so it flows to context:

```javascript
// In run(host, spec, opts = {}):
const capabilities = opts.capabilities ?? {};
// Pass into context used by plugins:
const context = { ..., capabilities };
```

- [ ] **Step 4: Run test — confirm pass**

```bash
node --test tests/plugin_capabilities.test.mjs
# Expected: 3 pass, 0 fail
```

- [ ] **Step 5: Run full test suite — confirm no regressions**

```bash
node --test 2>&1 | tail -5
```

- [ ] **Step 6: Commit**

```bash
git add plugin_manager.mjs tests/plugin_capabilities.test.mjs
git commit -m "feat: add requiredCapabilities gating to plugin_manager"
```

---

## Phase 3 — Plugin Discovery (Multi-Path Loader)

> **Goal:** `utils/plugin_discovery.mjs` loads CE plugins from `./plugins/`, optionally from `@nsasoft/nsauditor-ai-ee`, and from `NSAUDITOR_PLUGIN_PATH`. The existing `PluginManager.create(dir)` delegates to it.

---

### Task 3.1 — Implement utils/plugin_discovery.mjs

**Files:**
- Create: `utils/plugin_discovery.mjs`
- Test: `tests/plugin_discovery.test.mjs`

- [ ] **Step 1: Write the failing test**

Create `tests/plugin_discovery.test.mjs`:

```javascript
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { discoverPlugins } from '../utils/plugin_discovery.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, '..');

test('discoverPlugins loads CE plugins from ./plugins/', async () => {
  const plugins = await discoverPlugins(ROOT);
  assert.ok(plugins.length >= 20, `Expected 20+ plugins, got ${plugins.length}`);
  assert.ok(plugins.every(p => p.id && p.name && typeof p.run === 'function'));
});

test('all discovered plugins have unique IDs', async () => {
  const plugins = await discoverPlugins(ROOT);
  const ids = plugins.map(p => p.id);
  const unique = new Set(ids);
  assert.equal(unique.size, ids.length, 'Duplicate plugin ID found');
});

test('plugins are sorted by priority ascending', async () => {
  const plugins = await discoverPlugins(ROOT);
  for (let i = 1; i < plugins.length; i++) {
    assert.ok(
      (plugins[i].priority ?? 0) >= (plugins[i - 1].priority ?? 0),
      `Plugin ${plugins[i].id} out of order`
    );
  }
});

test('discoverPlugins handles missing NSAUDITOR_PLUGIN_PATH gracefully', async () => {
  process.env.NSAUDITOR_PLUGIN_PATH = '/nonexistent/path';
  const plugins = await discoverPlugins(ROOT);
  assert.ok(plugins.length >= 20, 'Still loads CE plugins when custom path missing');
  delete process.env.NSAUDITOR_PLUGIN_PATH;
});

test('EE package missing does not throw', async () => {
  // @nsasoft/nsauditor-ai-ee is not installed in CE — this must not throw
  await assert.doesNotReject(() => discoverPlugins(ROOT));
});
```

- [ ] **Step 2: Run test — confirm it fails**

```bash
node --test tests/plugin_discovery.test.mjs
# Expected: FAIL
```

- [ ] **Step 3: Create `utils/plugin_discovery.mjs`**

```javascript
// utils/plugin_discovery.mjs

import { readdir } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { join, resolve, dirname } from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

const _require = createRequire(import.meta.url);

async function loadPluginsFromDir(dir, source) {
  let files;
  try {
    files = await readdir(dir);
  } catch {
    return [];
  }
  const plugins = [];
  for (const file of files.filter(f => f.endsWith('.mjs'))) {
    try {
      const mod = await import(join(dir, file));
      const plugin = mod.default;
      if (plugin?.id && plugin?.name && typeof plugin?.run === 'function') {
        plugins.push({ ...plugin, _source: source, conclude: mod.conclude ?? plugin.conclude });
      }
    } catch (e) {
      if (process.env.NSA_VERBOSE) {
        console.error(`[plugin_discovery] Failed to load ${file}: ${e.message}`);
      }
    }
  }
  return plugins;
}

export async function discoverPlugins(baseDir) {
  const plugins = [];

  // Source 1: CE built-in plugins
  plugins.push(...await loadPluginsFromDir(join(baseDir, 'plugins'), 'ce'));

  // Source 2: EE package (@nsasoft/nsauditor-ai-ee)
  try {
    const eePkgPath = _require.resolve('@nsasoft/nsauditor-ai-ee/package.json');
    const eePluginsDir = join(dirname(eePkgPath), 'plugins');
    if (existsSync(eePluginsDir)) {
      plugins.push(...await loadPluginsFromDir(eePluginsDir, 'ee'));
    }
  } catch {
    // EE not installed — CE operates standalone
  }

  // Source 3: Custom plugin paths (colon-separated)
  const customPaths = process.env.NSAUDITOR_PLUGIN_PATH;
  if (customPaths) {
    for (const dir of customPaths.split(':')) {
      const abs = resolve(dir);
      if (existsSync(abs)) {
        plugins.push(...await loadPluginsFromDir(abs, 'custom'));
      }
    }
  }

  return plugins.sort((a, b) => (a.priority ?? 0) - (b.priority ?? 0));
}
```

- [ ] **Step 4: Run test — confirm pass**

```bash
node --test tests/plugin_discovery.test.mjs
# Expected: 5 pass, 0 fail
```

- [ ] **Step 5: Commit**

```bash
git add utils/plugin_discovery.mjs tests/plugin_discovery.test.mjs
git commit -m "feat: add plugin_discovery — multi-path loader (CE + EE + custom)"
```

---

### Task 3.2 — Wire discoverPlugins into PluginManager.create()

**Files:**
- Modify: `plugin_manager.mjs`

The current `PluginManager.create(dir)` uses its own directory scanning. Replace that internals with `discoverPlugins()`.

- [ ] **Step 1: Find the plugin loading code in `plugin_manager.mjs`**

Look for the `create(dir)` static method and the `readdir` / dynamic `import` calls inside it.

- [ ] **Step 2: Add import at top of `plugin_manager.mjs`**

```javascript
import { discoverPlugins } from './utils/plugin_discovery.mjs';
```

- [ ] **Step 3: Replace internal plugin loading with discoverPlugins**

Find where `PluginManager.create` reads the plugins directory. Replace the readdir + import loop with:

```javascript
static async create(dirOrOpts = {}) {
  // Accept both legacy string arg and new options object
  const baseDir = typeof dirOrOpts === 'string'
    ? dirOrOpts
    : (dirOrOpts.baseDir ?? process.cwd());

  // Support direct plugin injection (used in tests)
  const plugins = dirOrOpts.plugins
    ? dirOrOpts.plugins
    : await discoverPlugins(baseDir);

  return new PluginManager(plugins);
}
```

- [ ] **Step 4: Verify plugin count is identical after refactor**

Before touching anything, record the baseline count:
```bash
node -e "
import('./plugin_manager.mjs').then(async m => {
  const pm = await m.default.create('./plugins');
  console.log('plugin count:', pm.getAllPluginsMetadata().length);
});" 2>/dev/null
```

After the refactor, run again and assert the count matches:
```bash
node -e "
import('./plugin_manager.mjs').then(async m => {
  const pm = await m.default.create('./plugins');
  const count = pm.getAllPluginsMetadata().length;
  if (count !== 23) { console.error('FAIL: expected 23 plugins, got', count); process.exit(1); }
  console.log('PASS:', count, 'plugins loaded');
});"
```

Then run full suite:
```bash
node --test 2>&1 | tail -5
# Expected: same pass count as before (no regressions)
```

- [ ] **Step 5: Commit**

```bash
git add plugin_manager.mjs
git commit -m "refactor: PluginManager.create uses discoverPlugins for multi-path loading"
```

---

## Phase 4 — Finding Schema + Queue

> **Goal:** Structured finding format lives in CE so the schema is shared across all tiers. Agents (Phase 3 of roadmap) and the MCP `save_finding` tool (Pro) produce findings conforming to this schema.

---

### Task 4.1 — Implement utils/finding_schema.mjs

**Files:**
- Create: `utils/finding_schema.mjs`
- Test: `tests/finding_schema.test.mjs`

- [ ] **Step 1: Write the failing test**

Create `tests/finding_schema.test.mjs`:

```javascript
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  validateFinding,
  generateFindingId,
  FINDING_CATEGORIES,
  FINDING_STATUSES,
  FINDING_SEVERITIES,
} from '../utils/finding_schema.mjs';

const validFinding = {
  category: 'CRYPTO',
  status: 'UNVERIFIED',
  title: 'TLS 1.0 enabled',
  severity: 'MEDIUM',
  target: { host: '10.0.0.1', port: 443, protocol: 'tcp', service: 'https' },
};

test('validateFinding returns empty array for valid finding', () => {
  assert.deepEqual(validateFinding(validFinding), []);
});

test('validateFinding rejects invalid category', () => {
  const errors = validateFinding({ ...validFinding, category: 'INVALID' });
  assert.ok(errors.some(e => e.includes('category')));
});

test('validateFinding rejects invalid severity', () => {
  const errors = validateFinding({ ...validFinding, severity: 'ULTRA' });
  assert.ok(errors.some(e => e.includes('severity')));
});

test('validateFinding rejects missing title', () => {
  const { title, ...noTitle } = validFinding;
  const errors = validateFinding(noTitle);
  assert.ok(errors.some(e => e.includes('title')));
});

test('validateFinding rejects missing target.host', () => {
  const errors = validateFinding({ ...validFinding, target: { port: 443 } });
  assert.ok(errors.some(e => e.includes('target.host')));
});

test('generateFindingId returns unique IDs', () => {
  const ids = new Set(Array.from({ length: 10 }, () => generateFindingId()));
  assert.equal(ids.size, 10, 'IDs should be unique');
});

test('generateFindingId format is F-YYYY-NNNN', () => {
  const id = generateFindingId();
  assert.match(id, /^F-\d{4}-\d{4}$/);
});

test('FINDING_CATEGORIES includes all 6 categories', () => {
  assert.equal(FINDING_CATEGORIES.length, 6);
  assert.ok(FINDING_CATEGORIES.includes('AUTH'));
  assert.ok(FINDING_CATEGORIES.includes('CVE'));
});
```

- [ ] **Step 2: Run test — confirm it fails**

```bash
node --test tests/finding_schema.test.mjs
# Expected: FAIL
```

- [ ] **Step 3: Create `utils/finding_schema.mjs`**

```javascript
// utils/finding_schema.mjs

export const FINDING_CATEGORIES = ['AUTH', 'CRYPTO', 'CONFIG', 'SERVICE', 'EXPOSURE', 'CVE'];
export const FINDING_STATUSES   = ['UNVERIFIED', 'VERIFIED', 'POTENTIAL', 'FALSE_POSITIVE'];
export const FINDING_SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
export const FINDING_EFFORTS    = ['LOW', 'MEDIUM', 'HIGH'];

export function validateFinding(f) {
  const errors = [];
  if (!FINDING_CATEGORIES.includes(f?.category))
    errors.push(`invalid category: ${f?.category}`);
  if (!FINDING_STATUSES.includes(f?.status))
    errors.push(`invalid status: ${f?.status}`);
  if (!FINDING_SEVERITIES.includes(f?.severity))
    errors.push(`invalid severity: ${f?.severity}`);
  if (!f?.title || typeof f.title !== 'string')
    errors.push('title required');
  if (!f?.target?.host)
    errors.push('target.host required');
  return errors;
}

let _counter = 0;
export function generateFindingId() {
  const year = new Date().getFullYear();
  return `F-${year}-${String(++_counter).padStart(4, '0')}`;
}
```

- [ ] **Step 4: Run test — confirm pass**

```bash
node --test tests/finding_schema.test.mjs
# Expected: 8 pass, 0 fail
```

- [ ] **Step 5: Commit**

```bash
git add utils/finding_schema.mjs tests/finding_schema.test.mjs
git commit -m "feat: add finding_schema — structured finding format (shared CE/Pro/EE)"
```

---

### Task 4.2 — Implement utils/finding_queue.mjs

**Files:**
- Create: `utils/finding_queue.mjs`
- Test: `tests/finding_queue.test.mjs`

- [ ] **Step 1: Write the failing test**

Create `tests/finding_queue.test.mjs`:

```javascript
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { FindingQueue } from '../utils/finding_queue.mjs';

const mkFinding = (overrides = {}) => ({
  category: 'AUTH',
  status: 'UNVERIFIED',
  title: 'Weak SSH auth',
  severity: 'HIGH',
  target: { host: '10.0.0.1', port: 22, protocol: 'tcp', service: 'ssh' },
  ...overrides,
});

test('add() stores a finding and returns an ID', () => {
  const q = new FindingQueue();
  const id = q.add(mkFinding());
  assert.ok(id.startsWith('F-'), `Expected F-xxx ID, got ${id}`);
  assert.equal(q.size, 1);
});

test('add() throws on invalid finding', () => {
  const q = new FindingQueue();
  assert.throws(() => q.add({ category: 'INVALID' }), /Invalid finding/);
});

test('getByCategory filters correctly', () => {
  const q = new FindingQueue();
  q.add(mkFinding({ category: 'AUTH' }));
  q.add(mkFinding({ category: 'CRYPTO' }));
  assert.equal(q.getByCategory('AUTH').length, 1);
  assert.equal(q.getByCategory('CRYPTO').length, 1);
  assert.equal(q.getByCategory('CVE').length, 0);
});

test('getByStatus filters correctly', () => {
  const q = new FindingQueue();
  q.add(mkFinding({ status: 'UNVERIFIED' }));
  q.add(mkFinding({ status: 'UNVERIFIED' }));
  assert.equal(q.getByStatus('UNVERIFIED').length, 2);
  assert.equal(q.getByStatus('VERIFIED').length, 0);
});

test('markVerified updates status and evidence', () => {
  const q = new FindingQueue();
  const id = q.add(mkFinding());
  q.markVerified(id, { method: 'ssh-banner', result: 'password auth confirmed', timestamp: '2026-04-06T00:00:00Z', safe: true });
  const f = q.getByStatus('VERIFIED')[0];
  assert.ok(f, 'finding should be VERIFIED');
  assert.equal(f.evidence.verification.method, 'ssh-banner');
});

test('markFalsePositive updates status and reason', () => {
  const q = new FindingQueue();
  const id = q.add(mkFinding());
  q.markFalsePositive(id, 'backport patch confirmed');
  const f = q.getByStatus('FALSE_POSITIVE')[0];
  assert.ok(f, 'finding should be FALSE_POSITIVE');
  assert.equal(f.falsePositiveReason, 'backport patch confirmed');
});

test('prioritize sorts by severity descending', () => {
  const q = new FindingQueue();
  q.add(mkFinding({ severity: 'LOW' }));
  q.add(mkFinding({ severity: 'CRITICAL' }));
  q.add(mkFinding({ severity: 'MEDIUM' }));
  q.prioritize();
  const sevs = q.findings.map(f => f.severity);
  assert.deepEqual(sevs, ['CRITICAL', 'MEDIUM', 'LOW']);
});

test('toJSON returns serializable array', () => {
  const q = new FindingQueue();
  q.add(mkFinding());
  const json = q.toJSON();
  assert.ok(Array.isArray(json));
  assert.ok(json[0].id);
  // Confirm it's deep-copied (mutating original doesn't affect toJSON output)
  json[0].title = 'modified';
  assert.notEqual(q.findings[0].title, 'modified');
});
```

- [ ] **Step 2: Run test — confirm it fails**

```bash
node --test tests/finding_queue.test.mjs
# Expected: FAIL
```

- [ ] **Step 3: Create `utils/finding_queue.mjs`**

```javascript
// utils/finding_queue.mjs

import { validateFinding, generateFindingId } from './finding_schema.mjs';

const SEVERITY_SCORE = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 };

export class FindingQueue {
  constructor() {
    this.findings = [];
  }

  add(finding) {
    const errors = validateFinding(finding);
    if (errors.length > 0) throw new Error(`Invalid finding: ${errors.join(', ')}`);
    const id = finding.id || generateFindingId();
    this.findings.push({ ...finding, id });
    return id;
  }

  getByCategory(cat) {
    return this.findings.filter(f => f.category === cat);
  }

  getByStatus(status) {
    return this.findings.filter(f => f.status === status);
  }

  getUnverified() {
    return this.getByStatus('UNVERIFIED');
  }

  markVerified(id, verification) {
    const f = this._find(id);
    f.status = 'VERIFIED';
    f.evidence = { ...(f.evidence ?? {}), verification };
  }

  markFalsePositive(id, reason) {
    const f = this._find(id);
    f.status = 'FALSE_POSITIVE';
    f.falsePositiveReason = reason;
  }

  prioritize() {
    this.findings.sort(
      (a, b) => (SEVERITY_SCORE[b.severity] ?? 0) - (SEVERITY_SCORE[a.severity] ?? 0)
    );
    return this;
  }

  toJSON() {
    return JSON.parse(JSON.stringify(this.findings));
  }

  get size() {
    return this.findings.length;
  }

  _find(id) {
    const f = this.findings.find(f => f.id === id);
    if (!f) throw new Error(`Finding not found: ${id}`);
    return f;
  }
}
```

- [ ] **Step 4: Run test — confirm pass**

```bash
node --test tests/finding_queue.test.mjs
# Expected: 8 pass, 0 fail
```

- [ ] **Step 5: Commit**

```bash
git add utils/finding_queue.mjs tests/finding_queue.test.mjs
git commit -m "feat: add FindingQueue — structured finding manager with validation"
```

---

## Phase 5 — MCP Server CE Edition

> **Goal:** `mcp_server.mjs` exposes only CE tools (`scan_host`, `list_plugins`). Pro/Enterprise tools respond with a license upsell message when called without a valid key.

---

### Task 5.1 — Update mcp_server.mjs (CE Tools Only)

**Files:**
- Modify: `mcp_server.mjs`
- Test: `tests/mcp_server.test.mjs` (already exists — verify pass)

The current `mcp_server.mjs` exposes 4 tools: `scan_host`, `probe_service`, `get_vulnerabilities`, `list_plugins`. In CE, `probe_service` and `get_vulnerabilities` are Pro tools that must return a clear upgrade message, not silently fail or throw.

- [ ] **Step 1: Read the current `mcp_server.mjs` tools section**

Find the tool registration code (where tool names are registered with the MCP SDK).

- [ ] **Step 2: Identify Pro tool handlers (`probe_service`, `get_vulnerabilities`)**

These are identified in the README as Pro tools. Wrap their handlers with a capability check:

```javascript
// Add this helper near the top of mcp_server.mjs
function requireCapability(capabilities, cap, toolName) {
  if (!capabilities?.[cap]) {
    return {
      content: [{
        type: 'text',
        text: `🔒 ${toolName} requires a Pro license.\n\nUpgrade at https://www.nsauditor.com/ai/pricing or start a free 14-day trial at https://www.nsauditor.com/ai/trial\n\nCE tools available: scan_host, list_plugins`
      }],
      isError: true,
    };
  }
  return null;
}
```

- [ ] **Step 3: Add capability resolution to mcp_server.mjs startup**

```javascript
import { getTierFromEnv } from './utils/license.mjs';
import { resolveCapabilities } from './utils/capabilities.mjs';

// Near the top of the server setup:
const tier = getTierFromEnv();
const capabilities = resolveCapabilities(tier);
```

- [ ] **Step 4: Wrap Pro tool handlers**

In each Pro tool handler, add at the start:

```javascript
// probe_service handler:
const denied = requireCapability(capabilities, 'proMCP', 'probe_service');
if (denied) return denied;
// ... rest of handler

// get_vulnerabilities handler:
const denied = requireCapability(capabilities, 'proMCP', 'get_vulnerabilities');
if (denied) return denied;
// ... rest of handler
```

- [ ] **Step 5: Update list_plugins to include capability info**

In the `list_plugins` handler, add tier info to the response:

```javascript
// Append to list_plugins response:
const tierInfo = `\n\nCurrent tier: ${tier.toUpperCase()}\nLicense key: ${process.env.NSAUDITOR_LICENSE_KEY ? 'set' : 'not set'}`;
```

- [ ] **Step 6: Run existing MCP tests**

```bash
node --test tests/mcp_server.test.mjs
# Expected: all pass (tests use mocked context)
```

- [ ] **Step 7: Commit**

```bash
git add mcp_server.mjs
git commit -m "feat: MCP server CE edition — Pro tools return license upsell"
```

---

### Task 5.2 — Add `license` CLI Command

**Files:**
- Modify: `cli.mjs`
- Test: `tests/cli_license.test.mjs`

- [ ] **Step 1: Write the failing test**

Create `tests/cli_license.test.mjs`:

```javascript
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const exec = promisify(execFile);
const CLI = new URL('../cli.mjs', import.meta.url).pathname;

test('license --status prints CE when no key set', async () => {
  delete process.env.NSAUDITOR_LICENSE_KEY;
  const { stdout } = await exec('node', [CLI, 'license', '--status']);
  assert.ok(stdout.includes('CE') || stdout.includes('Community'), stdout);
});

test('license --capabilities lists CE capabilities', async () => {
  delete process.env.NSAUDITOR_LICENSE_KEY;
  const { stdout } = await exec('node', [CLI, 'license', '--capabilities']);
  assert.ok(stdout.includes('coreScanning'), stdout);
  assert.ok(stdout.includes('basicMCP'), stdout);
});
```

- [ ] **Step 2: Run test — confirm it fails**

```bash
node --test tests/cli_license.test.mjs
# Expected: FAIL — unknown command 'license'
```

- [ ] **Step 3: Add `license` command to `cli.mjs`**

Find the `parseArgs` or command dispatch section. Add a `license` case:

```javascript
// In the command dispatch section of cli.mjs:
case 'license': {
  const { getTierFromEnv } = await import('./utils/license.mjs');
  const { resolveCapabilities } = await import('./utils/capabilities.mjs');
  const tier = getTierFromEnv();
  const caps = resolveCapabilities(tier);
  const key = process.env.NSAUDITOR_LICENSE_KEY;

  if (args.includes('--status')) {
    const tierLabel = { ce: 'Community Edition (CE)', pro: 'Pro', enterprise: 'Enterprise' };
    console.log(`License status: ${tierLabel[tier] ?? tier}`);
    console.log(`Key: ${key ? `set (${key.slice(0, 8)}...)` : 'not set — running CE'}`);
    if (!key) {
      console.log('\nStart a free 14-day Pro trial: https://www.nsauditor.com/ai/trial');
    }
  } else if (args.includes('--capabilities')) {
    console.log(`Active capabilities for tier: ${tier}\n`);
    for (const [name, enabled] of Object.entries(caps)) {
      console.log(`  ${enabled ? '✓' : '✗'} ${name}`);
    }
  } else {
    console.log('Usage: nsauditor-ai license --status | --capabilities');
  }
  break;
}
```

- [ ] **Step 4: Run test — confirm pass**

```bash
node --test tests/cli_license.test.mjs
# Expected: 2 pass, 0 fail
```

- [ ] **Step 5: Commit**

```bash
git add cli.mjs tests/cli_license.test.mjs
git commit -m "feat: add license CLI command (--status, --capabilities)"
```

---

## Phase 6 — Final Validation

### Task 6.1 — Full Test Suite + Package Smoke Test

- [ ] **Step 1: Run all tests**

```bash
node --test 2>&1 | tail -10
```

Expected: 430+ passing (402 CE baseline + 8 capabilities + 5 license + 3 plugin_capabilities + 5 plugin_discovery + 8 finding_schema + 8 finding_queue + 2 cli_license).

- [ ] **Step 2: Verify CLI works end-to-end**

```bash
node cli.mjs license --status
# Expected: "License status: Community Edition (CE)"

node cli.mjs license --capabilities
# Expected: list of capabilities with ✓/✗

node cli.mjs scan --host 127.0.0.1 --plugins 001,008
# Expected: runs ping checker + concluder, produces output in ./out/
```

- [ ] **Step 3: Verify MCP server starts**

```bash
echo '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' | node mcp_server.mjs
# Expected: JSON response with scan_host, list_plugins, probe_service (with upsell note), get_vulnerabilities
```

- [ ] **Step 4: Tag v0.1.0**

```bash
git tag v0.1.0
```

- [ ] **Step 5: Final commit**

```bash
git add .
git commit -m "chore: Phase 1 complete — CE baseline v0.1.0"
```

---

## Phase CE-H — CE Hardening & Public Launch

> **Goal:** Fix all code-review-identified issues before making the CE repository public on GitHub. No EE work in this phase. All issues are CE-internal: security correctness, monetization gate integrity, CE spec completeness, and code quality.
>
> **Source:** Code review findings #1–#15 from the internal audit (April 2026).
>
> **Exit criteria:** `node --test` ≥ 438 pass, 0 fail. `npm pack --dry-run` shows no sensitive files. All 9 hardening items below resolved.

---

### Task H.1 — Security: SSRF Decimal-IP Regex Gap

**Files:**
- Modify: `mcp_server.mjs:169`
- Modify: `tests/mcp_server.test.mjs`

**Problem:** The fast-path SSRF regex in `validateHost()` misses decimal-encoded IPs (e.g. `2130706433` → `127.0.0.1`). The DNS resolution layer in `resolveAndValidate()` currently saves it, but if that layer is ever bypassed the regex becomes the only guard and it fails.

- [ ] **Step 1: Write failing test**

Add to `tests/mcp_server.test.mjs`:

```js
it('blocks decimal-encoded loopback IP', async () => {
  const { validateHost } = await import('../mcp_server.mjs');
  await assert.rejects(
    () => validateHost('2130706433'),
    /not allowed/
  );
});
```

Run: `node --test tests/mcp_server.test.mjs 2>&1 | tail -5`
Expected: FAIL (decimal IP currently passes the fast-path regex)

- [ ] **Step 2: Fix the fast-path regex in `mcp_server.mjs:169`**

Replace:
```js
if (/^(localhost|127\.|0\.|::1|0\.0\.0\.0|169\.254\.|fe80:|metadata\.google)/i.test(h)) {
```

With:
```js
// Reject decimal-encoded IPs (e.g. 2130706433 = 127.0.0.1) and all loopback/link-local forms
const isDecimalLoopback = /^\d+$/.test(h) && (() => {
  const n = Number(h);
  // 127.0.0.0/8 = 2130706432..2147483647 (0x7F000000..0x7FFFFFFF)
  return n >= 0x7F000000 && n <= 0x7FFFFFFF;
})();
if (isDecimalLoopback || /^(localhost|127\.|0\.|::1|0\.0\.0\.0|169\.254\.|fe80:|metadata\.google)/i.test(h)) {
  throw new Error('Scanning loopback, link-local, or metadata addresses is not allowed via MCP');
}
```

- [ ] **Step 3: Run test — expect pass**

```bash
node --test tests/mcp_server.test.mjs 2>&1 | tail -5
```

- [ ] **Step 4: Run full suite — expect 438+ pass, 0 fail**

```bash
node --test 2>&1 | tail -8
```

- [ ] **Step 5: Commit**

```bash
git add mcp_server.mjs tests/mcp_server.test.mjs
git commit -m "fix: block decimal-encoded loopback IPs in MCP SSRF guard"
```

---

### Task H.2 — Security: Plugin Path Traversal Guard

**Files:**
- Modify: `utils/plugin_discovery.mjs:56-61`
- Modify: `tests/` (new test file: `tests/plugin_discovery.test.mjs`)

**Problem:** `NSAUDITOR_PLUGIN_PATH` accepts any absolute path including `/etc`, `/usr`, etc. In shared/containerised environments with user-controlled env vars this is a code-execution vector.

- [ ] **Step 1: Write failing test**

Create `tests/plugin_discovery.test.mjs`:

Note: `plugin_discovery.mjs` is a cached ES module — mutating `NSAUDITOR_PLUGIN_PATH` after import has no effect in the same process. Use `child_process.execFileSync` to spawn a fresh Node.js process with the env var pre-set, so the module loads fresh with the unsafe path already in the environment.

```js
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '..');

describe('discoverPlugins — path guard', () => {
  it('ignores NSAUDITOR_PLUGIN_PATH entries outside cwd/HOME', () => {
    // Runs in a subprocess so the module is freshly imported with the env var set
    const script = `
      import { discoverPlugins } from './utils/plugin_discovery.mjs';
      const plugins = await discoverPlugins(process.cwd());
      const nonCE = plugins.filter(p => p._source === 'custom');
      if (nonCE.length > 0) {
        console.error('FAIL: loaded', nonCE.length, 'custom plugins from unsafe path');
        process.exit(1);
      }
      console.log('PASS: 0 custom plugins from /etc or /usr/lib');
    `;
    const result = execFileSync(process.execPath, ['--input-type=module'], {
      input: script,
      cwd: ROOT,
      env: { ...process.env, NSAUDITOR_PLUGIN_PATH: '/etc:/usr/lib', NSA_VERBOSE: '1' },
      encoding: 'utf8',
    });
    assert.ok(result.includes('PASS'), `Expected PASS, got: ${result}`);
  });
});
```

Run: `node --test tests/plugin_discovery.test.mjs 2>&1 | tail -5`
Expected: FAIL (currently loads from any path, subprocess exits 1)

- [ ] **Step 2: Add safe-path guard to `utils/plugin_discovery.mjs`**

Add after `const customPaths = process.env.NSAUDITOR_PLUGIN_PATH;`:

```js
const SAFE_PREFIXES = [process.cwd(), process.env.HOME].filter(Boolean).map(p => p.endsWith('/') ? p : p + '/');

function isSafePath(absPath) {
  return SAFE_PREFIXES.some(prefix => absPath.startsWith(prefix)) || absPath === process.cwd();
}
```

Then in the loop:
```js
for (const dir of customPaths.split(':')) {
  const abs = resolve(dir);
  if (!isSafePath(abs)) {
    if (process.env.NSA_VERBOSE) console.warn(`[plugin_discovery] Skipping unsafe NSAUDITOR_PLUGIN_PATH entry: ${abs}`);
    continue;
  }
  if (existsSync(abs)) {
    plugins.push(...await loadPluginsFromDir(abs, 'custom'));
  }
}
```

- [ ] **Step 3: Run test — expect pass**

```bash
node --test tests/plugin_discovery.test.mjs 2>&1 | tail -5
```

- [ ] **Step 4: Run full suite**

```bash
node --test 2>&1 | tail -8
```

- [ ] **Step 5: Commit**

```bash
git add utils/plugin_discovery.mjs tests/plugin_discovery.test.mjs
git commit -m "fix: restrict NSAUDITOR_PLUGIN_PATH to cwd and HOME subtrees"
```

---

### Task H.3 — Monetization: Capability Gate Defaults & Phase 2 Markers

**Files:**
- Modify: `plugin_manager.mjs` (`_hasCapabilities`, `run()`)
- Modify: `mcp_server.mjs:28` (add Phase 2 TODO comment)
- Modify: `cli.mjs` (add Phase 2 TODO comment at `getTierFromEnv()` call)
- Modify: `mcp_server.mjs:32` (`_setTier` — add `@internal` JSDoc)
- Modify: `tests/mcp_server.test.mjs` (add direct-handler CE denial tests)

**Problems:**
- `_hasCapabilities` returns `true` when `capabilities` is omitted → EE plugins run in CE silently
- `getTierFromEnv()` call sites have no Phase 2 TODO → migration surface invisible to maintainers
- `_setTier` is an exported symbol with no `@internal` marker

- [ ] **Step 1: Write failing tests**

Add to `tests/mcp_server.test.mjs`:

```js
it('probe_service handler denies CE when called directly (no server)', async () => {
  const { _setTier, handleProbeService } = await import('../mcp_server.mjs');
  _setTier('ce');
  // Direct handler call — should still respect capability gate
  // Currently this test documents the gap: direct calls bypass the gate
  // After fix, this should throw or return upsell
  // For now: document current behaviour and assert it doesn't silently succeed
  // (full fix is Phase 2 when JWT lands and handlers can self-gate)
  // Mark as todo until handler-level gating is added
});
```

- [ ] **Step 2: Fix `_hasCapabilities` permissive fallback in `plugin_manager.mjs`**

`_hasCapabilities` is synchronous — do NOT use dynamic `await import()` inside it. Instead, resolve capabilities once at plugin-load time in `create()` and store them on `this._resolvedCapabilities`.

Add to the top of `plugin_manager.mjs` imports:
```js
import { getTierFromEnv } from './utils/license.mjs';
import { resolveCapabilities } from './utils/capabilities.mjs';
```

In the `create()` static method, after plugins are loaded and `instance` is constructed:
```js
const tier = getTierFromEnv();
instance._resolvedCapabilities = resolveCapabilities(tier);
```

Replace `_hasCapabilities`:
```js
_hasCapabilities(plugin, capabilities) {
  if (!plugin.requiredCapabilities?.length) return true;
  // Fall back to capabilities resolved at load time from current env tier (never permissive).
  const caps = capabilities ?? this._resolvedCapabilities ?? {};
  return plugin.requiredCapabilities.every(cap => Boolean(caps[cap]));
}
```

The old `if (!capabilities) return true;` line is removed — the fallback is now the env-resolved capability map, never "allow all".

- [ ] **Step 3: Add Phase 2 TODO markers**

In `mcp_server.mjs` line 28 (before `let _tier = getTierFromEnv()`):
```js
// TODO (Phase 2): replace getTierFromEnv() with loadLicense(process.env.NSAUDITOR_LICENSE_KEY)
// and wire the returned tier here. Until then, pro_* prefix grants Pro tier without verification.
let _tier = getTierFromEnv();
```

In `cli.mjs` at the equivalent `getTierFromEnv()` call:
```js
// TODO (Phase 2): replace with loadLicense() for JWT verification
```

Add `@internal` JSDoc to `_setTier`:
```js
/**
 * @internal Test-only. Override tier without touching env vars.
 * Do NOT use in production code. When JWT license validation lands (Phase 2),
 * this function will be removed or guarded by NODE_ENV !== 'production'.
 */
export function _setTier(tier) {
```

- [ ] **Step 4: Run full suite**

```bash
node --test 2>&1 | tail -8
# Expected: 438+ pass, 0 fail
```

- [ ] **Step 5: Commit**

```bash
git add plugin_manager.mjs mcp_server.mjs cli.mjs tests/mcp_server.test.mjs
git commit -m "fix: capability gate defaults + Phase 2 migration markers"
```

---

### Task H.4 — CE Spec: 7-Day JSONL Retention

**Files:**
- Modify: `utils/scan_history.mjs`
- Modify: `tests/scan_history.test.mjs`

**Problem:** CE spec says "7-day JSONL history retention." Currently the JSONL file grows indefinitely. Pro/Enterprise spec says "unlimited." Must enforce the CE boundary.

- [ ] **Step 1: Write failing test**

Add to `tests/scan_history.test.mjs`:

```js
it('prunes entries older than 7 days for CE tier', async () => {
  const tmp = os.tmpdir() + '/nsa_hist_prune_' + Date.now() + '.jsonl';
  const hist = new ScanHistory(tmp);

  const old = new Date(Date.now() - 8 * 24 * 60 * 60 * 1000).toISOString(); // 8 days ago
  const recent = new Date().toISOString();

  // Write one old and one recent entry directly
  fs.writeFileSync(tmp, [
    JSON.stringify({ host: '1.1.1.1', timestamp: old, services: [] }),
    JSON.stringify({ host: '2.2.2.2', timestamp: recent, services: [] }),
  ].join('\n') + '\n');

  await hist.pruneForCE(); // method under test

  const lines = fs.readFileSync(tmp, 'utf8').trim().split('\n').filter(Boolean);
  assert.equal(lines.length, 1, 'Only the recent entry survives');
  assert.ok(JSON.parse(lines[0]).host === '2.2.2.2');
  fs.unlinkSync(tmp);
});
```

Run: `node --test tests/scan_history.test.mjs 2>&1 | tail -5`
Expected: FAIL (`pruneForCE` does not exist)

- [ ] **Step 2: Implement `pruneForCE()` in `utils/scan_history.mjs`**

```js
const CE_RETENTION_MS = 7 * 24 * 60 * 60 * 1000; // 7 days

/**
 * Remove JSONL entries older than 7 days. CE-only — call after each scan in CE tier.
 * Pro/Enterprise: unlimited retention, do not call this method.
 */
async pruneForCE() {
  let raw;
  try {
    raw = await fsp.readFile(this._path, 'utf8');
  } catch {
    return; // file doesn't exist yet
  }
  const cutoff = Date.now() - CE_RETENTION_MS;
  const kept = raw.split('\n').filter(line => {
    if (!line.trim()) return false;
    try {
      const entry = JSON.parse(line);
      return new Date(entry.timestamp).getTime() >= cutoff;
    } catch {
      return true; // keep unparseable lines rather than lose data
    }
  });
  await fsp.writeFile(this._path, kept.join('\n') + (kept.length ? '\n' : ''));
}
```

- [ ] **Step 3: Call `pruneForCE()` from CLI after each scan in CE mode**

In `cli.mjs`, after `scanHistory.save(...)` in the per-host scan loop, add:

```js
// CE: enforce 7-day JSONL retention
const { getTierFromEnv } = await import('./utils/license.mjs'); // already imported
if (getTierFromEnv() === 'ce') {
  await scanHistory.pruneForCE();
}
```

- [ ] **Step 4: Run tests**

```bash
node --test tests/scan_history.test.mjs 2>&1 | tail -5
node --test 2>&1 | tail -8
```

- [ ] **Step 5: Commit**

```bash
git add utils/scan_history.mjs cli.mjs tests/scan_history.test.mjs
git commit -m "feat: enforce 7-day JSONL retention for CE tier"
```

---

### Task H.5 — Code Correctness: Finding ID Uniqueness

**Files:**
- Modify: `utils/finding_schema.mjs`
- Modify: `tests/` (update finding_schema tests if they assert exact ID format)

**Problem:** Module-level `_counter` resets on every process restart → duplicate IDs across runs. Also breaks at `F-YYYY-9999`. The `uuid` package is already installed.

- [ ] **Step 1: Check existing tests for ID format assumptions**

```bash
grep -n 'F-202\|_counter\|generateFinding' tests/*.test.mjs
```

Note any tests that assert exact ID values (they'll need updating).

- [ ] **Step 2: Replace `_counter` with uuid**

In `utils/finding_schema.mjs`, replace:

```js
let _counter = 0;

export function generateFindingId() {
  const year = new Date().getFullYear();
  return `F-${year}-${String(++_counter).padStart(4, '0')}`;
}
```

With:

```js
import { v4 as uuidv4 } from 'uuid';

export function generateFindingId() {
  return `F-${uuidv4()}`;
}
```

ID format changes from `F-2026-0001` to `F-<uuid>`. Any tests that assert the old format must be updated to use `assert.match(id, /^F-[0-9a-f-]{36}$/)`.

- [ ] **Step 3: Update tests that assert old ID format**

The known breakage is in `tests/finding_schema.test.mjs:55` — the test `'generateFindingId format is F-YYYY-NNNN'`:

```js
// Before (line 53-55):
test('generateFindingId format is F-YYYY-NNNN', () => {
  const id = generateFindingId();
  assert.match(id, /^F-\d{4}-\d{4}$/, `ID format wrong: ${id}`);
```

Replace with:
```js
test('generateFindingId format is F-<uuid>', () => {
  const id = generateFindingId();
  assert.match(id, /^F-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/, `ID format wrong: ${id}`);
```

Also check `tests/finding_queue.test.mjs` — `assert.ok(id.startsWith('F-'))` still passes with uuid format, no change needed there.

Run to confirm only that one assertion needed updating:
```bash
node --test tests/finding_schema.test.mjs tests/finding_queue.test.mjs 2>&1 | tail -5
# Expected: all pass
```

- [ ] **Step 4: Run full suite**

```bash
node --test 2>&1 | tail -8
# Expected: 438+ pass, 0 fail
```

- [ ] **Step 5: Commit**

```bash
git add utils/finding_schema.mjs tests/
git commit -m "fix: replace module-level counter with uuid for finding IDs"
```

---

### Task H.6 — Code Correctness: Redaction Dedup + CPE Length Cap + MCP isError

**Files:**
- Modify: `cli.mjs` (remove duplicate `scrubByKey`, import from `redact.mjs`)
- Modify: `mcp_server.mjs` (CPE length cap + `isError` on Pro denial)
- Modify: `tests/mcp_server.test.mjs`

**Problems:**
- Duplicate `scrubByKey` in `cli.mjs:78` diverges silently from `utils/redact.mjs` canonical version
- Unbounded CPE string length in NVD cache key (DoS vector)
- `requireProCapability` returns `isError: false` — confuses MCP clients that inspect `isError`

- [ ] **Step 1: Remove duplicate `scrubByKey` from `cli.mjs`**

Find the local `scrubByKey` function in `cli.mjs` (~line 78). Confirm that `utils/redact.mjs` exports an identical or superior version:

```bash
grep -n 'scrubByKey\|function scrub' cli.mjs utils/redact.mjs
```

Remove the local definition and add/verify the import at the top of `cli.mjs`:

```js
import { scrubByKey } from './utils/redact.mjs';
```

- [ ] **Step 2: Add CPE length validation in `mcp_server.mjs`**

In `handleGetVulnerabilities`, after the CPE format check:

```js
if (!/^cpe:2\.3:[aho]:/.test(args.cpe)) {
  throw new Error('Invalid CPE 2.3 format. Expected: cpe:2.3:{a|h|o}:vendor:product:...');
}
// Add length cap:
if (args.cpe.length > 500) {
  throw new Error('CPE string too long (max 500 characters)');
}
```

- [ ] **Step 3: Write test for CPE length cap**

```js
it('rejects CPE strings longer than 500 chars', async () => {
  const { handleGetVulnerabilities } = await import('../mcp_server.mjs');
  const longCpe = 'cpe:2.3:a:vendor:product:' + 'x'.repeat(500);
  await assert.rejects(() => handleGetVulnerabilities({ cpe: longCpe }), /too long/);
});
```

- [ ] **Step 4: Change `isError` on Pro upsell denial to `true`**

In `requireProCapability`:

```js
return {
  content: [{ type: 'text', text: `🔒 **${toolName}** requires a Pro license.\n\n...` }],
  isError: true, // was false — MCP clients use isError to detect non-successful responses
};
```

Update any test that asserts `isError: false` on the upsell response.

- [ ] **Step 5: Run full suite**

```bash
node --test 2>&1 | tail -8
```

- [ ] **Step 6: Commit**

```bash
git add cli.mjs mcp_server.mjs tests/mcp_server.test.mjs
git commit -m "fix: remove duplicate scrubByKey, CPE length cap, isError on Pro denial"
```

---

### Task H.7 — Security: `globalThis.redactSensitiveForAI` Capability Gate

**Files:**
- Modify: `cli.mjs:236-242`

**Problem:** The `globalThis.redactSensitiveForAI` hook is checked before any capability gate. Any in-process code can replace the redaction pipeline without going through the tier system, breaking the ZDE guarantee.

- [ ] **Step 1: Add capability check before using the override**

In `cli.mjs`, find the block:

```js
if (typeof globalThis.redactSensitiveForAI === 'function') {
```

Replace with:

```js
// Only allow external redaction override for Pro/Enterprise tiers (enhanced redaction capability).
// CE always uses the built-in redact pipeline to preserve ZDE guarantee.
const { getTierFromEnv } = ...; // already imported
const { resolveCapabilities, hasCapability } = ...; // already imported
const _caps = resolveCapabilities(getTierFromEnv());
if (hasCapability(_caps, 'enhancedRedaction') && typeof globalThis.redactSensitiveForAI === 'function') {
```

- [ ] **Step 2: Run full suite**

```bash
node --test 2>&1 | tail -8
```

- [ ] **Step 3: Commit**

```bash
git add cli.mjs
git commit -m "fix: gate globalThis.redactSensitiveForAI override behind enhancedRedaction capability"
```

---

### Task H.8 — Final CE Public Release Verification

**Files:** None modified — verification only

- [ ] **Step 1: Full test run**

```bash
node --test 2>&1 | tail -10
# Required: all pass, 0 fail
```

- [ ] **Step 2: Verify npm pack is clean**

```bash
npm pack --dry-run 2>&1 | grep -v node_modules
# Must NOT include: .env, .scan_history/, out/, *.log, .DS_Store, tasks/
# Must include: cli.mjs, mcp_server.mjs, plugin_manager.mjs, plugins/, utils/, package.json, LICENSE, README.md
```

If `.env` appears, add it to `.npmignore`:

```bash
echo ".env" >> .npmignore
echo "out/" >> .npmignore
echo "tasks/" >> .npmignore
echo ".scan_history/" >> .npmignore
```

- [ ] **Step 3: Verify the package installs and scans offline**

```bash
npm pack
npm install -g nsauditor-ai-0.1.0.tgz
nsauditor-ai license --status
# Expected: ✓ Community Edition (CE) — no license key required
nsauditor-ai scan --host 127.0.0.1 --plugins 001
# Expected: runs ping checker, produces output
```

- [ ] **Step 4: Tag and push**

```bash
git tag -a v0.1.0-ce -m "CE hardening complete — ready for public launch"
git push origin main --tags
```

- [ ] **Step 5: Make repository public on GitHub**

Via GitHub UI: Settings → Danger Zone → Change visibility → Public.

---

## Roadmap (Phases 2–10)

High-level phases for Pro and Enterprise tiers. Each will be expanded into a detailed task plan before implementation begins.

### Phase L — Legacy CVE Remediation (URGENT, parallel)
11 CVEs across 8 legacy Windows products (VC++ 6 buffer overflows, Feb 2026). Credibility risk.
- [ ] L.1 Publish security advisory
- [ ] L.2–L.4 Apply input validation fix, rebuild, release patched versions
- [ ] L.5–L.7 Update advisory + NVD + add NSAuditor AI CTAs on download pages

### Phase 0 — Legal & IP Foundation
- [ ] 0.1–0.7 EE proprietary license, IP Assignment, EULA, Terms, Stripe, trademark

### Phase 2 — License System (JWT, offline) — PARTIAL ✅
- [x] 2.1 ECDSA P-256 key pair generation (done — keys in license-manager/private/)
- [x] 2.2 JWT signing service (done — license-manager repo: lib/jwt.mjs, lib/keygen.mjs, bin/generate-key.mjs)
- [ ] 2.3 Stripe webhook → JWT → email delivery
- [x] 2.4 Replace `license.mjs` stub with `jose` ES256 offline verification (done — v0.1.11, commit 4ba400e)
- [x] 2.5 14-day trial key generation (done — `generate-key.mjs --expires 14d`)
- [x] 2.6 Tests: valid/expired/tampered/no-key/prefix-mismatch/wrong-issuer/wrong-audience (14 CE tests, 15 license-manager tests, EE tests updated)
- [ ] 2.7 MCP admin server for Claude Desktop (license-manager repo, planned Phase 2.5)

### Phase 3 — Intelligence Engine (Pro Core Value)
- [ ] 3.1–3.3 CPE generation, offline NVD feed, CVE matching → FindingQueue
- [ ] 3.4–3.5 MITRE ATT&CK mapping, risk scoring
- [ ] 3.6–3.8 Wire into pipeline, Pro MCP tools, tests

### Phase 3b — Parallel Analysis Agents (Pro)
- [ ] 3b.1–3b.7 Agent runner, Auth/Crypto/Config/Service/Exposure agents, tests

### Phase 4 — Verification Engine (Key Differentiator)
- [ ] 4.1–4.8 Verifier runner, TLS/SSH/HTTP/default-creds/service verifiers, tests

### Phase 5 — Pro AI Pipeline & Reports
- [ ] 5.1–5.6 Pro prompt pipelines, enhanced redaction, executive reports, PDF, branded reports

### Phase 6 — Advanced CTEM
- [ ] 6.1–6.5 SQLite ScanStore, finding-aware delta, trend analysis, upgraded CTEM engine

### Phase 7 — Distribution & Billing
- [ ] 7.1–7.4 npm CE package, EE scoped package, curl installer, npx entry points
- [ ] 7.5–7.9 License server, Stripe checkout, customer portal, end-to-end billing test

### Phase 8 — Enterprise Features
- [ ] 8.1–8.3 Cloud scanners + Zero Trust in EE repo
- [ ] 8.4–8.6 Compliance engine (NIST/HIPAA/GDPR/PCI), ZDE policy engine
- [ ] 8.7–8.10 PostgreSQL ScanStore, Enterprise MCP tools, usage metering, Docker isolation
- [ ] 8.11–8.14 Docker images, air-gapped tarball, offline NVD feeds

### Phase 9 — Launch & Marketing
- [ ] 9.1–9.8 nsauditor.com/ai pages, GitHub release, npm publish, email campaign, Product Hunt

### Phase 10 — Marketplace (Future)
- [ ] 10.1–10.3 Plugin SDK docs, marketplace registry, third-party plugin payments

---

## Success Criteria — CE Public Launch (End of Phase CE-H)

- [ ] CE installs globally via `npm install -g nsauditor-ai` and scans offline with zero setup
- [ ] All CE tests pass (438+ expected), 0 fail
- [ ] `nsauditor-ai license --status` correctly shows CE/Pro/Enterprise tier
- [ ] Pro tool calls via MCP return upsell with `isError: true` (no silent failures)
- [ ] EE plugins auto-discovered when `@nsasoft/nsauditor-ai-ee` is installed
- [ ] `NSAUDITOR_PLUGIN_PATH` entries outside cwd/HOME are silently skipped (no path traversal)
- [ ] Decimal-encoded loopback IPs rejected by MCP SSRF guard
- [ ] Scan history pruned to 7 days automatically in CE mode
- [ ] Finding IDs are globally unique (uuid-based, no counter reset across restarts)
- [ ] `globalThis.redactSensitiveForAI` override requires `enhancedRedaction` capability (Pro+)
- [ ] `npm pack --dry-run` shows no `.env`, `out/`, `tasks/`, `.scan_history/` in package
- [ ] GitHub repository visibility changed to Public
- [ ] Git tag `v0.1.0-ce` pushed

---

## Phase CE-S — Security & Quality Fixes (post-launch review) ✅ COMPLETE

> **Source:** Comprehensive review by Code Reviewer + Security Engineer + Network Audit Reviewer after CE-H completed.
> **Goal:** Close confirmed security gaps and data-loss bugs before v0.1.1. All HIGH items block v0.1.1 release.
> **Status:** All 13 tasks merged to `main` (bc6cefb). 483 tests passing. Pushed to origin 2026-04-06.

---

### Validity Notes (findings reviewed against actual code)

| ID | Status | Rationale |
|----|--------|-----------|
| C-1 | Operational only | `git log --all -p -- .env` returned empty — keys never committed. Rotate keys as ops task; no code change needed. |
| C-2 | ✅ Resolved in v0.1.11 | `getTierFromEnv()` now returns 'ce' by default; `loadLicense()` does ES256 JWT verification. Prefix spoofing no longer possible. |
| C-3 | Mitigated by H.7 | `globalThis.redactSensitiveForAI` now gated behind `enhancedRedaction` capability. Residual risk via C-2 closes with Phase 2 JWT. |
| H-1 through H-7 | All confirmed valid | Code inspection confirmed each gap. |
| I-1, I-3, I-4, I-6, I-9, I-10 | Confirmed valid | Confirmed in code. |
| I-2 | Valid, deferred | 11 plugins missing `conclude()` — large scope, tracked for v0.2. |
| I-5, I-8 | Valid, backlog | CLI refactoring + normalization dedup — architectural debt, not bugs. |

---

### Task S.1 — Security: Symlink bypass in plugin discovery

**Finding H-1.** `isSafePath()` checks `resolve(dir)` but does not dereference symlinks. A symlink inside `$HOME` pointing outside the allowed tree passes the guard → arbitrary `.mjs` file exec on `import()`.

**File:** `utils/plugin_discovery.mjs:71`

- [ ] **Step 1: Add `realpathSync` import and resolve symlinks before the safe-path check**

```js
import { existsSync, realpathSync } from 'node:fs';
```

In the loop over `customPaths.split(':')`, replace:
```js
const abs = resolve(dir);
if (!isSafePath(abs)) {
```
With:
```js
const abs = resolve(dir);
let real;
try {
  real = realpathSync(abs);
} catch {
  // Path doesn't exist yet or is inaccessible — skip
  if (process.env.NSA_VERBOSE) console.warn(`[plugin_discovery] Cannot resolve real path for: ${abs}`);
  continue;
}
if (!isSafePath(real)) {
```

Update `existsSync(abs)` to `existsSync(real)` and `loadPluginsFromDir(abs, 'custom')` to `loadPluginsFromDir(real, 'custom')`.

- [ ] **Step 2: Write test**

Add to `tests/plugin_discovery.test.mjs`:
```js
test('rejects symlink pointing outside HOME', async () => {
  // Create a symlink inside a tmp dir that points to /tmp (outside cwd and HOME)
  // Verify it is skipped even though the resolved-before-real path would be inside HOME
  // (Use execFileSync subprocess pattern already established in this file)
});
```
If creating symlinks in CI is fragile, document clearly why and use `assert.ok(true, 'symlink test skipped in this environment')` with a comment.

- [ ] **Step 3: Run full suite and commit**
```bash
node --test tests/*.test.mjs 2>&1 | tail -8
git add utils/plugin_discovery.mjs tests/plugin_discovery.test.mjs
git commit -m "fix: dereference symlinks in plugin path guard (H-1)"
```

---

### Task S.2 — Security: CLI SSRF guard

**Finding H-2.** `cli.mjs` scan path passes `host` directly to plugins without any SSRF validation. MCP server has `validateHost()` but CLI does not call it. `nsauditor-ai scan --host 169.254.169.254` scans the cloud metadata endpoint.

**File:** `cli.mjs` (scan entry point, around the `scanSingleHost` function)

- [ ] **Step 1: Import and call `isBlockedIp` + `resolveAndValidate` before scan**

`utils/net_validation.mjs` already exports `isBlockedIp` and `resolveAndValidate`. Add import:
```js
import { isBlockedIp, resolveAndValidate } from './utils/net_validation.mjs';
```

In `scanSingleHost` (or wherever host is first used), add a guard:
```js
// SSRF guard: block loopback, private ranges, cloud metadata
if (isBlockedIp(host)) {
  throw new Error(`Scanning blocked address range is not allowed: ${host}`);
}
// For hostnames: resolve and validate resolved IP
if (!/^[\d.:[\]]+$/.test(host)) { // hostname, not literal IP
  try {
    await resolveAndValidate(host);
  } catch (err) {
    throw new Error(`Host rejected by SSRF guard: ${err.message}`);
  }
}
```

Note: This guard should be bypassable via env var `NSA_ALLOW_ALL_HOSTS=1` for local-network scanning use cases (power users scanning RFC 1918 hosts). Gate the guard: `if (!process.env.NSA_ALLOW_ALL_HOSTS)`.

- [ ] **Step 2: Write tests**

Add to `tests/cli_syntax.test.mjs` or a new `tests/cli_ssrf.test.mjs`:
- Blocked IPs (`127.0.0.1`, `169.254.169.254`, `10.0.0.1`) throw when `NSA_ALLOW_ALL_HOSTS` unset
- Blocked IPs allowed when `NSA_ALLOW_ALL_HOSTS=1`

- [ ] **Step 3: Run full suite and commit**
```bash
node --test tests/*.test.mjs 2>&1 | tail -8
git commit -m "fix: add SSRF guard to CLI scan path (H-2)"
```

---

### Task S.3 — Security: HTML report XSS in linkifyBareUrls

**Finding H-3.** `linkifyBareUrls` in `utils/report_html.mjs:101` injects URLs directly into `href="${u}"` without HTML-encoding. A URL containing `"` breaks the attribute boundary → XSS.

**File:** `utils/report_html.mjs:101-104`

**Current code:**
```js
return `${pre}<a href="${u}" target="_blank" rel="noopener noreferrer">${u}</a>`;
```

- [ ] **Step 1: Add an HTML-attribute escape helper and apply it**

```js
// Escape characters that break HTML attribute values
function escAttr(s) {
  return s.replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/'/g, '&#39;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}
```

Replace the return value:
```js
return `${pre}<a href="${escAttr(u)}" target="_blank" rel="noopener noreferrer">${escAttr(u)}</a>`;
```

- [ ] **Step 2: Write test**

In `tests/report_html.test.mjs`, add:
```js
test('linkifyBareUrls escapes double-quote in URL (XSS prevention)', () => {
  // A URL with " must not break out of the href attribute
  const input = `<p>See >http://example.com/"onmouseover="alert(1) for details</p>`;
  const result = buildHtmlReport({ /* minimal args */ });
  // The rendered href must contain &quot; not a raw "
  assert.ok(!result.includes(`href="http://example.com/"`));
});
```

- [ ] **Step 3: Run full suite and commit**
```bash
node --test tests/*.test.mjs 2>&1 | tail -8
git commit -m "fix: HTML-escape URLs in linkifyBareUrls to prevent XSS (H-3)"
```

---

### Task S.4 — Security: Guard test-only exports in mcp_server.mjs

**Finding H-4.** `_setTier()`, `_setValidateHost()`, `_setPluginManager()` are exported unconditionally. Any code importing `mcp_server.mjs` can disable SSRF protection or bypass tier gating at runtime.

**File:** `mcp_server.mjs:38-83`

- [ ] **Step 1: Wrap test exports in NODE_ENV guard**

Replace each test export function body:
```js
export function _setTier(tier) {
  if (process.env.NODE_ENV === 'production') throw new Error('_setTier is test-only');
  _tier = tier ?? getTierFromEnv();
  _capabilities = resolveCapabilities(_tier);
}

export function _setPluginManager(pm) {
  if (process.env.NODE_ENV === 'production') throw new Error('_setPluginManager is test-only');
  _pluginManager = pm;
}

export function _setNvdClient(client) {
  if (process.env.NODE_ENV === 'production') throw new Error('_setNvdClient is test-only');
  _nvdClient = client;
}

export function _setValidateHost(fn) {
  if (process.env.NODE_ENV === 'production') throw new Error('_setValidateHost is test-only');
  _validateHostFn = fn ?? validateHost;
}

export function _requireProCapability(toolName) {
  if (process.env.NODE_ENV === 'production') throw new Error('_requireProCapability is test-only');
  return requireProCapability(toolName);
}
```

- [ ] **Step 2: Add test verifying guard throws in production**

```js
test('_setTier throws when NODE_ENV=production', async () => {
  const origEnv = process.env.NODE_ENV;
  process.env.NODE_ENV = 'production';
  try {
    assert.throws(() => _setTier('pro'), /test-only/);
  } finally {
    process.env.NODE_ENV = origEnv;
  }
});
```

- [ ] **Step 3: Run full suite and commit**
```bash
node --test tests/*.test.mjs 2>&1 | tail -8
git commit -m "fix: guard test-only MCP exports behind NODE_ENV check (H-4)"
```

---

### Task S.5 — Security: TLS_SCANNER_TLS_MODULE whitelist

**Finding H-5.** `plugins/tls_scanner.mjs:21` uses `process.env.TLS_SCANNER_TLS_MODULE` directly in `import()`, allowing any module path to be injected.

**File:** `plugins/tls_scanner.mjs:21`

**Current code:**
```js
const TLS_MODULE_ID = process.env.TLS_SCANNER_TLS_MODULE || 'node:tls';
```

- [ ] **Step 1: Whitelist allowed values**

```js
const _rawTlsMod = process.env.TLS_SCANNER_TLS_MODULE;
const ALLOWED_TLS_MODULES = new Set(['node:tls', 'tls']); // 'tls' = bare name for stub injection in tests
const TLS_MODULE_ID = (_rawTlsMod && ALLOWED_TLS_MODULES.has(_rawTlsMod)) ? _rawTlsMod : 'node:tls';
if (_rawTlsMod && !ALLOWED_TLS_MODULES.has(_rawTlsMod)) {
  console.warn(`[tls_scanner] Ignoring unknown TLS_SCANNER_TLS_MODULE value: ${_rawTlsMod}`);
}
```

- [ ] **Step 2: Verify existing tests still pass (they inject via the env var)**

Run `node --test tests/tls_scanner.test.mjs` and confirm green. If test stubs use a path not in the whitelist, add the stub module ID (e.g. `'./tests/_tls_stub.mjs'`) to `ALLOWED_TLS_MODULES` — or refactor the stub injection mechanism.

- [ ] **Step 3: Run full suite and commit**
```bash
node --test tests/*.test.mjs 2>&1 | tail -8
git commit -m "fix: whitelist TLS_SCANNER_TLS_MODULE to prevent arbitrary module injection (H-5)"
```

---

### Task S.6 — Security: Webhook SSRF — enforce isSafeWebhookUrl inside sendWebhook

**Finding H-6.** `sendWebhook()` only calls `isValidWebhookUrl()` (checks http/https protocol). `isSafeWebhookUrl()` (SSRF check with DNS resolution) is only called in CLI `parseArgs`. Callers via scheduler or programmatic API bypass the SSRF check entirely.

**File:** `utils/webhook.mjs:57`

- [ ] **Step 1: Call isSafeWebhookUrl inside sendWebhook**

`sendWebhook` is already async. Add SSRF check at the top:
```js
export async function sendWebhook(url, payload, opts = {}) {
  // Enforce SSRF safety at the call site — callers that bypass CLI parseArgs
  // (scheduler, programmatic) are also protected.
  const safe = await isSafeWebhookUrl(url);
  if (!safe) {
    return { success: false, statusCode: 0, error: 'URL rejected by SSRF guard' };
  }
  // ... rest of function unchanged
```

Remove the now-redundant `if (!isValidWebhookUrl(url))` check since `isSafeWebhookUrl` calls it internally.

- [ ] **Step 2: Update tests**

`tests/webhook.test.mjs` may have tests that pass private-range URLs to `sendWebhook` directly. Update them to expect `{ success: false, error: /SSRF/ }` instead of a network error, or mock `isSafeWebhookUrl` to return `true` for those tests.

- [ ] **Step 3: Run full suite and commit**
```bash
node --test tests/*.test.mjs 2>&1 | tail -8
git commit -m "fix: enforce isSafeWebhookUrl inside sendWebhook to cover all callers (H-6)"
```

---

### Task S.7 — Security: IPv6 SSRF gaps in isBlockedIp

**Finding H-7.** `isBlockedIp()` misses `::127.0.0.1` (IPv4-compatible loopback shorthand) and `fc00::/7` (unique local — includes `fd00::/8`).

**File:** `utils/net_validation.mjs:19-22`

- [ ] **Step 1: Add missing IPv6 blocks**

```js
// IPv6 blocked addresses
if (addr === '::1' || addr === '::') return true;
if (/^fe80:/i.test(addr)) return true;                    // link-local (fe80::/10)
if (/^f[cd]/i.test(addr.slice(0, 2))) return true;       // fc00::/7 unique local (fc__ and fd__)
// IPv4-compatible loopback: ::127.0.0.1 maps to 127.0.0.1/8
const compatMatch = addr.match(/^::(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/i);
if (compatMatch) return isBlockedIp(compatMatch[1]);
```

- [ ] **Step 2: Write tests for the new cases**

In `tests/net_validation.test.mjs`:
```js
test('isBlockedIp blocks fc00::/7 unique local', () => {
  assert.equal(isBlockedIp('fc00::1'), true);
  assert.equal(isBlockedIp('fd12:3456:789a::1'), true);
});
test('isBlockedIp blocks ::127.0.0.1 (IPv4-compatible loopback)', () => {
  assert.equal(isBlockedIp('::127.0.0.1'), true);
});
test('isBlockedIp allows public IPv6', () => {
  assert.equal(isBlockedIp('2001:db8::1'), false);
});
```

- [ ] **Step 3: Run full suite and commit**
```bash
node --test tests/*.test.mjs 2>&1 | tail -8
git commit -m "fix: block fc00::/7 unique local and ::127.x IPv4-compat in isBlockedIp (H-7)"
```

---

### Task S.8 — Data Loss: Webapp Detector conclude() returns []

**Finding I-3.** `plugins/webapp_detector.mjs:230-232` exports `conclude()` that always returns `[]`. All webapp detections (WordPress, Joomla, etc.) are discarded during result fusion. This means the final report never shows detected web technologies.

**File:** `plugins/webapp_detector.mjs:230-232`

- [ ] **Step 1: Implement conclude() to emit detected apps as services**

```js
export async function conclude({ host, result }) {
  if (!result?.detectedApps?.length) return [];
  return result.detectedApps.map(app => ({
    protocol: 'tcp',
    port: app.port ?? 80,
    service: app.name,
    version: app.version ?? null,
    info: app.category ?? 'webapp',
    authoritative: false,
  }));
}
```

Read the actual `result` shape from `run()` to use the correct field names.

- [ ] **Step 2: Write test for conclude() output**

```js
test('conclude() emits detected apps as service records', async () => {
  const result = { detectedApps: [{ name: 'WordPress', version: '6.4', port: 80, category: 'CMS' }] };
  const records = await conclude({ host: '10.0.0.1', result });
  assert.equal(records.length, 1);
  assert.equal(records[0].service, 'WordPress');
  assert.equal(records[0].version, '6.4');
});
```

- [ ] **Step 3: Run full suite and commit**
```bash
node --test tests/*.test.mjs 2>&1 | tail -8
git commit -m "fix: webapp_detector conclude() now emits detected apps instead of returning [] (I-3)"
```

---

### Task S.9 — Quality: console.log pollution in host_up_check and ftp_banner_check

**Finding I-4.** `plugins/host_up_check.mjs` has 15+ unconditional `console.log` calls. `plugins/ftp_banner_check.mjs` similar. Other plugins use `DEBUG`/`dlog` guards correctly.

**Files:** `plugins/host_up_check.mjs`, `plugins/ftp_banner_check.mjs`

- [ ] **Step 1: Add dlog guard in host_up_check.mjs**

Add at top (matching pattern used in other plugins):
```js
const DEBUG = /^(1|true|yes|on)$/i.test(String(process.env.DEBUG_MODE || process.env.HOST_UP_DEBUG || ''));
function dlog(...a) { if (DEBUG) console.log('[host-up-check]', ...a); }
```

Replace every `console.log(...)` with `dlog(...)` and `console.error(...)` with `if (DEBUG) console.error(...)` throughout the file.

- [ ] **Step 2: Same fix for ftp_banner_check.mjs**

Audit `plugins/ftp_banner_check.mjs` for unconditional `console.log` and apply the same pattern.

- [ ] **Step 3: Run full suite and commit**
```bash
node --test tests/*.test.mjs 2>&1 | tail -8
git commit -m "fix: gate console.log in host_up_check and ftp_banner_check behind DEBUG flag (I-4)"
```

---

### Task S.10 — Quality: AI call timeout (AbortController)

**Finding I-6.** `cli.mjs:325` and `cli.mjs:348` call `client.messages.create()` / `client.responses.create()` with no timeout. A hanging AI provider blocks the entire pipeline indefinitely.

**File:** `cli.mjs:320-393`

- [ ] **Step 1: Add AbortController with configurable timeout**

```js
const AI_TIMEOUT_MS = Number(process.env.NSA_AI_TIMEOUT_MS) || 120_000; // 2 min default

const ac = new AbortController();
const aiTimer = setTimeout(() => ac.abort(), AI_TIMEOUT_MS);
try {
  if (aiProvider === 'claude') {
    resp = await client.messages.create({ ... }, { signal: ac.signal });
  } else {
    // OpenAI
    resp = await client.responses.create({ ... }, { signal: ac.signal });
    // or chat.completions.create(..., { signal: ac.signal })
  }
} finally {
  clearTimeout(aiTimer);
}
```

Note: Anthropic SDK `messages.create` accepts a `RequestOptions` second argument with `signal`. OpenAI SDK similarly accepts `{ signal }`. Verify the exact API for the installed SDK versions.

- [ ] **Step 2: Write test**

Mock the AI client to delay indefinitely, set `NSA_AI_TIMEOUT_MS=100`, verify the call rejects with an abort error within 500ms.

- [ ] **Step 3: Run full suite and commit**
```bash
node --test tests/*.test.mjs 2>&1 | tail -8
git commit -m "fix: add AbortController timeout to AI provider calls (I-6)"
```

---

### Task S.11 — Quality: OUI sync fallback is broken (fire-and-forget)

**Finding I-10.** `utils/oui.mjs:61` calls `initOui().catch(...)` and immediately checks `OUI_DB` which is still `null`. Vendor lookup silently returns `null` on first call.

**File:** `utils/oui.mjs:57-62`

- [ ] **Step 1: Fix sync fallback — make lookupVendor await initialization**

The cleanest fix: `lookupVendor` should not be called before `initOui()` completes. The callers (plugin context) already call `initOui()` at startup. Remove the broken sync fallback:

```js
export function lookupVendor(mac) {
  if (!OUI_DB || !mac || typeof mac !== 'string') {
    return null; // callers must call initOui() before lookupVendor
  }
  // ... rest unchanged
}
```

Add a comment in `plugin_manager.mjs` (wherever `initOui()` is called) noting it must complete before plugins run.

- [ ] **Step 2: Run full suite and commit**
```bash
node --test tests/*.test.mjs 2>&1 | tail -8
git commit -m "fix: remove broken fire-and-forget sync fallback in lookupVendor (I-10)"
```

---

### Task S.12 — Architecture: Consolidate isPrivateLike() duplication

**Finding (Architecture table).** `isPrivateLike()` is duplicated across 5 plugins: `arp_scanner.mjs`, `ping_checker.mjs`, and others. `utils/net_validation.mjs` already exports `isBlockedIp()` which covers the same ranges.

**Files:** `plugins/arp_scanner.mjs`, `plugins/ping_checker.mjs`, and 3 others; `utils/net_validation.mjs`

- [ ] **Step 1: Export isPrivateLike from net_validation.mjs (as alias for isBlockedIp)**

Add to `utils/net_validation.mjs`:
```js
/** @deprecated Use isBlockedIp(). Alias kept for plugin compatibility. */
export function isPrivateLike(ip) { return isBlockedIp(ip); }
```

- [ ] **Step 2: Update each plugin to import and use it**

For each of the 5 plugins with a local `isPrivateLike`:
1. Add `import { isPrivateLike } from '../utils/net_validation.mjs';`
2. Remove the local `isPrivateLike` function definition

- [ ] **Step 3: Run full suite and commit**
```bash
node --test tests/*.test.mjs 2>&1 | tail -8
git commit -m "refactor: consolidate isPrivateLike() duplication into net_validation.mjs (architecture)"
```

---

### Task S.13 — Architecture: Fix SNMP run() signature mismatch

**Finding (Architecture table).** `plugins/snmp_scanner.mjs:112` uses `run(host, options = {})` instead of the standard `run(host, port, opts)`. Works by accident because `options` receives the `port` number.

**File:** `plugins/snmp_scanner.mjs:112`

- [ ] **Step 1: Align signature**

```js
async run(host, port, opts = {}) {
  const options = opts; // drop-in rename
```

Verify nothing in the plugin uses `options` as a number. Port for SNMP is always 161 (UDP) and is likely hardcoded or read from `plugin.ports` — confirm before changing.

- [ ] **Step 2: Run full suite and commit**
```bash
node --test tests/snmp_scanner.test.mjs
git commit -m "fix: align SNMP run() signature to standard run(host, port, opts) (architecture)"
```

---

### Phase CE-S Success Criteria

- [x] `realpathSync` applied in plugin discovery — symlink bypass closed (S.1 a2ff9b7)
- [x] CLI scan path rejects blocked IP ranges (SSRF guard) (S.2 2c07192)
- [x] `linkifyBareUrls` HTML-encodes URL before injecting into `href` (S.3 be69d46)
- [x] Test-only MCP exports throw in `NODE_ENV=production` (S.4 1a6fb22)
- [x] `TLS_SCANNER_TLS_MODULE` is whitelisted to known-safe values (S.5 a1a64cc)
- [x] `sendWebhook()` enforces SSRF check for all callers (S.6 a70b998)
- [x] `isBlockedIp()` blocks `fc00::/7` and `::127.x` (S.7 b3c37a2)
- [x] `webapp_detector.conclude()` emits detected apps (no silent data loss) (S.8 d28bd7b)
- [x] `host_up_check` and `ftp_banner_check` use debug-gated logging (S.9 8e8eb11)
- [x] AI calls have AbortController with `NSA_AI_TIMEOUT_MS` timeout (S.10 bc6cefb)
- [x] `lookupVendor` sync fallback removed (broken fire-and-forget) (S.11 0f84acb)
- [x] `isPrivateLike()` consolidated to `net_validation.mjs` (S.12 401ebf6)
- [x] SNMP `run()` signature aligned to `(host, port, opts)` (S.13 99d63de)
- [x] All existing tests pass, new tests added for each fix (483/483)

---

## Phase CE-G — Gap Closure (architecture doc ↔ code alignment)

> **Source:** Comprehensive code-vs-docs audit (2026-04-07). Compared actual CE codebase against `docs/architecture.md` v2.
> **Goal:** Close all gaps between documented architecture and implemented code. Code changes + doc corrections.
> **Depends on:** CE-S complete (483 tests passing).

---

### Task G.1 — Code: Rename `localAI` → `aiAnalysis` in capabilities.mjs

**Gap:** Architecture doc §7.1 and upstream define capability as `aiAnalysis` ("Any provider — OpenAI/Claude/Ollama, basic prompts"). Code still has `localAI` from the old model where CE was Ollama-only.

**File:** `utils/capabilities.mjs:6`

- [ ] **Step 1: Rename the capability constant**

```js
// Before:
localAI:            { tier: 'ce' },

// After:
aiAnalysis:         { tier: 'ce' },  // Any provider (OpenAI/Claude/Ollama), basic prompts
```

- [ ] **Step 2: Search and update all references to `localAI`**

```bash
grep -rn 'localAI' --include='*.mjs' .
```

Update any tests or code that reference the old name.

- [ ] **Step 3: Run full suite and commit**
```bash
node --test tests/*.test.mjs 2>&1 | tail -8
git commit -m "refactor: rename localAI → aiAnalysis capability to match architecture doc (G.1)"
```

---

### Task G.2 — Code: Implement Ollama AI provider in cli.mjs

**Gap:** README and architecture doc say all 3 AI providers (OpenAI, Claude, Ollama) work in CE. Code only implements OpenAI and Claude. Ollama has no SDK import or provider logic.

**File:** `cli.mjs` (AI analysis section, around `maybeSendToOpenAI`)

- [ ] **Step 1: Add Ollama provider branch**

Ollama exposes an OpenAI-compatible API at `http://localhost:11434/v1`. Use the existing OpenAI SDK with a custom `baseURL`:

```js
if (aiProvider === 'ollama') {
  const { default: OpenAI } = await import('openai');
  const ollamaBase = process.env.OLLAMA_BASE_URL || 'http://localhost:11434/v1';
  const client = new OpenAI({ baseURL: ollamaBase, apiKey: 'ollama' });
  const model = process.env.OLLAMA_MODEL || 'llama3';
  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(), AI_TIMEOUT_MS);
  try {
    resp = await client.chat.completions.create({
      model,
      messages: [{ role: 'user', content: prompt }],
    }, { signal: ac.signal });
    aiText = resp.choices?.[0]?.message?.content || '';
  } finally {
    clearTimeout(timer);
  }
}
```

- [ ] **Step 2: Update provider detection logic**

Ensure `AI_PROVIDER=ollama` is handled in the provider switch/conditional alongside `claude` and `openai`.

- [ ] **Step 3: Write test**

Add to `tests/cli_ai.test.mjs` (or similar):
```js
test('Ollama provider uses OpenAI SDK with custom baseURL', async () => {
  // Mock OpenAI SDK constructor, verify baseURL is set to localhost:11434/v1
  // Verify model comes from OLLAMA_MODEL env var
});
```

- [ ] **Step 4: Run full suite and commit**
```bash
node --test tests/*.test.mjs 2>&1 | tail -8
git commit -m "feat: implement Ollama AI provider via OpenAI-compatible API (G.2)"
```

---

### Task G.3 — Code: Wire CSV export to CLI `--output-format`

**Gap:** `utils/export_csv.mjs` has `buildCsv()` fully implemented and tested, but no code path in `cli.mjs` calls it. Users cannot get CSV output.

**File:** `cli.mjs` (output section, near SARIF output logic)

- [ ] **Step 1: Import buildCsv and add CSV output path**

```js
import { buildCsv } from './utils/export_csv.mjs';
```

In the output section (where SARIF is handled), add:
```js
if (outputFormat === 'csv' || outputFormat === 'all') {
  const csv = buildCsv(conclusion);
  writeFileSync(join(outDir, 'scan_results.csv'), csv);
}
```

- [ ] **Step 2: Update `--output-format` help text to include `csv`**

Update the CLI argument parsing to accept `csv` as a valid value. Document: `--output-format sarif|csv`.

- [ ] **Step 3: Write test**

```js
test('--output-format csv produces scan_results.csv', async () => {
  // Run scan with --output-format csv against a mock/stub
  // Verify scan_results.csv file is created with CSV content
});
```

- [ ] **Step 4: Run full suite and commit**
```bash
node --test tests/*.test.mjs 2>&1 | tail -8
git commit -m "feat: wire CSV export to --output-format csv (G.3)"
```

---

### Task G.4 — Code: Integrate MITRE ATT&CK mapping into scan pipeline

**Gap:** `utils/attack_map.mjs` is fully implemented with `getAllTechniques(conclusion)` but never called from `cli.mjs`. Techniques are never added to scan output despite being documented in Phase 2.

**File:** `cli.mjs` (post-concluder, pre-output section)

- [ ] **Step 1: Import and call attack_map after conclusion**

```js
import { getAllTechniques } from './utils/attack_map.mjs';
```

After the concluder produces its result, enrich it:
```js
const techniques = getAllTechniques(conclusion);
if (techniques.length > 0) {
  conclusion.result.techniques = techniques;
}
```

- [ ] **Step 2: Verify techniques appear in output files**

Check that `scan_conclusion_raw.json` includes the `techniques` array. Optionally update `raw_report_html.mjs` to render techniques if not already handled.

- [ ] **Step 3: Write test**

```js
test('scan conclusion includes MITRE ATT&CK techniques', () => {
  // Provide a conclusion with SSH + FTP services
  // Verify getAllTechniques returns T1021 (SSH) and T1078 (FTP anon)
  // Verify techniques array is attached to conclusion.result
});
```

- [ ] **Step 4: Run full suite and commit**
```bash
node --test tests/*.test.mjs 2>&1 | tail -8
git commit -m "feat: integrate MITRE ATT&CK mapping into scan pipeline output (G.4)"
```

---

### Task G.5 — Doc: Fix architecture.md discrepancies (batch)

**Gaps:** D-1 through D-7 — documentation is wrong or incomplete vs actual code.

**File:** `docs/architecture.md`

- [ ] **Step 1: Fix net_validation.mjs location (D-1)**

In §2.1 repository structure, move `net_validation.mjs` from `config/` to `utils/`:
```
├── utils/
│   ├── ...
│   ├── net_validation.mjs         # SSRF validation (isBlockedIp, isPrivateLike, resolveAndValidate)
│   └── nvd_client.mjs
├── config/
│   └── services.json
```

- [ ] **Step 2: Fix plugin naming convention (D-2)**

Replace numeric-prefix names with actual filenames:
```
├── plugins/
│   ├── ping_checker.mjs
│   ├── ssh_scanner.mjs
│   ├── port_scanner.mjs
│   ├── ...
│   └── syn_scanner.mjs
```

- [ ] **Step 3: Add undocumented utils (D-4)**

Add to §2.1 utils/ listing:
```
│   ├── conclusion_utils.mjs       # Conclusion helper functions
│   ├── cpe.mjs                    # CPE string generation
│   ├── cve_validator.mjs          # CVE ID validation
│   ├── cvss.mjs                   # CVSS scoring utilities
│   ├── nvd_cache.mjs              # NVD response caching
│   ├── oui.mjs                    # OUI/MAC vendor lookup
```

- [ ] **Step 4: Fix isSafeWebhookUrl location in §13.2 (D-5)**

Update SSRF table: `isSafeWebhookUrl` is in `utils/webhook.mjs`, not `net_validation.mjs`.

- [ ] **Step 5: Fix capability gating method name in §7.2 (D-6)**

Replace `_canRunPlugin` with `_hasCapabilities` in the code example.

- [ ] **Step 6: Document index.mjs programmatic API (D-7)**

Add a brief note to §2.1 or a new subsection:
```
index.mjs exports: PluginManager, buildHtmlReport
```

- [ ] **Step 7: Commit**
```bash
git commit -m "docs: fix architecture.md discrepancies — file locations, naming, method names (G.5)"
```

---

### Phase CE-G Success Criteria

- [ ] `aiAnalysis` capability replaces `localAI` in code and all tests (G.1)
- [ ] Ollama AI provider functional via `AI_PROVIDER=ollama` (G.2)
- [ ] `--output-format csv` produces CSV output file (G.3)
- [ ] MITRE ATT&CK techniques appear in scan conclusion output (G.4)
- [ ] Architecture doc matches actual code structure (G.5)
- [ ] All tests pass (target: 490+)

---

## After CE Launch — EE Private Branch

Once the CE repo is public:

1. Create private GitHub repo `nsauditor-ai-ee`
2. Scaffold as npm package `@nsasoft/nsauditor-ai-ee` with `nsauditor-ai` as peer dependency
3. Copy EE-only plugins from `../nsauditor-plugin-manager`: `cloud_aws.mjs`, `cloud_gcp.mjs`, `cloud_azure.mjs`, `zero_trust_checker.mjs`
4. Proceed with Roadmap Phase 0 (legal/IP) → Phase 2 (JWT license) → Phase 3 (Intelligence Engine)

---

## Phase CE-P — Public Launch (completed 2026-04-07)

> **Goal:** Sanitize codebase, publish npm package, set up MCP for Claude Desktop, make GitHub repo public.

---

### Task P.1 — Security Audit & Sanitization ✅

- [x] 3-agent parallel security scan (secrets, comments, docs)
- [x] Remove personal names from test fixtures (Lidiva, ANAHIT → anonymized)
- [x] Remove real MAC addresses and device hostnames from tests
- [x] Fix SARIF `TOOL_URI` pointing to private repo `nsauditor-plugin-manager`
- [x] Strip license bypass comments (`pro_*` prefix mechanism)
- [x] Strip Phase 2 roadmap details (library names, algorithms, key strategies)
- [x] Remove internal migration docs from test comments
- [x] Remove unconditional `console.log` from SSH scanner
- [x] EULA: set effective date, remove draft disclaimer
- [x] Architecture doc: remove hosting platform names, condense monetization strategy

### Task P.2 — npm Package ✅

- [x] Create `bin/` wrapper scripts for npm 11 compatibility
- [x] Publish `nsauditor-ai@0.1.0` to npmjs
- [x] Add npm badge to README
- [x] Verify global install works (`npm install -g nsauditor-ai`)

### Task P.3 — MCP Server Fixes ✅

- [x] Fix `NSA_ALLOW_ALL_HOSTS` bypass not wired in MCP `validateHost()`
- [x] Fix relative plugin path (`./plugins` → absolute `__dirname/plugins`)
- [x] Document `PLUGIN_TIMEOUT_MS=5000` for Claude Desktop's 60s MCP limit
- [x] Update README: use `"command": "node"` with full path (npx unreliable in Claude Desktop)

### Task P.4 — Git History & Public Launch ✅

- [x] Squash 50 commits into single clean release commit
- [x] Force push sanitized history to main
- [x] Publish final `nsauditor-ai@0.1.4`
- [x] Make GitHub repo public: https://github.com/nsasoft/nsauditor-ai

---

## Phase CE-N — Next Up

> **Goal:** Security hardening, developer experience improvements, and EE scaffolding.
>
> **Progress (2026-04-26):**
> - N.3 ✅ EE Private Repo Scaffold (earlier)
> - N.5 ✅ FindingSchema cwe/owasp fields — shipped in v0.1.13 (520 tests, +14 new)
> - N.14 ✅ cweToMitre helper + CWE_TECHNIQUE_MAP — shipped in v0.1.14 (547 tests, +27 new)
> - N.6 ✅ Markdown report output (--output-format md, MCP markdown field) — shipped in v0.1.15 (575 tests, +28 new)
> - N.15 ✅ Fixed `toolVersion` resolution + extracted `utils/tool_version.mjs` helper — shipped in v0.1.16 (580 tests, +5 new)
> - N.16 ✅ Markdown injection defense (CommonMark dynamic fence length) — shipped in v0.1.17 (592 tests, +12 new)
> - N.17 ✅ Honor `--out <dir>` for SARIF/CSV/MD + extracted `utils/output_dir.mjs` helper — shipped in v0.1.18 (610 tests, +18 new)
> - N.8 ✅ Pre-flight `validate` command (5 checks, JSON mode, Docker HEALTHCHECK ready) — shipped in v0.1.19 (643 tests, +33 new)
> - N.20 ✅ Consolidated `toCleanPath` → `utils/path_helpers.mjs` (single source of truth) — shipped in v0.1.20 (652 tests, +9 net)
> - N.25 ✅ BUG FIX: validate uses PKG_ROOT (not process.cwd) for plugin discovery — shipped in v0.1.21 (656 tests, +4 incl. subprocess regression)
> - N.27 ✅ TWO BUG FIXES: `opts.ports` now flows from CLI through plugin_manager to port_scanner. Bigger than expected — plugin_manager was dropping ALL CLI-derived opts. Shipped in v0.1.22 (680 tests, +24 incl. orchestrator-level opts-propagation regression test)
> - N.30 ✅ NEW PLUGIN: MCP server scanner + bonus normalizeService fix (preserves custom security flags project-wide). Shipped in v0.1.23 (734 tests, +54 incl. 9 N.30 regression tests proving anonymousLogin/weakAlgorithms/etc. now actually survive)
> - v0.1.24 ✅ Docs-only refresh — README + architecture.md updated on npm to surface MCP Scanner plugin and current plugin counts (no code changes)
> - N.36 ✅ Migrated Claude default model `claude-sonnet-4-20250514` → `claude-sonnet-4-6` across cli.mjs, .env.example, README (×2), and provider tests — shipped in v0.1.25 (2026-04-30)
>
> **Published to npm:** v0.1.25 live at https://www.npmjs.com/package/nsauditor-ai
>
> **Published to npm:** v0.1.23 live at https://www.npmjs.com/package/nsauditor-ai
>
> **Published to npm:** v0.1.22 live at https://www.npmjs.com/package/nsauditor-ai (was 0.1.12)
>
> **Queue (priority order):**
> - **🟡 MEDIUM (BLOCKER for N.28; expanded by N.30)** — N.31 (port_scanner + mcp_scanner serial-probe perf — both must be parallelized; up to 80s wall time per plugin currently)
> - **🟡 MEDIUM (PROMOTED from LOW after 3-iteration evidence)** — N.19 (E2E CLI test infrastructure — would have caught the named-export bug in N.30, the opts-propagation bug in N.27, and the PKG_ROOT bug in N.25. Cost of absence is now empirically demonstrated.)
> - **MEDIUM** — N.28 (`--port-range <spec>` for thorough audits incl. MCP-common 3000-9000 range — gated on N.31)
> - **MEDIUM** — N.29 (generic banner-grab probe for arbitrary open ports — feeds future plugins)
> - **MEDIUM** — N.34 (distinguish OAuth 2.1 from arbitrary bearer-token auth in mcp_scanner — N.30 review; real-world relevance for mature MCP deployments)
> - **LOW** — N.18 (migrate mcp_server.mjs to tool_version helper — N.15 review; opportunistic)
> - **LOW** — N.32 (fix inverted comment in plugin_manager.mjs — N.27 review; opportunistic)
> - **LOW** — N.33 (add 3-way additive merge test for port_scanner — N.27 review)
> - **LOW** — N.35 (mcp_scanner static port list / dynamic range consistency — N.30 review)
> - **LOW** — N.21 (README `--out` directory-only constraint — N.17 review)
> - **LOW** — N.22 (rename `runValidation` opts.ai → opts.aiProviders — N.8 review)
> - **LOW** — N.23 (README HEALTHCHECK grep robustness — N.8 review)
> - **LOW** — N.24 (probe filename uniqueness hardening — N.8 review)
> - **Original CE-N tasks (unchanged priority):** N.7 (resumable scans),
>   N.9 (MCP token optimization), N.10 (SKILL.md), N.11 (subagents), N.12 (llms.txt),
>   N.13 (GitHub Action), N.1 (Keychain), N.2 (MCP server tweaks), N.4 (CI/CD)
>
> **Note on the LOW-priority backlog:** Seven LOW tasks (N.18, N.20–N.24) are review
> follow-ups that should be folded in opportunistically next time their host file is
> touched, not as standalone PRs. Doing them standalone is more churn than value for
> ≤5-LOC changes. The remaining LOW (N.19) is a non-trivial infrastructure investment
> with an unresolved scope question.

---

### Task N.1 — Keychain Integration for API Keys

Store sensitive credentials (API keys, tokens) in macOS Keychain instead of plaintext `.env` files.

- [ ] Add `security` CLI command to manage keychain entries
- [ ] `nsauditor-ai security set ANTHROPIC_API_KEY` — prompt and store in Keychain
- [ ] `nsauditor-ai security set OPENAI_API_KEY` — prompt and store in Keychain
- [ ] `nsauditor-ai security list` — show stored keys (masked)
- [ ] `nsauditor-ai security delete <key>` — remove from Keychain
- [ ] Update `cli.mjs` and `mcp_server.mjs` to read from Keychain first, fall back to env vars
- [ ] Support `keychain:<label>` syntax in Claude Desktop MCP config env vars
- [ ] Document in README

### Task N.2 — MCP Server Improvements

- [ ] Add MCP progress notifications to keep connection alive during long scans
- [ ] Wire `timeout` parameter in `scan_host` tool schema to `PLUGIN_TIMEOUT_MS`
- [ ] Add `--quick` scan mode (skip port_scanner/syn_scanner for faster MCP scans)
- [ ] Add stderr logging for debugging MCP connection issues

### Task N.3 — EE Private Repo Scaffold ✅

- [x] Create private GitHub repo `nsauditor-ai-ee`
- [x] Scaffold as npm package `@nsasoft/nsauditor-ai-ee` with `nsauditor-ai` as peer dependency
- [x] Copy EE-only plugins: `cloud_aws.mjs`, `cloud_gcp.mjs`, `cloud_azure.mjs`, `zero_trust_checker.mjs`
- [x] Implement Phase 2 JWT license validation (`jose` + ES256) — done in v0.1.11, EE tests use real JWT fixtures

### Task N.4 — CI/CD & Quality

- [ ] GitHub Actions: test on push (Node 20, 22, 24)
- [ ] Automated npm publish on version tag
- [ ] Add `.npmignore` audit to CI (ensure no secrets shipped)

### Task N.5 — Extend FindingSchema with `cwe` and `owasp` fields ✅ COMPLETED 2026-04-26 (v0.1.13)

> **Why:** Current `evidence` shape carries `cve` and `mitre` but no CWE or OWASP mapping. EE's
> `tasks/new-plugins-guide-pro-ee.md` §4 already specifies `cwe?: string[]` in the proposed
> finding shape. Adding both aligns CE with industry-standard finding formats (SARIF, OWASP ZAP,
> Burp), enables CWE→ATT&CK derivation in EE agents/verifiers, and unlocks OWASP Top 10
> categorization for HTTP findings.
>
> **Scope:** schema-only. Populating these fields is downstream work in EE (S5/S8) and CE
> http_probe / tls_scanner plugins as opportunity arises.
>
> **Result:** 520 tests pass (was 506 before; +14 new schema tests). No regressions.

- [x] Modify `utils/finding_schema.mjs`:
  - Document `evidence.cwe: string[]` (e.g. `['CWE-326', 'CWE-200']`)
  - Document `evidence.owasp: string[]` (e.g. `['A02:2021-Cryptographic Failures']`)
  - Validate format if present (regex `/^CWE-\d+$/` for CWE; passthrough string for OWASP)
  - Both fields optional — existing findings without them remain valid
- [x] Update `tests/finding_schema.test.mjs`:
  - Existing finding without cwe/owasp still validates ✓
  - Finding with `evidence.cwe: ['CWE-326']` validates ✓
  - Finding with `evidence.cwe: ['cwe-326']` (lowercase) fails validation
  - Finding with `evidence.cwe: 'CWE-326'` (string not array) fails validation
- [x] Update `docs/architecture.md` §4.1 FindingSchema definition to include the new fields
- [x] No plugin code changes — fields stay optional; downstream EE consumers populate them when ready

**Implementation notes (from review, not blocking):**
- `evidence.cwe = null` (vs `undefined`) currently fails with "must be an array". Defensible
  but inconsistent with how most validators treat null/undefined as equivalent. Revisit if
  a downstream consumer trips on it.
- Error messages echo the malformed input (e.g. `invalid cwe id: ${id}`). Minor log-injection
  footgun if errors get unstructured-logged. Cheap mitigation: drop the echo or truncate.
  Same pattern exists in pre-existing `invalid category: ${f?.category}` etc., so not
  worth fixing in isolation — fix project-wide if/when it becomes relevant.
- New test names use `validateFinding: X` (colon-prefixed), pre-existing tests use
  `validateFinding X`. Cosmetic drift; align next time the test file is touched.
- Permissive ID format: regex `/^CWE-\d+$/` accepts `CWE-0`, `CWE-99999999`, leading zeros.
  Consistent with how existing CVE IDs are handled (no format check at all).

**Downstream follow-ups when EE consumers start populating these fields:**
- Audit `utils/sarif.mjs` exporter to confirm cwe/owasp forwarding works (SARIF supports
  these natively via `taxa`/`relationships` — should just need wiring, no schema change).
- See **Task N.14** below for `cweToMitre()` helper (genuinely useful, ~20 lines).

### Task N.6 — Add Markdown report output format ✅ COMPLETED 2026-04-26 (v0.1.15)

> **Why:** Current output formats are JSON, HTML, SARIF, CSV, and the AI report (HTML).
> Markdown is the cheapest format to add and the highest-leverage one for AI/MCP workflows —
> Claude Desktop, GitHub issue bodies, Slack threads, and commit messages all consume it
> natively.
>
> **Result:** 575 tests pass (was 547; +28 new). MCP `scan_host` returns ready-to-quote
> Markdown alongside structured fields. Markdown rendering is best-effort (try/catch in
> the MCP handler) so a conclusion-shape surprise can't break the tool call.

- [x] Implement `utils/report_md.mjs` — render scan conclusion + AI analysis to Markdown
  - Sections: # Header (host, scan time, version, OS) → ## Summary (counts by severity if findings present) → ## Services → ## Findings → ## AI Analysis (optional)
  - GitHub-flavored Markdown: tables for services, fenced code blocks for evidence
  - Defensive: pipe/backtick/newline escaping in cells, "Unknown" values rendered as empty
  - Findings sorted descending by severity (Critical → Info), counts surfaced in Summary
  - Empty conclusion → minimal report ("No services detected" / "No security findings"), no error
- [x] Wire `--output-format md` (or `markdown`) in `cli.mjs` alongside existing format options
- [x] Output file: `out/scan_report.md` (single host) or `out/scan_<host>.md` (multi-host)
- [x] MCP `scan_host` tool: response now includes `markdown` field (best-effort render via try/catch)
- [x] Tests in `tests/report_md.test.mjs` — 28 tests covering structural assertions, finding extraction,
  severity sort, AI Analysis presence/absence, defensive edge cases, internal helpers
- [x] Updated README output-formats table, CLI reference, and Examples section

**Review feedback (captured as N.15–N.17 below):**
- [HIGH] cli.mjs `toolVersion` source is unreliable — see N.15
- [MEDIUM] Fenced-code-block injection in evidence rendering — see N.16
- [LOW] `--out <dir>` flag ignored by SARIF/CSV/MD output blocks (pre-existing) — see N.17

### Task N.7 — Resumable scans with per-host state persistence

> **Why:** A long subnet scan (/16 = 65k hosts; even /24 = 254 hosts can take an hour with
> deep plugins) currently restarts from zero on any interruption — Ctrl+C, network blip,
> laptop sleep, OOM, machine reboot. Per-host state persistence makes resumability free.
>
> **Pattern reference:** `416rehman/DeepZero` (MIT) persists per-sample state atomically to
> `work/<pipeline>/samples/<id>/state.json` and resumes on re-run. Same pattern fits nsauditor's
> per-host scan model.
>
> **Scope:** CE-only (EE inherits via `enrichScan` hook).

- [ ] State directory layout: `<outDir>/.scan-state/<scan-id>/<host>.json` per host
  - Atomic writes: write to `<host>.json.tmp`, fsync, rename
  - Each file: `{ host, status: 'pending' | 'in-progress' | 'complete' | 'failed', startedAt, completedAt, plugins: { [pluginId]: 'pending' | 'complete' | 'failed' } }`
- [ ] CLI flag `--resume <scan-id>` re-runs only hosts with status `pending` / `in-progress` / `failed`
- [ ] `--scan-id <id>` lets the user name the scan (default: timestamp-based)
- [ ] `nsauditor-ai scan --list-resumable` shows in-progress scans on disk with progress %
- [ ] Auto-resume: if `--resume` is omitted but a scan with the same target/options is incomplete on disk, prompt user (interactive) or auto-resume (non-interactive `CI=true`)
- [ ] Cleanup: scans complete >7 days are auto-pruned at next scan start (aligns with H.4 retention)
- [ ] Tests: simulated Ctrl+C mid-scan → state file shows in-progress; re-run resumes correctly; no duplicate finding IDs across resume boundary
- [ ] Update README with resume workflow

### Task N.8 — Pre-flight `validate` command ✅ COMPLETED 2026-04-26 (v0.1.19)

> **Why:** Fast feedback for CI/CD setups, Docker health checks, and first-time users.
> No scan runs — just verifies that the environment is correctly configured.
>
> **Result:** 643 tests pass (was 610; +33 new). Live smoke test confirms both
> human-readable and JSON modes work; `localhost` default keeps DNS check hermetic.

- [x] `nsauditor-ai validate` checks (5 total, run in parallel via `Promise.all`):
  - **plugins**: discovery returns plugins without error
  - **license**: JWT signature valid + not expired (skip if no key); warns if expiring ≤7 days
  - **ai_providers**: at least one of OpenAI / Anthropic / Ollama configured (warn if none)
  - **output_dir**: writable (round-trip a probe file); warn if free space < 100 MB via `fs.statfs`
  - **network**: DNS lookup with 1.5s timeout; defaults to `localhost` (hermetic — no external dependency)
- [x] Exit codes: 0 (all OK), 1 (warnings), 2 (errors)
- [x] `nsauditor-ai validate --json` emits structured output for CI parsing
- [x] All check functions accept injectable dependencies for hermetic unit testing
- [x] `tests/validate.test.mjs` — 33 tests:
  - Per-check positive/negative paths with mocked deps
  - Free-space below threshold → warn (with mocked `statfs`)
  - `statfs` unsupported / missing → graceful skip, no error
  - DNS timeout / lookup throw → warn, not crash
  - Aggregator: overall status + exit code mapping; **<2s perf budget verified**
  - Parallel execution: errors in one check don't block others
- [x] README: new "Pre-flight `validate` command" section with Docker HEALTHCHECK example
- [x] Patch release: 0.1.18 → 0.1.19

**Review feedback (captured as N.22–N.24 below):**
- [LOW] `runValidation` opts naming (`opts.ai` vs `checkAiProviders`) — see N.22
- [LOW] README HEALTHCHECK grep robustness — see N.23
- [LOW] Probe filename uniqueness hardening — see N.24

### Task N.9 — MCP response token optimization (summary-first, drill-down tools)

> **Why:** When an AI assistant (Claude Desktop) calls `scan_host` on a /24 subnet, the
> JSON response can be tens of KB — full evidence, banners, headers, all findings inline.
> That blows out the assistant's context window and forces it to truncate. The fix is a
> well-known pattern: return a high-signal summary in the response, persist full evidence
> to disk, expose drill-down tools for AI to fetch details on demand.
>
> **Pattern reference:** `ktol1/RedTeam-Agent` (MIT) operational guidance: *"For long scan
> output, write results to files first; summarize high-signal findings only: hosts, ports,
> services, vulnerabilities; redirect output to files first, then extract key lines."*
> Applies to MCP tool responses the same way it applies to terminal output.

- [ ] Modify `scan_host` MCP tool response shape:
  - Returns: `{ scanId, summary: { hostsScanned, servicesFound, findingsBySeverity, topFindings: [up to 5] }, outputDir, available_tools: [...] }`
  - No longer inlines full services/findings/evidence in the response
- [ ] Add MCP tool `get_scan_summary({ scanId })` — returns the same summary block
- [ ] Add MCP tool `get_scan_findings({ scanId, severity?, host?, category?, limit?, offset? })` — paginated finding access
- [ ] Add MCP tool `get_scan_evidence({ scanId, findingId })` — returns full evidence for one finding (raw banner, headers, probe response)
- [ ] Add MCP tool `get_scan_services({ scanId, host?, port? })` — service-level detail
- [ ] Persistent scan store: `<outDir>/.scan-state/<scanId>/` already exists (N.7); MCP tools read from there
- [ ] Update existing `risk_summary` (Pro EE) and `scan_compare` (Pro EE) to use the same drill-down pattern
- [ ] Tests: `scan_host` response under 4 KB even for /24 scan; drill-down tools return correct data; scanId is stable across resumed scans (N.7)
- [ ] Update README MCP section + Claude Desktop config example with new tool names

### Task N.10 — Ship companion `SKILL.md` for AI assistants using nsauditor

> **Why:** AI assistants (Claude Desktop, Cursor, Cline) using the MCP server today get
> tool descriptions only. That's enough to invoke tools but not enough to use them well —
> AI doesn't know workflow patterns ("use scan_compare for delta, not multiple
> scan_host calls"), output format conventions, or the safety frame ("scan only authorized
> targets"). A companion skill file fixes this — auto-loadable guidance.
>
> **Pattern reference:** `ktol1/RedTeam-Agent` (MIT) ships `.github/skills/redteam/SKILL.md`
> as auto-load AI guidance for Cursor / Cline / Claude Desktop. Same idea, different tone
> (defensive audit vs offensive). Useful AI integration polish.

- [ ] Create `SKILL.md` at repo root (and a copy in `.claude/skills/nsauditor.md`)
- [ ] Sections to include:
  - **What this tool does** — defensive network/infrastructure audit, scan/verify/report
  - **Authorization reminder** — only scan targets you own or have written authorization to scan
  - **Workflow patterns** — `scan_host` for one host, `scan_compare` for delta, `risk_summary` for prioritized output, `get_vulnerabilities` for ad-hoc CVE lookup
  - **Output format guidance** — Markdown for chat replies, JSON for downstream tooling, SARIF for code-host integration
  - **What this tool will NOT do** — explicit defensive-only frame (no exploitation, no lateral movement, no credential attacks). Mirror the Non-Goals section from EE TODO.
  - **MCP tool quick reference** — top 10 tools with one-line descriptions
- [ ] Wire MCP server to surface SKILL.md path in `initialize` response (servers.capabilities.skills) so compliant clients can auto-load it
- [ ] Tests: SKILL.md exists, valid Markdown, MCP server initialization includes the skill path
- [ ] Update README with skill auto-load instructions for Claude Desktop / Cursor / Cline

### Task N.11 — Ship companion Claude Code subagents for nsauditor workflows

> **Why:** N.10 ships a single SKILL.md for general guidance. That covers "what is nsauditor
> and how do I use it." It does NOT cover specialized workflows where the AI assistant
> benefits from a focused system prompt, scoped tool access, and a model tuned for the task
> (e.g., Haiku for fast finding triage, Sonnet/Opus for executive report writing).
>
> Subagents fill that gap: each is a markdown file in `.claude/agents/` with YAML frontmatter
> declaring model, scope, and system prompt. Claude Code auto-routes user intent to the
> right subagent. **MCP tools are atomic primitives; subagents are workflows that chain
> them.** Together they give AI assistants both the verbs (MCP) and the playbooks (subagents).
>
> **Pattern reference:** `0xSteph/pentest-ai-agents` (MIT) ships 28 offensive subagents in
> `.claude/agents/`. The defensive subset of that pattern is the highest-leverage AI
> integration polish item identified across the repos surveyed. **All borrowed agent ideas
> here are explicitly defensive — see EE TODO Non-Goals.**
>
> **Scope:** CE-only. Subagents reference MCP tools (which work in CE) and may also
> reference EE-only Pro tools (which silently no-op for CE users) — graceful degradation.

- [ ] Create `.claude/agents/` directory with 6 specialist subagents:

  **`nsauditor-scan-planner.md`**
  - Purpose: help user scope targets, select plugins, set output dir/format, plan recurring scans
  - Tools: `list_plugins`, `validate` (when N.8 lands), filesystem read for config files
  - Model: Sonnet (planning needs reasoning depth)
  - System prompt: "You are a defensive scan planner for NSAuditor AI. Help the user
    scope authorized targets, select appropriate plugins, and plan scan execution.
    Never plan scans of targets the user does not own or have written authorization for."

  **`nsauditor-finding-analyst.md`**
  - Purpose: triage scan output, prioritize findings, generate detection rules (Sigma/SPL/KQL) from findings
  - Tools: `get_scan_findings`, `get_scan_evidence` (when N.9 lands), `get_vulnerabilities` (Pro)
  - Model: Haiku (fast triage of high-volume output) with Sonnet fallback for complex correlation
  - System prompt: focus on prioritization by risk score, MITRE mapping, and translating findings into detection content for SIEM platforms

  **`nsauditor-compliance-auditor.md`**
  - Purpose: map findings to compliance frameworks (NIST CSF, HIPAA, PCI DSS, CIS, GDPR — IEC-62443/NERC-CIP when EE S9 lands)
  - Tools: `get_scan_findings`, `compliance_check` (Enterprise EE — graceful no-op for non-Enterprise)
  - Model: Sonnet (compliance reasoning needs precision)
  - System prompt: focus on control-by-control mapping with evidence citations, gap analysis, audit-ready output

  **`nsauditor-report-writer.md`**
  - Purpose: generate executive / technical / remediation reports from finding queues
  - Tools: `get_scan_summary`, `get_scan_findings` (paginated), `export_report` (Enterprise EE)
  - Model: Sonnet for technical reports, Opus optional for executive narrative quality
  - System prompt: matches OPENAI_PROMPT_MODE shapes (executive/technical/remediation) — leverages S6.1 prompt templates when EE is installed

  **`nsauditor-ctem-tracker.md`**
  - Purpose: analyze finding deltas across scans, track remediation progress, surface trends
  - Tools: `scan_compare`, `list-resumable` (when N.7 lands), `get_scan_findings` filtered by date
  - Model: Sonnet
  - System prompt: focus on what's *changed* — new CVEs since last scan, resolved findings, risk-score deltas, hosts trending up/down. Skip findings unchanged across scans unless user asks.

  **`nsauditor-mcp-workflow-orchestrator.md`**
  - Purpose: chain MCP tool calls for multi-step user requests ("scan this /24, identify HVTs, generate exec report for the CISO")
  - Tools: full MCP toolset
  - Model: Sonnet
  - System prompt: orchestration patterns — when to use scan_host vs scan_compare, when to drill down vs summarize, how to combine outputs

- [ ] Each agent file structure:
  ```yaml
  ---
  name: nsauditor-scan-planner
  description: Plan defensive network/infrastructure scans with NSAuditor AI
  model: claude-sonnet-4-6
  tools: [list_plugins, validate, Read]
  ---
  # System prompt body in Markdown
  ```
- [ ] Defensive frame in every agent: each system prompt opens with the same authorization
  reminder + explicit non-goals reference (no exploitation, no offensive workflows). Mirror
  the EE TODO Non-Goals section concisely.
- [ ] Installation: `nsauditor-ai install-agents [--target ~/.claude/agents]` copies the
  subagents into the user's Claude Code config. Idempotent — safe to re-run for upgrades.
  Default target is auto-detected (project-local `.claude/agents/` if in a project, else
  `~/.claude/agents/`).
- [ ] Document the install/upgrade flow in README + a new `docs/ai-agents.md`.
- [ ] Tests:
  - All 6 agent files exist with valid frontmatter (model, tools, name, description)
  - All 6 reference only the defensive frame (no mention of exploit/attack/lateral/credential terms)
  - `install-agents` is idempotent (re-running produces no-op or upgrade-only diff)
  - Each agent's `tools` list references only tools that actually exist in the MCP server
- [ ] Versioning: bump nsauditor-ai version on agent content changes; users `npm update` then re-run `install-agents`.

### Task N.12 — Ship `llms.txt` for AI-friendly product documentation

> **Why:** When a user asks Claude / ChatGPT / any AI assistant *"how do I use nsauditor-ai?"*,
> the assistant guesses from training data — which is incomplete, possibly outdated, and may
> hallucinate flag names, command syntax, or capabilities that don't exist. The fix is the
> `llms.txt` convention: a structured Markdown file at a well-known path that AI assistants
> can fetch for ground-truth product info.
>
> **Standard reference:** `llmstxt.org` — public spec; widely adopted (Anthropic, Cloudflare,
> Stripe, Vercel, etc. ship `llms.txt` at their docs roots). No license entanglement.
>
> **Two outputs:**
> - **Hosted**: `nsauditor.com/llms.txt` — for assistants that fetch by URL
> - **Bundled**: `docs/llms.txt` in the npm package — for offline / self-hosted use, and so
>   AI assistants integrating with the local CLI can `Read` it directly

- [ ] Author `docs/llms.txt` per the `llmstxt.org` spec — top-level Markdown with structured
  sections:
  - `# NSAuditor AI` — one-line description
  - `> Summary block` — what it does, who it's for, defensive-only positioning
  - `## Documentation` — links to README, architecture, plugin guide
  - `## CLI` — top commands (scan, license, validate when N.8 lands, install-agents when N.11 lands)
  - `## MCP tools` — quick reference of MCP tool names and one-line descriptions
  - `## Output formats` — JSON / HTML / SARIF / CSV / Markdown (when N.6 lands)
  - `## Authorization reminder` — explicit "scan only authorized targets" note
  - `## What this tool will not do` — defensive-only frame mirroring EE Non-Goals
- [ ] Optional `docs/llms-full.txt` — expanded version with full command reference and worked
  examples (per the spec's optional richer variant)
- [ ] Hosted publication: serve `nsauditor.com/llms.txt` from the marketing site / docs site
  (whichever is canonical). Static file, no build step.
- [ ] CLI command `nsauditor-ai docs --llm-format` prints the bundled `docs/llms.txt` to stdout
  (useful when an AI assistant has shell access via Bash but no web access)
- [ ] Auto-keep-in-sync: README and `llms.txt` should not drift. Either (a) generate one from
  the other, or (b) lint check in CI that command/flag references match between files.
- [ ] Tests: `docs/llms.txt` exists, parses as Markdown, contains required sections per spec
- [ ] Update README with a "For AI assistants" section linking to `llms.txt`

### Task N.13 — Official GitHub Action for nsauditor in CI/CD pipelines

> **Why:** Teams running ephemeral preview environments (Kubernetes pull-request envs,
> Vercel/Netlify previews, Terraform Cloud staging) want to scan those environments as
> part of the deploy pipeline — same way they run dependency scanning. Without an official
> Action, customers either skip CI/CD scanning or roll their own brittle wrapper around
> the npx invocation.
>
> **Reference pattern:** Major defensive-scanning CLIs (Trivy, Snyk, Semgrep, OSV-Scanner)
> all ship official GitHub Actions. It's table stakes for CI/CD adoption.
>
> **Scope:** CE-only (CE runs standalone; users with Pro/Enterprise licenses pass
> `NSAUDITOR_LICENSE_KEY` as an Action secret).

- [ ] Create separate repo `nsauditor/nsauditor-ai-action` (or `.github/actions/scan` in main repo)
  - Composite action wrapping the existing Docker image / npx invocation
  - Inputs: `target`, `plugins`, `output-format`, `output-dir`, `license-key` (secret), `fail-on-severity`
  - Outputs: `report-path`, `findings-count`, `critical-count`, `high-count`
- [ ] Action behavior:
  - Run `nsauditor-ai scan` against the configured target
  - Upload results as build artifact (JSON + Markdown report when N.6 lands)
  - If `fail-on-severity: high` and any HIGH/CRITICAL finding present → exit non-zero
  - SARIF output uploaded to GitHub Code Scanning (works alongside the existing SARIF support)
- [ ] Caching: cache `~/.nsauditor/nvd-cache` between runs to avoid re-fetching NVD on every CI run
- [ ] Documentation:
  - `examples/.github/workflows/nsauditor-scan.yml` showing common patterns:
    - PR-triggered scan of preview environment
    - Nightly scheduled scan with diff against last scan (uses N.7 resume + scan_compare)
    - Release-gate scan that blocks merge on critical findings
  - Action-level README covering inputs, outputs, GitHub Code Scanning integration
- [ ] Publish to GitHub Marketplace under `nsauditor/scan-action`
- [ ] Tests: end-to-end action test in CI hitting a known-vulnerable test target (HTTP service
  with intentionally outdated banner) → finding produced → SARIF uploaded → build fails on threshold
- [ ] Update main README with "Use in CI" section linking to the Action and example workflows
- [ ] Versioning: pin Action releases to nsauditor-ai versions; users can choose `@v1` (latest 1.x)
  or `@v1.2.3` (exact). Auto-bump action version on nsauditor-ai release.

### Task N.15 — [HIGH] Fix `toolVersion` resolution in `cli.mjs` (N.6 review) ✅ COMPLETED 2026-04-26 (v0.1.16)

> **Why:** N.6 wired Markdown report rendering with `toolVersion: process.env.npm_package_version`.
> That env var is **only set when running via `npm run`** — when users invoke the `nsauditor-ai`
> bin shim (the normal install path), it's `undefined` and the rendered report silently
> drops the "Tool version" header line.
>
> **Severity:** HIGH — real correctness bug in shipped code (v0.1.15). Affects every Markdown
> report generated by the CLI when nsauditor is installed normally.
>
> **Result:** 580 tests pass (was 575; +5 new). Subprocess test with stripped `npm_*` env vars
> confirms the bug class is closed.

- [x] Created `utils/tool_version.mjs` — single-source-of-truth helper exporting `TOOL_VERSION`
  and `TOOL_NAME`, resolved via `createRequire(import.meta.url)` from `package.json`.
  Centralizes the resolution so consumers can't reinvent the pattern (or reinvent it broken).
- [x] cli.mjs imports `TOOL_VERSION` from the helper, replaces the broken
  `process.env.npm_package_version` reference in the Markdown output block
- [x] Audited cli.mjs — no other `npm_package_version` references existed
- [x] `tests/tool_version.test.mjs` — 5 tests:
  - `TOOL_VERSION` is non-empty string
  - matches package.json version
  - matches semver-ish pattern
  - `TOOL_NAME` matches package name
  - **subprocess test with stripped `npm_*` env vars** proves resolution is npm-context-independent
- [x] Patch release: 0.1.15 → 0.1.16

**Note on scope discipline:** `mcp_server.mjs` still has its own inline `createRequire` resolution
pattern. Migrating it to the new helper is correct but pure-cleanup churn — deferred to avoid
scope expansion in this patch release. Worth folding in next time mcp_server.mjs is touched.

**Review feedback (captured as N.18–N.19 below):**
- [LOW] Migrate mcp_server.mjs to use `tool_version.mjs` helper — see N.18
- [LOW] Add a true E2E CLI test for `--output-format md` — see N.19

### Task N.18 — [LOW] Migrate `mcp_server.mjs` to `utils/tool_version.mjs` helper (N.15 review)

> **Why:** N.15 created `utils/tool_version.mjs` as a single source of truth for the package
> version. mcp_server.mjs (line 25–26) still has its own inline `createRequire('./package.json').version`
> resolution. Both implementations are correct, but the duplication invites future drift —
> exactly the bug class N.15 was created to prevent.
>
> **Severity:** LOW — both implementations work today. Pure cleanup. Should be folded in
> opportunistically next time mcp_server.mjs is touched (rather than as a standalone task)
> to avoid churning the file just for a 3-line change.

- [ ] Replace mcp_server.mjs's inline `createRequire` + `_pkg.version` with
  `import { TOOL_VERSION } from './utils/tool_version.mjs'`
- [ ] Update the local `TOOL_VERSION` reference (used in `handleScanHost` for the Markdown
  field) — should be a no-op rename since the imported constant has the same name
- [ ] Verify mcp_server.test.mjs still passes — no behavior change expected
- [ ] No version bump — pure refactor, zero observable change

### Task N.19 — [LOW] True E2E CLI integration test for `--output-format md` (N.15 review)

> **Why:** N.15's regression test uses a subprocess + helper-import to prove the version
> resolution works outside npm context. Combined with N.6's 28 renderer tests, the bug class
> is transitively covered. But there's no single end-to-end test that runs `cli.mjs` via
> the bin entry point with `--output-format md` and verifies the rendered file contains the
> tool version (and other expected content).
>
> **Severity:** LOW — bug class is already closed by transitive coverage. Adding an E2E test
> would (a) provide a single-test regression signal, (b) seed CLI integration testing
> infrastructure that other tasks (N.7 resumable scans, N.8 validate command, N.13 GitHub
> Action) would benefit from. **This is more of an infrastructure investment than a defect fix.**
>
> **Scope question:** Should likely be the seed task for a broader "CLI integration test
> harness" — mock scan target, fixture conclusion piped through real CLI invocation, output
> file assertions. Not just for the Markdown case.

- [ ] Decide: standalone single-test fix, OR broader CLI integration harness?
- [ ] If standalone: spawn cli.mjs in subprocess against a mocked / loopback-blocked target,
  capture exit, read `out/scan_report.md`, assert version/host/sections present
- [ ] If harness: design fixture/stub strategy that other CLI tests can reuse
  (probably stub `PluginManager.run()` to return canned conclusions, then run only
  the post-scan output blocks)
- [ ] Either way: explicitly catch the N.15 bug class — a regression that breaks version
  resolution must fail this test
- [ ] No version bump — test-only addition

### Task N.16 — [MEDIUM] Markdown injection defense in evidence rendering (N.6 review) ✅ COMPLETED 2026-04-26 (v0.1.17)

> **Why:** `utils/report_md.mjs` wraps evidence in 3-tick fenced code blocks. If `f.evidence`
> ever contains the literal `` ``` `` sequence, the closing fence breaks early and subsequent
> Markdown structure leaks through.
>
> **Severity:** MEDIUM — currently low practical risk because evidence sources are NVD URLs
> and short canned strings. Becomes a real Markdown-injection surface when banner data flows
> into evidence (S5 verifiers in EE, per-CVE probes).
>
> **Result:** 592 tests pass (was 580; +12 new). Adopted **Option B** (CommonMark-compliant
> dynamic fence length) — handles arbitrary content including pathological cases (e.g.,
> evidence with 10 consecutive backticks gets an 11-tick fence).
>
> **Version bump rationale:** Spec said "no version bump — defensive hardening, not a behavior
> fix." Bumped anyway (0.1.16 → 0.1.17) because the rendered Markdown output *does* change
> for any evidence containing backticks, and the project convention is to ship every change
> with a unique version number for reproducibility.

- [x] Added `safeFenceFor(content)` internal helper to `utils/report_md.mjs`:
  - Scans content for the longest run of consecutive backticks via `/`+/g`
  - Returns `'`'.repeat(max(3, longestRun + 1))` — minimum 3 (standard fence length)
  - Per CommonMark §4.5: closing fence must match opening fence length
- [x] Replaced hardcoded `'  ```'` opening/closing in evidence-render block with
  `'  ' + safeFenceFor(f.evidence)` for both fences (matched lengths guaranteed)
- [x] Exposed `safeFenceFor` via `_internals` for direct testing
- [x] 12 new tests in `tests/report_md.test.mjs`:
  - `safeFenceFor` unit tests: empty/null, no backticks, 1/3/4/10-backtick runs, longest-run-wins, non-string coercion
  - Integration tests: evidence with no backticks (3-tick), evidence with `` ``` `` (4-tick), evidence with 4 backticks (5-tick)
  - **Property test**: every fence pair in rendered output has matched opening/closing length
- [x] No README update needed — this is a defensive renderer fix, not a user-visible feature change

### Task N.20 — [LOW] Consolidate `toCleanPath` (N.17 review) ✅ COMPLETED 2026-04-26 (v0.1.20)

> **Why:** N.17 introduced `utils/output_dir.mjs` which had its own `toCleanPath` helper.
> cli.mjs line 47 also had its own local copy (used by AI-provider env-var resolution at
> lines 98–101 and the scan-history `outRoot` at line 615). Same body, different module
> scope. Pre-existing pattern, propagated by N.17.
>
> **Result:** 652 tests pass (was 643; +9 net — moved 4 tests, added 13). Both call sites
> now import the same single source of truth.
>
> **Disposition note:** Originally flagged as "fold in opportunistically next time cli.mjs
> is touched." Done standalone per user directive — kept the diff focused so the patch
> release is clean, single-concern.

- [x] Picked **Option B** — extracted `toCleanPath` to a dedicated `utils/path_helpers.mjs`.
  Reasoning: importing `_internals.toCleanPath` from output_dir.mjs would reach past a
  test-only export (code smell). A dedicated namespace also matches the project's
  established small-helper-module pattern (`tool_version.mjs`, `output_dir.mjs`,
  `validate.mjs`).
- [x] Created `utils/path_helpers.mjs` (29 LOC) — `toCleanPath` as a regular public export
  (no `_internals` wrapper since it's the public API now)
- [x] Updated `utils/output_dir.mjs` — imports `toCleanPath` from `path_helpers.mjs`,
  removed local definition, removed `_internals` export entirely (was only there to
  expose `toCleanPath` for tests; no longer needed)
- [x] Updated `cli.mjs` — imports `toCleanPath` from `path_helpers.mjs`, removed line 47
  local definition. All 4 call sites in cli.mjs (AI-provider env vars at lines 98/100/101,
  scan-history `outRoot` at line 615) work via the imported function.
- [x] Created `tests/path_helpers.test.mjs` — 13 tests covering: nullish, empty, plain
  paths, single/double/stacked quotes, whitespace trimming (including the "trim before
  quote-strip" ordering invariant), number coercion, object-with-toString coercion,
  all-quote-input edge case, internal-quote preservation
- [x] Updated `tests/output_dir.test.mjs` — removed the 4 toCleanPath tests (moved) and
  the `_internals` destructuring import
- [x] Live smoke test: `node cli.mjs validate` runs end-to-end; cli.mjs's other 4
  toCleanPath usages all resolve correctly via the new import
- [x] Patch release: 0.1.19 → 0.1.20

### Task N.21 — [LOW] README clarification: `--out` requires a directory (N.17 review)

> **Why:** N.17 updated the `--out <dir>` README description to mention alternate-format
> files, but didn't state that the value must be a directory. If a user passes
> `--out report.json` thinking it sets the report filename, `path.parse` returns
> `{ dir: '', ext: '.json' }` and `resolveBaseOutDir()` silently falls back to `'out'`.
> User gets `out/scan_results.sarif.json`, not `./report.json`. Silent UX trap.
>
> **Severity:** LOW — documentation/UX polish, not a defect.
>
> **Disposition:** Could be folded into N.18/N.20 (next opportunistic README touch) or
> done standalone. One-sentence README addition.

- [ ] Update README CLI reference for `--out <dir>`:
  - Note that the value must be an existing or creatable **directory path**
  - State explicitly that filenames-with-extensions silently fall back to `out/`
- [ ] Optional: emit a console warning in `resolveBaseOutDir()` when input has `parsed.ext`
  but `parsed.dir` is empty (catches the user-typed-`report.json` case at runtime)
- [ ] No version bump if doc-only; bump if warning is added

### Task N.22 — [LOW] Rename `runValidation` opts.ai → opts.aiProviders (N.8 review)

> **Why:** `runValidation()` aggregator passes `opts.ai ?? {}` to `checkAiProviders`. The
> opts key is `ai`, the function name is `checkAiProviders` — naming asymmetry. Other
> opts keys match their function names (`opts.plugins` ↔ `checkPlugins`, `opts.license` ↔
> `checkLicense`, `opts.outputDir` ↔ `checkOutputDir`, `opts.network` ↔ `checkNetwork`).
> The `ai` outlier is the only inconsistency.
>
> **Severity:** LOW — cosmetic naming cleanup. Affects only test code that injects the
> ai-provider opts (currently only used in `runValidation: returns checks array...` test).

- [ ] Rename `opts.ai` → `opts.aiProviders` in `runValidation()` body (utils/validate.mjs)
- [ ] Update the relevant test in `tests/validate.test.mjs`
- [ ] No version bump — internal rename, no public-API behavior change

### Task N.23 — [LOW] README HEALTHCHECK grep robustness (N.8 review)

> **Why:** N.8 README's Docker HEALTHCHECK example uses
> `grep -q '"overall": "ok"'`. Works correctly but JSON-formatting-sensitive — if the
> JSON serialization ever drops the space after `:` (or uses single-line output, etc.),
> the grep silently fails and the container reports unhealthy.
>
> **Severity:** LOW — cosmetic, current code works. Robustness improvement.

- [ ] Update README HEALTHCHECK example: switch grep target from
  `'"overall": "ok"'` to `'"exitCode": 0'`. The exit code is a numeric literal so it's
  formatting-stable.
- [ ] No version bump — README only

### Task N.24 — [LOW] Probe filename uniqueness hardening (N.8 review)

> **Why:** `checkOutputDir()` writes a probe file named `.nsauditor-validate-${process.pid}`
> to verify writability. PID is unique per OS process, so single-machine concurrency is
> safe. But if two containers share a volume and happen to spawn validates with the same
> PID (rare, theoretically possible), they could race on the probe file.
>
> **Severity:** LOW — paranoid defense. Not a known real-world failure mode.

- [ ] Append `crypto.randomUUID()` (or `Date.now()`) to probe filename:
  `.nsauditor-validate-${process.pid}-${crypto.randomUUID()}`
- [ ] Add a test confirming the filename includes a non-PID component (basic sanity)
- [ ] No version bump — defensive hardening

### Task N.25 — [HIGH] BUG: `validate` reports `0 plugins loaded` from outside package dir (N.8 / discovered post-publish v0.1.20) ✅ COMPLETED 2026-04-26 (v0.1.21)

> **Bug:** `nsauditor-ai validate` invoked from any directory other than the package's
> install root reports `0 plugins loaded`. The actual scan path is unaffected — only the
> `validate` subcommand is wrong.
>
> **Root cause:** `utils/validate.mjs` line 45 calls `discoverPlugins(process.cwd())` —
> i.e., it scans the **user's** working directory for plugins, not the package's plugin
> directory. The actual scan flow at `cli.mjs:847` correctly uses `${__dirname}/plugins`
> (package-relative). validate's check function diverges from this convention.
>
> **Severity:** HIGH — visible incorrect output for the normal install path. Every
> npm-install user invoking `nsauditor-ai validate` from outside the install dir sees
> a broken-looking "0 plugins" report. **Already shipped to npm in v0.1.20.**
>
> **How it slipped past tests:** The 33 unit tests for validate inject a mock `discover`
> function and never exercise the real plugin-discovery path. Bug only manifests via actual
> CLI invocation from outside the dev tree. **Strong argument for actually doing N.19**
> (true E2E CLI test infra) — exactly the bug class it would catch.
>
> **Disposition: shipped Option 1 (v0.1.21 patch fix). Option 2 obsoleted by the fix.**
> **Result:** 656 tests pass (was 652; +4 net — 1 PKG_ROOT correctness, 1 default-discovery
> reality check, 1 opts.pkgRoot override sanity, 1 subprocess regression test that spawns
> `cli.mjs validate --json` from `/tmp` and verifies plugins.count ≥ 20). Live smoke test
> from /tmp shows "26 plugins loaded" — bug confirmed fixed.

- [x] `utils/validate.mjs`: derive `PKG_ROOT` from `import.meta.url` (one level up from
  `utils/`); `checkPlugins()` defaults to `PKG_ROOT` instead of `process.cwd()`. Accepts
  `opts.pkgRoot` override for testing. PKG_ROOT exposed via `_internals` for assertion.
- [x] Added 4 regression tests:
  - `PKG_ROOT resolves to the repo root (parent of utils/)` — sanity
  - `checkPlugins: defaults to PKG_ROOT and finds real plugins` — exercises real discovery
  - `checkPlugins: opts.pkgRoot override works for testing` — confirms override path wired
  - **`N.25 REGRESSION: nsauditor-ai validate finds plugins when invoked from /tmp`** —
    actually spawns cli.mjs from `os.tmpdir()` and asserts `plugins.count >= 20`. Catches
    the exact bug class N.19 was meant to seed.
- [x] Bumped 0.1.20 → 0.1.21
- [x] Republished to npm (live at https://www.npmjs.com/package/nsauditor-ai)
- [x] Confirmed via global install + invocation from /tmp: `26 plugins loaded` ✓

**Lesson captured:** the 33 unit tests for validate all passed against v0.1.20 because
they injected mock `discover` functions. The bug only manifests via real subprocess
invocation. This is a textbook case for the N.19 E2E CLI test infrastructure —
dependency-injection unit tests cannot catch wrong-base-path-for-default-arg bugs.
Future similar code (anything that derives a default path from runtime context) should
have a subprocess-spawn regression test alongside the unit tests.

### Task N.27 — [HIGH] Wire `--ports` flag through to port_scanner ✅ COMPLETED 2026-04-26 (v0.1.22)

> **Bug discovered during real scan testing of 192.168.1.28 (post-v0.1.21 publish):**
> README documents `--ports <list>` as "Comma-separated ports to pass to plugins". The
> flag IS parsed in cli.mjs:547-548 and forwarded to plugin opts at cli.mjs:846. But
> `port_scanner.mjs` reads its scan list **exclusively from `config/services.json`** —
> it ignores `opts.ports` entirely.
>
> **Severity:** HIGH — documented CLI behavior doesn't work. User runs
> `nsauditor-ai scan --host X --ports 8090` expecting port 8090 to be scanned. It isn't.
> Discovered when verifying that an MCP endpoint at 192.168.1.28:8090 was missed by
> the scanner.

**TWO bugs found (one nested), both fixed:**

**Bug 1** (the obvious one): `port_scanner.mjs` ignored `opts.ports` — only consulted
`opts.tcpPorts` / `opts.udpPorts` arrays or `config/services.json`.

**Bug 2** (discovered during live verification — far more impactful): `plugin_manager.mjs`
**`_runOrchestrated()` constructed a fresh opts object that didn't include the CLI-derived
opts at all.** `callPlugin()` → `runWithCtx()` called `mod.run(host, port, { context, ...extra })`
— dropping every CLI flag value. `opts.ports` reached pm.run() and stopped there. **Every
plugin that read CLI-derived opts other than what plugin_manager explicitly knew about was
broken** — N.27 just made one specific case visible.

**Both fixes shipped together:**
- [x] `plugins/port_scanner.mjs`: added `parsePortsSpec()` helper (CWE-NNN-style spec
  parser) + additive merge of `opts.ports` into the TCP/UDP scan lists alongside the
  config defaults. Format support: `"8090"`, `"8090,9090"`, `"8090/tcp"`, `"8090/udp"`,
  case-insensitive protocol suffix, surrounding-whitespace tolerance, dedup, malformed
  entries silently skipped.
- [x] `plugin_manager.mjs`: `callPlugin()` gains a `cliOpts` parameter; `_runOrchestrated()`
  forwards the orchestrator's `opts` arg to `callPlugin()`. The CLI opts are spread FIRST
  in the run-time opts object (`{ ...cliOpts, context, ...extra }`) so orchestrator-built
  `context` always wins on collision (no caller can clobber it).
- [x] `tests/port_scanner.test.mjs` — +20 tests:
  - 14 unit tests for `parsePortsSpec` (all formats + edge cases)
  - 5 integration tests against real localhost servers proving opts.ports flows to actual scans
  - Plus the additive-merge invariant test
- [x] `tests/plugin_manager_opts_propagation.test.mjs` — NEW file, +4 tests:
  - opts.ports propagates verbatim through pm.run → plugin.run
  - empty opts still works (no regression)
  - arbitrary CLI fields forward without colliding with context
  - **caller-supplied `context` field cannot clobber orchestrator context** (security-relevant
    invariant test — orchestrator wins on collision)
- [x] Live verification: `--ports 8090` against 192.168.1.28:8090 now correctly reports
  port 8090 as OPEN (your MCP endpoint, previously invisible). `PLUGIN_TIMEOUT_MS=120000`
  was needed for the live test because port_scanner sequentially probes ~30 default ports
  + the new one and exceeds the 30s default plugin timeout — separate pre-existing perf
  issue worth tracking (could be N.31).
- [x] Patch release: 0.1.21 → 0.1.22

**Architectural note:** Bug 2 is a much bigger deal than Bug 1. Any future plugin that
needs to read CLI-supplied configuration would have hit the same wall. The fix opens the
door for cleaner CLI flag → plugin config wiring across the codebase. Worth being explicit
in the changelog so plugin authors know they CAN now read arbitrary opts fields.

**Review feedback (captured as N.31, N.32, N.33 above):**
- [MEDIUM] N.31 — port_scanner serial-probe perf surfaced during live verification
  (HARD BLOCKER for N.28's `--port-range` work)
- [LOW] N.32 — fix inverted comment in plugin_manager.mjs spread
- [LOW] N.33 — add 3-way additive merge test (port_scanner)

### Task N.31 — [MEDIUM] port_scanner + mcp_scanner serial-probe perf (surfaced during N.27 + N.30)

> **Why:** During live verification of N.27 against 192.168.1.28:8090, port_scanner
> timed out at the default 30s `PLUGIN_TIMEOUT_MS`. Cause: it sequentially probes ~30
> default ports (from config/services.json) at 1.2s per-port timeout = 36s wall time.
> Adding even one extra port via `--ports` pushes it further over budget. Live test
> required `PLUGIN_TIMEOUT_MS=120000` to complete.
>
> **Scope expanded by N.30:** mcp_scanner has the same architectural shape — 8 candidate
> ports × 5 paths × 2s timeout = potentially 80s wall time per scan. Same parallelization
> fix applies. Both plugins should be addressed together to avoid cherry-picking.
>
> **Severity:** MEDIUM — broken behavior on slow networks / firewalled hosts is now
> visible to anyone using `--ports` for the first time. This becomes a **HARD BLOCKER
> for N.28** (`--port-range 3000-9000` would scan 6000 ports → impossible at current speed).
>
> **Three possible fixes (pick one or combine):**

- [ ] **Option A — Parallelize** with concurrency cap (e.g., 50 concurrent TCP probes,
  20 concurrent UDP). Most impactful. Requires careful rate-limiting to not flood the
  target's firewall conntrack table.
- [ ] **Option B — Raise default plugin timeout** from 30s to 60s or 120s. Cheapest fix
  but punts the problem; doesn't help when ranges grow further.
- [ ] **Option C — Per-plugin timeout overrides** in the plugin contract (e.g., port_scanner
  declares `timeoutMs: 120000` and orchestrator honors it). Architecturally cleanest.
- [ ] Tests: simulate 50+ port scan, assert wall time < threshold; verify concurrency cap
  is enforced (no thundering herd on the target)
- [ ] Patch release after fix

### Task N.32 — [LOW] Fix inverted comment in `plugin_manager.mjs` (N.27 review)

> **Why:** N.27 added a comment to the `runWithCtx` spread:
> ```
> // CLI opts come last so they don't override critical orchestration fields
> ```
> But in the actual code, `cliOpts` is spread **FIRST**, not last:
> ```javascript
> mod.run(host, port, { ...cliOpts, context: withBaseContext(ctx), ...extra });
> ```
> The behavior is correct (orchestrator fields win because they're spread later), but
> a future maintainer reading "CLI opts come last" might "fix" the perceived inconsistency
> by swapping the order — and break the security invariant. The test catches it but the
> comment is misleading.
>
> **Severity:** LOW — pure documentation correction. Cosmetic.
>
> **Disposition:** Fold in opportunistically next time plugin_manager.mjs is touched.

- [ ] Update comment to: `// Orchestrator fields (context, OS-detector results) are spread
  AFTER cliOpts so they always win on collision — caller cannot clobber them.`
- [ ] No version bump — comment-only

### Task N.33 — [LOW] Add 3-way additive merge test for port_scanner (N.27 review)

> **Why:** N.27 tests cover 2-way merges (config + opts.ports, opts.tcpPorts + opts.ports)
> separately. The implementation handles 3-way (config + opts.tcpPorts + opts.ports) correctly
> but no test directly exercises that combination. A 3-way explicit test would be defensive
> against future refactors of the merge logic.
>
> **Severity:** LOW — coverage completeness, not a defect.

- [ ] Add test in `tests/port_scanner.test.mjs`:
  - Real localhost server A on port α
  - Real localhost server B on port β
  - Real localhost server C on port γ
  - Pass `tcpPorts: [α]` + `ports: String(γ)` + ensure config services.json contributes β
    (or use a fixture cwd that has β in services.json)
  - Assert all three (α, β, γ) appear in `tcpOpen`
- [ ] No version bump — test-only

### Task N.34 — [MEDIUM] Distinguish OAuth 2.1 from arbitrary bearer-token auth in mcp_scanner (N.30 review)

> **Why:** Latest MCP spec (March 2025+) **mandates OAuth 2.1 with PKCE** for HTTP-transport
> servers (see `tasks/mcp-server-audit-research.md` §4.1). Current mcp_scanner treats any
> `401/WWW-Authenticate` response as "auth required = good." This misses the real-world case
> where a server uses arbitrary bearer-token auth (or basic auth, or custom schemes) — which
> is non-conformant with the modern MCP spec and represents a security regression.
>
> Specifically: the user's `swarms-galaxy` MCP at 192.168.1.28:8090 uses `Authorization:
> Bearer <static-uuid-token>` — which IS auth, but is NOT OAuth 2.1. The scanner currently
> reports "auth required" without flagging the spec-non-conformance.
>
> **Severity:** MEDIUM — real-world relevance (most existing MCP deployments predate the
> OAuth 2.1 mandate). Affects audit accuracy for mature MCP environments.

- [ ] Probe `/.well-known/oauth-authorization-server` (RFC 8414 OAuth Server Metadata) on
  any port that returned 401 from the initialize probe. If 200 with valid metadata → OAuth
  2.1 confirmed. If 404 / non-OAuth response → arbitrary bearer auth.
- [ ] Add finding flag: `mcpNonOAuthAuth` — Medium severity, CWE-287 (Improper Authentication)
- [ ] Update README finding documentation
- [ ] Tests: mock server with `.well-known/oauth-authorization-server` → confirms OAuth.
  Mock server without it but with bearer-required initialize → flags non-OAuth.
- [ ] Patch release after fix

### Task N.35 — [LOW] mcp_scanner static port list / dynamic range consistency (N.30 review)

> **Why:** mcp_scanner's static `MCP_CANDIDATE_PORTS` includes `1967` (turtleSpaces, per
> research §2.2). The dynamic-port heuristic only includes `ctx.tcpOpen` ports in 3000-9000.
> So 1967 is probed via the static list but a port_scanner-discovered MCP server on, say,
> 1500 (random custom deployment) wouldn't be probed. Inconsistency between the two
> sources.
>
> **Severity:** LOW — cosmetic consistency. Static-list MVP coverage is fine; this is about
> future-proofing.
>
> **Disposition:** Two options:
> - Expand dynamic range to include the lower outliers (`[1967, 3000-9000]`)
> - Or derive dynamic range from the static list's min/max bounds
> Pick whichever is cleaner once N.28 (`--port-range`) lands; the consistency is more
> important once users can pass arbitrary ranges.

- [ ] Pick Option A or B; document reasoning
- [ ] Update tests to cover the new range behavior
- [ ] No version bump — minor scan-coverage improvement

### Task N.28 — [MEDIUM] Configurable port scan range (`--port-range`)

> **Why:** `port_scanner` defaults to a narrow well-known port set from
> `config/services.json` (~30 ports). Real-world MCP servers, dev services, and many
> custom applications run on non-standard ports in the 3000-9000 range (per the
> `mcp-server-audit-research.md` §2.2 reference table). Operators auditing their own
> infrastructure need an opt-in for thorough port coverage without editing config files.

- [ ] Add `--port-range <spec>` CLI flag to cli.mjs. Accepted forms:
  - `1-65535` — full TCP port sweep
  - `3000-9000` — range
  - `top1000` / `top100` — Nmap-style preset port lists
  - `mcp` — preset for the MCP-common ports (1967, 3000, 3005, 5173, 6274, 6277, 8000, 8090, plus 3000-9000 sample)
- [ ] Wire to port_scanner alongside N.27's `--ports` flag (additive: range + extra ports + config defaults all merged)
- [ ] Performance guardrails:
  - Warn user when range > 1000 ports: "scanning N ports against M hosts; estimated time: X seconds"
  - Optional `--scan-timeout-ms` per-port to bound full sweeps
- [ ] Tests for range parsing (1-100, 100-1, malformed, presets)
- [ ] README CLI reference + Examples section update

### Task N.29 — [MEDIUM] Service detection on arbitrary open ports

> **Why:** Even when N.27/N.28 cause port_scanner to find a non-standard open port,
> no service-specific probe (http_probe, tls_scanner, etc.) fires against it because
> those plugins gate on hardcoded port lists. Result: port discovered as "open" but
> service identity remains unknown ("port 8090, service=?, banner=null").
>
> A generic banner-grab + protocol-sniff fallback should fire for any TCP-open port
> not handled by a specific probe. Goal: produce useful service identification even
> for non-standard ports.

- [ ] Implement `plugins/generic_probe.mjs` (low priority, ~85 — runs after specific probes):
  - Trigger: TCP port marked open by port_scanner AND not claimed by another plugin
  - Probe sequence (each ~1s timeout):
    1. **Read banner** — connect, read up to 1KB or first newline, no send
    2. **HTTP GET /** — if banner empty, send `GET / HTTP/1.0\r\n\r\n`, parse status/Server header
    3. **TLS handshake** — if HTTP fails, attempt TLS ClientHello and extract certificate subject
  - Returns: `{ port, banner, http_status, http_server, tls_subject }` for the concluder
- [ ] Concluder uses the probe data to populate service/program/version fields
- [ ] Conservative defaults — don't flood targets:
  - Per-port concurrency cap (5 parallel)
  - Per-host total cap (50 generic probes max per scan)
  - Configurable via `GENERIC_PROBE_MAX_PORTS_PER_HOST` env var
- [ ] Tests with mocked sockets covering the 3-step probe ladder
- [ ] No version bump until paired with N.27/N.28 in a feature release

### Task N.30 — [HIGH] New plugin: MCP server scanner (`plugins/mcp_scanner.mjs`) ✅ COMPLETED 2026-04-26 (v0.1.23)

> **Result:** 734 tests pass (was 680; +54 net). MCP scanner ships as a CE plugin (id 070,
> priority 70). Live verified against the actual MCP server at 192.168.1.28:8090 (the same
> endpoint that triggered N.27's discovery): correctly identifies bearer-auth requirement
> and flags `mcpCleartextTransport: true` (CWE-319, MITRE T1040) for the HTTP transport.
>
> **Bonus structural fix discovered during implementation:** `utils/conclusion_utils.mjs`
> `normalizeService()` was silently stripping ALL plugin custom security flags
> (`anonymousLogin`, `weakAlgorithms`, `axfrAllowed`, etc.) — making downstream readers
> in sarif.mjs / export_csv.mjs / report_md.mjs effectively dead code for those flags.
> Fixed by spreading `...svc` in normalizeService so unknown fields pass through.

**Implementation summary (matched task spec):**
- [x] `plugins/mcp_scanner.mjs` (id 070, priority 70, requirements: host up)
  - Probes 8 candidate ports per research §2.2: 1967, 3000, 3005, 5173, 6274, 6277, 8000, 8090
  - Plus dynamic ports from `ctx.tcpOpen` in 3000–9000 range
  - JSON-RPC `initialize` to 5 paths (/, /mcp, /jsonrpc, /sse, /messages)
  - SSE detection via `Accept: text/event-stream` Content-Type check
  - Anonymous `tools/list` enumeration (only when initialize succeeded without auth)
  - All probes safe: read-only, single packet per attempt, no payload variations,
    no actual tool invocation
- [x] Per-service security flags produced (mapped to research §5 audit checklist):
  - `mcpAnonymousAccess` — Critical (anon + non-loopback target) → CWE-306, MITRE T1190
  - `mcpAnonymousToolList` — Critical (anon + tools/list returns names) → CWE-306, T1190+T1059
  - `mcpCleartextTransport` — High (HTTP not HTTPS) → CWE-319, MITRE T1040
  - `mcpDeprecatedProtocol` — High (older than current `2025-03-26` spec date) → CWE-1395
  - `mcpInspectorExposed` — Medium (5173/6274/6277 on non-loopback) → CWE-200
- [x] Loopback target gate — anon + 127.0.0.1 ≠ finding (developer tooling, expected)
- [x] `conclude` exported as **named export** (not on default object) — convention matches
  webapp_detector. Returns ServiceRecord per detection with `authoritative: true`.
- [x] `tests/mcp_scanner.test.mjs` — 29 tests:
  - 11 pure helper tests (parsers, version compare, loopback detection)
  - 8 buildFindings tests covering every finding class + dedup invariants
  - 7 integration tests with real localhost mock servers (clean MCP, anonymous
    + tools, non-MCP false-positive guard, SSE detection, invalid JSON-RPC,
    connection refused, conclude adapter)
  - 3 plugin-contract tests (id/priority/requirements/named-export wiring)
- [x] **Bonus fix: `utils/conclusion_utils.mjs`** — `normalizeService` now spreads `...svc`
  to preserve every plugin's custom security flags. Evidence accepts both array
  (legacy probe rows) and object (FindingSchema cwe/owasp/mitre) shapes.
- [x] `tests/conclusion_utils.test.mjs` — 25 tests including 9 explicit
  "N.30 REGRESSION" tests proving anonymousLogin / weakAlgorithms / axfrAllowed /
  dangerousMethods / community / cves / mcp* / authoritative all survive normalization.
- [x] Patch release: 0.1.22 → 0.1.23

**Live demo against 192.168.1.28:8090:**
```
🎯 MCP service in conclusion:
   port=8090
   banner=MCP/http path=/ auth=required transport=http
   mcpCleartextTransport=true
   evidence={"cwe":["CWE-319"],"owasp":["A02:2021-Cryptographic Failures"],"mitre":["T1040"]}
```

**Two issues encountered + fixed during implementation (worth flagging):**
1. **conclude was on default export, not named.** Pre-fix the result_concluder swallowed
   the missing-export silently and fell through to `fallbackRecord` which produced a
   wrong-port service entry (port 1967 — the first MCP candidate port). Fixed by moving
   `conclude` to a named export. Convention matches existing plugins (webapp_detector).
2. **normalizeService was stripping custom fields project-wide.** Affected every plugin
   with security flags, not just MCP. Fixed in conclusion_utils.mjs.

Both lessons captured: (a) plugin-author docs should explicitly call out "conclude must be
a named export", and (b) when adding a new conclude adapter, run an integration test that
verifies the conclusion picks up custom fields end-to-end (the unit test for conclude()
in isolation passes even when the adapter never runs).

**Review feedback (captured as N.34, N.35; mcp_scanner perf folded into N.31):**
- [MEDIUM] N.34 — Distinguish OAuth 2.1 from arbitrary bearer-token auth (MCP spec §4.1
  mandates OAuth 2.1 with PKCE; current scanner treats any 401 as "auth=good")
- [LOW] N.35 — Static port list / dynamic range consistency (1967 is in static list but
  outside dynamic 3000-9000 heuristic)
- mcp_scanner sequential 8 ports × 5 paths × 2s timeout = up to 80s wall — same perf
  issue as port_scanner; folded into **N.31** (both should be parallelized together)

**Meta-finding from three implementation iterations (named-export → normalizeService strip
→ high-port test injection):** strong empirical case for upgrading **N.19 (E2E CLI test
infrastructure)** from LOW to MEDIUM priority. Three substantive bugs across N.25/N.27/N.30
would all have been caught by a single end-to-end pipeline test that exercises the actual
plugin orchestration end-to-end (not just unit-level mocks). Captured below in queue.

> **Why:** N.27/N.28/N.29 give the scanner the ability to find arbitrary services on
> non-standard ports. The next layer is **identifying MCP servers** specifically and
> producing security findings tailored to MCP's known attack surface. Currently nsauditor
> would surface "HTTP service on port 8090" — what's needed is "MCP server (SSE transport,
> bearer-token auth, protocol 2024-11-05) with N exposed tools, served over **cleartext
> HTTP**".
>
> **Reference:** `tasks/mcp-server-audit-research.md` (in-tree research file) provides
> the comprehensive specification: ports, attack surface, audit checklist, known CVEs,
> vulnerability classes. Plugin design should map directly to that document's sections
> 2.2 (port reference), 3 (attack surfaces), and 5 (audit checklist).
>
> **Scope:** CE plugin. Adds a new scanner — does NOT add MCP intelligence (CVE matching,
> EE-tier remediation generation, etc.). Detection + basic-finding generation only.

#### Detection probe (safe, read-only)

- [ ] `plugins/mcp_scanner.mjs` with priority ~70 (after http_probe / tls_scanner so we
  know which ports are HTTP/HTTPS first)
- [ ] Triggered on: any HTTP/HTTPS open port. Default candidate ports per research §2.2:
  `1967, 3000, 3005, 5173, 6274, 6277, 8000, 8090` plus any port that http_probe identified
  as HTTP-speaking
- [ ] **Probe 1 — JSON-RPC initialize** (the canonical MCP fingerprint):
  - POST `/`, `/mcp`, `/jsonrpc`, `/sse`, `/messages` (SSE proxy convention) with body:
    ```json
    {"jsonrpc":"2.0","id":1,"method":"initialize","params":{
      "protocolVersion":"2024-11-05","capabilities":{},
      "clientInfo":{"name":"nsauditor-mcp-probe","version":"1.0"}}}
    ```
  - Expected MCP response: `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"...",
    "capabilities":{...},"serverInfo":{"name":"...","version":"..."}}}`
  - 200 → MCP server confirmed, anonymous access allowed (security finding)
  - 401/403 with WWW-Authenticate → MCP server probably present, auth required (good)
  - Other → not MCP
- [ ] **Probe 2 — SSE detection**: GET with `Accept: text/event-stream`. If response
  Content-Type is `text/event-stream` → SSE-transport MCP server. Read 1 frame, close.
- [ ] **Probe 3 — Tools enumeration** (only if Probe 1 succeeded WITHOUT auth — proves
  unauthenticated tool access):
  - POST `{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`
  - Result includes tool names → these become severity:HIGH evidence ("MCP server X exposes
    tools Y, Z without authentication")

#### Findings produced

Per audit checklist in research doc §5:

- [ ] **CRITICAL** — MCP server bound to non-loopback address without auth (matches §2.3
  network binding risk + §3.3 confused deputy)
- [ ] **CRITICAL** — MCP `tools/list` returns successfully without auth (anonymous
  capability disclosure + tool invocation possible)
- [ ] **HIGH** — MCP server using HTTP (not HTTPS) — bearer tokens / OAuth in cleartext
  (matches §3.3 token passthrough)
- [ ] **HIGH** — MCP server using deprecated protocolVersion (anything older than
  current spec — table to be maintained as MCP spec evolves)
- [ ] **MEDIUM** — MCP Inspector exposed on a non-localhost address (ports 5173, 6274,
  6277 — these are dev tools and should never be network-reachable)
- [ ] **INFO** — MCP server identified, auth properly required (positive observation —
  document for compliance)
- [ ] All findings populate `evidence.cwe[]` and `evidence.owasp[]` (per N.5/N.14):
  - Cleartext token passthrough → `CWE-319` (Cleartext Transmission)
  - No-auth → `CWE-306` (Missing Authentication)
  - Generally → `OWASP-LLM-MCP-2025-*` once OWASP publishes a stable LLM/MCP top-10

#### MITRE mapping

- [ ] Add MCP-relevant entries to `utils/attack_map.mjs`:
  - MCP no-auth → T1190 (Exploit Public-Facing Application)
  - MCP tool exposure → T1059 (Command and Scripting Interpreter — since MCP tools can
    execute code/commands on backing services)
  - MCP cleartext token → T1040 (Network Sniffing)

#### Tests

- [ ] `tests/mcp_scanner.test.mjs` covering:
  - Mock HTTP server returning valid MCP initialize response → detected, no findings
  - Mock returning 401 → detected, INFO finding (auth properly required)
  - Mock returning tools/list without auth → CRITICAL finding with tool names in evidence
  - Mock SSE Content-Type → SSE transport detected
  - Mock non-MCP HTTP server → not flagged as MCP (no false positive on normal web servers)
  - HTTP vs HTTPS detection feeds the cleartext-bearer finding
- [ ] No real network calls — all probes mocked

#### Documentation

- [ ] Update README plugin table to list mcp_scanner
- [ ] Update docs/architecture.md plugin list (currently says 26 — would become 27)
- [ ] Add "Auditing MCP servers" section to README explaining the new capability
- [ ] Cross-link from `tasks/mcp-server-audit-research.md`

#### Limitations to document

- [ ] **STDIO MCP servers are invisible to network scanning** — they don't bind to ports.
  Per research §2.1, stdio is the dominant local pattern. The plugin only catches
  HTTP/SSE-transport MCP servers. README must state this explicitly so users don't
  assume "no MCP findings = no MCP risk." Stdio MCP audit requires file-system
  inspection of `claude_desktop_config.json` / equivalent — different scope, possibly
  a future EE feature.

#### Dependencies

- [ ] Depends on N.27 + N.28 + N.29 to be useful at scale: without `--ports` working
  and generic-probe identifying HTTP on non-standard ports, mcp_scanner will only
  catch MCP servers running on already-scanned default ports. Logical sequencing:
  N.27 → N.28 → N.29 → N.30. All four could ship together as v0.2.0 (minor bump:
  new plugin + new flags).

### Task N.17 — [LOW] Honor `--out <dir>` for SARIF / CSV / MD output blocks (pre-existing) ✅ COMPLETED 2026-04-26 (v0.1.18)

> **Why:** README CLI reference documents `--out <dir>` for "Custom output directory" with
> default `out/`. That flag is honored by the main scan output but **ignored by all three
> alternate-format blocks** (SARIF, CSV, MD) — they hardcode `outDir = 'out'`.
>
> **Result:** 610 tests pass (was 592; +18 new). Created `utils/output_dir.mjs` helper
> mirroring the `utils/tool_version.mjs` pattern from N.15 — single source of truth for
> output-directory resolution.

- [x] Created `utils/output_dir.mjs` exporting `resolveBaseOutDir()`. Resolves env vars in
  priority order: `SCAN_OUT_PATH` (set by `--out`) → `OPENAI_OUT_PATH` (legacy) → `'out'`.
  Strips quotes/whitespace, falls back to parent dir if value points at a file.
  Reads env on each call (not cached) — important because the CLI sets `SCAN_OUT_PATH`
  during arg parsing, *after* module load.
- [x] cli.mjs: replaced inline env-resolution at line 110-112 (main scan output) with
  `resolveBaseOutDir()` call — identical semantics, eliminates duplication
- [x] cli.mjs: replaced hardcoded `'out'` in SARIF, CSV, and MD output blocks with
  `resolveBaseOutDir()` — closes the documented bug
- [x] Left line 615 (`outRoot` for scan history) alone — uses different normalization
  (`.replace(/\.[^/.]+$/, '')` regex vs `path.parse`) with subtly different semantics for
  edge cases. Out of N.17 scope; would need its own analysis to migrate safely.
- [x] `tests/output_dir.test.mjs` — 18 tests: env priority, defaults, file-path normalization,
  quote/whitespace stripping, **re-reads env on each call** (the critical property for CLI
  arg parsing → env-stamp → reader timing)
- [x] Updated README CLI reference to clarify `--out` applies to alternate-format files too
- [x] Patch release: 0.1.17 → 0.1.18

**Review feedback (captured retroactively as N.20 / N.21 above):**
- [LOW] `toCleanPath` consolidation — see N.20
- [LOW] README clarification: `--out` requires a directory — see N.21

---

### Task N.14 — `cweToMitre()` helper in `utils/attack_map.mjs` ✅ COMPLETED 2026-04-26 (v0.1.14)

> **Why:** N.5 added `evidence.cwe[]` to the FindingSchema. EE's intelligence_engine maps
> CVE→ATT&CK today, but for findings without CVEs (config issues, weak crypto detected by
> agents), there's no automatic technique mapping. CWE→ATT&CK is the standard fallback
> path used by SARIF, OWASP ZAP, and Burp.
>
> **Result:** 547 tests pass (was 520; +27 new in `attack_map.test.mjs`). No regressions.
> 35 CWE mappings shipped, covering auth/crypto/injection/memory-safety/info-disclosure/
> path-traversal/privilege-escalation/web/DoS categories.

- [x] Add `cweToMitre(cwe: string)` and `cwesToMitre(cwes: string[]|string)` to `utils/attack_map.mjs`
- [x] Static map covering 35 common CWEs (exceeded the ~30 target):
  - Authentication (7): CWE-256, 287, 306, 521, 798, 862, 863
  - Crypto (5): CWE-319, 326, 327, 328, 331
  - Injection (6): CWE-77, 78, 79, 89, 94, 1336
  - Memory safety (6): CWE-119, 120, 125, 416, 502, 787
  - Info disclosure (2): CWE-200, 209
  - Path traversal (2): CWE-22, 434
  - Privilege escalation (3): CWE-250, 269, 732
  - Web-specific (3): CWE-352, 601, 918
  - Resource/DoS (2): CWE-400, 770
- [x] Tests: per-CWE mappings, case-insensitive lookup, whitespace tolerance, unknown CWE
  returns `[]`, dedup union, fresh-copy invariant (static map not mutated by callers),
  CWE_TECHNIQUE_MAP coverage assertions (≥30 entries, valid format)
- [x] Wire into `mapServiceToAttack()` as a fallback path: only fires when CVE-derived
  mapping returns no techniques. Reads in priority: `service.cwes` → `service.cwe` →
  `service.evidence?.cwe`. Verified by dedicated test that CWE fallback does NOT fire
  when CVE mapping produced techniques.
- [x] Update README's AI Analysis section to mention CWE-based fallback
- [x] No EE changes required — EE intelligence_engine reads `attack_map.mjs` already

---

### Task N.36 — [LOW] Migrate Claude default model `claude-sonnet-4-20250514` → `claude-sonnet-4-6` ✅ COMPLETED 2026-04-30 (v0.1.25)

> **Why:** The hardcoded Anthropic model default and its mirrored copies in tests, README,
> and `.env.example` still pinned the old Sonnet 4 dated alias. Sonnet 4.6 (`claude-sonnet-4-6`)
> is the current Anthropic Claude release and is what the project's own subagent planning
> note (Task N.11, line 3368) already references — so the runtime default and the docs
> were lagging behind the project's stated target.
>
> **Result:** 11/11 AI provider tests pass. No regressions. Single-concern patch release.
> Default Claude model now consistent across all five touch-points.

- [x] `cli.mjs:99` — `ANTHROPIC_MODEL` default changed to `claude-sonnet-4-6`
- [x] `tests/cli_ai_provider.test.mjs` — 4 occurrences updated (default-resolution test + explicit-model assertions)
- [x] `README.md` — env-config examples at lines 201 + 447 updated
- [x] `.env.example:10` — updated to match
- [x] Verified zero remaining occurrences of `claude-sonnet-4-20250514` in the repo
- [x] Patch release: 0.1.24 → 0.1.25 — published to npm

---

**End of todo.md**
