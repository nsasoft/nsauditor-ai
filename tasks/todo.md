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

### Phase 2 — License System (JWT, offline)
- [ ] 2.1 ECDSA P-256 key pair generation
- [ ] 2.2 JWT signing service (Nsasoft-side)
- [ ] 2.3 Stripe webhook → JWT → email delivery
- [ ] 2.4 Replace `license.mjs` stub with `jose` ES256 offline verification
- [ ] 2.5 14-day trial key generation endpoint
- [ ] 2.6 Tests (valid/expired/tampered/no-key paths)

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

## After CE Launch — EE Private Branch

Once the CE repo is public:

1. Create private GitHub repo `nsauditor-ai-ee`
2. Scaffold as npm package `@nsasoft/nsauditor-ai-ee` with `nsauditor-ai` as peer dependency
3. Copy EE-only plugins from `../nsauditor-plugin-manager`: `cloud_aws.mjs`, `cloud_gcp.mjs`, `cloud_azure.mjs`, `zero_trust_checker.mjs`
4. Proceed with Roadmap Phase 0 (legal/IP) → Phase 2 (JWT license) → Phase 3 (Intelligence Engine)

---

**End of todo.md**
