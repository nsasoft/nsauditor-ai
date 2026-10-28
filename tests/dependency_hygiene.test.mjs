// tests/dependency_hygiene.test.mjs — CE dependency-hygiene drift guard (0.1.86)
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const pkg = JSON.parse(readFileSync(fileURLToPath(new URL('../package.json', import.meta.url)), 'utf8'));

test('@anthropic-ai/sdk constraint is above the GHSA-p7fg-763f-g4gf range (>0.91.0)', () => {
  const range = pkg.dependencies['@anthropic-ai/sdk'];
  const f = range.replace(/[^\d.]/g, '').split('.').map(Number); // ^0.100.0 -> [0,100,0]
  assert.ok(f[0] > 0 || f[1] >= 92, `@anthropic-ai/sdk floor ${range} must be > 0.91.0`);
});

test('CE no longer declares a direct uuid dep (uses crypto.randomUUID)', () => {
  assert.ok(!('uuid' in pkg.dependencies), 'direct uuid dropped in favor of crypto.randomUUID()');
});

test('CE no longer declares simple-wappalyzer (abandoned wappalyzer-core)', () => {
  assert.ok(!('simple-wappalyzer' in pkg.dependencies), 'simple-wappalyzer removed; in-house fingerprinter replaces it');
});

// zod and body-parser (1.1.0). Every zod 3.x is inside GHSA-mrhx-c7xc-m3w5 (memory exhaustion while validating oversized
// constrained collections; patched in 4.6.6). zod is a DIRECT dependency at the patched floor: npm then installs one zod 4.x
// for the whole tree, including under `npm install -g`, where a package's own `overrides` are not applied. Under openai@4, whose
// OPTIONAL zod peer was ^3.23.8, an install rooted at this package (development, and the air-gap carrier's `npm ci`) refused
// to resolve (ERESOLVE) without `overrides.zod: "$zod"`, and a project depending on this package still got zod 3.25.76 at its
// root. B87 (1.1.1) moved to openai 7, whose optional zod peer is ^3.25 || ^4.0, so the declared zod satisfies it. Measured
// 2026-10-28: the lockfile is IDENTICAL with and without the override, and a dependent project gets zod 4.6.7 only. So the
// override is retired, and the leg below pins the condition that made it unnecessary. CE imports zod nowhere and uses no
// openai zod helper; the MCP SDK accepts ^4.0.
// body-parser below 2.4.0 is inside GHSA-27r3-jxmh-p828; the lockfile is what the air-gap carrier installs.
const lock = JSON.parse(readFileSync(fileURLToPath(new URL('../package-lock.json', import.meta.url)), 'utf8'));
const cmp = (a, b) => { const x = a.split('.').map(Number), y = b.split('.').map(Number); for (let i = 0; i < 3; i++) if (x[i] !== y[i]) return x[i] - y[i]; return 0; };
const lockCopies = (name) => Object.entries(lock.packages || {})
  .filter(([k]) => k === `node_modules/${name}` || k.endsWith(`/node_modules/${name}`))
  .map(([k, v]) => ({ path: k, version: v.version }));

test('zod is a direct dependency whose floor is at or above 4.6.6 (GHSA-mrhx-c7xc-m3w5)', () => {
  const range = pkg.dependencies.zod;
  assert.ok(typeof range === 'string', 'zod must be declared in dependencies, not left to openai\'s optional peer');
  const floor = range.replace(/^[^\d]*/, '').split(/\s/)[0];
  assert.ok(cmp(floor, '4.6.6') >= 0, `zod floor ${range} must be >= 4.6.6`);
});

test('the lockfile resolves every zod copy at 4.6.6 or newer, and holds at least one', () => {
  const copies = lockCopies('zod');
  assert.ok(copies.length >= 1, 'positive control: the lockfile holds a zod');
  const below = copies.filter((c) => cmp(c.version, '4.6.6') < 0);
  assert.deepEqual(below, [], `zod copies below 4.6.6: ${JSON.stringify(below)}`);
});

test('the lockfile resolves every body-parser copy at 2.4.0 or newer, and holds at least one (GHSA-27r3-jxmh-p828)', () => {
  const copies = lockCopies('body-parser');
  assert.ok(copies.length >= 1, 'positive control: the lockfile holds a body-parser');
  const below = copies.filter((c) => cmp(c.version, '2.4.0') < 0);
  assert.deepEqual(below, [], `body-parser copies below 2.4.0: ${JSON.stringify(below)}`);
});

test('openai\'s zod peer ADMITS the declared zod, so no override is needed at this package\'s root (B87, openai 7)', () => {
  const entry = lock.packages['node_modules/openai'];
  assert.ok(entry, 'positive control: the lockfile holds openai');
  const peer = entry.peerDependencies?.zod;
  assert.equal(typeof peer, 'string', 'openai declares zod as a peer');
  const admitsZod4 = peer.split('||').some((r) => /^\^?4(\.|$)/.test(r.trim()));
  assert.ok(admitsZod4, `openai's zod peer (${peer}) does not admit zod 4. Under openai 4 it was ^3.23.8, and an install rooted `
    + 'here refused to resolve without overrides.zod; restore the override, or keep openai at a release whose peer admits ^4');
});
