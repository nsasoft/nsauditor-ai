// tests/fetch_redirect_policy_census.test.mjs
//
// EVERY `fetch` THIS PACKAGE SHIPS CARRIES AN EXPLICIT `redirect: 'manual'` (EE board B158's Community half; the release
// paired with Enterprise 2.1.2).
//
// A redirect policy is a credential-forwarding decision before it is a transport one: on Node 24.22.1 `fetch` strips
// `Authorization` and `Cookie` on a cross-origin redirect but FORWARDS a custom header (`apiKey`, `x-api-key`) wherever it
// points (EE audit-evidence-samples/ee-2.1.2/b129/04). The NVD client's `apiKey` did exactly that until this release.
// This census holds every first-party `fetch` in the shipped tree (package.json `files`) to the pin, DENY-BY-DEFAULT,
// keyed on the CALL, never on the string `fetch(`. Comments and string literals are blanked first. The pin counts when it
// is in the call's own arguments, or in the object literal a bare-identifier argument names in the same file
// (`fetch(url, fetchOpts)`). Aliases are DERIVED: `x = …fetch` binding fetch as a VALUE, and `x = await provider()` where
// the provider function's body returns `fetch`. A `typeof fetch` check is not a use. Any other reference is reported.
//
// Enterprise holds its own tree to the same rule (EE tests/fetch_redirect_policy_census.test.mjs); no test here reads it.
// STATED LIMIT, printed: a `fetch` inside a dependency is not first-party and not read — the Anthropic SDK's own `fetch`
// carries `x-api-key` and follows redirects (EE board B162: the SDK accepts a `fetch` option, so a pinned wrapper is the
// fix, measured first).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { stripCommentsAndStrings } from './support/strip_comments_and_strings.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const PIN = '__NSA_REDIRECT_MANUAL__';
const FETCH_REF = /(?<![\w$])(?:globalThis\.)?fetch(?![\w$])/g;
// fetch as a VALUE: `x = opts._fetch ?? globalThis.fetch` — never `x = await fetch(...)`, which binds a call's result.
const VALUE_ALIAS = /(?<![\w$])(?:this\.)?([A-Za-z_$][\w$]*)\s*=[^;=]*?(?<![\w$.])(?:globalThis\.)?fetch(?![\w$])(?!\s*\()/g;

function balanced(code, open, o, c) {
  let depth = 0;
  for (let i = open; i < code.length; i += 1) {
    if (code[i] === o) depth += 1;
    else if (code[i] === c) { depth -= 1; if (depth === 0) return code.slice(open + 1, i); }
  }
  return null;
}
/** The functions whose body returns `fetch` (a fetch PROVIDER), and the spans of those return statements. */
function providers(code) {
  const out = new Map();
  for (const m of code.matchAll(/(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\([^)]*\)\s*\{/g)) {
    const body = balanced(code, m.index + m[0].length - 1, '{', '}');
    if (body == null) continue;
    const start = m.index + m[0].length;
    const returns = [...body.matchAll(/(?<![\w$])return\s+(?:globalThis\.)?fetch(?![\w$])\s*;/g)];
    if (returns.length) out.set(m[1], returns.map((r) => start + r.index + r[0].indexOf('fetch')));
  }
  return out;
}
/** Is the pin in this call's arguments, or in the object literal a bare identifier argument names in the same file? */
function pinned(code, args) {
  if (args == null) return false;
  if (args.includes(`redirect: ${PIN}`)) return true;
  for (const [, id] of args.matchAll(/(?:^|,)\s*([A-Za-z_$][\w$]*)\s*(?=,|$)/g)) {
    const def = code.match(new RegExp(`(?:const|let|var)\\s+${id.replace(/\$/g, '\\$')}\\s*=\\s*\\{`));
    if (def && (balanced(code, def.index + def[0].length - 1, '{', '}') ?? '').includes(`redirect: ${PIN}`)) return true;
  }
  return false;
}

/** Census one source text: { aliases, calls: [{ name, pinned }], unbound: [snippet] }. */
export function censusSource(src) {
  const code = stripCommentsAndStrings(src.replace(/redirect\s*:\s*(['"])manual\1/g, `redirect: ${PIN}`));
  const aliases = new Set();
  const skip = [];
  for (const m of code.matchAll(VALUE_ALIAS)) { aliases.add(m[1]); skip.push([m.index, m.index + m[0].length]); }
  const prov = providers(code);
  for (const [name, refs] of prov) {
    for (const at of refs) skip.push([at, at + 5]);
    for (const m of code.matchAll(new RegExp(`(?<![\\w$])(?:this\\.)?([A-Za-z_$][\\w$]*)\\s*=\\s*(?:await\\s+)?${name}\\s*\\(`, 'g'))) aliases.add(m[1]);
  }
  const calls = [];
  const unbound = [];
  for (const m of code.matchAll(FETCH_REF)) {
    if (skip.some(([a, b]) => m.index >= a && m.index < b)) continue;
    if (/typeof\s+$/.test(code.slice(Math.max(0, m.index - 10), m.index))) continue;
    const open = code.slice(m.index + m[0].length).match(/^\s*\(/);
    if (!open) { unbound.push(code.slice(Math.max(0, m.index - 30), m.index + 40).replace(/\s+/g, ' ')); continue; }
    calls.push({ name: 'fetch', pinned: pinned(code, balanced(code, m.index + m[0].length + open[0].length - 1, '(', ')')) });
  }
  for (const name of aliases) {
    for (const m of code.matchAll(new RegExp(`(?<![\\w$])(?:this\\.)?${name.replace(/\$/g, '\\$')}\\s*\\(`, 'g'))) {
      calls.push({ name, pinned: pinned(code, balanced(code, m.index + m[0].length - 1, '(', ')')) });
    }
  }
  return { aliases: [...aliases].sort(), calls, unbound };
}

function shippedFiles() {
  const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
  const out = [];
  const walk = (rel) => {
    const abs = path.join(ROOT, rel);
    if (!fs.existsSync(abs)) return;
    if (fs.statSync(abs).isDirectory()) { for (const e of fs.readdirSync(abs)) walk(path.join(rel, e)); return; }
    if (/\.(?:mjs|js|cjs)$/.test(rel)) out.push(rel);
  };
  for (const entry of pkg.files) walk(entry.replace(/\/$/, ''));
  return out.sort();
}

test('(control, first) the census FLAGS an unpinned call, an alias call, a follow policy, a comment-only pin, a pin on another call, and a provider\'s unpinned call', () => {
  const flagged = (src) => censusSource(src).calls.filter((c) => !c.pinned).length;
  assert.equal(flagged('const r = await fetch(url, { headers });'), 1, 'a bare unpinned call');
  assert.deepEqual(censusSource('const r = await fetch(url, {});').aliases, [], 'a call RESULT assigned is not an alias');
  assert.equal(flagged("const f = opts._fetch ?? globalThis.fetch;\nawait f(url, { method: 'POST' });"), 1, 'a call through an alias');
  assert.equal(flagged("await fetch(url, { redirect: 'follow' });"), 1, 'an explicit follow');
  assert.equal(flagged("// redirect: 'manual'\nawait fetch(url, {});"), 1, 'a pin in a comment only');
  assert.equal(flagged("await fetch(a, { redirect: 'manual' });\nawait fetch(b, {});"), 1, 'the pin on a different call');
  assert.equal(flagged("async function getFetch() { if (typeof fetch === 'function') return fetch; }\nconst doFetch = await getFetch();\nawait doFetch(url, {});"), 1, 'a provider\'s alias, unpinned');
  assert.equal(flagged("const opts = { headers };\nawait fetch(url, opts);"), 1, 'an options object without the pin');
});

test('(control) the census PASSES a pinned call, an options object that carries the pin, and a provider\'s pinned call', () => {
  const r = censusSource("const fetchOpts = { signal, redirect: 'manual' };\nawait fetch(url, fetchOpts);\nasync function getFetch() { if (typeof fetch === 'function') return fetch; }\nconst doFetch = await getFetch();\nawait doFetch(url, { redirect: \"manual\" });\n// fetch(x)\nconst s = 'fetch(y)';");
  assert.deepEqual(r.calls.map((c) => [c.name, c.pinned]).sort(), [['doFetch', true], ['fetch', true]]);
  assert.deepEqual(r.unbound, []);
});

test('(control) a bare reference to fetch that is neither a call, a value alias, a provider\'s return nor a typeof check is reported', () => {
  assert.equal(censusSource('register(globalThis.fetch);').unbound.length, 1);
});

test('every fetch in the shipped tree carries `redirect: \'manual\'` — deny-by-default, keyed on the call', () => {
  const unpinned = [];
  const unbound = [];
  const population = [];
  for (const rel of shippedFiles()) {
    const r = censusSource(fs.readFileSync(path.join(ROOT, rel), 'utf8'));
    for (const c of r.calls) { population.push(`${rel} · ${c.name}`); if (!c.pinned) unpinned.push(`${rel} · ${c.name}`); }
    for (const u of r.unbound) unbound.push(`${rel} · ${u}`);
  }
  assert.deepEqual(unbound, [], 'a reference to fetch the census cannot follow');
  assert.deepEqual(unpinned, [], 'a shipped fetch follows redirects — pin `redirect: \'manual\'` with a named refusal, or declare why not');
  for (const site of ['utils/nvd_client.mjs · fetch', 'plugins/webapp_detector.mjs · fetch', 'plugins/upnp_scanner.mjs · fetch', 'plugins/050_tribe_health.mjs · fetch', 'plugins/opensearch_scanner.mjs · doFetch']) {
    assert.ok(population.includes(site), `the census no longer sees ${site}: ${JSON.stringify(population)}`);
  }
});
