/*
 * NSAuditor AI — Community Edition
 */
/**
 * THE `mdns` MODULE-SHAPE FALLBACK MUST FALL BACK.
 *
 * ── WHY THIS EXISTS ─────────────────────────────────────────────────────────────────────────
 * `plugins/mdns_scanner.mjs` resolved the dynamically-imported native module as:
 *
 *     const mdns = mdnsMod.default || mdns;      // ← the second `mdns` is THIS binding
 *
 * which is a TDZ self-reference: when `mdnsMod.default` is falsy the `||` evaluates `mdns`
 * before its own initialiser completes and throws `ReferenceError: Cannot access 'mdns' before
 * initialization`. The intended fallback — use the module NAMESPACE when there is no default
 * export — never ran. `mdnsMod.default || mdnsMod` is the correct form.
 *
 * ⚠️ IT IS A DEAD FALLBACK, NOT A LIVE CRASH, AND THE DISTINCTION IS THE REASON IT SURVIVED.
 * The call sits inside a `try/catch` in the scanner's main path that logs *"node-mdns not
 * available or forced/failure"* and degrades to the pure-JS `multicast-dns` strategy. So the
 * defect is invisible in every observable way: the scan still completes, the fallback path still
 * produces rows, and nothing is logged that a reader would distinguish from "the optional native
 * module simply is not installed". The only symptom is that a CJS-shaped `mdns` build exposing
 * its API on the namespace rather than on `.default` would be treated as ABSENT.
 *
 * ── WHY IT IS FOUND NOW ─────────────────────────────────────────────────────────────────────
 * Surfaced 2026-08-15 while measuring the F1 air-gapped-delivery closure: `mdns@2.7.2` is the one
 * native module (`gypfile: true`) in the built customer closure, it will not build on a NIC-down
 * host, and its guarded-import path therefore becomes load-bearing for the air-gap story. A
 * fallback that is load-bearing and dead is worth a test.
 *
 * ── WHAT THIS TEST DOES NOT DO ──────────────────────────────────────────────────────────────
 * It does not import `mdns` (which may be unbuilt on any given host — that is the whole point).
 * It exercises the EXPRESSION SHAPE against both module shapes, which is the property that broke.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const SRC = fs.readFileSync(path.join(ROOT, 'plugins', 'mdns_scanner.mjs'), 'utf8');

test('the mdns module-shape fallback is not a TDZ self-reference', () => {
  // The defect, pinned by shape: `X.default || X` is correct; `X.default || <the const itself>`
  // is the bug. Matching the source rather than behaviour because the behaviour is unreachable
  // without a built native module, which is exactly the condition that hid it.
  const selfRef = /const\s+(\w+)\s*=\s*(\w+)\.default\s*\|\|\s*\1\s*;/.exec(SRC);
  assert.equal(selfRef, null,
    'the module-shape fallback evaluates its OWN binding in the `||` right-hand side — a TDZ '
    + 'self-reference that throws ReferenceError instead of falling back to the module namespace. '
    + `Found: ${selfRef?.[0]}`);
});

test('the fallback resolves a namespace-shaped module (the case the TDZ form could never reach)', () => {
  // Both real shapes, exercised through the corrected expression. A CJS native addon imported
  // from ESM usually surfaces its exports on `.default`, but not always — and "usually" is what
  // a fallback exists for.
  const withDefault = { default: { rst: 'API-VIA-DEFAULT' } };
  const namespaceOnly = { rst: 'API-VIA-NAMESPACE' };

  const resolve = (mod) => mod.default || mod;
  assert.equal(resolve(withDefault).rst, 'API-VIA-DEFAULT');
  assert.equal(resolve(namespaceOnly).rst, 'API-VIA-NAMESPACE',
    'a namespace-shaped module must resolve to the namespace — this is the branch the TDZ form '
    + 'threw on, and therefore the branch that was never once exercised in production');
});

test('the guarded import still degrades rather than crashing (the property that hid the defect)', () => {
  // Regression pin on the CONTAINMENT, not just the expression: if a future edit lifts the
  // dynamic import out of its try/catch, an unbuilt optional native module stops being a
  // graceful degradation and becomes a scan-aborting throw — on exactly the air-gapped hosts
  // where it can never be built.
  const fn = /async function runWithNodeMdns\b/.exec(SRC);
  assert.ok(fn, 'runWithNodeMdns is gone — re-point this guard at whatever replaced it');
  const callSite = SRC.indexOf('runWithNodeMdns(host');
  assert.ok(callSite > 0, 'the call site moved; the containment assertion below is now vacuous');
  // The nearest enclosing construct before the call must be a `try {`.
  const before = SRC.slice(0, callSite);
  const lastTry = before.lastIndexOf('try {');
  const lastCatch = before.lastIndexOf('catch');
  assert.ok(lastTry > lastCatch,
    'the call to runWithNodeMdns is no longer inside a try block — an unbuilt optional native '
    + 'module would abort the scan instead of falling back to the multicast-dns strategy');
});
