// tests/dns_posture_check_ids.test.mjs
// ─────────────────────────────────────────────────────────────────────────────
// THE DNS-SECURITY AUDIT DECLARES WHICH FINDING IDS EACH OF ITS CHECKS CAN EMIT, AND THE DECLARATION IS THE CODE'S.
//
// Plugin 060 grades a domain in checks — the keys of `result.findings` (spf, dmarc, ns, …) — and records a check it could
// not measure in `details.notMeasured` by that key. A reader that must know which findings a not-measured check WOULD
// have produced (a compliance mapping holds exactly those findings' controls as a gap) reads `CHECK_IDS_BY_CATEGORY`.
// That table is held EQUAL, both ways, to the `check: "…"` literals each check's own function emits — so a new, renamed
// or removed finding id fails the build here, and cannot silently de-anchor a reader. The function that implements each
// check is the oracle this test DECLARES; everything else is read from the plugin's source and from a driven run.
// ─────────────────────────────────────────────────────────────────────────────
import './helpers/no_operator_home.mjs';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const dnsP = require('node:dns').promises;
const nodata = async (name) => { throw Object.assign(new Error(`query ENODATA ${name}`), { code: 'ENODATA' }); };
for (const k of ['resolve', 'resolve4', 'resolve6', 'resolveTxt', 'resolveCname', 'resolveMx', 'resolveNs', 'resolveSoa',
  'resolveCaa', 'resolveAny']) dnsP[k] = nodata;

const SRC = fs.readFileSync(new URL('../plugins/060_dns_sec_auditor.mjs', import.meta.url), 'utf8');
const { default: dnsSec, CHECK_IDS_BY_CATEGORY } = await import('../plugins/060_dns_sec_auditor.mjs');

// The function that implements each check — the oracle, declared.
const FUNCTION_OF_CHECK = Object.freeze({
  cname: 'checkDanglingCname', spf: 'analyzeSPF', dmarc: 'analyzeDMARC', dkim: 'discoverDKIM', ns: 'analyzeNS',
  dnssec: 'probeDNSSEC', axfr: 'checkZoneTransfer', mx: 'analyzeMX', caa: 'analyzeCAA', wildcard: 'checkWildcard',
});
/** Each top-level function's source text, from its declaration to the next one (or the plugin export). */
function functionBodies() {
  const starts = [...SRC.matchAll(/^(?:async )?function (\w+)\(/gm)].map((m) => [m.index, m[1]]);
  starts.push([SRC.indexOf('export default {'), null]);
  starts.sort((a, b) => a[0] - b[0]);
  return new Map(starts.slice(0, -1).map(([at, name], i) => [name, SRC.slice(at, starts[i + 1][0])]));
}
const BODIES = functionBodies();
const literals = (text) => [...text.matchAll(/check:\s*"([a-z0-9_]+)"/g)].map((m) => m[1]);
const notMeasuredNames = (text) => [...text.matchAll(/notMeasured\.push\(\{\s*check:\s*"([a-z0-9_]+)"/g)].map((m) => m[1]);
const issueIds = (text) => {
  const nm = notMeasuredNames(text);
  const all = literals(text);
  for (const n of nm) all.splice(all.indexOf(n), 1);
  return [...new Set(all)].sort();
};

test('(first) every check\'s declared ids EQUAL the ids its own function emits — both ways', () => {
  for (const [check, fn] of Object.entries(FUNCTION_OF_CHECK)) {
    assert.ok(BODIES.has(fn), `${fn} is a function of the plugin`);
    assert.deepEqual([...CHECK_IDS_BY_CATEGORY[check]].sort(), issueIds(BODIES.get(fn)), `${check} (${fn})`);
  }
});

test('the declared checks are exactly the keys a run grades under `findings`', async () => {
  const result = await dnsSec.run('example.test', 0, {});
  assert.deepEqual(Object.keys(CHECK_IDS_BY_CATEGORY).sort(), Object.keys(result.findings).sort());
  assert.deepEqual(Object.keys(FUNCTION_OF_CHECK).sort(), Object.keys(result.findings).sort());
});

test('every `check:` literal in the plugin is accounted for: a finding id of exactly one check, or a not-measured record', () => {
  const declared = Object.values(CHECK_IDS_BY_CATEGORY).flat();
  assert.equal(new Set(declared).size, declared.length, 'no id belongs to two checks');
  const checks = new Set(Object.keys(CHECK_IDS_BY_CATEGORY));
  for (const id of new Set(literals(SRC))) {
    assert.ok(declared.includes(id) || checks.has(id), `"${id}" is emitted by the plugin but declared nowhere`);
  }
});

test('a not-measured record names the check whose function records it — always a key of the declaration', () => {
  for (const [check, fn] of Object.entries(FUNCTION_OF_CHECK)) {
    for (const name of notMeasuredNames(BODIES.get(fn))) assert.equal(name, check, `${fn} records "${name}"`);
  }
  for (const name of notMeasuredNames(SRC)) assert.ok(Object.hasOwn(CHECK_IDS_BY_CATEGORY, name), name);
});

test('the declaration cannot be changed by a reader', () => {
  assert.ok(Object.isFrozen(CHECK_IDS_BY_CATEGORY));
  for (const ids of Object.values(CHECK_IDS_BY_CATEGORY)) assert.ok(Object.isFrozen(ids));
});
