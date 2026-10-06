// ENTERPRISE THAT IS INSTALLED BUT FAILS TO LOAD IS NEVER READ AS "NOT INSTALLED" (1.1.1 — the audit seat's T1-c ruling).
//
// The scan path imported `@nsasoft/nsauditor-ai-ee` inside a bare `catch {}` commented "EE not installed — the ONLY silent
// case", and it was not the only case: EVERY import failure landed there. Measured at EE 174212f: Enterprise imported six
// names Community 0.2.55 does not export, which fails the whole Enterprise module graph at LINK time — so on a Community
// below the floor the scan ran with no analysis agents, no CVE mapper and no compliance report, printed nothing, and the
// Pro delta then read every agent and engine row RESOLVED. The floor and the import guard (Enterprise's test) keep a
// standard install above the floor; this keeps a non-standard one (legacy-peer-deps, the airgap carrier, a hand copy)
// from going silent.
//
// The ruling: resolve the package FIRST. Unresolvable → not installed, silent. Resolvable but the import throws → loud on
// stderr, and `conclusion.result.eeLoadError` in the shape of the existing `eeEnrichmentError`, so the delta can refuse.
//
// FOURTH QUADRANT FIRST.
import { withNoDotenv } from './helpers/no_operator_dotenv.mjs';
import './helpers/no_operator_keychain.mjs';   // FIRST: keeps this file off the operator's real Keychain
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import * as L from '../utils/ee_load.mjs';

const load = (o) => { assert.equal(typeof L.loadEnterprise, 'function', 'utils/ee_load.mjs exports loadEnterprise'); return L.loadEnterprise(o); };
const notFound = () => Object.assign(new Error("Cannot find package '@nsasoft/nsauditor-ai-ee' imported from /x/cli.mjs"), { code: 'ERR_MODULE_NOT_FOUND' });
// The exact shape measured below the floor: a named import Community does not export fails the graph at link time.
const belowFloor = () => new SyntaxError("The requested module 'nsauditor-ai/utils/scan_delta.mjs' does not provide an export named 'isUdpTransport'");

// ── FOURTH QUADRANT FIRST ─────────────────────────────────────────────────────────────────────────────
test('(q1) NOT INSTALLED — the package does not resolve → { ee: null, loadError: null }, and it is never imported', async () => {
  let imported = false;
  const r = await load({ resolveEE: () => { throw notFound(); }, importEE: async () => { imported = true; return {}; } });
  assert.deepEqual(r, { ee: null, loadError: null });
  assert.equal(imported, false);
});

test('(q1) installed and loads → the module and no error', async () => {
  const mod = { enrichScan: async () => ({}) };
  const r = await load({ resolveEE: () => 'file:///x/index.mjs', importEE: async () => mod });
  assert.equal(r.ee, mod);
  assert.equal(r.loadError, null);
});

// ── THE DEFECT ────────────────────────────────────────────────────────────────────────────────────────
test('(a) installed, and the import throws the BELOW-FLOOR shape → a LOAD ERROR naming it, never "not installed"', async () => {
  const r = await load({ resolveEE: () => 'file:///x/index.mjs', importEE: async () => { throw belowFloor(); } });
  assert.equal(r.ee, null);
  assert.match(r.loadError ?? '', /does not provide an export named 'isUdpTransport'/);
});

test('(a) installed, and a DEPENDENCY of Enterprise is missing (ERR_MODULE_NOT_FOUND naming another package) → a load error: presence is decided by resolution, never by the error code', async () => {
  const r = await load({ resolveEE: () => 'file:///x/index.mjs',
    importEE: async () => { throw Object.assign(new Error("Cannot find package 'googleapis' imported from /x/ee/index.mjs"), { code: 'ERR_MODULE_NOT_FOUND' }); } });
  assert.match(r.loadError ?? '', /googleapis/);
});

test('(a) an import SEAM with no resolver means INSTALLED — a seam that throws is a load failure, not absence', async () => {
  const r = await load({ importEE: async () => { throw belowFloor(); } });
  assert.match(r.loadError ?? '', /isUdpTransport/);
});

test('(a) the DEFAULT resolver decides presence when no seam is given — and is NOT consulted when an import seam is (a checkout without Enterprise)', async () => {
  // Enterprise resolves from this checkout, so these legs replace the default resolver to describe one where it does not.
  assert.equal(typeof L.resolverDeps?.resolve, 'function', 'the default resolver is a replaceable dependency');
  const saved = L.resolverDeps.resolve;
  try {
    L.resolverDeps.resolve = () => { throw notFound(); };
    assert.deepEqual(await load({}), { ee: null, loadError: null }, 'no seam: the default resolver says absent → silent');
    const r = await load({ importEE: async () => { throw belowFloor(); } });
    assert.match(r.loadError ?? '', /isUdpTransport/, 'an import seam is an installed package — the default resolver is not asked');
  } finally { L.resolverDeps.resolve = saved; }
});

// ── REAL PACKAGES: Node's own resolver decides (the audit seat's T1-c fold 2) ───────────────────────────────
// Resolving the package ENTRY answers "does its entry resolve", not "is it installed": a package whose main file is
// missing (a truncated install) or whose exports map does not serve "." throws ERR_MODULE_NOT_FOUND /
// ERR_PACKAGE_PATH_NOT_EXPORTED at resolution — and read as ABSENT, the installed-but-broken class one layer down.
// Presence is decided by the package MANIFEST; any failure of the import itself is then a load failure. Each case is a
// real package in a scratch node_modules, resolved and imported by a child `node` from that directory.
import { spawnSync } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';

const EE_LOAD_URL = pathToFileURL(path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'utils', 'ee_load.mjs')).href;
function inScratch(pkg, files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-eepkg-'));
  try {
    if (pkg) {
      const root = path.join(dir, 'node_modules', '@nsasoft', 'nsauditor-ai-ee');
      fs.mkdirSync(root, { recursive: true });
      fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify({ name: '@nsasoft/nsauditor-ai-ee', version: '9.9.9', type: 'module', ...pkg }));
      for (const [f, text] of Object.entries(files ?? {})) fs.writeFileSync(path.join(root, f), text);
    }
    fs.writeFileSync(path.join(dir, 'child.mjs'), `import * as L from ${JSON.stringify(EE_LOAD_URL)};
const r = await L.loadEnterprise({ resolveEE: (s) => import.meta.resolve(s), importEE: () => import('@nsasoft/nsauditor-ai-ee') });
process.stdout.write(JSON.stringify({ loaded: r.ee ? Object.keys(r.ee).sort() : null, loadError: r.loadError }));`);
    const out = spawnSync(process.execPath, [path.join(dir, 'child.mjs')], { env: withNoDotenv(), cwd: dir, encoding: 'utf8' });
    assert.equal(out.status, 0, out.stderr);
    return JSON.parse(out.stdout);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
}

test('(q1) REAL — a healthy package loads', () => {
  assert.deepEqual(inScratch({ main: 'index.mjs' }, { 'index.mjs': 'export const enrichScan = 1;' }), { loaded: ['enrichScan'], loadError: null });
});

test('(q1) REAL — no package at all is ABSENT, silent', () => {
  assert.deepEqual(inScratch(null), { loaded: null, loadError: null });
});

test('(a) REAL — the package is there and its MAIN FILE is missing (a truncated install) → a LOAD error, never absent', () => {
  const r = inScratch({ main: 'index.mjs' }, {});
  assert.equal(r.loaded, null);
  assert.ok(r.loadError, 'installed-but-broken must not read as not installed');
});

test('(a) REAL — an exports map that does not serve "." → a LOAD error, never absent', () => {
  const r = inScratch({ exports: { './other': './other.mjs' } }, { 'other.mjs': 'export const x = 1;' });
  assert.ok(r.loadError);
});

test('(a) REAL — an exports map that serves its manifest but not "." → a LOAD error, never absent', () => {
  const r = inScratch({ exports: { './package.json': './package.json' } }, {});
  assert.ok(r.loadError);
});

// ── THROUGH THE SHIPPED SCAN PATH ─────────────────────────────────────────────────────────────────────
import { main } from '../cli.mjs';

async function scan(outRoot, hooks) {
  const savedArgv = process.argv;
  const saved = { SCAN_OUT_PATH: process.env.SCAN_OUT_PATH, OPENAI_OUT_PATH: process.env.OPENAI_OUT_PATH, NSA_ALLOW_ALL_HOSTS: process.env.NSA_ALLOW_ALL_HOSTS };
  const origLog = console.log; const origErr = console.error;
  const out = []; const err = [];
  try {
    delete process.env.OPENAI_OUT_PATH;
    process.env.SCAN_OUT_PATH = outRoot;
    process.env.NSA_ALLOW_ALL_HOSTS = '1';
    process.argv = ['node', 'cli', 'scan', '--host', '127.0.0.1', '--plugins', '003', '--ports', '1-2', '--parallel', '1'];
    console.log = (...a) => { out.push(a.map(String).join(' ')); };
    console.error = (...a) => { err.push(a.map(String).join(' ')); };
    await main(hooks);
  } finally {
    console.log = origLog; console.error = origErr;
    process.argv = savedArgv;
    for (const [k, v] of Object.entries(saved)) { if (v == null) delete process.env[k]; else process.env[k] = v; }
  }
  const dir = fs.readdirSync(outRoot).find((n) => n.startsWith('127.0.0.1_'));
  const raw = JSON.parse(fs.readFileSync(path.join(outRoot, dir, 'scan_conclusion_raw.json'), 'utf8'));
  return { out, err, raw };
}

test('THROUGH main(): Enterprise installed but failing to load → stderr NAMES it, and the written raw carries conclusion.result.eeLoadError', async () => {
  const outRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-eeload-'));
  try {
    const { err, raw } = await scan(outRoot, { importEE: async () => { throw belowFloor(); } });
    assert.ok(err.some((l) => /\[EE\] Enterprise is installed but FAILED TO LOAD/.test(l) && /isUdpTransport/.test(l)), err.join('\n'));
    assert.match(raw.conclusion?.result?.eeLoadError ?? '', /does not provide an export named 'isUdpTransport'/);
    assert.equal(raw.conclusion?.result?.eeEnrichmentError, undefined, 'a load failure is not an enrichment failure — enrichment never started');
  } finally { fs.rmSync(outRoot, { recursive: true, force: true }); }
});

test('THROUGH main(): Enterprise NOT installed → silent: no [EE] line and no eeLoadError', async () => {
  const outRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-eeload-'));
  try {
    const { err, raw } = await scan(outRoot, { resolveEE: () => { throw notFound(); }, importEE: async () => { throw notFound(); } });
    assert.deepEqual(err.filter((l) => /\[EE\]/.test(l)), []);
    assert.equal(raw.conclusion?.result?.eeLoadError, undefined);
  } finally { fs.rmSync(outRoot, { recursive: true, force: true }); }
});
