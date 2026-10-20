import './helpers/no_operator_dotenv.mjs';
import './helpers/no_operator_keychain.mjs';   // FIRST: the driven legs below load a licence through main()
import assert from 'node:assert/strict';
import test from 'node:test';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
// The REAL guard, through the namespace so a missing export fails its own legs. Until 1.3.0 this
// file tested `applySsrfGuard`, a verbatim COPY of the guard ("we replicate the exact logic"), so
// no edit to cli.mjs could turn it red — and the copy carried the literal-skip regex that let
// '6425673729' (the OS reads it as 127.0.0.1) through unresolved.
import * as cli from '../cli.mjs';
import { main } from '../cli.mjs';

// ⚠️ A HARNESS THAT PROBES THE NETWORK IS A SCANNER. Names are answered by a stubbed dns.lookup on
// the object net_validation.mjs imports; this file used to resolve dns.google, localhost, azurex and
// aws-foo for real. No spelling under test reaches getaddrinfo or a socket.
async function withResolver(table, fn) {
  const dns = (await import('node:dns/promises')).default;
  const orig = dns.lookup;
  const calls = [];
  dns.lookup = async (name, opts) => {
    calls.push(name);
    const raw = table[name];
    if (raw === undefined) { const e = new Error(`getaddrinfo ENOTFOUND ${name}`); e.code = 'ENOTFOUND'; throw e; }
    const list = [].concat(raw).map((address) => ({ address, family: address.includes(':') ? 6 : 4 }));
    return opts && opts.all ? list : list[0];
  };
  try { return await fn(calls); } finally { dns.lookup = orig; }
}
const UNSET = {};
const SET = { NSA_ALLOW_ALL_HOSTS: '1' };
const guard = (host, env = UNSET) => cli.assertScanTargetAllowed(host, env);

// ── FOURTH QUADRANT FIRST: what must keep passing.
test('(fourth quadrant, first) a public literal and a public name pass with the variable unset', async () => {
  assert.equal(typeof cli.assertScanTargetAllowed, 'function', 'cli.mjs does not export its scan-target guard');
  await withResolver({ 'dns.google': '8.8.8.8' }, async () => {
    await guard('8.8.8.8');
    await guard('dns.google');
  });
});

test('(fourth quadrant) NSA_ALLOW_ALL_HOSTS=1 lifts the WHOLE CLI guard — loopback and private pass (documented: README "on the CLI the whole guard")', async () => {
  await withResolver({}, async (calls) => {
    await guard('127.0.0.1', SET);
    await guard('10.0.0.1', SET);
    assert.equal(calls.length, 0, 'with the guard lifted nothing is resolved');
  });
});

test('(fourth quadrant) the cloud sentinels pass, any case, and are never resolved', async () => {
  await withResolver({}, async (calls) => {
    for (const h of ['aws', 'gcp', 'azure', 'AWS', 'Azure', 'GCP']) await guard(h);
    assert.equal(calls.length, 0);
  });
});

// ── DEFECTS.
test('blocked literals are refused with the pinned message — loopback, metadata, RFC 1918, ::1', async () => {
  for (const h of ['127.0.0.1', '169.254.169.254', '10.0.0.1', '192.168.1.1', '::1']) {
    await assert.rejects(() => guard(h), /^Error: Scanning blocked address range is not allowed: /, h);
  }
});

test('every spelling of loopback / metadata is refused (1.3.0 E; passed at 0.2.56)', async () => {
  for (const h of ['0:0:0:0:0:0:0:1', '[0:0:0:0:0:0:0:1]', '::ffff:7f00:1', '::ffff:a9fe:a9fe', 'febf::1', '0x7f000001', '0177.0.0.1']) {
    await assert.rejects(() => guard(h), /blocked address range/, h);
  }
});

test('a digits-only string the URL parser rejects is RESOLVED, not skipped — the OS reads 6425673729 as 127.0.0.1 (1.3.0 E)', async () => {
  // It matched the old literal-skip regex /^[\d.:[\]]+$/, so the guard never resolved it, isBlockedIp
  // said "not an address", and the scan's own connect sent it to loopback.
  await withResolver({ '6425673729': '127.0.0.1' }, async (calls) => {
    await assert.rejects(() => guard('6425673729'), /SSRF guard|blocked/);
    assert.ok(calls.includes('6425673729'), 'it must be resolved, not skipped as a literal');
  });
});

test('a name is refused if ANY answer is blocked, and an unresolvable or non-sentinel cloud-shaped name is refused', async () => {
  await withResolver({ 'localhost': '127.0.0.1', 'multi.example': ['93.184.216.34', '127.0.0.1'] }, async () => {
    await assert.rejects(() => guard('localhost'), /SSRF guard/);
    await assert.rejects(() => guard('multi.example'), /SSRF guard/);
    // NOT a sentinel: resolved, ENOTFOUND — refused because it does not resolve, never passed as a cloud token.
    for (const h of ['azurex', 'aws-foo']) {
      await assert.rejects(() => guard(h), (e) => e.code === 'ETARGETUNRESOLVED' && /could not be resolved/.test(e.message), h);
    }
  });
});

test('a non-string host does not crash the sentinel check and is refused', async () => {
  await withResolver({}, async () => {
    await assert.rejects(() => guard(null), /reject|blocked|invalid|could not be resolved/i);
  });
});

// ---------------------------------------------------------------------------
// 1.3.0 lane 1 C — DRIVEN through the real cli.mjs main(), not the mirror above: only an explicit
// truthy word lifts the CLI guard. Before 1.3.0, `NSA_ALLOW_ALL_HOSTS=0` and `=false` lifted it,
// because the check was plain truthiness. LOOPBACK ONLY: plugin 003 against 127.0.0.1 ports 1-2.
// ---------------------------------------------------------------------------
async function driveScan(host, allowValue) {
  const outRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-cli-ssrf-'));
  const savedArgv = process.argv;
  const saved = { SCAN_OUT_PATH: process.env.SCAN_OUT_PATH, OPENAI_OUT_PATH: process.env.OPENAI_OUT_PATH, NSA_ALLOW_ALL_HOSTS: process.env.NSA_ALLOW_ALL_HOSTS };
  try {
    delete process.env.OPENAI_OUT_PATH;
    process.env.SCAN_OUT_PATH = outRoot;
    if (allowValue === undefined) delete process.env.NSA_ALLOW_ALL_HOSTS; else process.env.NSA_ALLOW_ALL_HOSTS = allowValue;
    process.argv = ['node', 'cli', 'scan', '--host', host, '--plugins', '003', '--ports', '1-2'];
    const notInstalled = () => { throw Object.assign(new Error("Cannot find package '@nsasoft/nsauditor-ai-ee'"), { code: 'ERR_MODULE_NOT_FOUND' }); };
    try { await main({ importEE: async () => { throw new Error('injected: EE not installed'); }, resolveEE: notInstalled }); return null; } catch (e) { return e; }
  } finally {
    process.argv = savedArgv;
    for (const [k, v] of Object.entries(saved)) { if (v == null) delete process.env[k]; else process.env[k] = v; }
    fs.rmSync(outRoot, { recursive: true, force: true });
  }
}

test('(fourth quadrant, first) C: NSA_ALLOW_ALL_HOSTS="true" still lifts the CLI guard — a loopback scan completes', async () => {
  assert.equal(await driveScan('127.0.0.1', 'true'), null);
});

// ── (h): a refused target is an OPERATOR error, coded — exit 2 and one [ERROR] line, never a stack ─────────────────
test('a refused scan target carries a code — the literal refusal and the name refusal both, each message unchanged', async () => {
  const literal = await guard('127.0.0.1').then(() => null, (e) => e);
  assert.deepEqual([literal?.code, literal?.message], ['ETARGETREFUSED', 'Scanning blocked address range is not allowed: 127.0.0.1']);
  await withResolver({ 'lan.example': '10.0.0.1' }, async () => {
    const lan = await guard('lan.example').then(() => null, (e) => e);
    assert.equal(lan?.code, 'ETARGETREFUSED');
    assert.match(lan.message, /^Host rejected by SSRF guard: /);
    // A name that does not resolve was never REFUSED by the guard: it has its own code (below).
  });
});
// ── (m)/(au): a target that does not RESOLVE is refused for that reason — with or without NSA_ALLOW_ALL_HOSTS ─────────
// The override admits every address range; it never made an unresolved name scannable, which then ran UNPINNED, each plugin
// resolving the name on its own. MCP already refused it.
test('(fourth quadrant, first) under NSA_ALLOW_ALL_HOSTS a name that resolves is still returned with its answers — pinned', async () => {
  await withResolver({ 'lan.example': '10.0.0.5' }, async () => {
    assert.deepEqual(await guard('lan.example', SET), [{ address: '10.0.0.5', family: 4 }]);
  });
});
test('a name that does not resolve is ETARGETUNRESOLVED in BOTH arms — and the message never says a guard refused it', async () => {
  await withResolver({}, async () => {
    for (const env of [UNSET, SET]) {
      const err = await guard('nowhere.example', env).then(() => null, (e) => e);
      assert.equal(err?.code, 'ETARGETUNRESOLVED', JSON.stringify(env));
      assert.match(err.message, /^Host could not be resolved: nowhere\.example \(ENOTFOUND\) — /);
      assert.doesNotMatch(err.message, /guard|SSRF|refused|rejected|blocked/i);
    }
  });
});
test('a name that resolves to a BLOCKED address is still ETARGETREFUSED — the guard did refuse that one', async () => {
  await withResolver({ 'lan.example': '10.0.0.1' }, async () => {
    const err = await guard('lan.example').then(() => null, (e) => e);
    assert.equal(err?.code, 'ETARGETREFUSED');
  });
});
test('through the real main() under NSA_ALLOW_ALL_HOSTS: an unresolvable name is refused before any plugin runs, exit 2 and one line', async () => {
  const err = await withResolver({}, () => driveScan('nowhere.example', '1'));
  assert.equal(err?.code, 'ETARGETUNRESOLVED', String(err?.stack ?? err));
  const lines = []; const exits = [];
  cli.exitOnMainRejection(err, { error: (x) => lines.push(String(x)), exit: (c) => exits.push(c) });
  assert.equal(exits[0], 2);
  assert.equal(lines.length, 1);
  assert.match(lines[0], /^\[ERROR\] Host could not be resolved: nowhere\.example \(ENOTFOUND\) — /);
});

test('through the real main(): a refused target reaches the rejection handler as exit 2 and one [ERROR] line', async () => {
  const err = await driveScan('127.0.0.1', undefined);
  const lines = []; const exits = [];
  cli.exitOnMainRejection(err, { error: (x) => lines.push(String(x)), exit: (c) => exits.push(c) });
  assert.deepEqual({ lines, exits }, { lines: ['[ERROR] Scanning blocked address range is not allowed: 127.0.0.1'], exits: [2] });
});

test('C: "0", "false", "no" and "off" do NOT lift the CLI guard — loopback is refused', async () => {
  for (const v of ['0', 'false', 'no', 'off']) {
    const err = await driveScan('127.0.0.1', v);
    assert.match(String(err && err.message), /blocked address range/, `NSA_ALLOW_ALL_HOSTS=${v} must not lift the guard`);
  }
});
