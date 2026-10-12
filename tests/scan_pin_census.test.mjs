// tests/scan_pin_census.test.mjs
// ─────────────────────────────────────────────────────────────────────────────
// WHAT THE SCAN-TARGET PIN CANNOT SEE, ENUMERATED — DENY BY DEFAULT (EE 2.0.0, R1b; the architect seat's amended shape B).
//
// utils/scan_pin.mjs pins every in-process resolution through node:dns `lookup`. Two things sit outside it by construction:
// a SUBPROCESS (curl, ping, nmap … resolve through the OS) and the DNS PROTOCOL (`dns.resolve*`, `reverse`, a Resolver —
// never getaddrinfo). Every file under plugins/ and utils/ that imports child_process or a dns module (statically, through
// require, or through a dynamic import()) is DECLARED here with its pin mechanism or the reason it needs none. The commands
// each one runs are DERIVED from its source and held EQUAL to the declaration, so a new command, a new file or a removed
// one fails this file: incompleteness costs noise, not silence. A third-party package a plugin imports is declared the same
// way, because a package that spawns or queries DNS itself would sit outside both the pin and this source walk.
//
// ⚠️ THE CALLS ARE DERIVED FROM EACH FILE'S OWN IMPORTS, NEVER FROM A LIST OF LIKELY NAMES. Two earlier cuts of this census
// went silent on what they did not list: the first read only literal arguments and missed ping_checker's `const cmd =
// "ping"` (the driven subprocess leg found it still handed the NAME under the pin); the second matched calls against a
// fixed set of function names, so an aliased import (`execFile as run`), a namespace call (`cp.spawn(…)`) or a promisified
// alias under any other name was invisible — found by its own mutation battery, whose planted import changed nothing. A
// first argument it cannot bind, and an import with no call it can derive, are reported, never dropped.
//
// Its scope: this repository's own plugins/ and utils/. Enterprise's plugins are walked by the twin census in that repo.
// ─────────────────────────────────────────────────────────────────────────────
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const SUBPROCESS_TEST = fs.readFileSync(path.join(ROOT, 'tests', 'scan_pin_subprocess.test.mjs'), 'utf8');

const PINNED = 'pinned: handed the address';
const NOT_A_CONNECT = 'an availability probe for the binary, never a connect to the target';
const LITERAL_ONLY = 'runs only when the host string is itself a private IP LITERAL (isPrivateLike(host)) — a literal has nothing to pin';
/** Declared: file → the commands it runs (pinned, or excused), first arguments it passes unbound, and its DNS-protocol use. */
const DECLARED = {
  'plugins/http_probe.mjs': { commands: { curl: 'pinned: --resolve <name>:80:<address> keeps the Host header' } },
  'plugins/host_up_check.mjs': { commands: { ping: PINNED } },
  'plugins/ping_checker.mjs': { commands: { ping: PINNED, nping: PINNED, hping3: PINNED, arp: LITERAL_ONLY } },
  'plugins/arp_scanner.mjs': { commands: { arp: LITERAL_ONLY } },
  'plugins/syn_scanner.mjs': { commands: { nmap: PINNED, where: NOT_A_CONNECT, command: NOT_A_CONNECT } },
  'plugins/tls_scanner.mjs': { dnsProtocol: 'a PTR lookup (reverse) of an address the scan already holds — never a connect' },
  'plugins/060_dns_sec_auditor.mjs': { dnsProtocol: 'DNS posture of the DOMAIN (resolve*) — it never connects to the target' },
  'utils/keychain.mjs': {
    unbound: { cmd: 'the parameter of its own exec(cmd, args) wrapper; every caller passes the literal security (the macOS Keychain — never the network)' },
  },
  'utils/net_validation.mjs': { why: 'the CHECK itself: it resolves the target to produce the answers the scan is pinned to' },
  'utils/scan_pin.mjs': { why: 'the pin' },
  'utils/validate.mjs': { why: 'the doctor command\'s resolver health check (localhost by default) — not a scan' },
};
/** Declared: every third-party package a plugin imports, and why it cannot carry the target name past the pin. */
const THIRD_PARTY = {
  dnssd: 'multicast service discovery on the local link — sends to the mDNS group, never to a resolved name',
  mdns: 'multicast service discovery through the system daemon — no target name',
  'multicast-dns': 'multicast service discovery on the local link — no target name',
  'node-upnp-utils': 'SSDP multicast; a description URL is fetched only on the answering device\'s own address (upnp_scanner)',
  'node-fetch': 'built on node:http(s) — its connect resolves through the pinned lookup',
  'snmp-native': 'built on node:dgram (socket.send to the host) — resolves through the pinned lookup',
  xml2js: 'an XML parser — no network',
};

const stripComments = (src) => src.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:])\/\/[^\n]*/g, '$1');
const importOf = (mod) => new RegExp(String.raw`(?:from|import\(|require\()\s*['"\`](?:node:)?${mod}['"\`]`);
const CHILD_PROCESS = importOf('child_process');
const DNS_IMPORT = importOf(String.raw`dns(?:\/promises)?`);
const BUILTINS = new Set(['fs', 'fs/promises', 'path', 'url', 'net', 'tls', 'http', 'https', 'dgram', 'crypto', 'util', 'os', 'events', 'stream', 'zlib', 'dns', 'dns/promises', 'child_process', 'module', 'async_hooks', 'buffer', 'readline', 'timers', 'timers/promises']);

const CP_SPEC = String.raw`['"\`](?:node:)?child_process['"\`]`;
const CP_FUNCS = String.raw`(?:execFile|execFileSync|spawn|spawnSync|exec|execSync|fork)`;
const esc = (id) => id.replace(/\$/g, '\\$');

/**
 * The local names a source binds to child_process — DERIVED from its own imports, never from a list of likely names: named
 * imports and their aliases (`execFile as run`), a namespace (`import cp`, `import * as cp`, require, dynamic import), and
 * every `const` that holds one without calling it (`promisify(execFile)`, `opts._execFile ?? execFileAsync`, `cp.execFile`).
 */
export function childProcessNamesIn(src) {
  const names = new Set(); const receivers = new Set();
  const named = (list) => { for (const part of list.split(',')) { const m = /^\s*([\w$]+)(?:\s*(?:as|:)\s*([\w$]+))?\s*$/.exec(part); if (m) names.add(m[2] ?? m[1]); } };
  for (const m of src.matchAll(new RegExp(String.raw`\bimport\s*\{([^}]*)\}\s*from\s*${CP_SPEC}`, 'g'))) named(m[1]);
  for (const m of src.matchAll(new RegExp(String.raw`\bimport\s+([\w$]+)\s*(?:,\s*\{([^}]*)\})?\s*from\s*${CP_SPEC}`, 'g'))) { receivers.add(m[1]); if (m[2]) named(m[2]); }
  for (const m of src.matchAll(new RegExp(String.raw`\bimport\s*\*\s*as\s+([\w$]+)\s+from\s*${CP_SPEC}`, 'g'))) receivers.add(m[1]);
  for (const m of src.matchAll(new RegExp(String.raw`\b(?:const|let|var)\s*\{([^}]*)\}\s*=\s*(?:await\s+import|require)\(\s*${CP_SPEC}\s*\)`, 'g'))) named(m[1]);
  for (const m of src.matchAll(new RegExp(String.raw`([\w$]+)\s*=\s*(?:await\s+import|require)\(\s*${CP_SPEC}\s*\)`, 'g'))) receivers.add(m[1]);
  for (let grew = true; grew;) {
    grew = false;
    for (const m of src.matchAll(/\b(?:const|let|var)\s+([\w$]+)\s*=\s*([^;\n]+)/g)) {
      if (names.has(m[1]) || receivers.has(m[1])) continue;
      const holds = [...names].some((n) => new RegExp(String.raw`(?<![\w$.])${esc(n)}(?![\w$]|\s*\()`).test(m[2]))
        || [...receivers].some((r) => new RegExp(String.raw`(?<![\w$.])${esc(r)}\.${CP_FUNCS}(?![\w$]|\s*\()`).test(m[2]));
      if (holds) { names.add(m[1]); grew = true; }
    }
  }
  return { names, receivers };
}

/**
 * The commands a source runs, and what it passes that cannot be derived. A literal first argument is a command; a name is
 * looked up in `const|let|var <name> = …` and contributes every literal there, except one compared with ===/!==
 * (`process.platform === "win32" ? "where" : "command"` runs where and command, never win32). A name with no such binding,
 * or bound to an expression with no literal, is reported — and so is a file that imports child_process with no call derived.
 */
export function commandsIn(src) {
  const commands = new Set(); const unbound = new Set();
  const { names, receivers } = childProcessNamesIn(src);
  const callees = [...[...names].map(esc), ...[...receivers].map((r) => String.raw`${esc(r)}\.${CP_FUNCS}`)];
  let calls = 0;
  if (callees.length > 0) {
    const CALL = new RegExp(String.raw`(?<![.\w$])(?:${callees.join('|')})\s*\(\s*(?:(['"\`])([\w.-]+)\1|([A-Za-z_$][\w$]*))?`, 'g');
    for (const m of src.matchAll(CALL)) {
      calls += 1;
      if (m[2]) { commands.add(m[2]); continue; }
      const id = m[3];
      if (!id) { unbound.add('<a first argument that is neither a literal nor a name>'); continue; }
      const bindings = [...src.matchAll(new RegExp(String.raw`\b(?:const|let|var)\s+${esc(id)}\s*=\s*([^;\n]+)`, 'g'))];
      if (bindings.length === 0) { unbound.add(id); continue; }
      for (const b of bindings) {
        const literals = [...b[1].matchAll(/(!==?|===?)?\s*(['"`])([\w.-]+)\2/g)].filter((lit) => !lit[1]).map((lit) => lit[3]);
        if (literals.length === 0) unbound.add(id);   // bound to an expression, not a literal: reported, never silently dropped
        for (const lit of literals) commands.add(lit);
      }
    }
  }
  if (CHILD_PROCESS.test(src) && calls === 0) unbound.add('<child_process imported, no call derived>');
  return { commands, unbound };
}

/**
 * Whether a source speaks the DNS PROTOCOL: `resolve*`, `reverse` or a `Resolver`, reached through the name the dns module
 * is BOUND to in that file (default, namespace, require, dynamic import) or imported by name. Bound, so `path.resolve` and
 * `Promise.resolve` are not DNS.
 */
export function dnsProtocolIn(src) {
  const DNS = String.raw`['"\`](?:node:)?dns(?:\/promises)?['"\`]`;
  const PROTOCOL = String.raw`(?:resolve[A-Za-z0-9]*|reverse|Resolver)\b`;
  const bound = [
    ...src.matchAll(new RegExp(String.raw`\bimport\s+(?:\*\s+as\s+)?([\w$]+)\s*(?:,\s*\{[^}]*\})?\s*from\s*${DNS}`, 'g')),
    ...src.matchAll(new RegExp(String.raw`([\w$]+)\s*=\s*(?:await\s+import|require)\(\s*${DNS}\s*\)`, 'g')),
  ].map((m) => m[1]);
  if (bound.some((b) => new RegExp(String.raw`(?<![\w$.])${b.replace(/\$/g, '\\$')}\.(?:promises\.)?${PROTOCOL}`).test(src))) return true;
  return [...src.matchAll(new RegExp(String.raw`\{([^}]*)\}\s*from\s*${DNS}`, 'g'))].some((m) => new RegExp(String.raw`(?:^|[\s,])(?:promises|${PROTOCOL})`).test(m[1]));
}

/** Third-party specifiers a source imports (static, require, dynamic), builtins and relative paths excluded. */
export function thirdPartyIn(src) {
  const out = new Set();
  for (const m of src.matchAll(/(?:^|[;\n])\s*import\s+(?:[\w$*{}\s,]+\s+from\s+)?(['"])([^'"]+)\1|\bimport\(\s*(['"])([^'"]+)\3\s*\)|\brequire\(\s*(['"])([^'"]+)\5\s*\)/g)) {
    const spec = m[2] ?? m[4] ?? m[6];
    if (spec.startsWith('.') || spec.startsWith('node:') || BUILTINS.has(spec)) continue;
    out.add(spec.startsWith('@') ? spec.split('/').slice(0, 2).join('/') : spec.split('/')[0]);
  }
  return out;
}

function sourcesUnder(dir) {
  return fs.readdirSync(path.join(ROOT, dir)).filter((n) => n.endsWith('.mjs')).sort()
    .map((n) => ({ rel: `${dir}/${n}`, src: stripComments(fs.readFileSync(path.join(ROOT, dir, n), 'utf8')) }));
}

function census() {
  const found = {};
  for (const { rel, src } of [...sourcesUnder('plugins'), ...sourcesUnder('utils')]) {
    const cp = CHILD_PROCESS.test(src);
    const dnsImport = DNS_IMPORT.test(src);
    if (!cp && !dnsImport) continue;
    const { commands, unbound } = cp ? commandsIn(src) : { commands: new Set(), unbound: new Set() };
    found[rel] = { commands: [...commands].sort(), unbound: [...unbound].sort(), dnsProtocol: dnsImport && dnsProtocolIn(src), src };
  }
  return found;
}

test('(c1, first) the derivation reads every shape — an aliased or namespace import, a literal, a bound variable, a dynamic import — and nothing else', () => {
  const P = 'import { execFile } from "node:child_process"; const execFileP = promisify(execFile);\n';
  const cmds = (body, prefix = P) => [...commandsIn(prefix + body).commands].sort();
  const unbound = (body, prefix = P) => [...commandsIn(prefix + body).unbound].sort();
  // FOURTH QUADRANT FIRST — the shapes a name list misses: an ALIASED import, a NAMESPACE, a destructured dynamic import.
  assert.deepEqual(cmds('', 'import { execFile as run } from "node:child_process";\nrun("dig", [host]);'), ['dig'], 'an aliased import');
  assert.deepEqual(cmds('', 'import cp from "node:child_process";\ncp.spawn("traceroute", [host]);'), ['traceroute'], 'a namespace import');
  assert.deepEqual(cmds('', 'const { spawn: go } = await import("node:child_process");\ngo("mtr", [host]);'), ['mtr'], 'a destructured dynamic import');
  assert.deepEqual(cmds('', 'import * as cp from "child_process";\nconst run = cp.execFile;\nrun("whois", [host]);'), ['whois'], 'a namespace member held in a const');
  assert.deepEqual(unbound('', 'import { execFile } from "node:child_process";\nconst fn = execFile;'), ['<child_process imported, no call derived>'], 'an import with no call derived is reported');
  // The shapes the plugins use today.
  assert.deepEqual(cmds('await execFileP(\n  "nping",\n  [host])'), ['nping'], 'a literal across lines');
  assert.deepEqual(cmds('const cmd = "ping";\nawait execFileP(cmd, [host]);'), ['ping'], 'a command held in a const');
  assert.deepEqual(cmds('const cmd = process.platform === "win32" ? "where" : "command"; execFileP(cmd, a);'), ['command', 'where']);
  assert.deepEqual(unbound('function run(tool) { return execFile(tool, [host]); }'), ['tool'], 'an unbindable argument is reported');
  assert.deepEqual(unbound('const cmd = opts.bin ?? DEFAULT_BIN; execFile(cmd, a);'), ['cmd'], 'a variable bound to an EXPRESSION is reported, not dropped');
  assert.deepEqual(cmds('const m = /x/.exec(s); const x = "ping"; fetch(x); execFileP("arp", []);'), ['arp'], 'a RegExp .exec and a non-command string are not commands');
  assert.deepEqual(cmds('const { stdout } = await execFileP("arp", []); const out = await execFileP("ping", []);'), ['arp', 'ping'], 'a call\'s RESULT held in a const is not an alias');
  assert.ok(DNS_IMPORT.test('const d = await import("node:dns/promises");') && CHILD_PROCESS.test("require('child_process')"), 'dynamic import and require are imports');
  assert.ok(dnsProtocolIn('import dns from "node:dns/promises"; await dns.reverse(ip);'), 'a bound default import');
  assert.ok(dnsProtocolIn('mod = await import("node:dns/promises"); const r = new mod.Resolver();'), 'a dynamic import assigned, then a Resolver');
  assert.ok(dnsProtocolIn('import { resolveTxt } from "dns";'), 'a named import');
  assert.ok(!dnsProtocolIn('import dnsP from "node:dns/promises"; dnsP.lookup(h); path.resolve(a); Promise.resolve(1);'), 'lookup, path.resolve and Promise.resolve are not the DNS protocol');
  assert.deepEqual([...thirdPartyIn('import a from "snmp-native";\nconst b = await import(\'mdns\');\nimport x from "./y.mjs"; import n from "node:net";')].sort(), ['mdns', 'snmp-native']);
});

test('every file under plugins/ and utils/ that imports child_process or a dns module is DECLARED, and every declaration still has its trigger', () => {
  const found = census();
  assert.ok(Object.keys(found).length >= 8, `the census found ${Object.keys(found).length} files — the walk is broken`);
  assert.deepEqual(Object.keys(found).sort(), Object.keys(DECLARED).sort(),
    'a file reaches the OS resolver, a subprocess or the DNS protocol without a declared pin mechanism (or a declared one no longer does)');
});

test('each file\'s DERIVED commands and unbound arguments equal its declaration — a new command fails until it is pinned or excused', () => {
  for (const [rel, f] of Object.entries(census())) {
    assert.deepEqual(f.commands, Object.keys(DECLARED[rel].commands ?? {}).sort(), `${rel}: derived commands ${JSON.stringify(f.commands)}`);
    assert.deepEqual(f.unbound, Object.keys(DECLARED[rel].unbound ?? {}).sort(), `${rel}: a command passed through ${JSON.stringify(f.unbound)} cannot be derived`);
    assert.equal(f.dnsProtocol, Boolean(DECLARED[rel].dnsProtocol), `${rel}: DNS-protocol use derived ${f.dnsProtocol}, declared ${Boolean(DECLARED[rel].dnsProtocol)}`);
  }
});

test('every command declared PINNED reads the pin in its plugin, and is exercised by the driven subprocess leg', () => {
  const shims = new Set((/for \(const cmd of \[([^\]]*)\]\)/.exec(SUBPROCESS_TEST)?.[1] ?? '').match(/[\w.-]+/g) ?? []);
  assert.ok(shims.size >= 3, 'could not read the stand-in list of tests/scan_pin_subprocess.test.mjs');
  const found = census();
  let pinned = 0;
  for (const [rel, d] of Object.entries(DECLARED)) {
    for (const [cmd, how] of Object.entries(d.commands ?? {})) {
      if (!how.startsWith('pinned')) continue;
      pinned += 1;
      assert.ok(found[rel].src.includes('pinnedAddressFor('), `${rel} declares ${cmd} pinned but never reads the pin`);
      assert.ok(shims.has(cmd), `${cmd} is declared pinned in ${rel} but no stand-in in the subprocess leg exercises it`);
    }
  }
  assert.equal(pinned, 6, 'the pinned-command count moved — re-read the declaration');
});

test('every third-party package a plugin imports is DECLARED with why it cannot carry the target name past the pin', () => {
  const imported = new Set(sourcesUnder('plugins').flatMap(({ src }) => [...thirdPartyIn(src)]));
  assert.ok(imported.size >= 3, 'the walk found almost no third-party imports — it is broken');
  assert.deepEqual([...imported].sort(), Object.keys(THIRD_PARTY).sort(), 'a plugin imports an undeclared package (or a declared one is gone)');
});
