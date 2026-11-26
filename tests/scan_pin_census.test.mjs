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
// Its scope: this repository's plugins/, utils/ and its root *.mjs (cli, index, mcp_server, plugin_manager — the root was
// unwalked until the architect seat's R1b read: a root file gaining a spawn would have been invisible). Enterprise's files
// are walked by the twin census in that repo.
// ─────────────────────────────────────────────────────────────────────────────
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const SUBPROCESS_TEST = fs.readFileSync(path.join(ROOT, 'tests', 'scan_pin_subprocess.test.mjs'), 'utf8');

const PINNED = 'pinned: handed the address';
const NOT_A_CONNECT = 'an availability probe for the binary, never a connect to the target';
/** Declared: file → the commands it runs (pinned, or excused), first arguments it passes unbound, and its DNS-protocol use. */
const DECLARED = {
  'plugins/http_probe.mjs': { commands: { curl: 'pinned: --resolve <name>:80:<address> keeps the Host header' } },
  'plugins/host_up_check.mjs': { commands: { ping: PINNED } },
  'plugins/ping_checker.mjs': { commands: { ping: PINNED, nping: PINNED, hping3: PINNED, arp: PINNED } },
  'plugins/arp_scanner.mjs': { commands: { arp: PINNED } },
  'plugins/syn_scanner.mjs': { commands: { nmap: PINNED, where: NOT_A_CONNECT, command: NOT_A_CONNECT } },
  'plugins/tls_scanner.mjs': { dnsProtocol: 'a PTR lookup (reverse) of an address the scan already holds — never a connect' },
  'plugins/060_dns_sec_auditor.mjs': { dnsProtocol: 'DNS posture of the DOMAIN (resolve*) — it never connects to the target; its zone-transfer attempt (opt-in, DNS_AUDIT_AXFR_CHECK) connects to the nameservers\' resolve4 answers, which it classifies itself (outside the pin)' },
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
  'node-upnp-utils': {
    why: 'SSDP multicast; a description URL is fetched only on the answering device\'s own address (upnp_scanner). The version and witnesses below are read off the INSTALLED tree (1.0.3 in this checkout); package.json declares ^1.0.3, so a customer install may resolve a later 1.x whose request sites nobody read (G-20)',
    declared: '^1.0.3',
    agent: 'absent = global pool — its description fetch, mHttp.request(url, { method: \'GET\' }) in lib/upnp-utils-dd.js, passes no agent: http.globalAgent, keep-alive on. discover() reaches it for an M-SEARCH answer whose LOCATION host equals the sender; the body is appended with no cap inside a 1000 ms timer (G-20). Its second request site, invokeAction\'s SOAP POST (lib/upnp-utils.js), has no caller in the library and the plugin never calls it',
    version: '1.0.3',
    witness: [['lib/upnp-utils-dd.js', /req = mHttp\.request\(url, \{ method: 'GET' \}, \(res\) => \{/g, 1], ['lib/upnp-utils.js', /mHttp\.request\(/g, 1]],
    pluginMembers: ['_parseSdpResponseHeader', '_receivePacket', 'discover'],   // the plugin's own Symbol.for('nsauditor.upnp.…') keys are not members
  },
  'node-fetch': 'built on node:http(s) — its connect resolves through the pinned lookup',
  'snmp-native': 'built on node:dgram (socket.send to the host) — resolves through the pinned lookup',
  xml2js: 'an XML parser — no network',
};

// ONE left-to-right pass over comments AND strings, so each consumes its own extent: a `/*` inside a string ('*/*') or
// inside a line comment (`data/compliance/*.json`) opens nothing. The two-regex form this replaces stripped block comments
// first and ate live code in 13 of the 94 shipped files — non-whitespace characters missing against the comment ranges of
// Node's bundled acorn; 180 lines of http_probe, 517 of mcp_server — so every leg here was blind there. 12 of the 13 then
// failed node --check; the 13th, utils/raw_report_html.mjs, lost 23 characters and still parsed (the W-1 fold, architect
// v385; re-derived under v386). A block comment keeps its newlines. A regular-expression literal is read only after one of
// `= ( , : ; ! & | ? { [`, where a `/` cannot be a division (v387 R-7): there it is kept as code, so a `/*`, quote or
// backtick inside it opens nothing. Measured against the comment ranges of Node's bundled acorn: identical on 94 of the 94
// shipped files (it was 91 without the branch). Elsewhere — after `return`, `=>` or `)`, or at a line start — a regex is
// read as text: the stated limit in W-1's header, which (w1-k) watches.
const COMMENT_OR_STRING = /(?<!\\)\/\*[\s\S]*?\*\/|(?<![:\\])\/\/[^\n]*|(?<=[=(,:;!&|?{\[][ \t]*)\/(?![*\/])(?:\\[^\n]|\[(?:\\[^\n]|[^\]\\\n])*\]|[^\/\\\n\[])+\/[a-z]*|'(?:\\[\s\S]|[^'\\\n])*'|"(?:\\[\s\S]|[^"\\\n])*"|`(?:\\[\s\S]|[^`\\])*`/g;
const stripComments = (src) => src.replace(COMMENT_OR_STRING, (m) => (m.startsWith('/*') ? m.replace(/[^\n]/g, '') : m.startsWith('//') ? '' : m));
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
    .map((n) => ({ rel: dir === '.' ? n : `${dir}/${n}`, src: stripComments(fs.readFileSync(path.join(ROOT, dir, n), 'utf8')) }));
}
/** Every source the census walks: plugins/, utils/ and the root *.mjs. */
const walked = () => [...sourcesUnder('plugins'), ...sourcesUnder('utils'), ...sourcesUnder('.')];

function census() {
  const found = {};
  for (const { rel, src } of walked()) {
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

test('every file under plugins/, utils/ and the root that imports child_process or a dns module is DECLARED, and every declaration still has its trigger', () => {
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
  // MOVED DELIBERATELY 6 → 8 (board item "ARP for a pinned name"): both plugins' `arp` was LITERAL_ONLY, so a name pinned to a
  // LAN address lost ARP; each now hands `arp` the pinned address, driven by tests/scan_pin_subprocess.test.mjs (sp7).
  assert.equal(pinned, 8, 'the pinned-command count moved — re-read the declaration');
});

// The README's Security note names the system tools a scan hands a pinned address. It is the published form of this
// declaration, so it is held to it: a command declared pinned and missing there (as `arp` was) is a reader told less than
// the scan does, and a name there that nothing declares is a claim no pin backs.
test('the README names exactly the commands declared pinned', () => {
  const readme = fs.readFileSync(path.join(ROOT, 'README.md'), 'utf8');
  const m = /the system tools a scan runs \(([^)]*)\) are handed one/.exec(readme);
  assert.ok(m, 'the README sentence that lists the pinned system tools was not found');
  const listed = new Set([...m[1].matchAll(/`([\w.-]+)`/g)].map((x) => x[1]));
  const declared = new Set(Object.values(DECLARED).flatMap((d) => Object.entries(d.commands ?? {})
    .filter(([, how]) => how.startsWith('pinned')).map(([cmd]) => cmd)));
  assert.deepEqual([...listed].sort(), [...declared].sort());
});

test('every third-party package a plugin imports is DECLARED with why it cannot carry the target name past the pin', () => {
  const imported = new Set(sourcesUnder('plugins').flatMap(({ src }) => [...thirdPartyIn(src)]));
  assert.ok(imported.size >= 3, 'the walk found almost no third-party imports — it is broken');
  assert.deepEqual([...imported].sort(), Object.keys(THIRD_PARTY).sort(), 'a plugin imports an undeclared package (or a declared one is gone)');
});

/**
 * A `dgram` socket resolves through the lookup it captured when it was CREATED (measured by the architect seat on the R1b
 * read): one created at MODULE SCOPE exists before the first pinned run and sits outside the pin. Zero today; a ratchet.
 */
const MODULE_SCOPE_SOCKET = /^(?:export\s+)?(?:(?:const|let|var)\s+[\w$]+\s*=\s*)?(?:await\s+)?(?:new\s+(?:[\w$]+\.)?Session\(|(?:[\w$]+\.)?createSocket\()/m;
test('(c6) no plugin, util or root file creates a socket at MODULE scope — it would capture the lookup before any pin', () => {
  assert.ok(MODULE_SCOPE_SOCKET.test('const sock = dgram.createSocket("udp4");') && MODULE_SCOPE_SOCKET.test('export const s = new Session({ host });'),
    'positive control: a module-scope socket is seen');
  assert.ok(!MODULE_SCOPE_SOCKET.test('function f() {\n  const sock = dgram.createSocket("udp4");\n}'), 'a socket inside a function is not module scope');
  const sources = walked();
  assert.ok(sources.some(({ src }) => /createSocket\(/.test(src)), 'the walk reaches the files that create sockets — or this leg tests nothing');
  assert.deepEqual(sources.filter(({ src }) => MODULE_SCOPE_SOCKET.test(src)).map(({ rel }) => rel), []);
});

/**
 * ONE canonical form of a host name: utils/scan_pin.mjs keys the pin on it and exports it as canonicalHost. A second
 * canonicaliser agrees with it only until one of the two is edited — and they already disagree on a name domainToASCII
 * rejects (a direct call yields '', the pin's key keeps the raw name). So no other walked file calls an IDNA converter
 * (url.domainToASCII, punycode.toASCII) under any import shape. Its stated limit: a canonical form built another way —
 * the hostname of `new URL(…)` over a typed name, a hand-rolled mapping — is not a token this leg can see.
 */
const IDNA_CALL = /\b(?:domainToASCII|toASCII)\b/;
test('(c7) only utils/scan_pin.mjs converts a host name to its ASCII form — every other file goes through canonicalHost', () => {
  assert.ok(IDNA_CALL.test("import { domainToASCII as d } from 'node:url';") && IDNA_CALL.test('punycode.toASCII(h)')
    && IDNA_CALL.test("require('url').domainToASCII(h)"), 'positive control: an IDNA call is seen under each import shape');
  assert.ok(!IDNA_CALL.test('const name = canonicalHost(host);'), 'canonicalHost itself is not a second canonicaliser');
  assert.deepEqual(walked().filter(({ src }) => IDNA_CALL.test(src)).map(({ rel }) => rel), ['utils/scan_pin.mjs'],
    'a file other than utils/scan_pin.mjs canonicalises a host name — use canonicalHost');
});

// ─────────────────────────────────────────────────────────────────────────────
// W-1 (EE Z-1, architect v383; folded under v385): THE SHIPPED IMPORTERS OF node:http, https, http2, net, tls AND dgram —
// what each one pools, how it resolves, and its request sites.
//
// The pin above answers a RESOLUTION. A connection that is REUSED never resolves, so what pools — and where — decides how
// far utils/scan_pin.mjs's stated keep-alive limit reaches. Measured on Node 24.22.3: http.globalAgent and
// https.globalAgent keep connections alive by default, and a `new https.Agent()` does not. So every SHIPPED file importing
// one of those modules is DERIVED from package.json `files` and held EQUAL to a DECLARED row stating its `agent` (false |
// absent = global pool | custom, keep-alive on/off | n/a for a raw socket), its `lookup`, its `createConnection`, and a
// reason. The import is derived from the LOADER IDENTIFIER, never one call shape (netModulesIn says which). Per file the
// COUNTS of `lookup`, `agent`, `createConnection`, `Agent`, `globalAgent` and `keepAlive` are pinned by equality, COMMENTS
// INCLUDED, and for an http, https or http2 importer its request calls (`.request(`, `.get(`, a named request/get under any
// alias) plus the whole-word counts of `request`, `get` and `ClientRequest`: a new option, a new request site, a
// globalAgent mutation, or a comment gaining or losing one of those words fails here by file and token until the row is
// re-read. A row with an HTTP agent also pins a WITNESS of its option site by match
// count over its CODE (comments removed), so a value flip that keeps every token, or the option commented out, is red.
//
// What this census does NOT hold, by design: a request through global fetch (C-8's census,
// tests/fetch_redirect_policy_census.test.mjs); a subprocess (the commands table above); a third-party package's own
// sockets (THIRD_PARTY's rows — node-upnp-utils pools in http.globalAgent itself and carries a pooling statement and a
// witness over its INSTALLED request line, (w1-f)).
// Stated limits: tokens are case-sensitive and whole-word (a hyphen is a boundary, so a `user-agent` header IS counted); a
// request call through a name the count cannot bind (a method held in a variable, Reflect.apply, a request function
// passed in) moves no count — for an http, https or http2 importer the whole-word counts of `request`, `get` and
// `ClientRequest` (comments and strings included) then catch a site written with one of those words, and one written
// with none moves nothing; imports it cannot see (each of v387's five pinned in (w1-o)): a loader that is one arm of a
// conditional or logical expression (`c ? require : x`, `a ?? createRequire(u)`, `a || require`), a loader reached through a
// computed member (`process['getBuiltinModule']`), a parenthesised or comma-expression callee (`(0, require)('net')`), a
// computed or concatenated specifier (`import(name)`,
// `require('node:' + m)`), a loader passed through a parameter or an object property (`deps.load('net')`), a loader
// invoked through `.call`, `.apply` or Reflect.apply, a specifier pre-bound by `.bind(thisArg, 'net')` (the bound name
// IS a loader; its call carries no specifier), `module.constructor._load`, `process.binding`; the shipped set is read from
// package.json `files` without .npmignore, which can only REMOVE a file (an over-declared row: noise, not silence).
// stripComments reads a regular-expression literal only after `= ( , : ; ! & | ? { [`; one after `return`, `=>` or `)`, or
// at a line start, is read as text, and a quote or backtick inside it flips the string parity. That KEEPS the comments
// after it as code (the noise direction), and the silence direction is one edit further: after a flip a real template's
// text is read as code, and a `/*` inside it eats to the next `*/`. Today no shipped file is affected — identical to
// Node's bundled acorn on 94 of 94; the three files a regex used to affect (executive_report, jira_export, report_md) are
// read correctly by the branch. (w1-k) holds by equality the shipped files whose stripped text still has a line beginning
// with a comment opener, AND each one's count of such lines (two today, both `//` lines inside template literals — strings,
// correctly kept). A parse oracle (each shipped file, stripped, through node --check: 94 of 94 parse; the replaced
// two-regex form left 12 unparseable) sees code EATEN, never a comment KEPT — a kept comment parses. A `net` binding beyond
// isIP is held by a zero-count witness on each row that says so, one per binding form the file uses — a `net` namespace or
// a named import (v387 R-8, v389 R-10); any other binding form is red; limit: a destructured member of the namespace. An HTTP/1.x
// request line written by hand is held by (w1-h) (v387 R-9; limits: a request line assembled from pieces, HTTP/2).
// ─────────────────────────────────────────────────────────────────────────────

const NET_SPEC = String.raw`(?<q>['"\`])(?:node:)?(?<mod>http2|https|http|net|tls|dgram)\k<q>`;
const GAP = String.raw`(?:\s|\/\*[\s\S]*?\*\/|\/\/[^\n]*\n)*`;   // whitespace and comments between a loader and its specifier
const CALL = String.raw`${GAP}(?:\?\.${GAP})?\(`;   // a call's open paren, optionally `?.(`, comments allowed
const ID = String.raw`[\w$]+`;
const anyOf = (names) => [...names].map((n) => n.replace(/\$/g, '\\$')).join('|');
/**
 * The socket modules a source imports, read over the RAW text and keyed on the IDENTIFIER, never on one call shape (v385:
 * `_require('net')` and process.getBuiltinModule were invisible to the first cut). A LOADER is: import / import(), any
 * call ending `require(` (`_require`, `module.require`), getBuiltinModule, a name assigned from createRequire or from any
 * alias of it, a name holding a loader or a loader's `.bind(…)` (to a fixpoint, so an alias of an alias counts), and an
 * immediate `createRequire(…)(`. Every loader call may be optional, `?.(` (v386: the feature-detect spelling of
 * getBuiltinModule and a bound loader were invisible).
 */
export function netModulesIn(raw) {
  const creators = new Set(['createRequire']);
  for (const m of raw.matchAll(/\bcreateRequire\s+as\s+([\w$]+)/g)) creators.add(m[1]);
  for (const m of raw.matchAll(/\bcreateRequire\s*:\s*([\w$]+)/g)) creators.add(m[1]);
  for (const m of raw.matchAll(/([\w$]+)\s*=\s*(?:[\w$]+\.)*createRequire\b(?!\s*\()/g)) creators.add(m[1]);
  const loaders = new Set();
  for (const m of raw.matchAll(new RegExp(String.raw`(${ID})\s*=\s*(?:${ID}\.)*(?:${anyOf(creators)})${CALL}`, 'g'))) loaders.add(m[1]);
  for (const m of raw.matchAll(/\bgetBuiltinModule\s*:\s*([\w$]+)/g)) loaders.add(m[1]);
  // A name HOLDING a loader (not calling it, not a member of it, not one arm of a ternary), or holding its `.bind(…)`.
  for (let size = -1; size !== loaders.size;) {
    size = loaders.size;
    const held = String.raw`(?:getBuiltinModule|[\w$]*require${loaders.size ? `|${anyOf(loaders)}` : ''})(?![\w$])`;
    const re = new RegExp(String.raw`(${ID})\s*=\s*(?:${ID}\.)*${held}(?:${GAP}\??\.${GAP}bind${CALL}|(?!${GAP}[(.?]))`, 'g');
    for (const m of raw.matchAll(re)) loaders.add(m[1]);
  }
  const shapes = [
    String.raw`(?:\bfrom|\bimport${GAP}\(|require${CALL}|getBuiltinModule${CALL})${GAP}${NET_SPEC}`,
    String.raw`\bimport${GAP}${NET_SPEC}`,
    String.raw`(?:${anyOf(creators)})${CALL}[^()]*(?:\([^()]*\)[^()]*)*\)${CALL}${GAP}${NET_SPEC}`,
  ];
  if (loaders.size > 0) shapes.push(String.raw`(?<![\w$.])(?:${anyOf(loaders)})${CALL}${GAP}${NET_SPEC}`);
  const out = new Set();
  for (const shape of shapes) for (const m of raw.matchAll(new RegExp(shape, 'g'))) out.add(m.groups.mod);
  return [...out].sort();
}
const COUNTED_TOKENS = ['lookup', 'agent', 'createConnection', 'Agent', 'globalAgent', 'keepAlive'];
/** The count of each counted token in the RAW text (comments included): whole-word, `$` and `_` joining. */
export function connectionTokensIn(raw) {
  const count = (t) => (raw.match(new RegExp(String.raw`(?<![\w$])${t}(?![\w$])`, 'g')) ?? []).length;
  return Object.fromEntries(COUNTED_TOKENS.map((t) => [t, count(t)]));
}
/**
 * The request calls of an http, https or http2 importer, over the RAW text: every `.request(` and `.get(`, plus a call of
 * a name bound to request or get by a named import or a destructured require/import/getBuiltinModule, under any alias.
 */
export function httpCallsIn(raw) {
  const HTTP_SPEC = String.raw`['"\`](?:node:)?(?:http2|https|http)['"\`]`;
  const names = { request: new Set(), get: new Set() };
  const named = (list) => { for (const part of list.split(',')) { const m = /^\s*(request|get)(?:\s*(?:as|:)\s*([\w$]+))?\s*$/.exec(part); if (m) names[m[1]].add(m[2] ?? m[1]); } };
  for (const m of raw.matchAll(new RegExp(String.raw`\bimport\s*\{([^}]*)\}\s*from\s*${HTTP_SPEC}`, 'g'))) named(m[1]);
  for (const m of raw.matchAll(new RegExp(String.raw`\{([^}]*)\}\s*=\s*(?:await\s+import|[\w$.]*require|[\w$.]*getBuiltinModule)\s*\(\s*${HTTP_SPEC}\s*\)`, 'g'))) named(m[1]);
  const count = (re) => (raw.match(re) ?? []).length;
  const calls = (key) => count(new RegExp(String.raw`\.${key}\s*\(`, 'g'))
    + [...names[key]].reduce((n, id) => n + count(new RegExp(String.raw`(?<![\w$.])${id.replace(/\$/g, '\\$')}\s*\(`, 'g')), 0);
  return { request: calls('request'), get: calls('get') };
}
const HTTP_WORDS = ['request', 'get', 'ClientRequest'];
/**
 * The request WORDS of an http, https or http2 importer, over the RAW text: whole-word `request`, `get` and `ClientRequest`,
 * comments and strings included (v386: a request site the call count cannot bind — `const { request: s } = https`,
 * `new http.ClientRequest`, `http['request']` held in a const — moved no count).
 */
export function httpWordsIn(raw) {
  const count = (t) => (raw.match(new RegExp(String.raw`(?<![\w$])${t}(?![\w$])`, 'g')) ?? []).length;
  return Object.fromEntries(HTTP_WORDS.map((t) => [t, count(t)]));
}

test('(w1, first) the importer derivation reads every import shape, comments included, and no look-alike; the token count is whole-word with comments', () => {
  // FOURTH QUADRANT FIRST — the positive scope: every shape a customer-shipped file could use to reach a socket module.
  assert.deepEqual(netModulesIn("import http from 'node:http';"), ['http'], 'a default import');
  assert.deepEqual(netModulesIn('import * as tls from "tls";'), ['tls'], 'a namespace import without node:');
  assert.deepEqual(netModulesIn("import { request } from 'node:https';"), ['https'], 'a named import');
  assert.deepEqual(netModulesIn("const net = require ( 'net' );"), ['net'], 'a require, spaced');
  assert.deepEqual(netModulesIn('const h2 = await import("node:http2");'), ['http2'], 'a dynamic import');
  assert.deepEqual(netModulesIn("const { createSocket } = await import('dgram');"), ['dgram'], 'a destructured dynamic import');
  assert.deepEqual(netModulesIn('const https = await import(`node:https`);'), ['https'], 'a template-literal specifier');
  assert.deepEqual(netModulesIn("import 'node:net';"), ['net'], 'a side-effect import');
  assert.deepEqual(netModulesIn("export { connect } from 'node:tls';"), ['tls'], 'a re-export');
  assert.deepEqual(netModulesIn("// import http from 'node:http'"), ['http'], 'a COMMENTED import counts: noise, never silence');
  assert.deepEqual(netModulesIn("import a from 'node:http'; import b from 'node:https';\nimport c from 'node:net';"), ['http', 'https', 'net']);
  // The veto: look-alike specifiers and strings that are not imports.
  assert.deepEqual(netModulesIn("import a from 'https-proxy-agent'; import b from 'netmask'; import c from 'tls-ext';"), [], 'a package NAMED like a module');
  assert.deepEqual(netModulesIn("import d from './http.mjs'; import e from 'node:dns'; import f from 'node:http/x';"), [], 'a relative path, another builtin, a subpath');
  assert.deepEqual(netModulesIn("const s = 'node:http'; fetch('https://x'); const t = require.resolve('net');"), [], 'a string, a URL, require.resolve');
  // The token count: whole-word, case-sensitive, comments included.
  const Z = { lookup: 0, agent: 0, createConnection: 0, Agent: 0, globalAgent: 0, keepAlive: 0 };
  assert.deepEqual(connectionTokensIn('req({ agent: false }); // agent off, one lookup'), { ...Z, lookup: 1, agent: 2 }, 'a comment counts');
  assert.deepEqual(connectionTokensIn('opts.lookup; { lookup }; net.createConnection(p, h); headers["user-agent"]'), { ...Z, lookup: 2, agent: 1, createConnection: 1 }, 'a member, a shorthand, a call, a hyphenated header');
  assert.deepEqual(connectionTokensIn('new https.Agent({ keepAlive: true }); http.globalAgent.destroy(); // a globalAgent'), { ...Z, Agent: 1, globalAgent: 2, keepAlive: 1 }, 'the agent forms, comments included');
  assert.deepEqual(connectionTokensIn('userAgent agentName lookupAll createConnectionFor $agent agent$ _lookup AgentX myglobalAgent keepAliveMsecs'), Z, 'a longer identifier, and $ and _ joined, are not the tokens');
});

test('(w1-s, first) stripComments removes comments and nothing else — a `/*` or `//` inside a string, or a `/*` inside a line comment, opens nothing', () => {
  // FOURTH QUADRANT FIRST — code the stripper must KEEP. The two-regex form it replaces ate 180 lines of http_probe after
  // the string '*/*', 62 of target_http after another, and 517 of mcp_server after `data/compliance/*.json` in a // comment.
  assert.match(stripComments("h = { accept: '*/*' };\nspawn('nc', [x]);\n/* real */"), /spawn\('nc'/, 'code after a string holding */* survives');
  assert.match(stripComments('// reads data/compliance/*.json\nexec(\'dig\');\n// end */'), /exec\('dig'\)/, 'a /* inside a LINE comment opens no block');
  assert.match(stripComments('u = "http://x//y"; run("ping");'), /"http:\/\/x\/\/y"; run\("ping"\)/, 'a // inside a string is not a comment');
  assert.match(stripComments('t = `a // b /* c`; go();'), /`a \/\/ b \/\* c`; go\(\)/, 'a template literal');
  assert.match(stripComments('const re = /a\\/*b/; keep();'), /keep\(\)/, 'an escaped slash before * opens no block');
  // A regular-expression literal after `= ( , : ; ! & | ? { [` (where a `/` cannot be a division) is read as code (v387 R-7):
  // a `/*` in its class opens no block, and a quote or backtick in it flips no string parity.
  const kept = stripComments("x = /[/*]/; y();\nw(); /* end */ z();");
  assert.match(kept, /y\(\);\nw\(\);/, 'a /* inside a regex class opens no block'); assert.doesNotMatch(kept, /end/, 'the real comment after it still goes');
  assert.equal(stripComments("ok = s.match(/[`'\"]/); // gone\nt = `a`;"), "ok = s.match(/[`'\"]/); \nt = `a`;", 'a quote or backtick in a regex flips nothing');
  assert.equal(stripComments('a = b / c; // d\ne = f / g; h();'), 'a = b / c; \ne = f / g; h();', 'a division is not a regex');
  // The veto: real comments go, and a block comment keeps its newlines so line structure survives.
  assert.equal(stripComments('a(); // agent: false\nb(); /* lookup:\n x */ c();'), 'a(); \nb(); \n c();');
  assert.equal(stripComments('x(); // see https://example.test/a\ny();'), 'x(); \ny();', 'a URL inside a line comment goes with it');
});

test('(w1-i, first) the import derivation is keyed on the IDENTIFIER — every loader shape the repo uses or could, and no look-alike', () => {
  // FOURTH QUADRANT FIRST — the architect's v385 probes (B and C survived the first cut), then the aliases behind them.
  assert.deepEqual(netModulesIn("_require('net')"), ['net'], 'any …require( call — the repo\'s own _require convention');
  assert.deepEqual(netModulesIn("process.getBuiltinModule('node:http').request({ host })"), ['http'], 'getBuiltinModule');
  assert.deepEqual(netModulesIn("createRequire(import.meta.url)('https')"), ['https'], 'an immediate createRequire call');
  assert.deepEqual(netModulesIn("const load = createRequire(import.meta.url); load('dgram')"), ['dgram'], 'a name assigned from createRequire');
  assert.deepEqual(netModulesIn("import(/* x */ 'node:http')"), ['http'], 'a block comment before the specifier');
  assert.deepEqual(netModulesIn("require(\n  // the socket module\n  'net')"), ['net'], 'a line comment before the specifier');
  assert.deepEqual(netModulesIn("import { createRequire as cr } from 'node:module'; const r = cr(import.meta.url); r('tls')"), ['tls'], 'an aliased createRequire');
  assert.deepEqual(netModulesIn("const { createRequire: mk } = await import('node:module'); const q = mk(u); q('net')"), ['net'], 'a destructured createRequire');
  assert.deepEqual(netModulesIn("const cr2 = module.createRequire; const r2 = cr2(u); r2('dgram')"), ['dgram'], 'createRequire held in a const');
  assert.deepEqual(netModulesIn("const { getBuiltinModule: gbm } = process; gbm('node:net')"), ['net'], 'a destructured getBuiltinModule');
  assert.deepEqual(netModulesIn("const g = process.getBuiltinModule; g('http2')"), ['http2'], 'getBuiltinModule held in a const');
  assert.deepEqual(netModulesIn("const req = require; req('dgram')"), ['dgram'], 'require held in a const');
  assert.deepEqual(netModulesIn("module.require('net')"), ['net'], 'module.require');
  // The veto.
  assert.deepEqual(netModulesIn("require.resolve('net'); const load = createRequire(u); load('./net.mjs'); load.resolve('http'); getBuiltinModule; x.getBuiltinModuleNames('net')"), [],
    'require.resolve, a relative path through an alias, an alias\'s .resolve, a bare name, a longer method name');
});

test('(w1-t, first) the request-call count reads member calls and named imports under any alias, and nothing longer', () => {
  assert.deepEqual(httpCallsIn('https.request(o); mod.request({ host }); http.get(u); m.get(k);'), { request: 2, get: 2 }, 'member calls');
  assert.deepEqual(httpCallsIn("import { request as r, get } from 'node:https'; r(o); get(u);"), { request: 1, get: 1 }, 'a named import, aliased');
  assert.deepEqual(httpCallsIn("const { request: send } = _require('http'); send(o);"), { request: 1, get: 0 }, 'a destructured require, aliased');
  assert.deepEqual(httpCallsIn('x.requestFoo(); requestTarget(u); getThing(); a.getter(); // .request( in a comment'), { request: 1, get: 0 }, 'longer names are not calls; a comment IS counted');
});

test('(w1-o, first) a loader called optionally (`?.(`) or bound (`.bind(`) is a loader — architect v386 F and J', () => {
  // FOURTH QUADRANT FIRST — the shapes v386 found invisible, then their neighbours.
  assert.deepEqual(netModulesIn("process.getBuiltinModule?.('node:http')?.request({ host })"), ['http'], 'F: the feature-detect spelling of getBuiltinModule');
  assert.deepEqual(netModulesIn("require?.('net')"), ['net'], 'an optional require');
  assert.deepEqual(netModulesIn("_require?.( /* why */ 'dgram')"), ['dgram'], 'an optional …require( with a comment before the specifier');
  assert.deepEqual(netModulesIn("const r = createRequire(import.meta.url); r?.('tls')"), ['tls'], 'an optional call of a createRequire alias');
  assert.deepEqual(netModulesIn("createRequire?.(import.meta.url)?.('https')"), ['https'], 'an immediate createRequire, both calls optional');
  assert.deepEqual(netModulesIn("const g = process.getBuiltinModule.bind(process); g('node:net')"), ['net'], 'J: getBuiltinModule bound');
  assert.deepEqual(netModulesIn("const r = require.bind(null); r('tls')"), ['tls'], 'require bound');
  assert.deepEqual(netModulesIn("const q = _require.bind(null); q?.('dgram')"), ['dgram'], 'a …require bound, then called optionally');
  assert.deepEqual(netModulesIn("const g3 = process.getBuiltinModule?.bind(process); g3('https')"), ['https'], 'an optional .bind');
  assert.deepEqual(netModulesIn("const { getBuiltinModule: gbm } = process; const g2 = gbm.bind(process); g2('http2')"), ['http2'], 'an alias of a loader, bound');
  assert.deepEqual(netModulesIn("const r = createRequire(u); const r2 = r; r2('net')"), ['net'], 'an alias of a loader alias');
  assert.deepEqual(netModulesIn("const g = process.getBuiltinModule; const h = g.bind(process); h('node:tls')"), ['tls'], 'a chain of two: the bind of a name that holds a loader — the fixpoint');
  // The veto.
  assert.deepEqual(netModulesIn("const v = require.resolve.bind(null); v('net'); const n = x.getBuiltinModuleNames.bind(o); n('tls'); maybe?.('dgram')"), [],
    'a bound require.resolve, a bound longer method name, an optional call of a non-loader');
  // INVISIBLE — stated limits, pinned so that a fix flips them (v387 L1–L5; no shipped CE file uses these spellings today).
  // If one goes red the limit closed: update the header's "imports it cannot see" and this list.
  const INVISIBLE = [
    ["const l = typeof _require === 'function' ? _require : null; l('node:net')", 'L1: a loader as an arm of a conditional'],
    ["const l = globalThis.require ?? createRequire(import.meta.url); l('node:tls')", 'L2: a loader as an arm of ??'],
    ["process['getBuiltinModule']('node:net')", 'L3: a loader reached through a computed member'],
    ["(0, _require)('node:dgram')", 'L4: a comma-expression callee'],
    ["const l = globalThis.x || _require; l('node:http').request({ host })", 'L5: a loader as an arm of ||'],
  ];
  for (const [src, why] of INVISIBLE) assert.deepEqual(netModulesIn(src), [], `${why} — INVISIBLE, a stated limit`);
});

test('(w1-w, first) the request WORDS of an http importer — whole-word `request`, `get` and `ClientRequest`, comments and strings included — architect v386 G, H, I', () => {
  // FOURTH QUADRANT FIRST — the request sites the call count cannot bind.
  const Z = { request: 0, get: 0, ClientRequest: 0 };
  assert.deepEqual(httpWordsIn('const { request: __send } = https; __send({ host });'), { ...Z, request: 1 }, 'G: request destructured from a namespace');
  assert.deepEqual(httpWordsIn('new http.ClientRequest({ host });'), { ...Z, ClientRequest: 1 }, 'H: ClientRequest constructed');
  assert.deepEqual(httpWordsIn("const __r = http['request']; __r({ host });"), { ...Z, request: 1 }, 'I: a computed member held in a const');
  assert.deepEqual(httpWordsIn("http.get(u); // a get\nconst s = 'x-request-id';"), { ...Z, request: 1, get: 2 }, 'a comment and a hyphenated string count: noise, never silence');
  // The veto: longer identifiers, and `$` or `_` joined.
  assert.deepEqual(httpWordsIn('requestTarget requests getter getThing ClientRequestX myClientRequest $request get$ _get request_'), Z);
});

/** Every shipped JavaScript source under `root`, read from its package.json `files` (directories walked recursively), RAW. */
function shippedSources(root = ROOT) {
  const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
  const out = [];
  const visit = (rel) => {
    const st = fs.statSync(path.join(root, rel), { throwIfNoEntry: false });
    if (!st) return;
    if (st.isDirectory()) { for (const n of fs.readdirSync(path.join(root, rel)).sort()) visit(`${rel}/${n}`); return; }
    if (/\.(?:mjs|cjs|js)$/.test(rel)) out.push({ rel, raw: fs.readFileSync(path.join(root, rel), 'utf8') });
  };
  for (const entry of pkg.files) visit(entry.replace(/\/+$/, ''));
  return out;
}
function netCensus() {
  const found = {};
  for (const { rel, raw } of shippedSources()) {
    const modules = netModulesIn(raw);
    if (modules.length === 0) continue;
    found[rel] = { modules, tokens: connectionTokensIn(raw), raw };
    if (modules.some((m) => m.startsWith('http'))) Object.assign(found[rel], { calls: httpCallsIn(raw), words: httpWordsIn(raw) });
  }
  return found;
}

/** Declared: every shipped file importing a socket module → what it imports, how it pools, how it resolves, and why. */
const RAW_SOCKET = 'n/a — raw sockets, no HTTP agent: nothing pools';
const RESOLVES = 'absent — a host NAME resolves through node:dns lookup at connect (a dgram socket: the lookup it captured at createSocket), which the pin patches; an address skips it';
const NET_CC = 'net.createConnection — the TCP connect FUNCTION, not the http.request option';
const GLOBAL_HTTP = 'absent = global pool — `agent: undefined` reaches http.globalAgent, keep-alive on (measured on Node 24.22.3, the engines floor)';
const PER_REQUEST_HTTPS = 'custom, keep-alive off — a new https.Agent per request (rejectUnauthorized: !allowInsecure), whose default keepAlive is false';
// v387 R-8: a row saying `net` serves only isIP (and BlockList) holds it by a ZERO-count witness over its code — any other
// member of a `net` binding is red. Limit, stated: a destructured member (`const { connect } = net`, `import { connect }`).
const NET_BEYOND_ISIP = /(?<![\w$.])net\s*\.\s*(?!isIP(?:v4|v6)?\b)[\w$]+/g;
const NET_BEYOND_ISIP_AND_BLOCKLIST = /(?<![\w$.])net\s*\.\s*(?!isIP(?:v4|v6)?\b|BlockList\b)[\w$]+/g;
// v389 R-10: the witness must see the file's OWN binding form. A namespace bound to the identifier `net` (default import,
// `* as net`, require or dynamic import) is held by NET_BEYOND_ISIP*; a NAMED import by NET_NAMED_BEYOND_ISIP, which matches
// any named import of node:net other than exactly `{ isIP }`. Any other binding (another identifier, a destructured require,
// a re-export) has no witness that can see it, and a row saying "net only for isIP" over it is red.
const NET_NAMED_BEYOND_ISIP = /import\s*\{(?!\s*isIP\s*\}\s*from)[^}]*\}\s*from\s*['"](?:node:)?net['"]/g;
const NET_ONLY_SPEC = String.raw`['"](?:node:)?net['"]`;
const NET_BINDING_ANY = new RegExp(String.raw`from\s*${NET_ONLY_SPEC}|(?:require|import)\s*\(\s*${NET_ONLY_SPEC}\s*\)`, 'g');
const NET_BINDING_NAMESPACE = new RegExp(String.raw`import\s+(?:\*\s+as\s+)?net\s+from\s*${NET_ONLY_SPEC}|(?:const|let|var)\s+net\s*=\s*(?:await\s+)?(?:require|import)\s*\(\s*${NET_ONLY_SPEC}\s*\)`, 'g');
const NET_BINDING_NAMED = new RegExp(String.raw`import\s*\{[^}]*\}\s*from\s*${NET_ONLY_SPEC}`, 'g');
const NET_IMPORTERS = {
  'plugins/040_tls_cert_auditor.mjs': { modules: ['net', 'tls'], agent: RAW_SOCKET, lookup: RESOLVES, createConnection: 'absent',
    tokens: { lookup: 0, agent: 0, createConnection: 0, Agent: 0, globalAgent: 0, keepAlive: 0 }, witness: [[NET_NAMED_BEYOND_ISIP, 0]],
    why: 'tls.connect to the target for its certificate chain; net only for isIP (a named import, held by the named-import witness, v389 R-10)' },
  'plugins/060_dns_sec_auditor.mjs': { modules: ['dgram', 'net'], agent: RAW_SOCKET,
    lookup: 'absent — every `lookup` token is prose; it speaks the DNS protocol (resolve*), and its zone transfer connects to an ADDRESS from resolve4, outside the pin (declared in DECLARED above)',
    createConnection: `${NET_CC} — the opt-in zone transfer to a nameserver address`,
    tokens: { lookup: 14, agent: 0, createConnection: 1, Agent: 0, globalAgent: 0, keepAlive: 0 }, why: 'DNS posture of the domain; dgram is imported and never used' },
  'plugins/db_scanner.mjs': { modules: ['net'], agent: RAW_SOCKET, lookup: RESOLVES, createConnection: 'absent',
    tokens: { lookup: 0, agent: 0, createConnection: 0, Agent: 0, globalAgent: 0, keepAlive: 0 }, why: 'a net.Socket connect to the target\'s database ports' },
  'plugins/dns_scanner.mjs': { modules: ['dgram', 'net'], agent: RAW_SOCKET, lookup: RESOLVES, createConnection: `${NET_CC} — DNS over TCP to the target`,
    tokens: { lookup: 0, agent: 0, createConnection: 2, Agent: 0, globalAgent: 0, keepAlive: 0 }, why: 'DNS queries to the target over UDP and TCP' },
  'plugins/ftp_banner_check.mjs': { modules: ['net'], agent: RAW_SOCKET, lookup: RESOLVES, createConnection: 'absent',
    tokens: { lookup: 0, agent: 0, createConnection: 0, Agent: 0, globalAgent: 0, keepAlive: 0 }, why: 'reads the target\'s FTP banner over a net.Socket' },
  'plugins/host_up_check.mjs': { modules: ['dgram', 'net'], agent: RAW_SOCKET, lookup: RESOLVES, createConnection: 'absent',
    tokens: { lookup: 0, agent: 0, createConnection: 0, Agent: 0, globalAgent: 0, keepAlive: 0 }, why: 'TCP and UDP reachability probes to the target' },
  'plugins/http_probe.mjs': { modules: ['http', 'https', 'net'],
    agent: { http: `${GLOBAL_HTTP}; G-18, unchanged here`, https: PER_REQUEST_HTTPS },
    lookup: 'absent — node:dns lookup, which the pin patches (its one `lookup` token is prose); its curl leg is pinned through --resolve',
    createConnection: 'absent', tokens: { lookup: 1, agent: 5, createConnection: 0, Agent: 4, globalAgent: 0, keepAlive: 0 }, calls: { request: 2, get: 0 }, words: { request: 2, get: 1, ClientRequest: 0 },
    witness: [[/const agent = isHttps \? new https\.Agent\(\{ rejectUnauthorized: !allowInsecure \}\) : undefined;/g, 2], [NET_BEYOND_ISIP, 0]],
    why: 'the target\'s HTTP banner and headers over node:http(s), decoding nothing (G-18); net only for isIP' },
  'plugins/llmnr_scanner.mjs': { modules: ['dgram'], agent: RAW_SOCKET,
    lookup: 'absent — it sends to the LLMNR multicast group 224.0.0.252, an address: nothing resolves', createConnection: 'absent',
    tokens: { lookup: 0, agent: 0, createConnection: 0, Agent: 0, globalAgent: 0, keepAlive: 0 }, why: 'LLMNR multicast discovery on the local link' },
  'plugins/mcp_scanner.mjs': { modules: ['http', 'https'], agent: { http: GLOBAL_HTTP, https: PER_REQUEST_HTTPS },
    lookup: 'absent — node:dns lookup, which the pin patches (its one `lookup` token is prose)', createConnection: 'absent',
    tokens: { lookup: 1, agent: 3, createConnection: 0, Agent: 2, globalAgent: 0, keepAlive: 0 }, calls: { request: 1, get: 0 }, words: { request: 3, get: 0, ClientRequest: 0 },
    witness: [[/const agent = isHttps \? new https\.Agent\(\{ rejectUnauthorized: !allowInsecure \}\) : undefined;/g, 1],
      [/mod\.request\(\{ host, port, method, path, headers: reqHeaders, agent \}/g, 1]],
    why: 'MCP endpoints on the target over node:http(s), decoding nothing — the same shape as http_probe (G-19)' },
  'plugins/mdns_scanner.mjs': { modules: ['net'], agent: RAW_SOCKET, lookup: RESOLVES,
    createConnection: `${NET_CC} — probeTr069: port 7547 on the answering device, a hand-written GET / HTTP/1.1 with Connection: close; it reads the Server: header and 512 characters of the reply into the scan record`,
    tokens: { lookup: 0, agent: 0, createConnection: 1, Agent: 0, globalAgent: 0, keepAlive: 0 },
    why: 'mDNS discovery through its third-party packages, plus one TCP probe that SPEAKS HTTP/1.1 — a scanned-host HTTP reader with no http import, not on the waist (G-22)' },
  'plugins/netbios_scanner.mjs': { modules: ['dgram', 'net'], agent: RAW_SOCKET, lookup: RESOLVES, createConnection: `${NET_CC} — SMB on 445 and one more TCP probe`,
    tokens: { lookup: 0, agent: 0, createConnection: 2, Agent: 0, globalAgent: 0, keepAlive: 0 }, why: 'NetBIOS name queries over UDP, an mDNS query to 224.0.0.251, and TCP probes of the target' },
  'plugins/opensearch_scanner.mjs': { modules: ['https'],
    agent: 'absent = global pool — undici\'s global dispatcher, keep-alive on: global fetch IGNORES the https.Agent (rejectUnauthorized: false) the file builds under OPENSEARCH_SCANNER_INSECURE_TLS and hands it (Q3, a no-op), until C-7 moves the site onto the waist',
    lookup: 'absent — undici resolves through node:dns lookup, which the pin patches', createConnection: 'absent',
    tokens: { lookup: 0, agent: 3, createConnection: 0, Agent: 3, globalAgent: 0, keepAlive: 0 }, calls: { request: 0, get: 0 }, words: { request: 1, get: 0, ClientRequest: 0 },
    witness: [[/return new https\.Agent\(\{ rejectUnauthorized: false \}\);/g, 1], [/signal: ctrl\.signal,\n\s+agent\n/g, 1]],
    why: 'the OpenSearch banner at / through global fetch; node:https is imported (dynamically) only to build that agent' },
  'plugins/ping_checker.mjs': { modules: ['net'], agent: RAW_SOCKET, lookup: RESOLVES, createConnection: 'absent',
    tokens: { lookup: 0, agent: 0, createConnection: 0, Agent: 0, globalAgent: 0, keepAlive: 0 }, why: 'a TCP connect beside its pinned ping, nping, hping3 and arp subprocesses' },
  'plugins/port_scanner.mjs': { modules: ['dgram', 'net'], agent: RAW_SOCKET, lookup: RESOLVES, createConnection: 'absent',
    tokens: { lookup: 0, agent: 0, createConnection: 0, Agent: 0, globalAgent: 0, keepAlive: 0 }, why: 'TCP connect and UDP probes of the target' },
  'plugins/ssh_scanner.mjs': { modules: ['net'], agent: RAW_SOCKET, lookup: RESOLVES, createConnection: `${NET_CC} — the SSH banner`,
    tokens: { lookup: 0, agent: 0, createConnection: 1, Agent: 0, globalAgent: 0, keepAlive: 0 }, why: 'reads the target\'s SSH banner' },
  'plugins/sunrpc_scanner.mjs': { modules: ['dgram', 'net'], agent: RAW_SOCKET, lookup: RESOLVES, createConnection: 'absent',
    tokens: { lookup: 0, agent: 0, createConnection: 0, Agent: 0, globalAgent: 0, keepAlive: 0 }, why: 'portmapper queries to the target over UDP and TCP' },
  'plugins/tls_scanner.mjs': { modules: ['tls'], agent: RAW_SOCKET, lookup: RESOLVES, createConnection: 'absent',
    tokens: { lookup: 0, agent: 1, createConnection: 0, Agent: 0, globalAgent: 0, keepAlive: 0 }, why: 'tls.connect (or its test seam\'s connect) for protocol and cipher probes; its one `agent` token is prose' },
  'plugins/wsd_scanner.mjs': { modules: ['dgram'], agent: RAW_SOCKET,
    lookup: 'absent — it sends to the WS-Discovery multicast group 239.255.255.250, an address: nothing resolves', createConnection: 'absent',
    tokens: { lookup: 0, agent: 0, createConnection: 0, Agent: 0, globalAgent: 0, keepAlive: 0 }, why: 'WS-Discovery multicast on the local link' },
  'utils/net_validation.mjs': { modules: ['net'], agent: RAW_SOCKET,
    lookup: 'its own dns.lookup(all, verbatim) — the CHECK whose answers the scan is pinned to', createConnection: 'absent',
    tokens: { lookup: 10, agent: 0, createConnection: 0, Agent: 0, globalAgent: 0, keepAlive: 0 }, witness: [[NET_BEYOND_ISIP_AND_BLOCKLIST, 0]],
    why: 'net only for isIP and BlockList; it opens no socket' },
  'utils/scan_pin.mjs': { modules: ['net'], agent: RAW_SOCKET,
    lookup: 'it IS the pin: it replaces node:dns lookup and dns/promises lookup inside a scan', createConnection: 'absent',
    tokens: { lookup: 20, agent: 1, createConnection: 0, Agent: 1, globalAgent: 0, keepAlive: 0 }, witness: [[NET_BEYOND_ISIP, 0]],
    why: 'net only for isIP; it opens no socket (its one `agent` token is prose)' },
  'utils/target_http.mjs': { modules: ['http', 'https'], agent: 'false — one connection per request, never pooled',
    lookup: 'absent — node:dns lookup, which the pin patches inside a scan (its two `lookup` tokens are prose)', createConnection: 'absent',
    tokens: { lookup: 2, agent: 6, createConnection: 0, Agent: 0, globalAgent: 0, keepAlive: 0 }, calls: { request: 1, get: 0 }, words: { request: 10, get: 0, ClientRequest: 0 },
    witness: [[/transport\.request\(u, \{ method, headers, agent: false \}/g, 1]],
    why: 'the target HTTP waist (EE Z-1); no site uses it yet' },
  'utils/webhook.mjs': { modules: ['http', 'https', 'net'],
    agent: 'custom, keep-alive off — its own transport.Agent with the default agent\'s options and keepAlive: false, so no idle socket another caller opened carries a delivery',
    lookup: 'custom — pinnedLookup(target) answers the address its own SSRF check resolved (not the scan pin); in production a null target is refused before any request, so the lookup is absent only under the _setWebhookSafeChecker test seam',
    createConnection: 'absent', tokens: { lookup: 3, agent: 4, createConnection: 0, Agent: 1, globalAgent: 1, keepAlive: 1 }, calls: { request: 1, get: 0 }, words: { request: 8, get: 0, ClientRequest: 0 },
    witness: [[/\.\.\.\(target \? \{ lookup: pinnedLookup\(target\) \} : \{\}\)/g, 1],
      [/agent: new transport\.Agent\(\{ \.\.\.transport\.globalAgent\.options, keepAlive: false \}\)/g, 1], [NET_BEYOND_ISIP, 0]],
    why: 'the operator\'s webhook delivery — never a scanned host; net only for isIP' },
};
const AGENT_GRAMMAR = /^(?:false|absent = global pool|custom, keep-alive (?:on|off)|n\/a)(?: —|$)/;

test('(w1-a) every SHIPPED file importing node:http, https, http2, net, tls or dgram is DECLARED with the modules it imports', () => {
  const shipped = shippedSources().map(({ rel }) => rel);
  for (const { rel } of walked()) assert.ok(shipped.includes(rel), `the shipped walk misses ${rel} — it is broken`);
  assert.ok(shipped.some((rel) => rel.startsWith('bin/')), 'the shipped walk does not reach bin/, which the census above never read');
  const found = netCensus();
  assert.ok(Object.keys(found).length >= 15, `the census found ${Object.keys(found).length} importers — the walk is broken`);
  assert.deepEqual(Object.keys(found).sort(), Object.keys(NET_IMPORTERS).sort(),
    'a shipped file imports a socket module without a declared row (or a declared row no longer imports one)');
  for (const [rel, f] of Object.entries(found)) assert.deepEqual(f.modules, NET_IMPORTERS[rel].modules, `${rel}: imports ${JSON.stringify(f.modules)}`);
});

test('(w1-b) each row pins the COUNT of its six tokens and, for an http/https/http2 importer, its request calls — comments included; a moved count names file and token', () => {
  for (const [rel, f] of Object.entries(netCensus())) {
    for (const token of ['lookup', 'agent', 'createConnection', 'Agent', 'globalAgent', 'keepAlive']) {
      assert.equal(f.tokens[token], NET_IMPORTERS[rel].tokens[token],
        `${rel}: the token \`${token}\` occurs ${f.tokens[token]} times, declared ${NET_IMPORTERS[rel].tokens[token]} — re-read its row`);
    }
    assert.equal(Boolean(f.calls), Boolean(NET_IMPORTERS[rel].calls), `${rel}: an http, https or http2 importer declares its request calls; no other row does`);
    for (const call of Object.keys(f.calls ?? {})) {
      assert.equal(f.calls[call], NET_IMPORTERS[rel].calls[call],
        `${rel}: ${f.calls[call]} \`${call}\` calls, declared ${NET_IMPORTERS[rel].calls[call]} — a request site moved; re-read its agent row`);
    }
    assert.equal(Boolean(f.words), Boolean(NET_IMPORTERS[rel].words), `${rel}: an http, https or http2 importer declares its request words; no other row does`);
    for (const word of HTTP_WORDS.filter(() => f.words)) {
      assert.equal(f.words[word], NET_IMPORTERS[rel].words[word],
        `${rel}: the word \`${word}\` occurs ${f.words[word]} times, declared ${NET_IMPORTERS[rel].words[word]} — a request site the call count cannot bind may have moved; re-read its agent row`);
    }
  }
});

test('(w1-c) every row states agent, lookup, createConnection and a reason; a row with an HTTP agent pins a WITNESS of its option site', () => {
  const found = netCensus();
  assert.ok(Object.keys(NET_IMPORTERS).length > 0, 'no rows declared — this leg tests nothing');
  for (const [rel, row] of Object.entries(NET_IMPORTERS)) {
    const agents = typeof row.agent === 'string' ? [row.agent] : Object.values(row.agent ?? {});
    assert.ok(agents.length > 0 && agents.every((a) => AGENT_GRAMMAR.test(a)),
      `${rel}: agent ${JSON.stringify(row.agent)} is not false | absent = global pool | custom, keep-alive on/off | n/a`);
    for (const k of ['lookup', 'createConnection', 'why']) assert.ok(typeof row[k] === 'string' && row[k].length > 0, `${rel}: the row states no ${k}`);
    const rawSocketOnly = agents.every((a) => a.startsWith('n/a'));
    const positive = (row.witness ?? []).filter(([, n]) => n > 0);
    assert.equal(positive.length > 0, !rawSocketOnly, `${rel}: a row with an HTTP agent carries a witness of its option site; a raw-socket row carries only zero-count witnesses`);
    const code = stripComments(found[rel]?.raw ?? '');
    if (/net only for isIP/.test(row.why)) {
      const zero = (row.witness ?? []).filter(([, n]) => n === 0).map(([re]) => re);
      const count = (re) => (code.match(re) ?? []).length;
      const all = count(NET_BINDING_ANY), namespace = count(NET_BINDING_NAMESPACE), named = count(NET_BINDING_NAMED);
      assert.ok(all > 0, `${rel}: the row says net serves only isIP and the file's code binds no node:net`);
      assert.equal(namespace + named, all, `${rel}: ${all - namespace - named} binding(s) of node:net that no witness can see (another identifier, a destructured require, a re-export) under a row saying net serves only isIP`);
      if (namespace) assert.ok(zero.some((re) => re === NET_BEYOND_ISIP || re === NET_BEYOND_ISIP_AND_BLOCKLIST), `${rel}: the file binds a \`net\` namespace and the row carries no zero-count namespace witness holding "net only for isIP"`);
      if (named) assert.ok(zero.includes(NET_NAMED_BEYOND_ISIP), `${rel}: the file imports node:net by name and the row carries no zero-count NAMED-import witness holding "net only for isIP"`);
    }
    for (const [re, n] of row.witness ?? []) {
      const hits = (code.match(re) ?? []).length;
      assert.equal(hits, n, `${rel}: the witness ${re} matches ${hits} times in its code, declared ${n} — its option site moved or was commented out`);
    }
  }
});

test('(w1-d) utils/target_http.mjs, the waist: agent false, no lookup, no createConnection — read off the row AND the source', () => {
  const row = NET_IMPORTERS['utils/target_http.mjs'];
  assert.ok(row, 'utils/target_http.mjs has no row');
  assert.match(row.agent, /^false/); assert.match(row.lookup, /^absent/); assert.match(row.createConnection, /^absent/);
  const raw = fs.readFileSync(path.join(ROOT, 'utils', 'target_http.mjs'), 'utf8');
  // The positive check reads CODE: the file's own comments say `agent: false` too, and a raw read was satisfied by them with
  // the option deleted (the W-1 battery's M1). The veto below reads the raw text, the noise direction.
  assert.match(stripComments(raw), /(?<![\w$])agent:\s*false\b/, 'utils/target_http.mjs no longer passes agent: false');
  assert.doesNotMatch(raw, /(?<![\w$])(?:lookup|createConnection)\s*:|[{,]\s*(?:lookup|createConnection)\s*[,}]/,
    'utils/target_http.mjs passes a lookup or a createConnection option');
});

test('(w1-e) the shipped walk reads package.json `files` RECURSIVELY, files and directories alike, and nothing outside them', () => {
  // The shipped directories are flat today, so the corpus cannot tell a recursive walk from a one-level one (the W-1
  // battery's T4 survived on it). A fixture tree can.
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'w1-walk-'));
  try {
    const put = (rel, text) => { fs.mkdirSync(path.dirname(path.join(tmp, rel)), { recursive: true }); fs.writeFileSync(path.join(tmp, rel), text); };
    put('package.json', JSON.stringify({ files: ['lib/', 'top.mjs', 'absent/'] }));
    put('lib/deep/er/x.mjs', "import net from 'node:net';\n");
    put('lib/y.cjs', "const tls = require('tls');\n");
    put('lib/data.json', '{"import": "node:http"}');
    put('top.mjs', "export const f = () => import('node:dgram');\n");
    put('other/z.mjs', "import http from 'node:http';\n");
    assert.deepEqual(shippedSources(tmp).map(({ rel }) => rel), ['lib/deep/er/x.mjs', 'lib/y.cjs', 'top.mjs']);
  } finally { fs.rmSync(tmp, { recursive: true, force: true }); }
});

/** v387 R-9 (G-22): every shipped file whose RAW text writes an HTTP/1.x request line by hand — a raw-socket HTTP reader has
 * no http import, so the importer rows above cannot name it as one. */
const RAW_HTTP_LINE = /HTTP\/1\.[01]/;
const HAND_WRITTEN_HTTP = {
  'plugins/mdns_scanner.mjs': 'probeTr069 — GET / HTTP/1.1 to port 7547 over net.createConnection; a scanned-host HTTP reader NOT on the waist (G-22)',
};
test('(w1-h) the shipped files that write an HTTP/1.x request line by hand are DECLARED, by equality — v387 G-22', () => {
  // FOURTH QUADRANT FIRST — what the line test reads, and what it does not.
  for (const t of ['GET / HTTP/1.1\r\n', "'HEAD / HTTP/1.0'", '`${m} ${p} HTTP/1.1`']) assert.match(t, RAW_HTTP_LINE, `a request line: ${t}`);
  for (const t of ['HTTP/2', 'HTTPS/1.1', 'http/1.1', 'HTTP/1.2']) assert.doesNotMatch(t, RAW_HTTP_LINE, `not one: ${t}`);
  // Stated limits: a request line assembled from pieces ('HTTP/' + v), and HTTP/2, move nothing.
  const found = shippedSources().filter(({ raw }) => RAW_HTTP_LINE.test(raw)).map(({ rel }) => rel).sort();
  assert.deepEqual(found, Object.keys(HAND_WRITTEN_HTTP).sort(), 'a shipped file writes an HTTP/1.x request line by hand (or a declared one stopped) — it reads a scanned host outside the waist; declare it and name it among the readers');
  for (const rel of found) assert.match(NET_IMPORTERS[rel]?.why ?? '', /HTTP\/1\.1|not on the waist/, `${rel}: its importer row does not say it speaks HTTP`);
});

/**
 * The stripper's blind spot, declared: every shipped file in which a line of stripComments' output still BEGINS with a
 * comment opener, with the COUNT of such lines (v387 R-7: membership alone sees nothing more inside a member). Today both
 * are IN A STRING — a `//` line of browser script inside a template literal, which the stripper keeps correctly. The three
 * files whose comments a regex literal used to keep as code (executive_report, jira_export, report_md) closed when the
 * stripper gained its regex-literal branch; a comment KEPT after a regex the branch does not read would land here.
 */
const IN_A_STRING = 'a STRING, correctly kept — a `//` line of browser script inside a template literal';
const STRIPPED_OPENERS = {
  'utils/raw_report_html.mjs': { kind: IN_A_STRING, lines: 1 },
  'utils/report_html.mjs': { kind: IN_A_STRING, lines: 2 },
};
const OPENER_LINE = /^[ \t]*(?:\/\/|\/\*|\*(?:[ \t/]|$))/m;

test('(w1-k) the stripper\'s blind spot by equality: the shipped files in which a stripped line still begins with a comment opener', () => {
  // FOURTH QUADRANT FIRST — the limit is real and the line test reads what it names.
  assert.match(stripComments('function f(s) { return /[`]/.test(s); }\n// kept\nconst t = `x`;'), /\/\/ kept/, 'the stated limit, pinned: a regex after `return` is not read, and its backtick keeps the comment after it — if this goes red the limit closed; update the header');
  for (const line of ['  // a', '\t/* b', ' * c', ' */', ' *']) assert.match(line, OPENER_LINE, `an opener line: ${JSON.stringify(line)}`);
  for (const line of ['a * b', '  *ptr', 'x(); // y', "s = '// z'"]) assert.doesNotMatch(line, OPENER_LINE, `not an opener line: ${JSON.stringify(line)}`);
  // The corpus, by equality: a new file fails (read it against a real parser, then declare it), and so does a fixed one.
  const openerLines = (raw) => stripComments(raw).split('\n').filter((l) => OPENER_LINE.test(l)).length;
  const counted = Object.fromEntries(shippedSources().map(({ rel, raw }) => [rel, openerLines(raw)]).filter(([, n]) => n > 0));
  const found = Object.keys(counted).sort();
  assert.deepEqual(found, Object.keys(STRIPPED_OPENERS).sort(),
    'the set of shipped files whose stripped text still has a line beginning with a comment opener moved — read each against a real parser, then re-declare STRIPPED_OPENERS');
  for (const [rel, row] of Object.entries(STRIPPED_OPENERS)) {
    assert.equal(row.kind, IN_A_STRING, `${rel}: the declaration states no kind`);
    assert.equal(counted[rel], row.lines, `${rel}: ${counted[rel]} stripped lines begin with a comment opener, declared ${row.lines} — a comment may be kept as code; read it against a real parser`);
  }
});

test('(w1-f) node-upnp-utils pools in http.globalAgent itself — its row states it, and the INSTALLED version and request lines are pinned', () => {
  const row = THIRD_PARTY['node-upnp-utils'];
  assert.ok(row && typeof row === 'object' && AGENT_GRAMMAR.test(row.agent), 'node-upnp-utils has no pooling statement in the row grammar');
  // The pin below reads the INSTALLED tree; a customer install resolves the DECLARED range, which may admit a later 1.x.
  const declared = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8')).dependencies?.['node-upnp-utils'];
  assert.equal(declared, row.declared, `package.json declares node-upnp-utils ${declared}, the row says ${row.declared} — re-read what a customer install may resolve`);
  assert.match(row.why, new RegExp(`installed.*${String(row.declared).replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}`, 'i'), 'the row\'s why states that the pin is on the installed tree and names the declared range');
  const dir = path.join(ROOT, 'node_modules', 'node-upnp-utils');
  assert.ok(fs.existsSync(path.join(dir, 'package.json')), 'node-upnp-utils is not installed — this leg cannot measure');
  const installed = JSON.parse(fs.readFileSync(path.join(dir, 'package.json'), 'utf8')).version;
  assert.equal(installed, row.version, `node-upnp-utils ${installed} is installed, the row was read at ${row.version} — re-read its request sites`);
  for (const [file, re, n] of row.witness) {
    const hits = (stripComments(fs.readFileSync(path.join(dir, file), 'utf8')).match(re) ?? []).length;
    assert.equal(hits, n, `node-upnp-utils ${file}: the witness ${re} matches ${hits} times, declared ${n}`);
  }
  // Which of its request sites the plugin can reach: the members it touches, by equality (invokeAction is not among them).
  const plugin = stripComments(fs.readFileSync(path.join(ROOT, 'plugins', 'upnp_scanner.mjs'), 'utf8'));
  const members = [...new Set([...plugin.matchAll(/(?<![\w$.])(?:upnp|upnpModule)\.([\w$]+)/g)].map((m) => m[1]))].sort();
  assert.deepEqual(members, [...row.pluginMembers].sort(), 'upnp_scanner reaches a node-upnp-utils member the row was not read for');
});
