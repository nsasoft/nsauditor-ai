// tests/scan_pin_subprocess.test.mjs
// ─────────────────────────────────────────────────────────────────────────────
// THE SCAN-TARGET PIN AT THE SUBPROCESS LAYER (EE 2.0.0, R1b). curl, ping, nping, hping3 and nmap resolve through the OS,
// never through the pinned node:dns, so each plugin hands its command the address the scan's check resolved. Driven: the
// commands on PATH are recording stand-ins (they append their argv to a log and exit 1), the plugins run for real, and the
// log says what each plugin handed the OS — the NAME when nothing is pinned (the positive control), the ADDRESS when it is.
// A separate leg drives the REAL curl to prove --resolve does what http_probe relies on.
//
// `pin.test` (RFC 6761) never reaches a real resolver: pinned, the plugins' in-process TCP probes go to 127.0.0.1 and are
// refused fast; unpinned, they fail ENOTFOUND fast.
//
// FOURTH QUADRANT FIRST: unpinned, every command is handed the NAME.
// ─────────────────────────────────────────────────────────────────────────────
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import { spawn } from 'node:child_process';
import { runPinned } from '../utils/scan_pin.mjs';
import hostUpCheck from '../plugins/host_up_check.mjs';
import pingChecker from '../plugins/ping_checker.mjs';
import arpScanner from '../plugins/arp_scanner.mjs';
import synScanner from '../plugins/syn_scanner.mjs';
import { probeFirmware } from '../plugins/http_probe.mjs';

const NAME = 'pin.test';
const PIN = { [NAME]: [{ address: '::1', family: 6 }, { address: '127.0.0.1', family: 4 }] };   // IPv6 first: the tools take IPv4
let dir; let log; const saved = {};

before(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pin-shims-'));
  log = path.join(dir, 'argv.log');
  for (const cmd of ['ping', 'nping', 'hping3', 'nmap', 'curl', 'arp']) {
    fs.writeFileSync(path.join(dir, cmd), `#!/bin/sh\necho "${cmd} $*" >> "$SHIM_LOG"\nexit 1\n`, { mode: 0o755 });
  }
  for (const k of ['PATH', 'SHIM_LOG', 'ENABLE_SYN_SCAN']) saved[k] = process.env[k];
  process.env.PATH = `${dir}${path.delimiter}${process.env.PATH}`;
  process.env.SHIM_LOG = log;
  process.env.ENABLE_SYN_SCAN = '1';
});
after(() => {
  for (const [k, v] of Object.entries(saved)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
  fs.rmSync(dir, { recursive: true, force: true });
});

/** Run `fn` and return the argv lines the stand-ins recorded during it. */
async function recorded(fn) {
  fs.writeFileSync(log, '');
  await fn();
  return fs.readFileSync(log, 'utf8').trim().split('\n').filter(Boolean);
}
const lastArgOf = (lines, cmd) => lines.filter((l) => l.startsWith(`${cmd} `)).map((l) => l.split(' ').pop());

test('(sp1, first) UNPINNED, every command is handed the NAME — the stand-ins record what the plugins hand the OS', async () => {
  const lines = await recorded(async () => {
    await hostUpCheck.run(NAME);
    await pingChecker.run(NAME);
    await synScanner.run(NAME);
    await probeFirmware(NAME, 'NETGEAR R7000');
  });
  // Two pings: host_up_check's and ping_checker's own (the census missed the second; this leg found it).
  assert.deepEqual(lastArgOf(lines, 'ping'), [NAME, NAME], JSON.stringify(lines));
  assert.ok(lastArgOf(lines, 'nping').concat(lastArgOf(lines, 'hping3')).every((a) => a === NAME) && lastArgOf(lines, 'nping').length === 1);
  assert.deepEqual(lastArgOf(lines, 'nmap'), [NAME]);
  const curl = lines.find((l) => l.startsWith('curl '));
  assert.ok(curl && !curl.includes('--resolve') && curl.includes(`http://${NAME}/currentsetting.htm`), curl);
});

test('(sp2) PINNED, ping, nping, hping3 and nmap are handed the pinned IPv4 address — never the name', async () => {
  const lines = await recorded(() => runPinned(PIN, async () => {
    await hostUpCheck.run(NAME);
    await pingChecker.run(NAME);
    await synScanner.run(NAME);
  }));
  assert.deepEqual(lastArgOf(lines, 'ping'), ['127.0.0.1', '127.0.0.1'], JSON.stringify(lines));
  assert.deepEqual(lastArgOf(lines, 'nping'), ['127.0.0.1']);
  assert.deepEqual(lastArgOf(lines, 'hping3'), ['127.0.0.1']);
  assert.deepEqual(lastArgOf(lines, 'nmap'), ['127.0.0.1']);
  assert.ok(!lines.some((l) => l.split(' ').slice(1).includes(NAME)), `a command was still handed the name: ${JSON.stringify(lines)}`);
});

test('(sp3) PINNED, curl keeps the NAME in the URL (the Host header) and is told where to connect with --resolve', async () => {
  const lines = await recorded(() => runPinned(PIN, () => probeFirmware(NAME, 'NETGEAR R7000')));
  const curl = lines.find((l) => l.startsWith('curl '));
  assert.ok(curl, JSON.stringify(lines));
  assert.ok(curl.includes(`--resolve ${NAME}:80:127.0.0.1`), curl);
  assert.ok(curl.endsWith(`http://${NAME}/currentsetting.htm`), curl);
});

// sp3 is this leg's fourth quadrant: an ASCII name's arguments are the typed name in both positions, byte for byte.
test('(sp5) PINNED under a Unicode spelling, curl is handed the ASCII name in BOTH --resolve and the URL — an IDN-built curl converts the URL host, so a key on the spelling would miss and the name would resolve live', async () => {
  // The third is a name domainToASCII REJECTS: it keeps its raw key (the subprocess twin of scan_pin leg (b)). A second
  // canonicaliser — domainToASCII called here directly — would hand curl an empty name for it.
  for (const [spelling, ascii] of [['ⓛocalhost', 'localhost'], ['bücher.example', 'xn--bcher-kva.example'], ['xn--zz', 'xn--zz']]) {
    // Unpinned, nothing changes: no --resolve, and the URL carries the name as typed.
    const bare = (await recorded(() => probeFirmware(spelling, 'NETGEAR R7000'))).find((l) => l.startsWith('curl '));
    assert.ok(bare && !bare.includes('--resolve') && bare.endsWith(`http://${spelling}/currentsetting.htm`), `unpinned, the typed name changed: ${bare}`);
    const lines = await recorded(() => runPinned({ [spelling]: [{ address: '127.0.0.1', family: 4 }] }, () => probeFirmware(spelling, 'NETGEAR R7000')));
    const curl = lines.find((l) => l.startsWith('curl '));
    assert.ok(curl, JSON.stringify(lines));
    const args = curl.split(' ');
    assert.equal(args[args.indexOf('--resolve') + 1], `${ascii}:80:127.0.0.1`, `the --resolve key is not the ASCII name: ${curl}`);
    assert.equal(args.at(-1), `http://${ascii}/currentsetting.htm`, `the URL host is not the ASCII name: ${curl}`);
    if (spelling !== ascii) assert.ok(!curl.includes(spelling), `the typed spelling reached curl: ${curl}`);
  }
});

test('(sp4) the REAL curl honours --resolve: without it the name lands on loopback (positive control); with it, it never does', async () => {
  const real = ['/usr/bin/curl', '/usr/local/bin/curl', '/opt/homebrew/bin/curl'].find((p) => fs.existsSync(p));
  assert.ok(real, 'no real curl on this machine — this leg cannot measure, and a skipped leg is not a pass');
  let hits = 0;
  const server = http.createServer((req, res) => { hits += 1; res.end('ok'); });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const port = server.address().port;
  const run = (args) => new Promise((resolve) => { const p = spawn(real, args); p.on('close', resolve); p.on('error', resolve); });
  try {
    await run(['-s', '-m', '2', `http://localhost:${port}/`]);
    assert.equal(hits, 1, 'positive control: curl by name reached the loopback receiver');
    await run(['-s', '-m', '1', '--resolve', `localhost:${port}:203.0.113.10`, `http://localhost:${port}/`]);
    assert.equal(hits, 1, '--resolve did not govern where curl connected');
  } finally { await new Promise((r) => server.close(r)); }
});

// ── B216 (M1 of the architect's verdict on EE cc422af): curl globs its URL unless told not to ───────────────────────────
// curl expands `{}` and `[]` in a URL into several names and resolves each through the OS; --resolve pins only the name it
// was given, so the expanded names skip the pin. http_probe passes -g (--globoff) right after the pin arguments (-q is only
// effective as curl's FIRST argument). The entry check (utils/net_validation.mjs isHostnameSyntax) refuses such a host
// before a scan; this is the second line, at the argv.
test('(sp9, first) unpinned, curl\'s first argument is -g; pinned, -g follows -q --noproxy * — and the URL still carries the name', async () => {
  const bare = (await recorded(() => probeFirmware(NAME, 'NETGEAR R7000'))).find((l) => l.startsWith('curl '));
  assert.ok(bare, 'curl was not run unpinned');
  assert.equal(bare.split(' ')[1], '-g', `unpinned, -g is not curl's first argument: ${bare}`);
  const pinned = (await recorded(() => runPinned(PIN, () => probeFirmware(NAME, 'NETGEAR R7000')))).find((l) => l.startsWith('curl '));
  assert.ok(pinned, 'curl was not run pinned');
  assert.deepEqual(pinned.split(' ').slice(1, 5), ['-q', '--noproxy', '*', '-g'], `pinned, the head of curl's argv is wrong: ${pinned}`);
  assert.ok(pinned.endsWith(`http://${NAME}/currentsetting.htm`), pinned);
});

test('(sp10) the REAL curl, handed http_probe\'s own argv: a brace or range name reaches no address with -g; without it, an expanded name reaches one the pin never named', async () => {
  const real = ['/usr/bin/curl', '/usr/local/bin/curl', '/opt/homebrew/bin/curl'].find((p) => fs.existsSync(p));
  assert.ok(real, 'no real curl on this machine — this leg cannot measure, and a skipped leg is not a pass');
  const hits = [];
  const server = http.createServer((req, res) => { hits.push(req.headers.host); res.end('Firmware=V1.0.0'); });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const port = server.address().port;
  const run = (args) => new Promise((resolve) => { const p = spawn(real, args, { stdio: 'ignore' }); p.on('close', (code) => resolve(code)); p.on('error', () => resolve(-1)); });
  // The argv probeFirmware hands curl, recorded by the stand-in, with its port moved from 80 to the receiver's in exactly the
  // two places that carry it (asserted). Every other argument — -q, --noproxy, -g, the timeouts — is the shipped one.
  const shipped = async (host, address) => {
    const line = (await recorded(() => runPinned({ [host]: [{ address, family: 4 }] }, () => probeFirmware(host, 'NETGEAR R7000')))).find((l) => l.startsWith('curl '));
    assert.ok(line, `curl was not run for ${host}`);
    const args = line.split(' ').slice(1);
    const r = args.indexOf('--resolve');
    assert.ok(r > 0 && args[r + 1].endsWith(`:80:${address}`), `no --resolve on port 80: ${line}`);
    args[r + 1] = args[r + 1].replace(/:80:([^:]+)$/, `:${port}:$1`);
    assert.ok(args.at(-1).endsWith('/currentsetting.htm') && !args.at(-1).slice(7).includes(':'), `the URL already carries a port: ${line}`);
    args[args.length - 1] = args.at(-1).replace(/^(http:\/\/[^/]+)\//, `$1:${port}/`);
    return args;
  };
  try {
    // Positive control: the shipped argv, -g included, still reaches the PINNED address for an ordinary name.
    const plain = await shipped('pin.test', '127.0.0.1');
    assert.equal(await run(plain), 0, 'positive control: curl failed on an ordinary pinned name');
    assert.deepEqual(hits, [`pin.test:${port}`], 'positive control: the pinned name did not reach the receiver exactly once');
    // `localhos{t,x}` and `localhos[s-t]` each expand to `localhost`, which the OS answers with loopback — where the receiver
    // listens. The pin sends the typed name to TEST-NET-1 (192.0.2.1), so any hit on the receiver is a name the pin did not cover.
    for (const host of ['localhos{t,x}', 'localhos[s-t]']) {
      hits.length = 0;
      const args = await shipped(host, '192.0.2.1');
      assert.ok(args.includes('-g'), `the shipped argv lacks -g: ${args.join(' ')}`);
      const withG = await run(args);
      assert.deepEqual(hits, [], `${host}: with -g an expanded name still reached loopback`);
      assert.notEqual(withG, 0, `${host}: with -g curl reported success`);
      // The pre-fix argv is the shipped one minus -g: curl expands the name and the OS sends `localhost` to the receiver.
      const preFix = args.filter((a) => a !== '-g');
      assert.equal(preFix.length, args.length - 1, 'exactly one -g was removed');
      await run(preFix);
      assert.ok(hits.some((h) => h === `localhost:${port}`), `${host}: the pre-fix argv did not reach loopback — this leg cannot tell -g from a dead probe (hits ${JSON.stringify(hits)})`);
    }
  } finally { await new Promise((r) => server.close(r)); }
});

// ── N1 of the architect's verdict on Community 7b91fea: a literal is ADMITTED on its canonical reading ─────────────────
// The entries skip the lookup and the pin for a host canonicalIp reads as an IP literal, so http_probe must hand curl that
// SAME literal. Until 2.2.0 it handed curl the typed string: `0x08080808.` and `8.8.8.8.` were admitted as 8.8.8.8 while curl
// kept each as a host NAME and resolved it through the OS (outside the check), a CLI-typed leading NBSP or trailing U+3000
// reached the URL untrimmed, and an unbracketed IPv6 literal made the URL malformed (curl rc=3: the probe never ran).
// The URL now carries the canonical literal — bracketed when it is IPv6, with no zone id.
const URL_OF = (h) => `http://${h}/currentsetting.htm`;
const LITERAL_ROWS = [
  // [typed, the host the URL must carry] — the first two held before the fix: the fourth quadrant, written first.
  ['8.8.8.8', '8.8.8.8'],
  ['[2001:db8::1]', '[2001:db8::1]'],
  ['2001:db8::1', '[2001:db8::1]'],
  ['2001:db8::1%en0', '[2001:db8::1]'],
  ['[2001:db8::1%25en0]', '[2001:db8::1]'],
  ['0x08080808.', '8.8.8.8'],
  ['8.8.8.8.', '8.8.8.8'],
  [' 8.8.8.8', '8.8.8.8'],
  ['8.8.8.8　', '8.8.8.8'],
];

// N2: a LINK-LOCAL literal keeps its zone, which names the host; in the URL its delimiter is `%25` (RFC 6874). Stand-ins only:
// with no proxy curl would need the zone's interface to exist on the machine running the suite.
const ZONE_ROWS = [['fe80::1%en0', '[fe80::1%25en0]'], ['[fe80::1%25en0]', '[fe80::1%25en0]']];

test('(sp11, first rows hold pre-fix) an IP literal reaches curl as its CANONICAL form — bracketed when IPv6, zone only when link-local — with no --resolve', async () => {
  for (const [typed, want] of [...LITERAL_ROWS, ...ZONE_ROWS]) {
    const line = (await recorded(() => probeFirmware(typed, 'NETGEAR R7000'))).find((l) => l.startsWith('curl '));
    assert.ok(line, `curl was not run for ${JSON.stringify(typed)}`);
    assert.equal(line.split(' ').pop(), URL_OF(want), `${JSON.stringify(typed)}: ${line}`);
    assert.ok(!line.includes('--resolve'), `${JSON.stringify(typed)}: a literal is never pinned, yet --resolve was passed: ${line}`);
    assert.equal(line.split(' ')[1], '-g', `${JSON.stringify(typed)}: -g is not curl's first argument: ${line}`);
  }
});

test('(sp12) the REAL curl, handed http_probe\'s own argv for a literal: its request names the canonical address; the pre-fix argv names the typed string', async () => {
  const real = ['/usr/bin/curl', '/usr/local/bin/curl', '/opt/homebrew/bin/curl'].find((p) => fs.existsSync(p));
  assert.ok(real, 'no real curl on this machine — this leg cannot measure, and a skipped leg is not a pass');
  // A loopback PROXY receives curl's request line, which carries curl's own reading of the URL host — and nothing leaves
  // this machine. A literal is unpinned, so the shipped argv takes the environment's proxy (asserted: no --noproxy).
  const urls = [];
  const server = http.createServer((req, res) => { urls.push(req.url); res.end('Firmware=V1.0.0'); });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const env = { ...process.env, http_proxy: `http://127.0.0.1:${server.address().port}` };
  for (const k of ['no_proxy', 'NO_PROXY', 'ALL_PROXY', 'all_proxy', 'HTTP_PROXY']) delete env[k];
  const run = (args) => new Promise((resolve) => { const p = spawn(real, args, { stdio: 'ignore', env }); p.on('close', (code) => resolve(code)); p.on('error', () => resolve(-1)); });
  const shipped = async (typed) => {
    const line = (await recorded(() => probeFirmware(typed, 'NETGEAR R7000'))).find((l) => l.startsWith('curl '));
    assert.ok(line, `curl was not run for ${JSON.stringify(typed)}`);
    const args = line.split(' ').slice(1);
    assert.ok(!args.includes('--noproxy') && !args.includes('-q'), `the literal argv refuses the proxy — this leg cannot measure: ${line}`);
    return args;
  };
  try {
    for (const [typed, want] of LITERAL_ROWS) {
      urls.length = 0;
      const code = await run(await shipped(typed));
      assert.equal(code, 0, `${JSON.stringify(typed)}: curl failed (rc=${code}) on the shipped argv`);
      assert.deepEqual(urls, [URL_OF(want)], `${JSON.stringify(typed)}: curl's request did not name the canonical address`);
    }
    // Negative control: the pre-fix argv (the typed string in the URL). curl keeps each of these as a host NAME, which it would
    // resolve through the OS — so this leg tells the canonical URL from the typed one.
    for (const typed of ['0x08080808.', '8.8.8.8.']) {
      urls.length = 0;
      const args = await shipped(typed);
      args[args.length - 1] = URL_OF(typed);
      await run(args);
      assert.deepEqual(urls, [URL_OF(typed)], `${typed}: the pre-fix argv did not reach the proxy as the typed name — this leg cannot tell the fix from its absence`);
    }
  } finally { await new Promise((r) => server.close(r)); }
});

// ── ARP (board item "ARP for a pinned name"): `arp -n <address> [-i <iface>]`, so its target is the token after `-n`. ──
const arpTargetsOf = (lines) => lines.filter((l) => l.startsWith('arp ')).map((l) => { const a = l.split(' '); return a[a.indexOf('-n') + 1]; });
// Loopback is private-like and refuses fast: ping_checker's in-process TCP probes go nowhere off this machine. DUAL-STACK,
// IPv6 FIRST: ARP is an IPv4 protocol (`arp -n` takes an IPv4 address), so each plugin must take the pinned IPv4 answer
// whatever order the resolver returned them in — a family preference no single-family fixture exercises.
const LAN = { [NAME]: [{ address: '::1', family: 6 }, { address: '127.0.0.1', family: 4 }] };
const PUBLIC = { [NAME]: [{ address: '203.0.113.10', family: 4 }] };

// Each plugin is recorded ALONE: driven together, either one's two `arp` runs (no interface, then en0) satisfied a count
// meant for both, and a plugin that stopped running `arp` read green — two survivors of the first battery.
const PLUGINS = [['arp_scanner', arpScanner], ['ping_checker', pingChecker]];

test('(sp6, first) a private IP LITERAL is handed to arp as itself, by each plugin — the case that always worked', async () => {
  for (const [name, plugin] of PLUGINS) {
    const targets = arpTargetsOf(await recorded(() => plugin.run('127.0.0.1')));
    assert.ok(targets.length >= 1 && targets.every((t) => t === '127.0.0.1'), `${name}: ${JSON.stringify(targets)}`);
  }
});

test('(sp7) a NAME pinned to a LAN address: each plugin hands arp the pinned address — never the name', async () => {
  for (const [name, plugin] of PLUGINS) {
    const lines = await recorded(() => runPinned(LAN, () => plugin.run(NAME)));
    const targets = arpTargetsOf(lines);
    assert.ok(targets.length >= 1, `${name} did not run arp for a name pinned to a LAN address: ${JSON.stringify(lines)}`);
    assert.ok(targets.every((t) => t === '127.0.0.1'), `${name}: ${JSON.stringify(targets)}`);
  }
});

test('(sp8) a NAME pinned to a PUBLIC address, and an UNPINNED name: arp is not run, and the not-attempted row is kept', async () => {
  const pub = await recorded(() => runPinned(PUBLIC, () => arpScanner.run(NAME)));
  const unpinned = await recorded(() => arpScanner.run(NAME));
  assert.deepEqual([arpTargetsOf(pub), arpTargetsOf(unpinned)], [[], []]);
  for (const run of [await runPinned(PUBLIC, () => arpScanner.run(NAME)), await arpScanner.run(NAME)]) {
    assert.ok(run.data.some((r) => /Non-local target — ARP not attempted/.test(String(r.probe_info))), JSON.stringify(run.data));
  }
});

