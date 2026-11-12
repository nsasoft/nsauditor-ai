import './helpers/no_operator_dotenv.mjs';
import './helpers/no_operator_keychain.mjs';   // FIRST: this file imports cli.mjs
// tests/scan_target_canonical.test.mjs
// ─────────────────────────────────────────────────────────────────────────────
// N2 OF THE ARCHITECT'S VERDICT ON COMMUNITY 1264650 — a scan target is the address its check CLASSIFIED.
// The entries admit a host that canonicalIp reads as an IP literal with no lookup and no pin. Until 2.2.0 both handed the
// plugins the TYPED string, and canonicalIp's reader (WHATWG: a leading-zero part is OCTAL) and the OS resolver (macOS
// getaddrinfo: a leading-zero part of a DOTTED quad is DECIMAL) disagree: `0127.0.0.1` was classified as public 87.0.0.1
// and connected to 127.0.0.1; `010.0.0.01` was classified 8.0.0.1 and reached 10.0.0.1 with no NSA_ALLOW_ALL_HOSTS.
//   1. Both entries hand the plugins the CANONICAL literal (CLI scanSingleHost, MCP validateHostPinned).
//   2. A numeric host with a leading-zero part is refused at admission, before any lookup, in every arm.
//   3. An IPv6 zone is kept only for a link-local address (fe80::/10) — an unscoped fe80::1 is not the host fe80::1%en0.
// Driven through the real entries with a plugin manager that records the host it is handed; a real loopback listener
// and real plugins (with recording stand-ins for their commands) close it to the chain.
//
// FOURTH QUADRANT FIRST: the accepts.
// ─────────────────────────────────────────────────────────────────────────────
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';
import dnsPromises from 'node:dns/promises';
import PluginManager from '../plugin_manager.mjs';
import hostUpCheck from '../plugins/host_up_check.mjs';
import pingChecker from '../plugins/ping_checker.mjs';
import synScanner from '../plugins/syn_scanner.mjs';
import arpScanner from '../plugins/arp_scanner.mjs';
import { canonicalIp, isHostnameSyntax } from '../utils/net_validation.mjs';
import { scanSingleHost } from '../cli.mjs';
import { handleScanHost, _setPluginManager, _setValidateHost } from '../mcp_server.mjs';

const lookups = [];
const origLookup = dnsPromises.lookup;
dnsPromises.lookup = async function spy(h, o) { lookups.push(String(h)); return origLookup.call(dnsPromises, h, o); };
const saved = {};
for (const k of ['NSA_ALLOW_ALL_HOSTS', 'PATH', 'SHIM_LOG', 'ENABLE_SYN_SCAN']) saved[k] = process.env[k];
after(() => {
  dnsPromises.lookup = origLookup; _setPluginManager(null); _setValidateHost(null);
  for (const [k, v] of Object.entries(saved)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
});

const STOP = /stop: the scan body ran/;
const notStop = (e) => !STOP.test(String(e?.message));
/** A plugin manager whose scan records the host it was handed, optionally does something with it, then stops the handler. */
function hostPm(seen, act = async () => {}) {
  const scan = async (host) => { seen.push(host); await act(host); throw new Error('stop: the scan body ran'); };
  return { run: scan, _runOne: (plugin, host) => scan(host), findPlugin: () => ({ id: '999', name: 'stand-in network plugin' }) };
}
const allowAll = (on) => { if (on) process.env.NSA_ALLOW_ALL_HOSTS = '1'; else delete process.env.NSA_ALLOW_ALL_HOSTS; };
const cliScan = (pm, typed) => scanSingleHost(pm, typed, 'all', {}, false);
const mcpScan = (pm, typed) => { _setPluginManager(pm); _setValidateHost(null); return handleScanHost({ host: typed }); };
async function handedBy(entry, typed) {
  const seen = [];
  await assert.rejects(entry(hostPm(seen), typed), STOP, `${JSON.stringify(typed)} did not reach the scan body`);
  return seen[0];
}

test('(n2-1, first) both entries hand the plugins the CANONICAL literal — the reading the check classified', async () => {
  allowAll(false);
  // [typed, what the CLI hands on, what MCP hands on] — MCP lowercases the host before its check.
  const rows = [
    ['8.8.8.8', '8.8.8.8', '8.8.8.8'],
    ['0x08080808', '8.8.8.8', '8.8.8.8'],
    ['134744072', '8.8.8.8', '8.8.8.8'],
    ['8.8.8.8.', '8.8.8.8', '8.8.8.8'],
    ['2001:DB8::1', '2001:DB8::1', '2001:db8::1'],
    ['[2001:db8::1]', '2001:db8::1', '2001:db8::1'],
    ['2001:db8::1%en0', '2001:db8::1', '2001:db8::1'],
  ];
  for (const [typed, cli, mcp] of rows) {
    assert.equal(await handedBy(cliScan, typed), cli, `CLI, ${JSON.stringify(typed)}`);
    assert.equal(await handedBy(mcpScan, typed), mcp, `MCP, ${JSON.stringify(typed)}`);
  }
});

test('(n2-2) a name that merely LOOKS numeric is still a name — `0123.cafe` passes the syntax check; `[::1]` is refused as before', async () => {
  for (const name of ['0123.cafe', '010.example', 'a0127.0.0.1', 'bücher.example', '6425673729']) {
    assert.equal(canonicalIp(name), null, name);
    assert.equal(isHostnameSyntax(name), true, `${name}: a name with a leading-zero label but a non-numeric part is not ambiguous`);
  }
  allowAll(false);
  await assert.rejects(cliScan(hostPm([]), '[::1]'), { code: 'ETARGETREFUSED' });
  await assert.rejects(mcpScan(hostPm([]), '[::1]'), /not allowed via MCP/);
});

const AMBIGUOUS = ['0127.0.0.1', '0127.0.0.01', '010.0.0.01', '169.0254.169.254', '192.168.001.001', '08.8.8.8', '02130706433', '0x7f.000.0.1'];

test('(n2-3) a numeric host with a leading-zero part is refused at admission, before any lookup — CLI in both arms, and MCP', async () => {
  for (const typed of AMBIGUOUS) {
    assert.equal(canonicalIp(typed), null, `${typed}: admitted as a literal`);
    assert.equal(isHostnameSyntax(typed), false, `${typed}: passes as a host name`);
    for (const arm of [false, true]) {
      allowAll(arm);
      lookups.length = 0;
      // Guarded, the CLI refuses a classifier-blocked reading first (`192.168.001.001` reads private, `0x7f.000.0.1`
      // loopback); under NSA_ALLOW_ALL_HOSTS nothing classifies, so only the syntax refusal can stop it.
      const why = arm ? /not a valid host name.*leading zero/s : /not a valid host name.*leading zero|blocked address range/s;
      await assert.rejects(cliScan(hostPm([]), typed), (e) => e.code === 'ETARGETREFUSED' && why.test(e.message),
        `CLI${arm ? ' (NSA_ALLOW_ALL_HOSTS)' : ''}, ${typed}`);
      assert.ok(!lookups.includes(typed), `CLI${arm ? ' (NSA_ALLOW_ALL_HOSTS)' : ''}, ${typed}: looked up before the refusal`);
    }
    allowAll(false);
    lookups.length = 0;
    // MCP refuses a classifier-blocked reading first (`0127.0.0.01` is not; `192.168.001.001` reads private) — either is a
    // refusal; neither scan body runs.
    await assert.rejects(mcpScan(hostPm([]), typed), (e) => notStop(e) && /not a valid host name|not allowed via MCP/.test(e.message), `MCP, ${typed}`);
    assert.ok(!lookups.includes(typed.toLowerCase()), `MCP, ${typed}: looked up before the refusal`);
  }
});

test('(n2-4) a REAL loopback listener: this OS reads `0127.0.0.1` as loopback (positive control on darwin), and no entry lets a scan reach it', async () => {
  let hits = 0;
  const server = net.createServer((sock) => { hits += 1; sock.destroy(); });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const port = server.address().port;
  const reach = (host) => new Promise((resolve) => {
    const s = net.connect({ host, port });
    const done = (v) => { s.destroy(); resolve(v); };
    s.on('connect', () => done(true)); s.on('error', () => done(false)); s.setTimeout(1500, () => done(false));
  });
  const settle = () => new Promise((r) => setTimeout(r, 150));
  try {
    const osReading = await reach('0127.0.0.1');
    await settle();
    if (process.platform === 'darwin') {
      assert.ok(osReading && hits === 1, 'positive control: `0127.0.0.1` did not reach the loopback listener — this leg cannot tell the fix from its absence');
    }
    hits = 0;
    const entries = [['CLI', cliScan, false], ['CLI (NSA_ALLOW_ALL_HOSTS)', cliScan, true], ['MCP', mcpScan, false]];
    for (const [name, entry, arm] of entries) {
      allowAll(arm);
      const seen = [];
      await assert.rejects(entry(hostPm(seen, reach), '0127.0.0.1'), notStop, `${name}: the scan body ran for 0127.0.0.1`);
    }
    await settle();
    assert.equal(hits, 0, 'a scan reached the loopback listener through an entry');
  } finally { allowAll(false); await new Promise((r) => server.close(r)); }
});

test('(n2-5) an IPv6 zone is kept only for a link-local address — and only the CLI under NSA_ALLOW_ALL_HOSTS admits one', async () => {
  const rows = [
    ['fe80::1%en0', 'fe80::1%en0'],
    ['FE80::1%en0', 'FE80::1%en0'],
    ['[fe80::1%25en0]', 'fe80::1%en0'],   // RFC 6874: inside brackets the zone delimiter is `%25`
    ['[fe80::1%en0]', 'fe80::1%en0'],
    ['fe80::1%25en0', 'fe80::1%25en0'],   // outside brackets `%25` is not the RFC 6874 delimiter: the zone is `25en0`
    ['febf::1%en0', 'febf::1%en0'],        // the top of fe80::/10
    ['fec0::1%en0', 'fec0::1'],             // just outside it
    ['2001:db8::1%en0', '2001:db8::1'],
    ['[2001:db8::1%25en0]', '2001:db8::1'],
  ];
  for (const [typed, want] of rows) assert.equal(canonicalIp(typed), want, `canonicalIp(${JSON.stringify(typed)})`);
  allowAll(true);
  try {
    assert.equal(await handedBy(cliScan, 'fe80::1%en0'), 'fe80::1%en0');
    assert.equal(await handedBy(cliScan, '[fe80::1%25en0]'), 'fe80::1%en0');
  } finally { allowAll(false); }
  await assert.rejects(mcpScan(hostPm([]), 'fe80::1%en0'), /not allowed via MCP/);
});

test('(n2-6) REAL plugins behind the CLI entry: every subprocess row receives the canonical literal, not the typed spelling', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'n2-shims-'));
  const log = path.join(dir, 'argv.log');
  for (const cmd of ['ping', 'nping', 'hping3', 'nmap', 'arp']) {
    fs.writeFileSync(path.join(dir, cmd), `#!/bin/sh\necho "${cmd} $*" >> "$SHIM_LOG"\nexit 1\n`, { mode: 0o755 });
  }
  process.env.PATH = `${dir}${path.delimiter}${saved.PATH}`;
  process.env.SHIM_LOG = log;
  process.env.ENABLE_SYN_SCAN = '1';
  fs.writeFileSync(log, '');
  allowAll(true);   // the CLI's allow-all admits loopback, so the plugins' own TCP probes are refused fast on this machine
  try {
    const real = await PluginManager.create({ plugins: [hostUpCheck, pingChecker, synScanner, arpScanner] });
    const seen = [];
    const pm = { run: async (h, p, o) => { seen.push(h); await real.run(h, p, o); throw new Error('stop: the scan body ran'); } };
    await assert.rejects(cliScan(pm, '0x7f000001'), STOP);
    assert.deepEqual(seen, ['127.0.0.1']);
    const lines = fs.readFileSync(log, 'utf8').trim().split('\n').filter(Boolean);
    const targetOf = (l) => { const a = l.split(' '); return a[0] === 'arp' ? a[a.indexOf('-n') + 1] : a.at(-1); };
    for (const cmd of ['ping', 'nmap', 'arp']) assert.ok(lines.some((l) => l.startsWith(`${cmd} `)), `${cmd} was not run: ${JSON.stringify(lines)}`);
    assert.deepEqual([...new Set(lines.map(targetOf))], ['127.0.0.1'], `a command was handed something else: ${JSON.stringify(lines)}`);
  } finally {
    allowAll(false);
    process.env.PATH = saved.PATH;
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// ── The independent review of 81d299c: a NAME the URL parser reads as an IP address ────────────────────────────────────────
// The belt above reads ASCII digits. Typed in other digits or dots (U+FF10 fullwidth zero, U+FF0E fullwidth dot, U+1D7CE
// mathematical bold zero), `0177.0.0.1` is not an IP literal to canonicalIp, so it is a NAME: the system resolver answers
// 177.0.0.1 (decimal, public) and both entries admitted it, while canonicalHost and the WHATWG URL parser normalise the glyphs
// and read `0177` as octal — 127.0.0.1 — so a plugin that builds a URL (webapp_detector, tribe_health) connected to loopback
// with no lookup to pin. A name whose canonical form IS an IP address is refused before any lookup.
const READS_AS_ADDRESS = ['０177.0.0.1', '0177．0．0．1', '\u{1D7CE}177.0.0.1', '０１２７．０．０．１', '８.８.８.８'];

test('(n2-7) a name that the URL parser reads as an IP address is refused before any lookup — CLI in both arms, and MCP; a REAL URL client never reaches loopback', async () => {
  let hits = 0;
  const server = net.createServer((sock) => { hits += 1; sock.destroy(); });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const port = server.address().port;
  const fetchIt = async (host) => { try { await fetch(`http://${host}:${port}/`, { signal: AbortSignal.timeout(1500) }); } catch { /* the listener hangs up */ } };
  const settle = () => new Promise((r) => setTimeout(r, 150));
  try {
    await fetchIt('０177.0.0.1');
    await settle();
    assert.ok(hits >= 1, 'positive control: a URL client handed the typed glyph host did not reach the loopback listener — this leg cannot tell the fix from its absence');
    hits = 0;
    for (const typed of READS_AS_ADDRESS) {
      assert.equal(canonicalIp(typed), null, `${JSON.stringify(typed)}: admitted as a literal`);
      assert.equal(isHostnameSyntax(typed), false, `${JSON.stringify(typed)}: passes as a host name`);
      for (const arm of [false, true]) {
        allowAll(arm);
        lookups.length = 0;
        await assert.rejects(cliScan(hostPm([], fetchIt), typed),
          (e) => e.code === 'ETARGETREFUSED' && /not a valid host name.*reads as the IP address/s.test(e.message),
          `CLI${arm ? ' (NSA_ALLOW_ALL_HOSTS)' : ''}, ${JSON.stringify(typed)}`);
        assert.ok(!lookups.includes(typed), `CLI${arm ? ' (NSA_ALLOW_ALL_HOSTS)' : ''}, ${JSON.stringify(typed)}: looked up before the refusal`);
      }
      allowAll(false);
      lookups.length = 0;
      await assert.rejects(mcpScan(hostPm([], fetchIt), typed), (e) => notStop(e) && /not a valid host name via MCP/.test(e.message), `MCP, ${JSON.stringify(typed)}`);
      assert.ok(!lookups.some((l) => l === typed || l === typed.toLowerCase()), `MCP, ${JSON.stringify(typed)}: looked up before the refusal`);
    }
    await settle();
    assert.equal(hits, 0, 'a scan reached the loopback listener through an entry');
  } finally { allowAll(false); await new Promise((r) => server.close(r)); }
});
