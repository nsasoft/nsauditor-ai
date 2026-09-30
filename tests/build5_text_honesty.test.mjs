// THE README, --help AND THE probe_service SCHEMA SAY WHAT THE CODE DOES (CE 0.2.56 build 5 — the operator's ruling
// "text now, behaviour 1.2.1"; drafted and adversarially finalized by workflow wf_21d5e8a8-51a).
// Each leg DERIVES the truth from the shipped code, then holds the README / --help / MCP schema
// text to it. Absent-regexes are keyed on the CLAIM SHAPE, with \s+ across hard wraps.
// No subprocess: the help text is read from the cli.mjs source (no licence resolver, no Keychain).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const read = (rel) => fs.readFileSync(path.join(ROOT, rel), 'utf8');
const README = read('README.md');
const CLI = read('cli.mjs');
const HELP = (() => {
  const i = CLI.indexOf('nsauditor-ai — Modular AI-assisted');
  assert.ok(i > 0, 'help template not found in cli.mjs');
  return CLI.slice(i, CLI.indexOf('`', i));
})();
const flagBlock = (text, flag) => {
  const m = text.match(new RegExp(`\\n  ${flag.replace(/-/g, '\\-')}\\b[\\s\\S]*?(?=\\n  --|\\n\\n)`));
  assert.ok(m, `no ${flag} entry in --help`);
  return m[0];
};
const CTEM = (() => {
  const i = README.indexOf('## Continuous Monitoring (CTEM)');
  assert.ok(i > 0, 'README has no Continuous Monitoring (CTEM) section');
  const j = README.indexOf('\n## ', i + 5);
  return README.slice(i, j > 0 ? j : undefined);
})();

// ── A. watch mode: does the webhook fire on a service change? DERIVED by driving the real delta gate
//    with the shape the watch loop actually hands it (source tripwires on both ends).
async function webhookFiresOnServiceChange() {
  assert.match(CLI, /scanFn:\s*async \(h\) => \{\s*const out = await scanSingleHost\([^)]*\);\s*return out;/,
    'TRIPWIRE: scanFn no longer returns scanSingleHost output unmapped — re-derive this leg');
  assert.match(CLI, /buildDeltaReport\(results, previousCycleResults\)/,
    'TRIPWIRE: the watch loop no longer calls buildDeltaReport(results, previousCycleResults)');
  const fn = CLI.slice(CLI.indexOf('async function scanSingleHost('));
  const ret = fn.match(/\n  return \{([\s\S]*?)\};\n\}/);
  assert.ok(ret, 'TRIPWIRE: scanSingleHost return block not found');
  const keys = ret[1].replace(/\/\/[^\n]*/g, '').split(/[,\s]+/).filter((k) => /^[A-Za-z_$][\w$]*$/.test(k));
  assert.ok(keys.includes('conclusion') && keys.length >= 3, `return keys unreadable: ${keys}`);
  const shaped = (services) => Object.fromEntries(keys.map((k) => [k,
    k === 'conclusion' ? { result: { services } } : k === 'host' ? 'h' : null]));
  const { buildDeltaReport, hasSignificantChanges } =
    await import(pathToFileURL(path.join(ROOT, 'utils/delta_reporter.mjs')).href);
  const before = [{ port: 21, protocol: 'tcp', service: 'ftp', version: '1.0' }];
  const after = [{ port: 21, protocol: 'tcp', service: 'ftp', version: '2.0', anonymousLogin: true },
    { port: 22, protocol: 'tcp', service: 'ssh', version: '9' }];
  const top = (services) => ({ services, findingsCount: 0, tier: 'ce' });
  assert.equal(hasSignificantChanges(buildDeltaReport(new Map([['h', top(after)]]), new Map([['h', top(before)]]))), true,
    'NEGATIVE CONTROL: the driver cannot see a change even in the shape computeDiff reads');
  return hasSignificantChanges(buildDeltaReport(new Map([['h', shaped(after)]]), new Map([['h', shaped(before)]])));
}

// Claim shape: a webhook/alert that FIRES or SENDS on/when a change — not preceded by a negation.
const OVERCLAIM_WATCH = [
  /(?<!not\s)\b(?:fires?|sends?)\s+(?:--webhook-url\s+|webhook\s+)?(?:alerts?\s+)?(?:on|when)\s+(?:\S+\s+){0,6}?changes?\b/i,
  /Delta detection\*\*\s*—\s*new,\s+removed,\s+and\s+changed\s+services\s+highlighted\s+between\s+cycles/i,
  /Webhook URL for delta alerts|Send delta alerts/,
];
const DISCLOSED = /does\s+(?:NOT|not)\s+fire\s+on\s+a\s+service,\s+version\s+or\s+finding\s+change/;

test('A. the watch-mode webhook text matches what the delta gate does (README + --help)', async () => {
  const fires = await webhookFiresOnServiceChange();
  const surfaces = { 'README.md': README, '--help': HELP };
  if (fires) {
    // PINNED, NOT ENDORSED: when the gate is fixed, every disclosure must flip in the same commit.
    for (const [n, s] of Object.entries(surfaces)) assert.doesNotMatch(s, DISCLOSED, `${n} still says the webhook does not fire — the gate now fires`);
    return;
  }
  for (const [n, s] of Object.entries(surfaces)) {
    for (const re of OVERCLAIM_WATCH) assert.doesNotMatch(s, re, `${n} promises a change alert the gate never sends: ${re}`);
  }
  assert.match(flagBlock(HELP, '--watch'), DISCLOSED, '--help --watch does not say the webhook does not fire on a change');
  const row = README.split('\n').find((l) => l.startsWith('| `--watch` |'));
  assert.ok(row, 'README has its --watch row');
  assert.match(row, /not on a service, version or finding change/, 'the README --watch row does not state the limit');
  assert.match(CTEM, DISCLOSED, 'the Continuous Monitoring section does not state the limit');
  // At `info` every service counts: DERIVED from SEVERITY_RANK.info and the per-service filter.
  const rank = CLI.match(/const SEVERITY_RANK = \{[^}]*\binfo:\s*(\d+)\s*\}/);
  assert.ok(rank && /return svcSev >= sevRank;/.test(CLI), 'TRIPWIRE: SEVERITY_RANK or the per-service alert filter changed');
  if (Number(rank[1]) === 0) assert.match(CTEM, /at `info`, every service counts/, 'at info the filter passes every service; the section must say so');
});

// ── B. webhook retry wording DERIVED from the call site and the sender.
test('B. the README states the webhook retry as it ships', () => {
  const call = CLI.match(/sendWebhook\(webhookUrl, payload, \{ retries: (\d+), retryDelayMs: (\d+) \}\)/);
  assert.ok(call, 'TRIPWIRE: the watch-loop sendWebhook call changed shape');
  assert.match(read('utils/webhook.mjs'), /setTimeout\(r, retryDelayMs\)/, 'TRIPWIRE: the retry delay is no longer a constant');
  const times = { 1: 'once', 2: 'twice', 3: 'three times' }[call[1]];
  const secs = Number(call[2]) / 1000;
  assert.doesNotMatch(README, /exponential\s+backoff/i, 'the sender waits a constant delay; there is no backoff');
  assert.match(CTEM, new RegExp(`retried up to ${times} ${secs} s apart`), `the section must say "retried up to ${times} ${secs} s apart"`);
});

// ── C. scan-history location DERIVED from the module's own constant, bound to the bullet that states it.
test('C. the README names the scan-history file the code writes', async () => {
  const { HISTORY_FILE } = await import(pathToFileURL(path.join(ROOT, 'utils/scan_history.mjs')).href);
  assert.doesNotMatch(README, /`\.scan_history\/`/, 'no .scan_history/ directory exists');
  const bullet = README.split('\n').find((l) => l.startsWith('- **Scan history**'));
  assert.ok(bullet, 'README has its Scan history bullet');
  assert.ok(bullet.includes('`' + HISTORY_FILE + '`'), `the Scan history bullet must name \`${HISTORY_FILE}\``);
  assert.match(bullet, /`--out`/, 'the Scan history bullet must say the file sits in the --out directory');
});

// ── D. --ports: ADDED, and a range is not parsed — DERIVED from parsePortsSpec and the merge line.
test('D. --help and the README describe --ports as the port scanner treats it', async () => {
  const { parsePortsSpec } = await import(pathToFileURL(path.join(ROOT, 'plugins/port_scanner.mjs')).href);
  assert.match(read('plugins/port_scanner.mjs'), /tcpPorts = uniqInts\(\[\.\.\.tcpPorts, \.\.\.extra\.tcp\]\)/,
    'TRIPWIRE: --ports is no longer merged additively');
  const rangeParses = parsePortsSpec('1-1000').tcp.length > 0;
  const help = flagBlock(HELP, '--ports');
  const row = README.split('\n').find((l) => l.startsWith('| `--ports'));
  assert.ok(row, 'README has its --ports row');
  for (const [n, s] of [['--help', help], ['README row', row]]) {
    assert.doesNotMatch(s, /\boverride\b/i, `${n} calls --ports an override; the ports are ADDED`);
    if (!rangeParses) {
      const ranges = s.match(/\b\d+\s*[-–]\s*\d+\b/g) || [];
      if (ranges.length) assert.match(s, /not parsed/, `${n} shows a range (${ranges}) that parsePortsSpec drops`);
    }
  }
  assert.match(help, /ADDED|\badd/i, '--help must say the ports are added');
});

// ── E. probe_service pluginName: every quoted example RESOLVES through the real findPlugin over the
//    real CE plugin set (imported directly — no PluginManager.create, no EE discovery).
test('E. every probe_service pluginName example resolves to a plugin', async () => {
  const { TOOLS } = await import(pathToFileURL(path.join(ROOT, 'mcp_server.mjs')).href);
  const desc = TOOLS.find((t) => t.name === 'probe_service').inputSchema.properties.pluginName.description;
  const examples = [...desc.matchAll(/"([^"]+)"/g)].map((m) => m[1]);
  assert.ok(examples.length > 0, 'no quoted example extracted — the leg would pass vacuously');
  const PM = (await import(pathToFileURL(path.join(ROOT, 'plugin_manager.mjs')).href)).default;
  const dir = path.join(ROOT, 'plugins');
  const plugins = [];
  for (const f of fs.readdirSync(dir).filter((x) => x.endsWith('.mjs'))) {
    const m = await import(pathToFileURL(path.join(dir, f)).href);
    const p = m.default ?? m;
    if (p && p.id != null && p.name != null) plugins.push({ id: p.id, name: p.name });
  }
  assert.ok(plugins.length >= 10, `plugin set unreadable (${plugins.length})`);
  const find = (q) => PM.prototype.findPlugin.call({ plugins }, q);
  assert.equal(find('ssh_scanner'), null, 'NEGATIVE CONTROL: the resolver accepts anything');
  const dead = examples.filter((q) => !find(q));
  assert.deepEqual(dead, [], `pluginName examples that return "Unknown plugin": ${dead.join(', ')}`);
});

// ── F. no Desktop per-call limit stated as fact; the dated observations stated instead.
test('F. the README states no Desktop tool-call limit as fact, and gives the dated observations', () => {
  const LIMIT_AS_FACT = [
    /~?\s*60\s*s(?:econds?)?\b[^.\n]{0,20}\s+(?:MCP\s+)?tool-call\s+(?:limit|cap)/i,
    /(?:fits|within)\s+(?:Claude\s+)?Desktop's\s+(?:~?\s*60\s*s\s+)?(?:limit|window|wall|cap)/i,
    /~60\s*s\s+window|Desktop's\s+wall/i,
    /automatic\s+region-batching|fits\s+Desktop's\s+limit\s+automatically/i,
  ];
  for (const re of LIMIT_AS_FACT) assert.doesNotMatch(README, re, `README states a Desktop limit as fact: ${re}`);
  assert.equal((read('mcp_server.mjs').match(/pm\.runCloud\(/g) || []).length, 1, 'TRIPWIRE: scan_cloud call path changed');
  assert.match(README, /does not split a `regions:\["all"\]` call/);
  assert.match(README, /timed out in Claude Desktop on 2026-08-10/);
  assert.match(README, /returned within 138 s on 2026-09-30/);
  const cloudDefault = read('plugin_manager.mjs').match(/rawTimeout > 0 \? rawTimeout : (\d+)/)[1];
  assert.match(README, new RegExp('`CLOUD_PLUGIN_TIMEOUT_MS` \\(default `?' + cloudDefault));
  assert.match(README, /bounds each plugin, not the call/);
});
