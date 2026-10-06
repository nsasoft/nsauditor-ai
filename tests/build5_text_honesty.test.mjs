// THE README, --help AND THE probe_service SCHEMA SAY WHAT THE CODE DOES (CE 0.2.56 build 5 — the operator's ruling
// "text now, behaviour 1.3.0"; drafted and adversarially finalized by workflow wf_21d5e8a8-51a).
// Each leg DERIVES the truth from the shipped code, then holds the README / --help / MCP schema
// text to it. Absent-regexes are keyed on the CLAIM SHAPE, with \s+ across hard wraps.
// No subprocess: the help text is read from the cli.mjs source (no licence resolver, no Keychain).
import { watchScan } from './helpers/watch_scan.mjs';
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

// ── A. watch mode: does the webhook fire on a service change? DERIVED by driving the REAL producer (scanSingleHost through
//    Community's PluginManager, tests/helpers/watch_scan.mjs) into the function the watch loop runs (watchCycle), with
//    source tripwires on the loop's two ends. RE-POINTED at items 4 + 11: this leg used to rebuild scanSingleHost's
//    return shape from its source — a model of the defect, not a drive of it.
async function watchBehaviour() {
  assert.match(CLI, /scanFn:\s*async \(h\) => \{\s*const out = await scanSingleHost\([^)]*\);\s*return out;/,
    'TRIPWIRE: scanFn no longer returns scanSingleHost output unmapped — re-derive this leg');
  assert.match(CLI, /watchCycle\(results, previousCycleResults,\s*\{[^}]*everyCycle: alertEveryCycle\s*\}\)/,
    'TRIPWIRE: the watch loop no longer hands its cycle results, and the --alert-every-cycle choice, to watchCycle');
  assert.match(CLI, /for \(const \{ host: h, findings \} of alerts\)[\s\S]{0,120}buildAlertPayload\(h, findings, alertSeverity\)/,
    'TRIPWIRE: the watch loop no longer sends exactly watchCycle\'s alerts');
  const { scan } = await watchScan();
  const { watchCycle } = await import(pathToFileURL(path.join(ROOT, 'utils/watch_cycle.mjs')).href);
  const { severityRank } = await import(pathToFileURL(path.join(ROOT, 'utils/service_flags.mjs')).href);
  const rank = severityRank('High');
  const h = '203.0.113.40';
  const g = '203.0.113.41';
  const prev = new Map([[h, await scan(h, { ssh: '8.0', ftp: true })]]);
  const cur = new Map([[h, await scan(h, { ssh: '8.9', ftp: true })]]);
  assert.ok(prev.get(h).scanSummary?.services?.length === 2, 'POSITIVE CONTROL: the driver produced a real scan output with its summary');
  const first = new Map([[g, await scan(g, { ftp: true })]]);
  return {
    fires: watchCycle(cur, prev, { alertRank: rank }).alerts.length > 0,
    firstSilent: watchCycle(first, null, { alertRank: rank }).alerts.length === 0,
    everyFromFirst: watchCycle(first, null, { alertRank: rank, everyCycle: true }).alerts.length > 0,
    failedSilent: watchCycle(new Map([[h, { error: 'down' }]]), cur, { alertRank: rank, everyCycle: true }).alerts.length === 0,
  };
}

// Claim shape: a webhook/alert that FIRES or SENDS on/when a change — not preceded by a negation.
const OVERCLAIM_WATCH = [
  /(?<!not\s)\b(?:fires?|sends?)\s+(?:--webhook-url\s+|webhook\s+)?(?:alerts?\s+)?(?:on|when)\s+(?:\S+\s+){0,6}?changes?\b/i,
  /Delta detection\*\*\s*—\s*new,\s+removed,\s+and\s+changed\s+services\s+highlighted\s+between\s+cycles/i,
  /Webhook URL for delta alerts|Send delta alerts/,
];
const DISCLOSED = /does\s+(?:NOT|not)\s+fire\s+on\s+a\s+service,\s+version\s+or\s+finding\s+change/;

test('A. the watch-mode webhook text matches what the delta gate does (README + --help)', async () => {
  const b = await watchBehaviour();
  const surfaces = { 'README.md': README, '--help': HELP };
  const watchHelp = flagBlock(HELP, '--watch');
  const row = README.split('\n').find((l) => l.startsWith('| `--watch` |'));
  assert.ok(row, 'README has its --watch row');
  if (b.fires) {
    // Every disclosure of the old limit flipped in the same commit — and the trigger is stated EXACTLY (scout risk (c)):
    // a changed host with a finding at or above the severity, a silent first cycle, the every-cycle flag, a failed scan.
    for (const [n, s] of Object.entries(surfaces)) assert.doesNotMatch(s, DISCLOSED, `${n} still says the webhook does not fire — the gate now fires`);
    assert.match(watchHelp, /alerts a host whose scan changed[\s\S]*?finding at or above --alert-severity/, '--help --watch names the trigger');
    assert.match(row, /webhook for a host whose scan changed and that carries a finding at or above `--alert-severity`/, 'the README row names the trigger');
    if (b.firstSilent) {
      assert.match(watchHelp, /first cycle sets the\s+baseline and alerts nobody/, '--help says the first cycle alerts nobody');
      assert.match(row, /the first cycle sets the baseline and alerts nobody/, 'the README row says the first cycle alerts nobody');
      assert.match(CTEM, /The first cycle establishes the baseline and does not alert, whatever it finds/, 'the section says the first cycle is silent');
    }
    if (b.everyFromFirst) {
      assert.match(flagBlock(HELP, '--alert-every-cycle'), /on every --watch cycle, the first included/, '--help names the every-cycle flag');
      assert.match(CTEM, /`--alert-every-cycle` alerts every host carrying such a finding on every cycle, the first included/, 'the section names it');
    }
    if (b.failedSilent) {
      assert.match(watchHelp, /whose scan failed is reported on stdout and does not alert/, '--help says a failed scan does not alert');
      assert.match(CTEM, /A host whose scan failed is reported on stdout and does not alert in this release/, 'the section says so');
    }
  } else {
    for (const [n, s] of Object.entries(surfaces)) {
      for (const re of OVERCLAIM_WATCH) assert.doesNotMatch(s, re, `${n} promises a change alert the gate never sends: ${re}`);
    }
    assert.match(watchHelp, DISCLOSED, '--help --watch does not say the webhook does not fire on a change');
    assert.match(row, /not on a service, version or finding change/, 'the README --watch row does not state the limit');
    assert.match(CTEM, DISCLOSED, 'the Continuous Monitoring section does not state the limit');
  }
  // At `info` every FINDING counts: DERIVED from SEVERITY_RANK.info and the per-finding filter (1.3.0 (s1): the alert lists
  // the shared table's findings, one per item — it listed every service, finding or not, until then).
  const rank = CLI.match(/const SEVERITY_RANK = \{[^}]*\binfo:\s*(\d+)\s*\}/);
  assert.ok(rank && /\.filter\(\(f\) => severityRank\(f\.severity\) >= alertRank\)/.test(read('utils/watch_cycle.mjs')),
    'TRIPWIRE: SEVERITY_RANK or the per-finding alert filter changed');
  if (Number(rank[1]) === 0) assert.match(CTEM, /at `info`, every finding counts; a host with none gets no alert/, 'at info the filter passes every finding; the section must say so');
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
const DURATION = /(?<![=\w-])~?\s*\d+(?:\.\d+)?\s*(?:s|secs?|seconds?|-second|min(?:ute)?s?)\b|\b(?:a|one)\s+minute\b/i;
const SIXTY_LIMIT = [
  /(?<![=\w-])~?\s*60\s*(?:s|secs?|seconds?|-second)\b[^.\n]{0,40}\b(?:limit|cap|window|wall|budget|kill)/i,
  /\b(?:limit|cap|window|wall|budget|kill)\w*\b[^.\n]{0,40}(?<![=\w-])~?\s*60\s*(?:s|secs?|seconds?|-second)\b/i,
];
function desktopLimitAsFact(text) {
  const units = text.split(/(?<=[.!?])\s+|\n\s*\n|\n(?=\s*(?:[-*|>]|\d+\.)\s)/);
  return units.map((u) => u.replace(/\s+/g, ' ')).filter((u) => !/\b20\d\d-\d\d-\d\d\b/.test(u)
    && ((/\bDesktop\b/.test(u) && DURATION.test(u)) || SIXTY_LIMIT.some((re) => re.test(u))));
}
test('F. the README states no Desktop tool-call limit as fact, and gives the dated observations', () => {
  const LIMIT_AS_FACT = [
    /~?\s*60\s*s(?:econds?)?\b[^.\n]{0,20}\s+(?:MCP\s+)?tool-call\s+(?:limit|cap)/i,
    /(?:fits|within)\s+(?:Claude\s+)?Desktop's\s+(?:~?\s*60\s*s\s+)?(?:limit|window|wall|cap)/i,
    /~60\s*s\s+window|Desktop's\s+wall/i,
    /automatic\s+region-batching|fits\s+Desktop's\s+limit\s+automatically/i,
  ];
  for (const re of LIMIT_AS_FACT) assert.doesNotMatch(README, re, `README states a Desktop limit as fact: ${re}`);
  // A phrase list guards only the phrasings it lists: "a ~60 s per-call limit" passed the four above (the audit
  // seat's survivor). The rule instead: a sentence with no ISO date may not name Desktop beside a duration, nor pair
  // 60 s with a limit word in either order. A flag value (`--interval=60s`) is not a duration claim.
  for (const s of [
    'On one router a `scan_host` call timed out in Claude Desktop on 2026-08-10 and one returned within 138 s on 2026-09-30.',
    'HEALTHCHECK --interval=60s --timeout=5s --start-period=10s --retries=3 \\',
    'A plugin declares its own 90 s budget.',
    // one per lookbehind — each is cleared ONLY by that lookbehind (the HEALTHCHECK line reaches no limit word):
    '`--interval=60s` is a probe cadence, not a limit.',
    'The limit flag is `--timeout=60s`.',
    'In Claude Desktop, pass `--timeout=60s`.',
  ]) assert.deepEqual(desktopLimitAsFact(s), [], `ACCEPT case flagged: ${s}`);
  for (const s of [
    'Claude Desktop enforces a ~60 s per-call limit on MCP tools.',
    'MCP tool calls are cut off at a 60-second cap.',
    'Keep each call under the limit of 60 seconds.',
    'Desktop gives each call about a minute.',
  ]) assert.equal(desktopLimitAsFact(s).length, 1, `REJECT case passed: ${s}`);
  assert.deepEqual(desktopLimitAsFact(README), [], 'README states a Desktop time limit as fact, undated');
  assert.equal((read('mcp_server.mjs').match(/pm\.runCloud\(/g) || []).length, 1, 'TRIPWIRE: scan_cloud call path changed');
  assert.match(README, /does not split a `regions:\["all"\]` call/);
  assert.match(README, /timed out in Claude Desktop on 2026-08-10/);
  assert.match(README, /returned within 138 s on 2026-09-30/);
  const cloudDefault = read('plugin_manager.mjs').match(/rawTimeout > 0 \? rawTimeout : (\d+)/)[1];
  assert.match(README, new RegExp('`CLOUD_PLUGIN_TIMEOUT_MS` \\(default `?' + cloudDefault));
  assert.match(README, /bounds each plugin, not the call/);
});

// ── G. a repeated host: once per watch cycle, twice in a one-shot scan (1.3.0 lane 4, item 10) ─────────────────────
// The two modes DIFFER on the same input — parseHostArg keeps `X,X` (the one-shot path scans it twice into distinct
// output directories) while the scheduler scans each distinct host once per cycle — so the --watch text must say which.
// DERIVED by driving the real scheduler with a repeated host.
test('G. --help and the README --watch row say watch mode scans each distinct host once per cycle', async () => {
  const { createScheduler } = await import(pathToFileURL(path.join(ROOT, 'utils/scheduler.mjs')).href);
  const calls = [];
  const s = createScheduler({ intervalMs: 100_000, hosts: ['h', 'h'], scanFn: async (h) => { calls.push(h); return {}; } });
  await Promise.race([s.runOnce(), new Promise((r) => setTimeout(r, 1000).unref())]);
  assert.deepEqual(calls, ['h'], 'positive control: the scheduler scans a repeated host once');
  const ONCE = /each\s+distinct\s+host\s+once\s+per\s+cycle/;
  assert.match(flagBlock(HELP, '--watch'), ONCE, '--help --watch does not say a repeated host is scanned once per cycle');
  const row = README.split('\n').find((l) => l.startsWith('| `--watch` |'));
  assert.match(row ?? '', ONCE, 'the README --watch row does not say a repeated host is scanned once per cycle');
});

test('H. TRIPWIRE: the watch banner prints the scheduler\'s distinct count, not the list it was handed', () => {
  // A source tripwire, in this file's idiom: a CLI spawn of --watch would start a real scan. The banner moved below
  // createScheduler so it can read the deduped list; reverting it to the raw `hosts.length` would print a count the
  // cycles never scan.
  const line = CLI.split('\n').find((l) => l.includes('[CTEM] Watch mode enabled.'));
  assert.ok(line, 'TRIPWIRE: the watch banner line is gone');
  assert.match(line, /Hosts: \$\{scheduler\.hosts\.length\}\$\{dropped\}/, 'the banner does not print the scheduler\'s distinct count');
  assert.ok(CLI.indexOf('const scheduler = createScheduler(') < CLI.indexOf(line), 'the banner is printed before the scheduler exists');
});
