// AN ENTERPRISE STAGE THAT DID NOT RUN ON A HOST FIXED NOTHING THERE (1.1.1 — the audit seat's T1-c ruling, the delta half).
//
// When Enterprise fails to LOAD (utils/ee_load.mjs → `conclusion.result.eeLoadError`) or its enrichment THROWS
// (`conclusion.result.eeEnrichmentError`), the host's analysis agents and CVE mapper produce nothing in that scan. The
// run record still carries Enterprise's version (it is read from the package manifest, which resolves either way) and the
// same tier, so neither whole-comparison refusal fires — and before this leg every agent and engine row the other run
// held on that host read RESOLVED (or NEW, the other way). Both flags now ride from the persisted conclusion to the delta,
// and a queue-path row (an Enterprise producer) on a host where EITHER run carries one is NOT COMPARABLE — `evidence-gap`,
// the same reason an individual agent's not-run record carries; no new reason token. Community's plugins are untouched:
// a plugin's own status on the host governs its rows.
//
// FOURTH QUADRANT FIRST.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import * as SD from '../utils/scan_delta.mjs';
import * as RI from '../utils/report_inputs.mjs';
import { newRunId, writeRunStart, appendHostWritten, finalizeRunRecord, readRunRecord } from '../utils/run_record.mjs';
import { pathToFileURL } from 'node:url';
import { loadEnterprise } from '../utils/ee_load.mjs';
import { renderExecutiveReport } from '../utils/executive_report.mjs';

const { buildScanDelta, NOT_COMPARABLE_REASONS } = SD;
const HOST = '192.0.2.1';
const OTHER = '192.0.2.2';
const run = (id) => ({
  schema: 1, runId: id, startedAt: '2026-09-21T00:00:00Z', finishedAt: '2026-09-21T01:00:00Z',
  hostsRequested: [HOST, OTHER], hostsWritten: [{ host: HOST, dir: 'a' }, { host: OTHER, dir: 'b' }], pluginsRequested: ['003', '040'],
  portsRequested: null, tier: 'enterprise', ceVersion: '0.2.56', eeVersion: '1.1.1',
  kevLoaded: false, kevSnapshot: null, epssLoaded: false, epssSnapshot: null,
});
const agent = (title, plugin = 'crypto_agent', host = HOST) => ({ host, port: 21, protocol: 'tcp', severity: 'MEDIUM', title,
  evidenceGap: false, gapClass: null, plugin, pluginName: plugin, producerKind: 'agent' });
const pluginRow = (title) => ({ host: HOST, port: 443, protocol: 'tcp', severity: 'HIGH', title, evidenceGap: false, gapClass: null,
  plugin: '040', pluginName: 'TLS Certificate Auditor', producerKind: 'plugin' });
const hostStatus = (host, eeStage) => ({ host, dir: host === HOST ? 'a' : 'b', pluginStatusRecorded: true,
  status: [{ id: '003', status: 'ran' }, { id: '040', status: 'ran' }], portScan: { tcpOpen: [21, 443], tcpClosed: [] }, udpServices: [],
  ...(eeStage ? { eeStage } : {}) });
const side = (id, findings, stages = {}) => ({ record: run(id), findings,
  pluginStatus: [hostStatus(HOST, stages[HOST] ?? null), hostStatus(OTHER, stages[OTHER] ?? null)] });
const LOAD = { loadError: "The requested module 'nsauditor-ai/utils/scan_delta.mjs' does not provide an export named 'isUdpTransport'", enrichmentError: null };
const ENRICH = { loadError: null, enrichmentError: 'ENOSPC: no space left on device' };

test('eeStageOf reads BOTH flags from the persisted conclusion, and is null when Enterprise ran', () => {
  assert.equal(typeof RI.eeStageOf, 'function');
  assert.equal(RI.eeStageOf({ conclusion: { result: {} } }), null);
  assert.equal(RI.eeStageOf({}), null);
  assert.deepEqual(RI.eeStageOf({ conclusion: { result: { eeLoadError: 'x' } } }), { loadError: 'x', enrichmentError: null });
  assert.deepEqual(RI.eeStageOf({ conclusion: { result: { eeEnrichmentError: 'y' } } }), { loadError: null, enrichmentError: 'y' });
  assert.ok(!NOT_COMPARABLE_REASONS.some((r) => /ee-|enterprise/i.test(r) && r !== 'ee-presence-differs'), 'no new reason token');
});

// ── FOURTH QUADRANT FIRST ─────────────────────────────────────────────────────────────────────────────
test('(q1) Enterprise ran on both sides → an agent row that vanished reads RESOLVED, as today', () => {
  const d = buildScanDelta({ baseline: side('A', [agent('No transport encryption: ftp on port 21')]), current: side('B', []) });
  assert.equal(d.resolved.length, 1);
});

test('(q1) Enterprise failed on ANOTHER host → this host\'s agent row still reads RESOLVED (the rule is per host)', () => {
  const d = buildScanDelta({ baseline: side('A', [agent('No transport encryption: ftp on port 21')]), current: side('B', [], { [OTHER]: LOAD }) });
  assert.equal(d.resolved.length, 1);
});

test('(q1) a Community PLUGIN row on the failed host is untouched — its own plugin status governs it', () => {
  const d = buildScanDelta({ baseline: side('A', [pluginRow('Certificate expired')]), current: side('B', [], { [HOST]: LOAD }) });
  assert.equal(d.resolved.length, 1);
});

// ── THE DEFECT ────────────────────────────────────────────────────────────────────────────────────────
test('(a) Enterprise FAILED TO LOAD on the host now → the baseline\'s agent AND engine rows are NOT COMPARABLE (evidence-gap), never RESOLVED', () => {
  const base = [agent('No transport encryption: ftp on port 21'), agent('CVE-2023-38408 — tcp/ssh', 'intelligence_engine')];
  const d = buildScanDelta({ baseline: side('A', base), current: side('B', [], { [HOST]: LOAD }) });
  assert.equal(d.resolved.length, 0);
  assert.equal(d.notComparable.length, 2);
  for (const nc of d.notComparable) {
    assert.equal(nc.reason, 'evidence-gap');
    assert.equal(nc.direction, 'disappeared');
    assert.match(nc.detail, /Enterprise failed to load on 192\.0\.2\.1 in this run/, 'named absolutely: the failure is in the CURRENT run');
    assert.match(nc.detail, /isUdpTransport/, 'the recorded error is carried');
  }
});

test('(a) Enterprise\'s ENRICHMENT threw on the host now → the same refusal, and the detail says which stage', () => {
  const d = buildScanDelta({ baseline: side('A', [agent('No transport encryption: ftp on port 21')]), current: side('B', [], { [HOST]: ENRICH }) });
  assert.equal(d.resolved.length, 0);
  assert.match(d.notComparable[0]?.detail ?? '', /Enterprise failed during enrichment on 192\.0\.2\.1 in this run/);
});

test('(a) the APPEARED direction: the BASELINE\'s Enterprise failed, an agent row appears now → not NEW', () => {
  const d = buildScanDelta({ baseline: side('A', [], { [HOST]: LOAD }), current: side('B', [agent('No transport encryption: ftp on port 21')]) });
  assert.equal(d.newFindings.length, 0);
  assert.equal(d.notComparable[0]?.reason, 'evidence-gap');
  assert.equal(d.notComparable[0]?.direction, 'appeared');
});

test('(a) the side HOLDING the row recorded the failure (a partial queue written before enrichment threw) → not RESOLVED either', () => {
  const d = buildScanDelta({ baseline: side('A', [agent('No transport encryption: ftp on port 21')], { [HOST]: ENRICH }), current: side('B', []) });
  assert.equal(d.resolved.length, 0);
  assert.match(d.notComparable[0]?.detail ?? '', /Enterprise failed during enrichment on 192\.0\.2\.1 in the baseline run/);
});

test('ORDER, pinned: an ENGINE row straddling its identity-basis change (EE 1.0.0 → 1.1.1) on a host whose Enterprise failed now → evidence-gap — a stage that did not run is a coverage fact and answers first', () => {
  const base = side('A', [agent('CVE-2023-38408 — tcp/ssh', 'intelligence_engine')]);
  base.record = { ...base.record, eeVersion: '1.0.0' };
  // Precondition: WITHOUT the stage failure the same pair is identity-basis-changed, so both legs genuinely reach this row.
  assert.equal(buildScanDelta({ baseline: base, current: side('B', []) }).notComparable[0]?.reason, 'identity-basis-changed');
  const d = buildScanDelta({ baseline: base, current: side('B', [], { [HOST]: LOAD }) });
  assert.equal(d.notComparable[0]?.reason, 'evidence-gap');
  assert.match(d.notComparable[0]?.detail ?? '', /Enterprise failed to load/);
});

// ── THROUGH THE LOADER: two sealed runs on disk, the flag read from the written raw ──────────────────────────
async function sealedRun(outRoot, dir, { conclusionResult = {}, queue = null, startedAt, finishedAt }) {
  const runId = newRunId();
  await writeRunStart(outRoot, { runId, startedAt, hostsRequested: [HOST], pluginsRequested: ['003'], tier: 'enterprise', ceVersion: '0.2.56', eeVersion: '1.1.1' });
  fs.mkdirSync(path.join(outRoot, dir), { recursive: true });
  fs.writeFileSync(path.join(outRoot, dir, 'scan_conclusion_raw.json'), JSON.stringify({
    runId, pluginStatus: [{ id: '003', name: 'Port Scanner', status: 'ran' }],
    results: [{ id: '003', name: 'Port Scanner', result: { up: true, tcpOpen: [21], tcpClosed: [] } }],
    conclusion: { result: { services: [], ...conclusionResult } } }), 'utf8');
  if (queue) fs.writeFileSync(path.join(outRoot, dir, 'scan_finding_queue.json'), JSON.stringify({ findings: queue }), 'utf8');
  await appendHostWritten(outRoot, runId, { host: HOST, dir });
  await finalizeRunRecord(outRoot, runId, { finishedAt });
  return runId;
}

test('THROUGH loadRun: a baseline crypto_agent row, and a current run whose raw records eeLoadError → NOT COMPARABLE, never RESOLVED', async () => {
  const outRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-eestage-'));
  try {
    const q = [{ category: 'CRYPTO', status: 'UNVERIFIED', severity: 'MEDIUM', title: 'No transport encryption: ftp on port 21',
      target: { host: HOST, port: 21, protocol: 'tcp', service: 'ftp' }, evidence: { source: 'crypto_agent', cve: [], mitre: [], raw: {} } }];
    const a = await sealedRun(outRoot, 'a', { queue: q, startedAt: '2026-09-21T00:00:00.000Z', finishedAt: '2026-09-21T00:10:00.000Z' });
    const b = await sealedRun(outRoot, 'b', { conclusionResult: { eeLoadError: LOAD.loadError }, startedAt: '2026-09-22T00:00:00.000Z', finishedAt: '2026-09-22T00:10:00.000Z' });
    const load = async (runId) => {
      const l = await RI.loadRun(outRoot, { runId, allowPartial: false }, { tier: 'enterprise' });
      return { record: await readRunRecord(outRoot, runId), findings: l.model.findings, pluginStatus: l.model.plugins.byHost, integrity: 'chain-verified' };
    };
    const cur = await load(b);
    assert.deepEqual(cur.pluginStatus[0].eeStage, { loadError: LOAD.loadError, enrichmentError: null }, 'the loader carries the flag');
    const d = buildScanDelta({ baseline: await load(a), current: cur });
    assert.equal(d.resolved.length, 0, 'an Enterprise that did not load fixed nothing');
    assert.equal(d.notComparable.find((n) => n.title === q[0].title)?.reason, 'evidence-gap');
  } finally { fs.rmSync(outRoot, { recursive: true, force: true }); }
});

// ── B6-4a (1.2.1): THE CLIENT ARTIFACT NEVER CARRIES THE OPERATOR'S DIRECTORY LAYOUT ─────────────────────────────────
// The not-comparable detail embedded the load error verbatim, and a load error names ABSOLUTE paths — the Gate 3-B
// executive HTML carried the operator's install prefix eight times. The rule `vulnerabilityDataSource` already states for
// its own detail ("never a local path, which would carry the operator's directory layout into a client artifact") now
// holds for this one: each absolute path becomes its tail after the last `node_modules`, or its basename. The raw JSON
// and stderr stay local and keep the full path. The message is NODE'S OWN: a truncated install (the entry imports a
// module that is not there) under a scratch prefix whose path holds a SPACE, loaded through the real `loadEnterprise`.
const ABS = [/(?:^|[\s'"(=])(?:file:\/\/)?\/(?:Users|home|private|tmp|var|opt|root)\//, /[A-Za-z]:\\/];
const hasLocalPath = (text) => ABS.some((re) => re.test(String(text)));
async function realLoadError(prefix) {
  const pkg = path.join(prefix, 'lib', 'node_modules', '@nsasoft', 'nsauditor-ai-ee');
  fs.mkdirSync(pkg, { recursive: true });
  fs.writeFileSync(path.join(pkg, 'index.mjs'), "export * from './utils/cloud_scope_report.mjs';\n", 'utf8');
  const { loadError } = await loadEnterprise({ importEE: () => import(pathToFileURL(path.join(pkg, 'index.mjs')).href) });
  return loadError;
}

test('(B6-4a, fourth quadrant first) a load or enrichment error that names no local path reaches the detail UNCHANGED', () => {
  for (const stage of [LOAD, ENRICH]) {
    const d = buildScanDelta({ baseline: side('A', [agent('No transport encryption: ftp on port 21')]), current: side('B', [], { [HOST]: stage }) });
    assert.ok(d.notComparable[0]?.detail.endsWith(`(${stage.loadError ?? stage.enrichmentError})`), d.notComparable[0]?.detail);
  }
  assert.equal(SD.withoutLocalPaths(LOAD.loadError), LOAD.loadError, 'a package specifier is not a local path');
});

test('(B6-4a) each absolute path becomes its tail after the last node_modules, or its basename — every shape Node prints', () => {
  const cases = [
    ["Cannot find module '/Users/a b/.nvm/v/lib/node_modules/@nsasoft/nsauditor-ai-ee/utils/x.mjs' imported from /Users/a b/.nvm/v/lib/node_modules/@nsasoft/nsauditor-ai-ee/index.mjs",
      "Cannot find module '@nsasoft/nsauditor-ai-ee/utils/x.mjs' imported from @nsasoft/nsauditor-ai-ee/index.mjs"],
    ["Cannot find module 'C:\\Users\\a\\AppData\\Roaming\\npm\\node_modules\\@nsasoft\\nsauditor-ai-ee\\utils\\x.mjs'",
      "Cannot find module '@nsasoft\\nsauditor-ai-ee\\utils\\x.mjs'"],
    ['failed at file:///home/a/.pnpm/node_modules/.pnpm/x@1/node_modules/@nsasoft/nsauditor-ai-ee/index.mjs:12',
      'failed at @nsasoft/nsauditor-ai-ee/index.mjs:12'],
    ["ENOENT: no such file or directory, open '/home/a/dev/nsauditor-ai-ee/data/compliance/soc2.json'",
      "ENOENT: no such file or directory, open 'soc2.json'"],
    ["Cannot find module '/Users/a/lib/node_modules/@nsasoft/nsauditor-ai-ee/utils/clo", "Cannot find module '@nsasoft/nsauditor-ai-ee/utils/clo"],
    // A QUOTED path holding a space and no module extension is the quoted rule's own job: no unquoted rule can find its end.
    ["ENOENT: no such file or directory, mkdir '/Users/a b/out dir'", "ENOENT: no such file or directory, mkdir '<local path>'"],
    ["EPERM: operation not permitted, mkdir 'C:\\Users\\a b\\out dir'", "EPERM: operation not permitted, mkdir '<local path>'"],
    ['ENOSPC: no space left on device', 'ENOSPC: no space left on device'],
  ];
  for (const [input, want] of cases) assert.equal(SD.withoutLocalPaths(input), want, input);
});

test('(B6-4a) THROUGH loadRun AND the executive renderer: Node\'s own load error names no local path in the detail or the client HTML — the raw keeps it', async () => {
  const outRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-eestage-path-'));
  try {
    const loadError = await realLoadError(path.join(outRoot, 'opera tor prefix'));
    assert.ok(hasLocalPath(loadError) && /cloud_scope_report\.mjs/.test(loadError), `positive control: Node's message names the absolute path: ${loadError}`);
    const q = [{ category: 'CRYPTO', status: 'UNVERIFIED', severity: 'MEDIUM', title: 'No transport encryption: ftp on port 21',
      target: { host: HOST, port: 21, protocol: 'tcp', service: 'ftp' }, evidence: { source: 'crypto_agent', cve: [], mitre: [], raw: {} } }];
    const a = await sealedRun(outRoot, 'a', { queue: q, startedAt: '2026-09-21T00:00:00.000Z', finishedAt: '2026-09-21T00:10:00.000Z' });
    const b = await sealedRun(outRoot, 'b', { conclusionResult: { eeLoadError: loadError }, startedAt: '2026-09-22T00:00:00.000Z', finishedAt: '2026-09-22T00:10:00.000Z' });
    const load = async (runId) => {
      const l = await RI.loadRun(outRoot, { runId, allowPartial: false }, { tier: 'enterprise' });
      return { record: await readRunRecord(outRoot, runId), findings: l.model.findings, pluginStatus: l.model.plugins.byHost, integrity: 'chain-verified' };
    };
    const cur = await load(b);
    assert.equal(cur.pluginStatus[0].eeStage.loadError, loadError, 'the raw, which stays local, keeps the full message');
    const d = buildScanDelta({ baseline: await load(a), current: cur });
    const nc = d.notComparable.find((n) => n.title === q[0].title);
    assert.equal(nc?.reason, 'evidence-gap');
    assert.match(nc.detail, /Enterprise failed to load on 192\.0\.2\.1/, 'the row still says what failed, and where');
    assert.match(nc.detail, /@nsasoft\/nsauditor-ai-ee\/utils\/cloud_scope_report\.mjs/, 'and names the module by its package-relative tail');
    assert.equal(hasLocalPath(nc.detail), false, `the detail carries a local path: ${nc.detail}`);
    const html = renderExecutiveReport({ runId: b, startedAt: '2026-09-22T00:00:00.000Z', findings: [],
      coverage: { requested: 1, written: 1, partial: false, incomplete: false, missing: [] }, hosts: [] }, {},
    { renderedAt: new Date('2026-09-22T01:00:00Z'), delta: d });
    assert.ok(html.includes('cloud_scope_report.mjs'), 'positive control: the client HTML renders the row');
    assert.equal(hasLocalPath(html), false, 'the client HTML carries the operator\'s directory layout');
    assert.equal(html.includes('opera tor prefix'), false, 'not even the prefix\'s own words');
  } finally { fs.rmSync(outRoot, { recursive: true, force: true }); }
});

test('(B6-4a) the reduction runs BEFORE the 200-character cap — a cap landing inside /Users/<name>/ leaves no fragment of the name', () => {
  // The mutant this leg exists for: `withoutLocalPaths(String(e).slice(0, 200))` — cap first, then reduce. Driven, it leaves
  // `'qzx` here: the first three letters of the operator's user name, cut where the cap fell (the audit seat's mutant).
  const NAME = 'qzxoperator';
  const head = "Cannot find module '/Users/";
  const msg = `${'w'.repeat(200 - 3 - head.length - 1)} ${head}${NAME}/vwkdev/lib/node_modules/@nsasoft/nsauditor-ai-ee/utils/`
    + `cloud_scope_report.mjs' imported from /Users/${NAME}/vwkdev/lib/node_modules/@nsasoft/nsauditor-ai-ee/index.mjs`;
  assert.ok(msg.indexOf(NAME) < 200 && msg.indexOf(NAME) + NAME.length > 200, 'positive control: the cap falls inside the user name');
  const d = buildScanDelta({ baseline: side('A', [agent('No transport encryption: ftp on port 21')]),
    current: side('B', [], { [HOST]: { loadError: msg, enrichmentError: null } }) });
  const detail = d.notComparable[0]?.detail ?? '';
  assert.match(detail, /Cannot find module '@nsasoft\//, 'positive control: the row still names what failed');
  for (const part of ['Users', 'vwkdev']) assert.equal(detail.includes(part), false, `the detail carries the path component ${part}`);
  for (let k = 2; k <= NAME.length; k += 1) assert.equal(detail.includes(NAME.slice(0, k)), false, `the detail carries ${NAME.slice(0, k)}`);
});

test('PINNED, NOT ENDORSED (B6-4a): an UNQUOTED path with a space and no module extension reduces only up to its first space', () => {
  // Nothing marks where such a path ends. Node quotes these paths, so its own messages are covered (the table above); a
  // message composed by hand might not be. What is left after the space is the limit's own residue, unchanged in kind;
  // the component before it is a home directory, which the next leg's rule writes as `<local path>`. Stated in the
  // function's comment; when the limit is decided, these rows re-state.
  assert.equal(SD.withoutLocalPaths('cannot open C:\\Program Files\\nsauditor\\state'), 'cannot open <local path> Files\\nsauditor\\state');
  assert.equal(SD.withoutLocalPaths('cannot open /Users/qzx op/dev/state dir'), 'cannot open <local path> op/dev/state dir');
});

test('(B6-4a) outside node_modules, a path keeps its basename only when it is a FILE name below the first component — else <local path>', () => {
  // A home directory's basename IS the user's name, and a dotted user name looks like a file: so a basename survives only
  // when it carries an extension AND sits at depth >= 3 after the root (`/`, `X:\`, `file://`). The audit seat's rule.
  // Mutants: the depth condition removed -> the j.doe row RED; the extension condition removed -> the /home/alice/dev row RED.
  const rows = [
    ["mkdir '/Users/alice'", "mkdir '<local path>'"],
    ["mkdir '/Users/j.doe'", "mkdir '<local path>'"],
    ["open 'C:\\Users\\alice'", "open '<local path>'"],
    ['read /home/alice/dev', 'read <local path>'],
    ["read '/Users/alice/dev/x.json'", "read 'x.json'"],
    ["open '/etc/hosts'", "open '<local path>'"],   // an accepted loss: a client does not need it
  ];
  for (const [input, want] of rows) assert.equal(SD.withoutLocalPaths(input), want, input);
  // Stated, no work: a UNC path matches no rule and passes through.
  assert.equal(SD.withoutLocalPaths('open \\\\server\\share\\x'), 'open \\\\server\\share\\x', 'PINNED: UNC passes through');
});
