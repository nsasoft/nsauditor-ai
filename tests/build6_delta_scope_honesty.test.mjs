// THE DELTA'S TEXT SAYS WHAT THE DELTA DOES ABOUT A NARROWED --plugins RUN (CE 0.2.56 build 6 — the operator's ruling
// "text now, behaviour 1.3.0").
//
// F2, measured on the installed trio: an analysis agent and the CVE mapper derive their rows from OTHER plugins' output.
// Narrow `--plugins` in one of two compared runs and the agent still RUNS, with no input — its rows vanish (or appear),
// and the delta files them RESOLVED (or NEW), while a plugin's own row in the same pair is refused `plugin-not-run`.
//
// Every fact here is DRIVEN END TO END through the command a customer runs: two run records written by the real
// writers and sealed by the real chain, then `runReport(--since)` — `loadRun` → `buildSinceView` → `buildScanDelta` →
// `renderExecutiveReport` — and the verdict is read off the ARTIFACT it writes (the HTML row a client receives) and the
// stdout an operator reads. No loader shape is re-modelled here. Each text leg then holds the text to the verdict in BOTH
// directions: while the fact holds the text must state the limit, and the day 1.3.0 refuses these rows the limit sentence
// is false and the leg goes red until it is removed. PINNED, NOT ENDORSED.
//
// ⚠️ TWO PAIRS SINCE 1.3.0 (lane 6, the R restatement). From Enterprise 1.3.0 a scan that left an agent's input plugin
// out RECORDS it (Enterprise's input-gap record, the not-requested cause), and the delta refuses that agent's rows there.
// A run made before 1.3.0 cannot carry that record, so F2 still holds OF IT. The 1.2.0-stamped pair below is that LEGACY
// pair (F2_HOLDS_LEGACY); a second pair stamped 1.3.0 carries the record the narrowed scan writes (F2_HOLDS_130). The
// text legs follow each: the unscoped --plugins limit goes while the 1.3.0 pair is refused; the legacy-scoped limit
// stays exactly while the legacy pair still reads resolved / new. The per-row Basis cell (CE 023f197) names the legacy
// limit on the row itself.
import './helpers/no_operator_dotenv.mjs';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runReport } from '../cli.mjs';
import { resolveCapabilities } from '../utils/capabilities.mjs';
import { newRunId, writeRunStart, appendHostWritten, finalizeRunRecord } from '../utils/run_record.mjs';
import { sealRunRecord } from '../utils/run_chain.mjs';
import { AGENT_SCOPE_FROM_TIER, PLUGIN_NOT_RUN_REASON } from '../utils/scan_delta.mjs';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const read = (rel) => fs.readFileSync(path.join(ROOT, rel), 'utf8');
const HOST = '192.0.2.10';

// Queue entries as Enterprise writes them — the producer is `evidence.source`, and the loader stamps it an AGENT.
const tlsRow = { title: 'TLSv1 enabled on port 443', severity: 'MEDIUM', target: { host: HOST, port: 443, protocol: 'tcp' },
  evidence: { source: 'crypto_agent', cve: [], raw: { weakProtocol: 'TLSv1' } } };
const cveRow = { title: 'CVE-2024-6387 — tcp/ssh', severity: 'HIGH', target: { host: HOST, port: 22, protocol: 'tcp' },
  evidence: { source: 'intelligence_engine', cve: ['CVE-2024-6387'], raw: {} } };
// The shape of Enterprise's per-agent not-run record (EE utils/service_set_input_gap.mjs `agentNotRunRecord`): port 0,
// the agent's own source, `evidence.raw.evidenceGap`. Used only to derive whether the delta reads a per-agent record.
const notRun = { title: '[COVERAGE GAP] AGENT NOT RUN — crypto_agent did not run: timed out; nothing it would have assessed was looked for',
  severity: 'INFO', target: { host: HOST, port: 0, protocol: 'tcp', service: 'analysis-agent', program: 'crypto_agent' },
  evidence: { source: 'crypto_agent', cve: [], raw: { evidenceGap: true, gapClass: 'agent_not_run', cause: 'timed out' } } };
// The shape of Enterprise 1.3.0's input-gap record for an input plugin LEFT OUT (EE utils/service_set_input_gap.mjs
// `agentInputGapRecord(source, host, [], notRequested)`): port 0, the agent's own source, `evidence.raw.evidenceGap`.
const notRequested = { title: '[COVERAGE GAP] INPUT GAP — crypto_agent: a plugin that feeds the service set was not requested in this scan, so TLS protocols, ciphers, certificates and the HSTS header were NOT assessed on this host',
  severity: 'INFO', target: { host: HOST, port: 0, protocol: 'tcp', service: 'analysis-agent', program: 'crypto_agent' },
  evidence: { source: 'crypto_agent', cve: [], raw: { evidenceGap: true, gapClass: 'input_gap', notRequested: [{ anyOf: ['011'] }, { anyOf: ['040'] }] } } };
const https = [{ port: 443, protocol: 'tcp', service: 'https', status: 'open' }];
const ssh = (program, version) => [{ port: 22, protocol: 'tcp', service: 'ssh', status: 'open', program, version }];
const FULL_TLS = ['003', '005', '011', '040'];
const NARROW_TLS = ['003', '005'];
const tls011 = (title) => ({ id: '011', name: 'tls_scanner', result: { up: true, findings: [{ severity: 'medium', port: 443, title }] } });

// One run, written the way `scan` writes it: record start → host dir (raw + queue) → host written → finalize → seal.
async function mkRun(outRoot, { startedAt, ran, tcpOpen, services, queue = [], envelopes = [], eeVersion = '1.2.0' }) {
  const runId = newRunId();
  await writeRunStart(outRoot, { runId, startedAt, hostsRequested: [HOST], pluginsRequested: ran, portsRequested: '1-1024',
    tier: 'enterprise', ceVersion: eeVersion === '1.2.0' ? '0.2.56' : '0.2.57', eeVersion, prevDigest: null });
  const dir = `d-${runId}`;
  fs.mkdirSync(path.join(outRoot, dir), { recursive: true });
  fs.writeFileSync(path.join(outRoot, dir, 'scan_conclusion_raw.json'), JSON.stringify({ runId,
    pluginStatus: ran.map((id) => ({ id, name: id, status: 'ran', reason: null })),
    results: [{ id: '003', name: 'port_scanner', result: { up: true, tcpOpen, tcpClosed: [] } }, ...envelopes],
    conclusion: { result: { host: { name: HOST }, services } } }), 'utf8');
  fs.writeFileSync(path.join(outRoot, dir, 'scan_finding_queue.json'), JSON.stringify(queue), 'utf8');
  await appendHostWritten(outRoot, runId, { host: HOST, dir });
  await finalizeRunRecord(outRoot, runId, { finishedAt: startedAt });
  await sealRunRecord(outRoot, runId);
  return runId;
}
// `report --format executive --since prior`, as the customer runs it; the verdict is read off the written HTML.
async function since(baseline, current) {
  const outRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'b6-delta-'));
  try {
    await mkRun(outRoot, { startedAt: '2026-09-29T10:00:00.000Z', ...baseline });
    const cur = await mkRun(outRoot, { startedAt: '2026-09-30T10:00:00.000Z', ...current });
    const out = path.join(outRoot, 'delta.html');
    const r = await runReport({ from: outRoot, format: 'executive', run: cur, since: 'prior', out }, resolveCapabilities('enterprise'));
    assert.equal(r.code, 0, `the comparison itself must run: ${r.stderr}`);
    const html = fs.readFileSync(out, 'utf8');
    const rows = html.split(/<tr[ >]/).slice(1).map((x) => x.split('</tr>')[0]);
    return { stdout: r.stdout, rows, html };
  } finally { fs.rmSync(outRoot, { recursive: true, force: true }); }
}
// The DELTA table's row for a title (its rows carry `class="delta-<bucket>"`); a not-comparable row's reason code is the
// token before the first colon of its basis cell (`… not counted as RESOLVED; plugin-not-run: plugin …`).
const bucketOf = ({ rows }, title) => {
  const row = rows.find((x) => /class="delta-[a-z-]+"/.test(x) && x.includes(title));
  if (!row) return 'absent';
  const bucket = row.match(/class="delta-([a-z-]+)"/)[1];
  if (bucket !== 'not-comparable') return bucket;
  return row.replace(/<[^>]+>/g, ' ').match(/;\s*([a-z]+(?:-[a-z]+)+):/)?.[1] ?? 'not-comparable';
};

// THE FACT — three shapes, each a pair whose narrowed side still MEASURED the port (003 ran, 443/22 open).
const P = {
  agentGone: await since({ ran: FULL_TLS, tcpOpen: [443], services: https, queue: [tlsRow] },
    { ran: NARROW_TLS, tcpOpen: [443], services: https }),
  agentAppeared: await since({ ran: NARROW_TLS, tcpOpen: [443], services: https },
    { ran: FULL_TLS, tcpOpen: [443], services: https, queue: [tlsRow] }),
  // 002 not requested: 22/tcp answers, unidentified; the mapper has nothing to match and records nothing.
  cveGone: await since({ ran: ['003', '002'], tcpOpen: [22], services: ssh('OpenSSH', '9.8'), queue: [cveRow] },
    { ran: ['003'], tcpOpen: [22], services: ssh(null, null) }),
  // NEGATIVE CONTROL — a PLUGIN's own row in the identical narrowed pair is refused.
  pluginGone: await since({ ran: FULL_TLS, tcpOpen: [443], services: https, envelopes: [tls011('TLSv1 accepted')] },
    { ran: NARROW_TLS, tcpOpen: [443], services: https }),
  // POSITIVE CONTROL — the same agent row with the SAME plugin set resolves: the fixture CAN resolve.
  sameSet: await since({ ran: FULL_TLS, tcpOpen: [443], services: https, queue: [tlsRow] },
    { ran: FULL_TLS, tcpOpen: [443], services: https }),
  // A plugin row resolving with the same set — the basis leg's fourth quadrant.
  pluginFixed: await since({ ran: FULL_TLS, tcpOpen: [443], services: https, envelopes: [tls011('PLUGIN-ROW')] },
    { ran: FULL_TLS, tcpOpen: [443], services: https }),
  // The per-agent record the delta DOES read: the agent's own not-run record in the current run.
  agentNotRun: await since({ ran: FULL_TLS, tcpOpen: [443], services: https, queue: [tlsRow] },
    { ran: FULL_TLS, tcpOpen: [443], services: https, queue: [notRun] }),
  // THE 1.3.0 PAIR — the same narrowing, both runs stamped 1.3.0, the narrowed scan carrying the record it writes.
  agentGone130: await since({ ran: FULL_TLS, tcpOpen: [443], services: https, queue: [tlsRow], eeVersion: '1.3.0' },
    { ran: NARROW_TLS, tcpOpen: [443], services: https, queue: [notRequested], eeVersion: '1.3.0' }),
  agentAppeared130: await since({ ran: NARROW_TLS, tcpOpen: [443], services: https, queue: [notRequested], eeVersion: '1.3.0' },
    { ran: FULL_TLS, tcpOpen: [443], services: https, queue: [tlsRow], eeVersion: '1.3.0' }),
};
const F = { agentGone: bucketOf(P.agentGone, tlsRow.title), agentAppeared: bucketOf(P.agentAppeared, tlsRow.title),
  cveGone: bucketOf(P.cveGone, cveRow.title), agentGone130: bucketOf(P.agentGone130, tlsRow.title),
  agentAppeared130: bucketOf(P.agentAppeared130, tlsRow.title) };
// F2 OF A LEGACY PAIR (both runs before EE 1.3.0, no record possible) — and F2 OF A 1.3.0 PAIR (the record written).
const F2_HOLDS_LEGACY = F.agentGone === 'resolved' || F.agentAppeared === 'new' || F.cveGone === 'resolved';
const F2_HOLDS_130 = F.agentGone130 === 'resolved' || F.agentAppeared130 === 'new';
// The legacy-scoped limit, as every surface states it: a run before 1.3.0 could not record a plugin left out of it.
const LEGACY_LIMIT = (text) => /before\s+(?:EE|Enterprise)\s+1\.3\.0[^.]*could\s+not\s+record\s+(?:an\s+input\s+plugin|a\s+plugin)\s+left\s+out/i.test(text);
const READS_AGENT_RECORD = bucketOf(P.agentNotRun, tlsRow.title) === 'evidence-gap';

test('the 1.3.0 pair is REFUSED both ways on the record the narrowed scan writes — and the legacy pair still is not', () => {
  assert.deepEqual([F.agentGone130, F.agentAppeared130], ['evidence-gap', 'evidence-gap'], 'the not-requested record refuses the row');
  assert.equal(F2_HOLDS_130, false);
  assert.equal(F2_HOLDS_LEGACY, true, 'a pair before EE 1.3.0 carries no such record: its rows still read resolved / new (the legacy limit)');
});

test('controls — the pair is live: a plugin row is refused plugin-not-run, and a same-set agent row resolves', () => {
  assert.equal(bucketOf(P.pluginGone, 'TLSv1 accepted'), PLUGIN_NOT_RUN_REASON,
    'NEGATIVE CONTROL failed — the driver, not the engine, is being measured');
  assert.equal(bucketOf(P.sameSet, tlsRow.title), 'resolved', 'POSITIVE CONTROL failed — this fixture cannot resolve an agent row at all');
  assert.equal(bucketOf(P.pluginFixed, 'PLUGIN-ROW'), 'resolved', 'the plugin-row quadrant must resolve to be observed');
});

// The README's `**Latest:` paragraph — the npm page's headline, frozen into the tarball.
const LATEST = (() => {
  const README = read('README.md');
  const i = README.indexOf('**Latest: CE ');
  assert.ok(i >= 0, 'README has no **Latest: CE headline');
  const j = README.indexOf('\n\n', i);
  return README.slice(i, j > 0 ? j : undefined);
})();
const ABSOLUTE = /\bnever\s+(?:be\s+)?(?:called|reported|read|filed|counted)\s+(?:as\s+)?(?:resolved|fixed)/i;
const PLUGIN_SET_LIMIT = (text) => /different\s+`?--plugins`?/i.test(text) && /keep\s+`?--plugins`?\s+identical/i.test(text);

test('README headline — the --plugins limit is stated for the pair it holds of, and no unscoped "never called resolved"', () => {
  assert.equal(PLUGIN_SET_LIMIT(LATEST), F2_HOLDS_130, F2_HOLDS_130
    ? 'a 1.3.0 pair still resolves a narrowed-plugins agent row — the **Latest:** paragraph must say so, unscoped'
    : 'a 1.3.0 pair is refused: the UNSCOPED --plugins limit is false — delete it from the **Latest:** paragraph');
  assert.equal(LEGACY_LIMIT(LATEST), F2_HOLDS_LEGACY, F2_HOLDS_LEGACY
    ? 'a pair before EE 1.3.0 still resolves / news an agent row — the **Latest:** paragraph must state that legacy limit'
    : 'the legacy pair is refused too: remove the legacy limit from the **Latest:** paragraph');
  if (F2_HOLDS_LEGACY || F2_HOLDS_130) assert.doesNotMatch(LATEST, ABSOLUTE, 'the headline may not claim an absolute the engine does not meet');
});

test('CHANGELOG 0.2.56 — the entry records the narrowed --plugins limit it shipped with (history: one direction)', () => {
  const CL = read('CHANGELOG.md');
  const i = CL.indexOf('\n## 0.2.56 ');
  assert.ok(i >= 0, 'CHANGELOG has no 0.2.56 entry');
  const j = CL.indexOf('\n## ', i + 5);
  const entry = CL.slice(i, j > 0 ? j : undefined);
  const heading = entry.split('\n')[1];
  // ⚠️ ONE DIRECTION ON PURPOSE: a release record stays true of the release it records. When 1.3.0 refuses these rows,
  // 0.2.56 still did not, so this leg goes vacuous rather than red; the NEW entry states the fix.
  // 0.2.56 paired with Enterprise 1.2.0: what held of IT is the legacy pair's verdict.
  if (F2_HOLDS_LEGACY) {
    assert.doesNotMatch(heading, ABSOLUTE, 'the 0.2.56 heading claims an absolute 0.2.56 does not meet');
    assert.ok(PLUGIN_SET_LIMIT(entry), 'the 0.2.56 entry must state the narrowed --plugins limit it shipped with');
  }
});

test('AGENT_SCOPE_FROM_TIER — the limit the operator and the client read says what is and is not compared', () => {
  const says = /same tier[^.]*what makes them comparable/i.test(AGENT_SCOPE_FROM_TIER);
  assert.ok(!((F2_HOLDS_LEGACY || F2_HOLDS_130) && says), 'the limit tells the reader the shared tier makes agent rows comparable; a narrowed '
    + '--plugins run at the same tier resolves them anyway');
  assert.equal(PLUGIN_SET_LIMIT(AGENT_SCOPE_FROM_TIER), F2_HOLDS_130,
    F2_HOLDS_130 ? 'the limit must say that whether an agent\'s input plugins were requested is not compared, and to keep --plugins identical'
      : 'a 1.3.0 pair is refused on the record: remove the unscoped --plugins sentence from AGENT_SCOPE_FROM_TIER');
  assert.equal(LEGACY_LIMIT(AGENT_SCOPE_FROM_TIER), F2_HOLDS_LEGACY, F2_HOLDS_LEGACY
    ? 'a pair before EE 1.3.0 still resolves these rows: AGENT_SCOPE_FROM_TIER must state the legacy limit'
    : 'the legacy pair is refused too: remove the legacy limit from AGENT_SCOPE_FROM_TIER');
  // ⚠️ POLARITY, NOT PRESENCE. The two phrases above survive an inversion — "What IS compared is whether the plugins …"
  // carries both and says the opposite (the build-6 battery's one survivor). The NEGATION must govern the comparison of
  // the input plugins' being REQUESTED, exactly while F2 holds.
  assert.equal(/\bNOT\s+compared\s+is\s+whether\s+the\s+plugins\b[^.]*\bREQUESTED\b/i.test(AGENT_SCOPE_FROM_TIER), F2_HOLDS_130,
    F2_HOLDS_130 ? 'the limit must DENY that the input plugins\' being requested is compared — a sentence carrying the right words '
      + 'with the opposite polarity tells the reader the check exists'
      : 'the engine now compares them: the "NOT compared" sentence is false — remove it');
  // The delta DOES read a per-agent record (Enterprise's not-run record): the limit may not deny it, and it names it
  // exactly while the delta reads it — both directions, so the clause cannot outlive the behaviour either.
  assert.ok(!(READS_AGENT_RECORD && /not from a per-agent run record|persists no per-agent status/i.test(AGENT_SCOPE_FROM_TIER)),
    'the delta refuses an agent\'s row on that agent\'s own not-run record, so "not from a per-agent run record" is false');
  assert.equal(/an agent did not run/i.test(AGENT_SCOPE_FROM_TIER), READS_AGENT_RECORD, READS_AGENT_RECORD
    ? 'the limit must say the scope also reads the record a run writes when an agent did not run'
    : 'the delta no longer refuses on an agent\'s not-run record: remove that clause from AGENT_SCOPE_FROM_TIER');
  // The sentence has to REACH the operator of the very pair it describes — stdout prints no resolved rows, only this.
  assert.ok(P.agentGone.stdout.includes(`LIMIT: ${AGENT_SCOPE_FROM_TIER}`),
    'the limit must reach the stdout of the pair it describes, or the disclosure is not a disclosure');
  // …and the CLIENT's copy, twice: the LIMITS block of the written HTML carries the legacy limit, and the resolved row's
  // own Basis cell names it (CE 023f197). Compared on the escaped text, as the renderer writes it.
  const escapeHtml = (s) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  const inLimits = P.agentGone.html.includes(`<p class="limit">${escapeHtml(AGENT_SCOPE_FROM_TIER)}</p>`);
  assert.equal(inLimits && LEGACY_LIMIT(AGENT_SCOPE_FROM_TIER), F2_HOLDS_LEGACY, F2_HOLDS_LEGACY
    ? 'the client report of the legacy pair must carry the legacy limit in its LIMITS block'
    : 'the legacy pair is refused too: the limits block may drop the legacy sentence');
  const row = P.agentGone.rows.find((x) => /class="delta-resolved"/.test(x) && x.includes(tlsRow.title)) ?? '';
  assert.equal(/predates EE 1\.3\.0, so it could not record an input plugin left out of the scan/.test(row.replace(/<[^>]+>/g, ' ')), F2_HOLDS_LEGACY,
    'the resolved legacy row\'s own Basis cell must name the legacy limit beside the word "resolved"');
});

test('source premises — the delta\'s own comments do not call a --plugins subset refused, or the tier sufficient', () => {
  const SD = read('utils/scan_delta.mjs');
  const VIEW = read('utils/scan_delta_view.mjs');
  const tierSound = /are what make that\s*\/\/\s*sound/.test(SD);
  const wall = /`--plugins` subset[^]*?technically correct and practically a wall of NOT-COMPARABLE/.test(VIEW);
  assert.ok(!((F2_HOLDS_LEGACY || F2_HOLDS_130) && (tierSound || wall)),
    `a comment still asserts the premise F2 falsifies (tier makes it sound: ${tierSound}; subset = wall of NC: ${wall})`);
  const between = (text, a, b) => { const i = text.indexOf(a); assert.ok(i >= 0, `anchor gone: ${a}`);
    const j = text.indexOf(b, i); assert.ok(j > i, `anchor gone: ${b}`); return text.slice(i, j); };
  const places = {
    'scan_delta.mjs module header': between(SD, '// Cross-run delta', 'export const SCAN_DELTA_SCHEMA'),
    'scan_delta.mjs agent branch': between(SD, 'THE ORACLE DEPENDS ON THE PRODUCER KIND', "if (f.producerKind !== 'agent'"),
    'scan_delta_view.mjs header': between(VIEW, '// `report --since`', 'import '),
  };
  for (const [where, text] of Object.entries(places)) {
    assert.equal(/1\.2\.0 limit/.test(text), F2_HOLDS_130, F2_HOLDS_130 ? `${where} must name the agent-input limit`
      : `a 1.3.0 pair is refused on the record: remove the 1.2.0-limit note from ${where}`);
    assert.equal(/before (?:EE |Enterprise )?1\.3\.0/.test(text), F2_HOLDS_LEGACY, F2_HOLDS_LEGACY
      ? `${where} must name the legacy limit (a run before EE 1.3.0 could not record a plugin left out of it)`
      : `the legacy pair is refused too: remove the legacy note from ${where}`);
  }
});
