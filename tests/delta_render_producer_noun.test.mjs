// THE WORD A CUSTOMER READS, IN THE CELL THEY READ IT IN.
//
// ⚠️ THIS EXISTS BECAUSE THE FIX FOR IT SHIPPED HALF-DONE, IN A COMMIT THAT QUOTED THE RULE IT
// BROKE. EE 1.1.0 declared an analysis agent in `IDENTITY_BASIS_CHANGED_AT`, and the refusal
// DETAIL was changed from "plugin …" to "producer …" because an agent is not a plugin and that
// sentence reaches a client deliverable. The leg written with it asserted on `row.detail` — the
// half that had just been fixed — and passed. But both render seams build the cell as
// `${f.reason}: ${f.detail}`, and the REASON CODE was `plugin-identity-basis-changed`. Driven,
// what the customer actually read:
//     plugin-identity-basis-changed: producer intelligence_engine changed what it names …
// The word was still there, leading the line. That is this repo's own "verify the CLAIM
// everywhere, never the replacement STRING" — inside the commit that invoked it.
//
// ⚠️ AND THE FIRST REPAIR FOR *THAT* WAS ALSO WRONG, FOR A REASON WORTH MORE THAN THE DEFECT.
// It added a render-time LABEL map and left the code alone, under a header asserting:
//     "`NOT_COMPARABLE_REASONS` is append-only under `SCAN_DELTA_SCHEMA = 1`; renaming a code
//      changes what an existing consumer's stored verdicts MEAN."
// That premise is CHECKABLE and was never checked. Measured against the published artifact — not
// against git, which answers about the repo rather than about what a consumer holds —
// `npm pack nsauditor-ai@0.2.54` does not contain `utils/scan_delta.mjs` AT ALL, and the string
// appears nowhere in those bytes (positive control: `utils/report_inputs.mjs` is present, 47
// files). The whole delta engine is unpublished, so the number of stored verdicts carrying this
// code is ZERO and the append-only argument had no subject. No guard anywhere stated that rule;
// the only place in either repo asserting it was the comment I wrote to justify the weaker fix.
//
// The label map was worse than a missed opportunity. It was a SECOND COPY of the outcome's
// spelling, free to drift from the code; and it moved only ONE of the two human surfaces, so the
// terminal said `plugin-identity-basis-changed` while the client HTML said `identity basis
// changed` — one outcome, two names, which is the shape that makes a support call unanswerable.
// The code is RENAMED. One name, true of a plugin and of an agent alike, on every surface.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  buildScanDelta, NOT_COMPARABLE_REASONS, DECLARED_OUTCOMES,
  IDENTITY_BASIS_CHANGED_AT, AGENT_PRODUCER_KEYS,
} from '../utils/scan_delta.mjs';
import { renderExecutiveReport } from '../utils/executive_report.mjs';

const IDENTITY_CODE = 'identity-basis-changed';

// ⚠️ `pluginsRequested` MUST NAME THE PLUGIN THE FIXTURE USES. My first draft listed only '003',
// so the plugin leg bucketed `plugin-not-run` and never reached the identity branch — the test
// measured the engine's fallback rather than the rule under test. The sibling file carries the
// same warning about `hostsWritten`; this is that warning one field over.
const REC = (eeVersion, runId) => ({ runId, schema: 1, tier: 'enterprise', eeVersion,
  startedAt: '2026-09-01T00:00:00Z', hostsWritten: [{ host: '127.0.0.1' }],
  pluginsRequested: ['003', '1170'] });
const row = (over = {}) => ({ host: '127.0.0.1', plugin: 'intelligence_engine',
  pluginName: 'intelligence_engine', producerKind: 'agent', port: 5353,
  title: 'a coverage gap', severity: 'INFO', evidenceGap: false, ...over });
const side = (eeVersion, runId, findings) => ({ record: REC(eeVersion, runId), findings,
  integrity: 'chain-verified',
  pluginStatus: [{ host: '127.0.0.1', dir: 'd1', status: [], pluginStatusRecorded: true }] });

// ⚠️ THE PUBLIC ENTRY POINT, not the private renderer. `renderDelta` is module-private; driving it
// would measure a function no caller reaches. `renderExecutiveReport` is what writes the client
// HTML, so it is what the customer's words come out of.
const MODEL = { runId: 'R2', startedAt: '2026-09-08T10:00:00.000Z', findings: [],
  coverage: { requested: 1, written: 1, partial: false, incomplete: false, missing: [] }, hosts: [] };
const render = (delta) => renderExecutiveReport(MODEL, {},
  { renderedAt: new Date('2026-09-08T12:00:00Z'), delta });

const agentStraddle = () => buildScanDelta({
  baseline: side('1.0.0', 'b', [row({ title: 'old' })]),
  current: side('1.1.0', 'c', [row({ title: 'new' })]),
});

// ── THE PROPERTY, SURFACE-INDEPENDENT AND DERIVED ───────────────────────────────────────────
//
// This is the leg that matters, and it is deliberately NOT about a render seam. Both surfaces
// interpolate the code verbatim, and a third could be added tomorrow; if the CODE carries no noun
// its own declaration table can contradict, every surface is correct by construction. A per-seam
// assertion would have to be rewritten for each new seam — which is exactly how the first repair
// fixed the HTML and left the terminal wrong.
test('no reason code asserts a producer KIND that its own declaration table can contradict', () => {
  const declared = Object.keys(IDENTITY_BASIS_CHANGED_AT);
  assert.ok(declared.length > 0, 'nothing is declared, so this leg has no subject and would pass vacuously');
  const agents = declared.filter((k) => AGENT_PRODUCER_KEYS.includes(k));
  if (agents.length === 0) return;   // the noun would be true of every declared producer
  // ⚠️ THE CODE COMES FROM THE ENGINE, NOT FROM THIS FILE'S CONSTANT. Written the obvious way —
  // `assert.ok(!IDENTITY_CODE.includes('plugin'))` — this leg asserts a property of a literal
  // declared six lines up, so it passed while the engine was still emitting the old spelling and
  // it would pass again if the rename were reverted. It was GREEN in the RED run that motivated
  // the change, alone among five. A leg whose subject is its own fixture measures the fixture.
  const emitted = agentStraddle().notComparable[0]?.reason;
  assert.ok(emitted, 'the straddle produced no not-comparable row, so there is no code to judge');
  assert.ok(!emitted.includes('plugin'),
    `${agents.length} declared producer(s) are analysis AGENTS (${agents.join(', ')}), and both `
    + 'render seams print the code verbatim in front of a human. A code containing "plugin" is '
    + `therefore FALSE of its own subjects; the engine emitted "${emitted}". Drop the noun rather `
    + 'than swapping it: "identity basis changed" is true of a plugin and of an agent alike, so '
    + 'one spelling serves both.');
  assert.equal(emitted, IDENTITY_CODE, 'and it must be the spelling every other leg here names');
});

// ⚠️ BOTH DIRECTIONS, and the first draft of this leg asserted ONE row and was wrong about the
// engine rather than the engine wrong about the rule. A straddle emits two: the baseline row that
// `disappeared` and the current row that `appeared`. That is the substance of the declaration —
// a rule that covered only the appearing side would leave the vanishing side paired as RESOLVED,
// which is this engine's own dangerous verdict, reported about a producer that moved nothing.
test('the code the ENGINE emits is the declared one, in BOTH directions', () => {
  const d = agentStraddle();
  assert.deepEqual(d.notComparable.map((x) => x.direction).sort(), ['appeared', 'disappeared'],
    'a straddle must report the vanishing row as well as the arriving one, or the half it drops '
    + 'is bucketed as a real remediation');
  for (const x of d.notComparable) assert.equal(x.reason, IDENTITY_CODE);
  assert.equal(d.resolved.length, 0, 'and NOTHING may read as resolved across the declaration');
  assert.ok(NOT_COMPARABLE_REASONS.includes(IDENTITY_CODE), 'the vocabulary must declare it');
  assert.ok(DECLARED_OUTCOMES[IDENTITY_CODE], 'and the census must be able to see it');
});

// ── THE DRIVEN WITNESS, on the surface that reaches a client ────────────────────────────────

test('the RENDERED cell does not call an analysis agent a plugin', () => {
  const html = render(agentStraddle());
  assert.ok(/intelligence_engine/.test(html), 'the producer must still be named in the output');
  assert.doesNotMatch(html, /plugin-identity-basis-changed/,
    'the raw machine code led the cell and asserted "plugin" about an agent — the same class as '
    + 'the "plugin undefined did not run" detail this engine already had to fix, one seam over');
  assert.match(html, /identity-basis-changed/,
    'and the outcome must still REACH the reader — a repair that merely deleted the words would '
    + 'pass the assertion above while telling the customer nothing happened');
});

// ── FOURTH QUADRANT ─────────────────────────────────────────────────────────────────────────

test('FOURTH QUADRANT — a PLUGIN row still reads correctly, so the fix is not agent-only', () => {
  const d = buildScanDelta({
    baseline: side('1.0.0', 'b', [row({ plugin: '1170', pluginName: 'sg', producerKind: 'plugin',
      title: 'old', resource: null })]),
    current: side('1.1.0', 'c', [row({ plugin: '1170', pluginName: 'sg', producerKind: 'plugin',
      title: 'new', resource: 'sg-0abc' })]),
  });
  const html = render(d);
  assert.match(html, /identity-basis-changed/,
    'the reader must still be told WHAT happened, whoever produced the finding');
  assert.match(html, /plugin 1170|1170/,
    'and a genuine plugin must still be named as one — dropping the noun from the CODE must not '
    + 'cost the DETAIL its ability to say "plugin" where that is true');
});

// ⚠️ A HALF-RENAME IS THE FAILURE MODE OF A RENAME, and it is silent: the engine emits the new
// code, some other declaration still carries the old spelling, and the mismatch shows up only as
// an outcome that never fires. DERIVED over the tree rather than hand-listed, because a hand list
// is bounded by what its author remembered to look at.
//
// ⚠️ IT KEYS ON THE QUOTE, NOT ON THE SPELLING, and that distinction is the leg. The incident
// record in `scan_delta.mjs` and the header of this file both MENTION the old code in prose —
// that is a disclosure, and an absence guard that cannot tell a disclosure from the thing it
// discloses forces the record to be deleted to make the guard green. A consumer, by contrast,
// must QUOTE the code to compare against it. So the subject is a string literal, and a file that
// merely talks about the old name is not a finding. The first draft hand-exempted this file and
// would have gone red on the record in `scan_delta.mjs` the moment it was written.
const quotedOldCode = (text) => new RegExp(`['"]plugin-${IDENTITY_CODE}['"]`).test(text);

test('FOURTH QUADRANT — the sweep predicate finds a QUOTED literal and ignores a MENTION', () => {
  assert.ok(quotedOldCode(`const r = 'plugin-${IDENTITY_CODE}';`), 'a declaration must be caught');
  assert.ok(quotedOldCode(`if (f.reason === "plugin-${IDENTITY_CODE}") return;`), 'so must a comparison');
  assert.ok(!quotedOldCode(`// the code was \`plugin-${IDENTITY_CODE}\` before the rename`),
    'a prose mention in the incident record is a DISCLOSURE, not a surviving consumer — a guard '
    + 'that cannot tell them apart is one that forces its own history to be erased');
  assert.ok(!quotedOldCode(`assert.doesNotMatch(html, /plugin-${IDENTITY_CODE}/);`),
    'and a regex asserting the old name is ABSENT is the opposite of a consumer of it');
});

test('FOURTH QUADRANT — the OLD spelling survives in no string literal anywhere in the source', () => {
  const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
  const walk = (dir) => fs.readdirSync(dir, { withFileTypes: true }).flatMap((e) => {
    if (e.name === 'node_modules' || e.name === '.git') return [];
    const p = path.join(dir, e.name);
    return e.isDirectory() ? walk(p) : (/\.(mjs|js|json)$/.test(e.name) ? [p] : []);
  });
  const files = [...walk(path.join(root, 'utils')), ...walk(path.join(root, 'tests'))];
  assert.ok(files.length > 10, 'the walk found almost nothing — an empty corpus passes vacuously');
  const hits = files.filter((f) => quotedOldCode(fs.readFileSync(f, 'utf8')));
  assert.deepEqual(hits.map((f) => path.relative(root, f)), [],
    'the old spelling survives as a LITERAL — either a declaration the rename missed or a '
    + 'consumer that will never match the code the engine now emits');
});
