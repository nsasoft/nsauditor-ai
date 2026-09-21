// The cross-run delta rendered into the CLIENT-FACING report.
//
// ⚠️ A `resolved` ROW IN THIS DOCUMENT IS AN ASSERTION OF REMEDIATION TO THE CLIENT'S AUDITOR.
// stdout is read by the operator, who knows what the tool does; this HTML is read by the person
// the consultant is billing. Every honesty property therefore has to survive the render, and the
// compression pass that deletes a caveat is exactly what these tests exist to fail.
//
// The FOURTH-QUADRANT case first, as always: the defect is not "the delta is missing" — it is a
// delta that renders its verdicts and drops the basis those verdicts rest on. A footnote is the
// shape a compression pass keeps while making it worthless; the basis must ride the ROW.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { renderExecutiveReport } from '../utils/executive_report.mjs';
import { buildScanDelta, CHAIN_ASSURANCE_LABEL } from '../utils/scan_delta.mjs';

const rec = (over = {}) => ({ schema: 1, runId: 'R1', startedAt: '2026-09-01T10:00:00.000Z',
  finishedAt: '2026-09-01T11:00:00.000Z', hostsRequested: ['10.0.0.7'],
  hostsWritten: [{ host: '10.0.0.7', dir: 'd1' }], pluginsRequested: ['aws-s3'],
  portsRequested: null, tier: 'pro', ceVersion: '0.2.54', eeVersion: '1.0.0',
  kevLoaded: false, kevSnapshot: null, epssLoaded: false, epssSnapshot: null, ...over });
const s3 = (resource, severity = 'high') => ({ host: '10.0.0.7', plugin: 'aws-s3', resource, port: 443,
  title: 'No public access block configured', severity });
const model = { runId: 'R2', startedAt: '2026-09-08T10:00:00.000Z', findings: [],
  coverage: { requested: 1, written: 1, partial: false, incomplete: false, missing: [] }, hosts: [] };

const render = (delta) => renderExecutiveReport(model, {}, { renderedAt: new Date('2026-09-08T12:00:00Z'), delta });

// The row containing a given resource, so "in the row" is asserted rather than "somewhere on the page".
function rowFor(html, needle) {
  const rows = html.split(/<tr[ >]/).slice(1).map((r) => r.split('</tr>')[0]);
  return rows.find((r) => r.includes(needle)) ?? '';
}

test('a RESOLVED row carries its comparability basis IN THE ROW, not in a footnote', () => {
  const delta = buildScanDelta({
    baseline: { record: rec(), findings: [s3('bucket-c')], integrity: 'chain-verified' },
    current: { record: rec({ runId: 'R2' }), findings: [] },
  });
  assert.equal(delta.resolved.length, 1);
  const row = rowFor(render(delta), 'bucket-c');
  assert.notEqual(row, '', 'the resolved finding must appear as a row');
  assert.match(row, /chain-verified/,
    'the basis must travel WITH the assertion of remediation — a footnote is what a compression pass keeps and empties');
});

test('the chain-assurance limit renders IN THE BODY — what it is NOT is the first thing compression deletes', () => {
  const delta = buildScanDelta({
    baseline: { record: rec(), findings: [], integrity: 'chain-verified' },
    current: { record: rec({ runId: 'R2' }), findings: [] },
  });
  const html = render(delta);
  assert.match(html, /NOT tamper-proof/);
  assert.match(html, /not non-repudiation/);
  assert.ok(CHAIN_ASSURANCE_LABEL.length > 0);
});

test('NOT-COMPARABLE renders as COUNT and as PER-FINDING REASONS — a count alone re-creates the defect', () => {
  const delta = buildScanDelta({
    baseline: { record: rec(), findings: [s3('bucket-a')], integrity: 'chain-verified' },
    current: { record: rec({ runId: 'R2', pluginsRequested: ['aws-ec2'] }), findings: [] },
  });
  assert.equal(delta.notComparable.length, 1);
  const html = render(delta);
  assert.match(html, /plugin-not-run/, 'the reason must reach the client, not just a number');
  assert.match(rowFor(html, 'bucket-a'), /plugin-not-run/, 'and it must be on the finding’s own row');
  assert.doesNotMatch(html, /1 resolved/i, 'it must never be presented as remediation');
});

test('a REFUSED comparison renders the refusal and NO resolved rows at all', () => {
  const delta = buildScanDelta({
    baseline: { record: rec({ eeVersion: '0.46.0' }), findings: [s3('bucket-a')], integrity: 'chain-verified' },
    current: { record: rec({ runId: 'R2', eeVersion: '1.0.0' }), findings: [] },
  });
  assert.equal(delta.comparable, false);
  const html = render(delta);
  assert.match(html, /finding-count-semantics-boundary|not comparable/i);
  assert.doesNotMatch(html, /bucket-a/, 'a refused comparison asserts nothing about any finding');
});

test('with NO delta the report is unchanged — the section is absent, never an empty or fabricated one', () => {
  const html = renderExecutiveReport(model, {}, { renderedAt: new Date('2026-09-08T12:00:00Z') });
  assert.doesNotMatch(html, /id="delta"/);
  assert.doesNotMatch(html, /Since last scan/i);
});

// ════════════════════════════════════════════════════════════════════════════════════════════
// T5 / G8 — THE PER-ROW BASIS CONTRADICTED THE LIMITS BLOCK ON THE SAME PAGE.
//
// `deltaBasis` wrote a CONSTANT — "comparable: host, plugin, scope and framework enumeration
// present in both runs" — beside every resolved / new / changed row, while the same page's limits
// said framework movement was NOT EVALUATED and (before T2) scope never was either. The row is
// what a reader sees beside the word `resolved`; the limit is what a compression pass deletes.
// Of the two, the row is the one that has to be true.
// ════════════════════════════════════════════════════════════════════════════════════════════

test('G8 — the basis NEVER claims a leg the limits say was not evaluated', async () => {
  const { FRAMEWORK_MOVEMENT_NOT_EVALUATED } = await import('../utils/scan_delta.mjs');
  const delta = buildScanDelta({
    baseline: { record: rec(), findings: [s3('bucket-c')], integrity: 'chain-verified', pluginStatus: [] },
    current: { record: rec({ runId: 'R2' }), findings: [], pluginStatus: [] },
  });
  assert.ok(delta.limits.includes(FRAMEWORK_MOVEMENT_NOT_EVALUATED),
    'the premise: this edition records no framework enumeration, so the limit must be present');
  assert.equal(delta.resolved.length, 1);

  const row = rowFor(render(delta), 'bucket-c');
  // ⚠️ THE SAME LITERAL AS THE ACCEPT LEG BELOW, deliberately. The rendered form carries a colon
  // ("framework enumeration: present in both runs"), so a negative written without it would pass
  // trivially — including in the accept case — and the leg would be decoration.
  assert.doesNotMatch(row, /framework enumeration: present in both runs/,
    'the page cannot say in one cell that framework enumeration was present and in another that it was NOT EVALUATED');
  assert.match(row, /framework enumeration: not evaluated/,
    'and it must say so positively — dropping the clause would leave the reader to assume it was checked');
});

test('G8 — the basis names the leg as PRESENT when it genuinely was', () => {
  // ⚠️ THE FOURTH QUADRANT, and the only leg that can catch a basis rewritten to say "not
  // evaluated" unconditionally — which would pass the test above and understate the product.
  const withFw = { record: rec(), findings: [s3('bucket-c')], integrity: 'chain-verified',
    pluginStatus: [], frameworkEnumeration: ['CC6.1'] };
  const delta = buildScanDelta({
    baseline: withFw,
    current: { record: rec({ runId: 'R2' }), findings: [], pluginStatus: [], frameworkEnumeration: ['CC6.1'] },
  });
  const row = rowFor(render(delta), 'bucket-c');
  assert.match(row, /framework enumeration: present in both runs/,
    'when both runs DO carry an enumeration, the basis must say so');
  assert.doesNotMatch(row, /not evaluated/);
});

test('G8 — the basis reports BOTH sides’ integrity, because both are alterable', () => {
  // T3 made the current run verifiable and T4 made it refuse; a basis that names only the baseline
  // still describes half the evidence. `baseline <status> · current <status>`.
  const delta = buildScanDelta({
    baseline: { record: rec(), findings: [s3('bucket-c')], integrity: 'chain-verified', pluginStatus: [] },
    current: { record: rec({ runId: 'R2' }), findings: [], integrity: 'chain-absent', pluginStatus: [] },
  });
  const row = rowFor(render(delta), 'bucket-c');
  assert.match(row, /baseline chain-verified/);
  assert.match(row, /current chain-absent/,
    'the run being REPORTED is as alterable as the one being compared against');
});

test('G8 — the basis omits SCOPE when scope could not be evaluated', () => {
  // The SCOPE_NOT_EVALUATED case from T2, carried into the row: a side with no pluginStatus cannot
  // be said to have had no gaps, so the row must not claim scope was present in both runs.
  const delta = buildScanDelta({
    baseline: { record: rec(), findings: [s3('bucket-c')], integrity: 'chain-verified', pluginStatus: [] },
    current: { record: rec({ runId: 'R2' }), findings: [] },        // no pluginStatus: not evaluable
  });
  const row = rowFor(render(delta), 'bucket-c');
  assert.doesNotMatch(row, /\bscope\b[^<]*present in both runs/,
    'a page whose limits declare scope NOT EVALUATED cannot assert scope in its rows');
});
