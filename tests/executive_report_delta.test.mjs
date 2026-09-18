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
