// E1(b) — THE CLIENT DELTA TABLE MUST DISTINGUISH PER-REGION FINDINGS TO THE READER.
//
// ⚠️ (b) WAS HALF REFUTED AND THIS IS THE HALF THAT STOOD. The board said de-suffixing would
// "remove the region from the reader's view", so a render leg was owed. Measured, that is FALSE
// for the EE compliance report: its renderer never displays a violation's `resource` at all — a
// real report carries 32 bracketed suffixes in the JSON and ZERO in the rendered markdown, and
// the region reaches that reader through ARNs and URLs inside the finding text.
//
// It is TRUE here. `deltaRow` renders `f.resource` in the client-facing "Since Last Scan" table,
// and before E1 the ` [<region>]` suffix was the ONLY thing in that cell telling six
// `backup:account` rows from six regions apart. The delta's identity key now separates them —
// so the table lists six DISTINCT rows — but every one of them reads identically to a human.
// Six identical rows in a change table is worse than a collapse: it looks like a rendering bug,
// and a reader cannot act on any of them.
import test from 'node:test';
import assert from 'node:assert/strict';
import { renderExecutiveReport } from '../utils/executive_report.mjs';
import { shapeFinding } from '../utils/report_inputs.mjs';

const REGIONS = ['us-east-1', 'eu-west-2', 'ap-southeast-2', 'us-gov-west-1', 'cn-north-1', 'eusc-de-east-1'];

const MODEL = {
  runId: 'run_e1_delta_region', startedAt: '2026-05-01T00:00:00Z', finishedAt: '2026-05-01T00:10:00Z',
  tier: 'enterprise', ceVersion: '0.2.55', eeVersion: '1.1.0',
  coverage: { requested: 1, written: 1, reachable: 1, missing: [], partial: false, incomplete: false },
  plugins: { ran: 1, skipped: 0, errored: 0, timedOut: 0,
    byHost: [{ host: 'aws', dir: 'aws_20260501T000000Z', status: [
      { id: '1130', name: 'AWS Backup Auditor', status: 'ran', reason: null }] }] },
  kev: { loaded: false, snapshot: null },
  findings: [], hosts: [],
};

function reportWithDelta(added) {
  return renderExecutiveReport(MODEL, {}, {
    renderedAt: new Date('2026-05-01T00:10:00Z'),
    // ⚠️ THE REAL `renderDelta` SHAPE, read off the function rather than invented — a
    // wrong-shaped driver fabricates whatever it likes and proves nothing about the renderer.
    delta: {
      comparable: true, baselineIntegrity: 'sealed', currentIntegrity: 'sealed', limits: [],
      resolved: [], newFindings: added, changed: [], notComparable: [], unchanged: [],
    },
  });
}

test('six per-region scope findings render as six DISTINGUISHABLE rows', () => {
  const html = reportWithDelta(REGIONS.map((region) => ({
    title: 'Backup vault policy not enforced', resource: 'backup:account', region,
    severity: 'MEDIUM', plugin: 1130,
  })));
  for (const region of REGIONS) {
    assert.ok(html.includes(region),
      `the reader cannot tell the ${region} row from its five siblings — before E1 the `
      + '` [region]` suffix did that, and removing it without this leg leaves six identical rows');
  }
});

test('a finding with NO region renders no empty region furniture', () => {
  // The fourth quadrant: most producers carry no region, and a column of em-dashes on every
  // network finding is noise that trains a reader to ignore the cell that matters.
  const html = reportWithDelta([{ title: 'TLSv1 enabled', resource: 'tls:443', severity: 'HIGH', plugin: 3 }]);
  assert.ok(html.includes('tls:443'));
  assert.ok(!/backup:account/.test(html));
});

test('the region is rendered ESCAPED, like every other cell in the row', () => {
  const html = reportWithDelta([{
    title: 'x', resource: 'r', region: '<script>alert(1)</script>', severity: 'LOW', plugin: 1,
  }]);
  assert.ok(!html.includes('<script>alert(1)</script>'), 'a region must not reach the page raw');
});

test('the LOADER actually supplies the field this row renders — not just my fixture', () => {
  // ⚠️ THE THREE LEGS ABOVE DRIVE A HAND-BUILT MODEL, so on their own they prove the renderer
  // and nothing about production. If `shapeFinding` stopped carrying `region`, every one of them
  // would stay green while the live table went back to six identical rows. This leg closes that
  // by taking a RAW finding through the real loader and asserting the contract the row depends
  // on — and it is the same shape `scan_delta` spreads into `newFindings`/`resolved`.
  const shaped = shapeFinding('aws', {
    issues: ['Backup vault policy not enforced'], resource: 'backup:account',
    region: 'eu-west-2', severity: 'MEDIUM',
  }, 1130, 'AWS Backup Auditor');
  assert.equal(shaped.region, 'eu-west-2', 'the loader must carry the region onto the shaped finding');
  assert.equal(shaped.resource, 'backup:account', 'and leave the canonical resource alone');

  const html = reportWithDelta([shaped]);
  assert.ok(html.includes('eu-west-2'), 'and the row must show it');
  assert.ok(html.includes('backup:account'));
});

test('a suffixed resource from a PRE-E1 baseline renders canonically, with the region beside it', () => {
  // The upgrade case as the reader sees it: a baseline written by the published build carries
  // `backup:account [eu-west-2]`. The loader canonicalises it, so the table shows the same
  // object the current run shows — not a spurious "resolved / new" pair differing by decoration.
  const shaped = shapeFinding('aws', {
    issues: ['Backup vault policy not enforced'], resource: 'backup:account [eu-west-2]',
    region: 'eu-west-2', severity: 'MEDIUM',
  }, 1130, 'AWS Backup Auditor');
  assert.equal(shaped.resource, 'backup:account', 'the decoration is not identity and not display');
  const html = reportWithDelta([shaped]);
  assert.ok(!html.includes('backup:account [eu-west-2] '), 'no doubled decoration in the cell');
  assert.ok(html.includes('eu-west-2'));
});
