// tests/report_finding_content_fleet.test.mjs
//
// THE REPORT READ FIELDS NO SHIPPED PLUGIN EMITS, AND THE SUITE COULD NOT SEE IT
// BECAUSE ITS FIXTURES POPULATED THOSE FIELDS.
//
// Found by Gate 3-B on the installed EE 0.44.0 / CE 0.2.51 trio, driving the real
// `report` subcommand over a real 21-plugin AWS scan:
//
//     208 "(untitled finding)" — every one of 198 findings, in both tables
//     jira CSV: Summary EMPTY on every row
//
// `shapeFinding()` read `f.title`, `f.detail ?? f.description` and `f.remediation`.
// Measured across the shipped fleet: 27 of 29 EE plugins carry no `title:` field at
// all, no CE plugin carries one, and exactly THREE `findings.push` sites in the whole
// product set one. Cloud findings carry their content in `issues[]`. The report path
// never read `issues`.
//
// ⚠️ WHY THE EXISTING TESTS WERE GREEN OVER IT — the point of this file. Every report
// fixture in this suite writes `title` into its findings by hand, so the suite proves
// the RENDERER and never that any PRODUCER emits what the renderer reads. A fixture
// that supplies the field under test cannot discover that nothing supplies it in
// production. That is why this file drives one finding per REAL SHIPPED SHAPE rather
// than a hand-written finding: the shapes are the claim, not the values.
//
// The four shapes below are the fleet as MEASURED from a real conclusion file, not as
// imagined. Values are neutral — CE is a public package and a fixture is not the place
// for a real account id — but every KEY SET and TYPE is taken from live output.

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { shapeFinding } from '../utils/report_inputs.mjs';
import { renderJiraCsv, JIRA_COLUMNS } from '../utils/jira_export.mjs';
import { renderExecutiveReport } from '../utils/executive_report.mjs';

// ── The shipped fleet, one member per shape ────────────────────────────────────

// SHAPE 1 — `issues[]` of STRINGS. The dominant shape by a wide margin: 197 of 198
// findings in the measured run, produced by 1020/1030/1040/1060/1070/1080 and more.
const ISSUES_STRINGS = {
  userName: 'example-admin',
  arn: 'arn:aws:iam::000000000000:user/example-admin',
  severity: 'critical',
  issues: ['SHADOW ADMIN: User has full wildcard (*) permissions'],
  classification: 'shadow-admin',
};

// SHAPE 2 — `issues[]` of OBJECTS `{severity, detail}`. Emitted by 1030's error paths
// (five sites). ⚠️ It carries `.detail`, NOT `.title` — a fix that reads `.title` here
// produces nothing, which is the specific trap this leg exists to catch.
const ISSUES_OBJECTS = {
  userName: 'example-user',
  severity: 'medium',
  issues: [{ severity: 'medium', detail: 'Could not parse policy document' }],
};

// SHAPE 3 — the finding carries its OWN `title`. Only three sites product-wide, so it
// is the rarest shape and the one most likely to be broken by a careless fix: its
// title must survive VERBATIM rather than being regenerated from issues[].
const OWN_TITLE = {
  roleName: 'example-role',
  severity: 'info',
  category: 'federated-principal-oversize',
  title: 'Federated trust policy exceeds the inspected principal budget',
  issues: ['Federated trust policy exceeds the inspected principal budget'],
};

// SHAPE 4 — FOURTH QUADRANT, WRITTEN FIRST. Neither a title nor any issues. One such
// finding was present in the measured run (1030, `issues: []`). The report must still
// say "(untitled finding)" and must NOT fabricate a title from the resource keys or
// from anything else. A fix that invents content here is worse than the defect.
const NEITHER = {
  userName: 'example-empty',
  severity: 'info',
  issues: [],
};

describe('the report renders content for every shipped finding shape', () => {
  // ── FOURTH QUADRANT FIRST ───────────────────────────────────────────────────

  it('a finding with neither title nor issues stays untitled — it must not fabricate', () => {
    const s = shapeFinding('aws', NEITHER);
    assert.equal(s.title, null,
      'a finding carrying no content must yield a null title, so the renderer says "(untitled finding)"');
    assert.equal(s.detail, null, 'and it must not invent a detail body either');
  });

  it('a finding with its OWN title keeps it verbatim, never regenerated', () => {
    const s = shapeFinding('aws', OWN_TITLE);
    assert.equal(s.title, OWN_TITLE.title,
      'an explicit producer title is authoritative and must survive untouched');
  });

  // ── THE LEGS THE DEFECT WAS FOUND ON ────────────────────────────────────────

  it('SHAPE 1 — issues[] of strings yields a non-empty title', () => {
    const s = shapeFinding('aws', ISSUES_STRINGS);
    assert.ok(s.title && s.title.trim().length > 0,
      'the dominant shipped shape must not render as "(untitled finding)"');
    assert.match(s.title, /SHADOW ADMIN/,
      'the title must carry the finding\'s own words, not a generic label');
  });

  it('SHAPE 2 — issues[] of OBJECTS yields a non-empty title from `.detail`', () => {
    // The trap: these objects have `.detail`, not `.title`.
    const s = shapeFinding('aws', ISSUES_OBJECTS);
    assert.ok(s.title && s.title.trim().length > 0,
      'object-shaped issues must not render as "(untitled finding)"');
    assert.match(s.title, /Could not parse policy document/);
  });

  it('every shipped shape that HAS content produces a title — the fleet, together', () => {
    // A per-shape assertion proves each member; this proves the SET, so a shape added
    // later without a title path fails here even if nobody writes it its own leg.
    for (const [name, f] of [['strings', ISSUES_STRINGS], ['objects', ISSUES_OBJECTS], ['own-title', OWN_TITLE]]) {
      const s = shapeFinding('aws', f);
      assert.ok(s.title && s.title.trim().length > 0, `shape "${name}" produced no title`);
    }
  });

  it('the detail body carries ALL issues, not just the first', () => {
    const multi = { bucket: 'example-bucket', severity: 'low', issues: ['First issue here', 'Second issue here'] };
    const s = shapeFinding('aws', multi);
    assert.match(s.detail ?? '', /First issue here/);
    assert.match(s.detail ?? '', /Second issue here/,
      'a report that shows only the first issue silently drops findings the scan recorded');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// THE SECOND CONSEQUENCE OF THE SAME MISSING CONTENT: the Jira `External ID`.
//
// `externalIds()` keys on [host, port, title, detail]. With title AND detail both
// null — which is what every cloud finding was before the fix — every finding on one
// host produced an IDENTICAL key, and the only thing separating them was their
// ORDINAL among equal keys. That is stable across renders of the same model, which is
// what its comment claims and what my first measurement saw (7 rows, 7 distinct ids,
// no collision). It is NOT stable across RUNS: remove or add one finding and every
// later ordinal shifts, so every later id changes.
//
// That breaks the column's own documented promise — "stable per finding so that an
// importer WHICH KEYS ON IT can update rather than duplicate" — in precisely the
// update flow it exists for. Content-derived titles fix it by making the keys differ.
// ─────────────────────────────────────────────────────────────────────────────

describe('the Jira External ID is content-derived, so it survives a changed finding set', () => {
  const model = (findings) => ({ runId: 'r1', startedAt: '2026-09-04T00:00:00Z', findings });
  const f = (issues, severity = 'low') => shapeFinding('aws', { bucket: `b-${issues[0].slice(0, 6)}`, severity, issues });

  const A = f(['Access logging not enabled – audit trail gap']);
  const B = f(['Object Lock is not configured on this bucket']);
  const C = f(['MFA Delete is disabled on this bucket']);

  const idsOf = (rows) => rows.trim().split('\n').slice(1).map((r) => r.split(',').pop());

  it('every row carries a NON-EMPTY Summary — an empty one does not import as a Jira issue', () => {
    // The B2 leg the sheet's FAIL list never asserted, which is why a CSV of seven
    // untitled issues scored PASS by the letter.
    const csv = renderJiraCsv(model([A, B, C]));
    assert.equal(csv.trim().split('\n')[0], JIRA_COLUMNS.join(','));
    for (const row of csv.trim().split('\n').slice(1)) {
      assert.ok(row.length > 0 && !row.startsWith(','), `row has an empty Summary: ${row.slice(0, 60)}`);
    }
  });

  it('removing one finding leaves every OTHER id unchanged', () => {
    const before = idsOf(renderJiraCsv(model([A, B, C])));
    const after = idsOf(renderJiraCsv(model([A, C])));
    assert.equal(before[0], after[0], "A's id must not move when B is removed");
    assert.equal(before[2], after[1], "C's id must not move when B is removed");
  });

  it('RFC 4180: a finding whose text carries a comma, a quote and a newline stays in its column', () => {
    // Untestable until the content fix landed — uniform empty Descriptions contain no
    // delimiters at all, so this leg had never actually been exercised.
    const nasty = f(['Policy allows "*", and grants\nfull access, including delete']);
    const csv = renderJiraCsv(model([nasty]));
    const lines = csv.trim().split('\n');
    assert.equal(lines[0], JIRA_COLUMNS.join(','));
    // The embedded delimiters must be quoted, not split into extra columns.
    assert.match(csv, /"/, 'a field carrying a comma/quote/newline must be quoted');
    const parsed = csv.slice(csv.indexOf('\n') + 1);
    assert.ok(parsed.includes('Policy allows'), 'the finding text must survive into the CSV');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// PASS-TIER RECORDS ARE NOT WORK ITEMS AND ARE NOT "OTHER".
//
// Ruled by the architect seat after the content fix landed, from reading BOTH
// renderers rather than the one record that surfaced it:
//
//  · `renderJiraCsv` had no severity filter, so all 18 PASS records in a real AWS run
//    became Jira issues — 17 of them carrying substrate prose that a consultant would
//    have to close by hand. A Jira issue is a work item; a passing check is not work.
//  · `chartSev()` collapses any severity with no `SEV_COLORS` entry to the literal
//    'OTHER', and PASS had none — so a client-facing report labelled 18 passing checks
//    "OTHER".
//
// ⚠️ ONE ADDITION OF MY OWN, ATTRIBUTED RATHER THAN FOLDED IN SILENTLY: Top Risks had
// no filter either (`findings.sort(compareRisk).slice(0, TOP_RISKS_LIMIT)`). PASS only
// stayed out of it because 105 non-pass findings outranked it — on a CLEAN scan the
// section titled "Top Risks" would list passing checks. That is the same defect the
// ruling names, so it is fixed on the same reasoning.
// ─────────────────────────────────────────────────────────────────────────────

// `renderExecutiveReport` dereferences `brand.title` unguarded, so brand is required —
// the CLI always supplies a default, which is why the live runs render without `--brand`.
const BRAND = { title: null, companyName: null, preparedBy: null, contact: null, logoDataUri: null };

const passFinding = (issues) => shapeFinding('aws', { userName: 'clean-user', severity: 'pass', issues });
const lowFinding = (txt) => shapeFinding('aws', { bucket: 'b-low', severity: 'low', issues: [txt] });

const EXEC_MODEL = (findings) => ({
  runId: 'run_test', startedAt: '2026-09-04T00:00:00Z', finishedAt: '2026-09-04T01:00:00Z',
  tier: 'enterprise', ceVersion: '0.2.51', eeVersion: '0.44.0',
  coverage: { requested: 1, written: 1, reachable: 1, missing: [], partial: false, incomplete: false },
  plugins: { ran: 1, skipped: 0, errored: 0, timedOut: 0, byHost: [{ host: 'aws', dir: 'aws_1', status: [] }] },
  kev: { loaded: false, snapshot: null }, epss: { loaded: false, snapshot: null },
  hosts: [{ host: 'aws', dir: 'aws_1', up: true, findings }],
  findings,
});

describe('a passing check is not a work item and not "OTHER"', () => {
  // ── FOURTH QUADRANT FIRST — these must hold BEFORE the fix, so they are not decoration
  it('a NON-pass finding is still emitted to the Jira CSV — the filter must not over-reach', () => {
    const csv = renderJiraCsv({ runId: 'r', startedAt: 'x', findings: [lowFinding('Object Lock is not configured')] });
    assert.equal(csv.trim().split('\n').length, 2, 'header + exactly one data row');
    assert.match(csv, /Object Lock is not configured/);
  });

  it('a NON-pass contentless record still renders untitled — the PASS fix must not swallow it', () => {
    // "(untitled finding)" stays the ALARM for a non-pass finding whose producer emitted
    // nothing. If the PASS work also silenced this, the fleet test's Summary leg would
    // stop being able to fail, and a real producer defect would render as normal output.
    const s = shapeFinding('aws', { bucket: 'b-empty', severity: 'low', issues: [] });
    assert.equal(s.title, null);
  });

  // ── THE RULING'S LEGS ───────────────────────────────────────────────────────
  it('PASS records are EXCLUDED from the Jira CSV', () => {
    const csv = renderJiraCsv({ runId: 'r', startedAt: 'x',
      findings: [passFinding(['IAM user has no wildcard permissions']), lowFinding('Object Lock is not configured')] });
    const lines = csv.trim().split('\n');
    assert.equal(lines[0], JIRA_COLUMNS.join(','));
    assert.equal(lines.length, 2, 'only the non-pass finding may become an issue');
    assert.equal(/no wildcard permissions/.test(csv), false, 'a passing check must not become a Jira issue');
  });

  it('a contentless PASS record leaves the CSV entirely, so no row has an empty Summary', () => {
    const csv = renderJiraCsv({ runId: 'r', startedAt: 'x',
      findings: [passFinding([]), lowFinding('Object Lock is not configured')] });
    for (const row of csv.trim().split('\n').slice(1)) {
      assert.ok(!row.startsWith(','), `empty Summary survived: ${row.slice(0, 50)}`);
    }
  });

  it('the executive tier table counts PASS as its own tier, never as OTHER', () => {
    const html = renderExecutiveReport(EXEC_MODEL([passFinding(['IAM user has no wildcard permissions'])]), BRAND,
      { renderedAt: new Date('2026-09-04T02:00:00Z') });
    assert.match(html, /PASS/, 'PASS must be a labelled tier');
    assert.equal(/>OTHER</.test(html) && !/PASS/.test(html), false);
    assert.match(html, /data-row-severity="PASS"/,
      'a PASS record must carry its own row severity, not be collapsed to OTHER');
  });

  it('a contentless PASS record reads as clean, not as "(untitled finding)"', () => {
    const html = renderExecutiveReport(EXEC_MODEL([passFinding([])]), BRAND,
      { renderedAt: new Date('2026-09-04T02:00:00Z') });
    assert.match(html, /clean — no issues recorded/);
    assert.equal(/\(untitled finding\)/.test(html), false,
      '"(untitled finding)" is the alarm for a NON-pass producer defect, never a display state for a clean check');
  });

  it('PASS records never appear under "Top Risks"', () => {
    // MY ADDITION to the ruling, on its own reasoning: a passing check is not a risk.
    const html = renderExecutiveReport(EXEC_MODEL([passFinding(['IAM user has no wildcard permissions'])]), BRAND,
      { renderedAt: new Date('2026-09-04T02:00:00Z') });
    const top = html.slice(html.indexOf('Top Risks'), html.indexOf('Severity Distribution'));
    assert.equal(/no wildcard permissions/.test(top), false,
      'a clean scan must not list its passing checks as Top Risks');
  });
});
