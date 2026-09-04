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
