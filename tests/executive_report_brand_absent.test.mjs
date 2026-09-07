// tests/executive_report_brand_absent.test.mjs — `renderExecutiveReport` over an ABSENT brand.
//
// THE DEFECT, and what was MEASURED before this file existed. `renderExecutiveReport(model,
// brand, opts)` opened with `escapeHtml(brand.title || '...')` and dereferenced `brand` at ELEVEN
// sites across three functions (`renderExecutiveReport` · `renderCover` · `renderBrandBlock`),
// every one unguarded. Driven over eight brand shapes against the shipped module:
//
//     omitted (2-arg call)   THREW TypeError: Cannot read properties of undefined (reading 'title')
//     undefined              THREW TypeError: Cannot read properties of undefined (reading 'title')
//     null                   THREW TypeError: Cannot read properties of null (reading 'title')
//     string 'Acme'          OK  len=4579  title="Network Scan Report"  hasCompany=false
//     number 42              OK  len=4579  title="Network Scan Report"  hasCompany=false
//     array []               OK  len=4579  title="Network Scan Report"  hasCompany=false
//     {}                     OK  len=4579  title="Network Scan Report"  hasCompany=false
//     populated object       OK  len=4689  title="Q3 Review"            hasCompany=true
//
// TWO failures, not one, and the second is the quieter of the pair: null/undefined CRASH, and a
// non-object (a caller that passes the company NAME where the brand OBJECT belongs) renders a
// complete, plausible, SILENTLY UNBRANDED client deliverable at exit 0 — byte-identical to a
// report nobody asked to brand. That is the CC-4 shape one layer down: `tests/report_command.test.mjs`
// already pins "a value-less --brand is FATAL, not a silent unbranded default" because a shell
// glob that swallowed the path "produced the IDENTICAL unbranded default report, at exit 0, as
// never asking for a brand at all — silently."
//
// ⚠️ REACHABILITY WAS ADJUDICATED, NOT INHERITED. The board recorded this as "unreachable today
// because the CLI always supplies a default". That REPRODUCES, and the pin below ("the shipped
// loadBrand default still renders") is what keeps it reproducing. Driven through the shipped
// `runReport` handler with a brand file whose whole JSON document is `null` — the case that turns
// on `typeof null === 'object'` — plus `[]`, `"x"`, `0` and `false`: ALL FIVE exit 2 with no file
// written, because `loadBrand`'s `isPlainObject` tests `v !== null` explicitly and the CLI refuses
// on `!brandResult.ok` before the renderer is reached. loadBrand was separately driven over twelve
// inputs (absent · empty-string arg · missing file · a directory · null/array/string/number/true
// documents · malformed JSON · `{}`): every `ok:true` returned a plain object, and no failure path
// returns a brand at all.
//
// So the caller that can reach this is not the CLI — it is the NEXT one. `utils/` ships in
// package.json `files` and the package declares no `exports` field, so
// `nsauditor-ai/utils/executive_report.mjs` deep-imports and resolves from the EE repo today
// (measured). The renderer is a published entry point whose only guard was a convention held one
// module away.
//
// ⚠️ THE FOURTH-QUADRANT LEG IS FIRST IN THIS FILE ON PURPOSE and it is the one that rots. Every
// leg below it is incident-born and satisfies a "default when absent" fix trivially; a fix that
// defaults too eagerly — or normalises a real brand through the same path — stops honouring the
// consultant's own identity while every absent-brand leg stays green. It is proven discriminating
// by mutation, not by having been watched fail, because it guards behaviour that already worked.

import test from 'node:test';
import assert from 'node:assert/strict';
import { renderExecutiveReport } from '../utils/executive_report.mjs';
import { loadBrand } from '../utils/brand.mjs';

// A 1x1 PNG, base64 — the only data: shape `brand.mjs` can produce (magic-byte sniffed).
const PNG_1X1 = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==';

// A literal, not a builder — a shape change in report_inputs.mjs's model must be visible here
// rather than absorbed by a helper that adapts to whatever the producer now emits. Deliberately
// duplicated rather than imported from tests/executive_report.test.mjs, matching the standing
// note in tests/report_command.test.mjs's header.
const MODEL = {
  runId: 'run_20260907T090000Z_brandabs',
  startedAt: '2026-09-07T09:00:00Z',
  finishedAt: '2026-09-07T09:41:00Z',
  tier: 'pro',
  ceVersion: '0.2.51',
  eeVersion: null,
  coverage: { requested: 1, written: 1, reachable: 1, missing: [], partial: false, incomplete: false },
  plugins: {
    ran: 1, skipped: 0, errored: 0, timedOut: 0,
    byHost: [{ host: '10.0.0.9', dir: '10.0.0.9_20260907T090000Z', status: [
      { id: '003', name: 'Port Scanner', status: 'ran', reason: null },
    ] }],
  },
  kev: { loaded: true, snapshot: '2026-09-01' },
  epss: { loaded: true, snapshot: '2026-09-01' },
  hosts: [{
    host: '10.0.0.9', dir: '10.0.0.9_20260907T090000Z', up: true,
    findings: [{
      host: '10.0.0.9', port: 443, severity: 'HIGH',
      title: 'Weak SSH key exchange algorithms enabled',
      detail: 'diffie-hellman-group1-sha1 is offered by the SSH server.',
      remediation: 'Disable weak KEX algorithms in sshd_config.',
      cves: [], kev: false, epss: 0.12, id: 'f1',
    }],
  }],
  findings: [{
    host: '10.0.0.9', port: 443, severity: 'HIGH',
    title: 'Weak SSH key exchange algorithms enabled',
    detail: 'diffie-hellman-group1-sha1 is offered by the SSH server.',
    remediation: 'Disable weak KEX algorithms in sshd_config.',
    cves: [], kev: false, epss: 0.12, id: 'f1',
  }],
};

// Every field a brand can carry, all populated — so the fourth-quadrant leg below asserts on the
// WHOLE branded surface rather than on whichever field the fix happened to touch.
const FULL_BRAND = {
  title: 'Q3 External Perimeter Review',
  companyName: 'Acme Manufacturing GmbH',
  preparedBy: 'J. Rivera, Security Consulting LLC',
  contact: 'security@example.test',
  logoDataUri: PNG_1X1,
};

// ── FOURTH QUADRANT FIRST: a POPULATED brand is still honoured, field by field ────────────────

test('FOURTH QUADRANT: a populated brand still renders EVERY branded element', () => {
  const html = renderExecutiveReport(MODEL, FULL_BRAND, { renderedAt: new Date('2026-09-07T09:41:00Z') });

  // Asserted per FIELD, by its own rendered shape, so a fix that keeps one and drops another
  // cannot pass. `title` reaches TWO surfaces (the <title> element and the cover <h1>) and both
  // are checked: line 553 and line 368 were separate unguarded dereferences of the same field.
  assert.match(html, /<title>Q3 External Perimeter Review<\/title>/,
    'the brand title must reach the document <title>');
  assert.match(html, /<h1>Q3 External Perimeter Review<\/h1>/,
    'the brand title must reach the cover <h1>');
  assert.match(html, /<p class="brand-company">Prepared for Acme Manufacturing GmbH<\/p>/,
    'companyName must render in the brand block');
  assert.match(html, /<p class="brand-contact">Contact: security@example\.test<\/p>/,
    'contact must render as text in the brand block');
  assert.match(html, /Prepared by J\. Rivera, Security Consulting LLC · /,
    'preparedBy must render in the run-dates clause');
  assert.ok(html.includes(`src="${PNG_1X1}"`),
    'logoDataUri must render as the <img> src, unmodified');
  assert.match(html, /alt="Acme Manufacturing GmbH"/,
    'the logo alt text is the company name, not the generic fallback');

  // The generic fallback title must NOT appear anywhere when a real title was supplied — a fix
  // that renders the default BESIDE the brand (rather than instead of it) passes every assertion
  // above and is still wrong on a client deliverable.
  assert.ok(!html.includes('Network Scan Report'),
    'the default title must not appear when the brand supplies its own');
});

test('FOURTH QUADRANT: a deliberately unbranded report is still supported — `{}` renders', async () => {
  // The escape hatch has to exist, or the refusal below is a regression rather than a guard:
  // "no branding wanted" must remain expressible, and must keep rendering exactly what it
  // rendered before. Measured pre-fix: 4579 bytes, title "Network Scan Report", no brand block.
  const html = renderExecutiveReport(MODEL, {}, {});
  assert.match(html, /<title>Network Scan Report<\/title>/);
  assert.match(html, /<h1>Network Scan Report<\/h1>/);
  // ⚠️ ASSERTED ON THE ELEMENT, NEVER ON THE CLASS NAME. A bare
  // `html.includes('brand-logo')` matches the STYLESHEET — `.brand-logo { max-height: 64px }`
  // is emitted on every render — so the absence check would have been false-adjacent and this
  // leg went RED on its first run for that reason, not for the reason it names.
  assert.ok(!/<p class="brand-company">/.test(html), 'an empty brand emits no company line');
  assert.ok(!/<img class="brand-logo"/.test(html), 'an empty brand emits no logo element');
});

test('FOURTH QUADRANT: the shipped loadBrand default still renders — the CLI path cannot trip the guard', async () => {
  // THIS IS THE REACHABILITY PIN. `loadBrand(null)` is what the CLI passes on every `report
  // --format executive` invocation without `--brand`; if the refusal below could ever fire on
  // that object, this fix would have converted an unreachable crash into a live one. Driving the
  // real loader — not a hand-built stand-in — is what makes that a measurement.
  const r = await loadBrand(null);
  assert.equal(r.ok, true);
  const html = renderExecutiveReport(MODEL, r.brand, {});
  assert.match(html, /<title>Network Scan Report<\/title>/);
});

// ── The absent legs: what the unguarded dereference did ───────────────────────────────────────

// The assertion is on the MESSAGE, never on the error TYPE alone. Pre-fix, null and undefined
// already threw a TypeError — so `assert.throws(fn, TypeError)` PASSES over the defect and proves
// nothing. Each leg below requires the refusal to NAME `brand`, and explicitly requires the
// engine's own unguarded-dereference wording to be ABSENT.
function assertNamedRefusal(fn, what) {
  assert.throws(fn, (e) => {
    assert.ok(e instanceof TypeError, `${what}: expected a TypeError, got ${e?.constructor?.name}`);
    assert.match(e.message, /renderExecutiveReport/,
      `${what}: the refusal must name the function that refused`);
    assert.match(e.message, /\bbrand\b/,
      `${what}: the refusal must name the argument at fault`);
    assert.ok(!/Cannot read propert/.test(e.message),
      `${what}: this is an UNGUARDED DEREFERENCE, not a refusal — the guard did not run. `
      + `Message was: ${e.message}`);
    return true;
  });
}

test('a NULL brand is refused by name, not by an unguarded dereference', () => {
  assertNamedRefusal(() => renderExecutiveReport(MODEL, null, {}), 'null');
});

test('an UNDEFINED brand is refused by name, not by an unguarded dereference', () => {
  assertNamedRefusal(() => renderExecutiveReport(MODEL, undefined, {}), 'undefined');
});

test('an OMITTED brand argument is refused by name — a default parameter alone does not cover null', () => {
  // `renderExecutiveReport(model)` is the 2-arg call a new caller writes. A defaulted parameter
  // (`brand = {}`) would fix THIS leg and silently leave the explicit-null leg above crashing,
  // because a default only fires on `undefined` — which is why the fix is a normalisation and
  // this leg is kept separate from the undefined one rather than folded into it.
  assertNamedRefusal(() => renderExecutiveReport(MODEL), 'omitted');
});

// ── The non-object legs: the quiet half ───────────────────────────────────────────────────────

test('a NON-OBJECT brand is refused rather than silently rendering an unbranded deliverable', () => {
  // Every one of these rendered a complete, plausible, unbranded 4579-byte report before the fix
  // (measured, above). A consultant who passes their company NAME where the brand OBJECT belongs
  // got a client-facing report with their identity silently missing, at exit 0.
  for (const [label, value] of [
    ['a string', 'Acme Manufacturing GmbH'],
    ['a number', 42],
    ['a boolean', true],
    ['an array', ['Acme Manufacturing GmbH']],
  ]) {
    assertNamedRefusal(() => renderExecutiveReport(MODEL, value, {}), label);
  }
});

test('the refusal SAYS WHAT TO PASS — a message that only names the fault is half a refusal', () => {
  // A caller reading this message must not have to open the module to learn the remedy. Both
  // routes are named: the loader that produces the object, and the literal for a deliberately
  // unbranded report.
  assert.throws(() => renderExecutiveReport(MODEL, null, {}), (e) => {
    assert.match(e.message, /loadBrand/, 'the refusal must name the loader that produces a brand');
    assert.match(e.message, /\{\}/, 'the refusal must name the literal for a deliberately unbranded report');
    return true;
  });
});

test('the refusal NAMES what was actually passed, so the caller can see its own bug', () => {
  // "brand must be an object" over a value the caller cannot see is a message that sends them
  // reading the module. Each shape is described by what it IS.
  const cases = [[null, /\bnull\b/], [undefined, /\bundefined\b/], ['x', /string/], [42, /number/], [[], /array/]];
  for (const [value, re] of cases) {
    assert.throws(() => renderExecutiveReport(MODEL, value, {}), (e) => {
      assert.match(e.message, re, `the refusal must describe what was passed (${String(value)})`);
      return true;
    });
  }
});

test('PREMISE PIN: the module exports exactly two names, so the guard covers every brand dereference', async () => {
  // The guard sits at ONE entry point and covers eleven `brand.` dereferences because the other
  // eight live in `renderCover` and `renderBrandBlock`, which are reachable ONLY through
  // `renderExecutiveReport`. That is a STRUCTURAL justification, and a structural justification
  // is invalidated by the very change that breaks it — exporting either helper would open an
  // unguarded path while every leg above stayed green. Pinned by EQUALITY, not by a
  // does-not-include list: a name nobody thought of is the one that gets exported.
  const mod = await import('../utils/executive_report.mjs');
  assert.deepEqual(
    Object.keys(mod).sort(),
    ['egressViolations', 'renderExecutiveReport'],
    'a new export from this module may reach `brand` without passing the guard — either route it '
    + 'through renderExecutiveReport, or give it its own brand check and update this pin');
});

test('the refusal happens BEFORE any HTML is produced', () => {
  // A partial document handed back beside a thrown error is the worst of both: the caller may
  // still write it. Nothing is returned at all.
  // ⚠️ THE `threw` LEG IS WHAT MAKES THIS DISCRIMINATING. The sentinel assertion ALONE passes
  // over the original defect (an unguarded TypeError also returns nothing) — it would be
  // decoration. What it must catch is the OTHER fix nobody should ship: normalising an absent
  // brand into a silently unbranded client deliverable, which returns a full document and
  // throws nothing.
  let returned = 'sentinel';
  let threw = false;
  try { returned = renderExecutiveReport(MODEL, null, {}); } catch { threw = true; }
  assert.equal(threw, true, 'an absent brand must refuse, never silently render unbranded');
  assert.equal(returned, 'sentinel', 'a refused render must return nothing, not a partial document');
});
