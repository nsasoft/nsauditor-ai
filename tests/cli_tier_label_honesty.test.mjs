/**
 * A TIER LABEL IN `nsauditor-ai help` MUST NAME EXACTLY THE TIERS THAT CARRY THE CAPABILITY.
 *
 * ── WHY THIS EXISTS ──────────────────────────────────────────────────────────────────────────
 * `nsauditor-ai help` labelled the `report` subcommand `(Pro)` at two sites — the synopsis line
 * and the section header. `report` is gated on `hasCapability(caps, 'clientReporting')`, and
 * capabilities are MONOTONIC: measured here, ce grants 6 capabilities, pro 14, enterprise 19,
 * with ce ⊆ pro ⊆ enterprise. `clientReporting` is a `pro`-tier flag, so BOTH pro and enterprise
 * carry it — an Enterprise buyer reading `(Pro)` in the tool's own help concludes the capability
 * is not theirs.
 *
 * ⚠️ THAT IS AN UNDERCLAIM, AND THE UNDERCLAIM IS THE EXPENSIVE DIRECTION: a customer who
 * concludes a feature is not theirs simply does not use it, and NOTHING anywhere goes red. An
 * overclaim eventually produces a refusal a customer complains about; an underclaim produces
 * silence. So the durable repair is not the two edits — it is this guard, which fails when a tier
 * label in the rendered help disagrees with the capability registry.
 *
 * ── THE CONVENTION THIS FILE SETS (there was no counter-example to copy) ──────────────────────
 * Measured before writing it: those two `(Pro)` strings were the ONLY tier-labelled strings in the
 * entire help output. There is no second labelled subcommand to match, so this guard is SETTING
 * the convention rather than enforcing an existing one:
 *
 *     a tier label names EXACTLY the set of tiers whose resolved capabilities carry the
 *     capability that gates the labelled subcommand — no more, no less.
 *
 * `clientReporting` → `(Pro/Enterprise)`. An enterprise-only capability → `(Enterprise)`. A ce
 * capability, if one were ever labelled → `(CE/Pro/Enterprise)`. All three shapes are exercised
 * below against the REAL registry, so an implementation that simply hard-coded "Pro/Enterprise"
 * would fail two of them.
 *
 * The SPELLING is not invented either, and that was measured rather than assumed: the same help
 * output already writes the pair as `Pro/Enterprise` in three prose lines (the anti-spoofing note,
 * the unexpected-CE note and the NSAUDITOR_LICENSE_KEY row). Those are prose, not labels, so the
 * "only two labelled strings" measurement above still holds — but the register was already there
 * to match, which is why the label is `(Pro/Enterprise)` and not, say, `(Pro+)`.
 *
 * ── HOW THE COUPLING IS DERIVED, AND WHY IT IS NOT A LIST ─────────────────────────────────────
 * A guard that says "these two lines must read (Pro/Enterprise)" is decoration the moment a third
 * subcommand gains a label. So nothing here is listed:
 *   · the TIER VOCABULARY is derived from `CAPABILITIES` (every registry entry's `tier`);
 *   · the SUBCOMMAND → CAPABILITY coupling is derived from cli.mjs's own refusal sites —
 *     `if (!hasCapability(caps, '<cap>')) { logErr('`<subcommand>` …` — so a newly gated
 *     subcommand joins the corpus by being gated, not by being added here;
 *   · the LABELS are extracted from the REAL rendered help, driven through the real CLI.
 * A label this guard cannot attribute to a derived coupling is a FAILURE, never a silent pass —
 * the omission declares itself rather than wearing the exit code of a clean run.
 *
 * ── STATED RESIDUAL: VOCABULARY AND SHAPE INCOMPLETENESS COST SILENCE ─────────────────────────
 * A tier label is recognised only as a parenthesised group whose members are ALL tier names
 * (`(Pro)`, `(Pro/Enterprise)`, `(CE / Pro / Enterprise)`). `(Enterprise only)`, `(Pro tier)`,
 * `[Pro]` and a bare `Pro-only` are INVISIBLE to this guard — a missed form is a missed defect,
 * the inverse of a noisy exemption vocabulary. That residual is not asserted in prose alone: the
 * `declared limit` test below DRIVES each of those shapes through the extractor and asserts it
 * sees nothing, so widening the extractor turns this file red and the residual gets rewritten
 * instead of rotting.
 *
 * ── THE KEYCHAIN HAZARD, MEASURED AND REMOVED ────────────────────────────────────────────────
 * An OMITTED licence key does not mean CE: the resolver falls through to the macOS Keychain and
 * returns the developer's installed licence, so a subprocess assertion can be a property of the
 * laptop rather than of the code. Measured here: `help` returns BEFORE licence verification and
 * its output is byte-identical (16764 chars) under an expired-pro key, a valid pro key and a
 * valid enterprise key. The help text is tier-INDEPENDENT, which is the cleaner property — it is
 * asserted below, and every drive still passes an EXPLICIT key so the leg can never silently
 * become a reading of this machine's keychain.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { CAPABILITIES, resolveCapabilities, hasCapability } from '../utils/capabilities.mjs';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const CLI = path.join(ROOT, 'cli.mjs');
const SRC = fs.readFileSync(CLI, 'utf8');

// ── Pre-signed tokens, lifted from tests/license.test.mjs (the technique report_command.test.mjs
// and report_cli_liveness.test.mjs already use) — they verify against the SHIPPED public key, so
// no private key exists at test time and nothing is bypassed.
// ⚠️ VALID_PRO_KEY / VALID_ENTERPRISE_KEY expire 2036-04-11; re-mint on approach, never delete.
const LIC = fs.readFileSync(new URL('./license.test.mjs', import.meta.url), 'utf8');
const PRO_KEY = LIC.match(/VALID_PRO_KEY\s*=\s*'([^']+)'/)[1];
const ENTERPRISE_KEY = LIC.match(/VALID_ENTERPRISE_KEY\s*=\s*'([^']+)'/)[1];
const EXPIRED_KEY = LIC.match(/EXPIRED_PRO_KEY\s*=\s*'([^']+)'/)[1];

/** Drive the REAL CLI's help with an EXPLICIT licence key — never an omitted one. */
function renderHelp(key) {
  if (typeof key !== 'string' || key === '') {
    throw new TypeError('renderHelp needs an explicit licence key: omitting it reads the operator keychain');
  }
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-tier-label-'));
  const r = spawnSync(process.execPath, [CLI, 'help'], {
    encoding: 'utf8',
    env: {
      ...process.env,
      NSAUDITOR_LICENSE_KEY: key,
      XDG_CONFIG_HOME: path.join(tmp, 'nonexistent'),
      NSAUDITOR_LICENSE_STATE_FILE: path.join(tmp, 'lic-state.json'),
      NSAUDITOR_LICENSE_REVOCATIONS_FILE: path.join(tmp, 'lic-revocations.json'),
      NSAUDITOR_LICENSE_ID_REPLAY_DEFENSE: '0',
    },
  });
  assert.equal(r.status, 0, `\`help\` exited ${r.status}: ${r.stderr}`);
  assert.ok(r.stdout.length > 2000,
    'help output is implausibly short — the CLI did not print its help, so anything measured over '
    + 'it is measured over nothing');
  return r.stdout;
}

// ── The tier vocabulary and its rank, DERIVED from the registry ──────────────────────────────
// Rank is the number of capabilities the tier grants. That is only a valid ordering because the
// tiers are monotonic, which the premise test below MEASURES rather than assumes.
const grantCount = (tier) => Object.values(resolveCapabilities(tier)).filter(Boolean).length;
const TIERS = [...new Set(Object.values(CAPABILITIES).map((d) => d.tier))]
  .sort((a, b) => grantCount(a) - grantCount(b));
const TIER_SET = new Set(TIERS);

// The only hand-written table in this file: how a tier is SPELT in prose. It is held in equality
// with the derived vocabulary, so a new tier fails loudly here instead of quietly falling out of
// every label check.
const DISPLAY = { ce: 'CE', pro: 'Pro', enterprise: 'Enterprise' };

const byRank = (tiers) => TIERS.filter((t) => tiers.includes(t));
const spell = (tiers) => `(${byRank(tiers).map((t) => DISPLAY[t] ?? t).join('/')})`;

/** Tiers whose resolved capabilities carry `cap`, through the product's OWN predicate. */
function tiersCarrying(cap) {
  return TIERS.filter((t) => hasCapability(resolveCapabilities(t), cap));
}

// ── Label extraction ─────────────────────────────────────────────────────────────────────────
// A candidate is a parenthesised run of letters, spaces and slashes; it is a TIER LABEL only when
// every slash-separated member is a tier name. That filter is what keeps the live help's real
// decoys — `(CE / EE / custom)` and `(cron/systemd/CI)` — out of the corpus.
const CANDIDATE_RE = /\(([A-Za-z][A-Za-z /]*)\)/g;

function lineAt(text, index) {
  const start = text.lastIndexOf('\n', index) + 1;
  const end = text.indexOf('\n', index);
  return text.slice(start, end === -1 ? text.length : end);
}

function extractTierLabels(text) {
  const labels = [];
  for (const m of text.matchAll(CANDIDATE_RE)) {
    const members = m[1].split('/').map((s) => s.trim().toLowerCase()).filter((s) => s !== '');
    if (members.length === 0) continue;
    if (!members.every((w) => TIER_SET.has(w))) continue;
    labels.push({ raw: m[0], tiers: [...new Set(members)], line: lineAt(text, m.index) });
  }
  return labels;
}

// ── The subcommand → capability coupling, DERIVED from cli.mjs's own refusal sites ───────────
// Shape in the source:
//     if (!hasCapability(caps, 'clientReporting')) {
//       logErr('`report` is a Pro capability. …
// The refusal names the subcommand in backticks because it is addressed to the operator who typed
// it — which is exactly what makes the coupling machine-readable without a second copy of it.
const GATE_RE = /!hasCapability\(\s*caps,\s*'([A-Za-z0-9_]+)'\s*\)\s*\)\s*\{\s*logErr\(\s*'`([a-z][a-z-]*)`/g;

function gatedSubcommands(source) {
  const map = new Map();
  for (const m of source.matchAll(GATE_RE)) map.set(m[2], m[1]);
  return map;
}

/**
 * Adjudicate a help text against a subcommand → capability map. Returns human-readable findings;
 * an empty array is clean. `couplings` is a parameter so the fixtures below can drive the same
 * adjudicator they are asserting about, without depending on which subcommands happen to be gated
 * today — while the live leg passes the DERIVED map.
 */
function adjudicate(helpText, couplings) {
  const labels = extractTierLabels(helpText);
  const findings = [];
  for (const label of labels) {
    const subjects = [...couplings.keys()]
      .filter((name) => new RegExp(`\\b${name}\\b`, 'i').test(label.line));
    if (subjects.length === 0) {
      findings.push(`UNATTRIBUTABLE: the tier label ${label.raw} sits on a line that names no `
        + `capability-gated subcommand, so nothing can say whether it is true: "${label.line.trim()}". `
        + 'Either label a line that names its subcommand, or extend the coupling derivation — but a '
        + 'label nothing can adjudicate must never read as clean.');
      continue;
    }
    if (subjects.length > 1) {
      findings.push(`AMBIGUOUS: the tier label ${label.raw} sits on a line naming ${subjects.length} `
        + `gated subcommands (${subjects.join(', ')}), so its subject cannot be derived: `
        + `"${label.line.trim()}".`);
      continue;
    }
    const subcommand = subjects[0];
    const cap = couplings.get(subcommand);
    const carrying = tiersCarrying(cap);
    const labelled = byRank(label.tiers);
    if (labelled.join(',') === carrying.join(',')) continue;
    const missing = carrying.filter((t) => !labelled.includes(t));
    const extra = labelled.filter((t) => !carrying.includes(t));
    const kind = extra.length === 0 ? 'UNDERCLAIM' : (missing.length === 0 ? 'OVERCLAIM' : 'MISMATCH');
    findings.push(`${kind}: \`${subcommand}\` is gated on \`${cap}\`, which ${carrying.join(' + ')} `
      + `carry, but help labels it ${label.raw}`
      + (missing.length ? ` — ${missing.join(' + ')} carry the capability and are not named` : '')
      + (extra.length ? ` — ${extra.join(' + ')} are named and do not carry it` : '')
      + `. Write ${spell(carrying)}. Line: "${label.line.trim()}"`);
  }
  return findings;
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// PREMISE. The rule "a label names exactly the carrying tiers" is only meaningful if the registry
// really is monotonic and really does grant `clientReporting` above `ce`. A premise that is
// checkable must be checked, or the whole guard is adjudicating against nothing.
// ─────────────────────────────────────────────────────────────────────────────────────────────
describe('premise — the capability registry is monotonic and is the oracle', () => {
  it('ce ⊆ pro ⊆ enterprise, and the display table covers exactly the derived vocabulary', () => {
    assert.deepEqual(TIERS, ['ce', 'pro', 'enterprise'],
      'the tier vocabulary derived from CAPABILITIES changed. That is not a reason to edit this '
      + 'assertion — it is a reason to re-read every tier label in the help.');
    assert.deepEqual(Object.keys(DISPLAY).sort(), [...TIERS].sort(),
      'the prose spelling table and the derived tier vocabulary have diverged. A tier with no '
      + 'spelling would be silently unspellable in every failure message this file prints.');
    const granted = (t) => new Set(Object.entries(resolveCapabilities(t))
      .filter(([, v]) => v).map(([k]) => k));
    for (let i = 0; i + 1 < TIERS.length; i += 1) {
      const lower = granted(TIERS[i]);
      const upper = granted(TIERS[i + 1]);
      const lost = [...lower].filter((c) => !upper.has(c));
      assert.deepEqual(lost, [],
        `${TIERS[i]} carries ${lost.join(', ')} and ${TIERS[i + 1]} does not — capabilities are no `
        + 'longer monotonic, so "the tiers above the flag\'s tier also carry it" is no longer a '
        + 'valid derivation and this whole guard must be rethought.');
    }
    assert.ok(granted('ce').size < granted('pro').size && granted('pro').size < granted('enterprise').size,
      'the tiers no longer differ in what they grant — the rank ordering used to spell labels is '
      + 'no longer derivable from the registry');
  });

  it('clientReporting is carried by pro AND enterprise, and not by ce', () => {
    assert.deepEqual(tiersCarrying('clientReporting'), ['pro', 'enterprise']);
    assert.equal(hasCapability(resolveCapabilities('ce'), 'clientReporting'), false);
    assert.equal(CAPABILITIES.clientReporting.tier, 'pro',
      'clientReporting is no longer a pro-tier flag — re-derive every label that names it');
  });
});

// ─────────────────────────────────────────────────────────────────────────────────────────────
// FOURTH QUADRANT FIRST. The defect that motivated this file is a WRONG label, so the leg written
// first is the one that defect does not exercise: a CORRECT label must be accepted. Three
// distinct carrying-set shapes are used deliberately — an adjudicator that simply waved through
// anything spelling "Pro/Enterprise" would pass the report case and fail the other two.
// ─────────────────────────────────────────────────────────────────────────────────────────────
const FIXTURE_COUPLINGS = new Map([
  ['report', 'clientReporting'],   // carried by pro + enterprise
  ['cloudscan', 'cloudScanners'],  // carried by enterprise alone
  ['probe', 'coreScanning'],       // carried by every tier
]);

/*
 * ⚠️ EVERY ACCEPT LEG SEES ITS LABEL EXTRACTED BEFORE IT JUDGES IT, AND THAT WAS A MEASURED
 * DEFECT IN THIS FILE, NOT A PRECAUTION. As first written, each accept leg was a bare
 * `assert.deepEqual(adjudicate(help, …), [])` — which an extractor that finds NOTHING satisfies
 * just as well as one that finds the label and approves it. Measured: `CANDIDATE_RE` replaced by
 * a regex that can never match left nine legs of this file RED and all three accept legs GREEN.
 * The accept legs are precisely the ones this repo expects to rot into decoration, and they were
 * decoration on their first run. `seen()` makes each of them state what it saw before it states
 * that it approved of it.
 */
function seen(help) {
  const labels = extractTierLabels(help);
  assert.equal(labels.length, 1,
    `the fixture's tier label was not extracted (${labels.length} found) — everything this leg `
    + 'asserts after this point would be a statement about an empty corpus');
  return labels[0].tiers;
}

describe('ACCEPT leg — a label that matches the registry is clean (all three shapes)', () => {
  it('a pro-tier capability labelled (Pro/Enterprise) is accepted', () => {
    const help = '  nsauditor-ai report --from <dir> --format executive   (Pro/Enterprise)\n';
    assert.deepEqual(seen(help), ['pro', 'enterprise']);
    assert.deepEqual(adjudicate(help, FIXTURE_COUPLINGS), []);
  });

  it('an enterprise-only capability labelled (Enterprise) is accepted', () => {
    const help = '  nsauditor-ai cloudscan --host aws   (Enterprise)\n';
    assert.deepEqual(seen(help), ['enterprise']);
    assert.deepEqual(adjudicate(help, FIXTURE_COUPLINGS), []);
  });

  it('a ce capability labelled (CE / Pro / Enterprise) is accepted, spacing and all', () => {
    const help = '  nsauditor-ai probe --host 10.0.0.1   (CE / Pro / Enterprise)\n';
    assert.deepEqual(seen(help), ['ce', 'pro', 'enterprise']);
    assert.deepEqual(adjudicate(help, FIXTURE_COUPLINGS), []);
  });

  it('non-tier parentheticals from the LIVE help are not read as labels', () => {
    // Both decoys are real strings from the shipped help text, plus one synthetic near-miss.
    const decoys = [
      '  nsauditor-ai license --plugins   grouped by source (CE / EE / custom)\n',
      '  --watch <secs>   re-scan on an interval (cron/systemd/CI)\n',
      '  nsauditor-ai version          (or --version / -v)\n',
      '  nsauditor-ai report --from <dir>   writes report_<runId>.<ext> (one per run)\n',
    ];
    for (const d of decoys) {
      assert.deepEqual(extractTierLabels(d), [],
        `a non-tier parenthetical was read as a tier label, which would turn this guard into a `
        + `false-positive machine over ordinary help prose: ${d.trim()}`);
    }
    // NEGATIVE CONTROL FOR THIS ABSENCE CLAIM. The four assertions above are all satisfied by an
    // extractor that sees nothing at all. This line is the same SHAPE as the first decoy — a
    // three-member slash-and-space group in a `license --plugins` line — differing only in that
    // its members are tiers, so it isolates the filter rather than the regex.
    assert.equal(
      extractTierLabels('  nsauditor-ai license --plugins   grouped by source (CE / Pro / Enterprise)\n').length, 1,
      'the extractor is blind, so the four decoy assertions above proved nothing');
  });
});

// ─────────────────────────────────────────────────────────────────────────────────────────────
// VETO legs — BOTH polarities, plus the unattributable case. The motivating defect is the
// underclaim; the overclaim is the direction that would otherwise go unmeasured.
// ─────────────────────────────────────────────────────────────────────────────────────────────
describe('VETO legs — a label that disagrees with the registry is rejected', () => {
  it('UNDERCLAIM — (Pro) on a pro capability hides it from every Enterprise buyer', () => {
    const help = '  nsauditor-ai report --from <dir> --format executive   (Pro)\n';
    const findings = adjudicate(help, FIXTURE_COUPLINGS);
    assert.equal(findings.length, 1, `expected exactly one finding, got: ${JSON.stringify(findings)}`);
    assert.match(findings[0], /^UNDERCLAIM: `report` is gated on `clientReporting`/);
    assert.match(findings[0], /enterprise carry the capability and are not named/);
    assert.match(findings[0], /Write \(Pro\/Enterprise\)/);
  });

  /*
   * ⚠️ THIS LEG WAS WRITTEN AS AN OVERCLAIM AND THE ADJUDICATOR REFUTED IT ON ITS FIRST RUN — the
   * refutation is kept because it is the distinction that matters. `(Enterprise)` on a pro-tier
   * capability names nothing false; it OMITS `pro`. So it is the MIRROR of the shipped defect,
   * with the Pro buyer as the victim instead of the Enterprise buyer, and it is an UNDERCLAIM in
   * exactly the same expensive direction. A label only overclaims when it NAMES a tier that does
   * not carry the flag — the `(CE/…)` leg below. Naming the two directions by who is misled,
   * rather than by which word looks bigger, is what makes the failure message actionable.
   */
  it('UNDERCLAIM MIRROR — (Enterprise) alone hides a pro capability from every Pro buyer', () => {
    const help = '  nsauditor-ai report --from <dir> --format executive   (Enterprise)\n';
    const findings = adjudicate(help, FIXTURE_COUPLINGS);
    assert.equal(findings.length, 1, `expected exactly one finding, got: ${JSON.stringify(findings)}`);
    assert.match(findings[0], /^UNDERCLAIM: `report` is gated on `clientReporting`/);
    assert.match(findings[0], /pro carry the capability and are not named/);
    assert.match(findings[0], /Write \(Pro\/Enterprise\)/);
  });

  it('MISMATCH — (CE) on a pro capability is wrong in BOTH directions at once', () => {
    const help = '  nsauditor-ai report --from <dir>   (CE)\n';
    const findings = adjudicate(help, FIXTURE_COUPLINGS);
    assert.equal(findings.length, 1, `expected exactly one finding, got: ${JSON.stringify(findings)}`);
    assert.match(findings[0], /^MISMATCH/);
    assert.match(findings[0], /pro \+ enterprise carry the capability and are not named/);
    assert.match(findings[0], /ce are named and do not carry it/);
  });

  it('OVERCLAIM — (CE/Pro/Enterprise) on a pro capability offers it to Community users', () => {
    const help = '  nsauditor-ai report --from <dir>   (CE/Pro/Enterprise)\n';
    const findings = adjudicate(help, FIXTURE_COUPLINGS);
    assert.equal(findings.length, 1, `expected exactly one finding, got: ${JSON.stringify(findings)}`);
    assert.match(findings[0], /^OVERCLAIM/);
    assert.match(findings[0], /ce are named and do not carry it/);
  });

  it('UNATTRIBUTABLE — a label whose subject cannot be derived FAILS, it never passes quietly', () => {
    const help = '  nsauditor-ai frobnicate --all   (Enterprise)\n';
    const findings = adjudicate(help, FIXTURE_COUPLINGS);
    assert.equal(findings.length, 1, `expected exactly one finding, got: ${JSON.stringify(findings)}`);
    assert.match(findings[0], /^UNATTRIBUTABLE/);
  });

  // The ambiguous branch cannot occur on today's corpus — exactly one subcommand is capability-
  // gated — so without this fixture it is a branch that reads like a guard and has never run. It
  // becomes reachable the moment a second subcommand is gated and a line mentions both.
  it('AMBIGUOUS — a label on a line naming two gated subcommands is refused, not guessed', () => {
    const help = '  see also: nsauditor-ai report and nsauditor-ai cloudscan   (Enterprise)\n';
    const findings = adjudicate(help, FIXTURE_COUPLINGS);
    assert.equal(findings.length, 1, `expected exactly one finding, got: ${JSON.stringify(findings)}`);
    assert.match(findings[0], /^AMBIGUOUS/);
    assert.match(findings[0], /report, cloudscan/);
  });
});

// ─────────────────────────────────────────────────────────────────────────────────────────────
// THE DECLARED LIMIT, DRIVEN. A printed limit is a claim about the code; these shapes are stated
// in the header as invisible, so they are exercised here in the direction that keeps the claim
// honest. If a future author widens the extractor, this test goes RED and the header gets
// rewritten — which is the point. Do not delete it to make a widening land.
// ─────────────────────────────────────────────────────────────────────────────────────────────
describe('declared limit — label shapes outside the recognised form are INVISIBLE', () => {
  it('these are not seen, and the header says so', () => {
    for (const line of [
      '  nsauditor-ai report --from <dir>   (Enterprise only)\n',
      '  nsauditor-ai report --from <dir>   (Pro tier)\n',
      '  nsauditor-ai report --from <dir>   [Pro]\n',
      '  nsauditor-ai report --from <dir>   Pro-only\n',
      '  nsauditor-ai report --from <dir>   (Pro and above)\n',
    ]) {
      assert.deepEqual(extractTierLabels(line), [],
        'the extractor now recognises a shape the header declares invisible. That is an '
        + `improvement, not a failure — update the stated residual in this file's header, then `
        + `update this fixture: ${line.trim()}`);
    }
    // NEGATIVE CONTROL, same reason as the decoy leg: a declared limit asserted only by absence
    // is indistinguishable from an extractor that has stopped working.
    assert.equal(extractTierLabels('  nsauditor-ai report --from <dir>   (Pro)\n').length, 1,
      'the extractor is blind, so the invisibility claims above proved nothing');
  });
});

// ─────────────────────────────────────────────────────────────────────────────────────────────
// THE DERIVATION ITSELF must stay live. A coupling regex that stops matching turns every leg
// below it into a clean run over an empty corpus.
// ─────────────────────────────────────────────────────────────────────────────────────────────
describe('the subcommand → capability coupling is derived from cli.mjs and is live', () => {
  it('at least one gated subcommand is derived, and every derived capability is a real flag', () => {
    const couplings = gatedSubcommands(SRC);
    assert.ok(couplings.size >= 1,
      'no capability-gated subcommand was derived from cli.mjs. Either the refusal idiom changed '
      + '(`if (!hasCapability(caps, \'<cap>\')) { logErr(\'`<sub>`…`) — re-point this derivation, '
      + 'do not delete it) or nothing is gated any more. Until it is fixed, every label in the '
      + 'help is unadjudicable and this guard measures nothing.');
    for (const [sub, cap] of couplings) {
      assert.ok(Object.hasOwn(CAPABILITIES, cap),
        `\`${sub}\` is gated on \`${cap}\`, which is not a flag in the capability registry — a `
        + 'typo here would make every tier for it read as "carries nothing"');
    }
  });

  it('LIVENESS CANARY — `report` is still gated on clientReporting', () => {
    // Named explicitly, in the register of this repo's other derivation canaries: it is the one
    // coupling that exists today, so if it stops being derived the corpus is empty and every
    // other leg passes over nothing.
    assert.equal(gatedSubcommands(SRC).get('report'), 'clientReporting');
  });
});

// ─────────────────────────────────────────────────────────────────────────────────────────────
// THE LIVE LEGS — driven through the real CLI.
// ─────────────────────────────────────────────────────────────────────────────────────────────
describe('the rendered help is tier-INDEPENDENT, so no label can be a property of the keychain', () => {
  it('an expired-pro, a valid-pro and a valid-enterprise key render byte-identical help', () => {
    const ce = renderHelp(EXPIRED_KEY);
    const pro = renderHelp(PRO_KEY);
    const ent = renderHelp(ENTERPRISE_KEY);
    assert.equal(ce, pro, 'help output differs between an unlicensed and a Pro run');
    assert.equal(pro, ent, 'help output differs between a Pro and an Enterprise run');
    // Non-vacuity: three identical EMPTY strings would satisfy the equalities above.
    assert.ok(ce.includes('nsauditor-ai report --from'),
      'the help output does not contain the report synopsis — the equality above was compared over '
      + 'the wrong text');
    assert.ok(extractTierLabels(ce).length > 0,
      'the help carries no tier label at all under any tier, so the identity proves nothing about '
      + 'labels');
  });
});

describe('every tier label in `nsauditor-ai help` names exactly the tiers that carry it', () => {
  it('LIVENESS — the extractor finds labels in the real help (a clean run over none is not clean)', () => {
    const labels = extractTierLabels(renderHelp(ENTERPRISE_KEY));
    assert.ok(labels.length >= 2,
      `only ${labels.length} tier label(s) were extracted from the rendered help. Two were measured `
      + 'when this guard was written (the `report` synopsis and its section header). Fewer means the '
      + 'extractor has gone blind, and a blind extractor reports every help text as clean.');
    for (const l of labels) {
      assert.ok(/report/i.test(l.line),
        `a tier label was found on a line this guard did not expect: "${l.line.trim()}" — that is `
        + 'not necessarily wrong, but read it before widening anything');
    }
  });

  it('NO LABEL DISAGREES WITH THE CAPABILITY REGISTRY', () => {
    const findings = adjudicate(renderHelp(ENTERPRISE_KEY), gatedSubcommands(SRC));
    assert.deepEqual(findings, [],
      `tier label(s) in the help disagree with the capability registry:\n  - ${findings.join('\n  - ')}`);
  });
});
