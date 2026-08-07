// tests/framework_stem_parity.test.mjs
//
// ── WHAT THIS HOLDS ──────────────────────────────────────────────────────────────
// EE owns the compliance-framework set twice over: as a declaration
// (`utils/framework_ids.mjs` → `FRAMEWORK_STEMS`) and as DATA (`data/compliance/<stem>.json`,
// the files the compliance_matrix handler actually reads). CE names that same set on surfaces a
// customer and a MODEL both act on. Before this file, CE TRANSCRIBED it at four sites — the
// compliance_matrix inputSchema enum, the handler's validation list, this suite's own `STEMS`
// copy, and the tool DESCRIPTION — and nothing compared any of them to EE or to the data.
//
// The description is the one that matters most and is the one no schema validates: an assistant
// picks its `framework` token by READING it. A stale list there does not error — it silently
// steers tool selection, which is the same class as the phantom tool names EE's
// tests/agent_skill_tool_surface.test.mjs was written for (a claim that exists only as an
// IDENTIFIER, invisible to every prose sweep).
//
// ── WHY CE CANNOT SIMPLY IMPORT EE'S LIST AT MODULE LOAD ─────────────────────────
// `@nsasoft/nsauditor-ai-ee/utils/framework_ids.mjs` IS exported and resolvable (measured), but
// EE is not a CE dependency at all — CE must load and serve its tool registry with EE absent.
// `TOOLS` is built at module load, so importing EE there would make the REGISTRY itself
// conditional on an optional package. Hence: one CE-side constant, held in two-way equality with
// EE here, at test time, where the dependency is allowed to be hard.
//
// ── AND WHY THIS FILE FAILS, NEVER SKIPS, WHEN EE IS UNRESOLVABLE ────────────────
// "A gate that can skip itself is not a gate" (tasks/CLAUDE.md, the network-scan live-target
// gate). A cross-repo guard that turns itself off in the one environment where the two repos
// are NOT side by side is a guard that reports green precisely when it measured nothing —
// absent evidence read as evidence of absence. EE's own location-dependent cross-repo guard
// (tests/agent_skill_tool_surface.test.mjs) takes the same position, and this file follows it:
// an unresolvable EE is a FAILING test with a message that says how to restore the measurement.
//
// ── STATED SCOPE LIMIT, so a green here is not read as more than it is ───────────
// This guards the SET. It does not guard the per-framework PROSE that sits beside it: the
// compliance_matrix description also carries the GDPR scoping doctrine ("…Article 32
// security-of-processing substrate ONLY, never 'GDPR compliance'"), which is a legal hedge
// keyed to one stem. If gdpr were ever withdrawn, the list legs below go RED and that sentence
// would not. A conditional leg for it would be unfalsifiable today — an assertion that cannot
// fire reads exactly like one that passes — so the limit is stated here instead. Add the leg
// the day a framework is actually removed; that is when it becomes measurable.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createRequire } from 'node:module';
import { FRAMEWORK_STEMS as CE_STEMS, TOOLS } from '../mcp_server.mjs';

const _require = createRequire(import.meta.url);

// `data/compliance/` also ships non-framework JSON. These are NOT frameworks and must never
// appear in a `--compliance` token list: `sla` is an SLA/MTTR policy, `identity_registry` is a
// principal registry. Keeping the exclusion EXPLICIT (rather than filtering by shape) means a
// NEW non-framework file lands as a RED census here — a deliberate decision to exclude it,
// recorded in a diff — instead of being silently absorbed by a heuristic.
const NON_FRAMEWORK_STEMS = ['sla', 'identity_registry'];

/** Resolve EE, or FAIL with the reason and the repair — never skip. */
function eeRootOrFail() {
  try {
    return path.dirname(_require.resolve('@nsasoft/nsauditor-ai-ee/package.json'));
  } catch (err) {
    assert.fail(
      '@nsasoft/nsauditor-ai-ee is not resolvable from this CE checkout, so the framework-set ' +
      'parity between CE and EE COULD NOT BE MEASURED. This is a FAILURE, not a skip: CE\'s ' +
      'compliance_matrix enum, its tool description and its handler list all name EE\'s ' +
      'framework set, and an unmeasured green here is exactly how a stale list ships. ' +
      `Install or link EE (npm i @nsasoft/nsauditor-ai-ee) and re-run. Underlying: ${err && err.message}`,
    );
  }
}

/** EE's DECLARED set — the authority `--compliance` token validation is derived from. */
async function eeDeclaredStems() {
  try {
    const mod = await import('@nsasoft/nsauditor-ai-ee/utils/framework_ids.mjs');
    assert.ok(Array.isArray(mod.FRAMEWORK_STEMS),
      'EE exports utils/framework_ids.mjs but not FRAMEWORK_STEMS — the authority this file ' +
      'compares against has moved, and until this pointer is repaired CE\'s list is unguarded');
    return mod.FRAMEWORK_STEMS;
  } catch (err) {
    if (err && err.code === 'ERR_ASSERTION') throw err;
    assert.fail(
      'EE\'s utils/framework_ids.mjs could not be imported, so CE\'s framework set was compared ' +
      'against NOTHING. Failing rather than skipping — see this file\'s header. ' +
      `Underlying: ${err && err.message}`,
    );
  }
}

/** EE's SHIPPED set — the census of the files the handler actually opens. */
function eeCensusStems(eeRoot) {
  const dir = path.join(eeRoot, 'data', 'compliance');
  const entries = fs.readdirSync(dir)
    .filter((f) => f.endsWith('.json'))
    .map((f) => f.slice(0, -'.json'.length))
    .filter((s) => !NON_FRAMEWORK_STEMS.includes(s));
  assert.ok(entries.length > 0,
    `${dir} yielded zero framework JSON files — a census of nothing compares equal to nothing ` +
    'and would make every leg below vacuously green');
  return entries;
}

/** Order-insensitive set equality. Reordering the pickup order is legal; membership is not. */
function assertSameSet(actual, expected, what) {
  assert.deepEqual([...actual].sort(), [...expected].sort(), what);
}

test('the CE-side framework constant is exported and non-vacuous', () => {
  // Liveness before comparison: if CE_STEMS were undefined or empty, every set-equality below
  // would be comparing an absence against an absence for two of the three authorities.
  assert.ok(Array.isArray(CE_STEMS),
    'mcp_server.mjs must EXPORT one FRAMEWORK_STEMS array — with no single CE-side name for the ' +
    'set, the enum, the description and the handler each go on carrying their own copy');
  // NOT `>= 7`. A hard-coded floor here would be one more transcribed count of exactly the kind
  // this file exists to abolish, and it would read stale the day an eighth framework ships.
  // Non-vacuity is all this leg owes; MEMBERSHIP is the equality legs' job, and they derive it.
  assert.ok(CE_STEMS.length > 0,
    'CE\'s FRAMEWORK_STEMS is empty — every set-equality below would then be comparing an ' +
    'absence against an absence and reporting green');
  assert.ok(Object.isFrozen(CE_STEMS),
    'the set must be frozen — a mutable module-level array is one stray push away from a tool ' +
    'schema that disagrees with the handler that validates against it');
});

test('CE\'s framework set equals EE\'s DECLARED set, in both directions', async () => {
  const ee = await eeDeclaredStems();
  // Liveness of the AUTHORITY, before the comparison that leans on it: an equality that ends up
  // comparing CE_STEMS to CE_STEMS passes forever and reads identically to this one.
  assert.notStrictEqual(ee, CE_STEMS,
    'the "EE" side is the very array CE exports — this leg would be comparing CE to itself');
  assert.match(_require.resolve('@nsasoft/nsauditor-ai-ee/utils/framework_ids.mjs'),
    /nsauditor-ai-ee[/\\]utils[/\\]framework_ids\.mjs$/,
    'the EE authority resolved somewhere other than EE\'s own utils/framework_ids.mjs');
  // Both directions are different failures: CE missing a stem makes a shipped framework
  // unreachable through the MCP tool; CE carrying an extra stem advertises a framework whose
  // JSON does not exist, which the handler discovers only at call time, as a runtime error.
  assertSameSet(CE_STEMS, ee,
    'CE\'s FRAMEWORK_STEMS and EE\'s utils/framework_ids.mjs FRAMEWORK_STEMS disagree — one of ' +
    'the two repos shipped a framework the other does not know about');
});

test('CE\'s framework set equals the on-disk data/compliance census, in both directions', () => {
  const census = eeCensusStems(eeRootOrFail());
  // The census is the harder authority: EE's declaration could itself be stale. compliance_matrix
  // opens `data/compliance/<stem>.json` per stem, so a stem with no file is a tool that errors on
  // a value its OWN schema advertises, and a file with no stem is a shipped framework no MCP
  // caller can ask for.
  assertSameSet(CE_STEMS, census,
    'CE\'s FRAMEWORK_STEMS and the shipped data/compliance/*.json census disagree — either the ' +
    'MCP surface advertises a framework that has no map, or a shipped framework map is ' +
    'unreachable through the MCP surface');
});

test('the compliance_matrix ENUM names exactly the shipped census plus "all"', () => {
  const census = eeCensusStems(eeRootOrFail());
  const tool = TOOLS.find((t) => t.name === 'compliance_matrix');
  assert.ok(tool, 'compliance_matrix is missing from TOOLS');
  // ⚠️ COMPARED AGAINST THE CENSUS, NOT AGAINST CE_STEMS. Now that the enum is DERIVED from
  // CE_STEMS, an enum-vs-CE_STEMS assertion is a tautology that can never fail while reading
  // exactly like a passing check. The census is the independent authority that keeps it live.
  assertSameSet(tool.inputSchema.properties.framework.enum, [...census, 'all'],
    'the compliance_matrix framework enum does not match the shipped framework maps — a ' +
    'schema-rejected token is a framework a customer cannot ask for');
});

test('the compliance_matrix DESCRIPTION names exactly the shipped census', () => {
  const census = eeCensusStems(eeRootOrFail());
  const tool = TOOLS.find((t) => t.name === 'compliance_matrix');
  const m = /Frameworks:\s*([^.]+?),\s*or "all"/.exec(tool.description);
  assert.ok(m,
    'the description no longer names its framework list in the parsed `Frameworks: a, b, …, or ' +
    '"all"` shape, so this leg measured nothing. The description is what a model reads to CHOOSE ' +
    'a token; keep the shape or move this parser in the same commit');
  const named = m[1].split(',').map((s) => s.trim());
  assertSameSet(named, census,
    'the tool description names a different framework set than the one that ships — unlike the ' +
    'enum, a stale list here does not error: it silently steers tool selection');
});

test('the enum + description carry NO spelled-out framework count', () => {
  // `across all seven` was a transcribed count sitting beside a transcribed list. A count in a
  // COMPLETENESS claim rots on the next framework cycle and cannot be derived by a reader; the
  // mechanism (the constant's own length) can. This forbids the word form on this one tool only.
  const tool = TOOLS.find((t) => t.name === 'compliance_matrix');
  const texts = [tool.description, ...Object.values(tool.inputSchema.properties).map((p) => p.description || '')];
  for (const t of texts) {
    // Match FIRST, then assert. Building the message inline threw a TypeError on the first
    // text that did NOT match — a failure that names nothing and would have hidden which text
    // actually carries the count.
    const hit = /\b(five|six|seven|eight|nine)\b/i.exec(t);
    assert.equal(hit, null,
      `compliance_matrix text spells out a framework count ("${hit && hit[0]}") beside a list it ` +
      'must agree with — derive it from FRAMEWORK_STEMS.length so the next framework cycle ' +
      `cannot leave it stale. Offending text: ${JSON.stringify(t.slice(0, 120))}`);
  }
});

test('the CENSUS is read from the directory it is GIVEN — a dropped framework map goes RED', () => {
  // ── THE "dropped framework map" MUTANT, RUN ON EVERY PASS INSTEAD OF BY HAND ──
  // The census leg above passes over the real EE root. A reader that returned a hard-coded list
  // (or that read the wrong directory) would pass it identically. This builds a root that is the
  // real one MINUS one framework file, plus both non-framework files, and requires the reader to
  // report THAT root — the same discriminating shape as compliance_matrix_tool.test.mjs's
  // "a constant cannot pass". Done as a fixture rather than by deleting a shipped EE file,
  // because the EE working tree is not this lane's to disturb.
  const real = eeCensusStems(eeRootOrFail());
  const dropped = real[real.length - 1];
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ee-census-'));
  const dir = path.join(root, 'data', 'compliance');
  fs.mkdirSync(dir, { recursive: true });
  for (const stem of real) if (stem !== dropped) fs.writeFileSync(path.join(dir, `${stem}.json`), '{}');
  // Both non-framework files present, and a subdirectory (data/compliance/connectors/ is real):
  // a census that counted either would silently invent frameworks nobody ships.
  for (const nf of NON_FRAMEWORK_STEMS) fs.writeFileSync(path.join(dir, `${nf}.json`), '{}');
  fs.mkdirSync(path.join(dir, 'connectors'), { recursive: true });

  const census = eeCensusStems(root);
  assert.ok(!census.includes(dropped),
    `the census still reports '${dropped}' after its map was removed — it is not reading the ` +
    'directory it was given, so the real leg above measured nothing');
  for (const nf of NON_FRAMEWORK_STEMS) {
    assert.ok(!census.includes(nf), `'${nf}' is not a framework and must never reach a --compliance token list`);
  }
  assert.ok(!census.includes('connectors'), 'a SUBDIRECTORY was counted as a framework map');
  assert.throws(() => assertSameSet(CE_STEMS, census, 'probe'), /probe/,
    'CE\'s advertised set matched a census with a framework map missing — the census leg is dead');
});

test('NEGATIVE CONTROL — the comparator and the description parser both discriminate', () => {
  // Everything above is an equality that PASSES. A passing equality proves nothing unless the
  // machinery underneath it can fail: `assertSameSet` over two identical inputs and a parser that
  // returns the census by construction would both read exactly like this suite reading green.
  const census = eeCensusStems(eeRootOrFail());
  assert.throws(() => assertSameSet(census, [...census, 'sox'], 'probe'),
    /probe/, 'assertSameSet accepted a set with an extra member — the equality legs above are dead');
  assert.throws(() => assertSameSet(census, census.slice(1), 'probe'),
    /probe/, 'assertSameSet accepted a set missing a member — the equality legs above are dead');

  // The parser is exercised on a string it did not come from, with a list that is NOT the census.
  const probe = 'Frameworks: aaa, bbb, or "all" for the counts.';
  const parsed = /Frameworks:\s*([^.]+?),\s*or "all"/.exec(probe)[1].split(',').map((s) => s.trim());
  assert.deepEqual(parsed, ['aaa', 'bbb'],
    'the description parser does not actually read its input, so the description leg is decoration');
  // …and 'sox' is in none of the three authorities, so the guard is not a blanket accept.
  assert.ok(!CE_STEMS.includes('sox') && !census.includes('sox'),
    'a token that is not a shipped framework was reported as one');
});
