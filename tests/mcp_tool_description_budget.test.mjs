/**
 * A TOOL DESCRIPTION THAT DOES NOT FIT IS SILENTLY TRUNCATED, AND THE TAIL IS WHERE HEDGES LIVE.
 *
 * ── WHY THIS EXISTS ──────────────────────────────────────────────────────────────────────────
 * Found by Gate 3 at the 0.39.0 pre-release, by the only method that can find it: an operator ran
 * the prompts in Claude Desktop and the model reported that `scan_cloud`'s description **cut off
 * mid-word** at "a stat…". Measured: the description was 3,024 characters and the cut fell on
 * character 2,048 exactly. **976 characters — 32% — never reached the model.**
 *
 * The lost tail was not filler. It held every sentence that makes an empty `deferredScope` safe to
 * read: "a static capability boundary, NOT an evidence gap and NOT a finding" · "AN EMPTY OR SHORT
 * deferredScope IS NOT A CLAIM OF FULL COVERAGE" · "Not every plugin declares its capability
 * boundaries" — which is the exact sentence CE 0.2.44 was published to deliver — and the INFO-tier
 * rule. The release's own headline was 32% undelivered on the client its acceptance gate runs on.
 *
 * ⚠️ THE GATE PASSED ANYWAY, AND THAT IS THE INSTRUCTIVE PART. Prompts P1-P3 all showed the model
 * applying the invariant correctly, because the agent-skill was ALSO teaching it. Behaviour was
 * double-sourced, so testing behaviour could not see the missing half. An agent running the MCP
 * server WITHOUT the skill would have had nothing.
 *
 * ── WHY THIS GUARD IS NOT A LENGTH LIMIT ─────────────────────────────────────────────────────
 * There is no protocol limit to guard against: MCP deliberately specifies none, and client bounds
 * are heterogeneous — OpenAI-compatible clients enforce ~1024 on tool descriptions, Claude Desktop
 * ~2048 (measured above), Amazon Q ~10004, and Claude Code delivers well over 2048 intact. Writing
 * to any single measured boundary is writing to one client. The agent-skill README advertises
 * Cursor and Windsurf, which commonly front OpenAI models, so "just under 2048" still loses its
 * tail at 1024.
 *
 * So ORDER is the fix and BUDGET is only the belt. A description that leads with its hedges
 * degrades gracefully under EVERY bound, known or unmeasured: truncation can then cost mechanics,
 * never honesty. That is this repo's own recorded rule — COMPRESSION IS WHERE HEDGES DIE — applied
 * to compression by transport, which eats the END.
 *
 * ⚠️ THE BUDGET IS 2048, NOT 1024, AND THE REASON IS A CONFLICT WORTH RECORDING.
 * The first fix here cut the description to 1,012 chars — under the OpenAI-compatible bound — by
 * deleting its service enumeration. That broke six assertions in
 * `mcp_scan_cloud_tool_description.test.mjs`, and reading WHY is the point: that enumeration was
 * added because an EARLIER Desktop gate (0.19.2, prompt #4) proved a generic description LOSES
 * service-named asks — "audit my CodePipelines for segregation of duties" never invoked the tool and
 * the agent offered a manual bash workaround. Deleting it would have reintroduced a field-proven
 * defect to fix a different one: a later fix disarming an earlier guard, which this repo names.
 *
 * So both requirements are real and they do not both fit under 1024. The tie is broken on WHICH LOSS
 * IS SILENT: losing the routing surface is LOUD — the tool is not selected, the user sees no scan and
 * says so. Losing the honesty invariant is SILENT — the tool runs, produces output, and an empty
 * deferredScope gets reported as full coverage. So honesty leads, routing follows, and the budget is
 * the bound of the client this product's acceptance gate actually runs on.
 * ⚠️ AND UNDER LOUD-VS-SILENT THERE IS A CATEGORICAL AXIS — ATTRIBUTION — which is why the ranking
 * would not flip even if someone showed the routing loss to be quieter than we think.
 * Losing ROUTING means the product is never invoked: whatever the agent improvises instead is
 * visibly NOT the product's artifact — no evidence pack, no framework routing, nothing signed — so
 * the failure is a lost capability that cannot be mistaken for the product's word.
 * Losing HONESTY means the product's OWN output is misread as claiming full coverage: an
 * ATTRIBUTABLE FALSE ATTESTATION, the cardinal class this entire repo is built against.
 * Loud-vs-silent is the symptom; whose-output-misleads is the mechanism. (Axis contributed by the
 * reviewing seat that ruled on this fold.)
 *
 * ⚠️ RESIDUAL, boarded rather than hidden: under a ~1024 client (OpenAI-fronted, which the
 * agent-skill README advertises via Cursor/Windsurf) the ROUTING half is lost while all three
 * reading rules survive. That is the intended degradation, not an oversight.
 *
 * ⚠️ THE ORDER LEG IS THE ONE THAT MATTERS, AND WITHOUT IT THE BUDGET LEG IS A TRAP: a future edit
 * could shrink a description under budget while moving the hedge to the tail, and stay green while
 * reintroducing the exact defect. Both legs, or neither is worth having.
 *
 * ⚠️ THE SERVER CANNOT DETECT THIS ITSELF. `tools/list` is fire-and-forget; MCP gives a server no
 * channel by which a client reports what it actually rendered. Emission is the only place it can be
 * defended, which is why this is a build-time guard and not a runtime warning.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const src = readFileSync(join(ROOT, 'mcp_server.mjs'), 'utf8');

/**
 * The budget is the SMALLEST bound observed across clients this product advertises support for,
 * not the one that bit us. 2048 is Claude Desktop's; ~1024 is the OpenAI-compatible bound, and the
 * agent-skill README names Cursor and Windsurf. Guard the tighter one.
 */
const BUDGET = 2048;
/** Where a load-bearing hedge must appear by, so it survives even an unmeasured bound. */
const HEDGE_BY = 700;

function descriptions() {
  const re = /name:\s*'([a-z_]+)',\s*\n\s*description:\s*\n?\s*'([\s\S]*?)',\s*\n\s*inputSchema/g;
  const out = [...src.matchAll(re)].map((m) => ({ name: m[1], text: m[2] }));
  assert.ok(out.length >= 5,
    `only ${out.length} tool description(s) parsed — the extraction regex has stopped matching and `
    + 'this guard is measuring nothing');
  return out;
}

describe('MCP tool descriptions survive client truncation without losing their hedges', () => {
  it('BUDGET — no description exceeds the tightest advertised client bound', () => {
    /*
     * ⚠️ MEASURED IN EVERY UNIT A CLIENT MIGHT COUNT IN, because a guard that counts differently
     * from the client it models drifts by exactly the characters where the units disagree.
     * The observed 2048 was in JS string units (UTF-16 code units — the `indexOf` arithmetic that
     * located it), which `.length` also uses, so those agree by construction. But a client counting
     * UTF-8 BYTES sees a longer string: today 1,990 bytes against 1,978 units, a 12-unit gap that
     * is entirely the two ⚠️ sequences. Add one astral emoji (🔎, 🚨 — outside the BMP) and
     * codepoints, code units and bytes all diverge at once. So all three are checked: whichever
     * unit a client actually counts in, the budget holds.  [unit hazard raised at review]
     */
    const over = descriptions()
      .flatMap((d) => {
        const units = d.text.length;                        // UTF-16 code units — the observed bound
        const points = [...d.text].length;                  // codepoints
        const bytes = Buffer.byteLength(d.text, 'utf8');    // a byte-counting client
        return Math.max(units, points, bytes) > BUDGET
          ? [`${d.name} (units ${units}, codepoints ${points}, bytes ${bytes}; over by `
             + `${Math.max(units, points, bytes) - BUDGET})`]
          : [];
      });
    assert.deepEqual(over, [],
      `description(s) over the ${BUDGET}-char budget: ${over.join(', ')}. This is not a style rule: `
      + 'a client that truncates drops the TAIL, and the tail is where the hedges are. Shorten by '
      + 'moving mechanics into SKILL.md or the README, which are not length-bound — never by '
      + 'deleting an invariant.');
  });

  it('ORDER — scan_cloud states the coverage invariant before any plausible fold', () => {
    const d = descriptions().find((x) => x.name === 'scan_cloud');
    assert.ok(d, 'scan_cloud is gone — re-point this guard rather than deleting it');
    const head = d.text.slice(0, HEDGE_BY);
    for (const [label, needle] of [
      ['deferredScope is a static boundary', 'STATIC CAPABILITY BOUNDARY'],
      ['an empty list is never full coverage', 'IS NOT A CLAIM OF FULL COVERAGE'],
    ]) {
      assert.ok(head.includes(needle),
        `"${label}" does not appear in the first ${HEDGE_BY} chars of scan_cloud's description. `
        + 'Under truncation the model would receive the tool WITHOUT it, which is the 0.39.0 '
        + 'Gate-3 defect exactly. Lead with the hedge; the mechanics can be lost harmlessly.');
    }
  });

  it('the invariants survive BOTH known client bounds, not just the one that bit us', () => {
    const d = descriptions().find((x) => x.name === 'scan_cloud');
    for (const bound of [1024, 2048]) {
      const head = d.text.slice(0, bound);
      assert.match(head, /IS NOT A CLAIM OF FULL COVERAGE/,
        `truncated at ${bound} chars, scan_cloud's description loses the coverage invariant. `
        + '1024 is the OpenAI-compatible bound and 2048 is Claude Desktop\'s; the agent-skill '
        + 'README advertises clients in both families.');
    }
  });
});
