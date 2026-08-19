/**
 * A VERB THE CLI DISPATCHES MUST BE A VERB THE CLI'S OWN HELP ADVERTISES.
 *
 * ── WHY THIS EXISTS ──────────────────────────────────────────────────────────────────────────
 * `compliance sign-pack` and `compliance verify-pack` shipped in CE 0.2.43 / EE 0.38.0 as that
 * release's HEADLINE capability — evidence-pack authorship signing, the thing the whole cycle was
 * named after. They dispatched correctly, they were documented in the README, the CHANGELOG, the
 * press release, the architecture record and the contract. They were **absent from
 * `nsauditor-ai help`** for the entire release.
 *
 * Nothing was red. Reachability guards ask "can a customer REACH this?" and the answer was yes.
 * Nobody asked "can a customer FIND this?" — and a capability a user cannot discover from the
 * tool's own help is, for most users, a capability that does not exist. It was found on
 * 2026-08-19 by a release seat running `nsauditor-ai help | grep -oE "compliance [a-z-]+"` while
 * looking for the usage string of a command it already knew was there.
 *
 * ── WHAT IT CHECKS, AND WHY IT IS DERIVED RATHER THAN LISTED ─────────────────────────────────
 * The verb set is parsed out of the DISPATCH SITE, not hand-written here. A hand-written list is
 * a second copy of the thing it guards: it would have to be updated by the same commit that
 * forgets to update the help, so it would go stale in exactly the case it exists to catch.
 *
 * ── THE FOURTH QUADRANT ──────────────────────────────────────────────────────────────────────
 * The found defect is "dispatched but undocumented", so the leg written FIRST is the other
 * direction — "documented but not dispatched", a phantom command, which is the worse failure
 * because a user follows it and gets an error. Both legs are asserted; the phantom leg is the one
 * that would otherwise rot into decoration, because every incident so far has been the first kind.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { execFileSync } from 'node:child_process';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const CLI = join(ROOT, 'cli.mjs');
const src = readFileSync(CLI, 'utf8');

/**
 * Return exactly the `if (cmd === 'compliance') { … }` block by BRACE MATCHING from its opening
 * brace, rather than by a guessed character budget.
 */
function complianceBlock(src, start) {
  const open = src.indexOf('{', start);
  assert.ok(open > 0, 'the compliance dispatch block has no opening brace — re-point this guard');
  let depth = 0;
  for (let i = open; i < src.length; i += 1) {
    const ch = src[i];
    if (ch === '{') depth += 1;
    else if (ch === '}') {
      depth -= 1;
      if (depth === 0) {
        const body = src.slice(start, i + 1);
        // COVERAGE BY COMPOSITION, NOT BY ANCHOR POSITION. This canary's anchor (the pack-signing
        // dispatch) is not the block's terminal idiom, and does not need to be. An early termination
        // BEFORE the anchor fails THIS assertion. An early termination AFTER it (between sign-pack and
        // attest) drops `attest` from the derived set while help still advertises it, so the PHANTOM
        // leg fails instead. Every truncation window is loud through one leg or another — the property
        // belongs to the legs' composition, and this comment records which leg owns which window.
        // Probed 2026-08-19 by an independent seat: an unbalanced `}` injected into a string before the
        // anchor → canary RED; the between-window is covered by the phantom leg by the argument above.
        assert.match(body, /sub === 'verify-pack'|sub === 'sign-pack'/,
          'the captured compliance block does not contain the pack-signing dispatch — the brace '
          + 'match ended early, so the verb set is a PREFIX and this guard would report a '
          + 'dispatched verb as absent. Fix the capture, do not widen the assertion.');

        /*
         * ⚠️ THE COMPOSITION'S ONE RESIDUAL, CLOSED BY MEASUREMENT — AND IT TOOK TWO SEATS.
         *
         * The reviewing seat identified it exactly: a verb added BEYOND the captured range, in the
         * same commit that also omits its help entry, is silent — the phantom leg only fires for
         * dropped verbs help still lists, and a brand-new verb never entered either set. Their
         * proposed fix was a maintenance rule (re-anchor the canary when a verb joins the tail). It
         * is a correct rule, and it is the kind this repo has watched rot: it depends on the next
         * author remembering, and its failure is silent. So it is replaced by the assertion below.
         *
         * ⚠️ THE ASSERTION WAS UNPROVEN FOR THREE ROUNDS, AND HOW IT WAS FINALLY PROVEN IS THE
         * DURABLE PART. Three mutants chosen by POSITION each went RED through a DIFFERENT
         * pre-existing leg — canary, phantom, discoverability — and never reached this one; I
         * labelled it UNPROVEN rather than let its presence imply verification. The reviewing seat
         * then supplied the mechanism: a stray `}` inside a string decrements the naive depth
         * counter by one, so the capture closes one brace EARLY **relative to the true end, at a
         * location determined by the nesting depth at the injection point — not by the injection
         * point itself.** Choosing the injection by DEPTH instead of position isolates this leg on
         * the first try: injected at depth 1 (block level) after the `attest` idiom, with a planted
         * verb immediately beyond it, ONLY this assertion fires.
         *
         * The lesson is not about braces. A mutant that fails to reach its target does not license
         * "the guard is untestable" — it means the mutant was selected on the wrong variable.
         *
         * The check itself: if the brace match ends early, the TRUE remainder of the block sits
         * immediately after the capture and still contains `sub === '…'` idioms, which nothing
         * outside a command block does. It needs no re-anchoring, so it cannot trail the block's
         * growth — which is why it retires the maintenance rule rather than restating it.
         *
         * ── THE COMPLETE COVERAGE MAP: THREE WINDOWS, THREE OWNERS, ALL MEASURED ──────────────
         * Recorded so the composition is auditable rather than asserted, and so nobody deletes a
         * leg believing another one covers its window.
         *
         *   truncation BEFORE the pack-signing anchor        → CANARY (this assertion's sibling)
         *   truncation BETWEEN the last `===` idiom and the
         *     `!==` rejection                                → PHANTOM leg (attest drops from the
         *                                                      derived set while help still lists it)
         *   a verb planted BEYOND the capture                → ORPHAN-TAIL (this assertion)
         *
         * ⚠️ THE BETWEEN-WINDOW IS NOT THIS ASSERTION'S, AND THE REASON IS A REAL BLIND SPOT WORTH
         * WRITING DOWN: the regex below models `sub === '…'` only, while the DERIVATION models both
         * polarities. A tail orphaned in that window contains no `===` match at all, so this leg
         * sees nothing there. It is covered — by the phantom leg — but by a different leg for a
         * different reason, which is exactly the kind of thing that gets lost when a coverage claim
         * is stated as "the legs cover it" instead of naming which leg owns which case.
         *
         * ⚠️ READING A RED RUN: three test cases share this derivation, so a capture defect fails
         * THREE cases through this one assertion. That is isolation at the ASSERTION level, which is
         * what proof requires — do not read three red cases as three independent findings.
         */
        const after = src.slice(i + 1, i + 1 + 20000);
        const nextCmd = after.search(/if \(cmd === '/);
        const tail = nextCmd === -1 ? after : after.slice(0, nextCmd);
        const orphan = [...tail.matchAll(/sub === '([a-z-]+)'/g)].map((m) => m[1]);
        assert.deepEqual(orphan, [],
          `dispatch idiom(s) for ${orphan.join(', ')} sit AFTER the captured compliance block and `
          + 'before the next command block. The brace match terminated early, so the derived verb '
          + 'set is a prefix — and a verb in that tail whose help entry is also missing would be '
          + 'invisible to every other leg. Fix the capture.');
        return body;
      }
    }
  }
  assert.fail('unbalanced braces from the compliance dispatch site — capture is unreliable');
}

/** The verbs the `compliance` command actually dispatches, DERIVED from the dispatch site. */
function dispatchedComplianceVerbs() {
  const start = src.indexOf("if (cmd === 'compliance')");
  assert.ok(start > 0, 'the compliance dispatch block moved — re-point this guard rather than deleting it');
  /*
   * ⚠️ THE SLICE BOUND WAS A LATENT FALSE CLEAN, AND AN INDEPENDENT REVIEWER HAD THE REPRODUCER.
   * A fixed `start + 40000` window silently drops any dispatch idiom past it: pad the compliance
   * block by ~31k and delete a verb from help, and ALL THREE legs pass while a dispatched verb is
   * invisible — precisely the defect class this guard exists for. Headroom was 29,372 chars, so it
   * was latent rather than live, which is exactly how it would have survived to bite later.
   *
   * Fixed two ways, because either alone can rot: the window is now derived by brace-matching the
   * block, and a CANARY asserts the captured text still ends with the block's terminal idiom. A
   * bound that is computed can still be wrong; a bound that is computed AND checked announces it.
   */
  const body = complianceBlock(src, start);
  // ⚠️ BOTH POLARITIES, and the second one cost this guard a false positive on its first run.
  // `attest` is dispatched by a NEGATIVE test — `if (sub !== 'attest') { …reject… }` — so an
  // equality-only parse reported the product's oldest compliance verb as a phantom. A derivation
  // that models one idiom reports on that idiom, not on the code.
  const verbs = new Set([
    ...[...body.matchAll(/sub === '([a-z-]+)'/g)].map((m) => m[1]),
    ...[...body.matchAll(/sub !== '([a-z-]+)'/g)].map((m) => m[1]),
  ]);
  // Liveness: this repo dispatches many compliance verbs. One or zero means the parse died.
  assert.ok(verbs.size >= 5,
    `the dispatch parse found ${verbs.size} verb(s) — the regex has stopped matching and this `
    + 'guard is measuring nothing');
  return verbs;
}

/** The verbs `nsauditor-ai help` advertises. Driven through the REAL CLI, never re-parsed. */
function advertisedComplianceVerbs() {
  const out = execFileSync(process.execPath, [CLI, 'help'], { encoding: 'utf8' });
  const verbs = new Set([...out.matchAll(/nsauditor-ai compliance ([a-z-]+)/g)].map((m) => m[1]));
  assert.ok(out.length > 2000, 'help output is implausibly short — the CLI did not print its help');
  return verbs;
}

describe('CLI help advertises exactly the compliance verbs the CLI dispatches', () => {
  it('PHANTOM LEG — help never advertises a verb that does not dispatch', () => {
    const dispatched = dispatchedComplianceVerbs();
    const advertised = advertisedComplianceVerbs();
    const phantom = [...advertised].filter((v) => !dispatched.has(v));
    assert.deepEqual(phantom, [],
      `help advertises compliance verb(s) that nothing dispatches: ${phantom.join(', ')}. A user `
      + 'who follows the help gets an error, which is worse than an undocumented command. Either '
      + 'wire the verb or remove it from the help, in this same commit.');
  });

  it('DISCOVERABILITY LEG — every dispatched verb appears in help (the 0.38.0 defect)', () => {
    const dispatched = dispatchedComplianceVerbs();
    const advertised = advertisedComplianceVerbs();
    const undocumented = [...dispatched].filter((v) => !advertised.has(v));
    assert.deepEqual(undocumented, [],
      `these compliance verbs dispatch but are absent from \`nsauditor-ai help\`: `
      + `${undocumented.join(', ')}. Reachable is not the same as discoverable — \`sign-pack\` and `
      + '`verify-pack` were the HEADLINE capability of CE 0.2.43 / EE 0.38.0 and shipped a whole '
      + 'release undocumented in the tool\'s own help. Add a usage block in the same register as '
      + 'its siblings.');
  });

  it('the two pack-signing verbs specifically are advertised WITH their scope bound', () => {
    const out = execFileSync(process.execPath, [CLI, 'help'], { encoding: 'utf8' });
    for (const verb of ['sign-pack', 'verify-pack']) {
      assert.match(out, new RegExp(`compliance ${verb}`),
        `\`compliance ${verb}\` is missing from help — this is the exact 0.38.0 regression`);
    }
    // The scope bound is permanent and must travel with the claim wherever it is made, help
    // included: one framework's envelope, not the directory and not the pack.
    assert.match(out, /not the\s+directory, not the pack/,
      'the sign-pack help block lost its scope bound. The claim register keeps `pack-signing` at '
      + 'hedge-required precisely for this residual, so a help text that describes the capability '
      + 'without its scope is an overclaim on a surface every user reads.');
  });
});

/**
 * ⚠️ A SECOND USAGE SURFACE EXISTS, AND THIS GUARD WAS STRUCTURALLY BLIND TO IT.
 *
 * Found by an independent reviewer, and it is the sharper half of the original defect: when the CLI
 * is given an unknown compliance verb it prints its OWN usage string from the dispatch site — a
 * different string from `help`. At the 0.39.0 pre-release that string still read
 * `<attest|suppress|review|renew|keygen>`, so the very release that fixed the discoverability gap in
 * `help` was still shipping it on the error path a confused user is most likely to hit.
 *
 * The lesson generalises past this file: the first guard asked "does HELP list every dispatched
 * verb?" and answered yes. It never asked how many surfaces answer that question. **A parity guard
 * is only as complete as its enumeration of the surfaces that must agree.**
 */
describe('the unknown-verb error path names every dispatched verb too', () => {
  it('the dispatch-site usage string equals the dispatched verb set, BOTH directions', () => {
    const dispatched = dispatchedComplianceVerbs();
    const m = /Usage: nsauditor-ai compliance <([a-z|\-]+)>/.exec(src);
    assert.ok(m, 'the compliance usage string moved or was reworded — re-point this leg rather '
      + 'than deleting it; its absence would silently restore the defect.');
    const advertised = new Set(m[1].split('|'));

    const missing = [...dispatched].filter((v) => !advertised.has(v));
    assert.deepEqual(missing, [],
      `the unknown-verb usage string omits dispatched verb(s): ${missing.join(', ')}. A user who `
      + 'mistypes a subcommand is shown this string, not `help` — it is the surface most likely to '
      + 'be read by someone who does not already know the command exists.');

    /*
     * ⚠️ THE REVERSE DIRECTION, ADDED AFTER A SECOND REVIEW PASS CAUGHT ITS ABSENCE.
     * This leg shipped one-directional: dispatched ⊆ usage-string, never the reverse. Appending
     * `|frobnicate` to the usage string left ALL FOUR legs green — and a user who mistypes is then
     * told `frobnicate` is valid, types it, and gets the same error again. Recursively.
     *
     * The failure is not that I forgot a filter. THIS FILE'S OWN HEADER says the phantom direction
     * is the worse failure and must be written FIRST — and I wrote it first for `help`, then
     * enumerated a SECOND surface and covered only the direction the found defect exercised.
     * A rule applied to the artifact that taught it, and not re-applied to the artifact it later
     * grew, is a rule that only ever fixes the past.
     */
    const phantomInUsage = [...advertised].filter((v) => !dispatched.has(v));
    assert.deepEqual(phantomInUsage, [],
      `the unknown-verb usage string advertises verb(s) nothing dispatches: `
      + `${phantomInUsage.join(', ')}. This is the worse direction: the string is printed BECAUSE `
      + 'the user typed something invalid, so naming another invalid verb sends them round the same '
      + 'loop. Either wire the verb or remove it from the string, in this same commit.');
  });
});
