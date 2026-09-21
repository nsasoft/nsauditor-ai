// THE AI-PAYLOAD REDACTOR MUST NOT REWRITE OUR OWN IDENTIFIERS (board E3).
//
// ⚠️ THE DEFECT IS LIVE, not theoretical. `redactSensitiveForAI`'s IPv4 rule is
// `\b(?:(?:\d{1,3}\.){3}\d{1,3})\b`, and `-` is a non-word character, so the `\b` holds right
// after `EE-`: the four-component id `EE-0.3.2.4` matches as an address and is rewritten to
// `EE-[IP]`. Measured in this cycle's own evidence tree — TWO real payloads carry
// `plugin 1020 (EE-[IP] fold)` where the shipped source says `plugin 1020 (EE-0.3.2.4 fold)`.
//
// ⚠️ A REDACTOR'S FALSE POSITIVE IS INVISIBLE FROM THE REDACTED ARTIFACT ALONE. `EE-[IP]` reads
// like a redaction that worked. Only comparing against the raw shows an identifier was destroyed,
// which is why the census leg below is keyed on the PAIR and not on the output.
//
// ⚠️ AND THE TWO SHAPES ARE NOT EQUALLY LIVE — measured, not assumed:
//   EE-0.3.2.4   four dotted components → DAMAGED today, and shipping damaged
//   EE-0.4.2     three components       → untouched (the rule needs four groups)
//   EE-RT.1 / EE-RT.1.1 / EE-RT.12.25   → untouched; the rule needs four groups
//   EE-RT.11.1.2.5                      → WOULD be damaged. It is a REAL id: `plugins/
//                                         1050_aws_apigateway_auditor.mjs` carries it 4× (and
//                                         `EE-RT.11.1.2.2` once) — all in `//` comments, so none
//                                         is EMITTED, and the evidence tree holds zero
//                                         `EE-RT.[IP]`.
// ⚠️ SO THE HONEST STATEMENT IS "no EMITTED id has four components", NOT "the shape does not
// exist". An earlier draft of this header said the latter and used an INVENTED `EE-RT.1.2.3.4` —
// in the same commit message that announced not repeating E2's invented-constant defect. The
// shape exists in source; only the exposure is absent. The `EE-RT` half is still prophylactic,
// and now it is pinned by a literal that is really in the tree.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { redactSensitiveForAI } from '../cli.mjs';

// ⚠️ DERIVED FROM THIS FILE, NOT FROM `process.cwd()`. A cwd-relative root means running the
// suite from anywhere else silently walks nothing and the corpus leg passes over live evidence
// it never opened — a census bounded by the directory you happened to start in.
const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const EVIDENCE_ROOT = path.resolve(REPO, '..', 'audit-evidence-samples');

// ⚠️ EVERY LITERAL HERE IS COPIED FROM A REAL ARTIFACT, never invented — the fixture-from-
// imagination defect this lane hit one item ago. The first is the sentence that actually shipped
// damaged; the EE-RT ids are the ones the shipped data really carries.
const REAL_SENTENCE = 'retention-period validation already partial via plugin 1020 (EE-0.3.2.4 fold).';
const REAL_IDS = ['EE-0.3.2.4', 'EE-0.3.2.2', 'EE-0.3.3.5', 'EE-0.4.2',
  'EE-RT.1', 'EE-RT.1.1', 'EE-RT.10', 'EE-RT.12.25'];

const scrub = (s) => JSON.parse(JSON.stringify(redactSensitiveForAI({ t: s }))).t;

test('THE LIVE ONE: the sentence that shipped damaged survives intact', () => {
  assert.equal(scrub(REAL_SENTENCE), REAL_SENTENCE,
    'this exact sentence reached two AI payloads as "plugin 1020 (EE-[IP] fold)" — an identifier '
    + 'destroyed by a rule written for addresses');
});

test('every identifier shape this product EMITS survives the redactor', () => {
  const damaged = REAL_IDS.filter((id) => scrub(id) !== id);
  assert.deepEqual(damaged, [], `these ids were rewritten: ${damaged.join(', ')}`);
});

test('a FOUR-COMPONENT EE-RT id survives too — pinned by a REAL literal', () => {
  // `EE-RT.11.1.2.5` is real: four occurrences in plugins/1050_aws_apigateway_auditor.mjs, plus
  // `EE-RT.11.1.2.2` once. All in `//` comments, so no EMITTED id has four components and this
  // leg met no live exposure — but the shape is in the tree, one code path away from a payload.
  assert.equal(scrub('EE-RT.11.1.2.5'), 'EE-RT.11.1.2.5');
  assert.equal(scrub('EE-RT.11.1.2.2'), 'EE-RT.11.1.2.2');
});

// ── THE ACCEPT CASES. Written before the exemption, because the entire risk of widening a
// redactor's exemption is that it stops redacting.
test('A PUBLIC ADDRESS IS STILL REDACTED — the redactor still does its job', () => {
  assert.equal(scrub('scan of 203.0.113.5 returned'), 'scan of [IP] returned');
  assert.equal(scrub('203.0.113.5'), '[IP]');
});

test('a PRIVATE address is still preserved, as before', () => {
  for (const ip of ['192.168.1.1', '10.0.0.7', '172.16.5.4']) assert.equal(scrub(ip), ip);
});

test('the exemption does NOT swallow an address standing next to an id', () => {
  // ⚠️ THE WIDENING DIRECTION, and the one that would leak. If the exemption consumed more than
  // its own token — or if the two rules ran as separate passes in the wrong order — a public
  // address adjacent to an identifier would ride out of the payload unredacted.
  assert.equal(scrub('EE-0.3.2.4 at 203.0.113.5'), 'EE-0.3.2.4 at [IP]');
  assert.equal(scrub('203.0.113.5 then EE-0.3.2.4'), '[IP] then EE-0.3.2.4');
  assert.equal(scrub('EE-0.3.2.4,203.0.113.5'), 'EE-0.3.2.4,[IP]');
});

test('an id-LOOKALIKE that is really an address is still redacted', () => {
  // `FOO-203.0.113.5` is not one of our identifiers. The exemption is anchored on `EE-`, so this
  // must still be scrubbed — an exemption keyed on "preceded by any letters and a dash" would be
  // a hole a hostname could walk through.
  assert.equal(scrub('FOO-203.0.113.5'), 'FOO-[IP]');
  assert.equal(scrub('EEX-203.0.113.5'), 'EEX-[IP]');
  // ⚠️ THE LEFT EDGE, which `FOO-` and `EEX-` do not exercise at all: both differ from `EE-` in
  // their own characters, so the exemption never starts matching. A token ENDING in `EE-` is the
  // only shape that reaches the word boundary before it. Measured: dropping the leading `\b`
  // leaves every other leg in this file green and preserves `FEE-203.0.113.5` unredacted — a
  // public address riding out of the payload behind a prefix that merely ends in our own.
  assert.equal(scrub('FEE-203.0.113.5'), 'FEE-[IP]');
  assert.equal(scrub('XEE-203.0.113.5'), 'XEE-[IP]');
});

test('DECLARED RESIDUAL: an address wearing our OWN prefix rides out, and that is stated', () => {
  // ⚠️ NOT A BUG REPORT — A LIMIT, pinned so it is not silent. `EE-203.0.113.5` is preserved
  // verbatim where the old rule scrubbed it to `EE-[IP]`. No value test can separate it from a
  // real `EE-RT.11.1.2.5`: they are the same shape, and the exemption cannot know which is which.
  // The trade is deliberate — the alternative is destroying every identifier, which is the defect
  // this file closes — and the exposure is bounded by our own prefix appearing before a public
  // address, which no producer emits. If this assertion ever needs to change, the fix is a
  // producer-side id vocabulary, not a wider or narrower regex.
  assert.equal(scrub('EE-203.0.113.5'), 'EE-203.0.113.5');
});

// ── THE CENSUS: keyed on the PAIR, because the output alone cannot show a false positive.
test('RAW-vs-PAYLOAD CENSUS: no exempt-shaped token is present raw and absent redacted', () => {
  const ID_RE = /\bEE-(?:RT\.)?\d+(?:\.\d+)*\b/g;
  const raw = `${REAL_SENTENCE} ${REAL_IDS.join(' ')} and a host at 203.0.113.5`;
  const out = scrub(raw);
  const lost = [...new Set(raw.match(ID_RE) ?? [])].filter((id) => !out.includes(id));
  assert.deepEqual(lost, [],
    'an identifier present in the raw and absent from the payload was destroyed by redaction. '
    + 'This is the direction the redacted artifact cannot show on its own.');
  assert.ok(!out.includes('203.0.113.5'), 'and the census must not pass by disabling redaction');
});

test('THE CENSUS OVER THE REAL EVIDENCE TREE — reported, never silently skipped', (t) => {
  // ⚠️ THE TREE IS A SIBLING OF THE REPOS AND MAY BE ABSENT. An absent corpus must SAY so rather
  // than pass quietly: a census that measured nothing and one that found nothing are the same
  // green line.
  //
  // ⚠️ AND THE FIRST DRAFT DID EXACTLY WHAT ITS OWN NAME FORBADE. It wrote
  // `assert.ok(true, 'SKIPPED-BY-ABSENCE: …')` — which prints NOTHING. Driven from a directory
  // with no sibling tree it emitted `ok 9 … # skipped 0` and no SKIPPED text anywhere, under a
  // test named "reported, never silently skipped". An assertion message is only carried by TAP
  // when the assertion FAILS, so the honest report is `t.skip()`, which TAP marks.
  const root = EVIDENCE_ROOT;
  if (!fs.existsSync(root)) {
    t.skip(`SKIPPED-BY-ABSENCE: ${root} is not present in this checkout — the corpus was NOT measured`);
    return;
  }
  const payloads = [];
  const walk = (d) => {
    for (const e of fs.readdirSync(d, { withFileTypes: true })) {
      const p = path.join(d, e.name);
      if (e.isDirectory()) walk(p);
      else if (e.name === 'scan_response_ai_payload.json') payloads.push(p);
    }
  };
  try { walk(root); } catch { /* unreadable subtree */ }
  assert.ok(payloads.length > 0, 'the tree exists but holds no AI payloads — the walk is not reaching it');

  // ⚠️ THE ALREADY-WRITTEN PAYLOADS ARE PINNED BY PATH, UNDER AN EQUALITY RATCHET, and the two
  // directions are different failures. These are EVIDENCE — the record of a real scan — so they
  // are not rewritten to make a test pass; rewriting an artifact to match a later rule is the one
  // thing an evidence tree must never do. They were written before this fix and carry the damage.
  //
  // EQUALITY, not a subset: a NEW damaged payload fails (the fix regressed or a new id shape
  // escapes), and the pinned ones being REGENERATED CLEAN also fails, telling the next seat to
  // delete the pin rather than letting it rot into permanent documentation of a closed defect.
  // Their end is defined: Gate 2 re-scans the whole estate after E1, which rewrites both.
  const KNOWN_DAMAGED_BEFORE_THE_FIX = [
    'ee-1.1.0/aws_20260920_204226/scan_response_ai_payload.json',
    'ee-1.1.0/aws_20260920_210543/scan_response_ai_payload.json',
  ];
  const damaged = payloads
    .filter((p) => /EE-(?:RT\.)?\[IP\]/.test(fs.readFileSync(p, 'utf8')))
    .map((p) => path.relative(root, p)).sort();
  // ⚠️ AND THE PIN'S "DEFINED END" DID NOT EXIST UNTIL THIS LEG. The pinned paths are TIMESTAMPED
  // run directories: Gate 2 writes NEW directories and never rewrites these, so "regenerated
  // clean" is unreachable and the retirement condition I first wrote could never fire. What
  // actually happens is the operator CLEANING the release directory — which happened once
  // already this cycle. Both files then vanish, `damaged` and `present` are both empty, the
  // equality holds vacuously, and the pin rots inert with nothing saying to delete it.
  //
  // So ABSENCE is the retirement signal, and it must FAIL rather than pass: a pinned artifact
  // that is gone has nothing left to excuse.
  const present = KNOWN_DAMAGED_BEFORE_THE_FIX.filter((f) => fs.existsSync(path.join(root, f))).sort();
  const vanished = KNOWN_DAMAGED_BEFORE_THE_FIX.filter((f) => !fs.existsSync(path.join(root, f))).sort();
  assert.deepEqual(vanished, [],
    `these pinned artifacts are GONE: ${vanished.join(', ')}\n`
    + 'The pin exists only to excuse files that are on disk. Delete these entries from '
    + 'KNOWN_DAMAGED_BEFORE_THE_FIX in this commit — a pin that outlives what it records is '
    + 'permanent documentation of a closed defect, and the next reader cannot tell it from a '
    + 'live exemption.');

  assert.deepEqual(damaged, present,
    'the set of payloads carrying a DESTROYED identifier is not the pinned historical set.\n'
    + `  found:  ${damaged.join(', ') || '(none)'}\n`
    + `  pinned: ${present.join(', ') || '(none)'}\n`
    + 'MORE means the fix regressed, or an id shape escapes it — a live defect.\n'
    + 'FEWER means a pinned artifact was regenerated clean: delete it from the pin, in this '
    + 'commit, so the pin cannot outlive the thing it records.');
});

test('THE ADDRESS RULE EXISTS EXACTLY ONCE IN cli.mjs — a second copy is how the next instance arrives', () => {
  // ⚠️ THIS LEG EXISTS BECAUSE A MUTANT SURVIVED. Reverting the summary call site to its own
  // inline `\b(?:(?:\d{1,3}\.){3}\d{1,3})\b` left every other leg in this file GREEN: they all
  // drive `redactSensitiveForAI`, and the summary path is assembled inside `main()`. Sharing the
  // rule was the right change and was entirely unproven.
  //
  // The defect this closes is not a wrong regex — it is DUPLICATION. `cli.mjs` carried the
  // address pattern twice; the identifier bug was found and fixed in one copy, and the other
  // kept the original, not live only because a network-scan summary happens to carry no
  // identifier. So the ratchet is on the COUNT, not on the text: any second copy fails here,
  // whatever it is for.
  //
  // The private-address pattern is a DIFFERENT rule (it enumerates RFC1918 ranges rather than
  // matching any dotted quad) and is not counted — named explicitly so the exclusion is a
  // decision rather than an accident of the regex used to count.
  const src = fs.readFileSync(path.join(REPO, 'cli.mjs'), 'utf8');
  const anyDottedQuad = /\\b\(\?:\(\?:\\d\{1,3\}\\\.\)\{3\}\\d\{1,3\}\)\\b/g;
  const occurrences = [...src.matchAll(anyDottedQuad)];
  assert.equal(occurrences.length, 1,
    `the any-address pattern appears ${occurrences.length} times in cli.mjs. It must appear ONCE, `
    + 'inside `scrubIPv4KeepingProductIds`, with each call site supplying its own POLICY. A '
    + 'second copy is how the identifier defect survived in the summary field after being fixed '
    + 'in the redactor.');
  assert.match(src, /export function scrubIPv4KeepingProductIds/,
    'and the one copy must live in the shared helper');
  // Both call sites must go through it, or the count above is satisfied by a helper nobody uses.
  const callSites = [...src.matchAll(/scrubIPv4KeepingProductIds\(/g)];
  assert.ok(callSites.length >= 3,
    `expected the definition plus at least two call sites, found ${callSites.length} — a shared `
    + 'helper with no callers passes a count and changes nothing');
});
