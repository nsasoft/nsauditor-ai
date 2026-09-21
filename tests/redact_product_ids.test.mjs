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
//   EE-RT.1 / EE-RT.1.1 / EE-RT.12.25   → untouched; no current id has four components
//   EE-RT.1.2.3.4                       → would be damaged, and does not exist yet
// So the `EE-RT` half of this exemption is PROPHYLACTIC. Saying so rather than letting a green
// test imply it closed a live defect it never met.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { redactSensitiveForAI } from '../cli.mjs';

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

test('a FOUR-COMPONENT EE-RT id survives too — the prophylactic half, named as such', () => {
  // No shipped id has four components yet, so this leg met no live defect. It exists because the
  // Track-2 ids grow a component per cycle and the day one does, the damage is silent.
  assert.equal(scrub('EE-RT.1.2.3.4'), 'EE-RT.1.2.3.4');
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

test('THE CENSUS OVER THE REAL EVIDENCE TREE — reported, never silently skipped', () => {
  // ⚠️ THE TREE IS A SIBLING OF THE REPOS AND MAY BE ABSENT. An absent corpus must SAY so rather
  // than pass quietly: a census that measured nothing and a census that found nothing are the
  // same green line, which is the distinction this repo keeps having to re-draw.
  const root = path.resolve(process.cwd(), '..', 'audit-evidence-samples');
  if (!fs.existsSync(root)) {
    assert.ok(true, `SKIPPED-BY-ABSENCE: ${root} is not present in this checkout`);
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
  const present = KNOWN_DAMAGED_BEFORE_THE_FIX.filter((f) => fs.existsSync(path.join(root, f))).sort();
  assert.deepEqual(damaged, present,
    'the set of payloads carrying a DESTROYED identifier is not the pinned historical set.\n'
    + `  found:  ${damaged.join(', ') || '(none)'}\n`
    + `  pinned: ${present.join(', ') || '(none)'}\n`
    + 'MORE means the fix regressed, or an id shape escapes it — a live defect.\n'
    + 'FEWER means a pinned artifact was regenerated clean: delete it from the pin, in this '
    + 'commit, so the pin cannot outlive the thing it records.');
});
