// tests/scan_cloud_deferred_scope_wording.test.mjs
//
// THE `scan_cloud` TOOL DESCRIPTION IS A MODEL-FACING CLAIM SURFACE, and its deferredScope
// paragraph is the one sentence a model reads on EVERY cloud scan before telling a user what
// the coverage means. It carried a PER-PROVIDER ROSTER claim until EE 0.39:
//
//   "Today only the AWS plugins declare their capability boundaries; Azure and GCP declare
//    none … for Azure and GCP say plainly that the boundaries are not yet declared."
//
// True when written, and FALSE the moment the EE GCP/Azure parity lane shipped seven
// declarations — at which point this description would have instructed the model to tell
// users a capability was absent while it shipped. An UNDERCLAIM, which is the expensive
// direction because nothing complains.
//
// ⚠️ WHY THE FIX IS PROVIDER-AGNOSTIC RATHER THAN AN UPDATED ROSTER. CE floats over a peer
// RANGE: one CE build faces many EE versions, so ANY enumerated roster is immediately wrong
// for some installed pair, and CE cannot derive EE's declaring set — the plugins live in the
// other repo. A sentence that is true in BOTH states is therefore the only kind that cannot
// rot: "not every plugin declares its capability boundaries" holds while only AWS declares,
// and still holds now that GCP and Azure do, because the remaining silent AWS plugins keep it
// true. Nothing about a future trio's publish ordering can falsify it.
//
// TWO-WAY, per the fourth-quadrant discipline. The ABSENCE leg is the one the incident
// produced, so it is the leg that will keep passing on its own; the PRESENCE leg is the one
// that rots, so it is written first and asserted on the invariant's own words.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const SRC = fs.readFileSync(path.join(ROOT, 'mcp_server.mjs'), 'utf8');

// The paragraph under test, isolated so a hit elsewhere in the file cannot satisfy either leg.
function deferredScopeParagraph() {
  const at = SRC.indexOf('AN EMPTY OR SHORT deferredScope');
  if (at < 0) return '';
  return SRC.slice(at, at + 700);
}

test('scan_cloud: the deferredScope caveat states the PROVIDER-AGNOSTIC invariant', () => {
  const para = deferredScopeParagraph();
  assert.ok(para.length > 0,
    'the deferredScope caveat is missing from the scan_cloud description entirely — a model ' +
    'reading an empty list would have nothing telling it that empty is not full coverage');
  assert.match(para, /NOT A CLAIM OF FULL COVERAGE/,
    'the load-bearing clause must survive any rewrite');
  assert.match(para, /Not every plugin declares/i,
    'the invariant must be stated per-PLUGIN, which is derivable and stays true, rather than ' +
    'per-provider, which CE cannot derive and which goes stale on any EE release');
  assert.match(para, /Never tell a user that an empty deferredScope means everything was assessed/,
    'the imperative is timeless and must be kept verbatim');
});

test('scan_cloud: the caveat names NO provider roster (it cannot derive one)', () => {
  const para = deferredScopeParagraph();
  const forbidden = [
    /Azure and GCP declare none/i,
    /only the AWS plugins declare/i,
    /boundaries are not yet declared/i,
    /\b(?:Azure|GCP|AWS)\b[^.]{0,40}\bdeclare (?:none|no boundaries)\b/i,
  ];
  const hits = forbidden.filter((re) => re.test(para)).map(String);
  assert.deepEqual(hits, [],
    'the caveat enumerates a per-provider declaring roster. CE floats over a peer RANGE and ' +
    'cannot see which EE plugins declare, so a roster here is a claim about another repo\'s ' +
    'contents that no test in this repo can keep true:\n  ' + hits.join('\n  '));
});

// ⚠️ THE MODULE MUST PARSE, and this leg exists because its absence cost a broken build. Both
// legs above read mcp_server.mjs as TEXT — which is right for asserting wording, and blind to
// the file being syntactically broken. The first version of the rewrite above contained the
// word "provider's" inside a SINGLE-QUOTED description string, which terminated the string and
// left CE unimportable. Both text legs passed happily; the EE suite caught it, because a test
// over there IMPORTS this module. A guard that reads a code file as prose cannot tell you the
// code still runs, so the cheapest possible parse check belongs beside the wording legs.
test('scan_cloud: mcp_server.mjs still parses as a module', async () => {
  await assert.doesNotReject(
    () => import(path.join(ROOT, 'mcp_server.mjs')),
    'mcp_server.mjs does not parse — a wording edit that breaks a quoted string leaves every ' +
    'text-based assertion in this file passing over an unimportable module',
  );
});
