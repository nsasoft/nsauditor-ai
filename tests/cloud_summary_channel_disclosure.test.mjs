// tests/cloud_summary_channel_disclosure.test.mjs
// ─────────────────────────────────────────────────────────────────────────────
// A TIER LINE'S COUNT INCLUDES THE EVIDENCE-GAP AND DECLARED-SCOPE ROWS — AND NOW SAYS SO.
//
// `scan_cloud`'s header counts and each MEDIUM / LOW / INFO tier line count EVERY record at that severity (pre-cap,
// complete), while the categories listed on the tier line exclude the records that have their own channel — evidence
// gaps and declared scope boundaries, itemized above. Nothing said so, so the categories summed below the total: measured
// on a live AWS run, INFO (52) over categories summing to 35, the difference 5 gap rows and 12 deferred-scope rows. The
// counts stay complete; the tier line now discloses "of which N evidence gaps, M declared scope", and the payload carries
// the same numbers per tier (`channelCounts`) — so categories plus the two equal the count, on every line.
//
// FOURTH QUADRANT FIRST: a result with no gap and no declared-scope row renders exactly as before.
// ─────────────────────────────────────────────────────────────────────────────
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { summarizeCloudFindings, renderCloudFindingsMarkdown } from '../utils/cloud_finding_summary.mjs';

const run = (findings) => summarizeCloudFindings([{ id: '1150', result: { findings } }], () => 'aws');
const md = (s) => renderCloudFindingsMarkdown(s, ['aws']);

test('(first) no gap and no declared scope: the tier lines read exactly as before — no "of which" clause', () => {
  const s = run([
    { severity: 'MEDIUM', details: { category: 'a' } }, { severity: 'MEDIUM', details: { category: 'a' } },
    { severity: 'INFO', details: { category: 'b' } },
  ]);
  const out = md(s);
  assert.ok(out.includes('- **MEDIUM (2)** a ×2'), out);
  assert.ok(out.includes('- **INFO (1)** b ×1'), out);
  assert.doesNotMatch(out, /of which/);
  assert.equal(s.aws.channelCounts, undefined, 'no channel rows, no field');
});

test('both kinds: every tier line says how many of its count are evidence gaps and declared scope — and the numbers add up', () => {
  const s = run([
    { severity: 'INFO', details: { category: 'c1' } }, { severity: 'INFO', details: { category: 'c1' } },
    { severity: 'INFO', details: { category: 'c2' } },
    { severity: 'INFO', details: { category: 'g', evidenceGap: true } }, { severity: 'INFO', details: { category: 'g', evidenceGap: true } },
    { severity: 'INFO', details: { deferredScope: true, deferredScopeId: 'x' } },
    { severity: 'LOW', details: { category: 'l1' } }, { severity: 'LOW', details: { category: 'kms-gap', evidenceGap: true } },
  ]);
  const out = md(s);
  assert.ok(out.includes('- **INFO (6 — of which 2 evidence gaps, 1 declared scope, listed above)** c1 ×2 · c2 ×1'), out);
  assert.ok(out.includes('- **LOW (2 — of which 1 evidence gap, 0 declared scope, listed above)** l1 ×1'), out);
  for (const tier of ['MEDIUM', 'LOW', 'INFO']) {
    const cats = (s.aws.rollup[tier] ?? []).reduce((n, r) => n + r.count, 0);
    const ch = s.aws.channelCounts?.[tier] ?? { evidenceGaps: 0, deferredScope: 0 };
    assert.equal(cats + ch.evidenceGaps + ch.deferredScope, s.aws.counts[tier] ?? 0, `${tier}: categories + the two = the count`);
  }
});

test('a tier whose records are ALL channel rows still prints its line, with the disclosure and no categories', () => {
  const s = run([{ severity: 'LOW', details: { category: 'kms-gap', evidenceGap: true } }]);
  assert.ok(md(s).includes('- **LOW (1 — of which 1 evidence gap, 0 declared scope, listed above)**'), md(s));
});
