/**
 * A WITHDRAWN CAPABILITY CLAIM MAY NOT COME BACK — CE twin.
 *
 * The EE repo carries the full guard (`tests/capability_claim_honesty.test.mjs` there, with
 * the code-cited refutation of each claim). This is its CE half, and it exists because the
 * two repos publish two README files that npm freezes independently: fixing the EE page
 * leaves the CE page stale, which is precisely how the "Latest: CE 0.1.94" headline drifted
 * for eight cycles.
 *
 * The claim withdrawn here is narrower than EE's — CE ships no container image and no
 * air-gapped delivery — so what is guarded is the ABSOLUTE form of the air-gap claim:
 * "every feature works without internet access". Verified false on 2026-07-28: a default
 * scan attempts NVD egress unless `NSAUDITOR_OFFLINE_ONLY=1` is set.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const README = () => readFileSync(path.join(ROOT, 'README.md'), 'utf8');

const WITHDRAWN = [
  {
    id: 'absolute-airgap',
    pattern: /Every feature works without internet access|Fully air-gappable/i,
    why: 'a default scan attempts NVD egress unless NSAUDITOR_OFFLINE_ONLY=1 is set, so the ' +
         'unqualified form is false. To restore: make offline the default, or keep the qualifier.',
    probe: '- **Fully air-gappable.** Every feature works without internet access (Enterprise includes offline NVD feeds).',
  },
  {
    id: 'feed-data-delivered',
    pattern: /includes offline NVD feeds\b|NVD feed[ -]bundle/i,
    why: 'no feed data ships with either edition and no pipeline produces a bundle; the offline ' +
         'QUERY path is what Enterprise adds. To restore: build and ship the feed data.',
    probe: '(Enterprise includes offline NVD feeds).',
  },
];

/** Absence claims are satisfied by an empty file — so the honest replacement must be present. */
const MUST_STATE = [
  { pattern: /NSAUDITOR_OFFLINE_ONLY=1/,
    why: 'the offline path genuinely ships; withdrawing the overclaim must not delete the capability' },
  { pattern: /default\*{0,2} scan still attempts NVD egress/,
    why: 'the operational caveat is the entire correction — without it the qualifier is decorative' },
];

/**
 * THE ONE EXEMPTION (mirrors the EE guard). The release note that ANNOUNCES a withdrawal has
 * to quote what it withdraws, or it says nothing a reader can act on. So a line may carry a
 * withdrawn token if it also carries an explicit withdrawal marker — keyed on a fixed
 * three-literal vocabulary, and pinned at EQUALITY so a new exemption fails the build until
 * someone raises the pin deliberately, and a deleted disclosure fails it too.
 */
const WITHDRAWAL_MARKERS = ['WITHDRAWN', 'Deliberately not claimed', 'Planned —'];
const EXEMPT_LINE_COUNT = 1;   // the ZDE section's withdrawal record (moved from the 0.2.33 "What's New" bullet when release history was trimmed to the CHANGELOG)
const isDisclosure = (line) => WITHDRAWAL_MARKERS.some((m) => line.includes(m));

describe('capability-claim honesty (CE): the absolute air-gap claim stays withdrawn', () => {
  it('the README does not reassert a withdrawn claim', () => {
    const hits = [];
    README().split('\n').forEach((line, i) => {
      if (isDisclosure(line)) return;
      for (const c of WITHDRAWN) if (c.pattern.test(line)) hits.push(`README.md:${i + 1} [${c.id}]`);
    });
    assert.deepEqual(hits, [],
      'npm freezes this README at publish time, so a re-drifted claim becomes a permanently stale ' +
      'package page. Each withdrawn entry records what would have to ship to earn the words back.\n  ' +
      hits.join('\n  '));
  });

  // LIVENESS — a pattern list that matches nothing reads exactly like a clean subject.
  // Probes are hand-written literals, never derived from the patterns or the README.
  it('every withdrawn pattern actually matches its own probe', () => {
    const dead = WITHDRAWN.filter((c) => !c.pattern.test(c.probe)).map((c) => c.id);
    assert.deepEqual(dead, [], `these patterns protect nothing: ${dead.join(', ')}`);
  });

  it('the honest replacement is stated, not merely the overclaim deleted', () => {
    for (const req of MUST_STATE) {
      assert.match(README(), req.pattern, `README.md no longer states ${req.pattern} — ${req.why}`);
    }
  });

  it('exactly the expected number of lines use the withdrawal-marker exemption', () => {
    const exempt = [];
    README().split('\n').forEach((line, i) => {
      if (isDisclosure(line) && WITHDRAWN.some((c) => c.pattern.test(line))) {
        exempt.push(`README.md:${i + 1} ${line.trim().slice(0, 100)}`);
      }
    });
    assert.equal(exempt.length, EXEMPT_LINE_COUNT,
      `${exempt.length} lines invoke the exemption; the pin says ${EXEMPT_LINE_COUNT}. MORE means a ` +
      'withdrawn claim may have been re-stated beside a marker word. FEWER means a disclosure was ' +
      'deleted — the failure this guard exists to prevent.\n  ' + exempt.join('\n  '));
  });

  it('the README was actually read and is substantial', () => {
    assert.ok(README().length > 10_000, 'README.md is too small to be the real surface');
  });
});
