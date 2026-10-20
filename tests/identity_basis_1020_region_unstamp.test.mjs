// tests/identity_basis_1020_region_unstamp.test.mjs
// ─────────────────────────────────────────────────────────────────────────────
// 1020 STOPS STAMPING A REGION IT DID NOT READ AT EE 2.1.0 — AND THE DELTA DECLARES THAT, WITHOUT FORGETTING 1.1.0.
//
// When the S3 auditor cannot read a bucket's location it stamped the scan's configured region on the bucket's rows, a
// region nobody measured. From EE 2.1.0 such a row carries no region. `region` is part of a finding's identity, so the
// same bucket finding keyed `us-east-1` in a 2.0.0 run and keyed on no region in a 2.1.0 run would read as one finding
// resolved and a new one appearing. The pair straddles a change in what identifies the finding, so it is declared
// `identity-basis-changed`, exactly as 1020's 1.1.0 change was.
//
// ⚠️ THE 1.1.0 DECLARATION STILL HOLDS. A pair that straddles 1.1.0 with both runs before 2.1.0 (a 1.0.x baseline
// against a 1.1.0 to 2.0.x run, reachable through `report --run … --since …`) is still declared, and its detail names
// 1.1.0. Moving 1020's single entry from 1.1.0 to 2.1.0 would drop those pairs, which is the leg that guards it.
//
// The cost, stated: for one scan after the upgrade, a 1020 row that vanished is not called fixed.
//
// FOURTH QUADRANT FIRST: two runs on the same side of 2.1.0 compare normally, the unknown-location row included.
// ─────────────────────────────────────────────────────────────────────────────
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { dirname, join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import * as delta_ from '../utils/scan_delta.mjs';

const { buildScanDelta, IDENTITY_BASIS_CHANGED_AT, cmpVersion } = delta_;
const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

const REC = (eeVersion) => ({ runId: `r-${eeVersion}`, startedAt: '2026-10-01T00:00:00Z', schema: 1,
  eeVersion, ceVersion: '2.1.0', tier: 'enterprise', hostsWritten: [{ host: 'aws' }], pluginsRequested: ['1020'] });
// A bucket whose location was READ: its row carries that region, before 2.1.0 and after.
const READ = (over = {}) => ({ host: 'aws', plugin: '1020', pluginName: 's3', producerKind: 'plugin',
  resource: 'arn:aws:s3:::read-bucket', region: 'eu-west-1', title: "S3 bucket 'read-bucket' has no default encryption",
  severity: 'HIGH', evidenceGap: false, contentDigest: 'd-read', ...over });
// A bucket whose location could NOT be read: before 2.1.0 it carried the configured region; from 2.1.0, none.
const UNREAD = (over = {}) => ({ host: 'aws', plugin: '1020', pluginName: 's3', producerKind: 'plugin',
  resource: 'arn:aws:s3:::unread-bucket', title: "S3 bucket 'unread-bucket' has no default encryption",
  severity: 'HIGH', evidenceGap: false, contentDigest: 'd-unread', ...over });
const side = (eeVersion, findings) => ({ record: REC(eeVersion), findings, integrity: 'chain-verified',
  pluginStatus: [{ host: 'aws', plugin: '1020', status: 'ran' }] });
const delta = (bEE, bF, cEE, cF) => buildScanDelta({ baseline: side(bEE, bF), current: side(cEE, cF) });
const reasons = (d) => d.notComparable.map((x) => x.reason);

test('(first) both runs at 2.1.0: a vanished row IS resolved, and an unknown-location row with no region is unchanged', () => {
  const d = delta('2.1.0', [READ(), UNREAD()], '2.1.0', [UNREAD()]);
  assert.equal(d.resolved.length, 1, 'same identity basis on both sides: the row that went away was fixed');
  assert.equal(d.unchanged.length, 1, 'the unknown-location row compares by its resource, with no region on either side');
  assert.deepEqual(reasons(d), []);
});

test('both runs at 2.0.0: a vanished row IS resolved — the 2.1.0 change does not reach two runs before it', () => {
  const d = delta('2.0.0', [READ(), UNREAD({ region: 'us-east-1' })], '2.0.0', [UNREAD({ region: 'us-east-1' })]);
  assert.equal(d.resolved.length, 1);
  assert.equal(d.unchanged.length, 1);
  assert.deepEqual(reasons(d), []);
});

test('2.0.0 → 2.1.0: the unknown-location row (configured region → no region) is DECLARED, never resolved + new', () => {
  const d = delta('2.0.0', [UNREAD({ region: 'us-east-1' })], '2.1.0', [UNREAD()]);
  assert.equal(d.resolved.length, 0, 'the bucket finding did not go away — the region nobody read was dropped');
  assert.equal(d.newFindings.length, 0, 'and it is not a new exposure');
  assert.deepEqual(reasons(d), ['identity-basis-changed', 'identity-basis-changed']);
  for (const nc of d.notComparable) assert.match(nc.detail, /1020.*2\.1\.0/s, 'the detail names the producer and the release');
});

test('2.0.0 → 2.1.0: a vanished row is DECLARED for this one scan, not called fixed — the stated cost', () => {
  const d = delta('2.0.0', [READ()], '2.1.0', []);
  assert.equal(d.resolved.length, 0);
  assert.deepEqual(reasons(d), ['identity-basis-changed']);
  assert.match(d.notComparable[0].detail, /2\.1\.0/);
});

test('2.1.0 → 2.0.0, the other ordering, is declared too', () => {
  const d = delta('2.1.0', [READ()], '2.0.0', []);
  assert.equal(d.resolved.length, 0);
  assert.deepEqual(reasons(d), ['identity-basis-changed']);
});

test('the 1.1.0 declaration STILL HOLDS: 1.0.0 → 1.1.0 and 1.0.0 → 2.0.0 are declared, naming 1.1.0 and not 2.1.0', () => {
  for (const cur of ['1.1.0', '2.0.0']) {
    const d = delta('1.0.0', [READ({ region: undefined })], cur, []);
    assert.equal(d.resolved.length, 0, `1.0.0 → ${cur}: a pair straddling 1.1.0 may not report a remediation`);
    assert.deepEqual(reasons(d), ['identity-basis-changed'], `1.0.0 → ${cur}`);
    assert.match(d.notComparable[0].detail, /1\.1\.0/, `1.0.0 → ${cur}`);
    assert.doesNotMatch(d.notComparable[0].detail, /2\.1\.0/, `1.0.0 → ${cur}: no run in this pair is at 2.1.0`);
  }
});

test('1.0.0 → 2.1.0 straddles BOTH changes, and the detail names both', () => {
  const d = delta('1.0.0', [READ({ region: undefined })], '2.1.0', []);
  assert.equal(d.resolved.length, 0);
  assert.deepEqual(reasons(d), ['identity-basis-changed']);
  assert.match(d.notComparable[0].detail, /at EE 1\.1\.0 and 2\.1\.0;/);
});

// ── THE ONE FUNCTION (design C, confirmed by the audit seat) ───────────────────────────────────
// `IDENTITY_BASIS_CHANGED_AT` keeps each producer's FIRST change, unmoved: the published EE 2.0.0 reads it as its "at"
// label, and every straddle a 2.0.0 run can see is a first change, so that reader stays exactly true. A later change
// lives in `LATER_IDENTITY_BASIS_CHANGES`, and ONE function answers which changes a pair straddles.
test('identityBasisChangesBetween returns the versions a pair straddles, ascending — identityBasisChanged is its length', () => {
  const { identityBasisChangesBetween: between, identityBasisChanged } = delta_;
  assert.equal(typeof between, 'function');
  const cases = [['1.0.0', '1.1.0', ['1.1.0']], ['1.0.0', '2.0.0', ['1.1.0']], ['1.0.0', '2.1.0', ['1.1.0', '2.1.0']],
    ['2.0.0', '2.1.0', ['2.1.0']], [undefined, '2.1.0', ['1.1.0', '2.1.0']], ['2.1.0', '2.1.0', []], ['1.1.0', '2.0.0', []],
    ['2.1.0', '2.0.0', []]];
  for (const [b, c, want] of cases) {
    assert.deepEqual(between('1020', b, c), want, `1020 ${b} → ${c}`);
    assert.equal(identityBasisChanged('1020', b, c), want.length > 0, `1020 ${b} → ${c}`);
  }
  assert.deepEqual(between('1110', '1.0.0', '2.1.0'), ['1.1.0'], 'a producer with no later change: its first one only');
  assert.deepEqual(between('011', '1.0.0', '2.1.0'), [], 'an undeclared producer straddles nothing');
});

test('the label: one version as itself, two joined by "and", more as a list ending in "and"', () => {
  const { identityBasisChangeLabel: label } = delta_;
  assert.equal(label(['1.1.0']), '1.1.0');
  assert.equal(label(['1.1.0', '2.1.0']), '1.1.0 and 2.1.0');
  assert.equal(label(['1.1.0', '2.1.0', '3.0.0']), '1.1.0, 2.1.0 and 3.0.0');
});

test('CENSUS — the two tables cannot disagree: every later producer has a first change, and each list is strictly later and ascending', () => {
  const { LATER_IDENTITY_BASIS_CHANGES: later } = delta_;
  assert.ok(later && Object.keys(later).length > 0, 'an empty later table would leave every 2.1.0 leg above vacuous');
  for (const [producer, versions] of Object.entries(later)) {
    const first = IDENTITY_BASIS_CHANGED_AT[producer];
    assert.ok(first, `${producer} has a later change but no first one — the first table is where a producer is declared`);
    assert.ok(Array.isArray(versions) && versions.length > 0, producer);
    let prev = first;
    for (const v of versions) {
      assert.match(v, /^\d+\.\d+\.\d+$/, `${producer} declares ${v}, which cannot be ordered`);
      assert.ok(cmpVersion(v, prev) > 0, `${producer}: ${v} is not after ${prev}`);
      prev = v;
    }
  }
});

test('the LATER set is exactly this — moved deliberately, like the first table\'s pin', () => {
  // MOVED DELIBERATELY at EE 2.1.0: 1020 ADDED at '2.1.0' — a bucket whose location could not be read stops carrying the
  // configured region, and `region` is part of a finding's identity. Its 1.1.0 first change stays where it is.
  assert.deepEqual(JSON.parse(JSON.stringify(delta_.LATER_IDENTITY_BASIS_CHANGES)), { 1020: ['2.1.0'] });
});

// ⚠️ ONE READER. A second read of either table is a second answer to "did this pair straddle a change", and a second
// answer is how two artifacts come to disagree about one row. Comments are blanked before the subscripts are counted.
test('ONE READER — outside its reader no shipped file subscripts an identity table, and none names the later or Community one', () => {
  const files = [];
  const walk = (d) => { for (const e of readdirSync(d, { withFileTypes: true })) {
    if (['node_modules', '.git', 'tests'].includes(e.name)) continue;
    const p = join(d, e.name);
    if (e.isDirectory()) walk(p); else if (/\.(mjs|js)$/.test(e.name)) files.push(p);
  } };
  walk(ROOT);
  assert.ok(files.some((f) => f.endsWith(join('utils', 'scan_delta.mjs'))), 'positive control: the module itself was walked');
  const code = (f) => readFileSync(f, 'utf8').replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:])\/\/.*$/gm, '$1');
  const SUB = /\b(IDENTITY_BASIS_CHANGED_AT|LATER_IDENTITY_BASIS_CHANGES|COMMUNITY_IDENTITY_BASIS_CHANGED_AT)\s*\[/g;
  for (const f of files) {
    let src = code(f);
    if (f.endsWith(join('utils', 'scan_delta.mjs'))) {
      for (const reader of ['export function identityBasisChangesBetween(', 'export function communityIdentityBasisChangesBetween(']) {
        const at = src.indexOf(reader);
        assert.ok(at >= 0, `the reader is defined in the module: ${reader}`);
        const end = src.indexOf('\n}\n', at);
        src = src.slice(0, at) + src.slice(end);
      }
    } else {
      assert.doesNotMatch(src, /LATER_IDENTITY_BASIS_CHANGES|COMMUNITY_IDENTITY_BASIS_CHANGED_AT/, `${relative(ROOT, f)} names the later or Community table`);
    }
    assert.deepEqual(src.match(SUB) ?? [], [], `${relative(ROOT, f)} reads a table outside the one function`);
  }
});

