import './helpers/no_operator_home.mjs';   // FIRST: the MCP call log is computed from homedir() at load
// get_findings: WHEN A CATEGORY FILTER MATCHES NOTHING, SAY WHAT THE SCAN HOLDS.
//
// Filtered on a category, get_findings answered `total: 0` both when the category had no rows in this scan and when it
// named nothing at all, so a client could not tell the two apart — and a reply then guessed that the release might not
// emit a category it does. No plugin declares its categories, so "can this release emit it" is not answerable here.
// What IS answerable is what this scan holds: on a zero-row category call the response lists every category in the
// cached scan, with its total and the plugins that emitted it, and a constant note says what that list does and does
// not tell a reader.
//
// FOURTH QUADRANT FIRST: a call that matches, and a zero-row call with no category filter, return exactly what they did.
import { test, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import {
  _setTier, _putCloudScan, _resetCloudScanCache, handleGetFindings,
  GET_FINDINGS_NO_MATCH_NOTE, GET_FINDINGS_CATEGORIES_CAP, GET_FINDINGS_CATEGORIES_TRUNCATED_CLAUSE,
} from '../mcp_server.mjs';

const f = (severity, category, text = 'x') => ({ severity, ...(category ? { details: { category } } : {}), issues: [text] });
/** A cached AWS scan: two plugins, a category both emit, a category each emits alone, and an uncategorized row. */
function cache() {
  _putCloudScan('aws', { scanId: 'scan-1', ts: 1, args: {}, results: [
    { id: '1040', result: { findings: [
      f('INFO', 'multi-region-enumeration-incomplete'), f('CRITICAL', 'cloudtrail-zero-trails'), f('MEDIUM', 'cis-alarm-coverage'),
    ] } },
    { id: '1210', result: { findings: [
      f('INFO', 'multi-region-enumeration-incomplete'), f('INFO', 'aws-ec2-image-inventory-evidence-gap'), f('LOW', null),
    ] } },
  ] });
}
const TODAY_KEYS = ['findings', 'provider', 'scanId', 'total'];

beforeEach(() => { _resetCloudScanCache(); _setTier('enterprise'); cache(); });
afterEach(() => _setTier());

test('(first) a category that matches returns exactly the shape it returned before — no new field', async () => {
  const out = await handleGetFindings({ provider: 'aws', category: 'cis-alarm-coverage' });
  assert.deepEqual(Object.keys(out).sort(), TODAY_KEYS);
  assert.equal(out.total, 1);
});

test('(first) zero rows with NO category filter is unchanged: the new fields answer a category question only', async () => {
  for (const args of [{ plugin: '9999' }, { severity: 'HIGH' }]) {
    const out = await handleGetFindings({ provider: 'aws', ...args });
    assert.equal(out.total, 0);
    assert.deepEqual(Object.keys(out).sort(), TODAY_KEYS, JSON.stringify(args));
  }
});

test('an unknown category: every category the scan holds, with totals and plugins, and the constant note', async () => {
  const out = await handleGetFindings({ provider: 'aws', category: 'no-such-category' });
  assert.equal(out.total, 0);
  assert.deepEqual(out.categoriesInScan, [
    { category: 'aws-ec2-image-inventory-evidence-gap', total: 1, plugins: ['1210'] },
    { category: 'cis-alarm-coverage', total: 1, plugins: ['1040'] },
    { category: 'cloudtrail-zero-trails', total: 1, plugins: ['1040'] },
    { category: 'multi-region-enumeration-incomplete', total: 2, plugins: ['1040', '1210'] },
    { category: 'uncategorized(1210)', total: 1, plugins: ['1210'] },
  ]);
  assert.equal(out.note, GET_FINDINGS_NO_MATCH_NOTE);
  assert.equal(out.categoriesInScanTruncated, undefined);
});

test('a SEVERITY filter that excludes an existing category still lists it — the census ignores the other filters', async () => {
  const out = await handleGetFindings({ provider: 'aws', category: 'cloudtrail-zero-trails', severity: 'LOW' });
  assert.equal(out.total, 0);
  assert.deepEqual(out.categoriesInScan.find((c) => c.category === 'cloudtrail-zero-trails'),
    { category: 'cloudtrail-zero-trails', total: 1, plugins: ['1040'] }, 'it exists in this scan, at another severity');
});

test('a PLUGIN filter with a category ANOTHER plugin emits: listed under its real plugin', async () => {
  const out = await handleGetFindings({ provider: 'aws', category: 'aws-ec2-image-inventory-evidence-gap', plugin: '1040' });
  assert.equal(out.total, 0);
  assert.deepEqual(out.categoriesInScan.find((c) => c.category === 'aws-ec2-image-inventory-evidence-gap'),
    { category: 'aws-ec2-image-inventory-evidence-gap', total: 1, plugins: ['1210'] },
    'the reply can say: it is in this scan, from 1210, not from the plugin asked about');
});

test('the totals add up to every row the provider holds, uncategorized rows included', async () => {
  const all = await handleGetFindings({ provider: 'aws' });
  const out = await handleGetFindings({ provider: 'aws', category: 'no-such-category' });
  assert.equal(out.categoriesInScan.reduce((n, c) => n + c.total, 0), all.total);
});

test('over the cap: the first entries by name, flagged, and the note says so — never a silent cut', async () => {
  _resetCloudScanCache();
  const n = GET_FINDINGS_CATEGORIES_CAP + 7;
  const names = Array.from({ length: n }, (_, i) => `cat-${String(i).padStart(4, '0')}`);
  _putCloudScan('aws', { scanId: 'scan-2', ts: 1, args: {}, results: [
    { id: '1', result: { findings: [...names].reverse().map((c) => f('LOW', c)) } },
  ] });
  const out = await handleGetFindings({ provider: 'aws', category: 'no-such-category' });
  assert.equal(out.categoriesInScan.length, GET_FINDINGS_CATEGORIES_CAP);
  assert.deepEqual(out.categoriesInScan.map((c) => c.category), names.slice(0, GET_FINDINGS_CATEGORIES_CAP));
  assert.equal(out.categoriesInScanTruncated, true);
  assert.equal(out.note, `${GET_FINDINGS_NO_MATCH_NOTE} ${GET_FINDINGS_CATEGORIES_TRUNCATED_CLAUSE}`);
});

test('the note is a statement a reader can use: no internal names, and it never claims what the release can emit', () => {
  assert.doesNotMatch(GET_FINDINGS_NO_MATCH_NOTE, /details\.|_|plugin manager/i);
  assert.match(GET_FINDINGS_NO_MATCH_NOTE, /does not tell you whether this release can emit it/);
  assert.match(GET_FINDINGS_CATEGORIES_TRUNCATED_CLAUSE, /first \d+/);
});
