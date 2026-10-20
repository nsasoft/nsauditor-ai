// tests/mcp_scan_cloud_region_scope.test.mjs
// ─────────────────────────────────────────────────────────────────────────────
// `scan_cloud` NAMES THE AWS READS THAT STAY IN THE CONFIGURED REGION WHEN A REGION LIST IS PASSED — FROM WHAT EACH
// PLUGIN THAT RAN DECLARES, NEVER FROM A LIST WRITTEN HERE.
//
// The `regions` description said a passed list is followed by every region-scoped check except three named reads; a
// census of the Enterprise plugins found nine reads that ignore the list and three that fall back onto the configured
// region. The description cannot hold that list (and a hand list here would name Enterprise's plugins from Community), so
// each plugin declares its own (`readsOutsideRegionList`), and when a list was passed the response carries `regionScope`:
// every declared read of every AWS plugin that ran, and — `undeclared` — every AWS plugin that ran without the field.
//
// ⚠️ ABSENT IS NOT EMPTY. An Enterprise plugin that reads nothing outside a list carries an EMPTY declaration; one with no
// field at all predates it (the published 2.0.0 plugins), so whether its reads stayed in the configured region is not
// known — and 2.0.0's CloudTrail auditor does read its alarms and AWS Config there. Reading absent as empty would print
// an empty list beside reads that ignored it.
//
// FOURTH QUADRANT FIRST: no list passed, no `regionScope` — whatever the plugins declare.
// ─────────────────────────────────────────────────────────────────────────────
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { handleScanCloud, TOOLS, _setPluginManager } from '../mcp_server.mjs';

const READ = (over = {}) => ({ id: 'alarms', class: 'exception', service: 'Amazon CloudWatch', reads: 'the alarms', reason: 'read in the configured region', ...over });
function pm(plugins, statuses = {}) {
  return {
    plugins,
    runCloud: async () => ({
      host: 'cloud:aws', results: [], conclusion: null,
      manifest: plugins.map((p) => ({ id: String(p.id), name: p.name ?? String(p.id), status: statuses[p.id] ?? 'ran' })),
      providerStatus: { aws: { available: plugins.length, ran: plugins.length, skipped: 0, errored: 0 } },
      auditedProviders: ['aws'],
    }),
  };
}
const scan = async (plugins, args, statuses) => { _setPluginManager(pm(plugins, statuses)); try { return await handleScanCloud({ providers: ['aws'], ...args }); } finally { _setPluginManager(null); } };

test('(first) no list passed: no regionScope, whatever the plugins declare', async () => {
  const out = await scan([{ id: '1040', cloudProvider: 'aws', readsOutsideRegionList: [READ()] }], {});
  assert.equal(Object.hasOwn(out, 'regionScope'), false);
});

test('a list passed: every declared read of every AWS plugin that ran, named by plugin; an empty declaration adds none', async () => {
  const out = await scan([
    { id: '1030', cloudProvider: 'aws', readsOutsideRegionList: [] },
    { id: '1040', cloudProvider: 'aws', readsOutsideRegionList: [READ(), READ({ id: 'config-recorders', service: 'AWS Config', reads: 'the recorders' })] },
    { id: '1120', cloudProvider: 'aws', readsOutsideRegionList: [READ({ id: 'unread-location-bucket', class: 'fail-open', service: 'Amazon S3', reads: 'a bucket whose location was unread', reason: 'audited in the configured region' })] },
  ], { regions: ['eu-west-1'] });
  assert.deepEqual(out.regionScope, {
    readsOutsideList: [
      { plugin: '1040', id: 'alarms', class: 'exception', service: 'Amazon CloudWatch', reads: 'the alarms', reason: 'read in the configured region' },
      { plugin: '1040', id: 'config-recorders', class: 'exception', service: 'AWS Config', reads: 'the recorders', reason: 'read in the configured region' },
      { plugin: '1120', id: 'unread-location-bucket', class: 'fail-open', service: 'Amazon S3', reads: 'a bucket whose location was unread', reason: 'audited in the configured region' },
    ],
    undeclared: [],
  });
});

test('["all"] is a list too', async () => {
  const out = await scan([{ id: '1040', cloudProvider: 'aws', readsOutsideRegionList: [READ()] }], { regions: ['all'] });
  assert.equal(out.regionScope.readsOutsideList.length, 1);
});

test('an AWS plugin that ran with NO declaration is UNDECLARED — never read as one whose reads all followed the list', async () => {
  const out = await scan([{ id: '1040', cloudProvider: 'aws' }, { id: '1030', cloudProvider: 'aws', readsOutsideRegionList: [] }], { regions: ['eu-west-1'] });
  assert.deepEqual(out.regionScope.readsOutsideList, []);
  assert.deepEqual(out.regionScope.undeclared, ['1040']);
  assert.match(out.regionScope.note, /declare nothing about the regions they read/);
});

test('a malformed declaration is undeclared too — a read with no class or no words is not trusted', async () => {
  for (const bad of [[READ({ class: 'maybe' })], [READ({ reads: '' })], [{ id: 'x' }], 'alarms']) {
    const out = await scan([{ id: '1040', cloudProvider: 'aws', readsOutsideRegionList: bad }], { regions: ['eu-west-1'] });
    assert.deepEqual([out.regionScope.readsOutsideList, out.regionScope.undeclared], [[], ['1040']], JSON.stringify(bad));
  }
});

test('a plugin that did not run, and a plugin of another cloud, contribute nothing and are not undeclared', async () => {
  const out = await scan([
    { id: '1040', cloudProvider: 'aws', readsOutsideRegionList: [READ()] },
    { id: '1050', cloudProvider: 'aws' },
    { id: '1021', cloudProvider: 'gcp' },
  ], { regions: ['eu-west-1'] }, { 1040: 'skipped', 1050: 'errored' });
  assert.deepEqual(out.regionScope, { readsOutsideList: [], undeclared: [] });
});

test('the `regions` field points at regionScope and names no read itself — the list lives where it is derived', () => {
  const d = TOOLS.find((t) => t.name === 'scan_cloud').inputSchema.properties.regions.description;
  assert.match(d, /`regionScope`/);
  assert.doesNotMatch(d, /\bexcept\b|\b1110\b|KMS|AWS Config/, 'a hand list of exceptions in the field is the defect this replaces');
});

// The field has no other budget leg (mcp_tool_description_budget measures each tool's description, not its parameters').
// Measured 584 UTF-8 bytes with the hand list, 548 with the pointer. A longer field is a deliberate move of this number.
test('the `regions` field stays within its measured budget — 548 UTF-8 bytes', () => {
  const d = TOOLS.find((t) => t.name === 'scan_cloud').inputSchema.properties.regions.description;
  assert.ok(Buffer.byteLength(d, 'utf8') <= 548, `regions description is ${Buffer.byteLength(d, 'utf8')} bytes`);
});
