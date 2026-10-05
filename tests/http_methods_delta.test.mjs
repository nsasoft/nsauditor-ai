// tests/http_methods_delta.test.mjs
// 1.2.1 lane 3 (a4) across the comparison channels — the audit seat's leg 6.
//
// The HTTP probe's adapter (Option A) lands its record where the fallback did and ADDS the methods result. So: a 1.2.0
// baseline (the fallback record, no method fields) against a 1.2.1 run (the adapter's record, the fields present) must be
// NO change — a field appearing is not a service change. Both records are PRODUCED by the real concluder: the 1.2.0 shape
// by withholding 006's adapter from the registry, the 1.2.1 shape by its adapter.
//
// PINNED, NOT ENDORSED — a dangerous method APPEARING between two 1.2.1 runs is invisible to the comparison channels, as
// is every other service-check flag (weak SSH algorithms, anonymous FTP …): computeDiff compares a service's name and
// version, and the history / `report --since` count shapes producers' findings[] and the Enterprise queue, never a
// service record's flags. That is the shared-flag-table item (lane 3, (s1)) — when it lands, this leg goes red by design.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import concluder from '../plugins/result_concluder.mjs';
import { computeDiff } from '../utils/scan_history.mjs';
import { countHostFindings, FINDINGS_COUNT_BASIS } from '../utils/report_inputs.mjs';

const http006 = (fields) => ({ id: '006', name: 'HTTP Probe', result: { up: true, program: 'nginx', version: '1.18.0', ...fields,
  data: [{ probe_protocol: 'http', probe_port: 80, probe_info: 'Server: nginx/1.18.0' }] } });
const ssh = { id: '002', name: 'SSH Scanner', result: { up: true, program: 'OpenSSH', version: '8.9',
  data: [{ probe_protocol: 'tcp', probe_port: 22, probe_info: 'SSH-2.0-OpenSSH_8.9' }] } };
const servicesOf = async (results, opts) => (await concluder.run(results, opts)).services;
const line = (services, findingsCount = 0) => ({ services, findingsCount, findingsCountBasis: FINDINGS_COUNT_BASIS, tier: 'pro' });
const as120 = { adapters: new Map([['006', { conclude: null }]]) }; // the fallback record a 1.2.0 concluder produced

test('(fourth quadrant, first) two identical runs compare as no change', async () => {
  const s = await servicesOf([ssh, http006({ methodsTested: true, allowedMethods: ['GET'], dangerousMethods: [] })]);
  const d = computeDiff(line(s), line(s));
  assert.equal(d.summary, 'No changes detected since last scan.');
});

test('a 1.2.0 baseline (no method fields) against a 1.2.1 run (the fields present) is NO change — on every service', async () => {
  const before = await servicesOf([ssh, http006({})], as120);
  const after = await servicesOf([ssh, http006({ methodsTested: true, allowedMethods: ['GET'], dangerousMethods: [] })]);
  assert.equal('methodsTested' in before.find((s) => s.port === 80), false, 'positive control: the baseline is the 1.2.0 shape');
  assert.equal(after.find((s) => s.port === 80).methodsTested, true, 'positive control: the run carries the fields');
  const d = computeDiff(line(after), line(before));
  assert.deepEqual([d.newServices, d.removedServices, d.changedServices], [[], [], []]);
  assert.equal(d.summary, 'No changes detected since last scan.');
});

test('PINNED, NOT ENDORSED: a dangerous method appearing between two 1.2.1 runs is invisible to the comparison channels ((s1))', async () => {
  const quiet = [ssh, http006({ methodsTested: true, allowedMethods: ['GET'], dangerousMethods: [] })];
  const loud = [ssh, http006({ methodsTested: true, allowedMethods: ['GET', 'PUT'], dangerousMethods: ['PUT'] })];
  const d = computeDiff(line(await servicesOf(loud)), line(await servicesOf(quiet)));
  assert.deepEqual([d.newServices, d.removedServices, d.changedServices], [[], [], []], 'never resolved + new: same key');
  const raw = (results) => ({ results: results.map((r) => ({ id: r.id, name: r.name, result: r.result })) });
  assert.equal(countHostFindings('h', raw(loud)), countHostFindings('h', raw(quiet)),
    'the history / report --since count does not read service flags — when (s1) makes it, re-state this leg');
});
