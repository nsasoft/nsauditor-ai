// tests/http_methods_delta.test.mjs
// 1.2.1 lane 3 (a4) across the comparison channels — the audit seat's leg 6.
//
// The HTTP probe's adapter (Option A) lands its record where the fallback did and ADDS the methods result. So: a 1.2.0
// baseline (the fallback record, no method fields) against a 1.2.1 run (the adapter's record, the fields present) must be
// NO service change — a field appearing is not a service change. Both records are PRODUCED by the real concluder: the
// 1.2.0 shape by withholding 006's adapter from the registry, the 1.2.1 shape by its adapter. Each history LINE is the
// one that release's CLI writes: 1.2.0 wrote a service's identity only; 1.2.1 writes it through historyServiceEntry.
//
// (s1) B FLIPPED the leg this file pinned: computeDiff now compares each service's checks as a set, so a dangerous method
// appearing between two 1.2.1 scans is REPORTED (tests/service_flag_delta.test.mjs holds the rules). What stays pinned is
// the COUNT channel — the history findingsCount and `report --since` shape producers' findings[] and the Enterprise queue,
// never a service record's flags. Precisely (corrected from this file's first premise, which said every flag was invisible
// there): at the Pro and Enterprise tiers the analysis agents turn anonymous FTP, an SNMP default community, weak TLS / SSH
// and the certificate flags into queue findings, which that channel DOES read; what it does not see at any tier is a
// dangerous method, a zone transfer, an SMB null session or an MCP flag — and at the Community tier, no flag at all. That
// is (s1b), boarded.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import concluder from '../plugins/result_concluder.mjs';
import { computeDiff, historyServiceEntry, historyHostEntry } from '../utils/scan_history.mjs';
import { countHostFindings, FINDINGS_COUNT_BASIS } from '../utils/report_inputs.mjs';

const http006 = (fields) => ({ id: '006', name: 'HTTP Probe', result: { up: true, program: 'nginx', version: '1.18.0', ...fields,
  data: [{ probe_protocol: 'http', probe_port: 80, probe_info: 'Server: nginx/1.18.0' }] } });
const ssh = { id: '002', name: 'SSH Scanner', result: { up: true, program: 'OpenSSH', version: '8.9',
  data: [{ probe_protocol: 'tcp', probe_port: 22, probe_info: 'SSH-2.0-OpenSSH_8.9' }] } };
const servicesOf = async (results, opts) => (await concluder.run(results, opts)).services;
const base = { findingsCount: 0, findingsCountBasis: FINDINGS_COUNT_BASIS, tier: 'pro' };
// The line each release's CLI writes.
const line121 = (services) => ({ ...base, services: services.map(historyServiceEntry), ...historyHostEntry({ result: { services, evidence: [] } }) });
const line120 = (services) => ({ ...base,
  services: services.map((s) => ({ port: s.port, protocol: s.protocol ?? 'tcp', service: s.service ?? null, version: s.version ?? null })) });
const as120 = { adapters: new Map([['006', { conclude: null }]]) }; // the fallback record a 1.2.0 concluder produced

test('(fourth quadrant, first) two identical runs compare as no change', async () => {
  const s = await servicesOf([ssh, http006({ methodsTested: true, allowedMethods: ['GET'], dangerousMethods: [] })]);
  const d = computeDiff(line121(s), line121(s));
  assert.equal(d.summary, 'No changes detected since last scan.');
});

test('a 1.2.0 baseline (no method fields) against a 1.2.1 run (the fields present) is NO service change — and its checks are said not compared', async () => {
  const before = await servicesOf([ssh, http006({})], as120);
  const after = await servicesOf([ssh, http006({ methodsTested: true, allowedMethods: ['GET'], dangerousMethods: [] })]);
  assert.equal('methodsTested' in before.find((s) => s.port === 80), false, 'positive control: the baseline is the 1.2.0 shape');
  assert.equal(after.find((s) => s.port === 80).methodsTested, true, 'positive control: the run carries the fields');
  const d = computeDiff(line121(after), line120(before));
  assert.deepEqual([d.newServices, d.removedServices, d.changedServices], [[], [], []]);
  assert.deepEqual(d.changedFlags, [], 'nothing reported appeared over a baseline that recorded no checks');
  assert.match(d.summary, /service checks not compared: the baseline predates 1\.2\.1/);
});

test('(s1) B: a dangerous method APPEARING between two 1.2.1 scans is REPORTED by the line comparison — never resolved + new', async () => {
  const quiet = [ssh, http006({ methodsTested: true, allowedMethods: ['GET'], dangerousMethods: [] })];
  const loud = [ssh, http006({ methodsTested: true, allowedMethods: ['GET', 'PUT'], dangerousMethods: ['PUT'] })];
  const d = computeDiff(line121(await servicesOf(loud)), line121(await servicesOf(quiet)));
  assert.deepEqual([d.newServices, d.removedServices, d.changedServices], [[], [], []], 'same key: no service churn');
  assert.deepEqual(d.changedFlags.map((c) => [c.port, c.appeared]), [[80, ['dangerousMethods:PUT']]]);
});

test('PINNED, NOT ENDORSED ((s1b)): the history / report --since COUNT still does not read a service record\'s flags', async () => {
  const quiet = [ssh, http006({ methodsTested: true, allowedMethods: ['GET'], dangerousMethods: [] })];
  const loud = [ssh, http006({ methodsTested: true, allowedMethods: ['GET', 'PUT'], dangerousMethods: ['PUT'] })];
  const raw = (results) => ({ results: results.map((r) => ({ id: r.id, name: r.name, result: r.result })) });
  assert.equal(countHostFindings('h', raw(loud)), countHostFindings('h', raw(quiet)),
    'when (s1b) makes the count channel read the table, re-state this leg — never delete it');
});
