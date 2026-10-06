// tests/service_flag_delta.test.mjs
// 1.2.1 lane 3, (s1) option B — the comparison channel SEES a service-check finding appear. Each history line carries,
// per service, the table's comparison identities (`flags`, one cid per item) and, per table row that APPLIES to the
// record, whether it was MEASURED (`checks`: true, or the reason it was not). computeDiff compares them as SETS and
// decides from the line alone: a net findings count cannot see a method appear while another finding resolves.
//
// The ruled rules: an item gone is CLEARED only if its row was measured this run, else NOT COMPARED with the reason; an
// item new is APPEARED only if its row was measured on the baseline, else FIRST OBSERVED; a row measured on the baseline
// and not now is NOT COMPARED (a change); a row first measured now with nothing is "first tested, nothing found" (stated,
// not a change); a baseline written before 1.2.1 is stated, never read as no flags; a second identical scan is quiet.
// report --since is (s1b), boarded.
//
// FOURTH QUADRANT FIRST: two identical scans compare quiet — the one-time upgrade alert stays one-time.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import concluder from '../plugins/result_concluder.mjs';
import { computeDiff, historyServiceEntry, historyHostEntry } from '../utils/scan_history.mjs';
import { hasSignificantChanges, buildDeltaReport, formatDeltaSummary } from '../utils/delta_reporter.mjs';
import { buildAlertPayload } from '../utils/webhook.mjs';
import { FINDINGS_COUNT_BASIS } from '../utils/report_inputs.mjs';
import * as T from '../utils/service_flags.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const PAST = '2001-01-01T00:00:00Z';

// A history line as the CLI writes it, from REAL concluded records.
async function line(results) {
  const c = await concluder.run(results);
  return { findingsCount: 0, findingsCountBasis: FINDINGS_COUNT_BASIS, tier: 'pro',
    services: c.services.map(historyServiceEntry), ...historyHostEntry({ result: c }) };
}
const significant = (current, previous) =>
  hasSignificantChanges({ newHosts: [], removedHosts: [], hostDiffs: new Map([['h', computeDiff(current, previous)]]) });
const at = (d, port) => d.changedFlags.find((c) => c.port === port) ?? { appeared: [], cleared: [], firstObserved: [], notCompared: [], firstTestedNothingFound: [] };

const http006 = (fields) => ({ id: '006', name: 'HTTP Probe', result: { up: true, program: 'nginx', version: '1.18.0', ...fields,
  data: [{ probe_protocol: 'http', probe_port: 80, probe_info: 'Server: nginx/1.18.0' }] } });
const methods = (dangerous) => http006({ methodsTested: true, allowedMethods: ['GET', ...dangerous], dangerousMethods: dangerous });
const methodsNotTested = http006({ methodsTested: false, allowedMethods: null, dangerousMethods: null });

// ── THE QUIET QUADRANT ───────────────────────────────────────────────────────────────────────────────────────────
test('(fourth quadrant, first) two identical 1.2.1 scans compare quiet — no flag change, no alert', async () => {
  const a = await line([methods(['PUT'])]);
  const b = await line([methods(['PUT'])]);
  const d = computeDiff(b, a);
  assert.equal(d.flagsNotComparable, false);
  assert.deepEqual(d.changedFlags, []);
  assert.equal(d.summary, 'No changes detected since last scan.');
  assert.equal(significant(b, a), false, 'the second scan after the upgrade is quiet');
});

test('(fourth quadrant) an object with no services array states nothing about flags; a scan output WITHOUT its summary is NOT COMPARED, never quiet', () => {
  // computeDiff over a value with no top-level `services` states nothing about flags (B). RE-STATED at items 4 + 11:
  // this leg pinned that the --watch delta stayed quiet over a scan output — the shipped defect, since the output carried
  // no summary. The output now carries `scanSummary`; one WITHOUT it is not compared (tests/watch_cycle.test.mjs).
  const scanOut = { host: 'h', results: [], conclusion: { result: { services: [{ port: 80, protocol: 'http', dangerousMethods: ['PUT'] }] } } };
  const d = computeDiff(scanOut, scanOut);
  assert.equal(d.flagsNotComparable, false);
  assert.deepEqual(d.changedFlags, []);
  const report = buildDeltaReport(new Map([['h', scanOut]]), new Map([['h', scanOut]]));
  assert.equal(report.hostDiffs.get('h').notCompared, 'no-summary');
  assert.equal(hasSignificantChanges(report), true, 'a comparison that could not be made is news, never "no change"');
});

test('a MALFORMED line — the basis stamp without a services array — is not read, and nothing throws', async () => {
  const good = await line([methods(['PUT'])]);
  const bad = { flagsBasis: good.flagsBasis, hostFlags: [], hostChecks: {}, findingsCount: 0, findingsCountBasis: FINDINGS_COUNT_BASIS, tier: 'pro' };
  for (const [cur, prev] of [[good, bad], [bad, good]]) {
    const d = computeDiff(cur, prev);
    assert.deepEqual([d.flagsNotComparable, d.changedFlags], [false, []]);
  }
});

test('a baseline written before 1.2.1 (no flags on its line) is NOT COMPARED — stated, and counted as a change once', async () => {
  const now = await line([methods(['PUT'])]);
  const before = { findingsCount: 0, findingsCountBasis: FINDINGS_COUNT_BASIS, tier: 'pro',
    services: now.services.map(({ port, protocol, service, version }) => ({ port, protocol, service, version })) };
  const d = computeDiff(now, before);
  assert.equal(d.flagsNotComparable, true);
  assert.deepEqual(d.changedFlags, [], 'absent is never [] — nothing is reported appeared');
  assert.match(d.summary, /service checks not compared: the baseline predates 1\.2\.1/);
  assert.equal(significant(now, before), true, 'one alert, saying why');
  assert.match(formatDeltaSummary(buildDeltaReport(new Map([['h', now]]), new Map([['h', before]]))), /service checks not compared/);
});

// ── APPEARED / CLEARED / FIRST OBSERVED / FIRST TESTED ──────────────────────────────────────────────────────────────
test('a dangerous method APPEARING between two 1.2.1 scans is reported, per item', async () => {
  const d = computeDiff(await line([methods(['PUT', 'DELETE'])]), await line([methods(['PUT'])]));
  assert.deepEqual(at(d, 80).appeared, ['dangerousMethods:DELETE']);
  assert.match(d.summary, /appeared: 80\/http dangerousMethods:DELETE/);
  assert.equal(significant(await line([methods(['PUT', 'DELETE'])]), await line([methods(['PUT'])])), true);
  const report = formatDeltaSummary(buildDeltaReport(new Map([['h', await line([methods(['PUT', 'DELETE'])])]]),
    new Map([['h', await line([methods(['PUT'])])]])));
  assert.doesNotMatch(report, /No significant changes detected/, 'a flag-only change is a change in the delta summary too');
});

test('the CLI writes its history line through both builders — the line a test builds is the line a scan writes', () => {
  const cli = fs.readFileSync(path.join(ROOT, 'cli.mjs'), 'utf8');
  const at = cli.indexOf('scanSummary = {');
  assert.ok(at > 0, 'the scan summary is found');
  const block = cli.slice(at, cli.indexOf('};', at));
  assert.match(block, /services: services\.map\(historyServiceEntry\)/);
  assert.match(block, /\.\.\.historyHostEntry\(conclusion\)/);
});

test('(fourth quadrant) a method gone where the Allow header WAS read is CLEARED', async () => {
  const d = computeDiff(await line([methods([])]), await line([methods(['PUT'])]));
  assert.deepEqual(at(d, 80).cleared, ['dangerousMethods:PUT']);
  assert.match(d.summary, /cleared: 80\/http dangerousMethods:PUT/);
});

test('a method seen where the baseline did NOT test is FIRST OBSERVED — its own word, never "appeared", never silent', async () => {
  const now = await line([methods(['PUT'])]);
  const before = await line([methodsNotTested]);
  const d = computeDiff(now, before);
  assert.deepEqual(at(d, 80).firstObserved, ['dangerousMethods:PUT']);
  assert.deepEqual(at(d, 80).appeared, []);
  assert.match(d.summary, /first observed: 80\/http dangerousMethods:PUT/);
  assert.equal(significant(now, before), true);
});

test('a check first tested now with NOTHING found is stated, and is not a change', async () => {
  const now = await line([methods([])]);
  const before = await line([methodsNotTested]);
  const d = computeDiff(now, before);
  assert.deepEqual(at(d, 80).firstTestedNothingFound, ['dangerousMethods']);
  assert.match(d.summary, /first tested, nothing found: 80\/http dangerousMethods/);
  assert.equal(significant(now, before), false);
});

// ── NOT COMPARED — a coverage loss is a change, never "cleared" ──────────────────────────────────────────────────────
test('a method seen on the baseline, and NOT tested now, is NOT COMPARED with the reason — never cleared', async () => {
  const now = await line([methodsNotTested]);
  const d = computeDiff(now, await line([methods(['PUT'])]));
  assert.deepEqual(at(d, 80).cleared, []);
  assert.deepEqual(at(d, 80).notCompared, [{ id: 'dangerousMethods:PUT', reason: 'no Allow header was read this run' }]);
  assert.match(d.summary, /not compared: 80\/http dangerousMethods:PUT — no Allow header was read this run/);
  assert.equal(significant(now, await line([methods(['PUT'])])), true, 'a coverage loss is a change');
});

test('a check measured CLEAN on the baseline and not tested now is NOT COMPARED too — the row, with its reason', async () => {
  const d = computeDiff(await line([methodsNotTested]), await line([methods([])]));
  assert.deepEqual(at(d, 80).notCompared, [{ id: 'dangerousMethods', reason: 'no Allow header was read this run' }]);
});

test('SSH: a weak algorithm, and an SSH record that collected NO algorithms now, is NOT COMPARED — the adapter\'s [] never reads cleared', async () => {
  const ssh = (fields) => ({ id: '002', name: 'SSH Scanner', result: { up: true, program: 'OpenSSH', version: '7.2', ...fields,
    data: [{ probe_protocol: 'tcp', probe_port: 22, probe_info: 'SSH-2.0-OpenSSH_7.2', response_banner: 'SSH-2.0-OpenSSH_7.2' }] } });
  const before = await line([ssh({ algorithms: { kex: ['diffie-hellman-group1-sha1'] }, weakAlgorithms: ['diffie-hellman-group1-sha1'] })]);
  const now = await line([ssh({ algorithms: null })]);
  assert.deepEqual(now.services[0].flags, [], 'positive control: the adapter wrote [] — nothing graded');
  const d = computeDiff(now, before);
  assert.deepEqual(at(d, 22).cleared, []);
  assert.deepEqual(at(d, 22).notCompared, [{ id: 'weakAlgorithms:diffie-hellman-group1-sha1', reason: 'the SSH algorithms were not collected this run' }]);
});

test('(iv) weak ciphers: an absence is NOT COMPARED — the list is the cipher each version negotiated, never proof', async () => {
  const tls = (cipher) => ({ id: '011', name: 'TLS Scanner', result: { up: true, data: [{ probe_port: 443, probe_info: 'TLS: TLSv1.3',
    tlsEvidence: { supportedVersions: ['TLSv1.3'], ciphers: cipher ? { 'TLSv1.3': cipher } : {} } }] } });
  const d = computeDiff(await line([tls(null)]), await line([tls('ECDHE-RSA-RC4-SHA')]));
  assert.deepEqual(at(d, 443).cleared, []);
  assert.equal(at(d, 443).notCompared.length, 1);
  assert.match(at(d, 443).notCompared[0].reason, /the cipher each TLS version negotiated — an empty list is not proof/);
});

test('a service that did not answer this run: its flags are NOT COMPARED, said, and counted as a change', async () => {
  const before = await line([methods(['PUT'])]);
  const now = { ...before, services: before.services.map((s) => historyServiceEntry({ port: s.port, protocol: s.protocol,
    service: s.service, version: s.version, status: 'filtered', methodsTested: false, dangerousMethods: null })) };
  const d = computeDiff(now, before);
  assert.deepEqual(at(d, 80).notCompared, [{ id: 'dangerousMethods:PUT', reason: 'the service did not answer this run' }]);
  assert.equal(significant(now, before), true);
});

// ── (b) ONE CERTIFICATE, ONE IDENTITY — whichever producer saw it ─────────────────────────────────────────────────────
const TLS = (fields) => ({ id: '011', name: 'TLS Scanner', result: { up: true, data: [{ probe_port: 443, probe_info: 'TLS: TLSv1.3',
  tlsEvidence: { supportedVersions: ['TLSv1.3'], ciphers: {}, ...fields } }] } });
const cert = { expired: true, daysToExpiry: -3, selfSigned: false, hostnameValid: true, subject: 'CN=x', issuer: 'CN=x',
  names: [], validFrom: '', validTo: '', signatureAlgorithm: 'sha256', keyType: 'RSA', keyBits: 2048 };
const AUDIT = (issues) => ({ id: '040', name: 'TLS Certificate & Cipher Auditor', result: { up: true, portResults: [{ port: 443,
  service: 'https', severity: 'critical', certificate: cert, negotiation: { protocol: 'TLSv1.3', cipher: 'X', forwardSecrecy: true },
  chain: { depth: 0 }, authorized: false, issues }] } });

test('(fourth quadrant) the same expired certificate seen by 011 alone, then by 011 + 040, is NO change — the identity never switches', async () => {
  const alone = await line([TLS({ certExpiry: PAST })]);
  const both = await line([TLS({ certExpiry: PAST }), AUDIT([{ severity: 'critical', check: 'cert_expired', detail: 'expired' }])]);
  assert.deepEqual(alone.services[0].flags, ['certificate:expired']);
  assert.deepEqual(both.services[0].flags, ['certificate:expired'], 'positive control: two producers, one identity');
  assert.deepEqual(computeDiff(both, alone).changedFlags, []);
  // In the REVERSE order the certificate itself does not churn either — no cleared, appeared or first observed. What
  // remains is 040's coverage: its other checks were measured on the baseline and are not now, which the coverage-loss
  // rule states (one row-level line), so the reverse is "no churn", not "no change".
  const back = computeDiff(alone, both).changedFlags;
  assert.deepEqual(back.flatMap((c) => [...c.cleared, ...c.appeared, ...c.firstObserved]), []);
  assert.deepEqual(back.flatMap((c) => c.notCompared), [{ id: 'certAudit', reason: 'the check did not run on this service this run' }]);
});

test('a 040-only check, with 040 not run on the port now, is NOT COMPARED — 011\'s handshake does not measure it', async () => {
  const before = await line([TLS({}), AUDIT([{ severity: 'high', check: 'hostname_mismatch', detail: 'mismatch' }])]);
  const now = await line([TLS({})]);
  const d = computeDiff(now, before);
  assert.deepEqual(at(d, 443).cleared, []);
  assert.deepEqual(at(d, 443).notCompared, [{ id: 'certificate:hostname_mismatch', reason: 'the check did not run on this service this run' }]);
});

// ── (c) SNMP — a default community is measured only where it was TRIED and the agent answered ─────────────────────
const snmp = (community, tried, up = true) => ({ id: '007', name: 'SNMP Scanner', result: { up, program: 'Linux', version: '5.10',
  community, communityCustom: community == null && up ? true : undefined, communitiesTried: tried,
  data: [{ probe_protocol: 'udp', probe_port: 161, probe_info: up ? 'SNMP response' : 'No SNMP response', response_banner: up ? 'Linux' : null }] } });

test('SNMP: a baseline public, and a run that tried only a custom string, is NOT COMPARED — "public was not tried this run"', async () => {
  const d = computeDiff(await line([snmp(null, ['custom'])]), await line([snmp('public', ['public', 'private'])]));
  assert.deepEqual(at(d, 161).cleared, []);
  assert.deepEqual(at(d, 161).notCompared, [{ id: 'community:public', reason: 'public was not tried this run' }]);
});

test('(fourth quadrant) SNMP: public and private tried, the agent answered private only — public is CLEARED, private APPEARED', async () => {
  const d = computeDiff(await line([snmp('private', ['public', 'private'])]), await line([snmp('public', ['public', 'private'])]));
  assert.deepEqual(at(d, 161).cleared, ['community:public']);
  assert.deepEqual(at(d, 161).appeared, ['community:private']);
});

test('SNMP: an agent that answered nothing measures nothing', async () => {
  const d = computeDiff(await line([snmp(null, ['public', 'private'], false)]), await line([snmp('public', ['public', 'private'])]));
  assert.deepEqual(at(d, 161).cleared, []);
  assert.deepEqual(at(d, 161).notCompared, [{ id: 'community:public', reason: 'the service did not answer this run' }]);
});

// ── A DOMAIN'S DNS POSTURE IS A HOST-LEVEL FACT, wherever the concluder put it ───────────────────────────────────────
const DNSSEC = { up: true, overallSeverity: 'high', summary: { actionable: 1 },
  details: { spfRecord: null, dmarcRecord: null, dkimSelectors: [], dnssec: { hasDNSKEY: false } },
  findings: { spf: [{ severity: 'high', check: 'missing_spf', detail: 'No SPF record' }] } };
const DNS_009 = { id: '009', name: 'dns_scanner', result: { up: true, program: 'BIND', version: '9.18',
  data: [{ probe_port: 53, probe_protocol: 'udp', probe_info: 'version.bind' }] } };

test('(fourth quadrant) 060 on the 53/udp record, then in evidence: NO change — the comparison is host-level both times', async () => {
  const attached = await line([DNS_009, { id: '060', name: 'DNS Security Auditor', result: DNSSEC }]);
  const onEvidence = await line([{ id: '060', name: 'DNS Security Auditor', result: DNSSEC }]);
  assert.deepEqual(attached.hostFlags, ['dnsSecurity:missing_spf']);
  assert.deepEqual(onEvidence.hostFlags, ['dnsSecurity:missing_spf'], 'positive control: the same host-level identity');
  const d = computeDiff(onEvidence, { ...attached, services: onEvidence.services });
  assert.deepEqual(d.changedFlags, [], 'no host-level churn');
  assert.equal(significant(onEvidence, { ...attached, services: onEvidence.services }), false);
});

// ── THE CENSUS — every row is a declared producer + cid + applies + measured, and every state is a declared reason ──
test('(census) every table row declares its producer, cid, applies and measured — a row with none is a failure, not a default', () => {
  for (const row of T.SERVICE_FLAGS) {
    assert.ok(row.producer && (row.producer.source || row.producer.marker), `${row.key} declares its producer`);
    for (const fn of ['cid', 'applies', 'measured']) assert.equal(typeof row[fn], 'function', `${row.key}.${fn}`);
  }
});

test('(census) every flag on a line IS a cid the table derives from a graded finding — and every not-measured state is a declared reason', async () => {
  const records = (await concluder.run([methods(['PUT']), methodsNotTested, TLS({ certExpiry: PAST }),
    AUDIT([{ severity: 'high', check: 'self_signed', detail: 'x' }]), snmp('public', ['public']), DNS_009])).services;
  records.push({ port: 9, protocol: 'tcp', status: 'filtered', axfrAllowed: null, axfrTested: 'no-answer' });
  for (const r of records) {
    const { flags, checks } = T.serviceFlagState(r);
    assert.deepEqual(flags, [...new Set(T.flagFindings(r).filter((f) => T.rowOf(f.key).scope !== 'host').map((f) => f.cid))].sort(),
      `port ${r.port}: flags are exactly the table's cids`);
    for (const [k, st] of Object.entries(checks)) {
      if (st === true || (st && typeof st === 'object')) continue;
      assert.ok(st in T.NOT_COMPARED_REASONS, `${k}: "${st}" is a declared reason`);
    }
  }
  // No cid is spelled by hand where the line is written or read.
  for (const rel of ['utils/scan_history.mjs', 'cli.mjs', 'utils/delta_reporter.mjs']) {
    const src = fs.readFileSync(path.join(ROOT, rel), 'utf8');
    assert.doesNotMatch(src, /['"`](?:dangerousMethods|weak\w+|community|certificate|mcp|tribeHealth|dnsSecurity):/, `${rel} spells a cid`);
  }
});

test('(c) the SNMP record carries what was TRIED, as labels — a raw custom string never reaches it', async () => {
  const [rec] = (await concluder.run([snmp(null, ['zq7-secret-not-a-label'])])).services;
  assert.deepEqual(rec.communitiesTried, ['custom']);
  assert.equal(JSON.stringify(rec).includes('zq7-secret-not-a-label'), false);
});

// ── A FINDING WITH NO PORT HAS NO TRANSPORT (the audit seat's surviving mutant, pinned here) ──────────────────────────
test('the webhook payload keeps a portless finding portless — port null and protocol null, never 0 / "tcp"', () => {
  const [f] = T.conclusionFindings({ result: { services: [], evidence: [{ from: 'dns-sec-auditor', dnsSecurity: { findings: [
    { severity: 'high', category: 'spf', check: 'missing_spf', detail: 'No SPF record' }] } }] } }, 'h');
  const payload = buildAlertPayload('h', [{ port: f.port, protocol: f.protocol, service: f.service, description: f.title, severity: 'high' }]);
  assert.equal(payload.details[0].port, null);
  assert.equal(payload.details[0].protocol, null);
});

// ── WHAT THE README SAYS, against what B reaches ──────────────────────────────────────────────────────────────────
// B reaches the [ScanHistory] line. Items 4 + 11 then made the --watch gate compare each output's summary, so the
// Continuous Monitoring disclosure that the webhook did not fire on a change is gone and the section states the trigger;
// tests/build5_text_honesty.test.mjs holds those sentences to the gate's behaviour.
test('the README says what the [ScanHistory] line now reports, and the webhook\'s change trigger (items 4 + 11 closed its limit)', () => {
  const readme = fs.readFileSync(path.join(ROOT, 'README.md'), 'utf8');
  const bullet = readme.split('\n').find((l) => l.startsWith('- **Change detection**'));
  assert.ok(bullet, 'the Change detection bullet');
  for (const re of [/appeared/, /cleared/, /first observed/, /could not be compared, with the reason/, /never read as cleared/,
    /first scan after upgrading/]) assert.match(bullet, re);
  assert.doesNotMatch(readme, /webhook does NOT fire on a service, version or finding change/);
  assert.match(readme, /An alert is posted for each changed host carrying a finding at or above `--alert-severity`/);
});

// ── THE AUDIT SEAT'S FOLD ON a1c8aab ─────────────────────────────────────────────────────────────────────────────
// A CVE on a service record is a LOOKUP outcome, not an estate fact: an empty list after a lookup that failed, or after
// the vulnerability data moved, is not a fix. No shipped producer fills a record's CVEs today (UNEMITTED_FLAG_KEYS), so
// this is latent — and it goes live the day one does. Until a lookup outcome is recorded (F1's scope), the row's absence
// is NOT COMPARED and an appearance is FIRST OBSERVED, never cleared or appeared.
test('a CVE on the baseline and an empty list now is NOT COMPARED — never cleared; a new one is FIRST OBSERVED', () => {
  const cveLine = (cves) => ({ flagsBasis: T.FLAGS_BASIS, hostFlags: [], hostChecks: {}, findingsCount: 0,
    findingsCountBasis: FINDINGS_COUNT_BASIS, tier: 'pro', services: [historyServiceEntry({ port: 22, protocol: 'tcp',
      service: 'ssh', version: '7.2', status: 'open', cves })] });
  const gone = computeDiff(cveLine([]), cveLine(['CVE-2024-0001']));
  assert.deepEqual(at(gone, 22).cleared, []);
  assert.deepEqual(at(gone, 22).notCompared, [{ id: 'cve:CVE-2024-0001', reason: 'the scan did not record whether the CVE lookup ran' }]);
  const came = computeDiff(cveLine(['CVE-2024-0002']), cveLine([]));
  assert.deepEqual([at(came, 22).appeared, at(came, 22).firstObserved], [[], ['cve:CVE-2024-0002']]);
});

test('TLS: a weak protocol on the baseline and an 011 record with NO handshake now is NOT COMPARED — never cleared', async () => {
  const tls = (fields) => ({ id: '011', name: 'TLS Scanner', result: { up: true, data: [{ probe_port: 443, ...fields }] } });
  const before = await line([tls({ probe_info: 'TLS: TLSv1.3', tlsEvidence: { supportedVersions: ['TLSv1', 'TLSv1.3'], ciphers: {} } })]);
  const now = await line([tls({ probe_info: 'TLS: TLSv1.3', tlsEvidence: {} })]);
  // An 011 record that answered but carries no TLS fields: rebuild the line's record without the handshake marker.
  const noHandshake = { ...now, services: now.services.map((s) => historyServiceEntry({ port: s.port, protocol: s.protocol,
    service: s.service, version: s.version, status: 'open', source: 'tls-scanner', tls: false, weakProtocols: [], weakCiphers: [] })) };
  assert.deepEqual(before.services[0].flags, ['weakProtocols:TLSv1'], 'positive control: the baseline graded it');
  const d = computeDiff(noHandshake, before);
  assert.deepEqual(at(d, 443).cleared, []);
  assert.deepEqual(at(d, 443).notCompared.find((n) => n.id === 'weakProtocols:TLSv1'),
    { id: 'weakProtocols:TLSv1', reason: 'no TLS handshake was observed this run' });
});

test('two lines that BOTH carry a basis stamp, and differ, are NOT COMPARED as "basis-changed" — the ratchet for the first bump', async () => {
  const now = await line([methods(['PUT'])]);
  const other = { ...now, flagsBasis: 'service-flags-v0' };
  const d = computeDiff(now, other);
  assert.deepEqual([d.flagsNotComparable, d.flagsNotComparableReason], [true, 'basis-changed']);
  assert.match(d.summary, /service checks not compared: the two scans recorded them on a different basis/);
});

test('a service with checks on the baseline and ABSENT now: its checks are said not compared, by port — not left to "removed"', async () => {
  const before = await line([methods(['PUT'])]);
  const now = { ...before, services: [] };
  const d = computeDiff(now, before);
  assert.equal(d.removedServices.length, 1, 'positive control: the services diff reports the removal');
  assert.deepEqual(at(d, 80).notCompared, [{ id: 'dangerousMethods:PUT', reason: 'the service is not in this scan' }]);
  assert.match(d.summary, /not compared: 80\/http dangerousMethods:PUT — the service is not in this scan/);
});
