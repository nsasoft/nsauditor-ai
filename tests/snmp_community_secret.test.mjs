// tests/snmp_community_secret.test.mjs
// 1.3.0 lane 3, ahead of (s1) — a CREDENTIAL IN AN ARTIFACT. With SNMP_COMMUNITY set, the operator's own community
// string is a secret: it authenticates to their devices. The SNMP plugin wrote it into its raw result (`community`,
// `communitiesTried`, and a `No SNMP response for community "<it>"` evidence row) and its adapter copied it onto the
// service record, so the scan JSON, every evidence row and every reader carried it — and the CSV printed it as
// `default_community:<secret>`, a default-credential FINDING about the operator's own credential. The adapter already
// masked it as 'custom' in info and banner; the intent was never to carry it.
//
// Fixed at the SOURCE: a community string is recorded only when it is one of DEFAULT_COMMUNITIES (those are the
// finding); a custom one is recorded as the word 'custom', and a custom string that ANSWERED sets `communityCustom: true`
// so "tested with a custom string" stays distinguishable from "not tested". The CSV reads default membership too —
// defence in depth, because a mutant on one side of a seam proves nothing about the other.
//
// Harness: the SNMP library's Session.prototype.get is replaced for the duration of a leg, so the plugin's own handling
// of the string is what runs — every socket the Session opens is local and nothing is sent anywhere it could be answered.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import snmpNative from 'snmp-native';
import concluder from '../plugins/result_concluder.mjs';
import { conclude as snmpConclude } from '../plugins/snmp_scanner.mjs';
import { buildMarkdownReport } from '../utils/report_md.mjs';
import { buildSarifLog } from '../utils/sarif.mjs';
import { buildCsv } from '../utils/export_csv.mjs';
import { mapServiceToAttack } from '../utils/attack_map.mjs';

const SECRET = 'zq7-operator-community-4f19';
let fresh = 0;

// The plugin, imported FRESH with SNMP_COMMUNITY set (the community list is read at import), over a library whose
// `get` answers with `answer` (an empty list = no response).
async function runWith(t, communityEnv, answer) {
  const prevEnv = process.env.SNMP_COMMUNITY;
  if (communityEnv === undefined) delete process.env.SNMP_COMMUNITY; else process.env.SNMP_COMMUNITY = communityEnv;
  const proto = snmpNative.Session.prototype;
  const realGet = proto.get;
  proto.get = function get(_opts, cb) { setImmediate(() => cb(null, answer)); };
  t.after(() => {
    proto.get = realGet;
    if (prevEnv === undefined) delete process.env.SNMP_COMMUNITY; else process.env.SNMP_COMMUNITY = prevEnv;
  });
  const mod = await import(`../plugins/snmp_scanner.mjs?community-secret=${++fresh}`);
  const result = await mod.default.run('127.0.0.1', 161, {});
  const conclusion = { id: '100000', name: 'Result Concluder',
    result: await concluder.run([{ id: '007', name: 'SNMP Scanner', result }]) };
  return { result, conclusion, record: conclusion.result.services.find((s) => s.port === 161) };
}

// Everything a reader can print, plus the JSON a scan writes.
function everyOutput({ result, conclusion }) {
  const scanData = { host: '127.0.0.1', conclusion };
  return {
    rawResult: JSON.stringify(result),
    conclusion: JSON.stringify(conclusion),
    markdown: buildMarkdownReport(scanData),
    sarif: JSON.stringify(buildSarifLog(scanData)),
    csv: buildCsv(scanData),
    attack: JSON.stringify(conclusion.result.services.map((s) => mapServiceToAttack(s))),
  };
}
const leaks = (outputs) => Object.entries(outputs).filter(([, text]) => String(text).includes(SECRET)).map(([k]) => k);

test('(fourth quadrant, first) a DEFAULT community that answers is still recorded, flagged and rendered', async (t) => {
  const run = await runWith(t, undefined, [{ value: 'Linux edge 5.10.0' }]);
  assert.equal(run.result.up, true, 'positive control: the answered branch ran');
  assert.equal(run.record.community, 'public');
  assert.notEqual(run.record.communityCustom, true);
  assert.match(run.record.info, /Default SNMP community string 'public' accepted/);
  const out = everyOutput(run);
  assert.match(out.markdown, /SNMP default community string: public/);
  assert.match(out.csv, /default_community:public/);
});

test('a CUSTOM community that is never answered appears in no artifact — not in what was tried, not in an evidence row', async (t) => {
  const run = await runWith(t, SECRET, []);
  assert.equal(run.result.up, false);
  assert.equal(run.result.communitiesTried.length, 1, 'positive control: the custom string was tried');
  assert.deepEqual(leaks(everyOutput(run)), []);
  assert.equal(run.record.community, null);
});

test('a CUSTOM community that ANSWERS appears in no artifact, and the record says a custom string answered', async (t) => {
  const run = await runWith(t, SECRET, [{ value: 'Linux edge 5.10.0' }]);
  assert.equal(run.result.up, true, 'positive control: the answered branch ran');
  assert.deepEqual(leaks(everyOutput(run)), []);
  assert.equal(run.record.community, null, 'a custom string is not a default community, so there is no finding');
  assert.equal(run.record.communityCustom, true, '"answered to a custom string" must stay distinguishable from "not tested"');
  const out = everyOutput(run);
  assert.doesNotMatch(out.csv, /default_community/);
  assert.doesNotMatch(out.markdown, /SNMP default community string:/, 'the finding title — the Scope line names the check itself');
});

test('the adapter masks a custom string it is handed — a raw result written by an earlier release still carries it', async () => {
  const [rec] = await snmpConclude({ host: '127.0.0.1', result: { up: true, program: 'Linux', version: '5.10', community: SECRET,
    communitiesTried: [SECRET], data: [{ probe_protocol: 'udp', probe_port: 161, probe_info: 'SNMP response received', response_banner: 'x' }] } });
  assert.equal(JSON.stringify(rec).includes(SECRET), false, JSON.stringify(rec));
  assert.equal(rec.community, null);
  assert.equal(rec.communityCustom, true);
});

test('the CSV prints a default_community finding only for a DEFAULT community — a record hand-carrying any other string prints nothing', () => {
  const csvOf = (community) => buildCsv({ host: 'h', conclusion: { result: { services: [
    { port: 161, protocol: 'udp', service: 'snmp', program: 'Linux', version: '5.10', status: 'open', community }] } } });
  assert.match(csvOf('public'), /default_community:public/, 'positive control');
  const custom = csvOf(SECRET);
  assert.equal(custom.includes(SECRET), false, custom);
  assert.doesNotMatch(custom, /default_community/);
});
