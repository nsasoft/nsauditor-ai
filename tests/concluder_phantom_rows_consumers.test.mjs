import './helpers/no_operator_dotenv.mjs';
import './helpers/no_operator_keychain.mjs';   // FIRST: this file imports cli.mjs
// tests/concluder_phantom_rows_consumers.test.mjs
// ─────────────────────────────────────────────────────────────────────────────
// EE 2.0.0 / Community 1.0.0, 4(b) — the consumers that read the concluded `services` WITHOUT a status filter, driven
// through the REAL concluder on a router-shaped run: 003 saw 443 and 9200 open and 465 / 5601 refused; the TLS probe
// identified 443 and was refused on 465 and 993; the OpenSearch probe identified neither port.
//
// Before 4(b) every one of these consumers listed the refused and unidentified ports as SERVICES — measured over the
// evidence tree's 112 router runs the rule changes, 501 rows each in the CSV, SARIF, the Markdown table and the loader's
// `servicesOf`; the AI payload carries the same array. Each consumer now sees the identified set, and the refused ports
// stay visible where they belong: in `evidence`, with a reason.
//
// FOURTH QUADRANT FIRST: the identified service is still in every consumer.
// ─────────────────────────────────────────────────────────────────────────────
import { test } from 'node:test';
import assert from 'node:assert/strict';
import concluder from '../plugins/result_concluder.mjs';
import { buildCsv } from '../utils/export_csv.mjs';
import { buildSarifLog } from '../utils/sarif.mjs';
import { buildMarkdownReport } from '../utils/report_md.mjs';
import { servicesOf } from '../utils/report_inputs.mjs';
import { buildAIPayload } from '../cli.mjs';

const HOST = '192.0.2.1';
const tcpRow = (port, info, extra = {}) => ({ probe_protocol: 'tcp', probe_port: port, probe_info: info, response_banner: null, ...extra });
const RESULTS = [
  { id: '003', name: 'Port Scanner', result: { up: true, tcpOpen: [443, 9200], tcpClosed: [465, 5601],
    data: [tcpRow(443, 'Connected', { status: 'open' }), tcpRow(9200, 'Connected', { status: 'open' }),
      tcpRow(465, 'Connection refused', { status: 'closed' }), tcpRow(5601, 'Connection refused', { status: 'closed' })] } },
  { id: '011', name: 'TLS Scanner', result: { up: true, data: [tcpRow(443, 'TLS: TLSv1.3 TLS_AES_256_GCM_SHA384'),
    tcpRow(465, 'Error: connect ECONNREFUSED'), tcpRow(993, 'Error: timeout')] } },
  { id: '012', name: 'OpenSearch Scanner', result: { up: false, data: [tcpRow(9200, 'Connection refused'), tcpRow(5601, null)] } },
];
const PHANTOMS = [465, 993, 5601];

async function concluded() {
  const result = await concluder.run(RESULTS);
  return { id: '008', name: 'Result Concluder', result };
}

test('(first) the identified 443 and the open 9200 reach every consumer — and the phantoms reach none as a service', async () => {
  const conclusion = await concluded();
  const ports = {
    csv: buildCsv({ host: HOST, conclusion }).trim().split('\n').slice(1).map((l) => Number(l.split(',')[1])),
    sarif: buildSarifLog({ host: HOST, conclusion }).runs[0].results
      .map((r) => r.locations?.[0]?.physicalLocation?.artifactLocation?.uri ?? r.message?.text ?? ''),
    markdown: buildMarkdownReport({ host: HOST, conclusion, toolVersion: 't', scanTime: '2026-10-12T00:00:00Z' })
      .split('\n').filter((l) => /^\|\s*\d+\s*\|/.test(l)).map((l) => Number(l.split('|')[1])),
    servicesOf: servicesOf({ conclusion }).map((s) => s.port),
    aiPayload: buildAIPayload({ host: HOST, summary: '', results: RESULTS, conclusion, redact: false }).services.map((s) => s.port),
  };
  for (const name of ['csv', 'markdown', 'servicesOf', 'aiPayload']) {
    assert.deepEqual([...ports[name]].sort((a, b) => a - b), [443, 9200], `${name} lists the concluded services and only them`);
  }
  assert.equal(ports.sarif.length, 2, `SARIF carries one result per service: ${JSON.stringify(ports.sarif)}`);
  for (const p of PHANTOMS) assert.ok(!ports.sarif.some((t) => new RegExp(`\\b${p}\\b`).test(t)), `SARIF names phantom ${p}`);
});

test('the refused and unidentified ports stay visible — as evidence with a reason, in the payload the AI receives too', async () => {
  const conclusion = await concluded();
  const reasons = conclusion.result.evidence.filter((e) => e.reason).map((e) => `${e.from} ${e.port}`).sort();
  assert.deepEqual(reasons, ['opensearch-scanner 5601', 'tls-scanner 465', 'tls-scanner 993']);
  const payload = buildAIPayload({ host: HOST, summary: '', results: RESULTS, conclusion, redact: false });
  assert.deepEqual(payload.evidence.filter((e) => e.reason).map((e) => e.port).sort((a, b) => a - b), PHANTOMS);
});
