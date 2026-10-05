// tests/concluder_reaches_every_adapter.test.mjs
// 1.2.1 lane 3 — the concluder REACHES every adapter, and what it reaches LANDS. Replaces
// tests/concluder_drops_honesty.test.mjs, which pinned the drops "PINNED, NOT ENDORSED" until this release.
//
// (a1) The concluder resolved an adapter by importing `./<slug of the plugin's NAME>.mjs` and reading only a NAMED
//      `conclude`, so 014 and 024 (slug ≠ file name) and 040 / 050 / 060 (conclude on the default object) were never
//      reached. It now resolves by plugin ID — from the registry the PluginManager hands down, else from its own
//      directory — and reads `conclude` from either place. A plugin that declares `cloudProvider` is EXEMPT by a
//      DERIVED, printed set: cloud findings travel raw (cloud_finding_summary / harvestCloudFindings), and driven
//      through a service-record adapter they key to `tcp:NaN` and collapse into one fabricated PASS row.
// (a2) Reaching is not landing. The merge kept only identity fields when a non-authoritative record met an
//      authoritative one, 050's per-finding records shared their summary's key, 060's carried no port at all and keyed
//      to `dns:NaN`, 040 wrote "TLS" and the negotiated protocol into IDENTITY, and 024 named every port's program
//      "nmap". Adapter findings now travel under a namespace (certAudit, tribeHealth, dnsSecurity); a record with no
//      positive port is evidence, never a service row; 060's summary only ATTACHES to a 53/udp record a port-level
//      probe found (it audits a domain's DNS posture, not a port — it runs on every scan).
// (a6) UPnP host-name extraction keyed on the slug 'upnp_scanner' while the plugin is "Enhanced UPnP Scanner" — dead
//      since CE v0.1.3. Keyed on id 028 now (mDNS on 027).
// (a5) The census below is DERIVED: every plugin file that carries an adapter is driven through the REAL manager with a
//      result that records, by stack, which files read it — a new adapter joins by being written.
//
// FOURTH QUADRANT FIRST: what is reached today still lands, and what has no adapter still falls back.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import concluder from '../plugins/result_concluder.mjs';
import { PluginManager } from '../plugin_manager.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const PLUGINS = path.join(ROOT, 'plugins');
const servicesOf = async (results, opts) => (await concluder.run(results, opts)).services ?? [];
const importPlugin = (file) => import(pathToFileURL(path.join(PLUGINS, file)).href);
const isPort = (p) => Number.isInteger(p) && p > 0;

// ── FOURTH QUADRANT ──────────────────────────────────────────────────────────────────────────────
test('(q) a reached adapter (070, the MCP scanner) still lands its flags on the service record', async () => {
  const services = await servicesOf([{ id: '070', name: 'MCP Scanner', result: { up: true, mcpDetections: [{
    port: 3000, cwe: [], owasp: [], mitre: [], flags: { mcpAnonymousAccess: true },
    detection: { protocolVersion: '2024-11-05', scheme: 'http', serverInfo: {}, path: '/mcp', authRequired: false,
      ssePresent: false, tools: [] } }] } }]);
  const rec = services.find((s) => s.port === 3000);
  assert.ok(rec, 'the MCP record is concluded');
  assert.equal(rec.mcpAnonymousAccess, true);
});

const TLS_011 = { id: '011', name: 'TLS Scanner', result: { up: true, data: [{ probe_port: 443, probe_info: 'TLS: TLSv1.3',
  tlsEvidence: { supportedVersions: ['TLSv1', 'TLSv1.3'], ciphers: { TLSv1: 'ECDHE-RSA-RC4-SHA' }, certSelfSigned: true } }] } };

test('(q) a reached adapter (011, the TLS scanner) still lands its flags on 443, with its own identity', async () => {
  const rec = (await servicesOf([TLS_011])).find((s) => s.port === 443);
  assert.ok(rec);
  assert.equal(rec.certSelfSigned, true);
  assert.ok(rec.weakProtocols.includes('TLSv1'));
  assert.ok(rec.weakCiphers.length > 0);
  assert.equal(rec.program, 'TLS');
});

test('(q) a plugin with NO adapter still yields its fallback record (001, 006, 013)', async () => {
  const services = await servicesOf([
    { id: '006', name: 'HTTP Probe', result: { up: true, program: 'nginx', version: '1.18.0', dangerousMethods: ['PUT'],
      data: [{ probe_port: 80, probe_protocol: 'tcp', status: 'open' }] } },
  ]);
  const rec = services.find((s) => s.port === 80);
  assert.ok(rec, 'the probe still yields its fallback record');
  assert.equal(rec.source, 'http');
  assert.equal(rec.program, 'nginx');
  // The HTTP probe has no adapter until lane 3 (a4): its dangerous methods still never reach a record.
  assert.equal('dangerousMethods' in rec, false);
});

test('(q) a cloudProvider plugin is EXEMPT — its adapter is never called, and its result falls back as before', async () => {
  let calls = 0;
  const adapters = new Map([['1020', { cloudProvider: 'aws', conclude: () => { calls += 1; return [{ port: null, severity: 'PASS' }]; } }]]);
  const services = await servicesOf([{ id: '1020', name: 'AWS S3 Auditor', result: { up: true, data: [{ probe_port: 0, probe_protocol: 'api' }] } }],
    { adapters });
  assert.equal(calls, 0, 'a cloud adapter emits portless findings that would collapse into one fabricated row');
  assert.ok(services.every((s) => isPort(s.port)), JSON.stringify(services));
});

test('(q) a result that carries NO id still reaches its adapter, by the plugin\'s DECLARED name (callers that pass names only)', async () => {
  const { id, ...nameOnly } = TLS_011; // EE's network-path gate and several CE tests call concluder.run this way
  void id;
  const rec = (await servicesOf([nameOnly])).find((s) => s.port === 443);
  assert.ok(rec, 'the TLS record is concluded');
  assert.equal(rec.certSelfSigned, true, 'by its adapter, not the fallback record');
});

test('(q) an mDNS friendly name still becomes the host name (027)', async () => {
  const c = await concluder.run([{ id: '027', name: 'MDNS Scanner', result: { up: true, data: [{ probe_protocol: 'udp',
    probe_port: 5353, response_banner: JSON.stringify({ txt: { fn: 'MARKER-MDNS' } }) }] } }]);
  assert.equal(c.host.name, 'MARKER-MDNS');
});

// ── (a1) + (a2): every unreached adapter is reached, and what it emits lands ──────────────────────
const cert = { expired: false, daysToExpiry: 90, selfSigned: true, hostnameValid: false, subject: 'CN=MARKER-040',
  issuer: 'CN=x', names: [], validFrom: '', validTo: '', signatureAlgorithm: 'sha256', keyType: 'RSA', keyBits: 2048 };
const auditorResult = (port) => ({ up: true, portResults: [{ port, service: 'https', severity: 'high', certificate: cert,
  negotiation: { protocol: 'TLSv1.2', cipher: 'X', forwardSecrecy: false }, chain: { depth: 1 }, authorized: false,
  issues: [{ severity: 'high', detail: 'hostname mismatch MARKER-040' }, { severity: 'info', detail: 'not actionable' }] }] });

test('014 (NetBIOS/SMB): the null session lands on 445/tcp', async () => {
  const { default: p } = await importPlugin('netbios_scanner.mjs');
  const rec = (await servicesOf([{ id: '014', name: p.name, result: { up: true, nullSessionAllowed: true, shares: ['C$'],
    data: [{ probe_port: 445, probe_protocol: 'tcp', probe_info: 'SMB2 negotiate' }] } }])).find((s) => s.port === 445);
  assert.ok(rec, '445/tcp is concluded');
  assert.equal(rec.nullSessionAllowed, true);
  assert.equal(rec.source, 'netbios');
});

test('024 (SYN scan): its ports land, and a port only it saw is not credited to program "nmap"', async () => {
  const { default: p } = await importPlugin('syn_scanner.mjs');
  const rec = (await servicesOf([{ id: '024', name: p.name, result: { up: true, program: 'nmap',
    data: [{ probe_port: 2222, probe_protocol: 'tcp', status: 'open', service: 'ssh', response_banner: null }] } }]))
    .find((s) => s.port === 2222);
  assert.ok(rec);
  assert.equal(rec.source, 'syn_scanner');
  assert.notEqual(rec.program, 'nmap', 'nmap is the tool that saw the port, not the program listening on it');
});

test('040 (TLS certificate): on a port 011 did not conclude, the audit lands under certAudit', async () => {
  const rec = (await servicesOf([{ id: '040', name: 'TLS Certificate & Cipher Auditor', result: auditorResult(8443) }]))
    .find((s) => s.port === 8443);
  assert.ok(rec, '8443 is concluded');
  assert.equal(rec.source, 'tls-cert-auditor');
  assert.equal(rec.certAudit?.severity, 'high');
  assert.deepEqual(rec.certAudit?.issues, ['hostname mismatch MARKER-040']);
});

test('040 on 011\'s 443: the audit LANDS on the authoritative record and changes none of its identity', async () => {
  const rec = (await servicesOf([TLS_011, { id: '040', name: 'TLS Certificate & Cipher Auditor', result: auditorResult(443) }]))
    .find((s) => s.port === 443);
  assert.equal(rec.certAudit?.severity, 'high', 'reaching is not landing: the merge must carry the namespaced audit');
  assert.equal(rec.program, 'TLS');
  assert.equal(rec.version, null, 'the negotiated protocol is not the service version');
  assert.equal(rec.certSelfSigned, true, '011\'s own flags stay');
});

test('040 with no TLS on any port leaves no service row — its one record has no port and becomes evidence', async () => {
  const c = await concluder.run([{ id: '040', name: 'TLS Certificate & Cipher Auditor', result: { up: true, portResults: [], failedPorts: [] } }]);
  assert.ok(c.services.every((s) => isPort(s.port)), JSON.stringify(c.services));
  assert.ok(c.evidence.some((e) => e.from === 'tls-cert-auditor'), 'it is still recorded, as evidence');
});

const TRIBE = { up: true, overallSeverity: 'critical', summary: { critical: 1, high: 1, medium: 0 }, serverInfo: { name: 'tribe' },
  findings: { auth: [{ severity: 'critical', check: 'no_auth', detail: 'MARKER-050a no auth' }],
    debug: [{ severity: 'high', check: 'debug_endpoint', detail: 'MARKER-050b /debug open' }],
    health: [{ severity: 'pass', check: 'health_ok', detail: 'fine' }] } };

test('050 (debug endpoints): EVERY actionable finding lands on the 8080 record', async () => {
  const rec = (await servicesOf([{ id: '050', name: 'TRIBE v2 Neural API Security Probe', result: TRIBE }])).find((s) => s.port === 8080);
  assert.ok(rec);
  assert.equal(rec.source, 'tribe-health');
  assert.deepEqual(rec.tribeHealth?.findings?.map((f) => f.check).sort(), ['debug_endpoint', 'no_auth']);
  assert.equal(rec.tribeHealth?.severity, 'critical');
});

const DNSSEC = { up: true, overallSeverity: 'high', summary: { actionable: 3 },
  details: { spfRecord: null, dmarcRecord: null, dkimSelectors: [], dnssec: { hasDNSKEY: false } },
  findings: { spf: [{ severity: 'high', check: 'missing_spf', detail: 'MARKER-060a no SPF record' }],
    dmarc: [{ severity: 'high', check: 'missing_dmarc', detail: 'MARKER-060b no DMARC record' }],
    ns: [{ severity: 'medium', check: 'single_ns', detail: 'one NS' }],
    mx: [{ severity: 'pass', check: 'mx_ok', detail: 'fine' }] } };
const DNS_009 = { id: '009', name: 'dns_scanner', result: { up: true, program: 'BIND', version: '9.18',
  data: [{ probe_port: 53, probe_protocol: 'udp', probe_info: 'version.bind' }] } };

test('060 (DNS security) when the scan found a 53/udp service: every actionable finding lands on it, identity untouched', async () => {
  const services = await servicesOf([DNS_009, { id: '060', name: 'DNS Security Auditor', result: DNSSEC }]);
  const rec = services.find((s) => s.port === 53 && s.protocol === 'udp');
  assert.ok(rec);
  assert.deepEqual(rec.dnsSecurity?.findings?.map((f) => f.check).sort(), ['missing_dmarc', 'missing_spf', 'single_ns']);
  assert.equal(rec.program, 'BIND');
  assert.equal(rec.version, '9.18');
  assert.ok(services.every((s) => isPort(s.port)), JSON.stringify(services));
});

test('060 when the scan found NO 53/udp service: no service row is invented — the findings are evidence', async () => {
  const c = await concluder.run([{ id: '060', name: 'DNS Security Auditor', result: DNSSEC }]);
  assert.deepEqual(c.services, [], 'a domain DNS-posture audit is not a port on this host');
  const ev = c.evidence.find((e) => e.from === 'dns-sec-auditor');
  assert.ok(ev, 'it is recorded as evidence');
  assert.equal(ev.dnsSecurity?.findings?.length, 3);
});

// ── (a6) ─────────────────────────────────────────────────────────────────────────────────────────
test('028 (UPnP): the friendlyName becomes the host name and the summary says it', async () => {
  const { default: p } = await importPlugin('upnp_scanner.mjs');
  const c = await concluder.run([{ id: '028', name: p.name, result: { up: true, data: [{ probe_port: 1900, probe_protocol: 'udp',
    response_banner: JSON.stringify({ descriptionXML: '<root><friendlyName>R1</friendlyName></root>' }) }] } }]);
  assert.equal(c.host.name, 'R1');
  assert.match(c.summary, /\(R1\)/);
});

// ── the manager hands the registry down, and a custom plugin cannot capture a built-in id ─────────
test('the PluginManager hands its adapters down: a plugin the concluder\'s own directory does not hold is reached', async () => {
  const { default: concluderPlugin } = await importPlugin('result_concluder.mjs');
  let reached = 0;
  const outsider = { id: '9001', name: 'Outsider Probe', priority: 50, run: async () => ({ up: true }),
    conclude: ({ result }) => { reached += 1; return [{ port: 7777, protocol: 'tcp', service: 'x', status: 'open', source: 'outsider', marker: result.m }]; } };
  const mgr = await PluginManager.create({ plugins: [outsider, concluderPlugin] });
  const out = await mgr.runConcluder([{ id: '9001', name: 'Outsider Probe', result: { up: true, m: 'MARKER-9001' } }]);
  assert.equal(reached, 1);
  assert.equal(out.result.services.find((s) => s.port === 7777)?.marker, 'MARKER-9001');
});

test('a CUSTOM plugin that reuses a built-in id does not capture its adapter', async () => {
  const { default: concluderPlugin } = await importPlugin('result_concluder.mjs');
  const real = (await importPlugin('040_tls_cert_auditor.mjs')).default;
  const evil = { id: '040', name: 'Impostor', priority: 1, _source: 'custom', run: async () => ({}),
    conclude: () => [{ port: 31337, protocol: 'tcp', service: 'evil', status: 'open', source: 'impostor' }] };
  // Both orders: precedence is by SOURCE, so neither "first wins" nor "last wins" may decide it.
  for (const order of [[evil, { ...real, _source: 'ce' }], [{ ...real, _source: 'ce' }, evil]]) {
    const mgr = await PluginManager.create({ plugins: [...order, concluderPlugin] });
    const out = await mgr.runConcluder([{ id: '040', name: real.name, result: auditorResult(8443) }]);
    assert.equal(out.result.services.some((s) => s.source === 'impostor'), false, `order: ${order.map((p) => p.name).join(', ')}`);
    assert.ok(out.result.services.some((s) => s.source === 'tls-cert-auditor'));
  }
});

// ── (a5) THE DERIVED CENSUS ──────────────────────────────────────────────────────────────────────
// For every plugin file that carries an adapter (named `conclude`, or one on the default object), drive the REAL
// manager's runConcluder with a result that records, from the stack of every property read, which plugin files read it.
// The adapter's own file must be among them. Non-vacuity: called directly, the adapter reads the same result.
const CLOUD_EXEMPT = []; // CE ships no cloudProvider plugin; the EE twin derives its 18.
const files = fs.readdirSync(PLUGINS).filter((f) => f.endsWith('.mjs') && f !== 'result_concluder.mjs').sort();

function recordingResult(readers) {
  const seen = (stack) => { for (const f of files) if (stack.includes(`/plugins/${f}:`)) readers.add(f); };
  const handler = { get(t, k, r) { seen(String(new Error().stack)); return Reflect.get(t, k, r); } };
  return new Proxy({ up: true, data: [] }, handler);
}

test('(a5) every adapter is REACHED through the real manager — the set is derived from the plugin directory', async () => {
  // { baseDir } — a bare string is the LEGACY form ('./plugins'), which discovers from its PARENT: driven with ROOT it
  // found no CE plugin and no concluder, so runConcluder returned null and every adapter read as unreached.
  const mgr = await PluginManager.create({ baseDir: ROOT });
  assert.ok(mgr.plugins.some((p) => String(p.id) === '008'), 'positive control: the manager discovered the concluder');
  const withAdapter = [];
  const exempt = [];
  const unreached = [];
  for (const f of files) {
    const mod = await importPlugin(f);
    const p = mod.default;
    if (!p?.id || !p?.name) continue;
    const adapter = typeof mod.conclude === 'function' ? mod.conclude : (typeof p.conclude === 'function' ? p.conclude.bind(p) : null);
    if (!adapter) continue;
    if (p.cloudProvider) { exempt.push(String(p.id)); continue; }
    withAdapter.push(String(p.id));
    const direct = new Set();
    try { await adapter({ host: 'h', result: recordingResult(direct) }); } catch { /* reading is what counts */ }
    assert.ok(direct.has(f), `non-vacuity: plugin ${p.id}'s adapter reads its result when called directly`);
    const viaManager = new Set();
    await mgr.runConcluder([{ id: String(p.id), name: p.name, result: recordingResult(viaManager) }]);
    if (!viaManager.has(f)) unreached.push(`${p.id} (${f})`);
  }
  console.log(`concluder census: ${withAdapter.length} adapters driven (${withAdapter.join(', ')}); cloud-exempt: [${exempt.join(', ')}]`);
  assert.ok(withAdapter.length >= 15, `non-vacuity: ${withAdapter.length} adapters`);
  assert.deepEqual(exempt, CLOUD_EXEMPT, 'the cloud-exempt set is DERIVED — a network plugin cannot be exempted silently');
  assert.deepEqual(unreached, [], 'an adapter the concluder never reaches — its records never land on a service');
});

test('(a5) the same holds without the manager — the concluder\'s own registry reaches them too', async () => {
  const unreached = [];
  for (const f of files) {
    const mod = await importPlugin(f);
    const p = mod.default;
    if (!p?.id || p.cloudProvider || !(typeof mod.conclude === 'function' || typeof p.conclude === 'function')) continue;
    const readers = new Set();
    await concluder.run([{ id: String(p.id), name: p.name, result: recordingResult(readers) }]);
    if (!readers.has(f)) unreached.push(`${p.id} (${f})`);
  }
  assert.deepEqual(unreached, []);
});
