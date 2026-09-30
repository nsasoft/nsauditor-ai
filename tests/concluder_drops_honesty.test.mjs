// WHAT THE CONCLUDER DROPS, PINNED SO THE TEXT THAT STATES IT CANNOT GO STALE (1.2.0 build 3 — the second review round).
//
// `scan_host`, the Markdown / SARIF / CSV reports and `--fail-on` all read the concluder's service records. The concluder
// imports `./<slug of the plugin's NAME>.mjs` and reads its NAMED `conclude` export; anything else falls through to a
// fixed fallback record that keeps port / program / version / banner and drops every other field. MEASURED: six adapters
// exist and are never reached — 014 and 024 by name, 040 / 050 / 060 by name AND because their `conclude` sits on the
// default object, and Enterprise's 1023 — and the HTTP probe (006) has no adapter, so its dangerous-methods result never
// reaches a service record. Build 3 STATES this (operator ruling: honest text now, behaviour in 1.2.1).
//
// PINNED, NOT ENDORSED: when 1.2.1 reaches these adapters, the legs below go red, and the scan_host description, the
// Markdown Scope line, the README rows, `--help` and the skill must be re-stated in the same commit.
//
// FOURTH QUADRANT FIRST: an adapter the concluder DOES reach still lands its flags on the service record.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import concluder, { slugify } from '../plugins/result_concluder.mjs';

const PLUGINS = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', 'plugins');
const conclude = async (results) => (await concluder.run(results)).services ?? [];

// ── FOURTH QUADRANT ──────────────────────────────────────────────────────────────────────────────
test('(q) a reached adapter (070, the MCP scanner) still lands its flags on the service record', async () => {
  const services = await conclude([{ id: '070', name: 'MCP Scanner', result: { up: true, mcpDetections: [{
    port: 3000, cwe: [], owasp: [], mitre: [], flags: { mcpAnonymousAccess: true },
    detection: { protocolVersion: '2024-11-05', scheme: 'http', serverInfo: {}, path: '/mcp', authRequired: false,
      ssePresent: false, tools: [] } }] } }]);
  const rec = services.find((s) => s.port === 3000);
  assert.ok(rec, 'the MCP record is concluded');
  assert.equal(rec.mcpAnonymousAccess, true);
});

// ── PINNED, NOT ENDORSED ─────────────────────────────────────────────────────────────────────────
test('PINNED: the HTTP probe\'s dangerous methods never reach a service record (006 has no adapter)', async () => {
  const services = await conclude([
    { id: '006', name: 'HTTP Probe', result: { up: true, program: 'nginx', dangerousMethods: ['PUT', 'DELETE'],
      data: [{ probe_port: 80, probe_protocol: 'tcp', status: 'open' }] } },
  ]);
  assert.ok(services.length > 0, 'the probe still yields a (fallback) record — the leg is not vacuous');
  assert.deepEqual(services.filter((s) => 'dangerousMethods' in s), [],
    'if this moved, re-state what scan_host, the Markdown, SARIF and --fail-on say about dangerous HTTP methods');
});

// ── THE FIVE UNREACHED ADAPTERS, DRIVEN (the architect seat's refutation of this file's first census leg) ───────────
// The first version RE-MODELLED the concluder's resolution (slugify → existsSync → typeof conclude) instead of running it,
// so it pinned the MODEL of the defect: the seat simulated the full 1.2.1 fix and the leg stayed green. Each plugin is now
// DRIVEN through concluder.run with a result its OWN adapter turns into records, and the leg asserts the adapter's
// signature — its `source`, never the fallback record's, plus a marker planted where only the adapter reads — is ABSENT.
// Non-vacuity: the same result through the adapter itself carries both. Reaching an adapter flips its own leg red.
const adapterOf = (mod) => (typeof mod.conclude === 'function' ? mod.conclude : mod.default.conclude.bind(mod.default));
const everySource = (x, acc = new Set()) => {
  if (Array.isArray(x)) x.forEach((v) => everySource(v, acc));
  else if (x && typeof x === 'object') { if (typeof x.source === 'string') acc.add(x.source); Object.values(x).forEach((v) => everySource(v, acc)); }
  return acc;
};
const cert = { expired: false, daysToExpiry: 90, selfSigned: true, hostnameValid: false, subject: 'CN=MARKER-040',
  issuer: 'CN=x', names: [], validFrom: '', validTo: '', signatureAlgorithm: 'sha256', keyType: 'RSA', keyBits: 2048 };
const DRIVES = {
  '040': { file: '040_tls_cert_auditor.mjs', marker: 'MARKER-040', result: { up: true, portResults: [{ port: 8443,
    service: 'https', severity: 'high', certificate: cert, negotiation: { protocol: 'TLSv1.2', cipher: 'X', forwardSecrecy: false },
    chain: { depth: 1 }, authorized: false, issues: [{ severity: 'high', detail: 'hostname mismatch MARKER-040' }] }] } },
  '050': { file: '050_tribe_health.mjs', marker: 'MARKER-050', result: { up: true, overallSeverity: 'high',
    summary: { critical: 0, high: 1, medium: 0 }, serverInfo: { name: 'MARKER-050' },
    findings: { debug: [{ severity: 'high', check: 'debug_endpoint', detail: 'MARKER-050 /debug open' }] } } },
  '060': { file: '060_dns_sec_auditor.mjs', marker: 'MARKER-060', result: { up: true, overallSeverity: 'high',
    summary: { actionable: 1 }, details: { spfRecord: null, dmarcRecord: null, dkimSelectors: [], dnssec: { hasDNSKEY: false } },
    findings: { spf: [{ severity: 'high', check: 'missing_spf', detail: 'MARKER-060 no SPF record' }] } } },
  '014': { file: 'netbios_scanner.mjs', marker: 'MARKER-014', result: { up: true, nullSessionAllowed: true,
    shares: ['MARKER-014'], data: [{ probe_port: 445, probe_protocol: 'tcp', probe_info: 'SMB2 negotiate' }] } },
  // 024: the fallback record copies response_banner, so the marker would leak — the `source` signature carries it alone.
  '024': { file: 'syn_scanner.mjs', marker: null, result: { up: true, program: 'nmap',
    data: [{ probe_port: 22, probe_protocol: 'tcp', status: 'open', service: 'ssh', response_banner: 'x' }] } },
};

for (const [id, d] of Object.entries(DRIVES)) {
  test(`PINNED: plugin ${id}'s adapter is never reached — driven through concluder.run, its records are absent`, async () => {
    const mod = await import(pathToFileURL(path.join(PLUGINS, d.file)).href);
    assert.equal(String(mod.default.id), id, `${d.file} is plugin ${id}`);
    const own = await adapterOf(mod)({ host: 'h', result: d.result });
    const sig = [...everySource(own)];
    assert.equal(sig.length, 1, `non-vacuity: plugin ${id}'s adapter emits records under one source (${sig})`);
    if (d.marker) assert.match(JSON.stringify(own), new RegExp(d.marker), 'non-vacuity: the adapter carries the marker');
    const concluded = await concluder.run([{ id, name: mod.default.name, result: d.result }]);
    // (040 and 050's fallback records land on port 0 and are dropped, so a fallback record is NOT required here; the
    // leg's power is the adapter's own output above, and the full-fix mutant that turns each of these five red.)
    assert.ok(Array.isArray(concluded?.services), 'the concluder ran to a conclusion');
    assert.equal(everySource(concluded).has(sig[0]), false,
      `plugin ${id}'s adapter was REACHED (source "${sig[0]}") — re-state the scan_host description, the Markdown Scope line, the README and the skill`);
    if (d.marker) assert.doesNotMatch(JSON.stringify(concluded), new RegExp(d.marker));
  });
}

test('ENUMERATION, not the pin: every adapter the name-slug model predicts unreached is DRIVEN above', async () => {
  const predicted = [];
  let withAdapter = 0;
  for (const f of fs.readdirSync(PLUGINS).filter((x) => x.endsWith('.mjs')).sort()) {
    const mod = await import(pathToFileURL(path.join(PLUGINS, f)).href);
    const p = mod.default;
    if (!p || typeof p !== 'object' || !('name' in p)) continue;
    if (typeof mod.conclude !== 'function' && typeof p.conclude !== 'function') continue;
    withAdapter += 1;
    const target = path.join(PLUGINS, `${slugify(p.name, p.id)}.mjs`);
    const reached = fs.existsSync(target) && typeof (await import(pathToFileURL(target).href)).conclude === 'function';
    if (!reached) predicted.push(String(p.id));
  }
  assert.ok(withAdapter >= 10, `non-vacuity: ${withAdapter} plugins carry an adapter`);
  const undriven = predicted.filter((id) => !(id in DRIVES));
  assert.deepEqual(undriven, [], `a plugin whose adapter looks unreached has no drive above: ${undriven.join(', ')}`);
});
