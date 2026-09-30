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

test('PINNED: the set of CE adapters the concluder never reaches is exactly 014, 024, 040, 050, 060', async () => {
  const unreached = [];
  let withAdapter = 0;
  for (const f of fs.readdirSync(PLUGINS).filter((x) => x.endsWith('.mjs')).sort()) {
    const mod = await import(pathToFileURL(path.join(PLUGINS, f)).href);
    const p = mod.default;
    if (!p || typeof p !== 'object' || !('name' in p)) continue;
    if (typeof mod.conclude !== 'function' && typeof p.conclude !== 'function') continue;
    withAdapter += 1;
    const target = path.join(PLUGINS, `${slugify(p.name, p.id)}.mjs`);
    const reached = fs.existsSync(target) && typeof (await import(pathToFileURL(target).href)).conclude === 'function';
    if (!reached) unreached.push(String(p.id));
  }
  assert.ok(withAdapter >= 10, `non-vacuity: ${withAdapter} plugins carry an adapter`);
  assert.deepEqual(unreached.sort(), ['014', '024', '040', '050', '060'],
    'if this moved, re-state the dropped plugins in the scan_host description, the Markdown Scope line and the skill');
});
