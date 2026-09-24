// O1(b) — 028 and 070 DECLARE their budgets (CE 0.2.55, EE 1.1.0 build 6), asserted in the repo that
// owns them. Both timed out at the 30 s global default on every network scan in the evidence since
// EE 0.44.0, so on a customer's default-budget scan their surfaces read not-measured.
//
// The EVIDENCE rule — declared ≥ 1.5 × the measured maximum, and only where the evidence says a
// declaration is needed — lives in EE's `tests/plugin_declared_budget_census.test.mjs`, beside the
// evidence tree it reads. What this file pins is what CE can derive on its own:
//   · both declarations sit above the default and inside the ceiling, and resolve to themselves;
//   · a caller wall still binds them;
//   · 070's declaration covers the STRUCTURAL cost every target incurs — its static candidate ports ×
//     its probe paths × its default probe timeout — read from the plugin's own exports and source, so
//     a port or a path added without the budget growing fails here.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import { PLUGIN_TIMEOUT_CEILING_MS, resolvePluginTimeoutMs } from '../plugin_manager.mjs';
import upnp from '../plugins/upnp_scanner.mjs';
import mcp, { MCP_CANDIDATE_PORTS, MCP_PROBE_PATHS } from '../plugins/mcp_scanner.mjs';

const PM_SRC = fs.readFileSync(fileURLToPath(new URL('../plugin_manager.mjs', import.meta.url)), 'utf8');
const DEFAULT = Number((/const PLUGIN_TIMEOUT_MS = Number\(process\.env\.PLUGIN_TIMEOUT_MS \|\| (\d+)\)/.exec(PM_SRC) ?? [])[1]);

test('the shipped default is read from the manager\'s source, not assumed', () => {
  assert.ok(Number.isFinite(DEFAULT) && DEFAULT > 0, 'could not read PLUGIN_TIMEOUT_MS\'s shipped default from plugin_manager.mjs');
});

for (const [label, plugin] of [['028 (UPnP)', upnp], ['070 (MCP)', mcp]]) {
  test(`${label} declares a budget above the default and inside the ceiling, and the manager honours it`, () => {
    assert.ok(Number.isFinite(plugin.timeoutMs), `${label} must declare a numeric timeoutMs; got ${JSON.stringify(plugin.timeoutMs)}`);
    assert.ok(plugin.timeoutMs > DEFAULT, `a declaration at or under the ${DEFAULT} ms default buys nothing; got ${plugin.timeoutMs}`);
    assert.ok(plugin.timeoutMs <= PLUGIN_TIMEOUT_CEILING_MS, `above the ceiling the manager clamps, so ${plugin.timeoutMs} would not be the budget it gets`);
    assert.equal(resolvePluginTimeoutMs(plugin, undefined), plugin.timeoutMs, 'the CLI network path names no caller wall');
    assert.equal(resolvePluginTimeoutMs(plugin, 25000), 25000, 'a caller wall still binds over the declaration');
  });
}

test('070\'s declaration covers the structural cost every target incurs — derived from its exports', () => {
  const src = fs.readFileSync(fileURLToPath(new URL('../plugins/mcp_scanner.mjs', import.meta.url)), 'utf8');
  const probeMs = Number((/MCP_PROBE_TIMEOUT_MS \?\? (\d+)/.exec(src) ?? [])[1]);
  assert.ok(Number.isFinite(probeMs) && probeMs > 0, 'could not read the default probe timeout from mcp_scanner.mjs');
  const floor = MCP_CANDIDATE_PORTS.length * MCP_PROBE_PATHS.length * probeMs;
  assert.ok(floor > 0);
  assert.ok(mcp.timeoutMs >= floor,
    `the static candidate ports alone (${MCP_CANDIDATE_PORTS.length} × ${MCP_PROBE_PATHS.length} paths × ${probeMs} ms = ${floor} ms) `
    + `exceed the ${mcp.timeoutMs} ms declaration — a probe added without the budget growing`);
});
