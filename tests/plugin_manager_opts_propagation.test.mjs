// tests/plugin_manager_opts_propagation.test.mjs
//
// N.27 regression: pm.run(host, plugins, opts) MUST forward opts to plugin.run().
//
// Pre-fix v0.1.21: plugin_manager._runOrchestrated() called callPlugin() without
// forwarding the CLI-derived opts. callPlugin's runWithCtx then constructed a
// fresh `{ context, ...extra }` opts for plugin.run(), dropping --ports and any
// other CLI flag value. Result: opts.ports parsed at the CLI never reached the
// port_scanner. Bug discovered live during 192.168.1.28:8090 MCP endpoint test.
//
// This test catches the bug class by passing a unique opts.ports string through
// pm.run() and asserting the receiving fake plugin sees it.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { PluginManager } from '../plugin_manager.mjs';

/**
 * Build a PluginManager seeded (via test-injection path) with a pre-step plugin
 * that marks the host as up + a spy plugin that records every opts it receives.
 */
async function makePmWithSpyPlugin(spy) {
  const plugins = [
    {
      id: 'PRE',
      name: 'Pre-step (mark up)',
      priority: 10,
      runStrategy: 'single',
      protocols: [],
      ports: [],
      async run() { return { up: true, type: 'host-up', os: null }; },
    },
    {
      id: 'SPY',
      name: 'Spy Plugin',
      priority: 50,
      runStrategy: 'single',
      protocols: [],
      ports: [],
      requirements: { host: 'up' },
      async run(host, port, opts) {
        spy.calls.push({ host, port, opts });
        return { up: true, data: [], type: 'spy' };
      },
    },
  ];
  return PluginManager.create({ plugins });
}

test('N.27: opts.ports propagates from pm.run to plugin.run via orchestrator', async () => {
  const spy = { calls: [] };
  const pm = await makePmWithSpyPlugin(spy);

  await pm.run('127.0.0.1', 'all', { ports: '8090,9090/udp' });

  assert.equal(spy.calls.length, 1, 'spy plugin should be invoked exactly once');
  const opts = spy.calls[0].opts;
  assert.ok(opts, 'opts must be defined on the plugin call');
  assert.equal(opts.ports, '8090,9090/udp', 'opts.ports must be forwarded verbatim');
});

test('N.27: opts that have no ports field still works (no regression)', async () => {
  const spy = { calls: [] };
  const pm = await makePmWithSpyPlugin(spy);

  await pm.run('127.0.0.1', 'all', {});

  assert.equal(spy.calls.length, 1);
  const opts = spy.calls[0].opts;
  // ports should be undefined; orchestration fields (context) should still be present
  assert.equal(opts.ports, undefined);
  assert.ok(opts.context, 'context must still be injected');
});

test('N.27: arbitrary CLI-style opts forward without colliding with context', async () => {
  const spy = { calls: [] };
  const pm = await makePmWithSpyPlugin(spy);

  await pm.run('127.0.0.1', 'all', {
    ports: '5000',
    insecureHttps: true,
    customField: 'abc123',
  });

  const opts = spy.calls[0].opts;
  assert.equal(opts.ports, '5000');
  assert.equal(opts.insecureHttps, true);
  assert.equal(opts.customField, 'abc123');
  assert.ok(opts.context, 'context still injected');
  // Specifically: cliOpts must NOT clobber context (the spread order is
  // { ...cliOpts, context: ..., ...extra } so context wins)
  assert.notEqual(opts.context, 'abc123');
});

test('N.27: opts with `context` field cannot clobber orchestrator context', async () => {
  const spy = { calls: [] };
  const pm = await makePmWithSpyPlugin(spy);

  // Caller maliciously passes a context field that would override the orchestrator's
  await pm.run('127.0.0.1', 'all', { context: 'EVIL_OVERRIDE' });

  const opts = spy.calls[0].opts;
  assert.notEqual(opts.context, 'EVIL_OVERRIDE',
    'orchestrator context must always win over caller-supplied context');
  assert.equal(typeof opts.context, 'object',
    'context must remain the orchestrator-built object, not the string override');
});
