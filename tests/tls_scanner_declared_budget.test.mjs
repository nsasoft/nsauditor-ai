// tests/tls_scanner_declared_budget.test.mjs
//
// 011's DECLARED BUDGET, DRIVEN — what one port that accepts TCP and never answers costs the OTHER ports.
//
// 011 walks its ports one after another and, on each port, its four protocol versions one after another, each attempt
// bounded by TLS_SCANNER_TIMEOUT_MS (8 s by default). A port that accepts the connection and never sends a byte
// therefore costs 4 × 8 = 32 s by construction. Under the 30 s default that is more than the whole plugin's budget, so
// the plugin times out and reads not-measured AS A WHOLE — the ports it had already measured are lost with it. The
// declaration exists so that ONE such port is recorded as a transport failure and the other ports' results survive.
//
// Everything here is real: real node:tls against a real local TLS server, a real listener that accepts and stays
// silent, the real 8 s per-attempt default, and the real budget enforcement in PluginManager._runOne. Three arms run
// concurrently (~45 s of wall clock), each with its own question:
//   (a) under the plugin's OWN declaration, one hung port beside an answering one: the answering port's result
//       survives and the hung port is recorded as a transport failure (ETIMEDOUT) — the declaration's purpose;
//   (b) the SAME fixture under the 30 s default: the plugin reads not-measured as a whole — the control that proves the
//       fixture hangs long enough to matter, so (a) cannot pass on a fixture that never hangs;
//   (c) the STATED LIMIT, under the plugin's own declaration: two hung ports (64 s) still exceed it, and the plugin
//       reads not-measured as a whole, as before. If the budget is ever raised past that, this arm goes red and the
//       limit stated beside the declaration has to be re-read.
import { test, describe, after } from 'node:test';
import assert from 'node:assert/strict';
import tls from 'node:tls';
import net from 'node:net';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';

// The real defaults, not stand-ins: no per-attempt override, no version override, no global budget override.
delete process.env.TLS_SCANNER_TIMEOUT_MS;
delete process.env.TLS_SCANNER_VERSIONS;
delete process.env.PLUGIN_TIMEOUT_MS;
process.env.TLS_SCANNER_SNI = 'localhost'; // no reverse-DNS lookup; matches the certificate's CN

// Imported AFTER the deletes: plugin_manager reads PLUGIN_TIMEOUT_MS from the environment at load.
const { PluginManager, resolvePluginTimeoutMs, PLUGIN_TIMEOUT_MS } = await import('../plugin_manager.mjs');
const { default: tlsScanner } = await import('../plugins/tls_scanner.mjs');

function makeCert() {
  try {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-tls-budget-'));
    const key = path.join(dir, 'k.pem');
    const cert = path.join(dir, 'c.pem');
    execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-keyout', key, '-out', cert, '-days', '2',
      '-nodes', '-subj', '/CN=localhost/O=NSAuditorTest'], { stdio: 'ignore' });
    return { key: fs.readFileSync(key), cert: fs.readFileSync(cert) };
  } catch {
    return null;
  }
}

const material = makeCert();
const servers = [];
const silentSockets = new Set();

async function listen(server) {
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  servers.push(server);
  return server.address().port;
}

/** A listener that accepts every TCP connection and never sends a byte. */
async function hangPort() {
  const server = net.createServer((s) => { silentSockets.add(s); s.on('error', () => {}); s.on('close', () => silentSockets.delete(s)); });
  return listen(server);
}

after(() => {
  for (const s of silentSockets) s.destroy();
  for (const s of servers) s.close();
});

/** Run 011 through the manager's real budget enforcement with `ports` as its port map. TLS_SCANNER_PORTS is read in
 *  run()'s synchronous head, before its first await, so swapping it around the call cannot leak into a concurrent arm. */
async function drive(mod, ports) {
  const plugin = {
    ...mod,
    run(host, port, opts) {
      const prev = process.env.TLS_SCANNER_PORTS;
      process.env.TLS_SCANNER_PORTS = ports.map(([p, svc]) => `${p}:${svc}`).join(',');
      try { return mod.run(host, port, opts); } finally {
        if (prev === undefined) delete process.env.TLS_SCANNER_PORTS; else process.env.TLS_SCANNER_PORTS = prev;
      }
    },
  };
  const mgr = await PluginManager.create({ plugins: [plugin] });
  const t0 = Date.now();
  const out = await mgr._runOne(plugin, '127.0.0.1', 0, {});
  return { out, ms: Date.now() - t0, budget: resolvePluginTimeoutMs(plugin, undefined, PLUGIN_TIMEOUT_MS) };
}

describe('011 declared budget — one hung port beside an answering one', { concurrency: 3 }, async () => {
  if (!material) {
    if (process.env.CI) assert.fail('openssl is required to build the answering TLS server — refusing to skip in CI');
    test('skipped: openssl unavailable (would hard-fail in CI)', (t) => t.skip());
    return;
  }
  const answering = tls.createServer({ key: material.key, cert: material.cert }, (s) => { try { s.end(); } catch { /* ignore */ } });
  answering.on('tlsClientError', () => { /* the TLSv1 / TLSv1.1 attempts are refused by design */ });
  const live = await listen(answering);
  const hungA = await hangPort();
  const hungB = await hangPort();
  // The answering port comes FIRST, so a plugin-level timeout throws away a result that was already measured.
  const oneHung = [[live, 'https'], [hungA, 'tls-hang']];
  const twoHung = [[live, 'https'], [hungA, 'tls-hang'], [hungB, 'tls-hang']];

  test('(a) under its own declaration, the answering port survives and the hung port is a transport failure', async () => {
    const { out, ms, budget } = await drive(tlsScanner, oneHung);
    assert.equal(budget, tlsScanner.timeoutMs, 'the arm must run under the plugin\'s own declaration');
    assert.ok(!out.result.timedOut, `011 timed out after ${ms} ms under its ${budget} ms budget — one hung port cost the whole plugin`);
    assert.equal(out.result.up, true);
    const rows = new Map(out.result.data.map((r) => [r.probe_port, r]));
    assert.equal(rows.get(live)?.tlsEvidence?.tls, true, 'the answering port\'s handshake result must survive');
    assert.match(String(rows.get(live)?.probe_info), /TLS: /);
    assert.equal(rows.get(hungA)?.tlsEvidence?.tls, false);
    // The row LEADS with its transport class (the field the Enterprise input-gap check reads); SNI follows it here.
    assert.equal(String(rows.get(hungA)?.probe_info).split(' | ')[0], 'ETIMEDOUT',
      `the hung port is recorded by its transport class; got ${JSON.stringify(rows.get(hungA)?.probe_info)}`);
    assert.ok(ms >= 31_000, `the fixture must actually hang (4 versions × 8 s); the run took ${ms} ms`);
  });

  test('(b) the same fixture under the 30 s default reads not-measured as a whole — the fixture hangs', async () => {
    const { timeoutMs: _declared, ...undeclared } = tlsScanner;
    const { out, budget } = await drive(undeclared, oneHung);
    assert.equal(PLUGIN_TIMEOUT_MS, 30_000, 'this arm is the 30 s default the declaration is measured against');
    assert.equal(budget, PLUGIN_TIMEOUT_MS);
    assert.equal(out.result.timedOut, true, 'one hung port must exceed the default — otherwise (a) proves nothing');
    assert.equal(out.result.up, false);
    assert.match(String(out.result.error), new RegExp(`timed out after ${PLUGIN_TIMEOUT_MS}ms`));
    assert.deepEqual(out.result.data, [], 'the answering port\'s already-measured result is lost with the plugin');
  });

  test('(c) the stated limit: two hung ports still exceed the declaration and read not-measured as a whole', async () => {
    const { out, budget } = await drive(tlsScanner, twoHung);
    assert.equal(budget, tlsScanner.timeoutMs);
    assert.equal(out.result.timedOut, true, `two hung ports (64 s) must exceed the ${budget} ms declaration — if they no longer do, re-read the limit stated beside it`);
    assert.match(String(out.result.error), new RegExp(`timed out after ${budget}ms`));
    assert.deepEqual(out.result.data, []);
  });
});
