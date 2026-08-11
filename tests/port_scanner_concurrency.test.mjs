/**
 * THE PORT SCANNER MUST FINISH INSIDE THE ORCHESTRATOR'S BUDGET.
 *
 * ── THE DEFECT THIS PINS, measured end to end on 2026-08-10 ─────────────────────────────
 * Against a real router (192.168.1.1, ports 80 and 443 demonstrably open — `nc` connects,
 * `curl` returns 401), a full `--plugins all` scan reported the port scanner as
 * `up:false, tcpOpen:[]`, and `HTTP Probe` / `Webapp Detector` never ran at all.
 *
 * The plugin was not wrong. Called directly it returns `up:true` with
 * `tcpOpen:[80,21,53,443,631,1990,20005,5000,5555]` — but it takes **40,977 ms**, because it
 * probes the 50 configured ports (43 TCP + 7 UDP) ONE AT A TIME, and a filtered or silent
 * port costs the full per-port timeout. `PLUGIN_TIMEOUT_MS` defaults to 30,000, so
 * `_runOne`'s `Promise.race` loses and the orchestrator DISCARDS a correct result that
 * arrives eleven seconds later.
 *
 * ⚠️ WHY THIS IS A FALSE CLEAN AND NOT MERELY SLOWNESS. The discarded result is replaced by
 * an empty one, `ctx.tcpOpen` stays empty, and every plugin gated on `tcp_open` is then
 * skipped by `plugin_manager.mjs`'s bare `return false` — silently, with no finding and no
 * evidence gap. The compliance layer then reports PASS controls off a scan that never probed
 * HTTP. A scan whose port discovery timed out became indistinguishable, in the artifact and
 * in the report, from a host with nothing listening.
 *
 * ── WHY THE TIMING ASSERTION IS A REAL MEASUREMENT AND NOT A FLAKE ──────────────────────
 * Every probe here targets TEST-NET-1 (192.0.2.0/24, RFC 5737 — reserved for documentation
 * and guaranteed not to be routed), so every port takes the FULL per-port timeout. That
 * makes the sequential cost exactly `n * timeoutMs` by construction rather than by luck.
 * With n=16 and timeoutMs=250, sequential is >= 4,000 ms and bounded-concurrency is roughly
 * one or two batches. The bound below is deliberately loose — it fails only if the scan is
 * effectively serial, which is the defect, and cannot fail merely because a machine is busy.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import plugin from '../plugins/port_scanner.mjs';

const UNROUTABLE = '192.0.2.1';      // RFC 5737 TEST-NET-1
const N = 16;
const PER_PORT_TIMEOUT_MS = 250;
const SEQUENTIAL_FLOOR_MS = N * PER_PORT_TIMEOUT_MS;   // 4,000 ms

test('a full port sweep runs CONCURRENTLY, not one port at a time', async () => {
  const ports = Array.from({ length: N }, (_, i) => 9000 + i);
  const started = Date.now();
  const r = await plugin.run(UNROUTABLE, 0, { tcpPorts: ports, timeoutMs: PER_PORT_TIMEOUT_MS });
  const elapsed = Date.now() - started;

  // NON-VACUITY: the sweep must actually have probed every port. Without this the timing
  // assertion would pass trivially for a scanner that returned early and probed nothing —
  // which is precisely the shape of the bug being fixed.
  assert.equal(r.data.length, N,
    `expected ${N} probe rows, got ${r.data.length}. A fast run that probed nothing would ` +
    'satisfy the timing bound below while being the very defect it is meant to catch.');

  assert.ok(elapsed < SEQUENTIAL_FLOOR_MS * 0.6,
    `the sweep took ${elapsed}ms for ${N} unroutable ports at ${PER_PORT_TIMEOUT_MS}ms each. ` +
    `Sequential probing costs at least ${SEQUENTIAL_FLOOR_MS}ms by construction, so this is ` +
    'serial. Against the 50 configured ports that overruns PLUGIN_TIMEOUT_MS and the ' +
    'orchestrator throws away a correct result, reporting an empty scan instead.');
});

test('the DEFAULT sweep fits inside the orchestrator budget it actually runs under', async () => {
  // The regression that shipped was not "slow" in the abstract — it was slower than the
  // budget the caller enforces. That relationship is what this asserts, using the same
  // default the plugin manager uses, so a future change to either side re-tests the pair.
  const PLUGIN_TIMEOUT_MS = Number(process.env.PLUGIN_TIMEOUT_MS || 30000);
  const ports = Array.from({ length: 43 }, (_, i) => 9100 + i);   // the shipped TCP count
  const started = Date.now();
  const r = await plugin.run(UNROUTABLE, 0, { tcpPorts: ports, timeoutMs: PER_PORT_TIMEOUT_MS });
  const elapsed = Date.now() - started;

  assert.equal(r.data.length, 43, 'every configured port must be probed');
  assert.ok(elapsed < PLUGIN_TIMEOUT_MS / 2,
    `a worst-case sweep of the shipped port count took ${elapsed}ms against a ` +
    `${PLUGIN_TIMEOUT_MS}ms plugin budget. Half the budget is the margin, because the real ` +
    'run also pays DNS, banner reads and the UDP leg on top of this.');
});

test('concurrency does not reorder or drop results — every probed port is reported once', async () => {
  const ports = [9200, 9201, 9202, 9203, 9204, 9205];
  const r = await plugin.run(UNROUTABLE, 0, { tcpPorts: ports, timeoutMs: PER_PORT_TIMEOUT_MS });
  const seen = r.data.filter((d) => d.probe_protocol === 'tcp').map((d) => d.probe_port);
  assert.deepEqual([...seen].sort((a, b) => a - b), ports,
    'a concurrent sweep must still account for every port exactly once — dropping one is a ' +
    'silent false negative, and duplicating one inflates the evidence');
});

/**
 * ── THE SECOND, INDEPENDENT DEFECT: THE DEFAULT PORT LIST WAS RESOLVED FROM `process.cwd()` ──
 *
 * `loadConfigPortsFromServicesJson(cwd = process.cwd())` read `<cwd>/config/services.json`, and a
 * bare `catch {}` swallowed the miss. A globally installed CLI runs from wherever the OPERATOR
 * happens to be, so unless that directory contained a `config/services.json`, the port list came
 * back empty, the early return fired, and the scan reported `up:false` with every bucket empty —
 * in ONE MILLISECOND, having probed nothing.
 *
 * Measured 2026-08-10 on the installed build:
 *   cwd=/private/tmp (no ./config)  ->    1 ms,  0 rows, up:false
 *   cwd=<package dir> (has ./config) -> 4,243 ms, 50 rows, up:true, tcpOpen:[80,21,53,443,…]
 *
 * This is the defect that actually reached the smoke test, and it is the more serious of the
 * two: the sweep being slow is a performance bug, but a scanner whose default target list
 * silently empties itself for every customer who installs from npm is a FALSE CLEAN shipped to
 * everyone. The package's own data must be found relative to the PACKAGE, never to the caller.
 */
test('the default port list is found relative to the PACKAGE, not the caller\'s cwd', async (t) => {
  const cwd0 = process.cwd();
  const os = await import('node:os');
  const fs = await import('node:fs');
  const tmp = fs.mkdtempSync(`${os.tmpdir()}/nsa-cwd-`);
  try {
    process.chdir(tmp);                       // a directory with no ./config, like any user's
    const r = await plugin.run('192.0.2.1', 0, { timeoutMs: 60 });
    assert.ok(r.data.length > 0,
      'the scanner probed ZERO ports because it could not find its own config/services.json ' +
      'from the caller\'s cwd. Installed globally that is every run a customer makes, and it ' +
      'reports up:false with empty buckets — indistinguishable from a host with nothing open.');
    assert.ok(r.data.length >= 40,
      `expected the shipped ~50-port default set, got ${r.data.length}`);
  } finally {
    process.chdir(cwd0);
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

/**
 * ── R-MEDIUM, FOUND BY REVIEW: THE OVERRIDE COMMITTED ON *READ*, NOT ON *YIELD* ──────────
 *
 * The first fix tried cwd then the package and `break`s on the first file that READS. But
 * `config/services.json` is a common filename. If the caller's directory holds a FOREIGN one
 * — another application's, or an empty/typo'd nsauditor one (`{}`, `{"services":[]}`) —
 * `JSON.parse` succeeds, neither schema branch populates anything, **the package floor is
 * never read**, and the loader returns an empty set. Empty → early return → `up:false` →
 * every `tcp_open`-gated plugin skipped.
 *
 * The same false clean as the headline defect, re-gated on a filename collision instead of a
 * missing file — and the previous comment's promise that "a scan can no longer fall through
 * to nothing" was FALSE in exactly this case, which is its own small honesty defect.
 *
 * Repro measured before the fix: `mkdir -p /tmp/x/config; echo '{"other":"app"}' >
 * /tmp/x/config/services.json; cd /tmp/x` → 0 rows, up:false.
 *
 * The rule is therefore YIELD, not READ: an override counts only if it produces ports.
 */
test('a FOREIGN config/services.json in cwd must not shadow the package floor', async () => {
  const os = await import('node:os');
  const fs = await import('node:fs');
  const path = await import('node:path');
  const cwd0 = process.cwd();
  const tmp = fs.mkdtempSync(`${os.tmpdir()}/nsa-collide-`);
  fs.mkdirSync(path.join(tmp, 'config'), { recursive: true });
  try {
    for (const [label, body] of [['foreign app', '{"other":"app"}'],
                                 ['empty object', '{}'],
                                 ['empty services', '{"services":[]}']]) {
      fs.writeFileSync(path.join(tmp, 'config', 'services.json'), body);
      process.chdir(tmp);
      const r = await plugin.run('192.0.2.1', 0, { timeoutMs: 60 });
      assert.ok(r.data.length >= 40,
        `a ${label} config in cwd yielded ${r.data.length} probes — it shadowed the package's ` +
        'own port set and the scan probed nothing. An override counts only if it YIELDS ports.');
    }
  } finally {
    process.chdir(cwd0);
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('a VALID cwd override still wins — the documented behaviour is preserved', async () => {
  const os = await import('node:os');
  const fs = await import('node:fs');
  const path = await import('node:path');
  const cwd0 = process.cwd();
  const tmp = fs.mkdtempSync(`${os.tmpdir()}/nsa-override-`);
  fs.mkdirSync(path.join(tmp, 'config'), { recursive: true });
  fs.writeFileSync(path.join(tmp, 'config', 'services.json'),
    JSON.stringify({ services: [{ port: 9999, protocol: 'tcp' }] }));
  try {
    process.chdir(tmp);
    const r = await plugin.run('192.0.2.1', 0, { timeoutMs: 60 });
    assert.equal(r.data.length, 1, 'a non-empty override must REPLACE the package set, not merge');
    assert.equal(r.data[0].probe_port, 9999);
  } finally {
    process.chdir(cwd0);
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});
