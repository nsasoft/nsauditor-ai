import test from 'node:test';
import assert from 'node:assert/strict';

import { createScheduler } from '../utils/scheduler.mjs';

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/** Immediate-resolving scan function that records calls. */
function mockScanFn(callLog) {
  return async (host) => {
    callLog.push(host);
    return { host, status: 'ok' };
  };
}

// ---------------------------------------------------------------------------
// createScheduler — validation
// ---------------------------------------------------------------------------

test('createScheduler throws on missing intervalMs', () => {
  assert.throws(
    () => createScheduler({ hosts: ['a'], scanFn: async () => ({}) }),
    /intervalMs/,
  );
});

test('createScheduler throws on empty hosts', () => {
  assert.throws(
    () => createScheduler({ intervalMs: 1000, hosts: [], scanFn: async () => ({}) }),
    /hosts/,
  );
});

test('createScheduler throws on missing scanFn', () => {
  assert.throws(
    () => createScheduler({ intervalMs: 1000, hosts: ['a'] }),
    /scanFn/,
  );
});

// ---------------------------------------------------------------------------
// isRunning
// ---------------------------------------------------------------------------

test('isRunning reflects start/stop state', async () => {
  const s = createScheduler({
    intervalMs: 100_000, // very long so interval doesn't fire
    hosts: ['h1'],
    scanFn: async () => ({}),
  });

  assert.equal(s.isRunning(), false);
  s.start();
  assert.equal(s.isRunning(), true);
  await s.stop();
  assert.equal(s.isRunning(), false);
});

// ---------------------------------------------------------------------------
// runOnce
// ---------------------------------------------------------------------------

test('runOnce executes a single cycle and returns results', async () => {
  const log = [];
  const s = createScheduler({
    intervalMs: 100_000,
    hosts: ['10.0.0.1', '10.0.0.2'],
    scanFn: mockScanFn(log),
  });

  const results = await s.runOnce();
  assert.equal(results.size, 2);
  assert.ok(results.has('10.0.0.1'));
  assert.ok(results.has('10.0.0.2'));
  assert.deepEqual(log.sort(), ['10.0.0.1', '10.0.0.2']);
  assert.equal(s.isRunning(), false); // runOnce does NOT set running
});

// ---------------------------------------------------------------------------
// onScanComplete callback
// ---------------------------------------------------------------------------

test('onScanComplete fires for each host', async () => {
  const cbLog = [];
  const s = createScheduler({
    intervalMs: 100_000,
    hosts: ['a', 'b', 'c'],
    scanFn: async (h) => ({ h }),
    onScanComplete: (host, result) => cbLog.push({ host, result }),
  });

  await s.runOnce();
  assert.equal(cbLog.length, 3);
  const hosts = cbLog.map((e) => e.host).sort();
  assert.deepEqual(hosts, ['a', 'b', 'c']);
});

// ---------------------------------------------------------------------------
// onCycleComplete callback
// ---------------------------------------------------------------------------

test('onCycleComplete fires after all hosts', async () => {
  let cycleResults = null;
  const s = createScheduler({
    intervalMs: 100_000,
    hosts: ['x', 'y'],
    scanFn: async (h) => ({ h }),
    onCycleComplete: (results) => { cycleResults = results; },
  });

  await s.runOnce();
  assert.ok(cycleResults instanceof Map);
  assert.equal(cycleResults.size, 2);
});

// ---------------------------------------------------------------------------
// concurrency limit
// ---------------------------------------------------------------------------

test('respects concurrency limit', async () => {
  let peak = 0;
  let current = 0;
  const resolvers = [];

  // Scan function that tracks concurrent invocations
  const scanFn = async (host) => {
    current++;
    peak = Math.max(peak, current);
    // Create a micro-delay to let concurrency build up
    await new Promise((r) => { resolvers.push(r); Promise.resolve().then(() => { /* kick event loop */ }); });
    current--;
    return { host };
  };

  const s = createScheduler({
    intervalMs: 100_000,
    hosts: ['a', 'b', 'c', 'd'],
    parallel: 2,
    scanFn,
  });

  const cyclePromise = s.runOnce();

  // Resolve all pending scans after a tick to let them queue up
  await new Promise((r) => setTimeout(r, 10));
  while (resolvers.length) resolvers.shift()();
  await new Promise((r) => setTimeout(r, 10));
  while (resolvers.length) resolvers.shift()();

  await cyclePromise;
  assert.ok(peak <= 2, `Peak concurrency was ${peak}, expected <= 2`);
});

// ---------------------------------------------------------------------------
// error handling in scanFn
// ---------------------------------------------------------------------------

test('handles scanFn errors gracefully', async () => {
  const cbLog = [];
  const s = createScheduler({
    intervalMs: 100_000,
    hosts: ['ok-host', 'fail-host'],
    scanFn: async (h) => {
      if (h === 'fail-host') throw new Error('boom');
      return { h };
    },
    onScanComplete: (host, result) => cbLog.push({ host, result }),
  });

  const results = await s.runOnce();
  assert.equal(results.size, 2);
  assert.ok(results.get('fail-host').error.includes('boom'));
  assert.equal(cbLog.length, 2);
});

// ---------------------------------------------------------------------------
// stop during active scan waits for completion
// ---------------------------------------------------------------------------

test('stop waits for in-progress cycle to finish', async () => {
  let scanCompleted = false;
  const s = createScheduler({
    intervalMs: 100_000,
    hosts: ['h1'],
    scanFn: async () => {
      // Simulate a brief delay
      await new Promise((r) => setTimeout(r, 50));
      scanCompleted = true;
      return { done: true };
    },
  });

  s.start();
  // Give the first cycle a moment to begin
  await new Promise((r) => setTimeout(r, 10));
  await s.stop();
  assert.equal(scanCompleted, true, 'Stop should have waited for the in-progress scan');
  assert.equal(s.isRunning(), false);
});

// ---------------------------------------------------------------------------
// start is idempotent
// ---------------------------------------------------------------------------

test('calling start twice does not create duplicate intervals', async () => {
  const log = [];
  const s = createScheduler({
    intervalMs: 100_000,
    hosts: ['h1'],
    scanFn: async (h) => { log.push(h); return {}; },
  });

  s.start();
  s.start(); // second call should be ignored
  // Let first cycle finish
  await new Promise((r) => setTimeout(r, 20));
  await s.stop();
  // Should have only one cycle's worth of scans
  assert.equal(log.length, 1);
});

// ---------------------------------------------------------------------------
// 1.2.1 lane 4, item 10 — a duplicated host must not stall watch mode forever
// ---------------------------------------------------------------------------
// The cycle resolved on `results.size === hosts.length`, and `results` is keyed by host, so a duplicate (`--host h,h`,
// or a host inside an overlapping CIDR) could never reach the count: runCycle never resolved, _cycleInProgress stayed
// true and no later tick started. Watch mode went silent with no error. The scheduler dedupes once and resolves on a
// completion counter.

/** Resolve the cycle or fail after 1 s — a hang must read as a failure, never as a stuck test run. */
const withinOneSecond = (p) => Promise.race([p, new Promise((_, rej) => setTimeout(() => rej(new Error('the cycle never completed')), 1000).unref())]);

test('(fourth quadrant, first) distinct hosts are untouched — scanned once each, nothing reported dropped', { timeout: 3000 }, async () => {
  const log = [];
  const s = createScheduler({ intervalMs: 100_000, hosts: ['a', 'b'], scanFn: mockScanFn(log) });
  const results = await withinOneSecond(s.runOnce());
  assert.equal(results.size, 2);
  assert.deepEqual(s.hosts, ['a', 'b']);
  assert.equal(s.duplicatesDropped, 0);
});

test('a DUPLICATED host completes the cycle — scanned once, onCycleComplete fires once', { timeout: 3000 }, async () => {
  const log = [];
  let cycles = 0;
  const s = createScheduler({ intervalMs: 100_000, hosts: ['a', 'a'], scanFn: mockScanFn(log), onCycleComplete: () => { cycles++; } });
  const results = await withinOneSecond(s.runOnce());
  assert.deepEqual(log, ['a'], 'one scan per distinct host');
  assert.equal(results.size, 1);
  assert.equal(cycles, 1);
});

test('an OVERLAPPING list (a host inside a CIDR it is also listed beside) completes, first-occurrence order kept', { timeout: 3000 }, async () => {
  const log = [];
  const s = createScheduler({ intervalMs: 100_000, hosts: ['10.0.0.1', '10.0.0.0', '10.0.0.1'], scanFn: mockScanFn(log) });
  await withinOneSecond(s.runOnce());
  assert.deepEqual(log, ['10.0.0.1', '10.0.0.0']);
  assert.deepEqual(s.hosts, ['10.0.0.1', '10.0.0.0'], 'the distinct list the banner prints');
  assert.equal(s.duplicatesDropped, 1);
});

test('dedupe is EXACT-string: two spellings are two hosts (the scheduler cannot know they are one)', { timeout: 3000 }, async () => {
  const log = [];
  const s = createScheduler({ intervalMs: 100_000, hosts: ['A.example', 'a.example'], scanFn: mockScanFn(log) });
  await withinOneSecond(s.runOnce());
  assert.deepEqual(log.sort(), ['A.example', 'a.example']);
  assert.equal(s.duplicatesDropped, 0);
});

test('a scan that THROWS still counts toward completion', { timeout: 3000 }, async () => {
  const s = createScheduler({ intervalMs: 100_000, hosts: ['ok', 'boom'],
    scanFn: async (h) => { if (h === 'boom') throw new Error('socket exploded'); return { h }; } });
  const results = await withinOneSecond(s.runOnce());
  assert.equal(results.size, 2);
  assert.match(results.get('boom').error, /socket exploded/);
});
