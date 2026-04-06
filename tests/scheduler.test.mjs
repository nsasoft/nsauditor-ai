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
