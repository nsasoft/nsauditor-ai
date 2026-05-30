import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mapLimit } from '../utils/concurrency.mjs';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

test('returns results in input order', async () => {
  const out = await mapLimit([1, 2, 3, 4], 2, async (x) => x * 10);
  assert.deepEqual(out, [10, 20, 30, 40]);
});

test('never exceeds the concurrency limit (max in-flight)', async () => {
  let inFlight = 0, maxInFlight = 0;
  await mapLimit([1, 2, 3, 4, 5, 6], 2, async () => {
    inFlight++; maxInFlight = Math.max(maxInFlight, inFlight);
    await sleep(20);
    inFlight--;
  });
  assert.equal(maxInFlight, 2);
});

test('limit larger than item count runs all at once', async () => {
  let inFlight = 0, maxInFlight = 0;
  await mapLimit([1, 2, 3], 10, async () => {
    inFlight++; maxInFlight = Math.max(maxInFlight, inFlight);
    await sleep(20);
    inFlight--;
  });
  assert.equal(maxInFlight, 3);
});

test('limit of 1 runs serially (max in-flight 1)', async () => {
  let inFlight = 0, maxInFlight = 0;
  await mapLimit([1, 2, 3], 1, async () => {
    inFlight++; maxInFlight = Math.max(maxInFlight, inFlight);
    await sleep(10);
    inFlight--;
  });
  assert.equal(maxInFlight, 1);
});

test('empty input returns empty', async () => {
  assert.deepEqual(await mapLimit([], 4, async (x) => x), []);
});
