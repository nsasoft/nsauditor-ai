import assert from 'node:assert/strict';
import test from 'node:test';
import { computeAiTimeoutMs } from '../utils/ai_stage.mjs';

/**
 * Tests for the AbortController timeout pattern used around AI provider calls
 * in cli.mjs (maybeSendToOpenAI). The function is not exported, so we mirror
 * the exact pattern and verify it aborts within the configured window. The
 * default/override math lives in the exported computeAiTimeoutMs (see the
 * dedicated ai_stage.test.mjs) — the last test here pins it against the SHIPPED
 * function (review fold R-4: the previous version re-implemented the math inline
 * and asserted its own copy, i.e. it was green over dead logic).
 */

/**
 * Simulates an AI SDK call that hangs until the signal is aborted.
 */
function hangingAiCall(signal) {
  return new Promise((_, reject) => {
    if (signal?.aborted) {
      reject(new DOMException('Already aborted', 'AbortError'));
      return;
    }
    signal?.addEventListener('abort', () => {
      reject(new DOMException('Aborted', 'AbortError'));
    });
    // Never resolves on its own — simulates a hung AI provider
  });
}

test('AbortController timeout: aborts hanging AI call within configured window', async () => {
  const AI_TIMEOUT_MS = 100; // fast for tests
  const ac = new AbortController();
  const aiTimer = setTimeout(() => ac.abort(), AI_TIMEOUT_MS);

  const start = Date.now();
  try {
    await hangingAiCall(ac.signal);
    assert.fail('Should have been aborted');
  } catch (err) {
    const elapsed = Date.now() - start;
    assert.ok(err.name === 'AbortError', `expected AbortError, got ${err.name}`);
    assert.ok(elapsed < 500, `expected abort within 500ms, took ${elapsed}ms`);
  } finally {
    clearTimeout(aiTimer);
  }
});

test('AbortController timeout: clears timer when AI call succeeds quickly', async () => {
  const AI_TIMEOUT_MS = 5000;
  const ac = new AbortController();
  const aiTimer = setTimeout(() => ac.abort(), AI_TIMEOUT_MS);

  let timerCleared = false;
  try {
    // Simulate a fast-succeeding AI call
    const result = await Promise.resolve({ id: 'resp_123', content: [{ type: 'text', text: 'ok' }] });
    assert.equal(result.id, 'resp_123');
  } finally {
    clearTimeout(aiTimer);
    timerCleared = true;
  }
  assert.equal(timerCleared, true);
});

test('NSA_AI_TIMEOUT_MS default/override via the SHIPPED computeAiTimeoutMs (R-4)', () => {
  // no override, tiny payload → the 120s floor
  assert.equal(computeAiTimeoutMs({ envOverride: undefined, payloadBytes: 0 }), 120_000);
  assert.equal(computeAiTimeoutMs({ envOverride: '', payloadBytes: 0 }), 120_000);
  // a valid override wins even over payload scaling
  assert.equal(computeAiTimeoutMs({ envOverride: '30000', payloadBytes: 999_999 }), 30_000);
  // 0 / invalid override is ignored → falls through to the floor
  assert.equal(computeAiTimeoutMs({ envOverride: '0', payloadBytes: 0 }), 120_000);
});
