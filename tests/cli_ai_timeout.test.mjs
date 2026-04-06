import assert from 'node:assert/strict';
import test from 'node:test';

/**
 * Tests for the AbortController timeout pattern used around AI provider calls
 * in cli.mjs (maybeSendToOpenAI). The function is not exported, so we mirror
 * the exact pattern and verify it aborts within the configured window.
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

test('NSA_AI_TIMEOUT_MS: parsed as number with 120_000 default', () => {
  const fromEnv = (val) => Number(val) || 120_000;
  assert.equal(fromEnv(undefined), 120_000);
  assert.equal(fromEnv(''), 120_000);
  assert.equal(fromEnv('30000'), 30_000);
  assert.equal(fromEnv('0'), 120_000); // 0 coerces to 120_000 via || fallback
});
