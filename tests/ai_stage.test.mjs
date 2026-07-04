// tests/ai_stage.test.mjs
//
// BUG1 + BUG2(a) (operator report 2026-07-03). Pure, testable helpers extracted
// from cli.mjs maybeSendToOpenAI (which is not exported):
//   - BUG2(a): the AI bail message conflated "AI_ENABLED=false" with an
//     unresolved API key — it printed "AI_ENABLED=false; not sending" even when
//     AI_ENABLED=true and the KEY failed to resolve. aiBailMessage() distinguishes.
//   - BUG1: the AI conclusion aborted on cloud-scale payloads (fixed 120s
//     AbortController). computeAiTimeoutMs() scales the default with payload size
//     (floor 120s for small network payloads, ceiling 600s for cloud-scale),
//     honoring an explicit NSA_AI_TIMEOUT_MS override. On failure the pipeline
//     was fail-QUIET (only a scrolled-away console.error + a JSON error file);
//     aiFailureStubText() produces a visible scan_response_ai.txt naming the
//     error + the NSA_AI_TIMEOUT_MS remedy.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  aiProviderLabel,
  aiBailMessage,
  computeAiTimeoutMs,
  aiFailureStubText,
  aiSummaryLine,
} from '../utils/ai_stage.mjs';

// ─── BUG2(a): the bail message must distinguish disabled-vs-key ──────────────

test('aiProviderLabel maps provider ids to display labels', () => {
  assert.equal(aiProviderLabel('claude'), 'Claude');
  assert.equal(aiProviderLabel('ollama'), 'Ollama');
  assert.equal(aiProviderLabel('openai'), 'OpenAI');
  assert.equal(aiProviderLabel(undefined), 'OpenAI');
});

test('aiBailMessage: AI_ENABLED not set → the disabled message (never the key message)', () => {
  const m = aiBailMessage({ sendEnabled: false, key: null, aiProvider: 'claude', model: 'claude-sonnet-4-6' });
  assert.match(m, /AI_ENABLED/i, 'names AI_ENABLED as the reason');
  assert.equal(/API key/i.test(m), false, 'does NOT blame the key when AI is simply disabled');
});

test('aiBailMessage: AI_ENABLED=true but key unresolved → names the KEY + the provider env var, NOT "AI_ENABLED=false"', () => {
  const m = aiBailMessage({ sendEnabled: true, key: null, aiProvider: 'claude', model: 'claude-sonnet-4-6' });
  assert.match(m, /key/i, 'names the key as the reason');
  assert.match(m, /ANTHROPIC_API_KEY/, 'names the provider-specific env var (claude → ANTHROPIC_API_KEY)');
  assert.equal(/AI_ENABLED=false/i.test(m), false, 'must NOT misdiagnose as AI_ENABLED=false (the BUG2a defect)');
});

test('aiBailMessage: OpenAI provider names OPENAI_API_KEY on a key miss', () => {
  const m = aiBailMessage({ sendEnabled: true, key: null, aiProvider: 'openai', model: 'gpt-x' });
  assert.match(m, /OPENAI_API_KEY/);
});

// ─── BUG1: payload-scaled timeout ────────────────────────────────────────────

test('computeAiTimeoutMs: small (network-host) payload stays near the 120s floor', () => {
  const ms = computeAiTimeoutMs({ payloadBytes: 800 });
  assert.ok(ms >= 120_000 && ms <= 150_000, `small payload ~= floor, got ${ms}`);
});

test('computeAiTimeoutMs: cloud-scale payload (40KB) scales up to the 600s ceiling', () => {
  const ms = computeAiTimeoutMs({ payloadBytes: 40 * 1024 });
  assert.equal(ms, 600_000, `40KB payload → capped at 10min, got ${ms}`);
});

test('computeAiTimeoutMs: 28KB payload scales above the floor but under the ceiling', () => {
  const ms = computeAiTimeoutMs({ payloadBytes: 28 * 1024 });
  assert.ok(ms > 120_000 && ms < 600_000, `28KB payload in-between, got ${ms}`);
});

test('computeAiTimeoutMs: an explicit NSA_AI_TIMEOUT_MS override wins over scaling', () => {
  assert.equal(computeAiTimeoutMs({ payloadBytes: 40 * 1024, envOverride: '90000' }), 90_000);
  // invalid / zero / negative overrides are ignored (fall through to scaling)
  assert.equal(computeAiTimeoutMs({ payloadBytes: 800, envOverride: '0' }) >= 120_000, true);
  assert.equal(computeAiTimeoutMs({ payloadBytes: 800, envOverride: 'abc' }) >= 120_000, true);
});

// ─── BUG1: fail-visible stub ─────────────────────────────────────────────────

test('aiFailureStubText: an aborted (timeout) failure names the error + the NSA_AI_TIMEOUT_MS remedy', () => {
  const txt = aiFailureStubText({
    host: '10.0.0.1', model: 'claude-sonnet-4-6', providerLabel: 'Claude',
    errorMessage: 'Request was aborted.', timeoutMs: 120_000, whenIso: '2026-07-04T00:00:00.000Z',
  });
  assert.match(txt, /FAILED/i, 'the conclusion is marked FAILED (not silently absent)');
  assert.match(txt, /Request was aborted/, 'names the actual error');
  assert.match(txt, /NSA_AI_TIMEOUT_MS/, 'names the operator remedy env var');
  assert.match(txt, /timeout|aborted/i, 'explains it as a timeout');
});

test('aiFailureStubText: a non-timeout failure names the error but does not fabricate a timeout remedy', () => {
  const txt = aiFailureStubText({
    host: '10.0.0.1', model: 'm', providerLabel: 'Claude',
    errorMessage: '401 invalid api key', timeoutMs: 120_000, whenIso: '2026-07-04T00:00:00.000Z',
  });
  assert.match(txt, /FAILED/i);
  assert.match(txt, /401 invalid api key/);
  assert.equal(/NSA_AI_TIMEOUT_MS/.test(txt), false, 'no timeout remedy for a non-timeout error');
});

test('aiFailureStubText: the SDK "Request timed out." DOES get the NSA_AI_TIMEOUT_MS remedy (review fold R-3)', () => {
  const txt = aiFailureStubText({
    host: 'h', model: 'm', providerLabel: 'Claude',
    errorMessage: 'Request timed out.', timeoutMs: 600_000, whenIso: '2026-07-04T00:00:00.000Z',
  });
  assert.match(txt, /NSA_AI_TIMEOUT_MS/, 'an SDK request-timeout is a timeout the remedy addresses');
});

test('aiFailureStubText: a network "Connect Timeout Error" does NOT get the NSA_AI_TIMEOUT_MS remedy (review fold 9)', () => {
  // A TCP-connect failure is not the local AbortController firing — raising the
  // AI timeout is the wrong remedy, so only a literal abort should surface it.
  const txt = aiFailureStubText({
    host: 'h', model: 'm', providerLabel: 'Claude',
    errorMessage: 'Connect Timeout Error (attempted address: api.anthropic.com:443)',
    timeoutMs: 120_000, whenIso: '2026-07-04T00:00:00.000Z',
  });
  assert.match(txt, /FAILED/i);
  assert.equal(/NSA_AI_TIMEOUT_MS/.test(txt), false, 'a connect-timeout must NOT suggest the local-abort remedy');
});

// ─── review fold C/D: aiSummaryLine covers EVERY ai_status the CLI emits ──────

test('aiSummaryLine: ok / skipped / no_summary / failed render distinct, cause-carrying lines', () => {
  assert.match(aiSummaryLine({ host: 'h', ai_status: 'ok' }), /OK/);
  assert.match(aiSummaryLine({ host: 'h', ai_status: 'skipped' }), /SKIP/i);
  assert.match(aiSummaryLine({ host: 'h', ai_status: 'no_summary' }), /SKIP|no scan summary/i);
  const failed = aiSummaryLine({ host: 'h', ai_status: 'failed', ai_error: 'Request was aborted.' });
  assert.match(failed, /FAILED/);
  assert.match(failed, /Request was aborted/, 'a failed line carries the cause');
});

test('aiSummaryLine: key_unresolved renders a KEY-specific reason (not a bare FAILED with no cause) — review fold C', () => {
  const line = aiSummaryLine({ host: '10.0.0.1', ai_status: 'key_unresolved' });
  assert.match(line, /key/i, 'names the key as the cause');
  assert.equal(/FAILED \([^)]*\)$/.test(line), false, 'not a bare "FAILED (host)" with no reason');
});

test('aiSummaryLine: empty (provider returned 200 with no extractable text) is distinct from OK — review fold D', () => {
  const line = aiSummaryLine({ host: 'h', ai_status: 'empty' });
  assert.equal(/\bOK\b/.test(line), false, 'an empty conclusion must NOT read as OK');
  assert.match(line, /empty|no text|no conclusion/i);
});
