import assert from 'node:assert/strict';
import test from 'node:test';

/**
 * Tests for AI provider selection logic in cli.mjs.
 * Validates that AI_PROVIDER env var correctly selects between
 * OpenAI and Claude (Anthropic) configurations.
 */

// Mirror the provider selection logic from cli.mjs
function resolveProvider(env) {
  const toCleanPath = (s) => String(s ?? '').trim().replace(/^['"]+|['"]+$/g, '');
  const aiProvider = (env.AI_PROVIDER || 'openai').toLowerCase().trim();
  const model = aiProvider === 'claude'
    ? toCleanPath(env.ANTHROPIC_MODEL || 'claude-sonnet-4-20250514')
    : toCleanPath(env.OPENAI_MODEL || 'gpt-4o-mini');
  const keyRaw = aiProvider === 'claude'
    ? env.ANTHROPIC_API_KEY
    : env.OPENAI_API_KEY;
  const key = keyRaw ? String(keyRaw).trim() : null;
  const providerLabel = aiProvider === 'claude' ? 'Claude' : 'OpenAI';
  return { aiProvider, model, key, providerLabel };
}

test('AI Provider: defaults to openai when AI_PROVIDER is unset', () => {
  const r = resolveProvider({ OPENAI_API_KEY: 'sk-test' });
  assert.equal(r.aiProvider, 'openai');
  assert.equal(r.model, 'gpt-4o-mini');
  assert.equal(r.key, 'sk-test');
  assert.equal(r.providerLabel, 'OpenAI');
});

test('AI Provider: selects claude when AI_PROVIDER=claude', () => {
  const r = resolveProvider({
    AI_PROVIDER: 'claude',
    ANTHROPIC_API_KEY: 'sk-ant-test',
    ANTHROPIC_MODEL: 'claude-sonnet-4-20250514'
  });
  assert.equal(r.aiProvider, 'claude');
  assert.equal(r.model, 'claude-sonnet-4-20250514');
  assert.equal(r.key, 'sk-ant-test');
  assert.equal(r.providerLabel, 'Claude');
});

test('AI Provider: claude uses default model when ANTHROPIC_MODEL is unset', () => {
  const r = resolveProvider({
    AI_PROVIDER: 'claude',
    ANTHROPIC_API_KEY: 'sk-ant-test'
  });
  assert.equal(r.model, 'claude-sonnet-4-20250514');
});

test('AI Provider: openai uses custom model from env', () => {
  const r = resolveProvider({
    AI_PROVIDER: 'openai',
    OPENAI_API_KEY: 'sk-test',
    OPENAI_MODEL: 'gpt-4o'
  });
  assert.equal(r.model, 'gpt-4o');
});

test('AI Provider: key is null when provider key is missing', () => {
  const r = resolveProvider({ AI_PROVIDER: 'claude' });
  assert.equal(r.key, null);
});

test('AI Provider: case insensitive provider name', () => {
  const r = resolveProvider({
    AI_PROVIDER: 'Claude',
    ANTHROPIC_API_KEY: 'sk-ant-test'
  });
  assert.equal(r.aiProvider, 'claude');
  assert.equal(r.providerLabel, 'Claude');
});

test('AI Provider: trims whitespace from provider name', () => {
  const r = resolveProvider({
    AI_PROVIDER: '  claude  ',
    ANTHROPIC_API_KEY: 'sk-ant-test'
  });
  assert.equal(r.aiProvider, 'claude');
});

test('AI Provider: openai ignores anthropic key and vice versa', () => {
  const r1 = resolveProvider({
    AI_PROVIDER: 'openai',
    OPENAI_API_KEY: 'sk-openai',
    ANTHROPIC_API_KEY: 'sk-ant-ignored'
  });
  assert.equal(r1.key, 'sk-openai');

  const r2 = resolveProvider({
    AI_PROVIDER: 'claude',
    OPENAI_API_KEY: 'sk-openai-ignored',
    ANTHROPIC_API_KEY: 'sk-ant-used'
  });
  assert.equal(r2.key, 'sk-ant-used');
});
