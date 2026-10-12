import './helpers/no_operator_dotenv.mjs';
import './helpers/no_operator_keychain.mjs';   // FIRST: this file imports cli.mjs
import assert from 'node:assert/strict';
import test from 'node:test';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { aiModelFor, DEFAULT_OPENAI_MODEL } from '../cli.mjs';

/**
 * Tests for AI provider selection logic in cli.mjs.
 * Validates that AI_PROVIDER env var correctly selects between
 * OpenAI and Claude (Anthropic) configurations.
 *
 * ⚠️ THE MODEL COMES FROM cli.mjs ITSELF (EE 2.0.0, marketing task #203). This file used to MIRROR the selection, so the
 * default it asserted was its own copy's — changing cli.mjs's default could never fail it. `aiModelFor` is the CLI's own
 * function now; the key and label below are still a mirror (the CLI resolves the key through the keychain, inline).
 */
const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');

function resolveProvider(env) {
  const aiProvider = (env.AI_PROVIDER || 'openai').toLowerCase().trim();
  const model = aiModelFor(env);
  const keyRaw = aiProvider === 'claude'
    ? env.ANTHROPIC_API_KEY
    : aiProvider === 'ollama'
    ? 'ollama'
    : env.OPENAI_API_KEY;
  const key = keyRaw ? String(keyRaw).trim() : null;
  const providerLabel = aiProvider === 'claude' ? 'Claude' : aiProvider === 'ollama' ? 'Ollama' : 'OpenAI';
  return { aiProvider, model, key, providerLabel };
}

test('AI Provider: defaults to openai when AI_PROVIDER is unset', () => {
  const r = resolveProvider({ OPENAI_API_KEY: 'sk-test' });
  assert.equal(r.aiProvider, 'openai');
  assert.equal(r.model, 'gpt-6-luna');
  assert.equal(r.key, 'sk-test');
  assert.equal(r.providerLabel, 'OpenAI');
});

test('AI Provider: selects claude when AI_PROVIDER=claude', () => {
  const r = resolveProvider({
    AI_PROVIDER: 'claude',
    ANTHROPIC_API_KEY: 'sk-ant-test',
    ANTHROPIC_MODEL: 'claude-sonnet-4-6'
  });
  assert.equal(r.aiProvider, 'claude');
  assert.equal(r.model, 'claude-sonnet-4-6');
  assert.equal(r.key, 'sk-ant-test');
  assert.equal(r.providerLabel, 'Claude');
});

test('AI Provider: claude uses default model when ANTHROPIC_MODEL is unset', () => {
  const r = resolveProvider({
    AI_PROVIDER: 'claude',
    ANTHROPIC_API_KEY: 'sk-ant-test'
  });
  assert.equal(r.model, 'claude-sonnet-4-6');
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

test('AI Provider: selects ollama when AI_PROVIDER=ollama', () => {
  const r = resolveProvider({ AI_PROVIDER: 'ollama' });
  assert.equal(r.aiProvider, 'ollama');
  assert.equal(r.model, 'llama3');
  assert.equal(r.key, 'ollama');
  assert.equal(r.providerLabel, 'Ollama');
});

test('AI Provider: ollama uses custom model from OLLAMA_MODEL', () => {
  const r = resolveProvider({
    AI_PROVIDER: 'ollama',
    OLLAMA_MODEL: 'mistral'
  });
  assert.equal(r.model, 'mistral');
});

test('AI Provider: ollama key is always "ollama" (no real key needed)', () => {
  const r = resolveProvider({
    AI_PROVIDER: 'ollama',
    OPENAI_API_KEY: 'sk-ignored',
    ANTHROPIC_API_KEY: 'sk-ant-ignored'
  });
  assert.equal(r.key, 'ollama');
});

// ── #203: the OpenAI default ─────────────────────────────────────────────────────────────────────────────────────────
test('#203 — the OpenAI default is gpt-6-luna (DECLARED here, not computed from the constant), and an empty variable falls back to it', () => {
  assert.equal(DEFAULT_OPENAI_MODEL, 'gpt-6-luna');
  assert.equal(aiModelFor({}), 'gpt-6-luna');
  assert.equal(aiModelFor({ OPENAI_MODEL: '' }), 'gpt-6-luna');
  assert.equal(aiModelFor({ OPENAI_MODEL: '  "gpt-6.1-sol"  ' }), 'gpt-6.1-sol', 'a set variable still wins, cleaned of quotes and padding');
  assert.equal(aiModelFor({ AI_PROVIDER: 'claude' }), 'claude-sonnet-4-6', '#203 changes the OpenAI default only');
});

test('#203 — every Community surface that states the default states THIS one, and none still names gpt-4o-mini', () => {
  // docs/openai.md is the operator's held draft: its line moves under #205, which reviews and commits it.
  for (const rel of ['.env.example', 'docs/configuration.md']) {
    const lines = fs.readFileSync(path.join(ROOT, rel), 'utf8').split('\n').filter((l) => /^OPENAI_MODEL=/.test(l));
    assert.deepEqual(lines, [`OPENAI_MODEL=${DEFAULT_OPENAI_MODEL}`], rel);
  }
  for (const rel of ['cli.mjs', '.env.example', 'docs/configuration.md', 'README.md']) {
    assert.ok(!fs.readFileSync(path.join(ROOT, rel), 'utf8').includes('gpt-4o-mini'), `${rel} still names gpt-4o-mini`);
  }
});

test('#203 — the AI step reads its model ONLY through aiModelFor: one OPENAI_MODEL read in the CLI, and the step calls it', () => {
  // An inline `process.env.OPENAI_MODEL || '…'` in maybeSendToOpenAI would bypass the default every leg above checks.
  const src = fs.readFileSync(path.join(ROOT, 'cli.mjs'), 'utf8').replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:])\/\/[^\n]*/g, '$1');
  assert.equal((src.match(/(?<![\w$])OPENAI_MODEL\b/g) ?? []).length, 1, 'the CLI reads OPENAI_MODEL somewhere other than aiModelFor');
  const step = src.slice(src.indexOf('async function maybeSendToOpenAI('));
  assert.match(step.slice(0, 2000), /const model\s*=\s*aiModelFor\(process\.env\);/, 'the AI step no longer takes its model from aiModelFor');
});
