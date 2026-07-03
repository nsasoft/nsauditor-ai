// utils/ai_stage.mjs
//
// Pure, testable helpers for the CLI AI-conclusion stage (cli.mjs
// maybeSendToOpenAI). Extracted so the BUG1 (payload-scaled timeout +
// fail-visible failure) and BUG2(a) (disabled-vs-key bail message) logic can be
// unit-tested without importing the CLI entrypoint. No I/O, no side effects.

/** Display label for an AI provider id. */
export function aiProviderLabel(aiProvider) {
  return aiProvider === 'claude' ? 'Claude' : aiProvider === 'ollama' ? 'Ollama' : 'OpenAI';
}

/** The env var an operator sets for a provider's key (null for keyless ollama). */
export function aiKeyEnvVar(aiProvider) {
  if (aiProvider === 'claude') return 'ANTHROPIC_API_KEY';
  if (aiProvider === 'ollama') return null;
  return 'OPENAI_API_KEY';
}

/**
 * BUG2(a): the AI-stage bail message. The old code printed a single
 * "AI_ENABLED=false; not sending" for BOTH `!sendEnabled` and `!key`, so an
 * operator who set AI_ENABLED=true but whose key failed to resolve (unset env or
 * a missing `keychain:<label>` entry) was told AI was disabled — a misdiagnosis.
 * This distinguishes the two, and on a key miss names the provider-specific env
 * var + the keychain-reference possibility.
 *
 * @returns {string} the log line to print at the bail site.
 */
export function aiBailMessage({ sendEnabled, key, aiProvider, model }) {
  const label = aiProviderLabel(aiProvider);
  if (!sendEnabled) {
    return `[${label}] AI_ENABLED is not set to true — skipping AI conclusion. Model=${model}`;
  }
  // sendEnabled === true but the key did not resolve.
  const envVar = aiKeyEnvVar(aiProvider);
  const ref = envVar
    ? `\`${envVar}\` is unset/empty, or its \`keychain:<label>\` reference did not resolve`
    : 'the provider key did not resolve';
  return `[${label}] AI_ENABLED=true but the API key could not be resolved — ${ref}. Skipping AI conclusion. Model=${model}`;
}

/**
 * BUG1: scale the AI-call timeout with the payload size. The fixed 120s
 * AbortController aborted cloud-scale scans (AWS 28KB / Azure 40KB payloads with
 * 200+ findings) whose 16k-token conclusions take longer than 2 min to generate,
 * while a small 4-5KB network-host payload finished well inside 120s. An explicit
 * NSA_AI_TIMEOUT_MS (envOverride) always wins. Otherwise: floor 120s (preserves
 * network-host behavior), +15s per KB of payload, ceiling 600s (10 min).
 *
 * @param {{payloadBytes?: number, host?: string, envOverride?: string|number}} o
 * @returns {number} timeout in ms.
 */
export function computeAiTimeoutMs({ payloadBytes = 0, host = '', envOverride } = {}) {
  const explicit = Number(envOverride);
  if (Number.isFinite(explicit) && explicit > 0) return explicit; // operator override wins
  const FLOOR_MS = 120_000; // 2 min — unchanged for small network-host payloads
  const CEIL_MS = 600_000;  // 10 min hard cap
  const MS_PER_KB = 15_000;
  const kb = Math.max(0, Number(payloadBytes) || 0) / 1024;
  const scaled = FLOOR_MS + Math.round(kb * MS_PER_KB);
  return Math.min(CEIL_MS, Math.max(FLOOR_MS, scaled));
}

/**
 * BUG1 (fail-VISIBLE): on an AI failure the pipeline used to write only a JSON
 * error file + a console.error that scrolls away in a 3-cloud run, so the
 * operator just saw "no AI conclusion". This produces a human-readable
 * scan_response_ai.txt body that names the error and — when it looks like a
 * timeout/abort — the NSA_AI_TIMEOUT_MS remedy.
 *
 * @returns {string} the scan_response_ai.txt body for the failure case.
 */
export function aiFailureStubText({ host, model, providerLabel, errorMessage, timeoutMs, whenIso }) {
  // review fold 9: match ONLY the local AbortController abort (the case
  // NSA_AI_TIMEOUT_MS actually fixes) — NOT a network "Connect Timeout Error"
  // (undici TCP-connect failure) or a socket ETIMEDOUT, for which raising the
  // local timeout is the wrong remedy.
  const aborted = /\babort/i.test(String(errorMessage || ''));
  const lines = [
    `Model: ${model}`,
    `Provider: ${providerLabel}`,
    `When: ${whenIso}`,
    `Host: ${host}`,
    ``,
    `==== ${providerLabel} Conclusion: FAILED ====`,
    `The AI conclusion could NOT be generated for this scan.`,
    `Error: ${errorMessage}`,
  ];
  if (aborted) {
    const secs = Math.round((Number(timeoutMs) || 0) / 1000);
    lines.push(
      ``,
      `This looks like a TIMEOUT — the request was aborted${secs ? ` after ~${secs}s` : ''}. Large`,
      `cloud-scan payloads can exceed the AI timeout. Re-run with a longer timeout, e.g.:`,
      `  NSA_AI_TIMEOUT_MS=600000 nsauditor-ai --host <target> ...`,
    );
  }
  return lines.join('\n');
}

/**
 * One-line end-of-scan summary so an AI failure/skip is visible without scrolling
 * the per-stage logs. `ai_status` covers EVERY value maybeSendToOpenAI returns:
 *   'ok'            — a conclusion was generated
 *   'empty'         — provider returned 200 but no extractable text (NOT ok)
 *   'skipped'       — AI disabled (AI_ENABLED not true)
 *   'key_unresolved'— AI enabled but the API key did not resolve
 *   'no_summary'    — no scan summary to send
 *   'failed'        — the provider call threw (carries ai_error as the cause)
 * Any unknown status falls to the FAILED branch (fail-visible default).
 */
export function aiSummaryLine({ host, ai_status, ai_error }) {
  switch (ai_status) {
    case 'ok':             return `AI conclusion: OK (${host})`;
    case 'empty':          return `AI conclusion: EMPTY — provider returned no text (${host})`;
    case 'skipped':        return `AI conclusion: SKIPPED — AI_ENABLED not set (${host})`;
    case 'key_unresolved': return `AI conclusion: SKIPPED — API key could not be resolved (${host})`;
    case 'no_summary':     return `AI conclusion: SKIPPED — no scan summary to send (${host})`;
    default:               return `AI conclusion: FAILED (${host})${ai_error ? ` — ${ai_error}` : ''}`;
  }
}
