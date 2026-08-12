#!/usr/bin/env node
import 'dotenv/config';
import PluginManager from './plugin_manager.mjs';
import { buildHtmlReport } from './utils/report_html.mjs';
import fsp from 'node:fs/promises';
import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { realpathSync } from 'node:fs';
import { createRequire } from 'node:module';

const __dirname = dirname(fileURLToPath(import.meta.url));
const _require = createRequire(import.meta.url);
import path from 'node:path';
import { platform } from 'node:os';
import { openaiSimplePrompt, openaiPrompt as openaiProPrompt, openaiPromptOptimized } from './utils/prompts.mjs';
import { parseHostArg, parseHostFile } from './utils/host_iterator.mjs';
import { buildSarifLog } from './utils/sarif.mjs';
import { buildCsv } from './utils/export_csv.mjs';
import { buildMarkdownReport } from './utils/report_md.mjs';
import { recordScan, getLastScan, computeDiff, formatDiffReport, pruneForCE, HISTORY_FILE } from './utils/scan_history.mjs';
import { aiBailMessage, computeAiTimeoutMs, aiFailureStubText, aiSummaryLine } from './utils/ai_stage.mjs';
import { getTierFromEnv, loadLicense } from './utils/license.mjs';
import { resolveCapabilities, hasCapability, inferRequiredTier } from './utils/capabilities.mjs';
import { createScheduler } from './utils/scheduler.mjs';
import { buildDeltaReport, formatDeltaSummary, hasSignificantChanges } from './utils/delta_reporter.mjs';
import { sendWebhook, buildAlertPayload, isSafeWebhookUrl } from './utils/webhook.mjs';
import { scrubByKey } from './utils/redact.mjs';
import { isBlockedIp, resolveAndValidate } from './utils/net_validation.mjs';
import { getAllTechniques } from './utils/attack_map.mjs';
import { TOOL_VERSION } from './utils/tool_version.mjs';
import { resolveBaseOutDir } from './utils/output_dir.mjs';
import { toCleanPath } from './utils/path_helpers.mjs';

/* ------------------------- helpers & utilities ------------------------- */

const parseBool = (val, def = false) => {
  const s = String(val ?? '').trim().replace(/^['"]+|['"]+$/g, '').toLowerCase();
  if (!s && def != null) return !!def;
  return ['true', '1', 'yes', 'on', 'y'].includes(s);
};
const nowStamp = () => {
  const d = new Date();
  const pad = (n) => String(n).padStart(2, '0');
  return (
    d.getFullYear().toString() +
    pad(d.getMonth() + 1) +
    pad(d.getDate()) + '_' +
    pad(d.getHours()) +
    pad(d.getMinutes()) +
    pad(d.getSeconds())
  );
};
const safeHost = (h) => String(h ?? 'unknown').replace(/[\/\\?%*:|"<>]/g, '_');
// toCleanPath imported from ./utils/path_helpers.mjs (consolidated in v0.1.20)

/** Minimal redactor used if nothing external is provided. */
function redactSensitiveForAI(input, targetHost) {
  const DROP_KEYS = new Set([
    'ip6', 'deviceWebPage', 'deviceWebPageInstruction',
    'hardwareVersion', 'firmwareVersion'
  ]);
  const SERIAL_KEY_RE = /^(serial(number)?|sn)$/i;
  const isPrivateV4 = (ip) =>
    /^10\./.test(ip) ||
    /^172\.(1[6-9]|2\d|3[0-1])\./.test(ip) ||
    /^192\.168\./.test(ip);

  const scrubString = (str) => {
    let s = String(str);
    s = s.replace(/\bSerial\s*[:=]\s*[A-Za-z0-9._-]+/gi, 'Serial=[REDACTED_HIDDEN]');
    s = s.replace(/\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b/gi, '[MAC]'); // MAC
    s = s.replace(/\bfe80::[0-9a-f:]+\b/gi, '[FE80::/64]');         // IPv6 link-local
    s = s.replace(/\b(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{1,4}\b/gi, '[IPv6]');
    s = s.replace(/\b(?:(?:\d{1,3}\.){3}\d{1,3})\b/g, (ip) => (isPrivateV4(ip) ? ip : '[IP]'));
    return s;
  };

  const walk = (val, key = '') => {
    if (Array.isArray(val)) return val.map((v) => walk(v));
    if (val && typeof val === 'object') {
      const out = {};
      for (const [k, v] of Object.entries(val)) {
        if (DROP_KEYS.has(k)) continue;
        if (SERIAL_KEY_RE.test(k)) { out[k] = '[REDACTED_HIDDEN]'; continue; }
        out[k] = walk(v, k);
      }
      return out;
    }
    if (typeof val === 'string') return scrubString(val);
    return val;
  };

  return walk(input);
}

/* ------------------------- OpenAI & reporting -------------------------- */

async function maybeSendToOpenAI({ host, results, conclusion, promptMode = 'basic', outDir: presetOutDir = null }) {
  // --- env & opts -----------------------------------------------------------
  const sendEnabled   = parseBool(process.env.AI_ENABLED);
  const redactEnabled = parseBool(process.env.OPENAI_REDACT, true);
  const aiProvider    = (process.env.AI_PROVIDER || 'openai').toLowerCase().trim();
  const model         = aiProvider === 'claude'
    ? toCleanPath(process.env.ANTHROPIC_MODEL || 'claude-sonnet-4-6')
    : aiProvider === 'ollama'
    ? toCleanPath(process.env.OLLAMA_MODEL || 'llama3')
    : toCleanPath(process.env.OPENAI_MODEL || 'gpt-4o-mini');
  const { resolveSecret } = await import('./utils/keychain.mjs');
  const keyRaw        = aiProvider === 'claude'
    ? await resolveSecret(process.env.ANTHROPIC_API_KEY)
    : aiProvider === 'ollama'
    ? 'ollama'   // Ollama needs no real key; OpenAI SDK requires a non-empty string
    : await resolveSecret(process.env.OPENAI_API_KEY);
  const key           = keyRaw ? String(keyRaw).trim() : null;

  // Per-scan folder. Caller (scanSingleHost) may pass a pre-computed outDir so
  // that EE enrichment + compliance artifacts share the same folder as the AI
  // outputs — otherwise compute one here for legacy callers.
  let outDir = presetOutDir;
  if (!outDir) {
    const baseOutDir = resolveBaseOutDir();
    await fsp.mkdir(baseOutDir, { recursive: true });
    const ts     = nowStamp();
    const runDir = `${safeHost(host)}_${ts}`;
    outDir       = path.join(baseOutDir, runDir);
  }
  await fsp.mkdir(outDir, { recursive: true });

  // Paths (fixed names inside per-scan folder)
  const adminRawPath   = path.join(outDir, 'scan_conclusion_raw.json');
  const adminHtmlPath  = path.join(outDir, 'scan_conclusion_raw.html');
  const aiPayloadPath  = path.join(outDir, 'scan_response_ai_payload.json');
  const aiResponsePath = path.join(outDir, 'scan_response_ai.json');
  const aiTxtPath      = path.join(outDir, 'scan_response_ai.txt');
  const aiHtmlPath     = path.join(outDir, 'scan_response_ai.html');
  const aiErrPath      = path.join(outDir, 'scan_response_ai_error.json');

  // Ensure “Serial: …” appears in summary only if present
  const ensureSerialInSummary = (srcSummary, serialText) => {
    const s = String(srcSummary ?? '').trim();
    if (!s) return `Serial: ${serialText}`;
    if (/\bSerial\s*[:=]/i.test(s)) return s;
    return `${s}  Serial: ${serialText}`;
  };

  // Extract serial from conclusion/results/evidence
  const findSerial = () => {
    const direct = conclusion?.result?.serialNumber;
    if (typeof direct === 'string' && direct.trim()) return direct.trim();

    if (Array.isArray(results)) {
      for (const r of results) {
        const s = r?.result?.serialNumber;
        if (typeof s === 'string' && s.trim()) return s.trim();
      }
    }

    const scanText = (t) => {
      if (!t) return null;
      const m = String(t).match(/\bSerial\s*[:=]\s*([A-Za-z0-9._-]+)/i);
      return m?.[1] ? m[1].trim() : null;
    };
    const ev = conclusion?.result?.evidence;
    if (Array.isArray(ev)) {
      for (const e of ev) {
        const s1 = scanText(e?.banner);
        if (s1) return s1;
        const s2 = scanText(e?.info);
        if (s2) return s2;
      }
    }

    const svcs = conclusion?.result?.services;
    if (Array.isArray(svcs)) {
      for (const s of svcs) {
        const m = String(s?.banner ?? '').match(/\bSerial\s*[:=]\s*([A-Za-z0-9._-]+)/i);
        if (m?.[1]) return m[1].trim();
      }
    }
    return null;
  };

  // Basic pieces
  const baseSummary = conclusion?.result?.summary ?? conclusion?.summary ?? null;
  if (!baseSummary) {
    console.warn('[OpenAI] No conclusion.summary available; skipping.');
    return {
      file_paths: { folder: outDir, plain: null, ai_json: null, raw_json: null, html: null, admin_html: null },
      ai_conclusion: null,
      ai_status: 'no_summary',
    };
  }

  // Host OS hint for AI (if present)
  const hostOsHint = conclusion?.result?.host?.os || conclusion?.host?.os || null;

  // Compose summaries
  const detectedSerial = findSerial();
  const summaryWithFullSerial = detectedSerial ? ensureSerialInSummary(baseSummary, detectedSerial) : baseSummary;

  // --- Admin RAW (unsanitized) JSON + Admin HTML ----------------------------
  try {
    const adminRaw = { host, summary: summaryWithFullSerial, results, conclusion };
    await fsp.writeFile(adminRawPath, JSON.stringify(adminRaw, null, 2), 'utf8');
    console.log('[OpenAI] Wrote admin RAW:', adminRawPath);

    try {
      const { buildAdminRawHtmlReport } = await import('./utils/raw_report_html.mjs');
      const adminHtml = await buildAdminRawHtmlReport({
        host,
        whenIso: new Date().toISOString(),
        summary: (conclusion?.result?.summary ?? summaryWithFullSerial) || '',
        services: Array.isArray(conclusion?.result?.services) ? conclusion.result.services : [],
        evidence: Array.isArray(conclusion?.result?.evidence) ? conclusion.result.evidence : []
      });
      await fsp.writeFile(adminHtmlPath, adminHtml, 'utf8');
      console.log('[AdminHTML] Wrote Admin RAW HTML:', adminHtmlPath);
    } catch (e) {
      console.warn('[AdminHTML] Failed to write Admin RAW HTML:', e?.message || e);
    }
  } catch (e) {
    console.warn('[OpenAI] Failed to write admin RAW:', e?.message || e);
  }

  // --- Build sanitized payload for AI ---------------------------------------
  let payloadForAI = {
    host,
    host_os_hint: hostOsHint,
    summary: summaryWithFullSerial, // include full; redactor will mask
    services: conclusion?.result?.services ?? [],
    evidence: conclusion?.result?.evidence ?? [],
    _meta: {
      resultsCount: Array.isArray(results) ? results.length : (results ? 1 : 0),
      serialFound: !!detectedSerial
    }
  };

  if (redactEnabled) {
    let used = 'fallback';
    try {
      // Only allow external redaction override for Pro/Enterprise tiers.
      // CE always uses the built-in redact pipeline to preserve the ZDE guarantee.
      const redactCaps = resolveCapabilities(getTierFromEnv());
      if (hasCapability(redactCaps, 'enhancedRedaction') && typeof globalThis.redactSensitiveForAI === 'function') {
        let out = globalThis.redactSensitiveForAI(payloadForAI);
        if (out && typeof out.then === 'function') out = await out;
        if (typeof out === 'string') out = JSON.parse(out);
        if (!out || typeof out !== 'object') throw new Error('external redactor returned non-object');
        payloadForAI = out;
        used = 'external';
      } else {
        payloadForAI = redactSensitiveForAI(payloadForAI, host);
      }
    } catch (e) {
      console.warn('[OpenAI] Redaction failed, using fallback:', e?.message || e);
      payloadForAI = redactSensitiveForAI(payloadForAI, host);
      used = 'fallback';
    }

    // additional key-based scrubbing (CONFIDENTIAL_KEYWORDS=serial,password,token)
    const keywords = String(process.env.CONFIDENTIAL_KEYWORDS || '')
      .split(',')
      .map((s) => s.trim().toLowerCase())
      .filter(Boolean);
    if (keywords.length) payloadForAI = scrubByKey(payloadForAI, keywords, '[REDACTED_HIDDEN]');

    // Redact top-level host field (private IPs survive scrubString)
    if (typeof payloadForAI.host === 'string') {
      payloadForAI.host = '[REDACTED_HOST]';
    }

    // Redact any remaining IP addresses in the summary field
    if (typeof payloadForAI.summary === 'string') {
      payloadForAI.summary = payloadForAI.summary
        .replace(/\b(?:(?:\d{1,3}\.){3}\d{1,3})\b/g, '[REDACTED_HOST]');
    }

    // Also redact private IPs in nested service/evidence strings
    const privateIpRe = /\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b/g;
    function scrubPrivateIps(obj) {
      if (typeof obj === 'string') return obj.replace(privateIpRe, '[REDACTED_IP]');
      if (Array.isArray(obj)) return obj.map(scrubPrivateIps);
      if (obj && typeof obj === 'object') {
        const out = {};
        for (const [k, v] of Object.entries(obj)) out[k] = scrubPrivateIps(v);
        return out;
      }
      return obj;
    }
    payloadForAI.services = scrubPrivateIps(payloadForAI.services);
    payloadForAI.evidence = scrubPrivateIps(payloadForAI.evidence);

    payloadForAI = { ...payloadForAI, _meta: { ...(payloadForAI?._meta || {}), wasRedacted: true, redactor: used } };
  } else {
    payloadForAI = { ...payloadForAI, _meta: { ...(payloadForAI?._meta || {}), wasRedacted: false } };
  }

  // Ensure placeholder only if a serial was detected
  if (payloadForAI?._meta?.serialFound && detectedSerial) {
    const s = String(payloadForAI.summary ?? '').trim();
    if (!/\bSerial\s*[:=]/i.test(s)) {
      payloadForAI.summary = `${s}  Serial: [REDACTED_HIDDEN]`;
    } else {
      payloadForAI.summary = s.replace(/\bSerial\s*[:=]\s*([A-Za-z0-9._-]+)/i, 'Serial: [REDACTED_HIDDEN]');
    }
  }

  // --- Bail out early if sending disabled -----------------------------------
  const providerLabel = aiProvider === 'claude' ? 'Claude' : aiProvider === 'ollama' ? 'Ollama' : 'OpenAI';
  if (!sendEnabled || !key) {
    // BUG2(a): distinguish "AI disabled" from "AI enabled but key unresolved" —
    // the old single message misdiagnosed a keychain/env key miss as AI_ENABLED=false.
    console.log(aiBailMessage({ sendEnabled, key, aiProvider, model }));
    return {
      file_paths: { folder: outDir, plain: null, ai_json: null, raw_json: adminRawPath, html: null, admin_html: adminHtmlPath },
      ai_conclusion: null,
      ai_status: sendEnabled ? 'key_unresolved' : 'skipped',
    };
  }

  // --- Write the payload we plan to send ------------------------------------
  try {
    await fsp.writeFile(aiPayloadPath, JSON.stringify(payloadForAI, null, 2), 'utf8');
    console.log(`[${providerLabel}] Wrote AI payload:`, aiPayloadPath);
  } catch (e) {
    console.warn(`[${providerLabel}] Failed to write AI payload:`, e?.message || e);
  }

  // --- Select prompt ---------------------------------------------------------
  let promptText = openaiSimplePrompt;
  if (String(promptMode).toLowerCase() === 'pro') {
    promptText = openaiProPrompt;
  } else if (String(promptMode).toLowerCase() === 'optimized') {
    promptText = openaiPromptOptimized;
  }

  // Prepend EE intelligence enrichment block if present (Pro/Enterprise tier)
  const eeBlock = conclusion?.result?.eeEnrichment?.enrichedPrompt;
  if (eeBlock) promptText = eeBlock + '\n\n---\n\n' + promptText;

  // --- Send to AI provider ---------------------------------------------------
  let aiConclusionText = null;
  // review fold 8: contain the serialization — hoisting userContent above the
  // try (so the catch can name the timeout) must not let a JSON.stringify throw
  // (e.g. a circular payload) escape maybeSendToOpenAI uncaught. (payloadForAI is
  // already serialized once at the aiPayloadPath write above, so this is
  // defensive; the fallback keeps the timeout math + stub path alive.)
  let userContent;
  try {
    userContent = `Scan payload:\n${JSON.stringify(payloadForAI, null, 2)}`;
  } catch (e) {
    console.warn(`[${providerLabel}] Failed to serialize AI payload:`, e?.message || e);
    userContent = `Scan payload:\n${String(payloadForAI?.summary ?? '(unserializable payload)')}`;
  }
  // AbortController timeout — prevents the pipeline hanging on a stalled AI provider.
  // BUG1: scale with payload size (cloud-scale 28-40KB payloads exceeded the old
  // flat 120s default and aborted); an explicit NSA_AI_TIMEOUT_MS still wins.
  // Hoisted above the try so the catch's fail-visible stub can name the timeout.
  const AI_TIMEOUT_MS = computeAiTimeoutMs({
    payloadBytes: Buffer.byteLength(userContent, 'utf8'), // optional fold: UTF-8 bytes, not UTF-16 units
    host,
    envOverride: process.env.NSA_AI_TIMEOUT_MS,
  });
  try {
    console.log(`[${providerLabel}] Sending summary, model:`, model);

    let resp;

    const ac = new AbortController();
    const aiTimer = setTimeout(() => ac.abort(), AI_TIMEOUT_MS);

    try {
      if (aiProvider === 'claude') {
        // --- Claude (Anthropic) ---
        const { default: Anthropic } = await import('@anthropic-ai/sdk');
        // R-3: maxRetries:0 so the outer AbortController/timeout can't race the
        // SDK's own internal retry loop (which would multiply the wall-clock).
        const client = new Anthropic({ apiKey: key, maxRetries: 0 });

        resp = await client.messages.create({
          model,
          max_tokens: 16384,
          system: promptText,
          messages: [
            { role: 'user', content: userContent }
          ]
        }, { signal: ac.signal, timeout: AI_TIMEOUT_MS });

        console.log(`[${providerLabel}] Response id:`, resp?.id ?? '(unknown)');

        // Extract text from Claude response
        aiConclusionText = (resp?.content ?? [])
          .filter(b => b.type === 'text')
          .map(b => b.text)
          .join('\n')
          .trim() || null;
      } else if (aiProvider === 'ollama') {
        // --- Ollama (OpenAI-compatible API) ---
        const { default: OpenAI } = await import('openai');
        const ollamaBase = process.env.OLLAMA_BASE_URL || 'http://localhost:11434/v1';
        const client = new OpenAI({ baseURL: ollamaBase, apiKey: key, maxRetries: 0 }); // R-3

        resp = await client.chat.completions.create({
          model,
          messages: [
            { role: 'system', content: promptText },
            { role: 'user', content: userContent }
          ]
        }, { signal: ac.signal, timeout: AI_TIMEOUT_MS });

        console.log(`[${providerLabel}] Response id:`, resp?.id ?? '(unknown)');

        aiConclusionText = resp?.choices?.[0]?.message?.content?.trim() || null;
      } else {
        // --- OpenAI ---
        const { default: OpenAI } = await import('openai');
        const client = new OpenAI({ apiKey: key, maxRetries: 0 }); // R-3

        if (client.responses?.create) {
          resp = await client.responses.create({
            model,
            input: [
              { role: 'system', content: promptText },
              { role: 'user', content: userContent }
            ]
          }, { signal: ac.signal, timeout: AI_TIMEOUT_MS });
        } else if (client.chat?.completions?.create) {
          resp = await client.chat.completions.create({
            model,
            messages: [
              { role: 'system', content: promptText },
              { role: 'user', content: userContent }
            ]
          }, { signal: ac.signal, timeout: AI_TIMEOUT_MS });
        } else {
          throw new Error('OpenAI SDK: neither responses.create nor chat.completions.create is available.');
        }

      console.log(`[${providerLabel}] Response id:`, resp?.id ?? resp?.choices?.[0]?.id ?? '(unknown)');

      // Extract assistant text (robust)
      const extractAssistantText = (r) => {
        try {
          if (typeof r?.output_text === 'string' && r.output_text.trim()) return r.output_text.trim();
          const msg = r?.choices?.[0]?.message?.content;
          if (typeof msg === 'string' && msg.trim()) return msg.trim();
          const texts = [];
          const walk = (v) => {
            if (!v) return;
            if (Array.isArray(v)) return v.forEach(walk);
            if (typeof v === 'object') {
              if (typeof v.text === 'string') texts.push(v.text);
              if (typeof v.content === 'string') texts.push(v.content);
              for (const k of Object.keys(v)) walk(v[k]);
            }
          };
          walk(r?.output);
          const combined = texts.join('\n').trim();
          return combined || null;
        } catch {
          return null;
        }
      };

      aiConclusionText = extractAssistantText(resp);
    }
    } finally {
      clearTimeout(aiTimer);
    }

    // Write full AI response
    try {
      await fsp.writeFile(aiResponsePath, JSON.stringify(resp, null, 2), 'utf8');
      console.log(`[${providerLabel}] Wrote AI response:`, aiResponsePath);
    } catch (e) {
      console.warn(`[${providerLabel}] Failed to write AI response:`, e?.message || e);
    }

    // Write TXT & HTML
    try {
      const lines = [
        `Model: ${model}`,
        `Provider: ${providerLabel}`,
        `When: ${new Date().toISOString()}`,
        `Host: ${host}`,
        ``,
        `Payload path: ${aiPayloadPath}`,
        `Response path: ${aiResponsePath}`,
        ``,
        `==== ${providerLabel} Conclusion ====`,
        aiConclusionText ? aiConclusionText : '(no text content returned)'
      ];
      await fsp.writeFile(aiTxtPath, lines.join('\n'), 'utf8');
      console.log(`[${providerLabel}] Wrote AI TXT:`, aiTxtPath);

      if (typeof aiConclusionText === 'string' && aiConclusionText.trim()) {
        const html = await buildHtmlReport({
          host,
          whenIso: new Date().toISOString(),
          model,
          md: aiConclusionText.trim()
        });
        await fsp.writeFile(aiHtmlPath, html, 'utf8');
        console.log(`[${providerLabel}] Wrote AI HTML:`, aiHtmlPath);
      }
    } catch (e) {
      console.warn(`[${providerLabel}] Failed to write AI TXT/HTML:`, e?.message || e);
    }

    return {
      file_paths: {
        folder: outDir,
        plain: aiTxtPath,
        ai_json: aiResponsePath,
        raw_json: adminRawPath,
        html: aiHtmlPath,
        admin_html: adminHtmlPath
      },
      ai_conclusion: aiConclusionText,
      // review fold D: a 200 with no extractable text is NOT "ok" — the
      // end-of-scan summary must not read "OK" when there is no conclusion.
      ai_status: (typeof aiConclusionText === 'string' && aiConclusionText.trim()) ? 'ok' : 'empty',
    };
  } catch (err) {
    const errMsg = String(err?.message || err);
    console.error(`[${providerLabel}] Send failed:`, err?.stack || errMsg);
    try {
      await fsp.writeFile(aiErrPath, JSON.stringify({
        error: errMsg,
        stack: err?.stack || null,
        provider: aiProvider,
        model
      }, null, 2), 'utf8');
      console.log(`[${providerLabel}] Wrote AI error:`, aiErrPath);
    } catch (e) {
      console.warn(`[${providerLabel}] Also failed to write error file:`, e?.message || e);
    }

    // BUG1 (fail-VISIBLE): also write a human-readable scan_response_ai.txt stub
    // so the operator sees WHY there is no AI conclusion (the JSON error file +
    // the console.error above both scroll away in a 3-cloud run). Names the error
    // and, on a timeout/abort, the NSA_AI_TIMEOUT_MS remedy.
    let aiFailureStubPath = null;
    try {
      await fsp.writeFile(aiTxtPath, aiFailureStubText({
        host, model, providerLabel, errorMessage: errMsg,
        timeoutMs: AI_TIMEOUT_MS, whenIso: new Date().toISOString(),
      }), 'utf8');
      aiFailureStubPath = aiTxtPath;
      console.log(`[${providerLabel}] Wrote AI failure stub:`, aiTxtPath);
    } catch (e) {
      console.warn(`[${providerLabel}] Also failed to write AI failure stub:`, e?.message || e);
    }

    return {
      file_paths: {
        folder: outDir,
        // review fold 16: keep `plain` NULL on failure — a downstream consumer
        // uses `plain != null` as an AI-success proxy. The visible stub is
        // surfaced on its own `ai_failure_stub` key + via ai_status/ai_error.
        plain: null,
        ai_json: null,
        ai_failure_stub: aiFailureStubPath,
        raw_json: adminRawPath,
        html: null,
        admin_html: adminHtmlPath
      },
      ai_conclusion: null,
      ai_status: 'failed',
      ai_error: errMsg,
    };
  }
}

/* ------------------------------- CLI ----------------------------------- */

export async function parseArgs(argv) {
  const args = { cmd: 'scan', host: undefined, plugins: 'all', insecureHttps: false };
  const a = argv.slice(2);
  // Help: bare `--help`/`-h`/`help` or completely empty invocation.
  // Recognized before the scan-default so it doesn't crash with
  // "--host or --host-file is required" on a help request.
  //
  // CE-0.1.30.1 reviewer M1: short flag `-h` only matches at `a[0]`. The
  // long-flag `--help` matches anywhere in argv (typing `nsauditor-ai
  // scan --help` should still print help). Pre-fix the parser had
  // `a.includes('-h')` which would match `-h` as a value of another
  // flag (e.g., `--alert-severity -h` would silently fire help instead
  // of failing argv validation). Same fix mirrored in the version branch
  // below.
  if (a.length === 0 || a[0] === '--help' || a[0] === '-h' || a[0] === 'help' ||
      a.includes('--help')) {
    args.cmd = 'help';
    return args;
  }
  // Version: bare `--version`/`-v`/`version`. CE-0.1.30.1 — same pre-license
  // dispatch as help so a discovery flag never errors with
  // "--host or --host-file is required" or with a missing-key fatal.
  if (a[0] === '--version' || a[0] === '-v' || a[0] === 'version' ||
      a.includes('--version')) {
    args.cmd = 'version';
    return args;
  }
  if (a.length && !a[0].startsWith('--')) args.cmd = a[0];

  const get = (name) => {
    const i = a.indexOf(`--${name}`);
    if (i === -1) return undefined;
    const v = a[i + 1];
    if (!v || v.startsWith('--')) return true;
    return v;
  };

  args.host = get('host') || get('ip') || get('target');
  const p = get('plugins');
  if (p && p !== true && p.toLowerCase() !== 'all') {
    args.plugins = p.split(',').map((s) => s.trim()).filter(Boolean);
  } else if (p && p !== true && p.toLowerCase() === 'all') {
    args.plugins = 'all';
  }
  args.insecureHttps = !!(get('insecure-https') || get('insecure_https'));
  const hostFileVal = get('host-file') || get('host_file');
  args.hostFile = (hostFileVal && hostFileVal !== true) ? hostFileVal : undefined;
  const outVal = get('out');
  if (outVal && outVal !== true) process.env.SCAN_OUT_PATH = outVal;
  const portsVal = get('ports');
  args.ports = (portsVal && portsVal !== true) ? portsVal : null;
  const parallelVal = get('parallel');
  args.parallel = (parallelVal && parallelVal !== true) ? Math.max(1, parseInt(parallelVal, 10) || 1) : 1;
  args.failOn = get('fail-on') || get('fail_on') || null;
  if (args.failOn === true) args.failOn = null; // bare flag without value
  const ofVal = get('output-format') || get('output_format') || null;
  args.outputFormat = (ofVal && ofVal !== true) ? ofVal : null;

  // CTEM: continuous watch mode flags
  args.watch = !!(get('watch'));
  const intervalVal = get('interval');
  args.intervalMinutes = (intervalVal && intervalVal !== true) ? Math.max(1, parseInt(intervalVal, 10) || 60) : 60;
  const whUrl = get('webhook-url') || get('webhook_url') || null;
  if (whUrl && whUrl !== true) {
    if (!(await isSafeWebhookUrl(whUrl))) {
      console.error(`[ERROR] Webhook URL rejected: private/loopback/metadata addresses are not allowed.`);
      process.exit(2);
    }
    args.webhookUrl = whUrl;
  } else {
    args.webhookUrl = null;
  }
  const alertSev = get('alert-severity') || get('alert_severity') || null;
  args.alertSeverity = (alertSev && alertSev !== true) ? alertSev.toLowerCase() : 'high';

  // Compliance: framework selector + scope file. Forwarded to EE's
  // runCompliancePhase via enrichScan(). No-op without an EE Enterprise license.
  const complianceVal = get('compliance');
  args.compliance = (complianceVal && complianceVal !== true) ? complianceVal : null;
  const complianceScopeVal = get('compliance-scope') || get('compliance_scope');
  args.complianceScope = (complianceScopeVal && complianceScopeVal !== true) ? complianceScopeVal : null;

  // Per-scan account selection (EE 0.16.x). `--env <path>` loads a dotenv
  // (override-on) for this scan; `--aws-profile <name>` selects a named profile
  // from ~/.aws/credentials. Both are wired into main() via resolveScanEnv().
  // get() returns undefined (absent), true (value-less flag), or the string value.
  // EE 0.33.0 (N2): longitudinal compliance evidence. Both are forwarded verbatim to
  // EE, which owns every default and every validation — CE never parses or defaults
  // them. Tri-state like `--env` and NOT the `--compliance-scope` collapse-to-null
  // form: a value-less `--sla-policy` must be an error in main(), because silently
  // nulling it is precisely the quiet skip this feature exists to remove.
  // `--history` is the spelling the `compliance attest` subcommand documents and the one
  // an operator types there; `--compliance-history` is the scan-path spelling. Both
  // resolve to the same value because they name the same directory. Accepting only one
  // is how a DOCUMENTED flag becomes a flag that does nothing — and that is exactly what
  // shipped in the first draft here, caught by RUNNING the command rather than reading
  // it. The EE guard that catches this class is scoped to /--compliance[A-Za-z-]*/, and
  // `--history` does not match it.
  const complianceHistoryVal = get('compliance-history') || get('compliance_history') || get('history');
  args.complianceHistory = complianceHistoryVal === undefined ? undefined : complianceHistoryVal;
  const slaPolicyVal = get('sla-policy') || get('sla_policy');
  args.slaPolicy = slaPolicyVal === undefined ? undefined : slaPolicyVal;
  const attestWindowVal = get('window');
  args.attestWindow = (attestWindowVal && attestWindowVal !== true) ? attestWindowVal : null;

  // ── the approval surface (EE 0.35.0) ────────────────────────────────────────
  // Parsed HERE with every other flag rather than read from `process.argv` in the
  // subcommand, so one parser owns the `--flag value` / `--flag=value` / boolean
  // shapes. `attest` taught this: a second parser is a second set of edge cases.
  const str = (name) => { const v = get(name); return (v && v !== true) ? v : null; };
  args.approvalArgs = {
    suppressions: str('suppressions'),
    keyPath: str('key'),
    source: str('source'),
    titlePattern: str('title-pattern') ?? str('title_pattern'),
    status: str('status'),
    rationale: str('rationale'),
    approver: str('approver'),
    email: str('email'),
    role: str('role'),
    team: str('team'),
    suppressionId: str('id'),
    expiresInDays: str('expires-in-days'),
    attestationLevel: str('attestation-level'),
    compensatingControl: str('compensating-control'),
    force: !!get('force'),
  };
  const frameworkVal = get('framework');
  args.framework = (frameworkVal && frameworkVal !== true) ? frameworkVal : null;

  const envVal = get('env');
  args.env = envVal === undefined ? undefined : envVal; // string path, or true if value-less
  const awsProfileVal = get('aws-profile');
  args.awsProfile = awsProfileVal === undefined ? undefined : awsProfileVal;
  // Per-scan AWS region scoping (EE region cycle). `--aws-region <one|csv|all>`.
  // get() returns undefined (absent), true (value-less flag → error in main()),
  // or the raw string ('us-east-1' | 'us-east-1,eu-west-1' | 'all').
  const awsRegionVal = get('aws-region');
  args.awsRegion = awsRegionVal === undefined ? undefined : awsRegionVal;

  return args;
}

// EE-0.3.2.5 (CE side): cloud-provider sentinel hosts ('aws' / 'gcp' /
// 'azure', case-insensitive) are NOT real DNS names — they're scoping
// tokens that EE cloud-scanner plugins (020/021/022/023/030) interpret
// as "this run targets the cloud provider via its API, not a network
// address." resolveAndValidate() returns ENOTFOUND for these, so pre-
// 0.3.2.5 customers had to set NSA_ALLOW_ALL_HOSTS=1 to bypass — which
// is undocumented AND disables the guard for legitimate RFC 1918 / IP
// targets in the same scan. Whitelist the sentinels in scanSingleHost
// so cloud scans Just Work and the env-var bypass remains scoped to
// its documented use case (local-network auditing).
//
// Hoisted to module scope so the Set is built once at module load
// rather than per scanSingleHost() call (reviewer L1 fold).
const CLOUD_SENTINEL_HOSTS = new Set(['aws', 'gcp', 'azure']);

async function scanSingleHost(pm, host, plugins, opts, promptMode) {
  // SSRF guard — block loopback, private ranges, cloud metadata endpoints.
  // Set NSA_ALLOW_ALL_HOSTS=1 to scan RFC 1918 / private ranges (local network auditing).
  // Cloud-sentinel hosts (see CLOUD_SENTINEL_HOSTS above) skip the guard.
  const isCloudSentinel = typeof host === 'string' && CLOUD_SENTINEL_HOSTS.has(host.toLowerCase());

  if (!process.env.NSA_ALLOW_ALL_HOSTS && !isCloudSentinel) {
    if (isBlockedIp(host)) {
      throw new Error(`Scanning blocked address range is not allowed: ${host}`);
    }
    // Hostname (not literal IP) — resolve and validate the resolved address
    if (!/^[\d.:[\]]+$/.test(host)) {
      try {
        await resolveAndValidate(host);
      } catch (err) {
        throw new Error(`Host rejected by SSRF guard: ${err.message}`);
      }
    }
  }

  const { results, conclusion } = await pm.run(host, plugins || 'all', opts);

  // Enrich conclusion with MITRE ATT&CK technique mapping
  const techniques = getAllTechniques(conclusion);
  if (techniques.length > 0) {
    conclusion.result = conclusion.result || {};
    conclusion.result.techniques = techniques;
  }

  // Pre-compute the per-scan output folder so EE enrichment, compliance
  // artifacts, and AI outputs all land in the same directory. maybeSendToOpenAI
  // will reuse this presetOutDir below.
  const baseOutDir = resolveBaseOutDir();
  await fsp.mkdir(baseOutDir, { recursive: true });
  const ts        = nowStamp();
  const outDir    = path.join(baseOutDir, `${safeHost(host)}_${ts}`);
  await fsp.mkdir(outDir, { recursive: true });

  // EE enrichment hook — no-op if @nsasoft/nsauditor-ai-ee is not installed
  // or the license tier doesn't grant intelligenceEngine. Compliance + outDir
  // are forwarded so EE can write scan_finding_queue.json and SOC 2 artifacts.
  //
  // CE-0.1.30.5: forward the per-plugin `results` array. This is the hard
  // dependency that makes EE-0.3.2.1's cloud-finding harvester actually
  // work in production — pre-CE-0.1.30, EE only saw the concluder object
  // (single plugin output) and could not harvest findings from cloud
  // plugins (020/030/etc.) that live in pm.run().results[]. Without this
  // line, EE 0.3.2 emits a runtime warning ("CE 0.1.30+ … running with
  // older CE") AND continues to produce false-clean SOC 2 reports against
  // AWS accounts. EE 0.3.2 + CE 0.1.30 ship as a paired release; mixing
  // versions is supported but the EE-side cloud-harvest behavior requires
  // CE-0.1.30+ to take effect.
  // ⚠️ THE IMPORT AND THE CALL GET SEPARATE CATCHES, AND THE SPLIT IS THE POINT.
  // A single bare `catch {}` around both made "EE is not installed" — a legitimate,
  // expected, silent skip for every Community user — indistinguishable from "EE ran and
  // THREW", which silently deletes the deliverable: the scan exits 0, writes no compliance
  // report, and prints nothing. That is the false-clean shape, and it is the channel a
  // whole class of defects has reached production through (a malformed env var did exactly
  // this until 0.33.0 moved the parse). Absence stays silent; failure is named and the run
  // is marked, because an operator who asked for `--compliance` and got no report must not
  // have to diff directories to discover it.
  let ee = null;
  try {
    ee = await import('@nsasoft/nsauditor-ai-ee');
  } catch { /* EE not installed — CE proceeds unchanged. The ONLY silent case. */ }
  try {
    const eeEnrichment = ee ? await ee.enrichScan(conclusion, {
      host,
      outDir,
      compliance:      opts.compliance ?? process.env.COMPLIANCE_FRAMEWORKS ?? null,
      complianceScope: opts.complianceScope ?? null,
      // EE 0.33.0 (N2). Forwarded verbatim; EE owns the defaults, the validation and
      // the path-or-object handling for the policy.
      complianceTrackSla:    opts.complianceTrackSla,
      complianceHistoryRoot: opts.complianceHistoryRoot,
      slaPolicy:             opts.slaPolicy,
      results,
      onWarn: (msg) => console.warn(`[EE] ${msg}`),
    }) : null;
    if (eeEnrichment?.enrichedPrompt) {
      conclusion.result = conclusion.result || {};
      conclusion.result.eeEnrichment = eeEnrichment;
    }
  } catch (err) {
    // EE IS PRESENT AND FAILED. Never silent: name the stage that was lost, and mark the
    // conclusion so a downstream reader can tell "no findings" from "the stage that finds
    // them did not run". Still non-fatal — a scan that completed its CE work is worth
    // keeping — but it is now a visible degradation rather than an invisible one.
    console.error(`[EE] enrichment FAILED — this scan has no compliance report, no `
      + `intelligence enrichment and no analysis-agent findings: ${err?.message ?? err}`);
    conclusion.result = conclusion.result || {};
    conclusion.result.eeEnrichmentError = String(err?.message ?? err);
  }

  const { file_paths: ai_file_paths, ai_conclusion, ai_status, ai_error } = await maybeSendToOpenAI({ host, results, conclusion, promptMode, outDir });
  // BUG1 (fail-VISIBLE): a one-line end-of-scan AI status so a failed/aborted AI
  // conclusion is not silently swallowed under the per-stage logs.
  console.log(aiSummaryLine({ host, ai_status, ai_error }));

  // --- Scan history: record & compare ---
  let scanDiff = null;
  try {
    const outRoot = toCleanPath(process.env.SCAN_OUT_PATH || process.env.OPENAI_OUT_PATH || 'out').replace(/\.[^/.]+$/, '') || 'out';
    const services = conclusion?.result?.services ?? [];
    const serviceFindingsCount = services.reduce((n, svc) => {
      if (svc.anonymousLogin === true) n++;
      if (svc.axfrAllowed === true) n++;
      if (Array.isArray(svc.weakAlgorithms)) n += svc.weakAlgorithms.length;
      if (Array.isArray(svc.dangerousMethods)) n += svc.dangerousMethods.length;
      const cves = svc.cves || svc.cve || [];
      if (Array.isArray(cves)) n += cves.length;
      return n;
    }, 0);
    // review fold R-1: cloud plugins emit findings on `results[].result.findings`,
    // NOT as service-level attrs — so a cloud (--host aws) scan recorded
    // findingsCount:0 in scan_history over a 201-finding scan (a false-clean
    // history channel). Roll cloud findings into findingsCount + surface the split.
    const cloudFindingsCount = (results || []).reduce((n, r) => {
      const f = r?.result?.findings;
      return n + (Array.isArray(f) ? f.length : 0);
    }, 0);
    const findingsCount = serviceFindingsCount + cloudFindingsCount;

    const scanSummary = {
      timestamp: new Date().toISOString(),
      host,
      servicesCount: services.length,
      openPorts: services.filter((s) => s.status === 'open').map((s) => s.port),
      os: conclusion?.result?.host?.os ?? null,
      findingsCount,
      cloudFindingsCount,
      services: services.map((s) => ({
        port: s.port, protocol: s.protocol ?? 'tcp',
        service: s.service ?? null, version: s.version ?? null,
      })),
    };

    // Retrieve previous scan for this host before recording the new one
    const previous = await getLastScan(outRoot, host);
    await recordScan(outRoot, scanSummary);
    // CE: enforce 7-day JSONL retention (Pro/Enterprise: unlimited).
    // Note: concurrent parallel scans on the same outRoot can race here (TOCTOU);
    // acceptable for CE — production deployments should use a single scan process per directory.
    if (getTierFromEnv() === 'ce') {
      await pruneForCE(path.join(outRoot, HISTORY_FILE));
    }

    scanDiff = computeDiff(scanSummary, previous);
    if (previous) {
      console.log(`[ScanHistory] ${host}: ${scanDiff.summary}`);
    } else {
      console.log(`[ScanHistory] ${host}: First scan recorded.`);
    }
  } catch (err) {
    console.warn('[ScanHistory] Failed to record/compare scan:', err?.message || err);
  }

  return { host, results, conclusion, ai_file_paths, ai_conclusion, ai_status, ai_error, scanDiff };
}

/* -------------------- CI/CD severity threshold helpers ------------------- */

const SEVERITY_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

/**
 * Determine the maximum severity level present in a conclusion's services.
 * Checks security findings (anonymousLogin, axfrAllowed, weakAlgorithms,
 * dangerousMethods, CVEs) as well as open service status.
 * @param {object} conclusion
 * @returns {number} highest severity rank found (0-4)
 */
async function readSecretFromStdin(keyName) {
  if (!process.stdin.isTTY) {
    // Piped input
    return new Promise((resolve) => {
      let data = '';
      process.stdin.setEncoding('utf8');
      process.stdin.on('data', (chunk) => { data += chunk; });
      process.stdin.on('end', () => resolve(data.trim() || null));
    });
  }
  // Interactive prompt
  const { createInterface } = await import('node:readline');
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  return new Promise((resolve) => {
    rl.question(`Enter value for ${keyName}: `, (answer) => {
      rl.close();
      resolve(answer.trim() || null);
    });
  });
}

function maxSeverityInConclusion(conclusion) {
  const services = conclusion?.result?.services || [];
  let max = 0;

  for (const svc of services) {
    // anonymousLogin or axfrAllowed → Critical
    if (svc.anonymousLogin === true) max = Math.max(max, SEVERITY_RANK.critical);
    if (svc.axfrAllowed === true) max = Math.max(max, SEVERITY_RANK.critical);

    // weakAlgorithms or dangerousMethods → Medium
    if (Array.isArray(svc.weakAlgorithms) && svc.weakAlgorithms.length > 0) max = Math.max(max, SEVERITY_RANK.medium);
    if (Array.isArray(svc.dangerousMethods) && svc.dangerousMethods.length > 0) max = Math.max(max, SEVERITY_RANK.medium);

    // CVEs
    const cves = svc.cves || svc.cve || [];
    if (Array.isArray(cves)) {
      for (const cve of cves) {
        const sev = typeof cve === 'string' ? 'high' : String(cve?.severity || 'high').toLowerCase();
        max = Math.max(max, SEVERITY_RANK[sev] ?? SEVERITY_RANK.high);
      }
    }

    // Open service → Info (baseline)
    if (svc.status === 'open') max = Math.max(max, SEVERITY_RANK.info);
  }

  return max;
}

/**
 * CLI GRC-push startup preflight. Gates on the SAME condition the push itself runs
 * under — a `scan` that requests a compliance framework — so a framework-less recon
 * scan or a non-scan command with a globally-set `COMPLIANCE_GRC_PROVIDER` is NEVER
 * hard-failed at startup (the push is gated by `runCompliancePhase` returning null
 * with no frameworks — `nsauditor-ai-ee/utils/compliance_phase.mjs`). When a push IS
 * configured, validate the config now via EE's `preflightGrcConfig` so a bad token /
 * control-map / provider / redaction mode fails IMMEDIATELY instead of after a full
 * scan (a real per-org UX gap for an MSP). GRC push is an EE feature, so:
 *   - not a scan / no framework / GRC not requested → no-op (never imports EE);
 *   - EE unavailable → skip silently (no EE ⇒ no push ⇒ nothing to preflight;
 *     mirrors the enrichScan EE-optional pattern);
 *   - EE too old to export the fn → skip;
 *   - a `GrcConfigError` from preflightGrcConfig PROPAGATES so main() can
 *     fail-fast (exit 1) with the module's token-free message.
 * @param {object} env - process.env (or a test env)
 * @param {object} [opts] - { cmd, frameworks, importEE(test seam) }
 * @returns {Promise<{ran:boolean, reason?:string}>}
 */
/**
 * STARTUP POSTURE VETO — `NSAUDITOR_OFFLINE_ONLY=1` against a configured egress path.
 *
 * EE raises this as an `NsauditorConfigError` from `resolveComplianceEnvOpts`, and exports
 * that function specifically so CE can fail fast at startup with the SAME definition of
 * "offline". Until now nothing called it, and the veto's only route into CE was through
 * `enrichScan` — which at the time meant a bare `catch {}` on the scan path that did not
 * abort the scan: it silently dropped the ENTIRE EE stage (intelligence, agents, the
 * compliance report). A quiet skip wearing a fail-fast's name, one repo over from the test
 * that forbids exactly that.
 *
 * ⚠️ THAT CATCH IS NO LONGER BARE — the tense above is deliberate and was wrong until now.
 * The import and the call carry SEPARATE catches (see the scan path below): absence stays
 * silent, because a Community user legitimately has no EE, while FAILURE is named and
 * `conclusion.result.eeEnrichmentError` is set. This docblock argued from its own file's
 * corrected defect, in the present tense, forty lines from the code that fixes it — and it
 * was the FOURTH site of one dead premise, the other three being EE's §16.1 row, the
 * `nsauditor_env` docblock and that test's assertion message. The preflight's REASON is
 * unaffected: a contradiction between two operator settings should stop the run at startup
 * regardless of how loudly a later failure would report itself.
 *
 * Deliberately NOT gated on the command and NOT gated on a licence tier — a contradiction
 * between two operator settings is a configuration error under every command, and
 * `enrichScan` never even evaluated it below Pro tier. `tests/cli_posture_preflight.test.mjs`
 * pins both of those as decisions rather than accidents, and explains why this exits 2 while
 * the GRC preflight below exits 1.
 *
 * EE stays optional: an unresolvable EE means no EE egress paths to veto, and that is a
 * reason, not a failure.
 *
 * @param {Record<string,string|undefined>} env
 * @param {{importEE?: Function}} [opts]  `importEE` is the test seam — these cases must not
 *   require EE to be installed, the same convention `preflightGrcIfRequested` uses.
 * @returns {Promise<{ran: boolean, reason?: string}>}
 * @throws the EE `NsauditorConfigError` verbatim, so main() can print it and exit 2
 */
export async function preflightNsauditorPosture(env, opts = {}) {
  const { importEE } = opts;
  let ee;
  try {
    ee = importEE ? await importEE() : await import('@nsasoft/nsauditor-ai-ee');
  } catch {
    return { ran: false, reason: 'ee-unavailable' };
  }
  if (typeof ee?.resolveComplianceEnvOpts !== 'function') return { ran: false, reason: 'ee-too-old' };
  ee.resolveComplianceEnvOpts(env);
  return { ran: true };
}

export async function preflightGrcIfRequested(env, opts = {}) {
  const { cmd, frameworks, importEE } = opts;
  if (cmd !== 'scan') return { ran: false, reason: 'not-scan' };
  if (!String(frameworks ?? '').trim()) return { ran: false, reason: 'no-frameworks' };
  if (!String(env?.COMPLIANCE_GRC_PROVIDER ?? '').trim()) return { ran: false, reason: 'not-requested' };
  let ee;
  try {
    ee = importEE ? await importEE() : await import('@nsasoft/nsauditor-ai-ee');
  } catch {
    return { ran: false, reason: 'ee-unavailable' };
  }
  if (typeof ee?.preflightGrcConfig !== 'function') return { ran: false, reason: 'ee-too-old' };
  // Config fail-fast. The zero-map guard runs UNSCOPED (frameworks not threaded) —
  // safe (no false-fails); a per-framework-empty map still warns+no_ops at push time.
  await ee.preflightGrcConfig(env);
  return { ran: true };
}

export async function main() {
  const args = await parseArgs(process.argv);
  const { cmd, host, plugins, insecureHttps, hostFile, parallel, failOn, outputFormat, watch, intervalMinutes, webhookUrl, alertSeverity, ports, compliance, complianceScope, complianceHistory, slaPolicy, attestWindow, framework, awsRegion, approvalArgs } = args;

  // Version: handled before license verification so it works without a key.
  // CE-0.1.30.1 — closes the discovery-flag UX gap where pre-fix
  // `nsauditor-ai --version` errored with "Fatal: --host or --host-file
  // is required". Output format mirrors GNU `--version` convention:
  // "<tool> <version>" on a single line, then exit 0.
  if (cmd === 'version') {
    console.log(`nsauditor-ai ${TOOL_VERSION}`);
    process.exit(0);
  }

  // Help: handled before license verification so it works without a key.
  if (cmd === 'help') {
    console.log(`nsauditor-ai — Modular AI-assisted network security audit platform

Usage:
  nsauditor-ai [scan] --host <ip|cidr|hostname> [options]
  nsauditor-ai [scan] --host-file <path> [options]
  nsauditor-ai license <subcommand>
  nsauditor-ai security <subcommand>
  nsauditor-ai validate
  nsauditor-ai version          (or --version / -v)
  nsauditor-ai help             (or --help / -h)

Scan options:
  --host, --ip, --target <h>   Target host, IP, or CIDR
  --host-file <path>           File with one host per line (cloud sentinels in the
                               file reconcile CLOUD_PROVIDER the same as --host)
  --env <path>                 Load a dotenv (KEY=value) file for this scan (per-account
                               credentials). Override-on; missing file = hard error.
  --aws-profile <name>         Use a named profile from the OS-default ~/.aws/credentials.
                               Implies CLOUD_PROVIDER=aws; overrides explicit AWS_* keys.
  --aws-region <r>             AWS region scope: one (us-east-1), CSV (us-east-1,eu-west-1),
                               or 'all' (every account-enabled region). Default: AWS_REGION
                               if set, else a single region with an incomplete-coverage notice.
  --plugins <list|all>         Plugins to run (e.g. 001,003,020 or "all"; default: all)
  --ports <range>              Override port list (e.g. 22,80,443 or 1-1000)
  --out <dir>                  Output directory for scan artifacts
  --parallel <n>               Parallel host concurrency (default 1)
  --fail-on <severity>         Exit non-zero if any finding ≥ severity
  --output-format <fmt>        Additional report format: sarif | csv | md
  --insecure-https             Skip TLS validation on probed HTTPS targets
  --watch                      CTEM continuous ALERTING mode: re-scan on --interval,
                               diff against the previous cycle, fire --webhook-url when a
                               change crosses --alert-severity. NOT an evidence cadence —
                               it adds no retention or cross-run aggregation, skips SARIF/
                               CSV/Markdown output and --fail-on, and dies with this process.
                               Each tick is an ordinary scan, so with --compliance it writes
                               that tick's artifacts; nothing relates them across ticks. For
                               SOC 2 Type II history use a scheduler (cron/systemd/CI).
  --interval <minutes>         Watch interval (default 60)
  --webhook-url <url>          Send delta alerts (must be public; private/loopback blocked)
  --alert-severity <sev>       Min severity to alert on (default: high)
  --compliance <framework>     Map findings to controls. 'all' = all 7 frameworks, or a CSV
                               of soc2,hipaa,nist-csf,pci-dss,iso-27001,cis-v8,gdpr (aliases
                               nist/pci/iso/cis). Unknown tokens fail fast. Enterprise only.
  --compliance-scope <path>    JSON file describing the assessment scope
  --compliance-history <dir>   Directory of prior scans (one subdirectory per scan). Turns on
                               SLA/MTTR longitudinal tracking against that history. Enterprise.
  --sla-policy <path>          JSON file of SLA thresholds per severity; defaults to the
                               shipped data/compliance/sla.json. Turns SLA tracking on by
                               itself. Relative paths resolve against the current
                               directory. Enterprise.

Compliance subcommands:
  nsauditor-ai compliance attest --history <dir> [--framework <fw>] [--window 6m|12m|90d]
  nsauditor-ai compliance keygen --key <path> [--approver <name>] [--email <e>] [--role <r>]
                                 [--team <t>] [--force]
                                 Generate an Ed25519 approval keypair (private 0600) and print
                                 the identity-registry member to paste. Refuses to overwrite an
                                 existing key without --force: regenerating makes every
                                 signature that key ever made unverifiable. Enterprise.
  nsauditor-ai compliance suppress --suppressions <file> --source <s> --title-pattern <p>
                                 --status <accepted_risk|false_positive> --rationale <text>
                                 --approver <name> [--expires-in-days <n>]
                                 [--attestation-level <approver|deployment>]
                                 [--compensating-control <text>]
                                 Records an approval. SIGNS it when NSAUDITOR_SIGNING_KEY names
                                 a local Ed25519 PEM; records it unsigned otherwise, and the
                                 report labels which. A malformed key fails HERE, never on a
                                 scan. Enterprise.
  nsauditor-ai compliance review --history <dir>
                                 Expiry review across a scan-history root. Enterprise.
  nsauditor-ai compliance renew --suppressions <file> --id <id> --rationale <text>
                                 --approver <name> [--expires-in-days <n>]
                                 Extends an approval and records the renewal chain. Enterprise.
                                        Aggregate the per-scan attestation records in
                                        <dir> into a multi-period (Type II) recurring-scan
                                        attestation. Reads scan_attestation_<fw>.json from
                                        each subdirectory, so a history you already have is
                                        aggregatable. Discovery is ONE level deep and the
                                        report says so. Exits 3 when no evidence is found —
                                        an empty history is a finding, not a pass.

License subcommands:
  nsauditor-ai license install <KEY>    Verify and persist a license key (Keychain
                                        on macOS, ~/.nsauditor/.env on Linux/Windows
                                        with mode 0600). Rejects invalid/expired keys.
  nsauditor-ai license --status         Show active tier, org, seats, expiry
  nsauditor-ai license --capabilities   List active capabilities for current tier
  nsauditor-ai license --plugins        List discovered plugins grouped by source
                                        (CE / EE / custom) with active-or-required-tier

  Bought on AWS Marketplace? Your license key is delivered by registration, not npm:
  register at https://www.nsauditor.com/ai/marketplace/register/ with your AWS account
  ID + Agreement ID (agmt-..., from AWS Console -> AWS Marketplace -> Manage subscriptions),
  then install the emailed key with 'license install <key>' or NSAUDITOR_LICENSE_KEY.

MCP server-auth subcommands (EE-SEC.1):
  nsauditor-ai mcp install-key          Generate a new MCP auth key, persist (Keychain
                                        on macOS, ~/.nsauditor/.env elsewhere), print
                                        Claude Desktop config snippet. Run ONCE per
                                        machine; without this the MCP server refuses
                                        to start (anti-spoofing for Pro/Enterprise tools).
  nsauditor-ai mcp install-key <KEY>    Persist a caller-supplied key (e.g., enterprise-
                                        managed secret). Validates shape before storing.
  nsauditor-ai mcp print-key --confirm  Reveal the stored key (use with care)
  nsauditor-ai mcp rotate-key           Replace the stored key with a fresh one
  nsauditor-ai mcp status               Show storage source without revealing the key
  nsauditor-ai mcp tier                 Print actual MCP server tier (ground truth — bypasses
                                        Claude AI synthesis when "list_plugins" reports
                                        unexpected CE despite verified Pro/Enterprise license)

Security subcommands (macOS Keychain):
  nsauditor-ai security set <KEY>       Store a secret (read from stdin)
  nsauditor-ai security delete <KEY>    Remove a secret
  nsauditor-ai security list            List stored secrets (masked)
  nsauditor-ai security get <KEY>       Echo a secret (avoid in shared shells)

Environment:
  NSAUDITOR_LICENSE_KEY          Pro/Enterprise license JWT (env var; takes precedence)
  NSA_MCP_AUTH_KEY               MCP server auth key — read by mcp_server at startup;
                                 client supplies via Claude Desktop config env block
  NSA_MCP_AUTH_DISABLE=1         Skip MCP auth check (CI/dev escape hatch — emits warn)
  NSA_ALLOW_ALL_HOSTS=1          Permit RFC1918 / loopback (local-network auditing)
  CLOUD_PROVIDER=aws|gcp|azure   Required for cloud scanner plugins (020/021/022/023/030)
  AI_PROVIDER=openai|claude|ollama   AI provider for report generation
  NSAUDITOR_TSA_URL              RFC 3161 timestamp authority for compliance attestation.
                                 No default, ever — unset means the feature is absent.
                                 Refused at startup together with NSAUDITOR_OFFLINE_ONLY=1.

Cloud-scan hosts:
  --host aws[,gcp,azure]         One or more cloud sentinel literals, comma-separated
                                 (case-insensitive): use 'aws' for one cloud, or
                                 'aws,gcp,azure' to audit all three in one run (each cloud
                                 is scanned in turn). Do NOT write aws|gcp|azure with pipe
                                 characters — your shell treats | as a pipe. Sentinels are
                                 not DNS-resolved; they route the scan to the matching
                                 cloud-scanner plugins via the provider's control-plane
                                 API, and imply CLOUD_PROVIDER to the cloud leg(s) when
                                 unset ('aws,gcp,azure' → CLOUD_PROVIDER=aws,gcp,azure).
                                 A CLOUD_PROVIDER already pinned to a cloud that does NOT
                                 cover every requested leg is a hard error (fail-fast),
                                 not a silent skip of the uncovered legs. With
                                 --plugins all the scan AUTO-SCOPES to only that cloud's
                                 plugins (plugins not applicable to this host are skipped +
                                 logged — other-cloud plugins run on their OWN --host pass,
                                 non-cloud plugins need a network host) — so --plugins all
                                 is safe here.
                                 Note: the composite zero-trust checker (1023) has no
                                 single cloud and is therefore skipped under this
                                 auto-scope. It runs on a NETWORK host/CIDR scan with
                                 the full plugin set; selecting it by id on its own
                                 does not work, because it needs a discovery plugin to
                                 confirm the host is up first.
                                 INVERSE (cloud scope integrity): a cloud auditor runs
                                 ONLY on its own sentinel host. On a NETWORK host (IP /
                                 CIDR / hostname) the cloud-scanner plugins NEVER run —
                                 not via --plugins all, not via an explicit --plugins
                                 1020, and not because cloud credentials are present in
                                 the environment. '--host' is the sole cloud-scan
                                 trigger; credentials are a capability, not intent.

Examples:
  nsauditor-ai scan --host 10.0.0.1 --plugins all
  CLOUD_PROVIDER=aws AWS_PROFILE=default \\
    nsauditor-ai scan --host aws --plugins all --compliance all   # full AWS audit, all 7 frameworks
  nsauditor-ai scan --host aws,gcp,azure --plugins all --compliance all   # all 3 clouds in one run
  nsauditor-ai scan --host 10.0.0.0/24 --plugins all --compliance soc2
  nsauditor-ai license install enterprise_eyJhbGciOiJFUzI1NiIs...
  nsauditor-ai license --status

Docs: https://www.nsauditor.com/ai/   |   Pricing: https://www.nsauditor.com/ai/pricing/`);
    process.exit(0);
  }

  // Per-scan environment selection (--env / --aws-profile) + sentinel-host
  // implied CLOUD_PROVIDER. The eager `import 'dotenv/config'` at the top of
  // this file already loaded the default cwd `.env` (override-off) for
  // import-time consumers; this layers the explicitly-selected env ON TOP
  // (override-on) before license + dispatch.
  if (args.env === true) {
    console.error('Error: --env requires a file path (e.g. --env ~/envs/prod.env)');
    process.exit(2);
  }
  if (args.awsProfile === true) {
    console.error('Error: --aws-profile requires a profile name (e.g. --aws-profile prod)');
    process.exit(2);
  }
  // Resolve the scan host list up-front (scan command only) so the CLOUD_PROVIDER
  // reconcile below (resolveScanEnv) sees --host-file cloud-sentinel legs too. With
  // --host-file the `host` arg is undefined, so without this a host-file of cloud
  // sentinels would bypass the fail-fast/imply reconcile entirely. Reused as the
  // scan target below (no double-parse); a parse failure is left to the scan-time
  // resolution so the existing error path + exit code are unchanged.
  let resolvedHosts = null;
  if (cmd === 'scan' && hostFile) {
    try { resolvedHosts = await parseHostFile(hostFile); } catch { /* defer to scan-time resolution */ }
  }
  try {
    const { resolveScanEnv } = await import('./utils/env_loader.mjs');
    const fsm = await import('node:fs');
    const patch = resolveScanEnv({
      envPath: typeof args.env === 'string' ? args.env : undefined,
      awsProfile: typeof args.awsProfile === 'string' ? args.awsProfile : undefined,
      host,
      hosts: resolvedHosts ?? undefined,
      env: process.env,
      fileExists: (p) => fsm.existsSync(p),
      readFile: (p) => fsm.readFileSync(p, 'utf8'),
    });
    Object.assign(process.env, patch.set);          // override-on
    for (const k of patch.unset) delete process.env[k];
  } catch (err) {
    console.error(`Error: ${err.message}`);
    process.exit(1);
  }

  // GRC-push startup preflight (EE 0.32.x): if this scan would push (a `scan` with a
  // compliance framework + COMPLIANCE_GRC_PROVIDER set), validate the config NOW (after
  // --env load) so a bad token / control-map / provider fails fast instead of after a
  // full scan. The helper gates on the exact push condition (so a framework-less recon
  // scan / non-scan command is never hard-failed) + silently skips if EE isn't installed.
  // Posture veto FIRST — before the GRC preflight and before any scan work. An operator who
  // has forbidden outbound connections and also configured one must hear about it here, not
  // from an EE stage that a bare catch would drop on the floor. Exit 2 matches
  // `compliance attest`, the other door into the same veto.
  try {
    await preflightNsauditorPosture(process.env);
  } catch (err) {
    console.error(`Fatal: ${err.message}`);
    process.exit(2);
  }

  try {
    await preflightGrcIfRequested(process.env, { cmd, frameworks: args.compliance ?? process.env.COMPLIANCE_FRAMEWORKS });
  } catch (err) {
    // GrcConfigError (bad token/map/provider/redaction). The module's message is
    // token-free by construction; surface it and fail-fast.
    console.error(`Error: GRC push config invalid — ${err.message}`);
    process.exit(1);
  }

  // Build the AWS region intent AFTER env load so AWS_REGION (.env/shell) is visible.
  // Explicit --aws-region fail-fasts on an unknown region.
  let awsRegionIntent = null;
  try {
    const { buildRegionIntent } = await import('./utils/region_intent.mjs');
    awsRegionIntent = buildRegionIntent(awsRegion);
  } catch (err) {
    console.error(`Error: ${err.message}`);
    process.exit(2);
  }

  // Verify license JWT at startup (~5ms for ES256). Populates _verifiedTier
  // so all subsequent getTierFromEnv() calls return the cryptographically
  // validated tier instead of relying on prefix detection alone.
  await loadLicense();

  if (cmd === 'license') {
    const { resolveCapabilities } = await import('./utils/capabilities.mjs');
    const key = process.env.NSAUDITOR_LICENSE_KEY;
    const rawArgs = process.argv.slice(2);

    if (rawArgs.includes('--status')) {
      const result = await loadLicense(key);
      const tierLabel = { ce: 'Community Edition (CE)', pro: 'Pro', enterprise: 'Enterprise' };
      if (result.valid) {
        console.log(`✓ ${tierLabel[result.tier]} license active`);
        console.log(`  Org: ${result.org}`);
        console.log(`  Seats: ${result.seats}`);
        console.log(`  License ID: ${result.licenseId}`);
        console.log(`  Expires: ${result.expiresAt}`);
      } else {
        console.log(`✗ ${tierLabel[result.tier] ?? 'Community Edition (CE)'}`);
        console.log(`  Reason: ${result.reason}`);
        if (!key) {
          console.log('\n→ Bought on AWS Marketplace? Register to receive your license key:');
          console.log('    https://www.nsauditor.com/ai/marketplace/register/');
          console.log('    (you need your AWS account ID + Agreement ID — see the listing Usage Instructions)');
          console.log('→ View Pro/Enterprise pricing: https://www.nsauditor.com/ai/pricing/');
        }
      }
      // CE 0.1.35 (Thread L mitigation v2): version provenance footer
      // matches the MCP server's list_plugins suffix exactly. Customer
      // verification flow: read versions in Claude Desktop's MCP
      // response → compare against `license --status` output here.
      // Mismatch ⇒ Claude hallucinated.
      let _eeVersion = 'not installed';
      try {
        const ee = _require('@nsasoft/nsauditor-ai-ee/package.json');
        _eeVersion = ee && ee.version ? `${ee.version} (loaded)` : 'unknown (loaded)';
      } catch { /* CE-only — fine */ }
      console.log('');
      console.log('── Installation provenance ──');
      console.log(`  nsauditor-ai (CE):              ${TOOL_VERSION}`);
      console.log(`  @nsasoft/nsauditor-ai-ee (EE):  ${_eeVersion}`);
    } else if (rawArgs.includes('--capabilities')) {
      const { CAPABILITIES } = await import('./utils/capabilities.mjs');
      const tier = getTierFromEnv();
      const caps = resolveCapabilities(tier);
      console.log(`Active capabilities for tier: ${tier}\n`);
      // ⚠️ PRINT THE DESCRIPTION, NOT JUST THE NAME. This list is read back by assistants,
      // and a bare identifier is a claim with no text behind it: `✓ airGapped` was expanded
      // into "air-gapped deployment" — a withdrawn phrase — and `✓ pdfExport` into "the
      // output is auditor-consumable via pdfExport", for a function that throws. A reader
      // given reviewed text quotes it; a reader given an identifier invents one.
      for (const [name, enabled] of Object.entries(caps)) {
        const desc = CAPABILITIES[name] && CAPABILITIES[name].desc;
        console.log(`  ${enabled ? '✓' : '✗'} ${name}`);
        if (desc) console.log(`      ${desc}`);
      }
      console.log('\nEach line above states what the capability DOES. Quote these descriptions '
        + 'rather than expanding the flag name — the name is an identifier, not a claim.');
    } else if (rawArgs.includes('--plugins')) {
      // CE-0.1.30.3 — real enumeration of discovered plugins, grouped by
      // source (CE / EE / custom NSAUDITOR_PLUGIN_PATH). Pre-fix this
      // branch crashed with `TypeError: p.toLowerCase is not a function`
      // (since hotfixed in 0.1.28 to a Usage fallback). Now: discover
      // plugins, group by `_source`, format with active/required-tier
      // status. Output format matches the EE README "Quick Start" example.
      const tier = getTierFromEnv();
      const caps = resolveCapabilities(tier);
      const pm = await PluginManager.create(`${__dirname}/plugins`);

      const groups = { ce: [], ee: [], custom: [] };
      for (const plugin of pm.plugins) {
        const source = plugin._source ?? 'ce';
        if (!groups[source]) groups[source] = [];
        groups[source].push(plugin);
      }

      const sourceLabels = {
        ce: 'CE plugins (from nsauditor-ai)',
        ee: 'EE plugins (from @nsasoft/nsauditor-ai-ee)',
        custom: 'Custom plugins (from NSAUDITOR_PLUGIN_PATH)',
      };

      // Render in fixed order: ce → ee → custom (then any unknown sources alphabetical).
      const renderOrder = ['ce', 'ee', 'custom', ...Object.keys(groups).filter((k) => !['ce','ee','custom'].includes(k)).sort()];
      let totalRendered = 0;
      for (const source of renderOrder) {
        const plugins = groups[source];
        if (!plugins || plugins.length === 0) continue;
        if (totalRendered > 0) console.log('');
        console.log(`${sourceLabels[source] ?? `${source} plugins`}:`);

        // Sort by id (string-compare keeps zero-padded ids in numeric order).
        const sorted = [...plugins].sort((a, b) =>
          String(a.id ?? '').localeCompare(String(b.id ?? ''))
        );
        for (const plugin of sorted) {
          const required = Array.isArray(plugin.requiredCapabilities) ? plugin.requiredCapabilities : [];
          const allMet = required.length === 0 || required.every((c) => Boolean(caps[c]));
          // Reviewer M2 fold: derive the required tier from the unmet
          // capability set so the "requires: …" label is accurate even
          // when the plugin doesn't declare a `tier` field. EE plugins
          // 021/022/023 (no `tier` declaration) require `cloudScanners`
          // which is enterprise-gated — pre-fold they showed
          // "requires: pro" misleadingly. Now they show "requires:
          // enterprise" via inferRequiredTier(). plugin.tier is the
          // operator-declared override; fall back to inference.
          const inferredTier = inferRequiredTier(required);
          const requiresLabel = plugin.tier ?? inferredTier ?? 'pro';
          const status = allMet ? '✓ active' : `✗ requires: ${requiresLabel}`;
          // Layout matches the EE README example:
          //   "  003 SSH Scanner            ✓ active"
          const idStr = String(plugin.id ?? '?').padEnd(3);
          const nameStr = String(plugin.name ?? '<unnamed>').padEnd(28);
          console.log(`  ${idStr} ${nameStr} ${status}`);
        }
        totalRendered += sorted.length;
      }

      if (totalRendered === 0) {
        console.log('No plugins discovered. Re-install nsauditor-ai or check NSAUDITOR_PLUGIN_PATH.');
      } else {
        console.log('');
        console.log(`  ${totalRendered} plugin${totalRendered === 1 ? '' : 's'} total · current tier: ${tier}`);
      }

      // CE 0.1.35 (Thread L mitigation v2): emit installation provenance
      // identical in shape to the MCP server's list_plugins suffix.
      // Customers comparing Claude Desktop's MCP response against the
      // CLI baseline now see the SAME version block in both places.
      // Mismatch → Claude hallucinated. Match → real tool call.
      const ceVersion = TOOL_VERSION;
      let eeVersion = 'not installed';
      try {
        const eeManifest = _require('@nsasoft/nsauditor-ai-ee/package.json');
        eeVersion = eeManifest && eeManifest.version
          ? `${eeManifest.version} (loaded)`
          : 'unknown (loaded)';
      } catch { /* CE-only install — fine */ }
      console.log('');
      console.log('── Installation provenance ──');
      console.log(`  nsauditor-ai (CE):              ${ceVersion}`);
      console.log(`  @nsasoft/nsauditor-ai-ee (EE):  ${eeVersion}`);
    } else if (rawArgs.includes('--reset')) {
      // CE-0.1.73 — atomic dual-channel license-state reset for macOS
      // license-rotation flow. Discovered EE 0.11.0 first-install
      // rehearsal (2026-05-23): customer rotates EE license, gets
      // `license_id_mismatch` because the persisted licenseId binding
      // (from a prior install) doesn't match the new JWT's licenseId.
      //
      // Single-surface clearing ("rm ~/.nsauditor/license-state.json")
      // is a HALF-fix on macOS — _readLicenseState (license.mjs:402-434)
      // ALSO reads from Keychain NSAUDITOR_LICENSE_ID, and Keychain wins
      // on read (license.mjs:429: `state.licenseId = kcId; // Keychain
      // wins`). Customer must additionally run
      // `security delete-generic-password -s nsauditor-ai -a
      // NSAUDITOR_LICENSE_ID` for the replay-defense check
      // (license.mjs:664-670) to pass. This subcommand does both
      // atomically so customers don't have to run cryptic `security`
      // commands blind from a support email.
      //
      // Default: preserves NSAUDITOR_LICENSE_KEY (the JWT itself) for
      // immediate re-activation on next license check. --purge also
      // removes the JWT (forces full re-install with `license install`).
      const purge = rawArgs.includes('--purge');
      const { _getLicenseStateFilePath } = await import('./utils/license.mjs');
      const { keychainDelete } = await import('./utils/keychain.mjs');
      const fsp = await import('fs/promises');

      const cleared = { stateFile: false, keychainId: false, jwtPurged: false };

      // 1. Delete license-state.json (cross-platform path resolver).
      const statePath = _getLicenseStateFilePath();
      try {
        await fsp.unlink(statePath);
        cleared.stateFile = true;
      } catch (e) {
        if (e && e.code !== 'ENOENT') {
          console.warn(`⚠  Could not delete ${statePath}: ${e.message}`);
        }
      }

      // 2. Delete macOS Keychain NSAUDITOR_LICENSE_ID entry. Linux /
      //    Windows have no Keychain side-channel — file delete is
      //    sufficient there.
      if (process.platform === 'darwin') {
        try {
          cleared.keychainId = await keychainDelete('NSAUDITOR_LICENSE_ID');
        } catch { /* not fatal — file delete is the primary surface */ }
      }

      // 3. Optionally purge the JWT itself (forces full re-install).
      //    Darwin-only for now; file-based JWT purge on Linux/Windows
      //    requires editing ~/.nsauditor/.env which we leave to the
      //    operator (deleting the file would also remove unrelated env
      //    vars the operator may have placed there).
      if (purge && process.platform === 'darwin') {
        try {
          cleared.jwtPurged = await keychainDelete('NSAUDITOR_LICENSE_KEY');
        } catch { /* not fatal */ }
      }

      console.log('✓ License state reset');
      console.log(`  License state file: ${cleared.stateFile ? 'deleted (' + statePath + ')' : 'not found (already clean)'}`);
      if (process.platform === 'darwin') {
        console.log(`  Keychain NSAUDITOR_LICENSE_ID: ${cleared.keychainId ? 'deleted' : 'not found (already clean)'}`);
      }
      if (purge) {
        if (process.platform === 'darwin') {
          console.log(`  Keychain NSAUDITOR_LICENSE_KEY (JWT): ${cleared.jwtPurged ? 'purged' : 'not found (already clean)'}`);
        } else {
          console.log('  JWT (NSAUDITOR_LICENSE_KEY): file-based JWT not purged on this platform — remove the NSAUDITOR_LICENSE_KEY line manually from ~/.nsauditor/.env if needed.');
        }
        console.log('');
        console.log('  Re-install with: nsauditor-ai license install <KEY>');
      } else {
        console.log('  JWT (NSAUDITOR_LICENSE_KEY): preserved (default) — next license check will re-bind.');
        console.log('');
        console.log('  Verify with: nsauditor-ai license --status');
        console.log('  (Add --purge to additionally clear the JWT for full uninstall.)');
      }
    } else if (rawArgs.includes('install')) {
      // CE-0.1.30.4 — install command. Verify the JWT FIRST, then persist
      // to a platform-appropriate location (macOS Keychain / file).
      // Closes the customer-onboarding gap where new customers had no
      // friendly way to register a license without manually editing
      // shell-rc / .env files.
      const installIdx = rawArgs.indexOf('install');
      const rawKey = rawArgs[installIdx + 1];
      const installKey = typeof rawKey === 'string' ? rawKey.trim() : '';

      if (!installKey || installKey.startsWith('-')) {
        console.error('Usage: nsauditor-ai license install <KEY>');
        console.error('  KEY is the JWT from your purchase confirmation (starts with `pro_` or `enterprise_`).');
        console.error('  Verifies the signature before persisting; invalid keys are rejected.');
        console.error('');
        console.error('Storage locations (chosen by platform):');
        console.error('  macOS:    Keychain — service "nsauditor-ai", account "NSAUDITOR_LICENSE_KEY"');
        console.error('  Linux:    $XDG_CONFIG_HOME/nsauditor/.env (or ~/.nsauditor/.env), mode 0600');
        console.error('  Windows:  %USERPROFILE%\\.nsauditor\\.env (DPAPI integration on roadmap)');
        process.exit(2);
      }

      // 1. Verify the key BEFORE persisting. Bypasses the resolver chain
      //    by passing the key explicitly to loadLicense().
      const verified = await loadLicense(installKey);
      if (!verified.valid) {
        console.error(`✗ License key rejected: ${verified.reason}`);
        console.error('  No changes made. Confirm the key matches your purchase email exactly.');
        process.exit(1);
      }

      // 2. Persist (Keychain on macOS / file elsewhere). Lazy import to
      //    avoid loading the persistor unless install is actually invoked.
      const { persistLicenseKey } = await import('./utils/license.mjs');
      const persisted = await persistLicenseKey(installKey);
      if (!persisted.ok) {
        console.error(`✗ Verification succeeded but storage failed: ${persisted.error}`);
        console.error('  Fall-back: set NSAUDITOR_LICENSE_KEY env var manually:');
        console.error('    export NSAUDITOR_LICENSE_KEY="<your-key>"');
        process.exit(1);
      }

      // 3. Confirm. Same shape as `license --status` so customers see
      //    the persisted key reflected back. NEVER print the key value
      //    itself — it's a secret. Reviewer M1 fold: surface the
      //    Keychain-fallback warning if the persistor returned one
      //    (silent fallback would leave macOS users believing they
      //    have Keychain protection when they don't).
      const tierLabel = { ce: 'Community Edition (CE)', pro: 'Pro', enterprise: 'Enterprise' };
      if (persisted.warning) {
        console.warn(`⚠  ${persisted.warning}`);
      }
      console.log(`✓ ${tierLabel[verified.tier]} license installed`);
      console.log(`  Stored at: ${persisted.location}`);
      console.log(`  Org: ${verified.org}`);
      console.log(`  Seats: ${verified.seats}`);
      console.log(`  License ID: ${verified.licenseId}`);
      console.log(`  Expires: ${verified.expiresAt}`);
      console.log('');
      console.log('  Verify with: nsauditor-ai license --status');
    } else {
      console.log('Usage: nsauditor-ai license --status | --capabilities | --plugins | install <KEY> | --reset [--purge]');
    }
    process.exit(0);
  }

  // EE-SEC.1: MCP server authentication management. Generates, stores,
  // and inspects the shared secret that authorizes Claude Desktop (or
  // any MCP client) to call the local MCP server. Without this, any
  // process running as the operator could spawn the server and call
  // the Pro/Enterprise tools — including the AWS-talking shadow-admin
  // path detectors in EE 0.3.4. See utils/mcp_auth.mjs for the full
  // threat model.
  if (cmd === 'mcp') {
    const {
      generateMcpAuthKey,
      validateMcpAuthKeyShape,
      persistMcpAuthKey,
      reportMcpAuthSource,
      MCP_AUTH_ENV_VAR,
      MCP_AUTH_DISABLE_ENV_VAR,
    } = await import('./utils/mcp_auth.mjs');

    const rawArgs = process.argv.slice(2);
    const subCmd = rawArgs[1]; // install-key | print-key | rotate-key | status

    async function printConfigSnippet(key, persistedLocation) {
      // Thread K (CE 0.1.32): generate a MACHINE-SPECIFIC config snippet
      // so customers don't have to figure out:
      //   - which Node binary Claude Desktop should call (system /
      //     homebrew / nvm / fnm — Claude Desktop's launchd PATH does
      //     NOT include nvm/fnm bin dirs reliably)
      //   - which absolute path to the .mjs script
      //   - whether to use `keychain:` indirection (macOS only) or
      //     literal value (Linux/Windows)
      //   - whether to also include the license env line (only if
      //     license is configured AND we can avoid baking the JWT
      //     into the world-readable config file)
      //
      // This eliminates the install-type matrix that was the #1
      // source of customer-onboarding friction.
      const isDarwin = platform() === 'darwin';

      // process.execPath is the actual Node binary executing this CLI.
      // For nvm: /Users/<u>/.nvm/versions/node/vX.Y.Z/bin/node
      // For homebrew: /opt/homebrew/bin/node
      // For system: /usr/local/bin/node or /usr/bin/node
      // Always absolute; always the right binary that loaded our code.
      const nodeBin = process.execPath;

      // The script path: derive from where THIS cli.mjs file lives,
      // then walk to the bin/ directory. cli.mjs is at the package
      // root; bin/nsauditor-ai-mcp.mjs is its sibling.
      // import.meta.url gives the file:// URL of THIS cli.mjs.
      const cliUrl = new URL(import.meta.url);
      const cliPath = fileURLToPath(cliUrl);
      const pkgRoot = path.dirname(cliPath);
      const mcpScriptPath = path.join(pkgRoot, 'bin', 'nsauditor-ai-mcp.mjs');

      // MCP auth: keychain: indirection on macOS (no plaintext in
      // config file). Literal value on Linux/Windows where there's
      // no system secret store equivalent.
      const onKeychain = typeof persistedLocation === 'string' && persistedLocation.includes('Keychain');
      const authEnvValue = onKeychain ? `keychain:${MCP_AUTH_ENV_VAR}` : key;

      // License: detect whether configured and where it lives. On
      // macOS, prefer the keychain: indirection — same no-plaintext
      // pattern as auth. If license is in file (~/.nsauditor/.env)
      // but NOT in Keychain, we'll prompt the operator to migrate
      // (handled by the caller; this fn just emits the snippet).
      const { loadLicense } = await import('./utils/license.mjs');
      const licenseStatus = await loadLicense();
      const licenseConfigured = licenseStatus.valid;

      // Build the env block as a JSON-serializable object so the
      // snippet output is valid JSON the operator can paste verbatim.
      const envBlock = {};
      envBlock[MCP_AUTH_ENV_VAR] = authEnvValue;
      if (licenseConfigured) {
        if (isDarwin) {
          // Indirection — secret stays in Keychain. Requires that
          // the license actually IS in Keychain (or in a place
          // resolveSecret can reach). Caller is responsible for
          // ensuring this is true before printing the snippet.
          envBlock['NSAUDITOR_LICENSE_KEY'] = 'keychain:NSAUDITOR_LICENSE_KEY';
        }
        // On Linux/Windows we deliberately OMIT NSAUDITOR_LICENSE_KEY
        // from the env block — the MCP server will fall through to
        // the file fallback (~/.nsauditor/.env). Including a literal
        // JWT would expose it in the world-readable config file.
      }

      const snippet = {
        mcpServers: {
          'nsauditor-ai': {
            command: nodeBin,
            args: [mcpScriptPath],
            env: envBlock,
          },
        },
      };

      console.log('');
      console.log('═'.repeat(70));
      console.log('Claude Desktop config — paste this into:');
      if (isDarwin) {
        console.log('  ~/Library/Application Support/Claude/claude_desktop_config.json');
      } else if (platform() === 'win32') {
        console.log('  %APPDATA%\\Claude\\claude_desktop_config.json');
      } else {
        console.log('  ~/.config/Claude/claude_desktop_config.json');
      }
      console.log('═'.repeat(70));
      // Pretty-print with 2-space indent. If the operator already has
      // mcpServers, they merge the inner "nsauditor-ai" block.
      console.log(JSON.stringify(snippet, null, 2));
      console.log('═'.repeat(70));
      console.log('');

      if (onKeychain) {
        // macOS + Keychain reachable: the snippet uses indirection
        // for both auth and license. Secret never lands in the
        // world-readable Claude Desktop config file.
        console.log('Security notes:');
        console.log(`  • Auth key uses "keychain:${MCP_AUTH_ENV_VAR}" indirection — the actual`);
        console.log('    secret stays in macOS Keychain. The config file contains only the');
        console.log('    placeholder string, NOT the secret.');
        if (licenseConfigured) {
          console.log('  • License key uses the same indirection — JWT never lands in the config.');
        } else {
          console.log('  • No license configured. To activate Pro/Enterprise features:');
          console.log('      nsauditor-ai license install <YOUR-KEY>');
          console.log('    Then re-run `nsauditor-ai mcp install-key` to get a snippet that');
          console.log('    includes the license line.');
        }
        console.log('');
        console.log('  • On a HEADLESS macOS / SSH-only CI runner where Keychain GUI prompts');
        console.log("    won't reach you, replace the placeholder values with the literal");
        console.log('    secrets (run `nsauditor-ai mcp print-key --confirm` for the auth');
        console.log('    key). Move the config file to mode 0600 in that case.');
      } else {
        // Linux/Windows OR macOS-with-Keychain-unavailable: snippet
        // contains literal secret. chmod warning required.
        console.log('Security notes:');
        console.log(`  • Auth key value is the LITERAL secret in the config file.`);
        console.log('    chmod 600 your Claude Desktop config file to keep other local users');
        console.log('    from reading it:');
        if (platform() === 'win32') {
          console.log('      icacls "%APPDATA%\\Claude\\claude_desktop_config.json" /inheritance:r /grant:r "%USERNAME%:F"');
        } else if (isDarwin) {
          console.log('      chmod 600 ~/Library/Application\\ Support/Claude/claude_desktop_config.json');
        } else {
          console.log('      chmod 600 ~/.config/Claude/claude_desktop_config.json');
        }
        if (licenseConfigured) {
          console.log('  • License key is NOT in the env block — the MCP server reads it from');
          console.log('    ~/.nsauditor/.env (mode 0600) at startup. No JWT in the config.');
        } else {
          console.log('  • No license configured. To activate Pro/Enterprise features:');
          console.log('      nsauditor-ai license install <YOUR-KEY>');
        }
      }

      console.log('');
      console.log('After pasting:');
      console.log('  1. Save the config file');
      console.log('  2. Cmd+Q Claude Desktop (full quit) and re-launch');
      if (isDarwin) {
        console.log('  3. macOS will prompt for Keychain access on first launch — click "Always Allow"');
        console.log('     for both NSA_MCP_AUTH_KEY and NSAUDITOR_LICENSE_KEY entries.');
      }
      console.log('  4. Verify in Claude: ask "list nsauditor plugins"');
      console.log(`     Tier should report as "${licenseConfigured ? licenseStatus.tier : 'ce'}"`);
      console.log('');
      console.log('Diagnostic if it doesn\'t work:');
      console.log('  nsauditor-ai mcp status     # confirm storage source');
      if (licenseConfigured) {
        console.log('  nsauditor-ai license --status   # confirm license still verified');
      }
    }

    if (subCmd === 'install-key') {
      // Accept either a caller-supplied key (for restoring from backup
      // or aligning with an enterprise-managed secret) or generate a
      // fresh one. Both paths persist via the same multi-source storage
      // chain used for license keys.
      let key = rawArgs[2];
      let generated = false;
      if (!key || key.startsWith('-')) {
        key = generateMcpAuthKey();
        generated = true;
      } else {
        const validation = validateMcpAuthKeyShape(key);
        if (!validation.ok) {
          console.error(`✗ Key rejected: ${validation.reason}`);
          console.error(`  Expected format: nsa_mcp_<43-char-base64url>`);
          console.error(`  Generate a fresh key with: nsauditor-ai mcp install-key`);
          process.exit(1);
        }
      }

      const persisted = await persistMcpAuthKey(key);
      if (!persisted.ok) {
        console.error(`✗ Failed to persist MCP auth key: ${persisted.error}`);
        console.error(`  Fall-back: set ${MCP_AUTH_ENV_VAR} env var manually:`);
        console.error(`    export ${MCP_AUTH_ENV_VAR}="${key}"`);
        process.exit(1);
      }

      if (persisted.warning) {
        console.warn(`⚠  ${persisted.warning}`);
      }
      console.log(`✓ MCP auth key ${generated ? 'generated and ' : ''}installed`);
      console.log(`  Stored at: ${persisted.location}`);

      // Thread K: if license is configured but NOT in Keychain (e.g.,
      // operator has it in ~/.nsauditor/.env from a pre-0.1.30 install
      // or from manual editing), back-fill to Keychain on macOS so the
      // `keychain:NSAUDITOR_LICENSE_KEY` indirection in the printed
      // snippet actually resolves. Without this, the snippet would
      // include the indirection but the MCP server would fail to find
      // the license and report CE — exactly the customer-onboarding
      // friction Thread K eliminates.
      if (platform() === 'darwin') {
        try {
          const { resolveLicenseKey } = await import('./utils/license.mjs');
          const { keychainGetDetailed, keychainSet } = await import('./utils/keychain.mjs');
          const licenseKey = await resolveLicenseKey();
          if (licenseKey) {
            const keychainState = await keychainGetDetailed('NSAUDITOR_LICENSE_KEY');
            if (keychainState.state !== 'ok') {
              // License is reachable via env or file but not Keychain.
              // Mirror it into Keychain so the indirection works.
              await keychainSet('NSAUDITOR_LICENSE_KEY', licenseKey);
              console.log('');
              console.log('  ✓ License key mirrored from file/env to macOS Keychain');
              console.log('    so the snippet below can use keychain: indirection.');
              console.log('    Original storage location is preserved unchanged.');
            }
          }
        } catch (err) {
          // Best-effort: if the mirror fails, the snippet's keychain:
          // indirection won't resolve, but the operator can fall back
          // to literal-key configuration. Don't block install-key.
          console.warn(`  ⚠ Could not mirror license to Keychain (${err.message}).`);
          console.warn(`    The snippet below uses keychain: indirection — if Claude Desktop`);
          console.warn(`    reports CE tier, replace the indirection with the literal license JWT.`);
        }
      }

      await printConfigSnippet(key, persisted.location);
    } else if (subCmd === 'rotate-key') {
      // Generate a fresh key and persist over the old one. Old key is
      // immediately invalid — operator must update Claude Desktop
      // config to match. Reviewer 1 MEDIUM #3 fold: gate behind
      // --confirm to prevent accidental Claude-disconnect when an
      // operator typos `r` instead of `i` (rotate-key is keyboard-
      // adjacent to install-key). For SOC 2 audit windows where
      // availability matters, the extra keystroke is the right trade.
      const confirmed = rawArgs.includes('--confirm');
      if (!confirmed) {
        console.error(`✗ \`mcp rotate-key\` immediately invalidates the existing key.`);
        console.error(`  Any running Claude Desktop session will fail until you update`);
        console.error(`  the config with the new key value. Re-run with --confirm:`);
        console.error(`    nsauditor-ai mcp rotate-key --confirm`);
        process.exit(2);
      }
      const key = generateMcpAuthKey();
      const persisted = await persistMcpAuthKey(key);
      if (!persisted.ok) {
        console.error(`✗ Failed to persist rotated MCP auth key: ${persisted.error}`);
        process.exit(1);
      }
      if (persisted.warning) {
        console.warn(`⚠  ${persisted.warning}`);
      }
      console.log(`✓ MCP auth key rotated`);
      console.log(`  Stored at: ${persisted.location}`);
      console.log('');
      console.log('  ⚠ The OLD key is now invalid. Update your Claude Desktop config NOW.');
      await printConfigSnippet(key, persisted.location);
    } else if (subCmd === 'print-key') {
      // Reveal the stored key — gated behind --confirm to defend
      // against accidental shell-history capture. Reviewer 2 CRITICAL #1
      // fold: write the key to STDERR (not stdout) so accidental output
      // redirection (`> command.log`) doesn't slurp the secret into a
      // log file. Also refuse when stdout is non-TTY (pipe) unless
      // --force is added — guards against silent capture by command-
      // substitution (e.g., `KEY=$(nsauditor-ai mcp print-key --confirm)`
      // where the key is then echo'd into a script's history).
      const confirmed = rawArgs.includes('--confirm');
      const forced = rawArgs.includes('--force');
      if (!confirmed) {
        console.error(`✗ \`mcp print-key\` reveals a secret to your terminal.`);
        console.error(`  Re-run with --confirm if that's what you intended:`);
        console.error(`    nsauditor-ai mcp print-key --confirm`);
        console.error(`  Note that the key will be captured in shell history and any`);
        console.error(`  active screen-share / tmux scrollback. Prefer copying directly`);
        console.error(`  from the install-key output, or use \`keychain:\` indirection`);
        console.error(`  in your Claude Desktop config (see \`mcp install-key\` output).`);
        process.exit(2);
      }
      if (!process.stderr.isTTY && !forced) {
        console.error(`✗ \`mcp print-key --confirm\` refuses non-TTY output (likely a pipe`);
        console.error(`  or redirection). Add --force to override; this almost certainly`);
        console.error(`  means the key would land in a script/log file unintentionally.`);
        process.exit(2);
      }
      const { resolveMcpAuthKey } = await import('./utils/mcp_auth.mjs');
      const key = await resolveMcpAuthKey();
      if (!key) {
        console.error(`✗ No MCP auth key configured.`);
        console.error(`  Generate one with: nsauditor-ai mcp install-key`);
        process.exit(1);
      }
      // Write to STDERR (not stdout) so `> file.log` redirections don't
      // capture the secret. The TTY-check above ensures stderr IS a
      // visible terminal (otherwise we'd refuse). Operators copy from
      // the visible terminal output, not from a redirected stdout.
      process.stderr.write(`${key}\n`);
    } else if (subCmd === 'tier') {
      // Thread K (CE 0.1.32): customer-side ground-truth check for the
      // tier the MCP server WOULD resolve to at startup. Customers
      // (including the maintainer 2026-05-10) reported "Claude Desktop
      // shows tier=CE" — but on investigation, Claude (the AI) was
      // synthesizing the tier text from training data + context
      // without actually calling list_plugins via MCP. The real MCP
      // server's _tier was correct (enterprise), only Claude's
      // narration was wrong. `mcp tier` runs the same loadLicense()
      // path the MCP server uses and prints the unambiguous result —
      // customers can paste this output into a support ticket and
      // distinguish "MCP genuinely broken" from "Claude misreading".
      const { loadLicense, getTierFromEnv } = await import('./utils/license.mjs');
      const result = await loadLicense();
      const tier = getTierFromEnv();
      const tierLabels = {
        ce: 'Community Edition (CE)',
        pro: 'Pro',
        enterprise: 'Enterprise',
      };
      const symbol = tier === 'ce' ? '✗' : '✓';
      console.log(`${symbol} MCP server tier: ${tier} — ${tierLabels[tier] ?? tier}`);
      if (result.valid) {
        console.log(`  Org:        ${result.org}`);
        console.log(`  Seats:      ${result.seats}`);
        console.log(`  License ID: ${result.licenseId}`);
        console.log(`  Expires:    ${result.expiresAt}`);
        if (result.daysUntilExpiry !== undefined) {
          console.log(`  Renews in:  ${result.daysUntilExpiry} days`);
        }
        if (result.expiryWarning) {
          console.log(`  ⚠ ${result.expiryWarning}`);
        }
      } else {
        console.log(`  Reason: ${result.reason}`);
        console.log('');
        console.log('  Diagnose with: nsauditor-ai license --status');
        console.log('  Install with:  nsauditor-ai license install <KEY>');
      }
      console.log('');
      console.log('This is the EXACT tier the spawned MCP server resolves to. If Claude');
      console.log("Desktop reports a different tier, Claude isn't calling list_plugins —");
      console.log('it\'s synthesizing from context. Force a real call by asking:');
      console.log('  "Use the list_plugins MCP tool right now and show the raw response."');
      // Exit 0 if any tier resolved (success), 1 if CE/no key (operator action needed).
      process.exit(tier === 'ce' ? 1 : 0);
    } else if (subCmd === 'status') {
      // Report which storage source the resolver currently honors,
      // WITHOUT printing the key value. Safe to run in screen-share,
      // logs, etc. EE-SEC.1.1 (Thread I): also surfaces key age + the
      // keychain-locked state distinction (so headless macOS / SSH
      // sessions get an actionable error rather than a generic
      // "unconfigured" fallthrough). MEDIUM #4 fold: rotation
      // threshold respects NSA_MCP_AUTH_KEY_ROTATION_DAYS env override.
      const { getRotationWarningDays: _grwd } = await import('./utils/mcp_auth.mjs');
      const _rwd = _grwd();
      const result = await reportMcpAuthSource();
      if (result.source === 'unconfigured') {
        console.log(`✗ MCP authentication is not configured.`);
        console.log(`  Generate a key with: nsauditor-ai mcp install-key`);
        if (process.env[MCP_AUTH_DISABLE_ENV_VAR] === '1') {
          console.log('');
          console.log(`  ⚠ ${MCP_AUTH_DISABLE_ENV_VAR}=1 is set — server will start without auth.`);
        }
        process.exit(1);
      } else if (result.source === 'keychain-locked') {
        // EE-SEC.1.1 (Reviewer 2 MEDIUM #3 from EE-SEC.1): Keychain
        // entry exists but the security daemon refused to unlock —
        // GUI prompt unavailable. Common on SSH sessions, headless
        // CI runners, and login-keychain-not-unlocked-yet scenarios.
        // MEDIUM #3 fold (post-EE-SEC.1.1): operators triggering this
        // branch are by construction in a no-GUI context. Reorder
        // workarounds to put the GUI-FREE options first; "approve
        // GUI prompt" demoted to the fallback for operators who DO
        // have GUI access (rare given they hit this branch).
        console.log(`⚠ MCP auth key is configured in macOS Keychain, but Keychain access`);
        console.log(`  is currently locked (security daemon refused without GUI prompt).`);
        console.log(`  This is normal on SSH sessions and headless CI runners.`);
        console.log('');
        console.log(`  Detail: ${result.detail}`);
        console.log('');
        console.log(`  Workarounds (GUI-free paths first):`);
        console.log(`    1. Replace the keychain: indirection in Claude Desktop config`);
        console.log(`       with the literal key value (run \`mcp print-key --confirm\`).`);
        console.log(`    2. Move auth to the file fallback by setting NSA_MCP_AUTH_KEY`);
        console.log(`       in ~/.nsauditor/.env directly (mode 0600).`);
        console.log(`    3. If you have GUI access: approve a Keychain prompt in the`);
        console.log(`       macOS GUI session.`);
        process.exit(1);
      } else {
        console.log(`✓ MCP auth key configured`);
        console.log(`  Source: ${result.source}${result.detail ? ` (${result.detail})` : ''}`);
        // EE-SEC.1.1: surface key age when known. Older installs
        // (predating the timestamp companion) get null and the
        // CRITICAL #1 hint below instead.
        if (typeof result.ageDays === 'number') {
          const ageStr = result.ageDays === 0 ? 'today' : `${result.ageDays} day${result.ageDays === 1 ? '' : 's'} ago`;
          if (result.ageDays > _rwd) {
            console.log(`  ⚠ Created: ${result.createdAt} (${ageStr}) — > ${_rwd}d threshold`);
            console.log(`     Consider: nsauditor-ai mcp rotate-key --confirm`);
            console.log(`     SOC 2 CC6.1 / CC6.7 reviewers flag unrotated shared secrets.`);
          } else {
            console.log(`  Created: ${result.createdAt} (${ageStr})`);
          }
        } else if (result.legacyTimestampMissing) {
          // CRITICAL #1 fold (post-review): existing CE 0.1.31
          // operators upgrading have a key but no timestamp →
          // ageDays is null → silent. Distinct hint pointing at
          // backfill so SOC 2 evidence isn't dark for the installed base.
          console.log(`  ⚠ Created: unknown (pre-0.1.32 install — no rotation timestamp)`);
          console.log(`     Backfill the timestamp without invalidating the key:`);
          console.log(`       nsauditor-ai mcp print-key --confirm   # retrieve current key`);
          console.log(`       nsauditor-ai mcp install-key <KEY>      # re-install with timestamp`);
          console.log(`     Or rotate to a fresh key:`);
          console.log(`       nsauditor-ai mcp rotate-key --confirm`);
        }
        if (process.env[MCP_AUTH_DISABLE_ENV_VAR] === '1') {
          console.log('');
          console.log(`  ⚠ ${MCP_AUTH_DISABLE_ENV_VAR}=1 is set — server will start without auth.`);
        }
      }
    } else if (subCmd === 'verify-call') {
      // CE 0.1.36 (Thread L Phase 2): cryptographic ground truth for
      // "did Claude actually call the MCP server, or hallucinate a
      // response?" Server mints a fresh UUID per tools/call, embeds it
      // in the response text, AND appends to ~/.nsauditor/mcp-calls.log.
      // Customer pastes the UUID here; we grep the log. UUID present →
      // proven real call. UUID absent → fabricated (or log was rotated/
      // deleted; we say "unverifiable" rather than "fake").
      const { readFile, stat } = await import('node:fs/promises');
      const { join: _join } = await import('node:path');
      const { homedir: _homedir } = await import('node:os');
      const logPath = _join(_homedir(), '.nsauditor', 'mcp-calls.log');
      const uuid = rawArgs[2];
      if (!uuid) {
        console.error('Usage: nsauditor-ai mcp verify-call <uuid>');
        console.error('  Paste the call_id from the MCP tool response footer.');
        process.exit(2);
      }
      // Conservative UUID v4 shape check — avoid grepping the log with
      // arbitrary user input.
      if (!/^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/.test(uuid)) {
        console.error(`✗ Not a valid UUID: ${uuid}`);
        console.error('  Expected format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx');
        process.exit(2);
      }
      let logExists = false;
      try { await stat(logPath); logExists = true; } catch { /* missing */ }
      if (!logExists) {
        console.log(`✗ No MCP call log at ${logPath}`);
        console.log('  Either: (a) MCP server has never been invoked from this account, or');
        console.log('          (b) the log was deleted/rotated.');
        console.log('  Trigger one real call (e.g., ask Claude "use list_plugins") then retry.');
        process.exit(1);
      }
      const raw = await readFile(logPath, 'utf8');
      // Look for an exact JSON-string match on call_id to avoid prefix collisions.
      const needle = `"call_id":"${uuid.toLowerCase()}"`;
      const lines = raw.split('\n').filter((l) => l.includes(needle));
      if (lines.length === 0) {
        console.log(`✗ call_id not found in ${logPath}`);
        console.log('');
        console.log(`  ${uuid}`);
        console.log('');
        console.log('  This UUID was NOT issued by this MCP server. Most likely cause:');
        console.log('  Claude Desktop fabricated the response without invoking the server.');
        console.log('  (See README §"Verifying that Claude actually called the MCP server".)');
        process.exit(1);
      }
      try {
        const entry = JSON.parse(lines[lines.length - 1]);
        console.log(`✓ Verified MCP call`);
        console.log(`  call_id: ${entry.call_id}`);
        console.log(`  tool:    ${entry.tool}`);
        console.log(`  ts:      ${entry.ts}`);
        console.log(`  log:     ${logPath}`);
        console.log('');
        console.log('  This UUID was issued by the local MCP server, so the response');
        console.log('  bearing it was a genuine tool call (not a hallucination).');
        process.exit(0);
      } catch {
        console.log(`✓ Verified MCP call (matched ${lines.length} log line(s) for this UUID)`);
        console.log(`  log: ${logPath}`);
        process.exit(0);
      }
    } else {
      console.log('Usage:');
      console.log('  nsauditor-ai mcp install-key            Generate a new key, persist, print Claude config');
      console.log('  nsauditor-ai mcp install-key <KEY>      Persist a caller-supplied key (e.g., from backup)');
      console.log('  nsauditor-ai mcp print-key --confirm    Reveal the stored key (use with care)');
      console.log('  nsauditor-ai mcp rotate-key             Replace the stored key with a fresh one');
      console.log('  nsauditor-ai mcp status                 Show storage source without revealing the key');
      console.log('  nsauditor-ai mcp tier                   Print actual MCP server tier (ground truth, bypasses Claude AI synthesis)');
      console.log('  nsauditor-ai mcp verify-call <uuid>     Prove a tool response came from the real MCP server (not Claude hallucination)');
      console.log('');
      console.log('Environment variables:');
      console.log(`  ${MCP_AUTH_ENV_VAR}        Read by mcp_server.mjs at startup; client supplies via Claude config`);
      console.log(`  ${MCP_AUTH_DISABLE_ENV_VAR}=1   Skip auth check (CI/dev escape hatch — emits stderr warning)`);
    }
    process.exit(0);
  }

  if (cmd === 'security') {
    const { keychainSet, keychainDelete, keychainList, keychainGet } = await import('./utils/keychain.mjs');
    const rawArgs = process.argv.slice(2);
    const subCmd = rawArgs[1]; // set | delete | list | get
    const keyName = rawArgs[2];

    if (subCmd === 'set' && keyName) {
      // Read secret from stdin (piped) or prompt
      const secret = await readSecretFromStdin(keyName);
      if (!secret) { console.error('No secret provided.'); process.exit(1); }
      await keychainSet(keyName, secret);
      console.log(`Stored "${keyName}" in macOS Keychain (service: nsauditor-ai)`);
    } else if (subCmd === 'delete' && keyName) {
      const ok = await keychainDelete(keyName);
      console.log(ok ? `Deleted "${keyName}" from Keychain` : `"${keyName}" not found in Keychain`);
    } else if (subCmd === 'list') {
      const entries = await keychainList();
      if (entries.length === 0) {
        console.log('No nsauditor-ai keys stored in Keychain.');
      } else {
        console.log('Stored keys (service: nsauditor-ai):\n');
        for (const name of entries) {
          const val = await keychainGet(name);
          const masked = val ? `${val.slice(0, 8)}...(${val.length} chars)` : '(empty)';
          console.log(`  ${name} = ${masked}`);
        }
      }
    } else {
      console.log(`Usage:
  nsauditor-ai security set <KEY_NAME>     Store a secret in macOS Keychain
  nsauditor-ai security delete <KEY_NAME>  Remove a secret from Keychain
  nsauditor-ai security list               List stored secrets (masked)`);
    }
    process.exit(0);
  }

  if (cmd === 'validate') {
    const { runValidation } = await import('./utils/validate.mjs');
    const rawArgs = process.argv.slice(2);
    const wantJson = rawArgs.includes('--json');

    const { overall, checks, exitCode } = await runValidation();

    if (wantJson) {
      console.log(JSON.stringify({ overall, exitCode, checks }, null, 2));
    } else {
      const glyph = { ok: '✓', warn: '⚠', error: '✗', skip: '·' };
      console.log(`NSAuditor AI environment validation:\n`);
      for (const c of checks) {
        console.log(`  ${glyph[c.status] ?? '?'} [${c.status}] ${c.name}: ${c.message}`);
      }
      console.log(`\nOverall: ${overall.toUpperCase()} (exit ${exitCode})`);
    }
    process.exit(exitCode);
  }

  // ── `compliance attest` (EE 0.33.0, N2) ───────────────────────────────────
  // Placed BEFORE the unknown-command guard, or it would be dead code that exits 2.
  // Deliberately a THIN forward: EE owns framework validation, the offline posture
  // veto, framework-alias resolution and every default. CE contributes the flag
  // surface and the exit code — nothing here can drift out of sync with the engine
  // because nothing here decides anything.
  if (cmd === 'compliance') {
    const sub = process.argv[3];

    // ── THE APPROVAL SURFACE (EE 0.35.0) ───────────────────────────────────
    // `suppress` / `review` / `renew` / `keygen`. Same THIN-FORWARD discipline as
    // `attest` below: EE owns validation, defaults, the signing decision and every
    // refusal; CE contributes a flag surface and an exit code and decides nothing.
    //
    // ⚠️ CLI-ONLY BY RATIFIED SCOPE (D4 condition 1). These are NOT exposed as MCP
    // tools — the GRC-push precedent — because an approval surface reachable from a
    // chat client is its own decision and nobody has made it.
    //
    // ⚠️ NOTHING HERE FLIPS A CLAIM. Publishing the surface is not proving it: per D6
    // the three-part gate runs against the published registry bytes and the hedges
    // flip at N+1. If you are reading this while editing marketing copy, the answer
    // is still "not yet".
    if (sub === 'suppress' || sub === 'review' || sub === 'renew' || sub === 'keygen') {
      let ee;
      try {
        ee = await import('@nsasoft/nsauditor-ai-ee');
      } catch {
        console.error(`compliance ${sub} requires the Enterprise package (@nsasoft/nsauditor-ai-ee).`);
        process.exit(2);
      }
      const A = approvalArgs ?? {};
      const suppressionsPath = A.suppressions;
      try {
        if (sub === 'keygen') {
          const out = await ee.keygenCommand({
            privateKeyPath: A.keyPath,
            approver: A.approver || undefined,
            email: A.email || undefined,
            role: A.role || undefined,
            team: A.team || undefined,
            force: A.force,
          });
          console.log(`wrote ${out.privateKeyPath} (0600) and ${out.publicKeyPath} (0644)`);
          console.log('\nAdd this member to your identity registry:\n');
          console.log(JSON.stringify(out.registryMember, null, 2));
          console.log('\nThe private key never leaves this machine. Scanners do not need it — '
            + 'signing happens here, at approval time.');
          process.exit(0);
        }
        if (sub === 'review') {
          const { rows, summary } = await ee.reviewCommand({ rootDir: complianceHistory });
          console.log(`Suppressions: ${summary.total} total · ${summary.active} active · `
            + `${summary.approaching} approaching expiry · ${summary.expired} expired · `
            + `${summary.no_expiry} without expiry`);
          for (const r of rows) {
            console.log(`  [${r.expiryStatus}] ${r.suppressionId ?? '(no-id)'} — ${r.approver ?? '(no approver)'}`);
          }
          process.exit(0);
        }
        // `suppress` and `renew` both write, and both may SIGN — EE decides, from the
        // signing reference this forwards. A malformed reference fails HERE, at the
        // command, and never on a scan (D4).
        const signingKeyRaw = process.env.NSAUDITOR_SIGNING_KEY || undefined;
        if (sub === 'suppress') {
          const out = await ee.suppressCommand({
            suppressionsPath,
            match: { source: A.source, titlePattern: A.titlePattern },
            status: A.status,
            rationale: A.rationale,
            approver: A.approver,
            expiresInDays: A.expiresInDays ? Number(A.expiresInDays) : undefined,
            compensating_control: A.compensatingControl || undefined,
          }, { signingKeyRaw, attestationLevel: A.attestationLevel || undefined });
          const sig = out.suppression.signature;
          console.log(`wrote ${out.file} — ${out.suppression.id} (${out.suppression.status})`);
          console.log(sig
            ? `  signed: ${sig.algorithm}/${sig.backend}`
              + `${sig.attestationLevel ? ` at level ${sig.attestationLevel}` : ', identity model not declared'}`
            : '  unsigned — set NSAUDITOR_SIGNING_KEY to a local Ed25519 PEM to sign approvals');
          process.exit(0);
        }
        const out = await ee.renewCommand({
          suppressionsPath,
          suppressionId: A.suppressionId,
          rationale: A.rationale,
          approver: A.approver,
          expiresInDays: A.expiresInDays ? Number(A.expiresInDays) : undefined,
        });
        console.log(`renewed ${out.suppression?.id ?? A.suppressionId} in ${out.file ?? suppressionsPath}`);
        process.exit(0);
      } catch (err) {
        // Refusals arrive here and must stay loud: a malformed signing key, an
        // `awskms:` reference this release does not sign with, an existing key file
        // keygen will not overwrite. Every one of them is the operator learning
        // something true before an artifact exists.
        console.error(`Fatal: ${err.message}`);
        process.exit(2);
      }
    }

    if (sub !== 'attest') {
      console.error('Usage: nsauditor-ai compliance <attest|suppress|review|renew|keygen> …');
      process.exit(2);
    }
    if (typeof complianceHistory !== 'string' || complianceHistory.length === 0) {
      console.error('Fatal: compliance attest requires --history <dir>');
      process.exit(2);
    }
    let runAttestCommand;
    try {
      ({ runAttestCommand } = await import('@nsasoft/nsauditor-ai-ee'));
    } catch {
      console.error('compliance attest requires the Enterprise package (@nsasoft/nsauditor-ai-ee).');
      process.exit(2);
    }
    try {
      const { report, files, exitCode } = await runAttestCommand({
        // EE gates on this, exactly as it does for a compliance scan. CE resolves the
        // tier it already resolved for `--compliance`; presenting it here rather than
        // letting EE default keeps ONE definition of "Enterprise" across both paths.
        capabilities: resolveCapabilities(getTierFromEnv()),
        rootDir: complianceHistory,
        outDir: resolveBaseOutDir(),
        framework: framework || compliance || 'soc2',
        window: attestWindow || '6m',
        onWarn: (msg) => console.warn(`[EE] ${msg}`),
      });
      console.log(`Recurring attestation (${report.framework}): ${report.summary.scanCount} scans in window, status ${report.summary.complianceStatus}`);
      if (report.summary.invalidForAudit > 0) {
        console.warn(`  ${report.summary.invalidForAudit} of them are marked REPORT INVALID FOR AUDIT by their own attestation — see scansWithWarnings`);
      }
      for (const f of files) console.log(`  wrote ${f.path ?? f}`);
      process.exit(exitCode);
    } catch (err) {
      // A posture contradiction or an unknown framework arrives here. It must NOT be
      // swallowed: the whole point of the veto is that it stops the run loudly.
      console.error(`Fatal: ${err.message}`);
      process.exit(2);
    }
  }

  if (cmd !== 'scan') {
    console.error(`Unknown command: ${cmd}`);
    process.exit(2);
  }

  // Resolve host list
  let hosts;
  if (hostFile) {
    // Reuse the up-front resolution done for the CLOUD_PROVIDER reconcile (avoids a
    // second parse + duplicate suspicious-line warnings); re-parse only if that was
    // skipped/failed so a genuine host-file error still surfaces here as before.
    hosts = resolvedHosts ?? await parseHostFile(hostFile);
  } else if (host) {
    hosts = await parseHostArg(host);
  } else {
    console.error('Fatal: --host or --host-file is required');
    process.exit(2);
  }

  if (!hosts || hosts.length === 0) {
    console.error('Fatal: no hosts resolved');
    process.exit(2);
  }

  const opts = { insecureHttps };
  if (ports) opts.ports = ports;
  if (compliance) opts.compliance = compliance;
  if (complianceScope) opts.complianceScope = complianceScope;
  // A value-less flag is a mistake worth stopping for: `--sla-policy` with no path
  // would otherwise scan on and produce a report indistinguishable from one where the
  // operator never asked for SLA tracking at all.
  for (const [flag, val] of [['--compliance-history', complianceHistory], ['--sla-policy', slaPolicy]]) {
    if (val === true) {
      console.error(`Fatal: ${flag} requires a value`);
      process.exit(2);
    }
  }
  if (typeof complianceHistory === 'string' && complianceHistory.length > 0) {
    opts.complianceHistoryRoot = complianceHistory;
    // The history root IS the request: asking for a history and not tracking against
    // it would be a flag that reads as doing something and does nothing.
    opts.complianceTrackSla = true;
  }
  if (typeof slaPolicy === 'string' && slaPolicy.length > 0) {
    opts.slaPolicy = slaPolicy;
    // …and it TURNS TRACKING ON. Setting the policy alone was a byte-identical no-op:
    // the whole SLA block is gated on complianceTrackSla, so an operator who passed
    // --sla-policy and nothing else got a report indistinguishable from passing nothing,
    // with no warning in either channel. A flag that reads as configuring a feature must
    // not silently require a second flag to have any effect.
    opts.complianceTrackSla = true;
  }
  if (awsRegionIntent) opts.awsRegionIntent = awsRegionIntent;
  const pm = await PluginManager.create(`${__dirname}/plugins`);
  const promptMode = String(process.env.OPENAI_PROMPT_MODE || 'basic').toLowerCase().trim();

  // --- CTEM: continuous watch mode ---
  if (watch) {
    const intervalMs = intervalMinutes * 60 * 1000;
    console.log(`[CTEM] Watch mode enabled. Interval: ${intervalMinutes}m, Concurrency: ${parallel}, Hosts: ${hosts.length}`);
    if (webhookUrl) console.log(`[CTEM] Webhook URL: ${webhookUrl}, Alert severity: ${alertSeverity}`);

    let previousCycleResults = null;

    const scheduler = createScheduler({
      intervalMs,
      hosts,
      parallel,
      scanFn: async (h) => {
        const out = await scanSingleHost(pm, h, plugins, opts, promptMode);
        return out;
      },
      onScanComplete: (h, result) => {
        console.log(`[CTEM] Scan complete: ${h}`);
      },
      onCycleComplete: async (results) => {
        console.log(`[CTEM] Cycle complete. Scanned ${results.size} host(s).`);

        // Build delta report
        if (previousCycleResults) {
          const delta = buildDeltaReport(results, previousCycleResults);
          console.log(formatDeltaSummary(delta));

          // Send webhook alerts for significant changes
          if (webhookUrl && hasSignificantChanges(delta)) {
            const sevRank = SEVERITY_RANK[alertSeverity] ?? SEVERITY_RANK.high;

            for (const [h, scanOut] of results) {
              if (!scanOut?.conclusion) continue;
              const hostSev = maxSeverityInConclusion(scanOut.conclusion);
              if (hostSev >= sevRank) {
                const services = scanOut.conclusion?.result?.services || [];
                const findings = services.filter((svc) => {
                  let svcSev = 0;
                  if (svc.anonymousLogin === true || svc.axfrAllowed === true) svcSev = SEVERITY_RANK.critical;
                  if (Array.isArray(svc.weakAlgorithms) && svc.weakAlgorithms.length) svcSev = Math.max(svcSev, SEVERITY_RANK.medium);
                  if (Array.isArray(svc.dangerousMethods) && svc.dangerousMethods.length) svcSev = Math.max(svcSev, SEVERITY_RANK.medium);
                  const cves = svc.cves || svc.cve || [];
                  if (Array.isArray(cves) && cves.length) svcSev = Math.max(svcSev, SEVERITY_RANK.high);
                  return svcSev >= sevRank;
                });

                if (findings.length > 0) {
                  const payload = buildAlertPayload(h, findings, alertSeverity);
                  const webhookResult = await sendWebhook(webhookUrl, payload, { retries: 2, retryDelayMs: 1000 });
                  if (webhookResult.success) {
                    console.log(`[CTEM] Webhook alert sent for ${h}`);
                  } else {
                    console.warn(`[CTEM] Webhook alert failed for ${h}: ${webhookResult.error}`);
                  }
                }
              }
            }
          }
        } else {
          console.log('[CTEM] First cycle complete. Delta reporting will begin on next cycle.');
        }

        previousCycleResults = results;
      },
    });

    // Graceful shutdown on SIGINT/SIGTERM
    const shutdown = async () => {
      console.log('\n[CTEM] Shutting down...');
      await scheduler.stop();
      console.log('[CTEM] Stopped.');
      process.exit(0);
    };
    process.on('SIGINT', shutdown);
    process.on('SIGTERM', shutdown);

    scheduler.start();
    return; // keep process alive via setInterval
  }

  // Collect all scan outputs for post-processing
  const scanOutputs = [];

  // Single host — preserve original behaviour (flat output)
  if (hosts.length === 1) {
    const out = await scanSingleHost(pm, hosts[0], plugins, opts, promptMode);
    scanOutputs.push(out);
    console.log(JSON.stringify(out, null, 2));
  } else {
    // Multi-host with concurrency semaphore
    const concurrency = parallel;
    const allResults = [];
    let running = 0;
    let idx = 0;

    await new Promise((resolve, reject) => {
      const tryNext = () => {
        while (running < concurrency && idx < hosts.length) {
          const h = hosts[idx++];
          running++;
          scanSingleHost(pm, h, plugins, opts, promptMode)
            .then((result) => {
              allResults.push(result);
              running--;
              if (allResults.length === hosts.length) return resolve();
              tryNext();
            })
            .catch((err) => {
              allResults.push({ host: h, error: err?.message || String(err) });
              running--;
              if (allResults.length === hosts.length) return resolve();
              tryNext();
            });
        }
      };
      tryNext();
    });

    scanOutputs.push(...allResults);

    const out = {
      totalHosts: hosts.length,
      concurrency,
      results: allResults
    };
    console.log(JSON.stringify(out, null, 2));
  }

  // --- SARIF output ---
  const wantSarif = outputFormat && String(outputFormat).toLowerCase().includes('sarif');
  if (wantSarif) {
    const outDir = resolveBaseOutDir();
    await fsp.mkdir(outDir, { recursive: true });

    for (const scanOut of scanOutputs) {
      if (!scanOut?.conclusion) continue;
      const sarif = buildSarifLog({
        host: scanOut.host,
        conclusion: scanOut.conclusion,
        results: scanOut.results
      });
      const sarifFileName = scanOutputs.length > 1
        ? `scan_${safeHost(scanOut.host)}.sarif.json`
        : 'scan_results.sarif.json';
      const sarifPath = path.join(outDir, sarifFileName);
      await fsp.writeFile(sarifPath, JSON.stringify(sarif, null, 2), 'utf8');
      console.log(`[SARIF] Wrote SARIF output: ${sarifPath}`);
    }
  }

  // --- CSV output ---
  const wantCsv = outputFormat && String(outputFormat).toLowerCase().includes('csv');
  if (wantCsv) {
    const outDir = resolveBaseOutDir();
    await fsp.mkdir(outDir, { recursive: true });

    for (const scanOut of scanOutputs) {
      if (!scanOut?.conclusion) continue;
      const csv = buildCsv({
        host: scanOut.host,
        conclusion: scanOut.conclusion
      });
      const csvFileName = scanOutputs.length > 1
        ? `scan_${safeHost(scanOut.host)}.csv`
        : 'scan_results.csv';
      const csvPath = path.join(outDir, csvFileName);
      await fsp.writeFile(csvPath, csv, 'utf8');
      console.log(`[CSV] Wrote CSV output: ${csvPath}`);
    }
  }

  // --- Markdown output ---
  // Accept "md" or "markdown" in --output-format. Word-boundary match avoids matching
  // "md" inside other tokens (e.g. a hypothetical future format with "md" as a substring).
  const wantMd = outputFormat && /\b(md|markdown)\b/i.test(String(outputFormat));
  if (wantMd) {
    const outDir = resolveBaseOutDir();
    await fsp.mkdir(outDir, { recursive: true });

    for (const scanOut of scanOutputs) {
      if (!scanOut?.conclusion) continue;
      const md = buildMarkdownReport({
        host: scanOut.host,
        conclusion: scanOut.conclusion,
        toolVersion: TOOL_VERSION,
      });
      const mdFileName = scanOutputs.length > 1
        ? `scan_${safeHost(scanOut.host)}.md`
        : 'scan_report.md';
      const mdPath = path.join(outDir, mdFileName);
      await fsp.writeFile(mdPath, md, 'utf8');
      console.log(`[MD] Wrote Markdown report: ${mdPath}`);
    }
  }

  // --- Fail-on severity threshold ---
  if (failOn) {
    const threshold = SEVERITY_RANK[String(failOn).toLowerCase()];
    if (threshold == null) {
      console.error(`[fail-on] Unknown severity level: ${failOn}. Valid: critical, high, medium, low, info`);
      process.exit(2);
    }

    let highestFound = -1;
    for (const scanOut of scanOutputs) {
      if (!scanOut?.conclusion) continue;
      highestFound = Math.max(highestFound, maxSeverityInConclusion(scanOut.conclusion));
    }

    if (highestFound === -1) {
      console.error('[nsauditor] --fail-on set but no scan produced conclusions — exiting with code 2');
      process.exit(2);
    } else if (highestFound >= threshold) {
      console.error(`[fail-on] Findings at or above "${failOn}" threshold detected (max severity rank: ${highestFound}). Exiting with code 1.`);
      process.exit(1);
    } else {
      console.log(`[fail-on] No findings at or above "${failOn}" threshold. Exiting with code 0.`);
      process.exit(0);
    }
  }
}

// Only auto-run main() when this file is the process entrypoint. Importing
// cli.mjs (e.g. unit tests pulling in `parseArgs`) must NOT trigger a scan.
const _isEntrypoint = (() => {
  try {
    return !!process.argv[1] && realpathSync(fileURLToPath(import.meta.url)) === realpathSync(process.argv[1]);
  } catch {
    return false;
  }
})();
if (_isEntrypoint) {
  main().catch((err) => {
    console.error(err?.stack || err);
    process.exit(1);
  });
}
