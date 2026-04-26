#!/usr/bin/env node
import 'dotenv/config';
import PluginManager from './plugin_manager.mjs';
import { buildHtmlReport } from './utils/report_html.mjs';
import fsp from 'node:fs/promises';
import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
import path from 'node:path';
import { openaiSimplePrompt, openaiPrompt as openaiProPrompt, openaiPromptOptimized } from './utils/prompts.mjs';
import { parseHostArg, parseHostFile } from './utils/host_iterator.mjs';
import { buildSarifLog } from './utils/sarif.mjs';
import { buildCsv } from './utils/export_csv.mjs';
import { buildMarkdownReport } from './utils/report_md.mjs';
import { recordScan, getLastScan, computeDiff, formatDiffReport, pruneForCE, HISTORY_FILE } from './utils/scan_history.mjs';
import { getTierFromEnv, loadLicense } from './utils/license.mjs';
import { resolveCapabilities, hasCapability } from './utils/capabilities.mjs';
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

async function maybeSendToOpenAI({ host, results, conclusion, promptMode = 'basic' }) {
  // --- env & opts -----------------------------------------------------------
  const sendEnabled   = parseBool(process.env.AI_ENABLED);
  const redactEnabled = parseBool(process.env.OPENAI_REDACT, true);
  const aiProvider    = (process.env.AI_PROVIDER || 'openai').toLowerCase().trim();
  const model         = aiProvider === 'claude'
    ? toCleanPath(process.env.ANTHROPIC_MODEL || 'claude-sonnet-4-20250514')
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

  // Base output folder (resolved via the shared helper — honors --out and
  // the SCAN_OUT_PATH / OPENAI_OUT_PATH env vars consistently with the
  // SARIF/CSV/MD writers below).
  const baseOutDir  = resolveBaseOutDir();

  await fsp.mkdir(baseOutDir, { recursive: true });

  // Per-scan folder
  const ts       = nowStamp();
  const runDir   = `${safeHost(host)}_${ts}`;
  const outDir   = path.join(baseOutDir, runDir);
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
      ai_conclusion: null
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
    console.log(`[${providerLabel}] AI_ENABLED=false; not sending. Model=${model}`);
    return {
      file_paths: { folder: outDir, plain: null, ai_json: null, raw_json: adminRawPath, html: null, admin_html: adminHtmlPath },
      ai_conclusion: null
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
  try {
    console.log(`[${providerLabel}] Sending summary, model:`, model);

    let resp;
    const userContent = `Scan payload:\n${JSON.stringify(payloadForAI, null, 2)}`;

    // AbortController timeout — prevents the pipeline hanging on a stalled AI provider.
    const AI_TIMEOUT_MS = Number(process.env.NSA_AI_TIMEOUT_MS) || 120_000; // 2 min default
    const ac = new AbortController();
    const aiTimer = setTimeout(() => ac.abort(), AI_TIMEOUT_MS);

    try {
      if (aiProvider === 'claude') {
        // --- Claude (Anthropic) ---
        const { default: Anthropic } = await import('@anthropic-ai/sdk');
        const client = new Anthropic({ apiKey: key });

        resp = await client.messages.create({
          model,
          max_tokens: 4096,
          system: promptText,
          messages: [
            { role: 'user', content: userContent }
          ]
        }, { signal: ac.signal });

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
        const client = new OpenAI({ baseURL: ollamaBase, apiKey: key });

        resp = await client.chat.completions.create({
          model,
          messages: [
            { role: 'system', content: promptText },
            { role: 'user', content: userContent }
          ]
        }, { signal: ac.signal });

        console.log(`[${providerLabel}] Response id:`, resp?.id ?? '(unknown)');

        aiConclusionText = resp?.choices?.[0]?.message?.content?.trim() || null;
      } else {
        // --- OpenAI ---
        const { default: OpenAI } = await import('openai');
        const client = new OpenAI({ apiKey: key });

        if (client.responses?.create) {
          resp = await client.responses.create({
            model,
            input: [
              { role: 'system', content: promptText },
              { role: 'user', content: userContent }
            ]
          }, { signal: ac.signal });
        } else if (client.chat?.completions?.create) {
          resp = await client.chat.completions.create({
            model,
            messages: [
              { role: 'system', content: promptText },
              { role: 'user', content: userContent }
            ]
          }, { signal: ac.signal });
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
      ai_conclusion: aiConclusionText
    };
  } catch (err) {
    console.error(`[${providerLabel}] Send failed:`, err?.stack || err?.message || String(err));
    try {
      await fsp.writeFile(aiErrPath, JSON.stringify({
        error: String(err?.message || err),
        stack: err?.stack || null,
        provider: aiProvider,
        model
      }, null, 2), 'utf8');
      console.log(`[${providerLabel}] Wrote AI error:`, aiErrPath);
    } catch (e) {
      console.warn(`[${providerLabel}] Also failed to write error file:`, e?.message || e);
    }

    return {
      file_paths: {
        folder: outDir,
        plain: null,
        ai_json: null,
        raw_json: adminRawPath,
        html: null,
        admin_html: adminHtmlPath
      },
      ai_conclusion: null
    };
  }
}

/* ------------------------------- CLI ----------------------------------- */

async function parseArgs(argv) {
  const args = { cmd: 'scan', host: undefined, plugins: 'all', insecureHttps: false };
  const a = argv.slice(2);
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
  } else if (p && p.toLowerCase() === 'all') {
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

  return args;
}

async function scanSingleHost(pm, host, plugins, opts, promptMode) {
  // SSRF guard — block loopback, private ranges, cloud metadata endpoints.
  // Set NSA_ALLOW_ALL_HOSTS=1 to scan RFC 1918 / private ranges (local network auditing).
  if (!process.env.NSA_ALLOW_ALL_HOSTS) {
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

  // EE enrichment hook — no-op if @nsasoft/nsauditor-ai-ee is not installed
  try {
    const { enrichScan } = await import('@nsasoft/nsauditor-ai-ee');
    const eeEnrichment = await enrichScan(conclusion, { host });
    if (eeEnrichment?.enrichedPrompt) {
      conclusion.result = conclusion.result || {};
      conclusion.result.eeEnrichment = eeEnrichment;
    }
  } catch { /* EE not installed — CE proceeds unchanged */ }

  const { file_paths: ai_file_paths, ai_conclusion } = await maybeSendToOpenAI({ host, results, conclusion, promptMode });

  // --- Scan history: record & compare ---
  let scanDiff = null;
  try {
    const outRoot = toCleanPath(process.env.SCAN_OUT_PATH || process.env.OPENAI_OUT_PATH || 'out').replace(/\.[^/.]+$/, '') || 'out';
    const services = conclusion?.result?.services ?? [];
    const findingsCount = services.reduce((n, svc) => {
      if (svc.anonymousLogin === true) n++;
      if (svc.axfrAllowed === true) n++;
      if (Array.isArray(svc.weakAlgorithms)) n += svc.weakAlgorithms.length;
      if (Array.isArray(svc.dangerousMethods)) n += svc.dangerousMethods.length;
      const cves = svc.cves || svc.cve || [];
      if (Array.isArray(cves)) n += cves.length;
      return n;
    }, 0);

    const scanSummary = {
      timestamp: new Date().toISOString(),
      host,
      servicesCount: services.length,
      openPorts: services.filter((s) => s.status === 'open').map((s) => s.port),
      os: conclusion?.result?.host?.os ?? null,
      findingsCount,
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

  return { host, results, conclusion, ai_file_paths, ai_conclusion, scanDiff };
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

async function main() {
  const { cmd, host, plugins, insecureHttps, hostFile, parallel, failOn, outputFormat, watch, intervalMinutes, webhookUrl, alertSeverity, ports } = await parseArgs(process.argv);

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
          console.log('\n→ Start a free 14-day Pro trial: https://www.nsauditor.com/ai/trial');
        }
      }
    } else if (rawArgs.includes('--capabilities')) {
      const tier = getTierFromEnv();
      const caps = resolveCapabilities(tier);
      console.log(`Active capabilities for tier: ${tier}\n`);
      for (const [name, enabled] of Object.entries(caps)) {
        console.log(`  ${enabled ? '✓' : '✗'} ${name}`);
      }
    } else {
      console.log('Usage: nsauditor-ai license --status | --capabilities');
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

  if (cmd !== 'scan') {
    console.error(`Unknown command: ${cmd}`);
    process.exit(2);
  }

  // Resolve host list
  let hosts;
  if (hostFile) {
    hosts = await parseHostFile(hostFile);
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

main().catch((err) => {
  console.error(err?.stack || err);
  process.exit(1);
});
