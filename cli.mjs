#!/usr/bin/env node
import 'dotenv/config';
import PluginManager from './plugin_manager.mjs';
import { buildHtmlReport } from './utils/report_html.mjs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import { openaiSimplePrompt, openaiPrompt as openaiProPrompt, openaiPromptOptimized } from './utils/prompts.mjs';
import { parseHostArg, parseHostFile } from './utils/host_iterator.mjs';
import { buildSarifLog } from './utils/sarif.mjs';
import { recordScan, getLastScan, computeDiff, formatDiffReport } from './utils/scan_history.mjs';
import { createScheduler } from './utils/scheduler.mjs';
import { buildDeltaReport, formatDeltaSummary, hasSignificantChanges } from './utils/delta_reporter.mjs';
import { sendWebhook, buildAlertPayload, isSafeWebhookUrl } from './utils/webhook.mjs';

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
const toCleanPath = (s) => String(s ?? '').trim().replace(/^['"]+|['"]+$/g, '');

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

/** Scrub values whose KEY contains any keyword from CONFIDENTIAL_KEYWORDS. */
function scrubByKey(val, keywords, placeholder) {
  if (val == null) return val;
  if (!Array.isArray(keywords) || keywords.length === 0) return val;

  const walk = (v) => {
    if (Array.isArray(v)) return v.map(walk);
    if (v && typeof v === 'object') {
      const out = {};
      for (const [k, vv] of Object.entries(v)) {
        const hit = keywords.some((word) => k.toLowerCase().includes(word));
        out[k] = hit ? placeholder : walk(vv);
      }
      return out;
    }
    return v;
  };
  return walk(val);
}

/* ------------------------- OpenAI & reporting -------------------------- */

async function maybeSendToOpenAI({ host, results, conclusion, promptMode = 'basic' }) {
  // --- env & opts -----------------------------------------------------------
  const sendEnabled   = parseBool(process.env.SEND_TO_OPENAI);
  const redactEnabled = parseBool(process.env.OPENAI_REDACT, true);
  const aiProvider    = (process.env.AI_PROVIDER || 'openai').toLowerCase().trim();
  const model         = aiProvider === 'claude'
    ? toCleanPath(process.env.ANTHROPIC_MODEL || 'claude-sonnet-4-20250514')
    : toCleanPath(process.env.OPENAI_MODEL || 'gpt-4o-mini');
  const keyRaw        = aiProvider === 'claude'
    ? process.env.ANTHROPIC_API_KEY
    : process.env.OPENAI_API_KEY;
  const key           = keyRaw ? String(keyRaw).trim() : null;

  // Base output folder (directory ONLY; if a file path is given, take its dir)
  const outHintRaw  = toCleanPath(process.env.SCAN_OUT_PATH || process.env.OPENAI_OUT_PATH || 'out');
  const parsedHint  = path.parse(outHintRaw);
  const baseOutDir  = parsedHint.ext ? (parsedHint.dir || 'out') : (outHintRaw || 'out');

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
      if (typeof globalThis.redactSensitiveForAI === 'function') {
        let out = globalThis.redactSensitiveForAI(payloadForAI);
        if (out && typeof out.then === 'function') out = await out;
        if (typeof out === 'string') out = JSON.parse(out);
        if (!out || typeof out !== 'object') throw new Error('external redactor returned non-object');
        payloadForAI = out;
        used = 'external';
      } else {
        // your local helper from earlier in this file
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
  const providerLabel = aiProvider === 'claude' ? 'Claude' : 'OpenAI';
  if (!sendEnabled || !key) {
    console.log(`[${providerLabel}] SEND_TO_OPENAI disabled; not sending. Model=${model}`);
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

  // --- Send to AI provider ---------------------------------------------------
  let aiConclusionText = null;
  try {
    console.log(`[${providerLabel}] Sending summary, model:`, model);

    let resp;
    const userContent = `Scan payload:\n${JSON.stringify(payloadForAI, null, 2)}`;

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
      });

      console.log(`[${providerLabel}] Response id:`, resp?.id ?? '(unknown)');

      // Extract text from Claude response
      aiConclusionText = (resp?.content ?? [])
        .filter(b => b.type === 'text')
        .map(b => b.text)
        .join('\n')
        .trim() || null;
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
        });
      } else if (client.chat?.completions?.create) {
        resp = await client.chat.completions.create({
          model,
          messages: [
            { role: 'system', content: promptText },
            { role: 'user', content: userContent }
          ]
        });
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
  const { results, conclusion } = await pm.run(host, plugins || 'all', opts);
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
  const pm = await PluginManager.create('./plugins');
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
    const outDir = 'out';
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
