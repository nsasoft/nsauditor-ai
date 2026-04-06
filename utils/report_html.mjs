// utils/report_html.mjs
// HTML report builder for AI conclusion text (markdown -> styled HTML with badges & safe CVE/URL links)

import { attackUrl } from './attack_map.mjs';

export async function buildHtmlReport({ host, whenIso, model, md }) {
  // --- 0) Pre-sanitize: remove any literal or *escaped* anchors from the model's markdown ----
  // We keep only the visible text (URL/CVE token), then we'll linkify cleanly later.

  const stripEscapedAnchors = (s) =>
    String(s || '').replace(/&lt;a\b[\s\S]*?&gt;([\s\S]*?)&lt;\/a&gt;/gi, '$1');

  const stripLiteralAnchors = (s) =>
    String(s || '').replace(/<a\b[^>]*>([\s\S]*?)<\/a>/gi, '$1');

  // Collapse odd NVD fragments the model sometimes emits inside table cells, e.g.:
  //   https://nvd.nist.gov/vuln/detail/CVE-2023-2450" target="_blank" … >CVE-2023-2450
  // Reduce to just "CVE-2023-2450" so we can linkify later.
  const collapseWeirdNvd = (s) =>
    String(s || '').replace(
      /https?:\/\/nvd\.nist\.gov\/vuln\/detail\/(CVE-\d{4}-\d{4,7})["'][^>\n]*?>\s*\1/gi,
      '$1'
    );

  const mdSanitized =
    stripLiteralAnchors(
      stripEscapedAnchors(
        collapseWeirdNvd(md)
      )
    );

  // --- 0b) CVE validation markers → display tokens ---------------------------
  // {{CVE_VERIFIED:CVE-XXXX-XXXXX}} → CVE-XXXX-XXXXX   (linkifier handles normally)
  // {{CVE_UNVERIFIED:CVE-XXXX-XXXXX}} → ⚠CVE-XXXX-XXXXX (linkifier renders as warning)
  const expandCveMarkers = (s) =>
    String(s || '')
      .replace(/\{\{CVE_VERIFIED:(CVE-\d{4}-\d{4,7})\}\}/g, '$1')
      .replace(/\{\{CVE_UNVERIFIED:(CVE-\d{4}-\d{4,7})\}\}/g, '\u26A0$1');

  const mdClean = expandCveMarkers(mdSanitized);

  // --- 1) Markdown -> HTML ----------------------------------------------------
  let render;
  try {
    const { default: MarkdownIt } = await import('markdown-it');
    const mdIt = new MarkdownIt({ html: false, linkify: true, breaks: false, typographer: true });
    render = (s) => mdIt.render(String(s || ''));
  } catch {
    const escHtml = (s) => String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
    render = (s) =>
      escHtml(String(s || ''))
        .replace(/^###\s+(.*)$/gim, '<h3>$1</h3>')
        .replace(/^##\s+(.*)$/gim, '<h2>$1</h2>')
        .replace(/^#\s+(.*)$/gim, '<h1>$1</h1>')
        .replace(/^[-*]\s+(.*)$/gim, '<ul><li>$1</li></ul>')
        .replace(/\n{2,}/g, '</p><p>')
        .replace(/^/, '<p>') + '</p>';
  }

  let body = render(mdClean);

  // --- 2) Defensive cleanup in the produced HTML -----------------------------
  // If any *broken* anchors survived (e.g., href contains an encoded or literal <a …>):
  // strip such <a>…</a> tags entirely, keeping only their visible inner text.
  const stripBrokenAnchorsInHtml = (html) =>
    html.replace(/<a\b[^>]*href="[^"]*(?:&lt;|<)a[^"]*"[^>]*>([\s\S]*?)<\/a>/gi, '$1');

  // Also trim a dangling quote that sometimes ends up after </a>
  const stripDanglingQuoteAfterAnchor = (html) =>
    html.replace(/<\/a>"/g, '</a>');

  body = stripBrokenAnchorsInHtml(body);
  body = stripDanglingQuoteAfterAnchor(body);

  // --- 3) CVE/URL linkification (text nodes only) -----------------------------
  // A) Normalize already-linked CVEs that (correctly) point to NVD (strip junk attributes):
  const normalizeExistingNvdAnchors = (html) =>
    html.replace(
      /<a[^>]*href=["']https?:\/\/nvd\.nist\.gov\/vuln\/detail\/(CVE-\d{4}-\d{4,7})["'][^>]*>(?:\1|CVE-\d{4}-\d{4,7})<\/a>/gi,
      (_m, id) => `<a href="https://nvd.nist.gov/vuln/detail/${id}" target="_blank" rel="noopener noreferrer">${id}</a>`
    );

  // B1) Linkify unverified CVEs (⚠CVE-XXXX-XXXXX) — must run BEFORE bare CVE linkification:
  const linkifyUnverifiedCves = (html) =>
    html.replace(/(>[^<]*?)\u26A0(CVE-\d{4}-\d{4,7})/g, (_m, pre, id) =>
      `${pre}<span class="cve-unverified" title="This CVE could not be verified in NVD">${id} <sup>unverified</sup></span>`
    );

  // B2) Linkify CVE tokens *only inside text nodes* (avoid attributes and already-handled unverified CVEs):
  const linkifyBareCveTokens = (html) =>
    html.replace(/(>[^<]*?)\b(CVE-\d{4}-\d{4,7})\b/g, (m, pre, id, offset) => {
      // Skip if this CVE is already inside a cve-unverified span.
      // offset points to the '>' char that starts the match, so include it in the lookbehind.
      const context = html.slice(Math.max(0, offset - 200), offset + 1);
      if (/<span[^>]*class="cve-unverified"[^>]*>[^<]*$/.test(context)) return m;
      return `${pre}<a class="cve-verified" href="https://nvd.nist.gov/vuln/detail/${id}" target="_blank" rel="noopener noreferrer">${id}</a>`;
    });

  // C) Linkify bare URLs *only inside text nodes* (avoid attributes):
  const linkifyBareUrls = (html) =>
    html.replace(/(>[^<]*?)\b(https?:\/\/[^\s<>"')]+)\b/g, (_m, pre, u) => {
      if (!/^https?:\/\//i.test(u)) return `${pre}${u}`;
      return `${pre}<a href="${u}" target="_blank" rel="noopener noreferrer">${u}</a>`;
    });

  // D) As a final safety net, if there are any plaintext escaped-anchors in HTML (shouldn’t be),
  // remove them to their inner text again, then re-linkify.
  const stripEscapedAnchorsInHtml = (html) =>
    html.replace(/&lt;a\b[\s\S]*?&gt;([\s\S]*?)&lt;\/a&gt;/gi, '$1');

  // E) Linkify ATT&CK technique IDs (T1234 or T1234.001) in text nodes:
  const linkifyAttackTechniques = (html) =>
    html.replace(/(>[^<]*?)\b(T\d{4}(?:\.\d{3})?)\b/g, (_m, pre, tid) => {
      const url = attackUrl(tid);
      return `${pre}<a class="attack-badge" href="${url}" target="_blank" rel="noopener">${tid}</a>`;
    });

  body = normalizeExistingNvdAnchors(body);
  body = stripEscapedAnchorsInHtml(body);
  body = linkifyUnverifiedCves(body);
  body = linkifyBareCveTokens(body);
  body = linkifyBareUrls(body);
  body = linkifyAttackTechniques(body);

  // --- 4) SERVER-SIDE Priority badge injection -------------------------------
  // Your tests look for the badge span in the final HTML. We decorate here too (in addition to client-side).
  const decoratePriorityServer = (html) => {
    const rx = /(\b(?:<strong>|<b>)?\s*Priority\s*(?:<\/strong>|<\/b>)?\s*:\s*)(Critical|High|Medium|Low)\b/gi;
    return html.replace(rx, (_, pre, lvl) => {
      const key = String(lvl || '').toLowerCase();
      const cap = key.charAt(0).toUpperCase() + key.slice(1);
      return `${pre}<span class="badge badge-${key}">${cap}</span>`;
    });
  };
  body = decoratePriorityServer(body);

  // Simple esc for header fields
  const esc = (s) =>
    String(s ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');

  // --- 5) Final HTML (client-side: Severity/Priority badges) ------------------
  return `<!doctype html>
<html lang="en">
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Network Audit – ${esc(host)}</title>
<style>
:root{
  --bg:#0b0f14; --card:#121823; --text:#e7eef7; --muted:#a9b6c6;
  --border:#1f2937; --link:#60a5fa;
  --crit:#b71c1c; --high:#d32f2f; --med:#f57c00; --low:#388e3c;
  --crit-bg:#2b0f12; --high-bg:#311014; --med-bg:#2a1b0a; --low-bg:#0f2014;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:14px/1.55 system-ui,Segoe UI,Roboto,Ubuntu,sans-serif}
.main{max-width:980px;margin:24px auto;padding:24px;background:var(--card);border:1px solid var(--border);border-radius:14px}
h1,h2,h3{margin:1.2em 0 .6em}
h1{font-size:26px} h2{font-size:20px} h3{font-size:16px}
p,li{color:var(--text)}
a{color:var(--link);text-decoration:none} a:hover{text-decoration:underline}
code,kbd,pre{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
table{width:100%;border-collapse:collapse;margin:14px 0;border:1px solid var(--border)}
th,td{border:1px solid var(--border);padding:10px 12px;vertical-align:top}
th{background:#0e1420;color:#cfe0ff;text-align:left}
tbody tr:nth-child(odd){background:#0f1522}
.badge{display:inline-block;padding:2px 8px;border-radius:999px;font-weight:600;border:1px solid transparent;white-space:nowrap}
.badge-critical{background:var(--crit-bg);border-color:var(--crit);color:#ffb4b4}
.badge-high{background:var(--high-bg);border-color:var(--high);color:#ffc3c3}
.badge-medium{background:var(--med-bg);border-color:var(--med);color:#ffd8a6}
.badge-low{background:var(--low-bg);border-color:var(--low);color:#b9f6ca}
.cve-verified{color:#4caf50;font-weight:600}
.cve-unverified{color:#f44336;font-weight:600;text-decoration:line-through;text-decoration-style:wavy}
.cve-unverified sup{font-size:10px;color:#f44336;margin-left:2px}
.attack-badge{display:inline-block;padding:1px 7px;border-radius:999px;font-size:11px;font-weight:600;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;background:#1a1a2e;border:1px solid #4a4a8a;color:#a0a0ff;white-space:nowrap;text-decoration:none}
.attack-badge:hover{background:#2a2a4e;border-color:#6a6aaa;color:#c0c0ff;text-decoration:none}
.meta{color:var(--muted);font-size:12px;margin-top:2px}
.header{display:flex;justify-content:space-between;align-items:center;border-bottom:1px dashed var(--border);padding-bottom:12px;margin-bottom:18px}
</style>
<body>
  <div class="main">
    <div class="header">
      <div>
        <h1>Network Audit – ${esc(host)}</h1>
        <div class="meta">Generated: ${esc(whenIso)}</div>
      </div>
      <div class="meta">Model: ${esc(model)}</div>
    </div>
    ${body}
  </div>
<script>
(function(){
  const sevMap = { 'critical':'critical','high':'high','medium':'medium','med':'medium','low':'low' };
  function titleCase(s){ return s.charAt(0).toUpperCase() + s.slice(1); }

  // Severity badges in any table with a "Severity" header
  document.querySelectorAll('table').forEach(tbl => {
    const ths = Array.from(tbl.querySelectorAll('thead th'));
    const idx = ths.findIndex(th => /\\bSeverity\\b/i.test(th.textContent || ''));
    if (idx >= 0) {
      tbl.querySelectorAll('tbody tr').forEach(tr => {
        const td = tr.children[idx];
        if (!td) return;
        const raw = (td.textContent || '').trim();
        const key = sevMap[raw.toLowerCase()];
        if (key) td.innerHTML = '<span class="badge badge-' + key + '">' + titleCase(key) + '</span>';
      });
    }
  });

  // Priority badges anywhere ("Priority: X") — robust across p, li, td, th (handles bold labels)
  const re = /(\\b(?:<strong>|<b>)?\\s*Priority\\s*(?:<\\/strong>|<\\/b>)?\\s*:\\s*)(Critical|High|Medium|Low)\\b/i;
  document.querySelectorAll('p,li,td,th').forEach(node => {
    const txt = (node.textContent || '').trim();
    if (!/Priority\\s*:/i.test(txt)) return;
    if (node.querySelector('.badge')) return; // already server-side injected
    node.innerHTML = node.innerHTML.replace(re, function(_, pre, lvl){
      const key = (lvl||'').toLowerCase();
      return pre + '<span class="badge badge-' + key + '">' + (lvl.charAt(0).toUpperCase() + lvl.slice(1).toLowerCase()) + '</span>';
    });
  });
})();
</script>
</body>
</html>`;
}
