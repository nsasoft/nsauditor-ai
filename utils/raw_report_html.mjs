// utils/raw_report_html.mjs
// Admin RAW HTML report: show open services + full evidence (with status)
// Emits data-key="tcp-<port>" on open-service rows for tests (e.g., "tcp-80")

export async function buildAdminRawHtmlReport({
  host,
  whenIso,
  summary,
  os = null,
  services = [],
  evidence = [],
} = {}) {
  const esc = (s) =>
    String(s ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;");

  const guessStatus = (text) => {
    const t = String(text || "");
    if (/success|open\b/i.test(t)) return "open";
    if (/refused|closed|reset|rst/i.test(t)) return "closed";
    if (/timeout|no\s*response|unreachable|filtered/i.test(t)) return "filtered";
    return "";
  };

  // Build a quick lookup to enrich Evidence “Status” from services
  const svcByKey = new Map();
  for (const s of Array.isArray(services) ? services : []) {
    const key = `${String(s.protocol || "").toLowerCase()}/${Number(s.port)}`;
    if (!svcByKey.has(key)) svcByKey.set(key, s);
  }

  const openServices = services.filter((s) => String(s.status).toLowerCase() === "open");

  const openRows = openServices
    .map((s) => {
      const proto = String(s.protocol || "").toLowerCase();
      const key = `${proto}-${Number(s.port)}`; // <-- this puts tcp-80 in the HTML
      return `<tr data-key="${esc(key)}">
        <td>${Number(s.port) || ""}</td>
        <td>${esc(proto)}</td>
        <td>${esc(s.service || "")}</td>
        <td>${esc(s.program || "")}</td>
        <td>${esc(s.version || "")}</td>
        <td>${esc(s.status || "")}</td>
        <td>${esc(s.info || "")}</td>
        <td>${s.banner ? `<pre>${esc(s.banner)}</pre>` : ""}</td>
      </tr>`;
    })
    .join("");

  const evRows = (Array.isArray(evidence) ? evidence : [])
    .map((e) => {
      // normalize evidence (supports both normalized and legacy probe_* fields)
      const proto = String(e?.protocol ?? e?.probe_protocol ?? "").toLowerCase();
      const port = Number(e?.port ?? e?.probe_port) || "";
      const info = e?.info ?? e?.probe_info ?? "";
      const banner = e?.banner ?? e?.response_banner ?? "";
      const key = `${proto}/${port}`;
      const svc = svcByKey.get(key);
      // Prefer service.status, then explicit evidence status, then inference
      const status = svc?.status || e?.status || guessStatus(info) || guessStatus(banner) || "";
      return `<tr data-proto="${esc(proto)}" data-port="${port}" data-status="${esc(
        String(status).toLowerCase()
      )}">
        <td>${esc(e?.from || "")}</td>
        <td>${esc(proto)}</td>
        <td>${port}</td>
        <td class="ev-status">${esc(status)}</td>
        <td>${esc(info)}</td>
        <td>${banner ? `<pre>${esc(banner)}</pre>` : ""}</td>
      </tr>`;
    })
    .join("");

  return `<!doctype html>
<html lang="en">
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Admin Raw Report – ${esc(host)}</title>
<style>
:root{
  --bg:#0b0f14; --card:#0f1622; --text:#e7eef7; --muted:#a9b6c6;
  --border:#1f2937; --link:#60a5fa;
  --open:#15a34a; --closed:#ef4444; --filtered:#f59e0b;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:14px/1.55 system-ui,Segoe UI,Roboto,Ubuntu,sans-serif}
.main{max-width:1100px;margin:24px auto;padding:24px;background:var(--card);border:1px solid var(--border);border-radius:14px}
h1,h2{margin:1.2em 0 .6em}
h1{font-size:26px} h2{font-size:18px}
.meta{color:var(--muted);font-size:12px;margin-top:2px}
.header{border-bottom:1px dashed var(--border);padding-bottom:12px;margin-bottom:18px}
table{width:100%;border-collapse:collapse;margin:14px 0;border:1px solid var(--border)}
th,td{border:1px solid var(--border);padding:8px 10px;vertical-align:top}
th{background:#0e1420;color:#cfe0ff;text-align:left}
tbody tr:nth-child(odd){background:#0f1522}
pre{margin:0;white-space:pre-wrap;word-break:break-word}
.badge{display:inline-block;padding:2px 8px;border-radius:999px;font-weight:600;border:1px solid transparent}
.badge-open{background:rgba(21,163,74,.08);border-color:var(--open);color:#b9f6ca}
.badge-closed{background:rgba(239,68,68,.08);border-color:var(--closed);color:#fecaca}
.badge-filtered{background:rgba(245,158,11,.08);border-color:var(--filtered);color:#ffe4b5}
.controls{display:flex;gap:16px;align-items:center;margin:8px 0 14px;color:var(--muted)}
</style>
<body>
  <div class="main">
    <div class="header">
      <h1>Admin Raw Report – ${esc(host)}</h1>
      <div class="meta">Generated: ${esc(whenIso || new Date().toISOString())}${os ? ` • OS: ${esc(os)}` : ""}</div>
      ${summary ? `<div class="meta">Summary: ${esc(summary)}</div>` : ""}
    </div>

    <h2>Open Services</h2>
    <table>
      <thead>
        <tr>
          <th>Port</th><th>Protocol</th><th>Service</th><th>Program</th><th>Version</th><th>Status</th><th>Info</th><th>Banner</th>
        </tr>
      </thead>
      <tbody>
        ${openRows || ""}
      </tbody>
    </table>

    <div class="controls">
      <label><input type="checkbox" id="onlyOpen"> Show only OPEN in Evidence</label>
    </div>

    <h2>Evidence</h2>
    <table id="ev">
      <thead>
        <tr>
          <th>From</th><th>Protocol</th><th>Port</th><th>Status</th><th>Info</th><th>Banner</th>
        </tr>
      </thead>
      <tbody>
        ${evRows || ""}
      </tbody>
    </table>
  </div>

<script>
(function(){
  const onlyOpen = document.getElementById('onlyOpen');
  const tbl = document.getElementById('ev');
  if (!onlyOpen || !tbl) return;
  function apply(){
    const want = !!onlyOpen.checked;
    tbl.querySelectorAll('tbody tr').forEach(tr=>{
      const st = (tr.getAttribute('data-status')||'').toLowerCase();
      tr.style.display = (want && st !== 'open') ? 'none' : '';
      // badge styling in-place:
      const cell = tr.querySelector('.ev-status');
      if (!cell) return;
      const v = (cell.textContent||'').trim().toLowerCase();
      let cls = '';
      if (v === 'open') cls = 'badge badge-open';
      else if (v === 'closed') cls = 'badge badge-closed';
      else if (v === 'filtered') cls = 'badge badge-filtered';
      if (cls) cell.innerHTML = '<span class="'+cls+'">'+cell.textContent.trim()+'</span>';
    });
  }
  onlyOpen.addEventListener('change', apply);
  apply();
})();
</script>
</body>
</html>`;
}
