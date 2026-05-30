// utils/cloud_finding_summary.mjs
//
// Builds the caller-visible findings surface for scan_cloud DIRECTLY from the raw
// plugin results — the network-host concluder (result_concluder.mjs) doesn't
// understand cloud compliance findings and silently drops them. Robust across the
// plugin-specific finding shapes (AWS userName/issues, S3 bucketName, GCP/Azure title).

const RANK = { CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, INFO: 1, PASS: 0 };
const RESOURCE_KEYS = ['userName', 'bucketName', 'functionName', 'tableName', 'instanceId', 'groupId', 'keyId', 'topic', 'queue', 'vaultName', 'accountName', 'resource', 'resourceId', 'name', 'arn'];
const REASON_KEYS = ['classification', 'title', 'message', 'reason', 'finding', 'detail'];

/** Robust one-line descriptor from any plugin finding shape. Never empty. */
export function describeFinding(x) {
  if (!x || typeof x !== 'object') return String(x ?? '').slice(0, 160);
  let res = '';
  for (const k of RESOURCE_KEYS) { if (x[k]) { res = String(x[k]); break; } }
  let why = '';
  if (Array.isArray(x.issues) && x.issues.length) why = String(x.issues[0]);
  else for (const k of REASON_KEYS) { if (x[k]) { why = String(x[k]); break; } }
  const s = (res ? res + ' — ' : '') + why;
  return (s.trim() || JSON.stringify(x)).slice(0, 160);
}

function findingsOf(r) {
  const f = (r && (r.findings ?? r.result?.findings ?? r.result?.data)) ?? [];
  return Array.isArray(f) ? f : [];
}

/**
 * @param {Array} results              out.results (each {id, result:{findings|data}})
 * @param {(id:any)=>string|null} providerOf  plugin id -> cloudProvider
 * @param {number} [cap]               max CRITICAL/HIGH entries listed per provider
 * @returns {Object} { [provider]: { counts:{SEV:n}, findings:[{severity,plugin,title}], truncated:boolean } }
 */
export function summarizeCloudFindings(results, providerOf, cap = Number(process.env.CLOUD_FINDINGS_CAP) || 60) {
  const out = {};
  for (const r of (Array.isArray(results) ? results : [])) {
    const prov = providerOf(r?.id ?? r?.result?.id);
    if (!prov) continue;
    const bucket = (out[prov] ||= { counts: {}, findings: [], truncated: false });
    for (const x of findingsOf(r)) {
      const sev = String(x?.severity || x?.level || 'INFO').toUpperCase();
      bucket.counts[sev] = (bucket.counts[sev] || 0) + 1;
      if (sev === 'CRITICAL' || sev === 'HIGH') {
        if (bucket.findings.length < cap) bucket.findings.push({ severity: sev, plugin: String(r?.id ?? ''), title: describeFinding(x) });
        else bucket.truncated = true;
      }
    }
  }
  for (const prov of Object.keys(out)) out[prov].findings.sort((a, b) => (RANK[b.severity] || 0) - (RANK[a.severity] || 0));
  return out;
}

/** Compact markdown report from a summary. */
export function renderCloudFindingsMarkdown(summary, providers) {
  const order = providers && providers.length ? providers : Object.keys(summary);
  const lines = [];
  for (const prov of order) {
    const b = summary[prov]; if (!b) continue;
    const c = b.counts || {};
    lines.push(`## ${String(prov).toUpperCase()} — ${c.CRITICAL || 0} CRITICAL · ${c.HIGH || 0} HIGH · ${c.MEDIUM || 0} MEDIUM · ${c.LOW || 0} LOW · ${c.PASS || 0} PASS`);
    for (const f of (b.findings || [])) lines.push(`- **[${f.severity}]** ${f.plugin}: ${f.title}`);
    if (b.truncated) lines.push(`- _…CRITICAL/HIGH list truncated; see counts above for totals._`);
    lines.push('');
  }
  return lines.join('\n').trim();
}
