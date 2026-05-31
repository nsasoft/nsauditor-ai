// utils/cloud_finding_summary.mjs
//
// Builds the caller-visible findings surface for scan_cloud DIRECTLY from the raw
// plugin results — the network-host concluder (result_concluder.mjs) doesn't
// understand cloud compliance findings and silently drops them. Robust across the
// plugin-specific finding shapes (AWS bucket/userName/issues, GCP/Azure title).

const RANK = { CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, INFO: 1, PASS: 0 };
// Resource-identifying keys, most-specific first so a precise label wins over the
// generic resource/name/arn fallbacks. Grounded in the REAL EE plugin emissions
// (S3 1020 emits `bucket`, Key Vault `vault`, DynamoDB `table`, KMS `key`, …).
const RESOURCE_KEYS = ['userName', 'bucket', 'bucketName', 'function', 'functionName', 'table', 'tableName', 'instanceId', 'group', 'groupId', 'key', 'keyId', 'vault', 'vaultName', 'pipeline', 'topic', 'queue', 'projectId', 'domain', 'secretName', 'roleName', 'accountName', 'resource', 'resourceId', 'name', 'arn'];
const REASON_KEYS = ['classification', 'title', 'message', 'reason', 'finding', 'detail'];
const UNKNOWN_PROVIDER = 'unknown';

/** Robust one-line descriptor from any plugin finding shape. Never empty, never a raw object dump. */
export function describeFinding(x) {
  if (!x || typeof x !== 'object') return String(x ?? '').slice(0, 160);
  let res = '';
  for (const k of RESOURCE_KEYS) { if (x[k]) { res = String(x[k]); break; } }
  let why = '';
  if (Array.isArray(x.issues) && x.issues.length) why = String(x.issues[0]);
  else for (const k of REASON_KEYS) { if (x[k]) { why = String(x[k]); break; } }
  const s = ((res ? res + ' — ' : '') + why).trim();
  if (s) return s.slice(0, 160);
  const sev = String(x.severity || x.level || '').toUpperCase();
  return sev ? sev + ' finding (no description)' : 'finding (no description)';
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
    const found = findingsOf(r);
    if (!found.length) continue;
    // Attribute to the plugin's cloud; an unresolved id that carries REAL findings is
    // bucketed under 'unknown' rather than silently dropped (defense-in-depth against a
    // future id collision / cloudProvider drift — never let a real finding vanish).
    const prov = providerOf(r?.id ?? r?.result?.id) || UNKNOWN_PROVIDER;
    const bucket = (out[prov] ||= { counts: {}, findings: [], truncated: false });
    for (const x of found) {
      const sev = String(x?.severity || x?.level || 'INFO').toUpperCase();
      bucket.counts[sev] = (bucket.counts[sev] || 0) + 1;
      if (sev === 'CRITICAL' || sev === 'HIGH') {
        bucket.findings.push({ severity: sev, plugin: String(r?.id ?? ''), title: describeFinding(x) });
      }
    }
  }
  // Sort by severity (CRITICAL first) THEN truncate — so a CRITICAL is never evicted
  // from the displayed list by a HIGH. Counts above are always complete (pre-cap).
  for (const prov of Object.keys(out)) {
    const b = out[prov];
    b.findings.sort((a, c) => (RANK[c.severity] || 0) - (RANK[a.severity] || 0));
    if (b.findings.length > cap) { b.truncated = true; b.findings = b.findings.slice(0, cap); }
  }
  return out;
}

/** Compact markdown from a summary. Named providers first, then any extras (e.g. 'unknown') so nothing is hidden. */
export function renderCloudFindingsMarkdown(summary, providers) {
  const named = providers && providers.length ? providers.slice() : [];
  const order = [...named, ...Object.keys(summary).filter((p) => !named.includes(p))];
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
