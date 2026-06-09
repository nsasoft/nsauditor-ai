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
// Scan-coverage gap prose — an EXACT 1:1 mirror of the EE evidence-gap anchor
// (nsauditor-ai-ee utils/evidence_gap_contract.mjs EVIDENCE_GAP_ANCHOR; an EE meta-test
// drift-pins source equality). Used ONLY to order clauses WITHIN one finding — a rollup
// mixing a gap clause with an actionable clause (e.g. Key Vault key-enum gap +
// over-privilege broad-grant) must put each clause on its proper channel. NEVER used to
// classify findings — that is the details.evidenceGap marker's job.
export const GAP_CLAUSE_RE =
  /evidence[ -]?gap|\bUNVERIFIED\b|posture[^.]{0,60}\bunverified\b|posture[^.]{0,40}\bindeterminate\b|\bindeterminate,\s*manual verification|could not (?:be )?(?:read|verified?|verify|enumerated?|enumerate|complete[d]?|parse[d]?|determine[d]?|retrieve[d]?|scoped?)|did not complete|not a clean result|scan coverage is partial|provenance is partial|failed to (?:fetch|list|retrieve)|\bnot assessed\b|manual verification required/i;
// Substrate-evidence PASS prose (1220/1222 push these into the same issues[] as
// violations) — informational; never a lead clause while any alternative exists.
const PASS_CLAUSE_RE = /substrate evidence:/i;
// EE compliance-routing tag (e.g. 'EE-RT.1.2 multi-region-enumeration-incomplete: ')
// leading many gap emissions — anchor plumbing for the EE framework JSONs, not
// operator prose. Stripped at THIS presentation layer only (routing matches the
// RAW issue strings EE-side) so the 160-char slice spends its budget on substance.
const ROUTING_PREFIX_RE = /^EE-RT\.[\dx.]+ [a-z][a-z-]*: /;

function classifyClause(s) {
  if (PASS_CLAUSE_RE.test(s)) return 'pass';
  if (GAP_CLAUSE_RE.test(s)) return 'gap';
  return 'actionable';
}

// Lead-clause pick: actionable > gap > pass by default; the evidence-gap list flips to
// gap > actionable > pass so the [⚠ EVIDENCE GAP] badge always badges a GAP clause,
// never a verified fact. Falls back to issues[0] (never empty).
function pickClause(issues, prefer) {
  const order = prefer === 'gap' ? ['gap', 'actionable', 'pass'] : ['actionable', 'gap', 'pass'];
  for (const cls of order) {
    const hit = issues.find((i) => i && classifyClause(String(i)) === cls);
    if (hit !== undefined) return String(hit);
  }
  return String(issues[0]);
}

/** Robust one-line descriptor from any plugin finding shape. Never empty, never a raw object dump. */
export function describeFinding(x, opts = {}) {
  if (!x || typeof x !== 'object') return String(x ?? '').slice(0, 160);
  let res = '';
  for (const k of RESOURCE_KEYS) { if (x[k]) { res = String(x[k]); break; } }
  let why = '';
  if (Array.isArray(x.issues) && x.issues.length) why = pickClause(x.issues, opts.prefer);
  else for (const k of REASON_KEYS) { if (x[k]) { why = String(x[k]); break; } }
  why = why.replace(ROUTING_PREFIX_RE, '');
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
 * @param {number} [cap]               max CRITICAL/HIGH entries listed per provider (also caps evidenceGaps independently)
 * @returns {Object} { [provider]: { counts:{SEV:n}, findings:[{severity,plugin,title}], truncated:boolean,
 *                                   evidenceGaps:[{severity,plugin,title}], evidenceGapsTruncated?:boolean } }
 *   evidenceGaps surfaces findings carrying `details.evidenceGap === true` (the no-false-clean
 *   "could not verify" disclosures) REGARDLESS of severity, so a LOW/INFO gap is never invisible.
 */
export function summarizeCloudFindings(results, providerOf, cap = Number(process.env.CLOUD_FINDINGS_CAP) || 60) {
  const out = {};
  // Scan for the FIRST plugin that carries a scanScope (AWS plugins emit it on
  // result.summary.scanScope). Used to derive the incomplete-coverage advisory.
  // This runs before the per-finding loop so even results with no findings still
  // contribute their scanScope (e.g. a region-scoped scan with PASS on all checks).
  let advisoryScope = null;
  for (const r of (Array.isArray(results) ? results : [])) {
    const sc = r?.result?.summary?.scanScope;
    if (sc && typeof sc === 'object') { advisoryScope = sc; break; }
  }
  const advisory = incompleteCoverageAdvisory(advisoryScope);
  if (advisory) out._incompleteCoverage = advisory;

  for (const r of (Array.isArray(results) ? results : [])) {
    const found = findingsOf(r);
    if (!found.length) continue;
    // Attribute to the plugin's cloud; an unresolved id that carries REAL findings is
    // bucketed under 'unknown' rather than silently dropped (defense-in-depth against a
    // future id collision / cloudProvider drift — never let a real finding vanish).
    const prov = providerOf(r?.id ?? r?.result?.id) || UNKNOWN_PROVIDER;
    const bucket = (out[prov] ||= { counts: {}, findings: [], evidenceGaps: [], truncated: false });
    for (const x of found) {
      const sev = String(x?.severity || x?.level || 'INFO').toUpperCase();
      bucket.counts[sev] = (bucket.counts[sev] || 0) + 1;
      let findingEntry = null;
      if (sev === 'CRITICAL' || sev === 'HIGH') {
        findingEntry = { severity: sev, plugin: String(r?.id ?? ''), title: describeFinding(x) };
        bucket.findings.push(findingEntry);
      }
      if (x && typeof x === 'object' && x.details && x.details.evidenceGap === true) {
        // Lead with the GAP clause (the badge says "unverified" — badging a verified
        // fact is incoherent); carry the first actionable clause as a companion so a
        // mixed rollup's actionable content still reaches the caller (review fold D3).
        const gapEntry = { severity: sev, plugin: String(r?.id ?? ''), title: describeFinding(x, { prefer: 'gap' }) };
        const clauses = Array.isArray(x.issues) ? x.issues.filter(Boolean).map(String) : [];
        const actionable = clauses.find((i) => classifyClause(i) === 'actionable');
        if (actionable && clauses.some((i) => classifyClause(i) === 'gap')) {
          gapEntry.action = actionable.replace(ROUTING_PREFIX_RE, '').slice(0, 160);
        }
        // For CRITICAL/HIGH the actionable clause is normally itemized in the findings
        // list above, so the companion would duplicate it — but the findings list is
        // capped AFTER this loop, and an evicted entry would lose its actionable clause
        // everywhere. Keep a ref; the post-cap pass below drops the companion only when
        // the findings-list entry actually survived (0.19.3 batch-review fold).
        if (findingEntry) gapEntry._findingRef = findingEntry;
        bucket.evidenceGaps.push(gapEntry);
      }
    }
  }
  // Sort by severity (CRITICAL first) THEN truncate — so a CRITICAL is never evicted
  // from the displayed list by a HIGH. Counts above are always complete (pre-cap).
  for (const prov of Object.keys(out)) {
    if (prov === '_incompleteCoverage') continue; // meta-key, not a provider bucket
    const b = out[prov];
    b.findings.sort((a, c) => (RANK[c.severity] || 0) - (RANK[a.severity] || 0));
    if (b.findings.length > cap) { b.truncated = true; b.findings = b.findings.slice(0, cap); }
    if (b.evidenceGaps.length > cap) { b.evidenceGapsTruncated = true; b.evidenceGaps = b.evidenceGaps.slice(0, cap); }
    const kept = new Set(b.findings);
    for (const g of b.evidenceGaps) {
      if (g._findingRef) {
        if (kept.has(g._findingRef)) delete g.action; // itemized above — avoid the D3 duplicate
        delete g._findingRef; // internal ref must never reach the MCP payload
      }
    }
  }
  return out;
}

/**
 * Derive the scan-level incomplete-coverage advisory from a plugin's scanScope.
 * Returns null unless scope was IMPLICIT (operator expressed no region intent).
 * Informational + NOT harvested into compliance → maps to zero controls.
 *
 * @param {object|null} scanScope  A plugin's result.summary.scanScope object.
 * @returns {{ severity: 'info', kind: string, text: string }|null}
 */
export function incompleteCoverageAdvisory(scanScope) {
  if (!scanScope || scanScope.source !== 'implicit-default') return null;
  const unscanned = Array.isArray(scanScope.regionsKnownButNotScanned) ? scanScope.regionsKnownButNotScanned : [];
  if (unscanned.length > 0) {
    return {
      severity: 'info',
      kind: 'incomplete-region-coverage',
      text: `Incomplete region coverage — ${unscanned.length} enabled region(s) not scanned (${unscanned.join(', ')}). Re-run with --aws-region all (or set AWS_REGION) for full coverage.`,
    };
  }
  if (scanScope.resolveError) {
    return {
      severity: 'info',
      kind: 'incomplete-region-coverage',
      text: `Region scope was implicit and region enumeration could not be performed (${scanScope.resolveError}) — coverage NOT verified; pass --aws-region (or all) explicitly.`,
    };
  }
  return null;
}

/** Compact markdown from a summary. Named providers first, then any extras (e.g. 'unknown') so nothing is hidden. */
export function renderCloudFindingsMarkdown(summary, providers) {
  const named = providers && providers.length ? providers.slice() : [];
  // Exclude the meta-key _incompleteCoverage from the provider rendering loop.
  const order = [...named, ...Object.keys(summary).filter((p) => !named.includes(p) && p !== '_incompleteCoverage')];
  const lines = [];
  for (const prov of order) {
    const b = summary[prov]; if (!b) continue;
    const c = b.counts || {};
    lines.push(`## ${String(prov).toUpperCase()} — ${c.CRITICAL || 0} CRITICAL · ${c.HIGH || 0} HIGH · ${c.MEDIUM || 0} MEDIUM · ${c.LOW || 0} LOW · ${c.PASS || 0} PASS`);
    for (const f of (b.findings || [])) lines.push(`- **[${f.severity}]** ${f.plugin}: ${f.title}`);
    if (b.truncated) lines.push(`- _…CRITICAL/HIGH list truncated; see counts above for totals._`);
    for (const g of (b.evidenceGaps || [])) lines.push(`- **[⚠ EVIDENCE GAP — unverified]** ${g.plugin}: ${g.title}${g.action ? ` · actionable: ${g.action}` : ''}`);
    if (b.evidenceGapsTruncated) lines.push(`- _…evidence-gap list truncated; see LOW count for totals._`);
    lines.push('');
  }
  // Append the incomplete-coverage advisory (when present) as an informational note.
  // This advisory is summary-only and maps to zero compliance controls.
  if (summary._incompleteCoverage) {
    lines.push(`> **ℹ️ Advisory:** ${summary._incompleteCoverage.text}`);
    lines.push('');
  }
  return lines.join('\n').trim();
}
