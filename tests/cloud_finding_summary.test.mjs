import { test } from 'node:test';
import assert from 'node:assert/strict';
import { describeFinding, summarizeCloudFindings, renderCloudFindingsMarkdown } from '../utils/cloud_finding_summary.mjs';

test('describeFinding handles AWS IAM shape (userName + issues)', () => {
  const d = describeFinding({ userName: 'iam-violator-user', severity: 'critical', issues: ['SHADOW ADMIN: full wildcard'] });
  assert.match(d, /iam-violator-user/); assert.match(d, /SHADOW ADMIN/);
});

test('describeFinding handles title/message shapes + unknown shape', () => {
  assert.match(describeFinding({ title: 'open firewall', severity: 'high' }), /open firewall/);
  assert.match(describeFinding({ bucketName: 'b1', classification: 'public' }), /b1/);
  assert.ok(describeFinding({ severity: 'low', foo: 'bar' }).length > 0); // never empty
});

test('summarizeCloudFindings groups by provider, counts severities, lists CRIT/HIGH', () => {
  const results = [
    { id: '1030', result: { findings: [
      { severity: 'critical', userName: 'iam-violator-user', issues: ['SHADOW ADMIN'] },
      { severity: 'critical', userName: 'superadmin', issues: ['SHADOW ADMIN'] },
      { severity: 'high', userName: 'x', issues: ['priv'] },
      { severity: 'pass', userName: 'ok' },
    ] } },
    { id: '1021', result: { data: [ { severity: 'critical', title: 'default-allow-ssh' } ] } },
  ];
  const providerOf = (id) => ({ '1030': 'aws', '1021': 'gcp' }[String(id)] || null);
  const s = summarizeCloudFindings(results, providerOf);
  assert.equal(s.aws.counts.CRITICAL, 2);
  assert.equal(s.aws.counts.HIGH, 1);
  assert.equal(s.aws.counts.PASS, 1);
  assert.equal(s.aws.findings.filter((f) => f.severity === 'CRITICAL').length, 2);
  assert.ok(s.aws.findings.some((f) => /iam-violator-user/.test(f.title)));
  assert.equal(s.gcp.counts.CRITICAL, 1);
});

test('summarizeCloudFindings caps the CRIT/HIGH list + flags truncation', () => {
  const findings = Array.from({ length: 5 }, (_, i) => ({ severity: 'high', title: 'f' + i }));
  const results = [{ id: '1030', result: { findings } }];
  const providerOf = () => 'aws';
  const s = summarizeCloudFindings(results, providerOf, 3);
  assert.equal(s.aws.counts.HIGH, 5);       // counts are complete
  assert.equal(s.aws.findings.length, 3);    // displayed list capped
  assert.equal(s.aws.truncated, true);
});

test('renderCloudFindingsMarkdown lists every CRITICAL', () => {
  const s = { aws: { counts: { CRITICAL: 1, HIGH: 0 }, findings: [{ severity: 'CRITICAL', plugin: '1030', title: 'iam-violator-user — SHADOW ADMIN' }], truncated: false } };
  const md = renderCloudFindingsMarkdown(s, ['aws']);
  assert.match(md, /CRITICAL/); assert.match(md, /iam-violator-user/);
});

test('describeFinding surfaces REAL plugin resource keys (bucket/vault/group/table/key/function/pipeline)', () => {
  assert.match(describeFinding({ bucket: 'prod-pii-bucket', severity: 'critical', issues: ['Bucket policy grants public access'] }), /prod-pii-bucket/);
  assert.match(describeFinding({ vault: 'kv-prod', severity: 'high', issues: ['no purge protection'] }), /kv-prod/);
  assert.match(describeFinding({ group: 'sg-123', severity: 'critical', issues: ['0.0.0.0/0 ingress'] }), /sg-123/);
  assert.match(describeFinding({ table: 'ddb-tbl', severity: 'high', issues: ['no PITR'] }), /ddb-tbl/);
  assert.match(describeFinding({ key: 'kms-1', severity: 'high', issues: ['wildcard decrypt'] }), /kms-1/);
  assert.match(describeFinding({ function: 'fn-x', severity: 'critical', issues: ['public URL'] }), /fn-x/);
  assert.match(describeFinding({ pipeline: 'pl-1', severity: 'high', issues: ['no encryption'] }), /pl-1/);
});

test('describeFinding never emits a raw object dump for an indeterminate finding', () => {
  const d = describeFinding({ severity: 'high', foo: 'bar' });
  assert.ok(d.length > 0);
  assert.doesNotMatch(d, /[{}]/); // no JSON.stringify blob on the headline surface
});

test('cap keeps CRITICALs in the displayed list over HIGHs when truncating', () => {
  const findings = [
    ...Array.from({ length: 60 }, (_, i) => ({ severity: 'high', title: 'h' + i })),
    { severity: 'critical', userName: 'late-crit', issues: ['SHADOW ADMIN'] },
  ];
  const s = summarizeCloudFindings([{ id: '1030', result: { findings } }], () => 'aws', 5);
  assert.equal(s.aws.counts.CRITICAL, 1);          // counts complete
  assert.equal(s.aws.counts.HIGH, 60);
  assert.equal(s.aws.findings.length, 5);          // displayed list capped
  assert.equal(s.aws.truncated, true);
  assert.ok(s.aws.findings.some((f) => f.severity === 'CRITICAL' && /late-crit/.test(f.title))); // CRITICAL survives
});

test('a result whose provider cannot be resolved is bucketed under "unknown", never dropped', () => {
  const s = summarizeCloudFindings([{ id: '9999', result: { findings: [{ severity: 'critical', title: 'orphan-finding' }] } }], () => null);
  assert.equal(s.unknown.counts.CRITICAL, 1);
  const md = renderCloudFindingsMarkdown(s, ['aws']); // 'aws' named, but unknown must still render
  assert.match(md, /orphan-finding/);
});

test('summarizeCloudFindings collects LOW details.evidenceGap findings into evidenceGaps (not lost)', () => {
  const results = [{ id: '1025', result: { findings: [
    { severity: 'low', issues: ['GCP IAM impersonation posture UNVERIFIED (evidence gap)'], details: { evidenceGap: true } },
  ] } }];
  const s = summarizeCloudFindings(results, () => 'gcp');
  assert.equal(s.gcp.counts.LOW, 1);                       // count unchanged/complete
  assert.equal(s.gcp.findings.length, 0);                  // not in the CRIT/HIGH list
  assert.equal(s.gcp.evidenceGaps.length, 1);              // surfaced in its own list
  assert.match(s.gcp.evidenceGaps[0].title, /UNVERIFIED \(evidence gap\)/);
  assert.equal(s.gcp.evidenceGaps[0].plugin, '1025');
});

test('a LOW finding WITHOUT evidenceGap is not collected as an evidence gap', () => {
  const results = [{ id: '1020', result: { findings: [
    { severity: 'low', issues: ['minor informational note'] },
  ] } }];
  const s = summarizeCloudFindings(results, () => 'aws');
  assert.equal(s.aws.counts.LOW, 1);
  assert.equal(s.aws.evidenceGaps.length, 0);
});

test('evidenceGaps survive the CRITICAL/HIGH cap (independent collection)', () => {
  const findings = [];
  for (let i = 0; i < 70; i++) findings.push({ severity: 'high', title: `h-${i}` });
  findings.push({ severity: 'low', issues: ['firewall enumeration UNVERIFIED (evidence gap)'], details: { evidenceGap: true } });
  const s = summarizeCloudFindings([{ id: '1021', result: { findings } }], () => 'gcp', 5);
  assert.equal(s.gcp.findings.length, 5);                  // CRIT/HIGH list capped
  assert.equal(s.gcp.truncated, true);
  assert.equal(s.gcp.evidenceGaps.length, 1);              // the gap is NOT evicted by the findings cap
  assert.match(s.gcp.evidenceGaps[0].title, /UNVERIFIED \(evidence gap\)/);
});

test('evidenceGaps are capped independently with an evidenceGapsTruncated flag', () => {
  const findings = [];
  for (let i = 0; i < 4; i++) findings.push({ severity: 'low', issues: [`gap-${i} (evidence gap)`], details: { evidenceGap: true } });
  const s = summarizeCloudFindings([{ id: '1025', result: { findings } }], () => 'gcp', 2);
  assert.equal(s.gcp.counts.LOW, 4);
  assert.equal(s.gcp.evidenceGaps.length, 2);
  assert.equal(s.gcp.evidenceGapsTruncated, true);
});

test('renderCloudFindingsMarkdown renders an EVIDENCE GAP section labelled unverified', () => {
  const s = { gcp: { counts: { CRITICAL: 0, HIGH: 0, LOW: 1 }, findings: [],
    evidenceGaps: [{ severity: 'LOW', plugin: '1025', title: 'GCP IAM impersonation posture UNVERIFIED (evidence gap)' }], truncated: false } };
  const md = renderCloudFindingsMarkdown(s, ['gcp']);
  assert.match(md, /EVIDENCE GAP/);
  assert.match(md, /unverified/i);
  assert.match(md, /1025: GCP IAM impersonation posture UNVERIFIED/);
});

test('renderCloudFindingsMarkdown emits NO evidence-gap section when there are none (backward-compat)', () => {
  const s = { aws: { counts: { CRITICAL: 1, HIGH: 0 }, findings: [{ severity: 'CRITICAL', plugin: '1030', title: 'iam-violator-user — SHADOW ADMIN' }], evidenceGaps: [], truncated: false } };
  const md = renderCloudFindingsMarkdown(s, ['aws']);
  assert.match(md, /iam-violator-user/);
  assert.doesNotMatch(md, /EVIDENCE GAP/);
});

// ── Actionable-clause-first describeFinding (0.19.2 Desktop validation, prompt #1) ──
// Plugin 1222 emits ONE rollup finding per vault whose issues[] mixes scan-coverage gap
// clauses with ACTIONABLE clauses (over-privilege broad-grant). describeFinding showed
// only issues[0] (the gap clause, truncated) so the actionable CC6.1/CC6.3 finding never
// reached the Desktop user. The fix: lead with the first NON-gap issue when one exists —
// the [⚠ EVIDENCE GAP] badge already conveys gap-ness on the gap channel.

const KV_GAP_CLAUSE = "Key Vault 'nsa-cmk-kv' key enumeration could not complete (Forbidden) — key rotation/expiry posture unverified, evidence gap";
const KV_ACTIONABLE_CLAUSE = "Key Vault 'nsa-cmk-kv' (legacy access-policy model) grants broad ('all'/'purge'/sensitive-crypto) key/secret/certificate permissions to 3 principal(s) — over-privileged access (least-privilege erosion); migrate to Azure RBAC + scoped roles";

test('describeFinding leads with the first ACTIONABLE (non-gap) issue when issues mix gap + actionable clauses', () => {
  const d = describeFinding({
    vault: 'nsa-cmk-kv', severity: 'medium',
    issues: [KV_GAP_CLAUSE, KV_ACTIONABLE_CLAUSE],
    details: { evidenceGap: true },
  });
  assert.match(d, /grants broad/);
  assert.doesNotMatch(d, /key enumeration could not complete/);
});

test('describeFinding keeps the gap clause when ALL issues are gap clauses (unchanged behavior)', () => {
  const d = describeFinding({ vault: 'kv-x', severity: 'medium', issues: [KV_GAP_CLAUSE], details: { evidenceGap: true } });
  assert.match(d, /key enumeration could not complete/);
});

test('describeFinding actionable-first does not disturb single-issue actionable findings', () => {
  const d = describeFinding({ bucket: 'b1', severity: 'critical', issues: ['Bucket policy grants public access'] });
  assert.match(d, /b1 — Bucket policy grants public access/);
});

test('summarizeCloudFindings evidence-gap itemization surfaces the actionable clause of a mixed rollup', () => {
  const results = [{ id: '1222', result: { findings: [{
    vault: 'nsa-cmk-kv', severity: 'medium',
    issues: [KV_GAP_CLAUSE, KV_ACTIONABLE_CLAUSE],
    details: { evidenceGap: true },
  }] } }];
  const s = summarizeCloudFindings(results, () => 'azure');
  assert.equal(s.azure.evidenceGaps.length, 1);
  // Post-fold-D3 contract: the badge-coherent GAP clause leads the title; the
  // actionable clause surfaces via the `action` companion (rendered on the same line).
  assert.match(s.azure.evidenceGaps[0].title, /key enumeration could not complete/);
  assert.match(s.azure.evidenceGaps[0].action, /grants broad/);
});

// ── Adversarial-review folds (D1/D2/D3) ──
// D1: substrate-evidence PASS clauses must never lead while an actionable clause exists.
// D2: GAP_CLAUSE_RE mirrors the EE EVIDENCE_GAP_ANCHOR (not-assessed / could-not-be-scoped
//     phrasings are gap clauses, not actionable leads).
// D3: the evidenceGaps list leads with the GAP clause (badge-coherent) and carries the
//     first actionable clause as an `action` companion the renderer appends — so the
//     actionable content of a mixed rollup reaches the Desktop user without badging a
//     verified fact as "unverified".

const KV_SUBSTRATE_PASS = "Key Vault 'nsa-cmk-kv' substrate evidence: AuditEvent logs exported to Log Analytics — audit-trail PASS";
const KV_NOT_ASSESSED = "Key Vault 'nsa-cmk-kv' diagnostic-logging posture not assessed (@azure/arm-monitor not available) — manual verification required";

test('D1: substrate-evidence PASS clause never leads when an actionable clause exists', () => {
  const d = describeFinding({ vault: 'nsa-cmk-kv', severity: 'medium', issues: [KV_GAP_CLAUSE, KV_SUBSTRATE_PASS, KV_ACTIONABLE_CLAUSE] });
  assert.match(d, /grants broad/);
  assert.doesNotMatch(d, /substrate evidence/);
});

test('D1: all-gap-plus-PASS finding leads with the gap clause, not the PASS clause', () => {
  const d = describeFinding({ vault: 'kv-x', severity: 'medium', issues: [KV_GAP_CLAUSE, KV_SUBSTRATE_PASS] });
  assert.match(d, /key enumeration could not complete/);
});

test('D2: a not-assessed clause is a gap clause — the actionable clause still leads', () => {
  const d = describeFinding({ vault: 'nsa-cmk-kv', severity: 'medium', issues: [KV_NOT_ASSESSED, KV_ACTIONABLE_CLAUSE] });
  assert.match(d, /grants broad/);
});

test('D3: describeFinding prefer:"gap" leads with the gap clause of a mixed finding', () => {
  const d = describeFinding({ vault: 'nsa-cmk-kv', severity: 'medium', issues: [KV_ACTIONABLE_CLAUSE, KV_GAP_CLAUSE] }, { prefer: 'gap' });
  assert.match(d, /key enumeration could not complete/);
});

test('D3: gap-list entries lead with the gap clause AND carry the actionable clause as action', () => {
  const results = [{ id: '1222', result: { findings: [{
    vault: 'nsa-cmk-kv', severity: 'medium',
    issues: [KV_GAP_CLAUSE, KV_SUBSTRATE_PASS, KV_ACTIONABLE_CLAUSE],
    details: { evidenceGap: true },
  }] } }];
  const s = summarizeCloudFindings(results, () => 'azure');
  assert.equal(s.azure.evidenceGaps.length, 1);
  assert.match(s.azure.evidenceGaps[0].title, /key enumeration could not complete/);
  assert.match(s.azure.evidenceGaps[0].action, /grants broad/);
});

test('D3: gap-list entries with NO actionable clause carry no action key', () => {
  const results = [{ id: '1025', result: { findings: [{
    severity: 'low', issues: ['GCP IAM impersonation posture UNVERIFIED (evidence gap)'], details: { evidenceGap: true },
  }] } }];
  const s = summarizeCloudFindings(results, () => 'gcp');
  assert.equal(s.gcp.evidenceGaps[0].action, undefined);
});

test('D3: renderer appends the actionable companion to the gap line', () => {
  const s = { azure: { counts: { MEDIUM: 1 }, findings: [], truncated: false,
    evidenceGaps: [{ severity: 'MEDIUM', plugin: '1222', title: 'nsa-cmk-kv — key enumeration could not complete', action: "grants broad ('all'/'purge'/sensitive-crypto) permissions to 3 principal(s)" }] } };
  const md = renderCloudFindingsMarkdown(s, ['azure']);
  assert.match(md, /EVIDENCE GAP/);
  assert.match(md, /actionable: grants broad/);
});

test('GAP_CLAUSE_RE is exported (EE drift-pins it against EVIDENCE_GAP_ANCHOR)', async () => {
  const mod = await import('../utils/cloud_finding_summary.mjs');
  assert.ok(mod.GAP_CLAUSE_RE instanceof RegExp);
  assert.ok(mod.GAP_CLAUSE_RE.flags.includes('i'));
});

test('D3: a CRITICAL/HIGH flagged finding gets NO action companion (its actionable clause is already itemized above)', () => {
  const results = [{ id: '1040', result: { findings: [{
    resource: 'prod-trail', severity: 'high', details: { evidenceGap: true },
    issues: ['Trail prod-trail is not multi-region (IsMultiRegionTrail=false)',
             'read coverage UNVERIFIED — data-event evidence gap'],
  }] } }];
  const s = summarizeCloudFindings(results, () => 'aws');
  assert.equal(s.aws.findings.length, 1);                       // actionable clause itemized as HIGH
  assert.match(s.aws.evidenceGaps[0].title, /evidence gap/);    // gap clause leads the gap line
  assert.equal(s.aws.evidenceGaps[0].action, undefined);        // no duplicate companion
});

// ── 0.19.3 batch-review folds ────────────────────────────────────────────────

test('describeFinding strips the EE-RT routing prefix at the presentation layer (fold)', () => {
  // EE prepends a 47-char compliance-routing tag to gap emissions; it is anchor
  // plumbing, not operator prose — with the 160-char slice it eats the
  // remediation tail. Routing happens EE-side on the RAW issue strings, so
  // stripping here is presentation-only.
  const x = {
    resource: 'kms:account [us-east-1]', severity: 'info', details: { evidenceGap: true },
    issues: ['EE-RT.1.2 multi-region-enumeration-incomplete: KMS key enumeration truncated at page cap (5000 keys) in the scanned region(s). Keys beyond the cap were NOT audited — re-scan with higher keysPageCap.'],
  };
  const d = describeFinding(x, { prefer: 'gap' });
  assert.doesNotMatch(d, /EE-RT/);
  assert.match(d, /KMS key enumeration truncated/);
  // the generalized budget-anchor variant strips too
  const d2 = describeFinding({ severity: 'info', issues: ['EE-RT.1.5.x.3 scan-time-budget-exceeded: region us-west-2 errored — posture UNVERIFIED.'] }, { prefer: 'gap' });
  assert.doesNotMatch(d2, /EE-RT/);
  assert.match(d2, /region us-west-2 errored/);

  // EE's A1 cycle ③ renamed both prefixes (the old ones rendered as the violation TITLE in
  // the customer's evidence pack). CE ships independently, so BOTH spellings must strip:
  // the two above prove the legacy pairing still works, these two prove the current one does.
  const d3 = describeFinding({
    severity: 'info', details: { evidenceGap: true },
    issues: ['Evidence gap (multi-region enumeration incomplete): KMS key enumeration truncated at page cap (5000 keys) in the scanned region(s). Keys beyond the cap were NOT audited.'],
  }, { prefer: 'gap' });
  assert.doesNotMatch(d3, /Evidence gap \(/);
  assert.match(d3, /KMS key enumeration truncated/);
  const d4 = describeFinding({
    severity: 'info',
    issues: ['Evidence gap (scan time budget exceeded): region us-west-2 errored — posture UNVERIFIED.'],
  }, { prefer: 'gap' });
  assert.doesNotMatch(d4, /Evidence gap \(/);
  assert.match(d4, /region us-west-2 errored/);
});

test('a CRIT/HIGH gap finding EVICTED by the findings cap keeps its actionable companion (fold)', () => {
  const gapClause = 'key enumeration could not be completed — evidence gap';
  const actClause = 'vault grants broad key permissions to 3 principals — over-privileged';
  const results = [{ id: '1222', result: { findings: [
    { severity: 'critical', vault: 'kv1', issues: ['public network access enabled'] },
    { severity: 'critical', vault: 'kv2', issues: ['purge protection disabled'] },
    { severity: 'high', vault: 'kv3', details: { evidenceGap: true }, issues: [gapClause, actClause] },
  ] } }];
  const s = summarizeCloudFindings(results, () => 'azure', 2);
  assert.equal(s.azure.findings.length, 2);
  assert.ok(!s.azure.findings.some((f) => /kv3/.test(f.title)), 'HIGH must be evicted by the cap in this fixture');
  const g = s.azure.evidenceGaps.find((e) => /kv3/.test(e.title));
  assert.ok(g, 'gap entry present');
  assert.match(g.action || '', /over-privileged/, 'evicted HIGH must keep its actionable companion on the gap line');
  assert.equal('_findingRef' in g, false, 'internal ref must not leak into the MCP payload');
});

test('a CRIT/HIGH gap finding that SURVIVES the cap still gets NO duplicate companion (D3 preserved)', () => {
  const results = [{ id: '1222', result: { findings: [
    { severity: 'high', vault: 'kv3', details: { evidenceGap: true },
      issues: ['key enumeration could not be completed — evidence gap', 'vault grants broad key permissions — over-privileged'] },
  ] } }];
  const s = summarizeCloudFindings(results, () => 'azure', 10);
  assert.ok(s.azure.findings.some((f) => /kv3/.test(f.title)));
  const g = s.azure.evidenceGaps[0];
  assert.equal(g.action, undefined, 'survivor keeps the D3 no-duplicate rule');
  assert.equal('_findingRef' in g, false);
});

test('summarizeCloudFindings rolls up MEDIUM+LOW by details.category, count-desc, excludes gaps, per-plugin fallback', () => {
  const results = [{ id: '1150', result: { findings: [
    { severity: 'MEDIUM', details: { category: 'sqs-age-alarm-missing' } },
    { severity: 'MEDIUM', details: { category: 'sqs-age-alarm-missing' } },
    { severity: 'MEDIUM', details: { category: 'sns-failure-alarm-missing' } },
    { severity: 'LOW', details: { category: 's3-lifecycle-demoted' } },
    { severity: 'LOW', details: { category: 'kms-gap', evidenceGap: true } },   // excluded from rollup (gap channel)
    { severity: 'MEDIUM', details: {} },                                        // -> uncategorized(1150) per-plugin
  ] } }];
  const s = summarizeCloudFindings(results, () => 'aws');
  const r = s.aws.rollup;
  assert.deepEqual(r.MEDIUM, [
    { category: 'sqs-age-alarm-missing', count: 2 },
    { category: 'sns-failure-alarm-missing', count: 1 },
    { category: 'uncategorized(1150)', count: 1 },
  ]);
  assert.deepEqual(r.LOW, [{ category: 's3-lifecycle-demoted', count: 1 }]);   // the kms-gap LOW is NOT here
  assert.equal(s.aws.counts.MEDIUM, 4);   // counts stay complete (pre-rollup): the gap LOW is still counted
  assert.equal(s.aws.counts.LOW, 2);
});

test('renderCloudFindingsMarkdown renders rollup; suffix only when getFindingsAvailable', () => {
  const summary = { aws: { counts: { MEDIUM: 3, LOW: 0 }, findings: [], evidenceGaps: [],
    rollup: { MEDIUM: [{ category: 'sqs-age-alarm-missing', count: 2 }, { category: 'sqs-dlq-missing', count: 1 }], LOW: [] } } };
  const withTool = renderCloudFindingsMarkdown(summary, ['aws'], { getFindingsAvailable: true });
  assert.match(withTool, /\*\*MEDIUM \(3\)\*\* sqs-age-alarm-missing ×2 · sqs-dlq-missing ×1 — drill any category via get_findings/);
  const without = renderCloudFindingsMarkdown(summary, ['aws'], { getFindingsAvailable: false });
  assert.match(without, /\*\*MEDIUM \(3\)\*\* sqs-age-alarm-missing ×2 · sqs-dlq-missing ×1/);
  assert.doesNotMatch(without, /get_findings/);   // no unknown-tool advertisement in a 2a-only build
});

test('gap companion joins ALL actionable clauses (not just the first)', () => {
  const x = { severity: 'LOW', details: { evidenceGap: true }, issues: [
    'KMS key enumeration could not be completed',     // gap (leads)
    'over-privileged broad grant to 3 principals',    // actionable #1
    'public key policy wildcard present',             // actionable #2
  ] };
  const s = summarizeCloudFindings([{ id: '1222', result: { findings: [x] } }], () => 'azure');
  const g = s.azure.evidenceGaps[0];
  assert.match(g.action, /over-privileged broad grant/);
  assert.match(g.action, /public key policy wildcard/);   // BOTH actionable clauses present
});

test('describeFinding truncates on a boundary, not mid-word', () => {
  const long = 'x'.repeat(150) + ' supercalifragilistic';
  const out = describeFinding({ title: long, severity: 'medium' });
  assert.ok(out.length <= 161);
  assert.doesNotMatch(out, /supercalifragil$/);   // not cut mid-word
  assert.match(out, /…$/);                          // explicit ellipsis
});

test('evidenceGaps carry gapKind from details.walkthroughRequired (absent -> couldnt-read)', () => {
  const results = [{ id: '1150', result: { findings: [
    { severity: 'LOW', details: { evidenceGap: true, walkthroughRequired: true }, issues: ['scope walkthrough'] },
    { severity: 'LOW', details: { evidenceGap: true }, issues: ['DescribeAlarms AccessDenied'] },
  ] } }];
  const s = summarizeCloudFindings(results, () => 'aws');
  assert.equal(s.aws.evidenceGaps[0].gapKind, 'walkthrough-required');
  assert.equal(s.aws.evidenceGaps[1].gapKind, 'couldnt-read');   // absent -> fail-close default
});

// ── 0.32.11: THE INFO TIER AND THE deferredScope MARKER WERE INVISIBLE ────────────
//
// Gate-3 (2026-08-05) found that of AWS's 62 INFO findings, ~7 were the evidence gaps
// already reported and the other ~55 appeared in NO summary at all — several of them
// `deferredScope` declarations ("S3 Multi-Region Access Points not evaluated", "DynamoDB
// multi-region table enumeration deferred"). The open question was whether the assistant
// summarised badly or the PRODUCT's own summary hid its scope limitations.
//
// Measured by driving this module: the header renders CRITICAL·HIGH·MEDIUM·LOW·PASS with
// INFO absent as a COLUMN, `findings[]` admits only CRITICAL/HIGH, the rollup admits only
// MEDIUM/LOW, and only `details.evidenceGap === true` reaches `evidenceGaps[]`. A
// deferredScope INFO finding was counted at the counts line and then rendered by no branch.
// So it is the product, and `deferredScope` is a contract-v1 FROZEN marker whose entire
// purpose is to let a customer tell *not assessed* from *assessed and clean*.

test('INFO is a column in the rendered header — a tier that exists must be countable', () => {
  const results = [{ id: '1060', result: { findings: [
    { severity: 'INFO', resource: 'r1', issues: ['an informational observation'], details: { category: 'obs' } },
    { severity: 'CRITICAL', resource: 'r2', issues: ['a real problem'], details: { category: 'bad' } },
  ] } }];
  const s = summarizeCloudFindings(results, () => 'aws');
  const md = renderCloudFindingsMarkdown(s, ['aws']);
  const header = md.split('\n')[0];
  assert.match(header, /1 INFO/,
    'the header omitted the INFO tier while 1 INFO finding existed — the summary reports ' +
    'fewer findings than the scan emitted, which is how a third of a scan goes missing');
  assert.match(header, /1 CRITICAL/); // positive control: the header is really being read
});

test('deferredScope declarations reach the summary — "not assessed" must not read as "clean"', () => {
  const results = [{ id: '1060', result: { findings: [
    { severity: 'INFO', resource: 'dynamodb:account',
      issues: ['Deferred scope (auditor walkthrough recommended) — multi-region table enumeration is not evaluated in this release.'],
      details: { category: 'dynamodb-scope-deferred-v1', deferredScope: true, deferredScopeId: 'EE-RT.2' } },
  ] } }];
  const s = summarizeCloudFindings(results, () => 'aws');
  assert.equal(s.aws.deferredScope.length, 1, 'the structured payload must carry a deferredScope surface');
  assert.match(s.aws.deferredScope[0].title, /multi-region table enumeration/);

  const md = renderCloudFindingsMarkdown(s, ['aws']);
  assert.match(md, /multi-region table enumeration/,
    'a declaration of what was NOT assessed is absent from the rendered summary — the ' +
    'report reads more complete than the scan was');
});

test('a deferredScope declaration is NOT badged as an evidence gap', () => {
  // contract-v1 §2: `deferredScope` "must NOT route as a live gap". The 2026-06-10 operator
  // decision deliberately UNMARKED these from evidenceGap because a capability boundary
  // routed would fail every scan universally. Surfacing must not undo that by the back door —
  // badging a static boundary "⚠ EVIDENCE GAP — unverified" re-asserts exactly the claim the
  // unmarking removed.
  const results = [{ id: '1060', result: { findings: [
    { severity: 'INFO', resource: 'r', issues: ['Deferred scope — X is not evaluated.'],
      details: { category: 'c', deferredScope: true, deferredScopeId: 'EE-RT.2' } },
  ] } }];
  const s = summarizeCloudFindings(results, () => 'aws');
  assert.equal(s.aws.evidenceGaps.length, 0, 'a deferredScope finding must not enter the evidenceGaps channel');
  const md = renderCloudFindingsMarkdown(s, ['aws']);
  assert.ok(!/EVIDENCE GAP[^\n]*X is not evaluated/.test(md),
    'the boundary was rendered under the evidence-gap badge');
});

test('a multi-line issue does not break the markdown list', () => {
  // Five of the nine deferredScope producers build the issue as "…—\n- bullet\n- bullet".
  // The render loop emits one list item per line, so an embedded newline terminates the item
  // and dumps the rest as unformatted body text.
  const results = [{ id: '1130', result: { findings: [
    { severity: 'INFO', resource: 'v', issues: ['Deferred scope — the following are not evaluated:\n- alpha\n- beta'],
      details: { category: 'c', deferredScope: true, deferredScopeId: 'EE-RT.12' } },
  ] } }];
  const md = renderCloudFindingsMarkdown(summarizeCloudFindings(results, () => 'aws'), ['aws']);
  const scopeLines = md.split('\n').filter((l) => /alpha/.test(l));
  assert.equal(scopeLines.length, 1, 'the declaration spilled across lines and broke the list');
  assert.ok(/^- /.test(scopeLines[0]), 'the spilled remainder is no longer a list item');
});

test('the INFO tier rolls up by category so 55 observations are visible without 55 lines', () => {
  const findings = Array.from({ length: 12 }, (_, i) => ({
    severity: 'INFO', resource: 'r' + i, issues: ['obs ' + i],
    details: { category: i < 8 ? 'kms-key-note' : 'lifecycle-note' },
  }));
  const s = summarizeCloudFindings([{ id: '1070', result: { findings } }], () => 'aws');
  const md = renderCloudFindingsMarkdown(s, ['aws']);
  assert.match(md, /kms-key-note ×8/);
  assert.match(md, /lifecycle-note ×4/);
});

test('an INFO evidence gap still reaches the gap channel and is not double-counted in the rollup', () => {
  const results = [{ id: '1030', result: { findings: [
    { severity: 'INFO', resource: 'g', issues: ['Evidence gap: could not read the policy'],
      details: { category: 'gap', evidenceGap: true } },
    { severity: 'INFO', resource: 'o', issues: ['plain observation'], details: { category: 'obs' } },
  ] } }];
  const s = summarizeCloudFindings(results, () => 'aws');
  assert.equal(s.aws.evidenceGaps.length, 1);
  const info = (s.aws.rollup.INFO || []).map((r) => r.category);
  assert.deepEqual(info, ['obs'],
    'an evidence gap was rolled up as an ordinary observation as well as badged — the same ' +
    'record counted on two channels is how a cross-cloud roll-up becomes arithmetically wrong');
});
