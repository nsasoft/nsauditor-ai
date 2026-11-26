// tests/support/report_coverage_gaps/_cloud_mixed_rows.mjs (a declared helper: the leading underscore)
// ─────────────────────────────────────────────────────────────────────────────
// G-72 (EE Z-1, architect VERDICT-v395 §4 (2), RULINGS-v396 C3): three Enterprise cloud rows on which `details.evidenceGap`
// is ADDITIVE. Each row states a defect, or a surface the scanner READ, and also carries the gap marker. Their producers
// declare nothing, so each row is COUNTED as a finding (as on the CE 6618bae page) and is ALSO listed as a coverage gap.
//
// Shapes copied with file and line from the Enterprise repo; names, counts and ids are examples, not an account's:
//   F-A  EE plugins/1222_azure_keyvault_deep_auditor.mjs:578-588 (the per-vault row), :378 (key enumeration could not
//        complete, the gap clause) and :494 (over-privileged grant, the defect clause); the same row is pinned by
//        EE tests/azure_keyvault_deep_auditor.test.mjs:893-907 (an over-privilege clause and a key-enum gap, flag true).
//        gapReasons carries the category only; the producer adds azureErrorFacts(e) fields beside it (:289).
//   F-B  EE plugins/1020_aws_s3_auditor.mjs:497 (Bucket ACL grants public access, CRITICAL) and :657 (Sample truncated …,
//        markEvidenceGap); the marker's own comment is :1101-1105 ("may simultaneously carry a real public-exposure
//        violation"); `resource` is copied from `bucket` as at :1599-1601.
//   F-C  EE plugins/1022_azure_cloud_scanner.mjs:604-611 (keyvault-network-acl-absent-defaults-allow, MEDIUM, one clause:
//        the scanner READ the API response, and the clause names a public-network-exposure risk and its fix).
// ─────────────────────────────────────────────────────────────────────────────

const plugin = (id, name) => ({ id, name, priority: 100, requirements: {}, runStrategy: 'single' });

export const MIXED_PLUGINS = {
  1222: plugin('1222', 'Azure Key Vault Deep Auditor'),
  1020: plugin('1020', 'AWS S3 Security Auditor'),
  1022: plugin('1022', 'Azure Security Audit'),
};

export const MIXED_RESULTS = {
  // F-A: an over-privileged grant (HIGH) and a key-enumeration gap on ONE row.
  1222: () => ({ up: true, findings: [
    { source: 'azure-keyvault-deep-auditor', resource: 'kv-example', severity: 'high',
      issues: [
        "Key Vault 'kv-example' key enumeration could not complete — key rotation/expiry posture unverified, evidence gap",
        "Key Vault 'kv-example' grants the highly-privileged role 'Owner' to 1 principal(s) (at vault scope) — over-privileged key/secret access (least-privilege erosion)",
      ],
      details: { category: 'keyvault-rbac-over-privileged-grant', evidenceGap: true,
        gapReasons: [{ category: 'keyvault-key-enumeration-unreadable' }] } },
  ] }),
  // F-B: a public bucket ACL (CRITICAL) whose object sample was truncated.
  1020: () => ({ up: true, findings: [
    { bucket: 'public-assets-example', resource: 'public-assets-example', severity: 'critical', objectListTruncated: true,
      issues: [
        'Bucket ACL grants public access (AllUsers) – bucket is publicly accessible',
        'Sample truncated: 1000 of >1000 objects scanned; remaining UNVERIFIED — public-exposure count may be higher',
      ],
      details: { category: 's3-bucket-acl-public', evidenceGap: true } },
  ] }),
  // F-C: one clause, MEDIUM, a surface the scanner read.
  1022: () => ({ up: true, findings: [
    { source: 'azure-keyvault-auditor', resource: 'kv-net-example', severity: 'medium',
      issues: [
        "Key Vault 'kv-net-example' networkAcls block absent from API response. Azure documented default when unset is defaultAction='Allow' — equivalent CC6.1 public-network-exposure risk. Configure networkAcls.defaultAction=Deny explicitly + auditor walkthrough for cross-account-aware retrieval.",
      ],
      details: { category: 'keyvault-network-acl-absent-defaults-allow', signal: 'networkAcls.defaultAction', evidenceGap: true } },
  ] }),
};

export const MIXED_LABELS = {
  1222: 'F-A 1222 (over-privileged grant + key-enumeration gap)',
  1020: 'F-B 1020 (public ACL at CRITICAL + truncated sample)',
  1022: 'F-C 1022 (one-clause network ACL default, MEDIUM)',
};
