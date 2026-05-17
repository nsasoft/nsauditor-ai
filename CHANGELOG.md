# Changelog

Release notes for **`nsauditor-ai`** (Community Edition). The main [README](./README.md) focuses on features and usage — this file is the per-release history, kept for upgrade triage and audit reference.

For Enterprise Edition release notes, see [`@nsasoft/nsauditor-ai-ee`](https://www.npmjs.com/package/@nsasoft/nsauditor-ai-ee).

---

## 0.1.49 — docs-only: paired-release announcement for EE 0.5.0 (minor-version milestone bump 0.4.x → 0.5.x — EE-RT.18 v2 plugin 1190 SES Email Integrity Auditor extension: DKIM CNAME DNS resolution + DMARC TXT record parser + SES classic API parity + 8 same-session reviewer folds incl. 1 CRITICAL false-CLEAN closure on DMARC pct=0 + 1 HIGH false-NEGATIVE closure on DMARC sp subdomain-policy override)

No code changes. CE 0.1.49 ships the same code as 0.1.40 → 0.1.48 with README updated to announce the paired **EE 0.5.0 release** and reflect the plugin 1190 v2 extension in the public plugin catalog. CE binary is code-identical to the 0.1.40-line; the bump exists solely to carry the EE-paired-release narrative to the npm landing page and to deprecate 0.1.48 with the explicit EE-paired-release pointer. **0.5.0 is a minor-version milestone bump** (vs the natural 0.4.10) marking the first ship to add NETWORK-LAYER cross-reference (live DNS resolution via `node:dns/promises`) to the AWS-SDK-substrate evidence baseline — structurally distinct evidence-acquisition surface from prior 0.4.x cycles.

---

## 0.1.48 — docs-only: paired-release announcement for EE 0.4.9 (seventh-ship-cycle in 0.4.x — EE-RT.17 v2 plugin 1180 ElastiCache Redis Auditor extension: KMS-DescribeKey promotion + subnet route-table verifier + 7 same-session reviewer folds incl. 1 MEDIUM false-NEGATIVE closure on default-VPC main-RT inheritance)

No code changes. CE 0.1.48 ships the same code as 0.1.40 → 0.1.47 with README updated to announce the paired **EE 0.4.9 release** and reflect the plugin 1180 v2 extension in the public plugin catalog. CE binary is code-identical to the 0.1.40-line; the bump exists solely to carry the EE-paired-release narrative to the npm landing page and to deprecate 0.1.47 with the explicit EE-paired-release pointer.

**EE 0.4.9 paired-release highlights:**

- **Plugin 1180 EXTENDED across dims 2 + 6** via **EE-RT.17 v2** — single-plugin extension cycle. Closes **both** v1 deferred items (R-MEDIUM-3 KMS-DescribeKey promotion + R-LOW-2 subnet route-table cross-reference).
- **Part A — kms:DescribeKey cross-reference promotion** (dim 2 at-rest encryption; mirrors plugin 1140 v2 pattern). UNVERIFIABLE `:key/UUID` ARN shapes promoted via `KeyMetadata.KeyManager` to deterministic PASS (CUSTOMER) / MEDIUM (AWS). Conservative on AccessDenied / NotFound / unknown KeyManager — no false-CLEAN promotion.
- **Part B — Subnet route-table verifier** (dim 6 subnet placement; closes v1 R-LOW-2; cross-plugin sister with plugin 1170 SG perimeter). `elasticache:DescribeCacheSubnetGroups` + `ec2:DescribeRouteTables` walk. Per-subnet IGW-route detection via `/^igw-[a-f0-9]+$/i` (correctly excludes egress-only `eigw-`). HIGH on IGW-routed subnet(s) (with per-subnet `igwDestinationsBySubnet` evidence per R-HIGH-1 fold for auditor evidentiary completeness) / PASS on all-verified-private / **LOW + evidenceGap on main-RT-inheritance per R-MEDIUM-2 reviewer-fold false-NEGATIVE closure** (default-VPC main-RT typically carries `0.0.0.0/0 → igw-*`; cache subnet groups using subnets with no explicit RT associations are a real false-NEGATIVE hazard).
- **EE plugin count: UNCHANGED at 20** (no new plugin; existing 1180 grew in scope).
- **7 same-session reviewer folds across the cycle** (independent `general-purpose-agent` review yielded 12 findings; 7 folded same-session, 1 deferred to cross-plugin Thread H sweep, 4 withdrawn after verification). **MEDIUM-2 closure (most important)**: main-RT-inheritance escalated INFO → LOW + evidenceGap. **HIGH-1 closure**: IGW destination CIDR blocks surfaced in HIGH finding details. **MEDIUM-3/LOW-6/7/9/10/11/NIT-12 closures**: cache-key semantic legibility + dead-branch removal + SDK-injection threading + test gaps + doc-comment past-tense for v2-shipped.
- **DEFERRED R-MEDIUM-4** to cross-plugin Thread H sweep: `_promote*FromKms(finding, keyManager)` signature brittleness across plugins 1140 v2 + 1180 v2 — cross-plugin fold to `(finding, keyManagerByArn: Map)` signature for single-source-of-truth lookup.
- **No new SDK dependencies** — `@aws-sdk/client-kms` + `@aws-sdk/client-ec2` already declared in optionalDependencies since EE 0.4.5 (used by plugins 1140 v2 + 1170).
- **Real-AWS smoke validation END-TO-END**: smoke against `<operator-test-account>` (no fixture changes needed). `redis-leaky-cache` → dim 6 LOW `elasticache-subnet-main-rt-inheritance` (the R-MEDIUM-2 fold escalation demonstrably firing against the real default-VPC main-RT-inheritance pattern). Both KMS + EC2 clients load cleanly with no AccessDenied / no throttling; per-resource caches populate correctly. `findingsBySeverity: { pass:1, medium:3, high:5, low:2, info:1 }`; durationMs=1428. **No real-AWS exercise of KMS promotion path** — existing ElastiCache fixtures use alias-form CMK keys (unit tests + plugin 1140 v2 real-AWS validation cover the promotion path).
- **Coverage matrix UNCHANGED at 10/4/33** — institutional honesty per the matrix-shift discipline; 5 new aws-elasticache-redis-auditor mapping rules add evidence depth on already-covered CC6.6 + C1.1 controls.
- **EE-side stats: +29 new tests** (22 v2 base + 7 reviewer-fold pin tests); **EE full regression: 4696/4696; 45-session 100% green streak preserved**.
- **Fifth consecutive trio-publish across EE + CE + agent-skill in a single session** — institutionalized discipline now spans 5 ship cycles (0.4.5/0.4.6/0.4.7/0.4.8/0.4.9). Paired agent-skill 0.1.15 catalog refresh reflects the plugin 1180 v2 extension on the AI-coding-agent knowledge surface.
- **Memory tag closures**: `aws_string_case_normalization` holds steady at **20×** (v2 reinforced KeyManager + IGW GatewayId case-norm at comparison boundary per SPLIT-SURFACE variant); `conservative_classifier_principle` reinforced in 4 new fold sites; `emit_literal_set_drift` extended with `ELASTICACHE_AT_REST_KMS_UNVERIFIABLE_CATEGORY` named-constant discipline.

**CE-side state:** unchanged binary. CE 0.1.48 = CE 0.1.47 = ... = CE 0.1.40 = CE 0.1.39 code-identical; bump exists solely to carry the EE-paired-release narrative + deprecate 0.1.47 with the explicit EE-paired-release pointer.

**Recommended upgrade path:** `npm install -g nsauditor-ai@0.1.48 @nsasoft/nsauditor-ai-ee@0.4.9` (paired upgrade; + `npm install nsauditor-ai-agent-skill@0.1.15` for AI-coding-agent users).

---

## 0.1.47 — docs-only: paired-release announcement for EE 0.4.8 (sixth-ship-cycle in 0.4.x — EE-RT.14 v3 plugin 1140 RDS Auditor 7 → 10 dimensions with database audit-logging + 9 same-session reviewer folds incl. 1 HIGH false-INFO closure on Aurora cluster log path; first 0.4.x extension cycle to validate PASS+HIGH path end-to-end against real AWS)

No code changes. CE 0.1.47 ships the same code as 0.1.40 → 0.1.46 with README updated to announce the paired **EE 0.4.8 release** and update plugin **1140 AWS RDS Auditor** row in the public plugin catalog to reflect the v3 extension (7 → 10 dimensions; +database audit-logging triad). CE binary is code-identical to the 0.1.40-line; the bump exists solely to carry the EE-paired-release narrative to the npm landing page and to deprecate 0.1.46 with the explicit EE-paired-release pointer.

**EE 0.4.8 paired-release highlights:**

- **Plugin 1140 EXTENDED 7 → 10 dimensions** via **EE-RT.14 v3** — first 0.4.x extension cycle of an existing plugin (vs. NEW plugin cycles). Closes the "database activity logs" SOC 2 dimension per `tasks/things-to-check.md` §4 audit-canonical checklist (CC7.2 + CC7.3 continuous monitoring + event evaluation).
- **3 new audit-logging dimensions**: **dim 8 pgAudit enabled** (postgres-only — `DescribeDBParameters → pgaudit.log` + cross-checks `shared_preload_libraries` contains `pgaudit` token per R-MEDIUM-2 reviewer-fold **false-PASS closure** since Postgres silently ignores the GUC when SPL omits pgaudit; new MEDIUM category `rds-pgaudit-misconfigured`), **dim 9 CloudWatch Logs exports** (`EnabledCloudwatchLogsExports` engine-dispatched essential/optional policy: postgres essential=`postgresql`; mysql/mariadb essential=`error`; oracle essential=`audit`+`trace`; sqlserver essential=`error`), **dim 10 CloudWatch Logs retention** (`logs:DescribeLogGroups` enumeration on engine-dispatched prefix per R-HIGH-1 reviewer-fold: `/aws/rds/instance/<id>/` for non-Aurora, `/aws/rds/cluster/<DBClusterIdentifier>/` for `aurora-*` engines — pre-fold hard-coded the instance path → 0 log groups on every Aurora node = false-INFO MEDIUM across whole Aurora fleet).
- **EE plugin count: UNCHANGED at 20** (no new plugin; existing 1140 grew in scope).
- **9 same-session reviewer folds across the cycle** (independent `general-purpose-agent` review yielded 12 findings; 9 folded same-session, 3 deferred to v3.1 / cross-plugin sweep). **HIGH-1 closure**: Aurora cluster log-path detection (false-INFO closure across whole Aurora fleet). **MEDIUM-2 closure**: pgAudit + shared_preload_libraries cross-check (false-PASS closure on misconfigured pgaudit instances). **MEDIUM-3/4/5 closures**: cwl-opt-out + retentionDistribution + transient-error all surfaced as distinct categories for auditor evidence-pack legibility.
- **Real-AWS smoke validation END-TO-END**: in-place modification of existing `rds-compliant-cluster` fixture (cost $0; brief Multi-AZ failover during apply-immediately reboot) validated ALL 3 v3 PASS-path classifiers; unmodified `rds-violator-db` validated HIGH path. Account-wide finding distribution: 9 PASS + 2 MEDIUM + 4 INFO + 5 HIGH. **First 0.4.x extension cycle to validate BOTH PASS-path AND HIGH-path classifiers** against real AWS in the same smoke run.
- **`@aws-sdk/client-cloudwatch-logs` already declared in optionalDependencies** (used by plugin 1040 since EE 0.4.0); v3 reuses it via new `_loadCwlSdk` lazy loader.
- **Coverage matrix UNCHANGED at 10/4/33** — institutional honesty per the matrix-shift discipline; 7 new aws-rds-auditor mapping rules under CC7.2 add evidence depth on already-covered controls.
- **EE-side stats: +68 new tests** (49 v3 base + 19 reviewer-fold pin tests); **EE full regression: 4642/4642; 44-session 100% green streak preserved**.
- **Fourth consecutive trio-publish across EE + CE + agent-skill in a single session** — institutionalized discipline now spans 4 ship cycles (0.4.5/0.4.6/0.4.7/0.4.8). Paired agent-skill 0.1.14 catalog refresh reflects the plugin 1140 v3 extension on the AI-coding-agent knowledge surface.
- **Memory tag closures**: `aws_string_case_normalization` extended (engine + log-name normalization in v3 classifiers; recurrence count holds at **20×** with SPLIT-SURFACE callout); `conservative_classifier_principle` reinforced in 4 new fold sites; `emit_literal_set_drift` extended with `_PGAUDIT_LIBRARY_NAME` + `_SHARED_PRELOAD_LIBRARIES_PARAM` named-constant discipline.

**CE-side state:** unchanged binary. CE 0.1.47 = CE 0.1.46 = CE 0.1.45 = ... = CE 0.1.40 = CE 0.1.39 code-identical; bump exists solely to carry the EE-paired-release narrative + deprecate 0.1.46 with the explicit EE-paired-release pointer.

**Recommended upgrade path:** `npm install -g nsauditor-ai@0.1.47 @nsasoft/nsauditor-ai-ee@0.4.8` (paired upgrade; + `npm install nsauditor-ai-agent-skill@0.1.14` for AI-coding-agent users).

---

## 0.1.46 — docs-only: paired-release announcement for EE 0.4.7 (fifth-ship-cycle in 0.4.x — EE-RT.18 v1 NEW plugin 1190 AWS SES Email Integrity Auditor + 11 same-session reviewer folds incl. 1 CRITICAL false-CLEAN closure on NotPrincipal+Allow wildcard-equivalence)

No code changes. CE 0.1.46 ships the same code as 0.1.40 → 0.1.45 with README updated to announce the paired **EE 0.4.7 release** and add plugin **1190 AWS SES Email Integrity Auditor** to the public plugin catalog. CE binary is code-identical to the 0.1.40-line; the bump exists solely to carry the EE-paired-release narrative to the npm landing page and to deprecate 0.1.45 with the explicit EE-paired-release pointer.

**EE 0.4.7 paired-release highlights:**

- **NEW plugin 1190 `aws-ses-auditor`** (EE-RT.18 v1) — first plugin in the 1190-1199 ID range. Closes the next-highest-priority gap from `tasks/things-to-check.md` AWS SOC 2 audit-canonical compliance checklist after Redis closed in 0.4.6. **6 audit dimensions:** DKIM enablement + signing status (CC6.1 / Privacy — HIGH on SigningEnabled=false; transient INFO + walkthroughRequired; FAILED MEDIUM on DNS drift) + custom MailFrom domain alignment (Privacy substrate — DMARC alignment substrate via MailFromDomainStatus) + configuration set TLS enforcement (C1.1 — REQUIRE PASS / OPTIONAL HIGH SMTP-downgrade-attack window / non-string distinct LOW with tlsPolicyType evidence per R-MEDIUM-7 fold) + identity sending authorization policy permissive principals (CC6.6 — multi-class wildcard detector covering bare `"*"` / `{AWS:*}` / `{Service:*}` / `{Federated:*}` / `{CanonicalUser:*}` / array forms per R-HIGH-4 fold + distinct HIGH `ses-sending-auth-notprincipal-allow` per R-CRITICAL-1 fold catching universal-grant-minus-exclusion-list wildcard-EQUIVALENT class + LOW + evidenceGap `ses-sending-auth-malformed-statement` for Effect-missing send-action statements per R-HIGH-2 fold) + dedicated IP pool sending posture (CC7.1 substrate, account-level) + suppression list state (CC7.1 deliverability substrate — ZDE invariant: NEVER reads suppressed-destination email addresses; count + reason only).
- **EE plugin count: 19 → 20** (plugin 1190 added).
- **11 same-session reviewer folds across the cycle** — ties the single-cycle reviewer-fold record for security-classifier-correctness-surface plugins (independent `general-purpose-agent` review yielded 12 findings; 11 folded same-session, 1 deferred to cross-plugin Thread H sweep). **CRITICAL-1 closure** — NotPrincipal+Effect=Allow distinct HIGH category (pre-fold silently classified as bounded = false-CLEAN; matches plugins 1070 + 1150 NotPrincipal+Allow discipline). **HIGH-4 closure** — `_isWildcardPrincipal` walks every Principal class value (pre-fold only `principal.AWS` inspected). **HIGH-2 closure** — missing-Effect malformed-statement LOW + evidenceGap (pre-fold silently dropped).
- **Fourth EE plugin to ship without smoke-time SDK hotfix** — `@aws-sdk/client-ses` + `@aws-sdk/client-sesv2` both preemptively added to optionalDependencies BEFORE smoke validation per the 11th pre-implementation checklist item (preemptive SDK addition now institutional discipline).
- **Coverage matrix UNCHANGED at 10/4/33** — institutional honesty per the matrix-shift discipline; EE 0.4.7 adds substrate evidence depth on already-covered CC6.1 / CC6.6 / C1.1 via 8 new aws-ses-auditor mapping rules.
- **EE-side stats: +116 new tests** (94 EE-RT.18 v1 unit-test suite + 22 reviewer-fold pin tests); **EE full regression: 4574/4574; 43-session 100% green streak preserved**.
- **No real-AWS smoke against violation-tier fixtures** — <operator-internal-test-infra-repo> has NO SES paired fixtures yet (full-stack fixtures deferred to EE-RT.18 v2 alongside DKIM CNAME DNS resolution + DMARC TXT record parsing). Empty-account smoke baseline against <operator-test-account> DID succeed end-to-end (plugin loads via CE→EE binding, all 4 SESv2 API enumerations succeed, baseline 2 INFO findings emit correctly, durationMs=842, ZDE invariant preserved).
- **Third consecutive trio-publish across EE + CE + agent-skill in a single session** — institutional discipline (after 0.4.5 institutionalized the pattern + 0.4.6 confirmed it). Paired agent-skill 0.1.13 catalog refresh adds plugin 1190 to the AI-coding-agent knowledge surface.
- **Memory tag closures:** `aws_string_case_normalization` at **20×** with explicit SPLIT-SURFACE callout (DKIM/Tls/MailFromStatus enums upcased / IAM Action/Effect lowercased); `conservative_classifier_principle` reinforced in 5 new fold sites; `emit_literal_set_drift` extended with `_DKIM_STATUS_VALID` + `_MAILFROM_STATUS_SUCCESS` + `_TLS_POLICY_VALID` named-constant discipline.

**CE-side state:** unchanged binary. CE 0.1.46 = CE 0.1.45 = CE 0.1.44 = CE 0.1.43 = CE 0.1.42 = CE 0.1.41 = CE 0.1.40 = CE 0.1.39 code-identical; bump exists solely to carry the EE-paired-release narrative to the npm landing page and to deprecate 0.1.45 with the explicit EE-paired-release pointer.

**Recommended upgrade path:** `npm install -g nsauditor-ai@0.1.46 @nsasoft/nsauditor-ai-ee@0.4.7` (paired upgrade; + `npm install nsauditor-ai-agent-skill@0.1.13` for AI-coding-agent users).

---

## 0.1.45 — docs-only: paired-release announcement for EE 0.4.6 (fourth multi-ship cycle in 0.4.x — EE-RT.16 v2 SG Perimeter extension RESTRICTED_PORTS 13 → 23 ports + EE-RT.17 v1 NEW plugin 1180 AWS ElastiCache Redis Auditor + 10 same-session reviewer folds incl. 2 CONVERGENT-CRITICAL findings)

No code changes. CE 0.1.45 ships the same code as 0.1.40 / 0.1.41 / 0.1.42 / 0.1.43 / 0.1.44 with README updated to announce the paired **EE 0.4.6 release** and add plugin **1180 AWS ElastiCache Redis Auditor** to the public plugin catalog (plus update the plugin 1170 row to reflect EE-RT.16 v2 RESTRICTED_PORTS growth from 13 → 23 ports per CIS AWS Foundations v3.0).

**EE 0.4.6 paired-release highlights:**

- **EE plugin count: 18 → 19** — fourth plugin-count growth in the 0.4.x cycle. NEW plugin **1180 AWS ElastiCache Redis Auditor** (EE-RT.17 v1) covers 6 SOC 2 substrate-evidence dimensions: transit encryption (C1.1), at-rest encryption with KMS key custody (C1.1 four-tier ladder), Redis AUTH / IAM-auth user groups (CC6.1 + CC6.2), Multi-AZ deployment (A1.2), SnapshotRetentionLimit cadence (A1.2), subnet placement (CC6.6). Dual API enumeration (DescribeReplicationGroups + DescribeCacheClusters) with inter-API dedup. Memcached out-of-scope by design. Closes the highest-priority gap from `tasks/things-to-check.md` AWS SOC 2 audit-canonical compliance checklist.
- **Plus EE-RT.16 v2** — plugin 1170 AWS EC2 SG Perimeter Auditor extension; **RESTRICTED_PORTS grown 13 → 23 ports** per CIS AWS Foundations Benchmark v3.0 (adds Redshift 5439, K8s API 6443, etcd 2379-2380, Kibana 5601, InfluxDB 8086, Kafka 9092, Consul 8500, ZooKeeper 2181, Vault 8200) + new `opts.additionalRestrictedPorts` operator-config knob (integer-validated 0-65535 + deduped against baseline) + per-SG cardinality cap with rollup trailer (`...and N more` overflow) + system-managed-SG name-prefix exclusion list (`ElasticMapReduce-`, `eks-cluster-sg-`, `AWSServiceRole`, `awseb-` etc.).
- **Ten same-session reviewer folds applied across the cycle** (7 EE-RT.16 v2 incl. 2 CONVERGENT-CRITICAL + 3 EE-RT.17 v1) — **most-folds-in-a-single-cycle for 0.4.x to date**:
  - EE-RT.16 v2: **C1 (CONVERGENT-CRITICAL)** pre-existing v1 PASS-tier titlePattern bug (v1 R-HIGH-1 fold softened narrative but did NOT update soc2.json regex); **C2 (CONVERGENT-CRITICAL)** cardinality-cap-trailer titlePatterns silently dropped at framework-engine harvest pre-fold; R-HIGH-1 CIS v3.0 alignment narrative; R-MEDIUM-1 `default-` over-broad prefix removal; R-MEDIUM-2 additionalRestrictedPorts integer validation; R-LOW-1 canonical-pattern parity; NIT-2 header comment refresh.
  - EE-RT.17 v1: R-MEDIUM-1 UserGroupIds cardinality cap via `_USER_GROUP_DISPLAY_CAP = 10` (canonical-pattern parity with plugin 1170 v2); R-LOW-1 transient Multi-AZ state INFO + evidenceGap (avoid false-CLEAN on enabling/disabling); R-LOW-2 inter-API dedup test pin.
- **Coverage matrix UNCHANGED at 10/4/33** — institutional honesty per the matrix-shift discipline; EE 0.4.6 adds evidence depth on already-covered CC6.1 / CC6.2 / CC6.6 / A1.2 / C1.1.
- **EE full regression: 4458/4458** (was 4361 at EE 0.4.5 publish; +97 tests: 56 EE-RT.16 v2 + 41 EE-RT.17 v1). 42-session 100% green streak preserved.
- **Memory tag closures:** `aws_string_case_normalization` at **19×** cross-codebase (+2 fold-sites this cycle); `conservative_classifier_principle` reinforced in 6 fold sites; `emit_literal_set_drift` holds at 17×.
- **Third EE plugin to ship without smoke-time SDK hotfix** — `@aws-sdk/client-elasticache` preemptively added to optionalDependencies per the 11th pre-implementation checklist item (plugins 1150, 1170, 1180 all shipped without smoke-time hotfix; preemptive SDK addition now institutional discipline).
- **Second trio-publish across EE + CE + agent-skill in a single session** — institutionalizes the trio-publish pattern that started in the 0.4.5 cycle. Paired agent-skill 0.1.12 catalog refresh adds plugin 1180 + plugin 1170 v2 to AI-coding-agent knowledge surface.
- **Real-AWS smoke-validated** against `<operator-internal-test-infra-repo>` paired fixtures (account <operator-test-account>, plugins 1170 v2 + 1180 v1): `findingCount: 21`; CC6.6 → FAIL (8), C1.1 → FAIL (4), CC6.1 → FAIL (2), A1.2 → FAIL (3). Plugin 1180 correctly classifies `redis-secure-cache` (PASS transit + MEDIUM at-rest AWS-owned-default + MEDIUM no-auth + HIGH Multi-AZ disabled + HIGH SnapshotRetention=0 + INFO subnet) + `redis-leaky-cache` (HIGH on transit + at-rest + retention; INFO standalone-not-applicable for Multi-AZ).

**CE-side state:** unchanged binary. CE 0.1.45 = CE 0.1.44 = CE 0.1.43 = CE 0.1.42 = CE 0.1.41 = CE 0.1.40 = CE 0.1.39 code-identical; bump exists solely to carry the EE-paired-release narrative to the npm landing page and to deprecate 0.1.44 with the explicit EE-paired-release pointer.

**Recommended upgrade path:** `npm install -g nsauditor-ai@0.1.45 @nsasoft/nsauditor-ai-ee@0.4.6` (paired upgrade; + `npm install nsauditor-ai-agent-skill@0.1.12` for AI-coding-agent users).

---

## 0.1.44 — docs-only: paired-release announcement for EE 0.4.5 (third multi-ship cycle in 0.4.x — EE-RT.14 v2 RDS extension to 7 dims + kms:DescribeKey + EE-RT.16 v1 NEW plugin 1170 AWS EC2 SG Perimeter Auditor + 9 same-session reviewer folds)

No code changes. CE 0.1.44 ships the same code as 0.1.40 / 0.1.41 / 0.1.42 / 0.1.43 with README updated to announce the paired **EE 0.4.5 release** and add plugin **1170 AWS EC2 SG Perimeter Auditor** to the public plugin catalog (plus update the plugin 1140 row to reflect EE-RT.14 v2 growth from 3 dims → 7).

**EE 0.4.5 paired-release highlights:**

- **EE plugin count: 17 → 18** — third plugin-count growth in the 0.4.x cycle. NEW plugin **1170 AWS EC2 SG Perimeter Auditor** (EE-RT.16 v1) covers 6 SOC 2 CC6.6 network-segmentation dimensions + 1 CC6.2 governance dimension. RESTRICTED_PORTS covers 13 ports (SSH/RDP/MS SQL/MySQL/Postgres/Redis/Memcached/MongoDB/Elasticsearch/CouchDB/Docker/Kubelet). Orthogonal evidence to plugin 1023 zero-trust-checker (1023 = OBSERVED ports; 1170 = DECLARED policy). Cross-plugin sister of the EE-RT.14 v2 `_classifyPublicAccessibility` dimension.
- **Plus EE-RT.14 v2** — plugin 1140 AWS RDS Auditor grown from 3 substrate dimensions to **7**: BackupRetentionPeriod (A1.2 cadence), PubliclyAccessible (CC6.6 perimeter), IAMDatabaseAuthenticationEnabled (CC6.1 password-less auth), snapshot encryption (C1.1 cross-cycle). Plus the **kms:DescribeKey cross-reference path** that promotes UNVERIFIABLE `:key/UUID` ARN shapes to deterministic PASS (customer-managed) / MEDIUM (AWS-managed) via `KeyMetadata.KeyManager`. Closes the v1 smoke-discovered fixture-design gap where `rds-compliant-cluster` references its CMK by bare UUID form. Conservative on AccessDenied/NotFound/unknown KeyManager — leaves at UNVERIFIABLE LOW (no false-CLEAN promotion).
- **Nine same-session reviewer folds applied across the cycle** (5 EE-RT.14 v2 + 4 EE-RT.16 v1):
  - EE-RT.14 v2: R-HIGH-1 `_IAM_AUTH_SUPPORTED_ENGINES` lifted + frozen; R-MEDIUM-1 `RDS_STORAGE_KMS_UNVERIFIABLE_CATEGORY` named constant; R-MEDIUM-3 `_isUnverifiableKmsShape` single source of truth; R-LOW-1 upper-bound clamp on backup-retention override; R-NIT-1 explicit `IncludeShared=false` on snapshot enumeration.
  - EE-RT.16 v1: R-HIGH-1 UserIdGroupPairs evidenceGap + softened PASS narrative (false-CLEAN closure on intra-VPC SG-as-source rules); R-MEDIUM-1 all-protocol SG-scope suppression (single CRITICAL/SG instead of N+1); R-MEDIUM-1 CONVERGENT SG-list + ENI AccessDenied account-level evidenceGap findings (operator-channel warnings → auditor-channel findings); NIT-3 header comment accuracy.
- **Coverage matrix UNCHANGED at 10/4/33** — institutional honesty per the matrix-shift discipline; EE 0.4.5 adds evidence depth on already-covered CC6.1 / CC6.2 / CC6.6 / A1.2 / C1.1.
- **EE full regression: 4361/4361** (was 4255 at EE 0.4.4 publish; +106 tests: 52 EE-RT.14 v2 + 54 EE-RT.16 v1 — 49 initial + 5 reviewer-fold pins). 40-session 100% green streak preserved.
- **Memory tag closures:** `emit_literal_set_drift` recurrence at **17×** cross-codebase (+3 EE-RT.14 v2 fold-sites); `aws_string_case_normalization` at **17×** (+1 preemptive in plugin 1170 IpProtocol normalization); `conservative_classifier_principle` reinforced in 5 fold sites.
- **No new SDK deps required** — `@aws-sdk/client-ec2` + `@aws-sdk/client-kms` both already in EE `optionalDependencies` from the EE 0.4.0 cohort.

**CE-side state:** unchanged binary. CE 0.1.44 = CE 0.1.43 = CE 0.1.42 = CE 0.1.41 = CE 0.1.40 = CE 0.1.39 code-identical; bump exists solely to carry the EE-paired-release narrative to the npm landing page and to deprecate 0.1.43 with the explicit EE-paired-release pointer.

**Recommended upgrade path:** `npm install -g nsauditor-ai@0.1.44 @nsasoft/nsauditor-ai-ee@0.4.5` (paired upgrade).

---

## 0.1.43 — docs-only: paired-release announcement for EE 0.4.4 (second new EE plugin in the 0.4.x cycle — AWS SQS/SNS Auditor 1150 + 3 same-session reviewer folds)

No code changes. CE 0.1.43 ships the same code as 0.1.40 / 0.1.41 / 0.1.42 with README updated to announce the paired **EE 0.4.4 release** and add plugin **1150 AWS SQS/SNS Auditor** to the public plugin catalog.

**EE 0.4.4 paired-release highlights:**

- **EE plugin count: 16 → 17** — second plugin-count growth in the 0.4.x cycle (paired with the EE 0.4.3 addition of plugin 1140). New plugin **1150 AWS SQS/SNS Auditor** (EE-RT.15 v1) covers **5 SOC 2 substrate-evidence dimensions** spanning two AWS services in one plugin: SQS encryption at rest (C1.1; four-tier severity ladder matching plugin 1140's structure), SQS transit-encryption policy (CC6.6; `aws:SecureTransport=false` Deny statement), SNS encryption at rest (C1.1; SNS has no SQS-managed-SSE equivalent so absent = HIGH), SNS topic-policy permissive-Principal (CC6.6; wildcard-Principal with full NotAction-Allow + NotPrincipal-Allow + Resource-scope filtering per plugin 1070 + 1110 precedent), and SQS dead-letter queue presence (A1.2 + CC7.1, **dual-mapped** — missing DLQ is the canonical silent-message-loss class for event-driven architectures).
- **Three same-session reviewer folds applied** (R-HIGH-1 NotAction/NotPrincipal bypass class — closes the AWS-documented wildcard-equivalent classes that plugins 1070 + 1110 already handle; R-HIGH-2 Resource-scope filter — prevents false-positive emissions on statements scoped to other topics' ARNs; R-MEDIUM-1 per-resource AccessDenied evidenceGap — same false-CLEAN-class family as the EE-RT.14 v1 hotfix lineage, emits INFO + evidenceGap + walkthroughRequired finding rather than silent-omit on per-queue/topic AccessDenied).
- **First EE plugin to ship WITHOUT a smoke-time SDK hotfix** — `@aws-sdk/client-sqs` + `@aws-sdk/client-sns` were added to EE `optionalDependencies` PREEMPTIVELY per the 11th pre-implementation checklist item (EE-RT.14 v1 lesson institutionalized).
- **Coverage matrix UNCHANGED at 10/4/33** — institutional honesty per the matrix-shift discipline; EE-RT.15 v1 adds SQS/SNS substrate evidence under already-covered C1.1 + CC6.6 + A1.2 + CC7.1.
- **EE full regression: 4255/4255** (was 4160 at EE 0.4.3 publish; +95 tests: 78 EE-RT.15 v1 unit-test suite + 17 same-session reviewer-fold tests). 38-session 100% green streak preserved.
- **Real-AWS smoke-validated** against `<operator-internal-test-infra-repo>` paired fixtures (account `<operator-test-account>`, 4 resources: `sqs-encrypted-queue` + `sqs-cleartext-queue` + `sns-encrypted-topic` + `sns-cleartext-topic`): `findingCount: 0 → 10`; **C1.1 → FAIL (4)**, **CC6.6 → FAIL (4)**, **A1.2 → FAIL (2)**, **CC7.1 → FAIL (2)**. All 10 classifications match ground truth (AWS-managed `alias/aws/sqs` correctly = MEDIUM not PASS; SNS default policy wildcard-Principal-WITH-Condition correctly = HIGH not CRITICAL — institutionally-correct conservative-classifier-discipline emissions).
- **No pre-publish smoke gap** — unlike EE 0.4.3 (which discovered missing `@aws-sdk/client-rds` at smoke and required a hotfix), EE 0.4.4 cleared the smoke gate on first attempt thanks to the preemptive SDK declaration.

**CE-side state:** unchanged binary. CE 0.1.43 = CE 0.1.42 = CE 0.1.41 = CE 0.1.40 = CE 0.1.39 code-identical; bump exists solely to carry the EE-paired-release narrative to the npm landing page and to deprecate 0.1.42 with the explicit EE-paired-release pointer.

**Recommended upgrade path:** `npm install -g nsauditor-ai@0.1.43 @nsasoft/nsauditor-ai-ee@0.4.4` (paired upgrade).

---

## 0.1.42 — docs-only: paired-release announcement for EE 0.4.3 (first new EE plugin since the 0.4.0 cohort — AWS RDS Auditor 1140 + EE-RT.13 structural fix)

No code changes. CE 0.1.42 ships the same code as 0.1.40 / 0.1.41 with README updated to announce the paired **EE 0.4.3 release** and add plugin **1140 AWS RDS Auditor** to the public plugin catalog.

**EE 0.4.3 paired-release highlights:**

- **EE plugin count: 15 → 16** — first growth since EE 0.4.0 (which expanded 8→15 with the v0.4.0 Runtime Assurance cohort 1070–1130). New plugin **1140 AWS RDS Auditor** (EE-RT.14 v1) covers 3 SOC 2 substrate-evidence dimensions in v1: Multi-AZ deployment (A1.2 availability), storage encryption at rest with KMS-key custody classification (C1.1 confidentiality — four-tier severity ladder including conservative LOW+evidenceGap on `:key/UUID` ARN shapes per institutional `conservative_classifier_principle` memory), and parameter-group SSL enforcement (C1.1 transit-encryption — postgres `rds.force_ssl` + mysql `require_secure_transport`). v2+ defers 4 more dimensions (BackupRetentionPeriod / PubliclyAccessible / IAMDatabaseAuthentication / snapshot encryption) + `kms:DescribeKey` cross-reference.
- **EE-RT.13 structural fix for the EE-0.4.2-HOTFIX regression class** — PLUGIN_ID lifted to plugin-exported constants imported by `CLOUD_PLUGIN_SOURCE_MAP` via computed-key syntax. 16-file refactor (15 plugin files + engine). Module-load-time guarantee against the false-clean SOC 2 reporting regression that shipped in EE 0.3.9 / 0.4.0 / 0.4.1.
- **EE-RT.10.x.1 plugin 1110 effective-decrypt whitespace defense** — 8th sibling `aws_string_case_normalization` fold (memory tag at 15× recurrence; cumulative 8 plugins / 26 fold-sites).
- **Coverage matrix UNCHANGED at 10/4/33** — institutional honesty per the matrix-shift discipline; EE-RT.14 v1 adds RDS substrate evidence under A1.2 + C1.1 (both already covered).
- **EE full regression: 4160/4160** (was 4097 at EE 0.4.2 publish; +63 tests). 37-session 100% green streak preserved.
- **Real-AWS smoke-validated** against `<operator-internal-test-infra-repo>` paired fixtures (account `<operator-test-account>`): `findingCount: 0 → 6`; A1.2 → FAIL; C1.1 → FAIL.
- **Pre-publish smoke gap caught + hotfixed:** `@aws-sdk/client-rds` was missing from EE `optionalDependencies` (same false-CLEAN class as EE-0.3.3.5 missing `arm-storage`). Hotfixed in `package.json` before any customer impact — institutional defense of pre-publish smoke against silent SDK-load failure validated.

**CE-side state:** unchanged binary. CE 0.1.42 = CE 0.1.41 = CE 0.1.40 = CE 0.1.39 code-identical; bump exists solely to carry the EE-paired-release narrative to the npm landing page and to deprecate 0.1.41 with the explicit EE-paired-release pointer.

**Recommended upgrade path:** `npm install -g nsauditor-ai@0.1.42 @nsasoft/nsauditor-ai-ee@0.4.3` (paired upgrade).

---

## 0.1.41 — docs-only: paired-release announcement for EE 0.4.2 (CRITICAL HOTFIX + 31 recurrence-class surface closures across 7 plugins)

No code changes. CE 0.1.41 ships the same code as 0.1.40 with README updated to announce the paired **EE 0.4.2 publish**, which closed a CRITICAL silent false-clean SOC 2 reporting regression that affected EE 0.3.9 / 0.4.0 / 0.4.1 (cloud-finding harvester's `CLOUD_PLUGIN_SOURCE_MAP` had stale pre-0.3.9 plugin IDs → every plugin emission silently dropped at harvester boundary → `findingCount: 0` regardless of AWS state). EE 0.4.2 also shipped 31 recurrence-class surface closures across 7 plugins (8 `emit_literal_set_drift` in plugin 1130 + 23 `aws_string_case_normalization` fold-sites across plugins 1030/1060/1070/1080/1090/1120) + EE-RT.12.25 cross-plugin run()-level integration scaffold (6 of 15 EE plugins at parity).

---

## 0.1.40 — docs-only: paired-release announcement for EE 0.4.0 (cohort expansion 8 → 15 EE plugins)

No code changes. CE 0.1.40 ships the same code as 0.1.39 with README updated to announce the paired **EE 0.4.0 publish**. EE plugin count grew **8 → 15** with 7 new AWS auditor plugins: 1070 KMS Auditor (EE-RT.3) + 1080 Lambda Security Auditor (EE-RT.5) + 1090 Secrets Manager + SSM Parameter Store Auditor (EE-RT.8) + 1100 CodePipeline + CodeBuild Operational Integrity (EE-RT.9 + 9.1) + 1110 IAM Effective Decrypt-Path Auditor (EE-RT.10 + 10.1) + 1120 S3 Lifecycle + Cross-Region Replication Auditor (EE-RT.4 + 4.1) + the **headline thread** — 1130 AWS Backup Auditor (EE-RT.12 v1 → v1.24, ~7800 lines / 545 tests / 12-dimension air-gapped vault attestation arc). **`peerDependencies` floor bumped `^0.1.38` → `^0.1.40` at EE 0.4.0** — clean paired-release coordination floor.

---

## 0.1.39 — docs-only: paired-release announcement for EE 0.3.9 (PI1.5 matrix shift + plugin-ID range realignment + collision-shadow disclosure)

No code changes. CE 0.1.39 ships the same code as 0.1.38 with README updated to announce the paired **EE 0.3.9 release** + carry the **plugin-ID rename disclosure** to the CE npm landing page.

**EE-paired release highlights (institutional-grade transparency on the CE README so a customer landing on the CE npm page sees both the new EE plugins AND the prior-version collision-shadow disclosure):**

1. **MATRIX SHIFT 10/3/34 → 10/4/33** — EE 0.3.9 opens **PI1.5 (Stored items)** as partial coverage via the new `aws-dynamodb-auditor` plugin (1060). First SOC 2 Processing Integrity evidence stream in the EE v0.4.0 Runtime Assurance track.

2. **NEW EE plugin 1050** — `aws-apigateway-auditor`. First entry-point evidence plugin for Serverless-Framework deployments. CC6.1 + CC6.6 + CC6.7 + CC7.1 + A1.2 per-method/route audit (NONE-auth CRITICAL, TLS_1_0 HIGH, stage-level access logging / throttling / WAF).

3. **NEW EE plugin 1060** — `aws-dynamodb-auditor`. PI1.5 partial-coverage substrate evidence: PITR + deletion-protection + KMS-CMK + resource-policy + CloudTrail data-event cross-reference. Closes the auditor-canonical "audit-the-auditor" question on AWS DynamoDB audit-store / payroll-runs / financial-batch tables.

4. **EE plugin-ID range realignment to 1000+** — all 8 EE plugins moved from CE-overlapping IDs (020 / 021 / 022 / 023 / 030 / 040 / 050 / 060) to the disjoint 1000+ range (1020 / 1021 / 1022 / 1023 / 1030 / 1040 / 1050 / 1060). CE retains 001-099.

**🚨 INSTITUTIONAL DISCLOSURE — silent plugin-shadow class on EE 0.3.7 + 0.3.8:**

Pre-EE-0.3.9, CE plugin 040 (`TLS Cert Auditor`, priority 450) and EE plugin 040 (`AWS CloudTrail Operational Integrity`, priority 510) declared the same string `id: "040"`. The CE plugin manager's `findPlugin()` resolver at `plugin_manager.mjs:494` returns the **first match** by ID via `Array.find()`. Plugins are loaded via `discoverPlugins()` sorted ascending-by-priority, so the lower-priority CE plugin won the ID lookup. **Practical consequence**: customers running `nsauditor-ai scan --host aws --plugins 040 --compliance soc2` on EE 0.3.7 or 0.3.8 received **CE TLS Cert Auditor evidence (NOT EE CloudTrail evidence)** for that ID slot. `--plugins all` was unaffected (both plugins ran via the iteration path); the collision only manifested in ID-based selection.

**Same collision class would have affected EE plugin 050 (API Gateway, unpublished) and EE plugin 060 (DynamoDB, unpublished) — caught and fixed pre-publish.**

**Type-II auditors evaluating evidence from EE 0.3.7 / 0.3.8 scans**: treat any `--plugins 040` evidence as CE TLS Cert Auditor evidence (`_source: 'ce'`), not EE CloudTrail evidence (`_source: 'ee'`). Re-scan with EE 0.3.9 + `--plugins 1040` for the intended CC7.2 + CC7.3 substrate evidence.

**Migration for existing scripts pinning EE plugin IDs:**

```bash
# Old (EE 0.3.7 / 0.3.8 — partially broken due to 040 collision):
nsauditor-ai scan --host aws --plugins 020,030,040 --compliance soc2

# New (EE 0.3.9 — disjoint 1000+ namespace, all 8 EE plugins available):
nsauditor-ai scan --host aws --plugins 1020,1030,1040,1050,1060 --compliance soc2
```

`--plugins all` continues to work unchanged across all versions.

**CE 0.1.39 ↔ EE 0.3.9 pairing:** EE 0.3.9's `peerDependencies` floor is `^0.1.38`, so CE 0.1.38 OR 0.1.39 satisfy the floor. CE 0.1.39 is the recommended pairing because its README carries the collision-shadow disclosure on the npm landing page. Either CE version works functionally.

```bash
npm install -g nsauditor-ai@0.1.39 @nsasoft/nsauditor-ai-ee@0.3.9
```

If you're already on 0.1.38, this upgrade carries no functional difference. Upgrade for fresh-install README quality + the EE-paired-release disclosure.

---

## 0.1.38 — docs-only: README cleanup + CHANGELOG split

No code changes. The README on the npm package page used to lead with eight stacked "What's New" release-note blocks for 0.1.30 → 0.1.37 (plus an EE 0.3.3 paired note), which buried features and usage below ~220 lines of release narrative. 0.1.38 ships the same code as 0.1.37 with the README rewritten to be feature-and-usage focused on the first screen and the per-release history moved to this CHANGELOG. A new `docs/mcp-verification.md` page carries the previously-inline forensics on Claude Desktop response fabrication and the `nsauditor-ai mcp verify-call <id>` workflow.

If you're already on 0.1.37, this upgrade carries no functional difference. Upgrade only if you want the new README on a freshly-installed copy or you're a contributor looking at the source. The 0.1.37 security fix (MCP bin shim auth/license bypass) is the most recent functional change — see below.

```bash
npm install -g nsauditor-ai@0.1.38
```

---

## 0.1.37 — 🛑 SECURITY FIX: bin shim bypassed auth + license verification

**Affects all installations using Claude Desktop (or any MCP client invoking the published `nsauditor-ai-mcp` binary).** Pre-0.1.37, the bin shim at `bin/nsauditor-ai-mcp.mjs` directly called `createServer() + server.connect()` and never invoked the startup block in `mcp_server.mjs` that runs:

1. **`authorizeMcpServerStartup()`** — the `NSA_MCP_AUTH_KEY` enforcement we shipped in EE-SEC.1 (CE 0.1.31). Skipped means **any process with stdio access to the spawned MCP child could call the tools without supplying the auth key**.
2. **`await loadLicense()`** — JWT verification of the operator's license key. Skipped means `_tier` stuck at the module-load CE default, so paid Pro/Enterprise customers saw "Current tier: CE" responses and lost MCP access to gated tools entirely.
3. Rotation cadence warnings, keychain-locked diagnostics — all silent.

**Root cause**: an `argv[1].endsWith('mcp_server.mjs')` guard in `mcp_server.mjs` only matched when the server was invoked directly as `node mcp_server.mjs`. Claude Desktop spawns via the published bin (`nsauditor-ai-mcp`), so the guard was always false in production. The guard existed so that test imports of the module wouldn't auto-start the server — but the fix should have been to extract the startup into a function the bin shim explicitly calls.

**Detection**: in 0.1.36 you could spot this if you noticed your MCP responses said `Current tier: Community Edition (CE)` despite `nsauditor-ai mcp tier` from the shell saying `enterprise`. The disagreement was the 0.1.37 bug surfacing.

**Fix**:
- Extracted the entire startup sequence into `export async function startStdioServer()` in `mcp_server.mjs`.
- `bin/nsauditor-ai-mcp.mjs` now imports and awaits `startStdioServer()`. Every Claude Desktop spawn now runs the auth check and license verification it always should have.
- Regression test (`tests/mcp_bin_startup.test.mjs`) spawns the bin shim with no auth key in env and asserts the auth check refuses startup. If the bin shim ever regresses to bypassing startup again, this test fails.

**Action required**: upgrade immediately.

```bash
npm install -g nsauditor-ai@0.1.37
# Restart Claude Desktop. Verify with:
# - Real MCP call from Claude → response should say "Current tier: Enterprise" (or Pro)
# - nsauditor-ai mcp verify-call <uuid>  ← the 0.1.36 sentinel still works
```

**Threat model note**: a process needing stdio access to your Claude Desktop MCP child already had to be running as your user (or able to write to your `~/Library/Application Support/Claude/` config). The auth-bypass exposure is *defense-in-depth degradation*, not "anyone on the internet can call your scanner." But the tier-stuck-at-CE bug definitely cost paying customers actual functionality, and SOC 2 evidence generated from MCP-routed CE-tier responses would fail audit because it lacked enterprise-tier checks.

Thanks to the customer who caught this in the wild while we were chasing what looked like a Claude Desktop hallucination — turned out the bug was on our side.

---

## 0.1.36 — cryptographic per-call sentinel UUID (hallucination becomes mathematically detectable)

The version-block comparison shipped in 0.1.34/0.1.35 catches lazy hallucinations, but a sufficiently capable AI client can still copy a previously-seen version block from chat context and pass off a fabricated response. **0.1.36 closes that gap** with a per-call cryptographic sentinel that the AI cannot fake.

**How it works:**
- Each `tools/call` invocation mints a fresh server-side UUID via Node's `crypto.randomUUID()`.
- The UUID is appended to the response text under a `── Verified MCP call ──` footer.
- The same UUID is persisted to `~/.nsauditor/mcp-calls.log` (mode 0600, JSON-per-line) **before** the response is returned.
- A new CLI subcommand `nsauditor-ai mcp verify-call <uuid>` greps the log:
  - **Found** → the UUID was issued by your local MCP server, so the response bearing it is genuine.
  - **Not found** → the UUID was never issued, so the entire response was fabricated by the AI client.

**Customer verification workflow (10 seconds):**

```bash
# 1. In Claude Desktop, ask Claude to use any MCP tool (e.g., list_plugins).
# 2. The response ends with:
#       ── Verified MCP call ──
#       call_id: 3f8a1b22-7e44-4c91-9d62-12bd0a4f5e91
#       Verify: nsauditor-ai mcp verify-call 3f8a1b22-7e44-4c91-9d62-12bd0a4f5e91
# 3. Run that exact verify command in your terminal:
nsauditor-ai mcp verify-call 3f8a1b22-7e44-4c91-9d62-12bd0a4f5e91
# ✓ Verified MCP call → genuine
# ✗ call_id not found  → fabricated (response was AI-generated, not from the MCP server)
```

This makes the hallucination detection unfakeable in principle: the AI client has no access to your local Node `crypto.randomUUID()` output, and the sentinel is generated **at the moment the call hits the server** — there's no way to forge a UUID that will appear in a log file the client cannot read or write.

The 0.1.34/0.1.35 version-block check remains as the first line of defense (instant visual mismatch). The 0.1.36 UUID is the cryptographic ground truth for any response you'd act on.

`scan_host`, `probe_service`, `get_vulnerabilities`, and `list_plugins` all mint sentinels — even Pro-tier denials carry a UUID so customers can prove the call reached the server.

```bash
npm install -g nsauditor-ai@0.1.36
```

---

## 0.1.35 — CLI provenance footer matches MCP response (so the comparison actually works)

0.1.34 added the version-provenance block to the MCP server's `list_plugins` response, but **the CLI baseline (`license --plugins` / `license --status`) didn't show versions** — so customers couldn't easily compare. 0.1.35 fixes that asymmetry.

Both CLI commands now emit an identical provenance block:

```
── Installation provenance ──
  nsauditor-ai (CE):              0.1.35
  @nsasoft/nsauditor-ai-ee (EE):  0.3.4 (loaded)
```

**Customer hallucination-detection workflow (5 seconds, no log archeology):**

1. In Claude Desktop: ask "list plugins" → receive a response that should end with the provenance block
2. In your terminal: run `nsauditor-ai license --plugins`
3. Compare the two `── Installation provenance ──` blocks character-for-character
4. **Match** → real MCP `tools/call` happened, response is trustworthy
5. **Mismatch / missing block** → Claude fabricated the response (see 0.1.33 advisory)

This is the v1 mitigation; the v2 (0.1.36) adds per-call cryptographic sentinel UUIDs that the customer can grep against the server log directly. v1 catches the common case where Claude either omits the block entirely (unlikely to fabricate the new structure verbatim) or includes a stale version pulled from training data.

---

## 0.1.34 — list_plugins now embeds CE+EE versions for hallucination detection

Companion to the 0.1.33 advisory. The `list_plugins` MCP tool's response now appends the actual installed CE + EE version numbers, so customers can verify a Claude Desktop response in **5 seconds** without log archeology:

```
── Installation provenance (verify against your shell) ──
nsauditor-ai (CE):              0.1.34
@nsasoft/nsauditor-ai-ee (EE):  0.3.4 (loaded)
Verify: nsauditor-ai --version  &&  npm list -g @nsasoft/nsauditor-ai-ee
If versions in this response don't match your shell, the response was
AI-generated rather than retrieved from the MCP server (see CE 0.1.33 advisory).
```

How it works as a hallucination detector:
- The MCP server reads `process.execPath`'s package.json + tries to resolve `@nsasoft/nsauditor-ai-ee/package.json` at request time. Both are real machine-specific values.
- Claude Desktop fabricated responses in the wild have shown stale version numbers from training data, missing version lines entirely, or different counts each time the same question is asked (observed 32→32→31 plugin counts in three consecutive hallucinations on 2026-05-10).
- A real tool response will exactly match `nsauditor-ai --version` + `npm list -g @nsasoft/nsauditor-ai-ee`. Mismatch = hallucinated.

This is a v1 mitigation — 0.1.36 adds per-call cryptographic sentinel UUIDs that the customer can grep against the server log.

---

## 0.1.33 — ⚠ MCP integration with Claude Desktop is unreliable

**Critical advisory for customers using NSAuditor AI through Claude Desktop's MCP integration.** During the maintainer's own integration test on 2026-05-10, we discovered that **Claude Desktop's AI fabricates scan results, plugin lists, vulnerability findings, and tier information without actually invoking the MCP tools** for our specific server. Other MCP servers in the same Claude Desktop config receive real `tools/call` invocations; ours does not.

**Empirical evidence**:
- `~/Library/Logs/Claude/main.log` shows multiple permission grants for `mcp__nsauditor-ai__list_plugins` and `mcp__nsauditor-ai__scan_host` on 2026-05-10
- `~/Library/Logs/Claude/mcp-server-nsauditor-ai.log` shows **zero** `"method":"tools/call"` entries on the same day
- Other servers in the same config logged real calls (ns-ftp:29, wp-publisher-netsecmag:14, ai-pr-distribution:6, sendgrid:3)
- When asked to scan 1.1.1.1, Claude Desktop returned a detailed report with plugin breakdown + Zero Trust score — entirely fabricated

**Likely cause**: Claude Desktop's MCP client appears to time out our server (which loads PluginManager + 32 plugins + license verify before responding). Claude (the AI) silently substitutes fabricated responses from training rather than surfacing the timeout. The hallucinations are convincingly formatted and indistinguishable from real output without log inspection.

**Mandatory verification — for any output you'd act on**:

```bash
# Tier check (ground truth bypassing Claude AI synthesis):
nsauditor-ai mcp tier

# Real plugin scan (always hits the network):
nsauditor-ai scan --host <X> --plugins all --out <dir>

# Confirm Claude Desktop actually called the MCP server:
grep '"method":"tools/call"' ~/Library/Logs/Claude/mcp-server-nsauditor-ai.log | tail -5
# If main.log shows recent permission grants for nsauditor-ai tools but
# THIS file shows no matching tools/call entries, the responses you saw
# in Claude Desktop were AI-generated, NOT real.
```

**SOC 2 evidence and any compliance report MUST be generated via the CLI** — never via the Claude Desktop MCP integration — until this is resolved upstream. The 0.1.36 per-call cryptographic sentinel ships the structural mitigation: see [docs/mcp-verification.md](./docs/mcp-verification.md).

---

## 0.1.32 — Claude Desktop integration overhaul + ground-truth diagnostics

The 0.1.32 line bundles three operational improvements driven by real customer-onboarding friction surfaced during the developer's own Claude Desktop integration test (2026-05-10):

- **`nsauditor-ai mcp install-key` now auto-generates a machine-specific Claude Desktop config snippet.** Reads `process.execPath` (the Node binary actually running) and derives the script path from `import.meta.url` — the printed JSON has absolute paths that work whether you're on system Node, homebrew, nvm, fnm, local-project install, Linux, or Windows. No install-type detective work, no PATH-misalignment failures. On macOS, the snippet uses `keychain:` indirection for **both** auth and license — secrets never land in the world-readable Claude Desktop config file.
- **License `keychain:` indirection.** `loadLicense()` and `resolveLicenseKey()` honor the `keychain:LABEL` prefix on the env-supplied value (mirrors the EE-SEC.1 MCP-auth pattern). Operators can put `"NSAUDITOR_LICENSE_KEY": "keychain:NSAUDITOR_LICENSE_KEY"` in their Claude Desktop env block; the JWT stays in macOS Keychain. Backward-compat: literal JWTs continue to work unchanged.
- **`nsauditor-ai mcp tier` ground-truth subcommand.** Customer-side check that prints the EXACT tier the spawned MCP server resolves to. We discovered Claude Desktop reports of "Current tier: CE" despite verified Pro/Enterprise license were caused by Claude (the AI) **synthesizing the tier text from training data + context** instead of actually calling `list_plugins` via MCP. The MCP server's resolution was always correct. `mcp tier` bypasses Claude's interpretive layer — paste the output into a support ticket to distinguish "MCP genuinely broken" from "Claude misreading."
- **MCP key rotation cadence (Thread I).** Optional 90-day rotation soft warning at server startup + `mcp status` (override via `NSA_MCP_AUTH_KEY_ROTATION_DAYS`, clamped to [7, 365]). SOC 2 CC6.1/CC6.7 reviewers expect a credential-rotation cadence; an unrotated MCP auth key is treated the same way as an unrotated IAM access key.
- **Keychain-locked vs Keychain-empty distinction.** New `keychain-locked` source variant in `mcp status` for headless macOS / SSH-only CI runners — instead of falling through silently to "unconfigured", operators get an actionable error with three GUI-free workarounds.
- **Atomic file writes** for `~/.nsauditor/.env` (`.tmp` + POSIX-rename) so concurrent readers + crash recovery never observe a truncated file.
- **Auto-mirror license file→Keychain on `mcp install-key`** (macOS) when the license is configured in `~/.nsauditor/.env` but absent from Keychain. Lets the printed snippet's `keychain:` indirection actually resolve, with original storage location preserved unchanged.

**Breaking change for existing 0.1.31 operators**: nothing breaks, but the recommended Claude Desktop config snippet has changed. Re-run `nsauditor-ai mcp install-key` after upgrading to get the new auto-generated snippet with absolute paths + license indirection. Old configs continue to work.

```bash
npm install -g nsauditor-ai@0.1.32
nsauditor-ai mcp install-key   # prints the new snippet — paste into Claude Desktop config
nsauditor-ai mcp tier          # confirm the actual MCP server tier (ground truth)
```

---

## 0.1.31 — security release

**MCP server authentication is now required.** Pre-0.1.31, the local MCP server (stdio transport) accepted any incoming JSON-RPC frames — any process running as your user could spawn it and use the Pro/Enterprise tools (which include the AWS-talking shadow-admin path detectors that ship in `@nsasoft/nsauditor-ai-ee`). 0.1.31 closes this gap with a per-operator shared-secret check at startup.

**Breaking change for existing operators**: after upgrading, run `nsauditor-ai mcp install-key` once. Without this step, the MCP server refuses to start and Claude Desktop will report a connection failure. The error message points back at this command.

```bash
npm install -g nsauditor-ai@0.1.31
nsauditor-ai mcp install-key   # generates a 256-bit key, persists it, prints Claude Desktop config snippet
```

**What's in the box (EE-SEC.1):**

- `nsauditor-ai mcp install-key` — generates a 256-bit auth key, stores it in macOS Keychain (or `~/.nsauditor/.env` mode 0600 elsewhere), prints a paste-ready Claude Desktop config snippet. Run once per machine.
- `nsauditor-ai mcp status` / `print-key --confirm` / `rotate-key --confirm` — inspect, reveal (TTY-only by default), and rotate the key.
- **`keychain:` indirection on macOS** — the printed config snippet uses `"NSA_MCP_AUTH_KEY": "keychain:NSA_MCP_AUTH_KEY"` instead of the literal key. The MCP server resolves the placeholder at startup; **the secret never lands in your `claude_desktop_config.json`** (which is mode 0644 on macOS by default — readable by other local users and any sandboxed app). On Linux/Windows where there's no Keychain equivalent, the snippet falls back to the literal key with a `chmod 600` warning.
- **`NSA_MCP_AUTH_DISABLE=1`** escape hatch for CI / dev — emits a stderr warning every startup so you don't forget; a louder warning fires when DISABLE is set AND no key was ever installed.
- Multi-source resolver mirrors the existing license-key pattern: env → Keychain → file. Constant-time key comparison via `crypto.timingSafeEqual`. Full threat model documented in [`utils/mcp_auth.mjs`](./utils/mcp_auth.mjs).

---

## Enterprise Edition 0.3.3 (paired note)

The Enterprise Edition (`@nsasoft/nsauditor-ai-ee`) shipped a 0.3.3 point release on 2026-05-08. CE stays at 0.1.30 — no CE bump required, the EE upgrade is single-line: `npm install -g @nsasoft/nsauditor-ai-ee@latest`. The release closes a Critical false-clean SOC 2 reporting bug that mirrored the AWS-side bug fixed in 0.3.2 — this time in the Azure cloud scanner — and extends mapped SOC 2 coverage to multi-cloud:

- **Azure plugin (022) finding-shape rewrite** — the EE-0.3.2.1 cloud-finding harvester only recognized one canonical shape (`{resource, severity, issues[]}`); plugin 022 was emitting `{severity, finding, resource}` (singular `finding`). Findings reached the engine but were silently dropped — Azure customers running `--compliance soc2` saw "6/6 covered controls passing" against subscriptions with real RBAC + NSG + Storage issues. Caught at internal dogfood against a live Azure subscription.
- **GCP plugin (021) preventive shape port** — plugin 021 had the same `{finding}` singular shape; pre-emptively migrated to the canonical shape so the same bug doesn't re-emerge for GCP customers in v0.4.0 when GCP `mapsToFindings` rules ship.
- **Azure → SOC 2 mapping rules added** — RBAC `Owner | Contributor | User Access Administrator at subscription scope` → CC6.1 (3 patterns); NSG `0.0.0.0/0 → port` anchored regex → CC6.6; Storage `allowBlobPublicAccess` + `enableHttpsTrafficOnly` → C1.1. CC6.1, CC6.6, and C1.1 now have *both* AWS-side and Azure-side evidence rows — actual multi-cloud SOC 2 evidence.
- **Drift detector extended to all three cloud plugins** — every `azure-cloud-scanner` `titlePattern` in `soc2.json` is now asserted to match at least one canonical issue string the plugin emits, and vice versa. The class-of-bug that produced two false-clean variants in successive releases is now structurally closed.
- **Pre-publish gate fixes** — `@azure/arm-authorization` peer-dep was pinned at `^10.0.0` (latest published is 9.0.0; clean installs would have failed); `@azure/arm-storage` was missing from `optionalDependencies` (Storage audit silently no-op'd on clean install). Both caught at the pre-publish clean-tarball smoke and corrected before ship.

See the [EE package on npm](https://www.npmjs.com/package/@nsasoft/nsauditor-ai-ee) for the full EE changelog.

---

## 0.1.30

Paired release with `@nsasoft/nsauditor-ai-ee@0.3.2` that closes the customer-onboarding gap and a critical false-clean SOC 2 reporting bug:

- **`nsauditor-ai license install <KEY>`** — verifies the JWT *before* persisting; writes to macOS Keychain or `~/.nsauditor/.env` (mode 0600) depending on platform. Three-line install flow: `npm install -g` → `license install` → `license --status`. No more shell-rc edits.
- **Multi-source license loader** — `loadLicense()` resolves keys from env var → platform Keychain → `~/.nsauditor/.env`, in that order. CI/CD env-var override still wins.
- **`nsauditor-ai license --plugins`** — real enumeration of discovered plugins, grouped by source (CE / EE / custom), with active-or-required-tier status.
- **`nsauditor-ai --version` / `-v`** — prints version and exits 0 (parallel to `--help`'s discovery-flag UX).
- **Cloud-sentinel SSRF bypass** — `--host aws|gcp|azure` no longer requires `NSA_ALLOW_ALL_HOSTS=1`. The sentinel literals route to EE cloud-scanner plugins via the provider's API; the SSRF guard's RFC 1918 / loopback protection is preserved for real network targets.
- **EE-0.3.2.1 hard dep** — CE forwards the per-plugin `results` array to `enrichScan()`. Without this, EE 0.3.2's cloud-finding harvester sees nothing and produces false-clean SOC 2 reports against AWS accounts. EE emits a runtime version-skew warning when this opt is missing.
