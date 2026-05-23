# Changelog

Release notes for **`nsauditor-ai`** (Community Edition). The main [README](./README.md) focuses on features and usage — this file is the per-release history, kept for upgrade triage and audit reference.

For Enterprise Edition release notes, see [`@nsasoft/nsauditor-ai-ee`](https://www.npmjs.com/package/@nsasoft/nsauditor-ai-ee).

---

## 0.1.71 (STAGED 2026-05-22 — pending trio-publish) — Paired with EE 0.10.0 NIST CSF 2.0 Track 3 third-framework cycle

No CE code changes — paired-publish for trio-publish discipline + customer discoverability. CE's `--compliance` flag already accepts CSV (wired since EE 0.3.0); the engine is framework-agnostic per the EE 0.9.0 + EE 0.10.0 cycle pattern. Engine paths are EE-side; CE binary surfaces the framework via `--compliance nist-csf` (or `--compliance soc2,hipaa,nist-csf` for the full 3-framework pack from a single scan).

**Paired EE 0.10.0 highlights** (full detail in EE CHANGELOG):
- NEW `data/compliance/nist-csf.json` (auditor-canonical Subcategory-level mapping; 23 declared + 6 OOS groups; 13/10/83 matrix across 106 of CSF 2.0's 107 Subcategories)
- EXTENDED EE `utils/soc2_renderer.mjs` (`'nist-csf'` slot table in `frameworkControlCitation` with 8 slots incl. NEW `implementation-tiers` disclaimer; `isNistCsfReport` flag; Tiers OOS disclaimer section in BOTH markdown AND HTML render paths — R-HIGH-2 reviewer fold from 2nd reviewer pass)
- Schema-additive fields propagation to controlEntries (R-HIGH-1 reviewer fold from 2nd reviewer pass) — closes the ghost-schema gap for `function` / `categoryCode` / `subcategory` / `outcomeText` / `informativeReferences` (NIST CSF) AND `requiredOrAddressable` / `standardOrSpec` / `ruleText` (HIPAA, EE 0.9.0) AND `manualProcedure` (SOC 2 + HIPAA, EE 0.9.3 + 0.9.4) — all pre-fold were declared in framework JSON + validated by tests but never reached auditor-facing output
- 91 net new tests across 3 new test files (anchor-drift + mapping + renderer)
- 560-line `docs/nist-csf-coverage.md`
- 2 reviewer passes (single-agent A with combined NIST/code lens + parallel-reviewer B with security/air-gap/citation-leak lens); 5 same-session folds total
- EE regression 6104/6104 across 983 suites; 75-session 100% green streak preserved

**Plugin count UNCHANGED at 24**; **SOC 2 + HIPAA coverage matrices UNCHANGED**; **NIST CSF 2.0 coverage matrix introduced at 13/10/83**. **Govern function OOS-by-design with GV.SC-04 partial as substrate-evidence exception; Respond function OOS-entirely; Implementation Tiers OOS as organizational-maturity claim.** **Twenty-eighth consecutive trio-publish** institutionalized 0.4.5–0.10.0.

No breaking changes — additive only.

---

## 0.1.70 (PUBLISHED 2026-05-22 to npm as `latest`, superseded by 0.1.71 on trio-publish) — **License verifier air-gap operational hardening + paired with EE 0.9.1 external-audit-findings ship-blocker patch**

Three new defenses against the realistic license-abuse paths the external adversarial-audit-skill cycle (2026-05-22) called out as D-HIGH-1, D-HIGH-2, D-HIGH-3. The JWT verifier itself remains cryptographically tight (algorithm-pinned ES256 + iss/aud/sub pinned + clock-tolerance bounded); the new defenses close the operational gaps that don't require JWT forgery.

### D-HIGH-1 — Per-host licenseId replay defense

A `seats:1` Pro license can no longer be installed on 10,000 machines. First successful activation persists the `licenseId` to platform-appropriate storage; subsequent loads with a different licenseId fail-closed to CE with `reason: 'license_id_mismatch'`. Closes the seat-cloning class.

Storage routing per `_getLicenseStateFilePath`:
- macOS: file at `~/.nsauditor/license-state.json` (mode 0600); licenseId additionally written to Keychain via service=`nsauditor-ai` account=`NSAUDITOR_LICENSE_ID`. Keychain wins on read.
- Linux: file at `$XDG_STATE_HOME/nsauditor/license-state.json` (falls back to `~/.nsauditor/license-state.json`); mode 0600.
- Windows: file at `%LOCALAPPDATA%\nsauditor\license-state.json`; profile ACL inherited.

Atomic write semantics via `.tmp` + rename; survives partial-crash without leaving an in-flight half-written state file.

### D-HIGH-2 — Signed revocation blocklist baked into the package

New `data/license-revocations.json` shipped in the npm tarball. Vendors can revoke individual licenses via CE patch bump without rotating `PUBLIC_KEY_PEM` (which would invalidate ALL licenses). Verification chain:
- File contains `{ schema_version, issued_at, revoked: [licenseId, ...], signature }`.
- License-manager service signs the canonical JSON (revoked array sorted alphabetically; signature field excluded from signing input) with the same ES256 private key as JWTs.
- Verifier loads `PUBLIC_KEY_PEM`, asserts `asymmetricKeyType === 'ec'` AND `namedCurve === 'prime256v1'` (algorithm-pinning fold per reviewer pass — future RSA-key rotation cannot silently enable RS256 forgery), then verifies via `createVerify('SHA256') + dsaEncoding: 'der'`.
- Fail-open posture on invalid signature / malformed JSON / missing file (returns `[]`, no revocation enforced) — by design; tampering of `node_modules/` already implies full privilege; fail-closed would brick legitimate customers via a single bad patch.

Initial 0.9.1 ship: empty-list envelope; license-manager service signs subsequent updates.

### D-HIGH-3 — Monotonic-clock anchor against faketime/clock-rollback

Persisted `lastSeenUnixTs` checked on each load; wall-clock rewind beyond `CLOCK_ROLLBACK_TOLERANCE_S` (default 300s — covers NTP step + DST + suspend/resume) fails-closed with `reason: 'clock_rollback_detected'`. Defeats `faketime`-style attacks against the JWT `exp` claim in air-gap deployments where NTP cannot be consulted at verification time.

Configurable via `NSAUDITOR_LICENSE_CLOCK_TOLERANCE_S` env (capped at 24h per reviewer fold — anything beyond a day is a backdoor disable, not a "clock skew", and should go through the explicit `NSAUDITOR_LICENSE_CLOCK_ANCHOR=0` env var).

### Support-only escape hatches

Three env vars disable individual defenses for documented edge cases (hardware migration without vendor support, emergency clock rollback for a stuck system, etc.). All accept case-insensitive `0` / `false` / `no` / `off` / `disabled`:
- `NSAUDITOR_LICENSE_ID_REPLAY_DEFENSE`
- `NSAUDITOR_LICENSE_REVOCATION_CHECK`
- `NSAUDITOR_LICENSE_CLOCK_ANCHOR`

Persistent audit-trail of disable events is deferred to CE 0.1.71 — operators concerned about defense hygiene should grep their env at deployment time.

### New test file: `tests/license_air_gap_hardening.test.mjs`

+33 tests across 7 describe blocks covering: state-file round-trip + path resolution + mode 0600 + atomic-write semantics; replay defense end-to-end (first activation persists, mismatch rejection, seat-clone scenario, escape hatch); signed-blocklist verification (valid + invalid signature + wrong-key + missing-file + malformed-JSON + unsupported-schema + end-to-end loadLicense rejection + escape hatch); monotonic-clock-anchor scenarios (forward / small-rewind tolerance / large-rewind rejection / `faketime` attack / configurable tolerance / escape hatch); cross-defense interaction ordering (revocation → replay → clock); canonicalization stability under array reordering.

### Regression

**CE regression: 968 tests across 32 suites; 967 pass** (was 935/934). The 1 pre-existing failure (`returns CE tier when no key`) is an operator-machine quirk where the local Keychain contains a real license that satisfies the resolver chain — not a regression introduced by 0.1.70. Existing `tests/license.test.mjs` redirects state file + disables new defenses in its `before()` hook so the JWT-verification path tests remain isolated from the air-gap hardening.

### Paired with EE 0.9.1

EE 0.9.1 ship-blockers A-CRIT-1 (NVD offline feed importer), B-CRIT-1/2 (plugin 1110 KMS layer cross-reference), and C-CRIT-1..4 (plugin 1030 PRIVESC_ACTIONS additions) — see EE [CHANGELOG.md](https://github.com/nsasoft/nsauditor-ai-ee/blob/main/CHANGELOG.md) for full detail. **Twenty-seventh consecutive trio-publish** institutionalized 0.4.5–0.9.1.

---

## 0.1.69 — docs-only: paired-release announcement for EE 0.9.0 HIPAA FRAMEWORK CYCLE (first 0.9.x release; HIPAA Security Rule §164.312 Technical Safeguards ships as second supported compliance framework alongside SOC 2; HIPAA coverage matrix 7 covered + 3 partial + 45 OOS; HHS Required/Addressable discipline per control; §164.312(c)(1) ransomware-defense substrate via Logically Air-Gapped Backup Vault cross-verification; per-framework SLA-citation map; 6 same-session reviewer folds; +85 new tests across 3 new suites; plugin count UNCHANGED at 24; SOC 2 coverage matrix UNCHANGED at 10/4/33; EE regression 5890/5890 across 928 suites; 69-session 100% green streak preserved; twenty-sixth consecutive trio-publish; no breaking changes — additive only)

No code changes. CE 0.1.69 ships the same code as 0.1.40–0.1.68 with README + CHANGELOG updated for the paired EE 0.9.0 release.

**EE 0.9.0 paired-release highlights:**

- **MINOR VERSION MILESTONE — HIPAA framework cycle**: HIPAA Security Rule §164.312 Technical Safeguards ships as the second supported compliance framework alongside SOC 2. Closes the long-standing "planned" gap in EE's `docs/architecture.md` for the highest-demand next framework after SOC 2. New `data/compliance/hipaa.json` (175 mappings inherited from soc2.json's grep-verified pattern set with HIPAA-grounded rationales). New `docs/hipaa-coverage.md` (~440 lines) — auditor-grade coverage doc mirroring `docs/soc2-coverage.md` shape.

- **HIPAA coverage matrix**: 7 covered + 3 partial + 45 OOS within §164.312 + entire §164.308 Administrative Safeguards (31 specs) + entire §164.310 Physical Safeguards (12 specs). The §164.308 + §164.310 OOS sets are *architecturally* OOS for any infrastructure scanner (governance/training/BAAs/facility-access/device-disposal evidence streams require HR systems + GRC platforms + facilities-management vendors). Pair with HIPAA-focused GRC platforms (Drata HIPAA, Vanta HIPAA, Compliancy Group, Tugboat Logic) for §164.308 + §164.310 coverage.

- **HHS Required vs Addressable discipline**: schema-additive `requiredOrAddressable: 'R'|'A'` + `standardOrSpec: 'standard'|'implementation-specification'` + `ruleText: <HHS rule text>` fields per control in `data/compliance/hipaa.json`. Misrepresenting Addressable as Required (or vice versa) is overclaiming — auditors specifically test for this. NSAuditor surfaces the classification per control in the rendered HIPAA report.

- **§164.312(c)(1) Integrity ransomware-defense substrate**: EE's `aws-backup-auditor` Logically Air-Gapped Backup Vault cross-verification (KMS policy + Grants + replicas + VPC-endpoint composite attestation) produces the strongest substrate evidence available on the AWS layer — HHS-OCR has highlighted ransomware-resilient ePHI backups in 2024 enforcement actions. A composite-attestation PASS evidences that ePHI backups would survive a full source-account compromise.

- **Per-framework SLA-citation map** in EE's `utils/soc2_renderer.mjs`: new `frameworkControlCitation(framework, slot)` helper threaded through markdown + HTML renderers. HIPAA reports cite `§164.312(b) audit-controls cadence` (SLA), `§164.308 administrative-safeguards governance — OOS for §164.312 Technical-Safeguards report` (governance sentinel), `§164.312(d) Person or Entity Authentication` (identity). SOC 2 reports remain byte-identical (single-line cosmetic golden-fixture update). Closes the auditor-detectable cross-framework citation leak class.

- **Zero engine / CLI changes required**: EE's `loadFrameworkMap` already framework-agnostic (reads `data/compliance/{framework}.json` by parameter); CE's `--compliance` flag already accepts CSV (wired since EE 0.3.0). Multi-framework workflow shipping today: `nsauditor-ai scan --host aws --plugins all --compliance soc2,hipaa --out evidence/` produces separate `scan_compliance_soc2.{md,html,json}` AND `scan_compliance_hipaa.{md,html,json}` artifact sets in one scan.

- **Zero BAA required** — Zero Data Exfiltration architecture means ePHI never leaves customer infrastructure. Nsasoft does not see, store, or process customer ePHI under any condition; no Business Associate Agreement needed under HIPAA §160.103.

- **6 same-session reviewer folds** (2 R-HIGH defensive-coding + 2 R-MEDIUM scope-broadening + 1 R-LOW comment fix + 1 docstring strengthening; 0 R-CRITICAL — clean cycle). Two parallel reviewers: HIPAA Security Officer perspective + senior code reviewer perspective. Confirmed: §164.312 sub-criteria routing clean, HHS R/A classification correct, §164.308 + §164.310 OOS enumerations complete against 45 CFR.

- **+85 new tests across 3 new suites**: `tests/hipaa_mapping_anchor_drift.test.mjs` (32) — load-bearing anchor-drift defense via inheritance contract from soc2.json; `tests/hipaa_mapping.test.mjs` (36) — engine-end-to-end fixture tests across all 7 covered + 3 partial §164.312 controls + sub-criteria discrimination (CloudTrail does NOT fire (a)(1); TLS does NOT fire (a)(2)(iv); encryption-at-rest does NOT fire (e)(1)); `tests/hipaa_renderer.test.mjs` (17) — per-framework citation correctness + SOC 2 regression-protection.

- **EE regression: 5890/5890 across 928 suites; 69-session 100% green streak preserved.**

- **AWS-dogfood verified — 2026-05-21 smoke scan** against operator's test AWS account produced 207 findings analyzed, all routed to correct §164.312 sub-criteria; per-framework citation map confirmed firing in production reports; ransomware-defense substrate §164.312(c)(1) surfaces correctly. Zero regression on SOC 2 path (same 207 findings → 9 FAIL + 4 PASS + 1 partial + 33 OOS matching 10/4/33 exactly).

- **No breaking changes** — additive only. The 0.8.0 customer migration carryover (suppressions targeting `match.source: 'azure-cloud-scanner'` silently no-op post-0.8.0) remains as-is. **HIPAA framework cycle is opt-in via `--compliance hipaa` or `--compliance soc2,hipaa`**.

- **Plugin count UNCHANGED at 24**. **SOC 2 coverage matrix UNCHANGED at 10/4/33** (additive-only cycle; no SOC 2 mappings changed). **HIPAA coverage matrix introduced at 7/3/45**.

---

## 0.1.68 — docs-only: paired-release announcement for EE 0.8.0 MINOR VERSION MILESTONE (EE-RT.23 Move B plugin 1022 per-dim source-attribution refactor + Engine `details.category` projection contract + Key Vault soc2.json gap closure +13 mappings; 7 same-session reviewer folds; +23 new tests / +6 new suites; plugin count UNCHANGED at 24; coverage matrix UNCHANGED at 10/4/33; EE regression 5805/5805 across 907 suites; 68-session 100% green streak preserved; twenty-fifth consecutive trio-publish; ⚠️ customer migration: `match.source: 'azure-cloud-scanner'` suppressions silently no-op post-0.8.0)

No code changes. CE 0.1.68 ships the same code as 0.1.40–0.1.67 with README + CHANGELOG updated for the paired EE 0.8.0 release.

**EE 0.8.0 paired-release highlights:**

- **MINOR VERSION MILESTONE — EE-RT.23 Move B**: plugin 1022 Azure scanner refactored to per-dim source attribution. Each of the 4 helpers (`auditNsgRules` / `auditRbac` / `auditStorageAccounts` / `auditKeyVaults`) attaches its own `source` to every finding emission: `azure-nsg-auditor` / `azure-rbac-auditor` / `azure-storage-auditor` / `azure-keyvault-auditor`. PLUGIN_ID stays `"1022"`; `--plugins 1022` continues to work (backward-compat). The umbrella `azure-cloud-scanner` source stays in `CLOUD_PLUGIN_SOURCE_MAP` as defense-in-depth fallback only (no soc2.json mappings; defends against a future maintainer adding a 5th helper without attaching source). Closes the long-standing blocker (originally flagged in EE 0.6.9 R1-MEDIUM-1) for routing Azure storage findings into Appendix A "Cloud Bucket Exposure Attestation" without commingling NSG / RBAC / Key Vault.

- **Engine `details.category` projection contract** — `normalizeFindings` + `analyseAgainstFramework` violation surface now carry `category` (additive, backward-compat via raw escape hatch). Generally-useful for dim-discriminator use cases across plugin 1024 GCS / plugin 1025 GCP IAM / future plugins. **Engine projection contract change is the institutional rationale for the 0.7.x → 0.8.0 MINOR bump.**

- **Key Vault soc2.json gap closure — 13 new mappings** (3 CC6.1 + 3 CC6.3 + 3 C1.1 + 4 A1.2). Pre-0.8.0 Key Vault dim emitted 10 distinct `details.category` values but had ZERO soc2.json routing — latent silent false-clean class on CC6.1 / CC6.3 / C1.1 / A1.2 substrate evidence.

- **Appendix A multi-cloud expansion** — `_CLOUD_BUCKET_AUDIT_SOURCES` extended from 2 (AWS S3 + GCS) to 3 (+ `azure-storage-auditor`); NSG / RBAC / Key Vault remain intentionally OUT of the Set (not bucket-equivalent). F2 reviewer fold: `computeBucketStats` dedup key now provider-qualified `${source}::${resource}` (closes cross-cloud bucket-name collision for multi-cloud customers using shared naming conventions; common for DR replication).

- **7 same-session reviewer folds** (2 R-HIGH + 3 R-MEDIUM + 2 R-LOW; 0 R-CRITICAL — clean cycle on the institutional-CRITICAL anchor-drift class surface). F1 R-HIGH: anchor-drift defense test now loads patterns from shipped soc2.json directly (single source of truth — closes EE-RT.20-class recurrence INSIDE the defense test).

- **+23 new tests / +6 new suites** across EE's `tests/azure_cloud_scanner.test.mjs` + `tests/compliance_engine.test.mjs` + `tests/soc2_renderer.test.mjs`. Includes KV category-name stability pin (LOAD-BEARING — category is now the routing key for soc2.json so a typo-fix would break routing silently).

- **EE regression: 5805/5805 across 907 suites; 68-session 100% green streak preserved.**

- **⚠️ Customer migration required**: any suppression file with `match.source: 'azure-cloud-scanner'` will silently no-op post-0.8.0 (umbrella source is now defense-in-depth fallback only). Split into per-dim entries:
  - `RBAC: Owner role assigned` → `match.source: 'azure-rbac-auditor'`
  - `NSG rule "..." allows inbound` → `match.source: 'azure-nsg-auditor'`
  - `Storage account ...` → `match.source: 'azure-storage-auditor'`
  - `Key Vault '...' ...` → `match.source: 'azure-keyvault-auditor'`

- **Plugin count UNCHANGED at 24**. **Coverage matrix UNCHANGED at 10/4/33** (pure substrate-evidence depth uplift on already-covered controls — but Key Vault dim now has 13 mappings where it had ZERO).

---

## 0.1.67 — docs-only: paired-release announcement for EE 0.7.3 R-CRITICAL hotfix (closes 2 production bugs surfaced by EE 0.7.2 dogfood scan: cross-version google-auth-library fragmentation broke SA impersonation chains [R-CRITICAL — 100% false-clean impact on free-trial/gmail GCP customers + business GCP customers with no-long-lived-SA-keys policy]; GOOGLE_CLOUD_PROJECT_ID env-var alias silently skipped [R-MEDIUM]; +14 new tests across 2 new suites including a regression pin replicating the gax 5.x grpc adapter idiom; plugin count UNCHANGED at 24; coverage matrix UNCHANGED at 10/4/33; EE regression 5782/5782 across 900 suites; 67-session 100% green streak preserved; twenty-fourth consecutive trio-publish)

No code changes. CE 0.1.67 ships the same code as 0.1.40–0.1.66 with README + CHANGELOG updated for the paired EE 0.7.3 release.

**EE 0.7.3 paired-release highlights:**

- **R-CRITICAL fix — Headers-shape shim for cross-version `google-auth-library` fragmentation.** EE's `utils/gcp_auth.mjs` resolves `google-auth-library@9.15.1` (hoisted via `googleapis@^144`) → 9.x's `Impersonated.getRequestHeaders()` returns plain object. But `@google-cloud/resource-manager@^6` bundles nested `google-auth-library@10.6.2` + `google-gax@5.x` → gax 5.x's grpc adapter calls `headers.forEach((value, key) => ...)` expecting WHATWG Headers instance. Cross-version fragmentation → TypeError → `2 UNKNOWN: Getting metadata from plugin failed with error: headers.forEach is not a function` on the FIRST IAM call. Plugin 1025's conservative classifier correctly emitted `gcp-iam-project-unreadable` LOW + walkthroughRequired — but underneath the impersonation chain was completely broken, so ALL 7 dims silently skipped. **Production false-clean impact**: ~100% on any impersonation-using deployment in EE v0.7.0–0.7.2. NEW `_wrapAuthClientHeadersShim` monkey-patches the Impersonated instance's `getRequestHeaders` to coerce 9.x's plain-object return into a Headers instance; 10.x pass-through; version-agnostic + future-proof. +8 new tests including a regression pin that exactly replicates the gax 5.x grpc adapter idiom.

- **Customer-segment impact:**
  - **GCP free-trial / gmail customers** — impersonation is the ONLY working credential model when `iam.disableServiceAccountKeyCreation` is enforced (Google's "Secure by default"). Pre-0.7.3 100% false-clean. **Post-0.7.3 audit works end-to-end.**
  - **Business GCP customers with no-long-lived-SA-keys security policy** — same impact. Many enterprise security teams mandate impersonation as their auth model. **Post-0.7.3 audit works.**
  - **Business GCP customers using JSON keyfiles or pure ADC** — unaffected (R-CRITICAL specific to impersonation injection).

- **R-MEDIUM fix — Accept `GOOGLE_CLOUD_PROJECT_ID` as a third env-var alias.** Operators following the `gcloud auth application-default login` setup convention (which writes `GOOGLE_CLOUD_PROJECT_ID`, with `_ID` suffix) saw silent skip with `[plugin 1025] No GCP_PROJECT_ID configured`. Extended `loadConfig` + `preflight` from 2-way OR to 3-way OR: `opts.projectId > GCP_PROJECT_ID > GOOGLE_CLOUD_PROJECT > GOOGLE_CLOUD_PROJECT_ID`. +6 new tests covering all precedence paths.

- **Dogfood validation (post-fix)** — Re-ran `nsauditor-ai scan --plugins 1025 --compliance soc2` against operator's GCP test project with `GOOGLE_IMPERSONATE_SERVICE_ACCOUNT` set + ONLY `GOOGLE_CLOUD_PROJECT_ID` (no `GCP_PROJECT_ID` aliasing). **8 findings emitted** (was 1 false-clean LOW pre-fix): 5 PASS + 2 MEDIUM + 1 LOW. All 7 dims exercise via the impersonated `nsauditor-readonly` audit SA. `accessDeniedByApi.listPolicies: 1` confirms the 0.7.2 R2-MED-13 counter wiring works end-to-end against real GCP.

- **Pure bug-fix patch** — no plugin emissions changed; no soc2.json changes; no new SDK deps; no new plugins. Demonstrates the institutional value of post-publish dogfood scans against real cloud infra: two production bugs caught within 30 minutes of trio publish, both fixed + tested + re-validated in the same session.

- **Plugin count UNCHANGED at 24**. **Coverage matrix UNCHANGED at 10/4/33**. **EE regression: 5782/5782 across 900 suites; 67-session 100% green streak preserved.**

---

## 0.1.66 — docs-only: paired-release announcement for EE 0.7.2 Move B pure-test functional patch (closes 5 deferred 0.7.1 reviewer-pass coverage gaps: R2-MED-7 BFS edge cases (+17), R2-MED-13 counter wiring (+15 parameterized across 5 v2 apiName strings × 3 counter classes), R2-LOW-16/17 helper edges (+10), R2-HIGH-4 SDK loader graceful-degradation contract (+8), R2-MED-12 real-SDK fallback (+3 via generated PKCS#8 keypair); +50 new tests across 6 new suites; no production code changes; no plugin emissions changed; no soc2.json changes; no new SDK deps; plugin count UNCHANGED at 24; coverage matrix UNCHANGED at 10/4/33; EE regression 5768/5768 across 898 suites; 66-session 100% green streak preserved; twenty-third consecutive trio-publish)

No code changes. CE 0.1.66 ships the same code as 0.1.40 → 0.1.65 with README/CHANGELOG updated for the paired EE 0.7.2 release.

**EE 0.7.2 paired-release highlights:**

- **Move B pure-test functional patch** — closes the 5 test-coverage gaps marked low-priority at 0.7.1's reviewer pass. **R2-MED-7** BFS edge cases (+17 tests in `tests/gcp_iam_project_auditor.test.mjs`): disjoint cycles, disconnected subgraphs, terminate-at-first-admin (multi-admin chain), parallel branches to distinct admins, depthCap exact-match + one-short boundaries, depthCap=1 minimum, per-PATH visited Set semantics, malformed edges (null / missing-to / non-string-to), nonexistent edge targets, cycle through admin, self-loop on start, edge label fallback chain (label → displayName → key), fractional depthCap, parallel edges to same admin. **R2-MED-13** counter wiring (+15 parameterized): 5 v2 apiName strings (`projects.roles.list`, `projects.serviceAccounts.list`, `projects.serviceAccounts.keys.list`, `projects.serviceAccounts.getIamPolicy`, `listPolicies`) × 3 counter classes (throttle-retry, access-denied, wall-budget-exhausted). **R2-LOW-16/17** helper edges (+10): `_saEmailFromName` slash boundaries + control-char-before-slash; `_parseIso8601ToMs` UTC-vs-offset discriminator. **R2-HIGH-4** SDK loader graceful-degradation contract (+8): direct unit tests for `_loadGoogleApisIamAdminSdk` + `_loadOrgPolicySdk` missing-dep error branches. **R2-MED-12** `buildGcpAuthOptions` real-SDK fallback (+3 in `tests/gcp_auth.test.mjs`): generated PKCS#8 keypair + tmpdir SA keyfile exercises `_loadGoogleAuthLibrarySdk` end-to-end.

- **No production code changes** — pure-test functional patch. No plugin emissions changed; no soc2.json changes; no new SDK deps. Demonstrates the institutional discipline of separating test-coverage backfill from feature work.

- **Bundled staged peerDep bump** — `peerDependencies.nsauditor-ai` ^0.1.40 → ^0.1.65 (queued at 0.7.1 post-publish per `[[npm_tarball_replacement_trap]]` discipline to avoid a docs-only patch right after a fresh functional release). Pre-0.7.2 EE installs against deprecated CE versions emit `npm WARN deprecated` but install + work; post-0.7.2 installs cleanly against CE 0.1.66 only.

- **Plugin count UNCHANGED at 24**. **Coverage matrix UNCHANGED at 10/4/33** (pure-test patch — no plugin emissions changed). **EE regression: 5768/5768 across 898 suites; 66-session 100% green streak preserved.**

---

## 0.1.65 — docs-only: paired-release announcement for EE 0.7.1 EE-RT.22 v2 plugin 1025 R2 expansion (extends GCP IAM Project-Level Auditor from 3 dims to 7 dims; +4 new dims: custom-role permission audit + SA key custody + SA impersonation graph BFS + Organization Policy constraint enumeration; NEW `utils/gcp_auth.mjs` helper honors `GOOGLE_IMPERSONATE_SERVICE_ACCOUNT`; **17 same-session reviewer folds = NEW HIGH-WATER MARK** vs 0.7.0's 12 (1 R-CRITICAL EE-RT.20 class recurrence catch + 7 R-HIGH + 8 R-MEDIUM + 1 R-LOW(+1 grouped)); plugin count UNCHANGED at 24; +22 new soc2.json mappings; new SDK deps `googleapis` + `@google-cloud/org-policy` in optionalDependencies; twenty-second consecutive trio-publish)

No code changes. CE 0.1.65 ships the same code as 0.1.40 → 0.1.64 with README/CHANGELOG updated for the paired EE 0.7.1 release.

**EE 0.7.1 paired-release highlights:**

- **EE-RT.22 v2 plugin 1025 R2 expansion** — closes all 4 v1-deferred dimensions of the GCP IAM Project-Level Auditor. Plugin grows from 3 dims to 7. **Dim 4** custom-role permission audit (CC6.1; `iam.projects.roles.list` view=FULL; `*` wildcard = CRITICAL, admin-equivalent permission intersection across `_ADMIN_EQUIVALENT_PERMISSIONS` 16-entry allowlist = HIGH). **Dim 5** SA key custody (CC6.1 + C1.1 dual-mapped; user-managed long-lived keys = HIGH — the canonical SA-credential-leakage class; 90-day rotation narrative-uplift). **Dim 6** SA impersonation graph BFS — flagship dim (CC6.1; mirrors plugin 1030 shadow-admin BFS adapted to GCP IAM data model; per-PATH visited Set for cycle defense; depth cap = 4; 2-hop = HIGH, 3+ hop = CRITICAL; project-scope impersonation grants surface independently as CRITICAL via R1-HIGH-2 reviewer fold). **Dim 7** Organization Policy constraint enumeration (CC6.6 + C1.1 dual-mapped; 4 sensitive constraints incl. `iam.disableServiceAccountKeyCreation`).

- **NEW `utils/gcp_auth.mjs` helper** — shared `buildGcpAuthOptions` honoring `GOOGLE_IMPERSONATE_SERVICE_ACCOUNT` env var. Closes the gap where GCP client libraries do NOT honor gcloud CLI's `auth/impersonate_service_account` config — pre-helper plugins 1024/1025 silently fell back to raw ADC when running locally against environments with `iam.disableServiceAccountKeyCreation` enforced. Three credential modes: keyFilename, pure ADC, ADC + impersonation via `google-auth-library`'s `Impersonated` class.

- **R-CRITICAL fold (R2-CRITICAL-1) — EE-RT.20 R1-CRITICAL-1 class recurrence catch.** soc2.json PASS-tier SA-key patterns silently failed to match when plugin emitted `(display: 'X')` optional segment between email and `has` clause. Production false-clean impact would have been ~100% on real GCP fixtures (every SA has `displayName` populated). Patterns rewritten to use `.*` to tolerate the optional segment.

- **Plugin count UNCHANGED at 24** (v2 = in-place expansion of plugin 1025, not new plugin). **Coverage matrix UNCHANGED at 10/4/33** — pure substrate-evidence depth uplift on already-covered CC6.1 / CC6.6 / C1.1 controls. **EE regression: 5715/5715 across 892 suites; 65-session 100% green streak preserved.**

- **Cross-repo privacy scrub (parallel non-functional work)** — operator-flagged CRITICAL privacy class at 0.7.1 review: shipped npm files MUST NOT contain operator-private references. Substitutions applied across all 3 repos for personal emails / internal repo paths / real account IDs. New memory `[[npm_package_privacy]]` pinned. Force-push history rewrite applied to CE + agent-skill public repos.

---

## 0.1.64 — docs-only: paired-release announcement for EE 0.7.0 MINOR-VERSION MILESTONE (NEW plugin 1025 GCP IAM Project-Level Auditor opening the v0.7.x cross-cloud-parity line; first plugin in the GCP-IAM-deep-audit cohort; 3 audit dimensions across CC6.1 + CC6.6 substrate evidence; 12 R1 reviewer folds (0 R-CRITICAL + 2 R-HIGH + 5 R-MEDIUM + 5 R-LOW — clean review pass); plugin count 23 → 24; 11 new soc2.json mappings; new SDK dep `@google-cloud/resource-manager`; twenty-first consecutive trio-publish)

---

## 0.1.63 — docs-only: paired-release announcement for EE 0.6.9 (patch-level EE-RT.21 v2 R2 reviewer-deferred-items cleanup for plugin 1024 GCP Cloud Storage Auditor; 5 R1 reviewer folds (0 R-CRITICAL + 1 R-HIGH + 1 R-MEDIUM + 3 R-LOW — clean review pass); plugin count UNCHANGED at 23; 3 new soc2.json mappings; NEW institutional pre-publish doc-consistency gate; twentieth consecutive trio-publish)

No code changes. CE 0.1.63 ships the same code as 0.1.40 → 0.1.62 with README/CHANGELOG updated for the paired EE 0.6.9 release.

**EE 0.6.9 paired-release highlights:**

- **Appendix A multi-cloud parity** — `utils/soc2_renderer.mjs:computeBucketStats` extended from AWS-S3-only filter to multi-cloud (AWS S3 + GCS). "Cloud Bucket Exposure Attestation" appendix now correctly surfaces plugin 1024 GCS findings alongside plugin 1020 AWS S3 findings. Filter lifted to a frozen Set `_CLOUD_BUCKET_AUDIT_SOURCES` per `[[emit_literal_set_drift]]`. Azure plugin 1022 intentionally excluded (commingled NSG/RBAC/Storage emissions + engine-projection constraint; deferred to a future plugin-1022 refactor cycle).
- **Evidence-gap soc2.json routing** — two new titlePattern entries route `_CAT_METADATA_UNREADABLE` + `_CAT_IAM_UNREADABLE` LOW + evidenceGap emissions explicitly to CC6.6. Pre-fold these emissions relied on the downstream renderer honoring the `evidenceGap: true` flag — but explicit titlePattern routing is the safer pattern per `[[soc2_titlepattern_anchor_drift]]`.
- **R1-HIGH-1 C1.1 dual-mapping fold** — reviewer caught rationale-vs-implementation drift: rationale text asserted "+ C1.1 confidentiality boundary" but the metadata-unreadable mapping shipped only under CC6.6. Added the parallel C1.1 entry. Restores cross-cloud parity with plugin 1020 S3 (whose `_CAT_ENCRYPTION_UNVERIFIABLE` also dual-maps to C1.1). Institutional learning: every claim in a soc2.json rationale must be implemented by the corresponding JSON structure.
- **NEW pre-publish doc-consistency gate** — introduced this cycle in `tasks/CLAUDE.md` after the 0.6.8 → user-caught doc drift. 22 doc-surface audit checklist (14 EE + 4 CE + 4 agent-skill files) + auto-grep + SOC 2 matrix invariant check. Codified as `[[pre_publish_doc_consistency_gate]]` auto-memory for cross-session persistence.
- **Plugin count UNCHANGED at 23**. Coverage matrix UNCHANGED at 10/4/33 — pure substrate-evidence quality uplift.
- **EE full regression: 5423/5423 across 851 suites; 61-session 100% green streak preserved.**

**Trio-publish institutionalization continued.** Paired with EE 0.6.9 + agent-skill 0.1.30 — **twentieth consecutive trio-publish across EE + CE + agent-skill in a single session** (0.4.5–0.6.9).

**Customer install (post-trio-publish):**

```bash
npm install -g nsauditor-ai@0.1.63 @nsasoft/nsauditor-ai-ee@0.6.9
npm install nsauditor-ai-agent-skill@0.1.30   # AI-coding-agent users
```

---

## 0.1.62 — docs-only: paired-release announcement for EE 0.6.8 (NEW plugin 1024 GCP Cloud Storage Auditor — first multi-cloud parity plugin in 6 months; 4 R1 reviewer folds (0 R-CRITICAL + 0 R-HIGH + 3 R-MEDIUM + 1 R-LOW — clean review pass); plugin count 22 → 23; 20 new soc2.json mappings; nineteenth consecutive trio-publish)

No code changes. CE 0.1.62 ships the same code as 0.1.40 → 0.1.61 with README/CHANGELOG updated for the paired EE 0.6.8 release.

**EE 0.6.8 paired-release highlights:**

- **NEW plugin 1024 GCP Cloud Storage Auditor** — first NEW EE plugin since 0.6.1 (six months); first multi-cloud parity plugin since the v0.6.x line opened. Audits Google Cloud Storage buckets against AICPA Trust Services Criteria 2017 across 6 dimensions mirroring plugin 1020 AWS S3 Auditor: bucket-level IAM public bindings (CC6.6 — allUsers = CRITICAL, allAuthenticatedUsers = HIGH), Uniform Bucket-Level Access enforcement (CC6.6 + C1.1 dual-mapped — closes legacy bucket-ACL false-PASS class), Object Versioning (C1.1 + A1.2 dual-mapped per S3 versioning precedent), Bucket Lock retention policy (C1.1 + C1.2 dual-mapped per S3 Object Lock COMPLIANCE-mode precedent; SEC 17a-4 / FINRA 4511 WORM-alignment), Customer-Managed Encryption Keys via Cloud KMS (CC6.1 four-tier custody ladder mirroring plugin 1140 v2 RDS), and bucket-level access logging (CC7.1 evidence acquisition).
- **Co-existing public-member-types fold** (R1-MEDIUM-1) — when both `allUsers` and `allAuthenticatedUsers` are present in different bindings, the CRITICAL finding surfaces the HIGH evidence (`alsoPublicAuthenticatedCount` + roles + narrative). Pre-fold the HIGH evidence was silently dropped at the precedence gate; distinct CC6.6 sub-postures have distinct remediation paths.
- **CMEK regex tightening** (R1-LOW-1) — full-format 6-segment regex `^projects/[^/]+/locations/[^/]+/keyRings/[^/]+/cryptoKeys/[^/]+(/cryptoKeyVersions/[^/]+)?$` replaces the substring check. Prevents `projects/x/oops/cryptokeys/k` adversarial-mimic false-PASS.
- **Cross-cloud parity dual-mappings** (R1-MEDIUM-1 mappings) — 5 new soc2.json entries dual-mapping GCS retention + versioning findings to C1.2 + A1.2 matching the AWS S3 (plugin 1020) precedents.
- **Conservative classifier severity consistency** (R1-MEDIUM-2) — run()-level per-bucket exception emits LOW + evidenceGap (not INFO), matching the metadata-error pattern in `_auditBucket`.
- **Institutional contract applied day-1**: EE-RT.13 PLUGIN_ID exported constant + Thread H equivalent (`_callGcsWithInstrumentation` with HTTP-code→AWS-style error normalization + AccessDenied counter + throttle-retry with wall budget) + ZDE `_stripControlChars` on every GCS-returned string surface + `result.ok===true` envelope per EE-RT.12.25.
- **New SDK dep**: `@google-cloud/storage` in optionalDependencies. Plugin 1021 (legacy GCP Cloud Scanner) keeps its dynamic import.
- **Plugin count 22 → 23**. Coverage matrix UNCHANGED at 10/4/33 — pure substrate-evidence depth uplift on already-covered controls.
- **EE full regression: 5415/5415 across 851 suites; 60-session 100% green streak preserved.**

**Trio-publish institutionalization continued.** Paired with EE 0.6.8 + agent-skill 0.1.29 — **nineteenth consecutive trio-publish across EE + CE + agent-skill in a single session** (0.4.5–0.6.8).

**Customer install (post-trio-publish):**

```bash
npm install -g nsauditor-ai@0.1.62 @nsasoft/nsauditor-ai-ee@0.6.8
npm install nsauditor-ai-agent-skill@0.1.29   # AI-coding-agent users
```

---

## 0.1.61 — docs-only: paired-release announcement for EE 0.6.7 (patch-level R2 reviewer-deferred-items cleanup cycle — EE-RT.16 v3.1 plugin 1170 SG-reference-graph edge dedup + EE-RT.20.5 v6.1 plugin 1200 CloudWatch Logs probe retry-on-empty parity; 4 R1 reviewer folds (0 R-CRITICAL + 0 R-HIGH + 1 R-MEDIUM + 3 R-LOW — clean review pass) + 1 unanticipated `_retryOnNotFound` two-phase restructure (caught by test interaction); plugin count UNCHANGED at 22; soc2.json UNCHANGED; eighteenth consecutive trio-publish)

No code changes. CE 0.1.61 ships the same code as 0.1.40 → 0.1.60 with README/CHANGELOG updated for the paired EE 0.6.7 release.

**EE 0.6.7 paired-release highlights:**

- **Plugin 1170 SG-reference-graph edge dedup (the substrate-evidence headline)** — `_buildSgReferenceGraph` now dedupes edges by `(sourceGroupId, targetGroupId)` with `ports` aggregated as array. Pre-fold a real-world ALB-fronting-app SG (3 ingress perms for ports 80/443/8080 all referencing the same source SG) emitted 3 distinct edges A→B; the BFS treated each as a separate chain, inflating auditor-visible `chainCount` 2-5× and exhausting per-target chain caps on noise rather than on genuinely distinct reachability paths. Post-fold the BFS sees exactly 1 chain per distinct (source, target) pair — auditor visibility into genuinely distinct exposure paths restored. `isCrossVpc` aggregation is AND-semantic — if ANY pair is same-VPC, the merged edge is treated as same-VPC (per `[[conservative_classifier_principle]]`: walk a possibly-same-VPC chain rather than silently skip).
- **Plugin 1200 CloudWatch Logs probe retry-on-empty parity (the long-tail consistency headline)** — the v6 CWL Logs probe was asymmetric: `DescribeLogGroups` returns `logGroups: []` (NOT a thrown exception) on missing groups, so the shared `_retryOnNotFound` helper's thrown-NotFound retry path never fired. A freshly-created CWL log group probed within seconds of creation could false-DEAD. Post-fold `_retryOnNotFound` accepts an optional retry-on-result predicate; the CWL call site passes a predicate that fires retry when the response carries no exact-name match (covers both empty and prefix-only-sibling responses). Eventual-consistency parity now consistent across IAM / Lambda / SNS / SQS / EventBridge API destination / CloudWatch Logs.
- **Two-phase restructure of `_retryOnNotFound`** — initially the result-based retry was added inside the existing try block, but a compound-path test interaction (transient empty → second-call throws `ResourceNotFoundException`) caused 3 total network calls (initial + result-retry + thrown-retry). Restructured to two mutually-exclusive phases — Phase 1 = initial call + thrown-NotFound retry; Phase 2 = result-based retry — capping total calls at 2 on all compound paths. The per-call-site outer catch routes a second-call thrown error (NotFound → DEAD; AccessDenied → UNVERIFIABLE).
- **R-MEDIUM-1 reviewer fold — arrival-order independence** locked with a second regression fixture mirroring the first (SAME-VPC pair declared first, cross-VPC pair second) + JSDoc tightened to call out the AND-semantic explicitly.
- **R-LOW-1 reviewer fold — partial-render contract** on malformed port specs in the array documented + 2 regression fixtures.
- **R-LOW-2 reviewer fold — `_portKeys` scratch lifetime** documented at the function-signature comment so future refactor can't expose the dedup index.
- **R-LOW-1 reviewer fold — compound-path coverage** with 2 new tests (transient empty → second-call AccessDenied → UNVERIFIABLE / transient empty → second-call thrown RNF → DEAD). Both verify total network calls = 2 — drove the two-phase restructure.
- **soc2.json UNCHANGED** — no new emission categories (internal graph structure + retry-policy refinement).
- **Plugin count UNCHANGED at 22**; coverage matrix UNCHANGED at 10/4/33.
- **EE full regression: 5314/5314 across 834 suites; 59-session 100% green streak preserved.**

**Trio-publish institutionalization continued.** Paired with EE 0.6.7 + agent-skill 0.1.28 — **eighteenth consecutive trio-publish across EE + CE + agent-skill in a single session** (0.4.5–0.6.7).

**Customer install (post-trio-publish):**

```bash
npm install -g nsauditor-ai@0.1.61 @nsasoft/nsauditor-ai-ee@0.6.7
npm install nsauditor-ai-agent-skill@0.1.28   # AI-coding-agent users
```

---

## 0.1.60 — docs-only: paired-release announcement for EE 0.6.6 (minor cycle — EE-RT.16 v3 plugin 1170 SG→SG transitive chain reachability + EE-RT.20.5 v6 plugin 1200 dead-target probe warm-up (IAM role + EventBridge API destination + CloudWatch Logs); 5 R1 reviewer folds (1 R-HIGH + 2 R-MEDIUM + 2 R-LOW; 0 R-CRITICAL — clean review pass); plugin count UNCHANGED at 22; seventeenth consecutive trio-publish)

No code changes. CE 0.1.60 ships the same code as 0.1.40 → 0.1.59 with README/CHANGELOG updated for the paired EE 0.6.6 release.

**EE 0.6.6 paired-release highlights:**

- **SG→SG transitive chain reachability (the substrate-evidence headline)** — plugin 1170 (`aws-ec2-sg-perimeter-auditor`) gains v3 transitive reachability analysis. Pre-v3, each EC2 Security Group was audited in isolation: a SG with no direct public-CIDR ingress would emit the PASS-tier "no direct public-internet ingress CIDR rules" finding — even if it was transitively reachable from the internet through a chain of `UserIdGroupPairs` SG-references. Post-v3, the plugin builds the SG-reference graph, identifies public-CIDR roots (0.0.0.0/0 / ::/0 ingress), and BFS-walks the graph with cycle defense, depth cap (default 5, max 20, operator-tunable), and per-target chain cap (default 10, max 100). 2-hop chains emit **HIGH**; 3+ hop chains emit **CRITICAL** (operator-blindness principle: deeper chains are less likely to be noticed in a per-SG review). Cross-VPC edges are skipped (out-of-scope for v3 v1; surfaced as INFO trailer). New operator opts: `skipTransitiveReachability` / `transitiveChainDepthCap` / `transitiveChainsPerTargetCap` / `transitiveChainSamplesPerFindingCap`. v3 v1 documented limitation: per-hop port-flow tracked but NOT intersected (walkthroughRequired=true on every transitive finding).
- **Dead-target probe warm-up (the long-tail closure)** — plugin 1200 v6 closes the 0.6.5 reviewer-deferred long-tail of unverifiable EventBridge target ARN shapes. New probes for IAM role (`iam:GetRole`), EventBridge API destination (`events:DescribeApiDestination`), and CloudWatch Logs (`logs:DescribeLogGroups` with exact-name disambiguation guard so prefix-match siblings don't false-LIVE). New SDK deps `@aws-sdk/client-iam` + `@aws-sdk/client-cloudwatch-logs` (both in optionalDependencies). **Operator note**: `iam:GetRole` is a global API resolving per-partition (aws / aws-cn / aws-us-gov / ISO). Orchestrators wiring `opts._iamClient` must construct a single global IAM client per-partition (NOT per-region). Documented at `_loadIamSdk` per R-MEDIUM-2 reviewer fold.
- **R-HIGH-1 reviewer fold — BFS short-circuits enqueue past per-target cap**: pre-fold the plugin 1170 v3 BFS marked the target truncated but kept enqueueing further work through the capped target, cloning `path` and `visited` Sets each frame. On hub-and-spoke topologies (common in shared-services VPCs with 200+ SGs and fan-out ≥10), this produced path-enumeration explosion with O(paths × depth) heap usage — multi-second hang + 100+MB transient heap on pathological accounts. Post-fold: when the per-target cap is hit, BFS skips enqueueing through that edge entirely. Regression test pins hub-and-spoke fixture.
- **R-MEDIUM-1 reviewer fold — IAM `NoSuchEntityException` lifted into `_DEAD_TARGET_NOTFOUND_ERROR_NAMES` Set**: pre-fold the bare disjunction `err.name === "NoSuchEntityException"` at the IAM catch site bypassed the Set, AND the `_retryOnNotFound` wrapper was silently disabled for IAM (the canonical worst-case for AWS eventual consistency — IAM lag 10-30s documented). Per `[[emit_literal_set_drift]]` (now 9× cumulative recurrence of this class across the EE codebase), bare literals lift to the Set. Post-fold: `"nosuchentityexception"` and `"nosuchentity"` added to the Set; bare disjunction collapsed; eventual-consistency retry restored for IAM (a freshly-created role added to an EventBridge rule within ~30s of probe time now retries before confirming DEAD instead of emitting a false-DEAD companion-LOW).
- **R-MEDIUM-2 reviewer fold — IAM partition-routing contract documented**: orchestrator-facing contract surfaced at `_loadIamSdk` so GovCloud / aws-cn / ISO operators don't construct a regional IAM client by mistake.
- **R-LOW-2 reviewer fold — plugin 1170 v3 depth-cap-hit surfaced separately from per-target-cap**: pre-fold a graph deeper than `transitiveChainDepthCap` silently truncated without operator-visible signal — false-CLEAN class on deeply-buried CRITICAL exposures. Post-fold: `_walkTransitiveReachability` returns `depthCapHit: boolean`; the INFO trailer distinguishes "raise chainsPerTargetCap" from "raise depthCap" with separate reason strings.
- **R-LOW-2 reviewer fold — plugin 1200 v6 API destination ARN regex future-proofed**: trailing `/` made optional so future AWS ARN shapes without UUID suffix don't false-malformed.
- **R2 reviewer-deferred (queued for 0.6.7)**: plugin 1170 v3 edge-dedup in `_buildSgReferenceGraph` (multi-rule SG references currently inflate chain counts 2-5×) + plugin 1200 v6 Logs probe retry-on-empty parity with Lambda/SNS/SQS + R-NIT documentation folds.
- **3 new soc2.json mappings** under CC6.6 (transitive-public HIGH + CRITICAL + INFO truncation trailer).
- **EE full regression: 5304/5304 across 834 suites; 58-session 100% green streak preserved.**

**Trio-publish institutionalization continued.** Paired with EE 0.6.6 + agent-skill 0.1.27 — **seventeenth consecutive trio-publish across EE + CE + agent-skill in a single session** (0.4.5–0.6.6).

**Customer install (post-trio-publish):**

```bash
npm install -g nsauditor-ai@0.1.60 @nsasoft/nsauditor-ai-ee@0.6.6
npm install nsauditor-ai-agent-skill@0.1.27   # AI-coding-agent users
```

---

## 0.1.59 — docs-only: paired-release announcement for EE 0.6.5 (patch-level v4-reviewer-cleanup cycle — EE-RT.20.4 plugin 1200 v5: R-NIT named-constants + targetVerificationReason sentinel observability + sessionToken cross-plugin sweep (18 plugins) + dead-target companion-LOW (Lambda + SNS + SQS); 5 R1 reviewer folds; plugin count UNCHANGED at 22; sixteenth consecutive trio-publish)

No code changes. CE 0.1.59 ships the same code as 0.1.40 → 0.1.58 with README/CHANGELOG updated for the paired EE 0.6.5 release.

**EE 0.6.5 paired-release highlights:**

- **sessionToken cross-plugin sweep (the operator-impact headline)** — 18 EE AWS plugins (1020 through 1200) now thread `sessionToken` through their AWS-SDK credentials block. Pre-0.6.5, auditors using `aws sts assume-role` (the canonical cross-account audit pattern) saw all auto-loaded clients fail signing because the temporary `sessionToken` was silently dropped. Post-0.6.5: AssumeRole-style auditor credentials work uniformly across the entire EE catalog. New source-level regression test pins the contract.
- **Dead-target companion-LOW (the substrate-evidence headline)** — closes the EE 0.6.4 R-HIGH-2 documented limitation. Plugin 1200 now probes per-target liveness for the 3 most-common EventBridge target types: Lambda (`lambda:GetFunction` on full qualified ARN — alias/version correctness verified server-side), SNS (`sns:GetTopicAttributes`), and SQS (`sqs:GetQueueUrl` + `sqs:GetQueueAttributes` — partition-aware via SDK URL resolution). When at least one verified rule contains targets pointing to deleted resources, the plugin emits a **companion LOW finding alongside the PASS verdict** carrying the affected ARNs (capped at 10 + `deadTargetArnsTruncated` count). New operator opts: `skipTargetLivenessProbe: true` + `deadTargetProbeTimeoutMs`.
- **Three deferred target types** (IAM role + API destination + CloudWatch Logs) queued for 0.6.6 — would add 3-4 IAM grants. Unknown ARN shapes currently route to UNVERIFIABLE per the conservative-classifier discipline.
- **R-HIGH-1 reviewer fold — case-insensitive NotFound matching**: defends against future AWS SDK case changes per `[[aws_string_case_normalization]]` (15× recurrent class). Pre-fold a future `aws.simplequeueservice.*` (lowercase variant) would have crashed the region scan; post-fold the matcher is case-insensitive at the boundary.
- **R-HIGH-2 reviewer fold — one-retry on NotFound (eventual-consistency defense)**: freshly-created Lambda/SNS/SQS resources (added to EB rule within ~30s of probe time) may transiently return `ResourceNotFoundException`. Pre-fold this emitted false-DEAD findings on legitimately-active resources — operator-credibility hit. Post-fold: one retry with 750ms backoff before confirming DEAD.
- **R-HIGH-3 reviewer fold — Lambda probe passes FULL qualified ARN** to `GetFunction.FunctionName` (alias `PROD` pointing to a deleted version surfaces as DEAD instead of false-LIVE).
- **R-HIGH (Explore) reviewer fold — parallel probes via Promise.all** with per-target timeout (default 2s; operator-tunable). Latency-bounded fan-out across N targets per rule.
- **R-MEDIUM-1 reviewer fold — SQS partition-aware via `GetQueueUrl`** instead of synthesized URL. Pre-fold the synthesized `amazonaws.com` URL would have thrown `UnknownEndpoint` on aws-cn / aws-us-gov / aws-iso partitions, crashing the region scan.
- **Sentinel observability — `targetVerificationReason` enum** on rule shape (AccessDenied / SdkUnavailable / BeyondCap / SkippedByOpts). Auditors drill down by failure mode instead of seeing opaque `targetCount: null`.
- **R-NIT named-constants consolidation** — frozen Set `SH_HUB_NOT_ENABLED_ERROR_NAMES` lifts 2 bare-string sites in SecurityHub probe helpers per `[[emit_literal_set_drift]]`.
- **Plugin count UNCHANGED at 22**; coverage matrix UNCHANGED at 10/4/33 — pure evidence-acquisition depth uplift on CC7.1.

**Upgrade guidance:**

- **Auditors using AssumeRole-style credentials on any EE plugin** — Upgrade. EE 0.6.4 and earlier silently dropped `sessionToken` across all 18 plugins. This blocks cross-account audits with temporary credentials.
- **Customers with EventBridge rules routing GuardDuty / Inspector2 findings to Lambda / SNS / SQS targets** — Upgrade. Dead-target companion-LOW closes a real false-PASS class for rules still referencing deleted resources.
- **GovCloud / aws-cn / ISO-partition operators using SQS targets** — Upgrade. Pre-fold SQS URL synthesis assumed commercial AWS and would have thrown `UnknownEndpoint` on non-commercial partitions.
- **Cost-sensitive scheduled runs** — Set `skipTargetLivenessProbe: true` to preserve 0.6.4 dim cost profile (per-target probes add latency).

See [EE 0.6.5 release notes](https://www.npmjs.com/package/@nsasoft/nsauditor-ai-ee/v/0.6.5) for full per-fold breakdown.

**Customer install (paired):**

```bash
npm install -g nsauditor-ai@0.1.59 @nsasoft/nsauditor-ai-ee@0.6.5
npm install nsauditor-ai-agent-skill@0.1.26   # AI-coding-agent users
```

---

## 0.1.58 — docs-only: paired-release announcement for EE 0.6.4 (patch-level reviewer-cleanup cycle — EE-RT.20.3 plugin 1200 v4: EventBridge target verification + multi-failedAccount surface + trigger uniformity; 5 R1 reviewer folds incl. R-HIGH-1 cap-skew classifier closure; plugin count UNCHANGED at 22; fifteenth consecutive trio-publish)

No code changes. CE 0.1.58 ships the same code as 0.1.40 → 0.1.57 with README/CHANGELOG updated for the paired EE 0.6.4 release.

**EE 0.6.4 paired-release highlights:**
- **EventBridge target verification (R-HIGH-2)** — closes the substrate-without-sink false-PASS class at the RULE level. Pre-fold, a rule could be PASS even with zero `Targets` (sink-less rule routing findings nowhere); post-fold `events:ListTargetsByRule` verifies each matched rule has ≥1 target. New MEDIUM `*-alerting-destination-targetless` verdict for sink-less rules.
- **Multi-failedAccount surface (R-MEDIUM-2)** — Inspector2 `BatchGetAccountStatus` helper now returns `failedAccounts: <array>` (was singular pre-fold; the rest of failed accounts silently dropped on delegated-admin scans). Caller emits one LOW per failed account with `accountId` + `errorCode` + `errorMessage` in details.
- **Trigger uniformity (R-LOW-2)** — GuardDuty alerting-destination trigger gates on `detector.Status === ENABLED` (matches Inspector2's enabled-only semantic). SUSPENDED detectors no longer noise the alerting check.
- **R-HIGH-1 reviewer fold — cap-skew classifier closure**. Pre-fold, rules 1-10 target-less + rules 11+ beyond verification cap → emitted MEDIUM TARGETLESS. But rule 11 could be the actual sink (cap-skew false-MEDIUM). Post-fold: emits LOW UNVERIFIABLE with `capExceeded: true` and explicit "raise `targetVerificationRuleCap`" remediation. Conservative-classifier discipline restored.
- **R-HIGH consolidated reviewer fold** — `_listEventBridgeRuleTargets` pagination loop (AWS historical max 5 targets per rule but API supports NextToken; defensive hard-cap 500) + JSDoc clarity on return shape.
- **R-MEDIUM-1 reviewer fold — multi-failedAccount per-region emission cap**. Pre-fold worst-case = 100 failed accounts × 17 regions = 1700 individual LOWs (finding-surface pollution). Post-fold per-region cap of 10 + rollup LOW per region with `omittedCount` + `sampledOmittedAccountIds: array`. Surface reduced ~9× while preserving operator-actionable evidence at the head.
- **R-HIGH-2 reviewer fold — dead-target documented-limitation note**. Target COUNT verified, per-target LIVENESS not (Target.Arn could point to deleted Lambda / detached SNS topic). Per-target liveness probes would require ~6 new IAM grants on Lambda / SNS / SQS / etc. Companion-LOW finding queued for 0.6.5; soc2.json PASS rationale now documents the limitation explicitly.
- **New operator opts** — `skipEventBridgeTargetVerification: true` (opt-out for cost-sensitive runs or operators without `events:ListTargetsByRule` IAM grant) + `targetVerificationRuleCap: 1..100` (per-rule verification cap; default 10).
- **Plugin count UNCHANGED at 22**; coverage matrix UNCHANGED at 10 covered / 4 partial / 33 OOS — pure evidence-depth hardening on CC7.1.

**Upgrade guidance:**
- **Customers running plugin 1200 on EE 0.6.3** — Upgrade. The target-verification dim closes a real false-PASS class at the rule level.
- **Customers running delegated-admin Inspector2 scans across member accounts** — Upgrade. EE 0.6.3 silently dropped all but the first failed account per region; 0.6.4 surfaces each (capped at 10 + rollup per region).
- **Customers with cost-sensitive scheduled runs OR no events:ListTargetsByRule IAM grant** — Set `skipEventBridgeTargetVerification: true` to preserve the 0.6.3 dimension cost profile (verdict routes to LOW UNVERIFIABLE — correct conservative-classifier output when target-presence is unknown).

See [EE 0.6.4 release notes](https://www.npmjs.com/package/@nsasoft/nsauditor-ai-ee/v/0.6.4) for full per-fold breakdown.

**Customer install (paired):**

```bash
npm install -g nsauditor-ai@0.1.58 @nsasoft/nsauditor-ai-ee@0.6.4
npm install nsauditor-ai-agent-skill@0.1.25   # AI-coding-agent users
```

---

## 0.1.57 — docs-only: paired-release announcement for EE 0.6.3 (patch-level evidence-acquisition extension — EE-RT.20.2 plugin 1200 v3: alerting-destination dim closes substrate-without-sink false-PASS class for GuardDuty/Inspector2; R-CRITICAL-1 Inspector Classic ARN-collision fold + R-HIGH-1 SH-only PASS narrative split + R-HIGH-3 EventBridge content-filter grammar; plugin count UNCHANGED at 22; fourteenth consecutive trio-publish)

No code changes. CE 0.1.57 ships the same code as 0.1.40 → 0.1.56 with README/CHANGELOG updated for the paired EE 0.6.3 release.

**EE 0.6.3 paired-release highlights:**
- **Alerting-destination dim (NEW)** — closes the substrate-without-sink false-PASS class for GuardDuty + Inspector2. Verifies at least one of EventBridge rule (source=`aws.guardduty` / `aws.inspector2`) OR SecurityHub product subscription is wired per service per region. Without one of these routing paths, findings live only in the AWS service console — no proactive paging, no SOC 2 monitoring-evidence stream.
- **Verdict tiers** (per service per region): PASS `alerting-destination-present` (EB rule present) / MEDIUM `alerting-destination-sh-only` (SH aggregates but no paging guarantee; auditor walkthrough required to confirm SH → downstream paging) / HIGH `alerting-destination-missing` (no path; substrate-without-sink class) / LOW `alerting-destination-unverifiable` (AccessDenied / SDK unavailable; conservative classifier).
- **R-CRITICAL-1 reviewer fold** — SecurityHub product ARN substring collision closure (Inspector Classic vs Inspector2). Pre-fold the substring `:product/aws/inspector` matched BOTH Inspector Classic (deprecated 2024) AND Inspector2 — a stale Classic subscription emitting zero findings would have falsely PASSed the Inspector2 dim. Post-fold: boundary-anchored helper with strict `/aws/inspector2` constant.
- **R-HIGH-1 reviewer fold** — SH-only path is institutionally insufficient (SecurityHub aggregates findings but doesn't guarantee proactive paging out). Post-fold: SH-only emits MEDIUM (was PASS pre-fold) with walkthrough prompt to confirm operator has wired an `aws.securityhub` EventBridge rule downstream.
- **R-HIGH-3 reviewer fold** — EventBridge content-filter grammar (`{prefix: "aws."}`, `{wildcard: "aws.guard*"}`). Pre-fold the source matcher was strict-equality; catch-all routing rules emitted false-HIGH "no destination." Post-fold: `_eventBridgeSourceMatches` helper recognizes string + prefix + wildcard forms (case-insensitive; regex-meta escape in wildcard pattern for defense against operator IaC).
- **Inspector2 helper hardening (R-MEDIUM-2 + item d)** — `_getInspector2AccountStatus` now returns `{accountStatus, accessDenied, failedAccount}` (was `null | <obj>` conflating four cases). New `_CAT_INS_FAILED_ACCOUNT` LOW surfaces AWS-published `failedAccounts[].errorCode + errorMessage` instead of generic UNVERIFIABLE.
- **New SDK deps** — `@aws-sdk/client-eventbridge` + `@aws-sdk/client-securityhub` added to optionalDependencies. When unavailable, the dimension downgrades to LOW + evidenceGap; rest of plugin 1200 continues uninterrupted.
- **Plugin count UNCHANGED at 22**; coverage matrix UNCHANGED at 10 covered / 4 partial / 33 OOS — pure substrate-evidence depth uplift on CC7.1 controls already classified as 'covered'.

**Upgrade guidance:**
- **Customers running plugin 1200 on EE 0.6.0 / 0.6.1 / 0.6.2** — Upgrade. The substrate-without-sink false-PASS class affects every plugin 1200 deployment.
- **Customers running Amazon Inspector Classic alongside Inspector2** — Upgrade. The R-CRITICAL ARN-collision closure prevents a false-PASS from stale Classic subscriptions.
- **Customers using `{prefix}` / `{wildcard}` content-filter EventBridge rules** — Upgrade. Catch-all routing rules now match correctly.
- **Customers with cost-sensitive scheduled runs** — `skipAlertingDestination: true` opts out of the new dimension entirely.

See [EE 0.6.3 release notes](https://www.npmjs.com/package/@nsasoft/nsauditor-ai-ee/v/0.6.3) for full per-fold breakdown.

**Customer install (paired):**

```bash
npm install -g nsauditor-ai@0.1.57 @nsasoft/nsauditor-ai-ee@0.6.3
npm install nsauditor-ai-agent-skill@0.1.24   # AI-coding-agent users
```

---

## 0.1.56 — docs-only: paired-release announcement for EE 0.6.2 (patch-level evidence-acquisition extension — EE-RT.20.1 plugin 1200 v2: multi-region enumeration + FindingPublishingFrequency check + Inspector2 baseline expansion; closes FedRAMP / StateRAMP / IL5+ false-PASS class for GovCloud + ISO regions; plugin count UNCHANGED at 22; thirteenth consecutive trio-publish)

No code changes. CE 0.1.56 ships the same code as 0.1.40 → 0.1.55 with README/CHANGELOG updated for the paired EE 0.6.2 release.

**EE 0.6.2 paired-release highlights:**
- **Multi-region GuardDuty + Inspector2 enumeration** (closes the single-region false-PASS class). `ec2:DescribeRegions` enumerates opted-in regions; per-region dispatch; per-region findings carry region tag. Operator opts: `regions: string[]` (filter to subset), `skipMultiRegion: true` (cost-sensitive opt-out), `regionListCap` (1..256 clamp; default 64).
- **GovCloud + ISO region support** — closes a **FedRAMP / StateRAMP / IL5+ false-PASS class**: pre-0.6.2 region regex silently rejected 4-part region IDs (`us-gov-east-1` / `us-iso-east-1` / `us-isob-east-1` / `us-isof-south-1`); operator passing those regions explicitly got silent skip. Post-fold regex admits both 3-part and 4-part forms.
- **GuardDuty `FindingPublishingFrequency` check** — CC7.1 detection-latency. 4 outcomes (PASS optimal / LOW suboptimal / LOW unverifiable for null detector or unknown enum). Operator-tunable baseline (`gdFrequencyPassFrequency`); default FIFTEEN_MINUTES. Ordering-based comparison — a detector publishing more frequently than the operator-tuned baseline still emits PASS rather than misclassified LOW.
- **Inspector2 baseline expansion** — `lambdaCode` (Lambda code scanning) + `codeRepository` (Inspector2 GitHub/GitLab scanning, GA 2024+) added to institutional baseline. Operators with Inspector2 enabled but the newer scan-targets disabled see a partial-coverage MEDIUM finding with the disabled resources named, instead of false-CLEAN PASS.
- **Soft-degrade** — EC2 SDK load failure or `DescribeRegions` AccessDenied → fall back to client's configured region + emit distinct LOW finding pinpointing the IAM gap.
- **Backward compatibility** — Operators on EE 0.6.1 who passed singular GuardDuty or Inspector2 clients into the plugin's test seam keep legacy single-region behavior. No 0.6.1 integrations break on upgrade.
- **Plugin count UNCHANGED at 22**; coverage matrix UNCHANGED at 10 covered / 4 partial / 33 OOS — pure substrate-evidence depth uplift on CC7.1 controls already classified as 'covered'.

**Upgrade guidance:**
- **GovCloud, ISO, or ISO-B operators on EE 0.6.0 / 0.6.1** — Upgrade. The earlier region regex silently skipped 4-part region IDs.
- **Multi-region AWS operators on EE 0.6.0 / 0.6.1** — Upgrade. Single-region scope previously masked per-region posture gaps.
- **Single-region commercial-AWS operators on EE 0.6.1** — Optional. Set `skipMultiRegion: true` to preserve 0.6.1 behavior; the FindingPublishingFrequency and Inspector2 baseline-expansion checks still apply.

See [EE 0.6.2 release notes](https://www.npmjs.com/package/@nsasoft/nsauditor-ai-ee/v/0.6.2) for full per-fold breakdown.

**Customer install (paired):**

```bash
npm install -g nsauditor-ai@0.1.56 @nsasoft/nsauditor-ai-ee@0.6.2
npm install nsauditor-ai-agent-skill@0.1.23   # AI-coding-agent users
```

---

## 0.1.55 — docs-only: paired-release announcement for EE 0.6.1 (patch-level new-plugin extension — EE-RT.20 v1 NEW plugin 1200 AWS Inspector2 / GuardDuty Enablement Auditor; plugin count 21 → 22; first AWS-managed-threat-detection substrate audit; twelfth consecutive trio-publish)

No code changes. CE 0.1.55 ships the same code as 0.1.40 → 0.1.54 with README/CHANGELOG updated for the paired EE 0.6.1 release.

**EE 0.6.1 paired-release highlights:**
- **NEW plugin 1200 AWS Inspector2 / GuardDuty Enablement Auditor** — plugin count 21 → 22 (second plugin-count increase in the v0.6.x line). First AWS-managed-threat-detection substrate audit; bundles GuardDuty + Inspector2 per the plugin 1150 multi-service precedent.
- **4 active SOC 2 substrate-evidence dimensions** (dim 5 org-scope deferred to v2): GuardDuty Detector enablement per region (CC7.1 — HIGH `gd-not-enabled` institutional silent-blind class), GuardDuty protection-feature coverage (CC7.1 — institutional baseline S3_DATA_EVENTS / EKS_AUDIT_LOGS / EBS_MALWARE_PROTECTION / RDS_LOGIN_EVENTS / LAMBDA_NETWORK_LOGS / RUNTIME_MONITORING), Inspector2 enablement (CC7.1 + CC7.2 — DISABLED/SUSPENDED = HIGH silent-blind for CVE coverage on EC2/ECR/Lambda fleet), Inspector2 scan-target coverage (CC7.1 zero / CC7.2 partial — institutional baseline {EC2, ECR, Lambda}).
- **6 same-session R1 reviewer folds** (network-security + Explore in parallel): **R1-CRITICAL-1 soc2.json titlePattern misalignment closure** (4 patterns; would have silently failed CC7.1/CC7.2 compliance routing — every plugin 1200 finding routes correctly post-fold) + R1-CRITICAL-1 AccessDenied distinct findings + R1-CRITICAL-2 legacy DataSources case normalization + R1-HIGH-2 SUSPENDED/DISABLED Detector Status guard + R1-HIGH-3/4 dead-code drift closures.
- **4 R2 reviewer-deferred** (queued in EE-RT.20.1): all-regions enumeration / FindingPublishingFrequency check / alerting-destination check / BatchGetAccountStatus contract verification.
- **+52 new tests**; EE full regression: 5096/5096 across 803 suites; **54-session 100% green streak preserved**.
- **7 new soc2.json rules** (4 CC7.1 + 3 CC7.2) — all anchored to actual plugin emission strings.
- **Coverage matrix UNCHANGED at 10/4/33** — institutional honesty (plugin 1200 deepens evidence on already-covered CC7.1 + CC7.2).
- **CE binary unchanged.**
- **Twelfth consecutive trio-publish across EE + CE + agent-skill** — 0.4.5–0.6.1 (12 ship cycles).

```bash
npm install -g nsauditor-ai@0.1.55 @nsasoft/nsauditor-ai-ee@0.6.1
npm install nsauditor-ai-agent-skill@0.1.22  # AI-coding-agent users
```

---

## 0.1.54 — docs-only: paired-release announcement for EE 0.6.0 (minor-version milestone — EE-RT.19 v1 NEW plugin 1160 AWS VPC Endpoints / PrivateLink Auditor; plugin count 20 → 21; first plugin to specifically audit the PrivateLink isolation boundary)

No code changes. CE 0.1.54 ships the same code as 0.1.40 → 0.1.53 with README/CHANGELOG updated for the paired EE 0.6.0 release.

**EE 0.6.0 paired-release highlights:**
- **NEW plugin 1160 AWS VPC Endpoints / PrivateLink Auditor** — plugin count 20 → 21 (first new plugin since EE 0.4.7 introduced plugin 1190; entire v0.5.x line was evidence-quality + surface widening on existing 20 plugins).
- **4 SOC 2 substrate-evidence dimensions**: endpoint resource policy permissive principals (CC6.6 — CRITICAL on unconditional wildcard breaking PrivateLink isolation), PrivateDNS enabled (CC6.6 — MEDIUM silent-bypass when Interface + PrivateDnsEnabled=false), endpoint state (A1.2 + CC7.2 — HIGH `failed` silent-failure class), endpoint type substrate disclosure (Privacy + CC6.6).
- **Clean reviewer pass** (0 R-CRITICAL + 0 R-HIGH); 2 R-MEDIUM/NIT folded same-session (unknown-type fail-safe + Effect case-insensitivity pin).
- **+59 new tests** (57 base + 2 reviewer-fold pins); full EE regression: 5044/5044 across 792 suites; 51-session 100% green streak preserved.
- **7 new soc2.json mapping rules** (5 CC6.6 + 2 CC7.2/A1.2 dual-mapped). Coverage matrix UNCHANGED at 10/4/33 — pure substrate-evidence depth uplift.
- **No new SDK dependencies** — `@aws-sdk/client-ec2` already declared since EE 0.4.5.
- **Eleventh consecutive trio-publish across EE + CE + agent-skill in a single session** — 0.4.5/0.4.6/0.4.7/0.4.8/0.4.9/0.5.0/0.5.1/0.5.2/0.5.3/0.5.4/0.6.0.

**Recommended upgrade path:** `npm install -g nsauditor-ai@0.1.54 @nsasoft/nsauditor-ai-ee@0.6.0` (+ `npm install nsauditor-ai-agent-skill@0.1.21` for AI-coding-agent users).

---

## 0.1.53 — docs-only: paired-release announcement for EE 0.5.4 (cross-plugin Thread H sweep in v0.5.x — §7.5 _promote*FromKms signature hardening on plugin 1140 v2 + 1180 v2 + §8 operator-config DoS caps on plugin 1170 v2; clean reviewer pass; final v0.5.x close-out cycle)

No code changes. CE 0.1.53 ships the same code as 0.1.40 → 0.1.52 with README/CHANGELOG updated for the paired EE 0.5.4 release.

**EE 0.5.4 paired-release highlights:**
- **§7.5 — `_promote*FromKms` cross-plugin signature hardening** (plugin 1140 v2 + plugin 1180 v2): accepts BOTH legacy `keyManager` string OR new `keyManagerByArn: Map<arn, keyManager>` — Map form looks up by `finding.details.kmsKeyArn` (single source of truth, closes caller-side parallel-threading false-CLEAN class).
- **§8 — Operator-config DoS caps** (plugin 1170 v2): new `_OPERATOR_CONFIG_MAX_ENTRIES = 1000` bounds `additionalRestrictedPorts` / `additionalRestrictedPortNames` / `additionalSystemManagedSgNamePrefixes`. Operator-tunable caps. Defends against hostile config-injection DoS.
- **Clean reviewer pass** (0 R-CRITICAL + 0 R-HIGH; 2 R-MEDIUM coverage gaps + 1 R-LOW edge-case folded same-session).
- **+20 new tests this cycle**; full EE regression: 4982/4982; 50-session 100% green streak preserved.
- **Coverage matrix UNCHANGED at 10/4/33** — pure structural-discipline tightening.
- **Tenth consecutive trio-publish across EE + CE + agent-skill in a single session** — 0.4.5/0.4.6/0.4.7/0.4.8/0.4.9/0.5.0/0.5.1/0.5.2/0.5.3/0.5.4. **v0.5.x close-out cycle**; ready for 0.6.0 milestone (EE-RT.19 VPC Endpoints / PrivateLink Auditor NEW plugin recommended).

**Recommended upgrade path:** `npm install -g nsauditor-ai@0.1.53 @nsasoft/nsauditor-ai-ee@0.5.4` (+ `npm install nsauditor-ai-agent-skill@0.1.20` for AI-coding-agent users).

---

## 0.1.52 — docs-only: paired-release announcement for EE 0.5.3 (patch-level extension in v0.5.x — EE-RT.18 v3 plugin 1190 SES Email Integrity Auditor: Part A DKIM public-key fingerprint capture/pin + Part B in-band DMARC alignment classifier + 5 same-session reviewer folds incl. 1 R-CRITICAL false-CLEAN closure on truncated DKIM keys)

No code changes. CE 0.1.52 ships the same code as 0.1.40 → 0.1.51 with README updated to announce the paired **EE 0.5.3 release** and reflect the plugin 1190 v3 extension. CE binary is code-identical to the 0.1.40-line; bump carries the EE-paired-release narrative + deprecates 0.1.51.

**EE 0.5.3 paired-release highlights:**

- **Part A — DKIM public-key fingerprint capture/pin**: new emission categories `ses-dkim-fingerprint-verified` (PASS) / `ses-dkim-fingerprint-mismatch` (HIGH — catches unauthorized rotation / key substitution attacks via operator-supplied `opts.dkimFingerprintPinStore`) / `ses-dkim-fingerprint-unverifiable` (LOW + evidenceGap).
- **Part B — In-band DMARC alignment classifier**: new emissions `ses-dmarc-alignment-strict-met` (PASS) / `ses-dmarc-alignment-relaxed` (INFO) / `ses-dmarc-alignment-dkim-strict-impossible` (HIGH — adkim=s + DKIM disabled = guaranteed failure) / `ses-dmarc-alignment-spf-strict-impossible` (HIGH — aspf=s + no custom MailFrom = guaranteed failure) / `ses-dmarc-alignment-unverifiable` (LOW).
- **R-CRITICAL closure (discovered via test)**: `_stripControlChars` 256-char truncation corrupted long DKIM keys producing wrong SHA-256 fingerprints (false-CLEAN pin matches against truncated hashes) — new `_stripControlCharsNoTruncate` helper bypasses the cap at cryptographic-data surface only.
- **R-HIGH closures**: empty/short-key floor (≥128 bytes) + multiple-DKIM1-records LOW + evidenceGap + DMARC double-failure visibility (`spfStrictAlsoImpossible` detail when both alignment paths impossible).
- **R-MEDIUM closure**: pin-store + failed-capture-on-pinned-token downgraded to LOW + evidenceGap (closes silent-PASS class for stale-pin OR hidden-mismatch).
- **+61 new tests this cycle** (45 v3 base + 16 reviewer-fold pins); plugin 1190 test count grew 248 → 309 across 49 → 60 suites. **EE full regression: 4962/4962; 49-session 100% green streak preserved**.
- **8 new soc2.json mapping rules** (CC6.1). Coverage matrix UNCHANGED at 10/4/33.
- **No new SDK dependencies** — v3 uses existing node:dns/promises + node:crypto.
- **Ninth consecutive trio-publish across EE + CE + agent-skill in a single session** — 0.4.5/0.4.6/0.4.7/0.4.8/0.4.9/0.5.0/0.5.1/0.5.2/0.5.3.

**Recommended upgrade path:** `npm install -g nsauditor-ai@0.1.52 @nsasoft/nsauditor-ai-ee@0.5.3` (+ `npm install nsauditor-ai-agent-skill@0.1.19` for AI-coding-agent users).

---

## 0.1.51 — docs-only: paired-release announcement for EE 0.5.2 (patch-level consolidation in v0.5.x — EE-RT.18 v2.1 plugin 1190 SES Email Integrity Auditor deferred-items sweep: 7 deferred reviewer-fold items closed + 6 same-session reviewer folds incl. 1 CRITICAL soc2 mapping closure + silent-loss-class closure on SES classic API quota exhaustion)

No code changes. CE 0.1.51 ships the same code as 0.1.40 → 0.1.50 with README updated to announce the paired **EE 0.5.2 release** and reflect the plugin 1190 v2.1 consolidation in the public plugin catalog. CE binary is code-identical to the 0.1.40-line; the bump exists solely to carry the EE-paired-release narrative to the npm landing page and to deprecate 0.1.50 with the explicit EE-paired-release pointer. **0.5.2 is a patch-level consolidation cycle** in the v0.5.x line — pure plugin 1190 deferred-items sweep, no new SDK boundary, no new evidence-acquisition surface.

**EE 0.5.2 paired-release highlights:**

- **7 deferred-items closed from 0.5.0 cycle:** R-MEDIUM-2 (DKIM partial-match severity tier — new MEDIUM `ses-dkim-dns-partial-with-transients`) + R-MEDIUM-4 (explicit `_DNS_TRANSIENT_ERROR_CODES` named Set + module-load-time disjointness IIFE) + R-MEDIUM-5 (broadened classic-side error taxonomy: `IdentityNotVerified` / `ConfigurationSetDoesNotExist` / quota-error names) + R-LOW-4 (DMARC chunk-split end-to-end) + R-LOW-5 (DKIM special-chars) + R-LOW-6 (identityType producer→consumer normalization) + R-NIT-1/2 (cosmetic).
- **R-CRITICAL closure**: missing `soc2.json` mapping for new `ses-dkim-dns-partial-with-transients` MEDIUM emission — added CC6.1 titlePattern.
- **R-HIGH closures**: unknown-DNS-code fail-safe call-site pin (2 new tests) + **silent-loss-class closure on SES classic API quota exhaustion** (post-retry-exhaustion bubble now emits `ses-classic-policy-unverifiable` LOW + evidenceGap with `cause: "classic-sdk-quota-exhausted"` rather than disappearing into warnings.push) + identityType producer→consumer round-trip integration test.
- **R-MEDIUM closures**: mixed-failure-mode test + module-load-time disjointness IIFE (`_assertDnsErrorCodeSetsDisjoint()` promotes the `_DNS_NORECORD_ERROR_CODES ∩ _DNS_TRANSIENT_ERROR_CODES = ∅` invariant from test-time to Node startup enforcement).
- **+41 new tests this cycle** (34 deferred-items sweep base + 7 reviewer-fold pins); plugin 1190 test count grew 207 → 248 across 40 → 49 suites. **EE full regression: 4901/4901; 48-session 100% green streak preserved**.
- **1 new soc2.json mapping rule** (CC6.1). Coverage matrix UNCHANGED at 10/4/33 — pure evidence-quality uplift on already-covered CC6.1 + CC6.6 + A1.2 + CC7.1 + CC7.2 controls.
- **No new SDK dependencies** — pure plugin 1190 v2 consolidation.
- **Eighth consecutive trio-publish across EE + CE + agent-skill in a single session** — institutionalized discipline now spans 8 ship cycles (0.4.5/0.4.6/0.4.7/0.4.8/0.4.9/0.5.0/0.5.1/0.5.2). Paired agent-skill 0.1.18 catalog refresh reflects the plugin 1190 v2.1 consolidation on the AI-coding-agent knowledge surface.

**CE-side state:** unchanged binary. CE 0.1.51 = CE 0.1.50 = ... = CE 0.1.40 = CE 0.1.39 code-identical; bump exists solely to carry the EE-paired-release narrative + deprecate 0.1.50 with the explicit EE-paired-release pointer.

**Recommended upgrade path:** `npm install -g nsauditor-ai@0.1.51 @nsasoft/nsauditor-ai-ee@0.5.2` (paired upgrade; + `npm install nsauditor-ai-agent-skill@0.1.18` for AI-coding-agent users).

---

## 0.1.50 — docs-only: paired-release announcement for EE 0.5.1 (patch-level extension in v0.5.x — EE-RT.15 v2 plugin 1150 SQS/SNS Auditor + 6th + 7th dimensions: CloudWatch alarm coverage on SQS ApproximateAgeOfOldestMessage + SNS NumberOfNotificationsFailed + 7 same-session reviewer folds incl. 1 CRITICAL false-CLEAN closure on empty-AlarmActions silent-PASS)

No code changes. CE 0.1.50 ships the same code as 0.1.40 → 0.1.49 with README updated to announce the paired **EE 0.5.1 release** and reflect the plugin 1150 v2 extension in the public plugin catalog. CE binary is code-identical to the 0.1.40-line; the bump exists solely to carry the EE-paired-release narrative to the npm landing page and to deprecate 0.1.49 with the explicit EE-paired-release pointer. **0.5.1 is a patch-level extension** in the v0.5.x line — first plugin-1150 dim to cross an SDK boundary (SQS+SNS → CloudWatch); single-fetch budget via `_enumerateMetricAlarms` paginating `cloudwatch:DescribeAlarms` once + `_buildAlarmIndex` building per-resource Maps for O(1) lookup. Closes the **"messaging monitoring" SOC 2 dimension** per `tasks/things-to-check.md` §4 institutional checklist.

**EE 0.5.1 paired-release highlights:**

- **Dim 6 — SQS ApproximateAgeOfOldestMessage CloudWatch alarm coverage** (CC7.2 + A1.2): per-queue PASS / MEDIUM / LOW / LOW + evidenceGap severity ladder. Closes false-CLEAN window where SQS queue exists with no operational substrate.
- **Dim 7 — SNS NumberOfNotificationsFailed CloudWatch alarm coverage** (CC7.2 + A1.2): per-topic analogue. Closes false-CLEAN window where SNS subscription delivery failures produce no operator paging.
- **R-CRITICAL fold closure**: `ActionsEnabled=true + AlarmActions=[]` was silent PASS pre-fold — CloudWatch fires NO operator paging on empty AlarmActions. Post-fold `actionable` requires BOTH `ActionsEnabled=true` AND non-empty `AlarmActions[]`. Discriminates "all disabled" vs "all empty actions" in remediation narrative.
- **R-HIGH closure**: soc2.json PASS-tier titlePatterns narrowed to anchor on `AWS/SQS:ApproximateAgeOfOldestMessage` / `AWS/SNS:NumberOfNotificationsFailed` clauses (prevents adjacent-severity narrative-drift partial-match).
- **R-MEDIUM-1 closure**: defensive `typeof .get === "function"` guard on `cwState.alarmIndex` shape.
- **R-LOW (FIFO) closure**: end-to-end FIFO queue test + stripped-dim defense (case-sensitive split-surface).
- **+52 new tests this cycle** (41 v2 base + 11 reviewer-fold pins); plugin 1150 test count grew 116 → 168 across 22 → 33 suites. **EE full regression: 4860/4860; 47-session 100% green streak preserved**.
- **No new SDK dependencies** — `@aws-sdk/client-cloudwatch` already declared in optionalDependencies since EE 0.4.0 (used by plugin 1040).
- **12 new soc2.json titlePattern entries** (8 CC7.2 + 4 A1.2 dual-mapped). Coverage matrix UNCHANGED at 10/4/33 — institutional honesty per the matrix-shift discipline; 0.5.1 adds substrate evidence depth on already-covered CC7.2 + A1.2.
- **Synthetic-mock validation only** this cycle — real-AWS smoke deferred (no SQS/SNS paired fixtures yet in operator's internal test infrastructure; ship-without per documented gap, EE 0.5.0 SES precedent).
- **Seventh consecutive trio-publish across EE + CE + agent-skill in a single session** — institutionalized discipline now spans 7 ship cycles (0.4.5/0.4.6/0.4.7/0.4.8/0.4.9/0.5.0/0.5.1). Paired agent-skill 0.1.17 catalog refresh reflects the plugin 1150 v2 extension on the AI-coding-agent knowledge surface.

**CE-side state:** unchanged binary. CE 0.1.50 = CE 0.1.49 = ... = CE 0.1.40 = CE 0.1.39 code-identical; bump exists solely to carry the EE-paired-release narrative + deprecate 0.1.49 with the explicit EE-paired-release pointer.

**Recommended upgrade path:** `npm install -g nsauditor-ai@0.1.50 @nsasoft/nsauditor-ai-ee@0.5.1` (paired upgrade; + `npm install nsauditor-ai-agent-skill@0.1.17` for AI-coding-agent users).

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
- **No real-AWS smoke against violation-tier fixtures** — operator's internal test infrastructure has NO SES paired fixtures yet (full-stack fixtures deferred to EE-RT.18 v2 alongside DKIM CNAME DNS resolution + DMARC TXT record parsing). Empty-account smoke baseline against <operator-test-account> DID succeed end-to-end (plugin loads via CE→EE binding, all 4 SESv2 API enumerations succeed, baseline 2 INFO findings emit correctly, durationMs=842, ZDE invariant preserved).
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
- **Real-AWS smoke-validated** against `operator's internal test infrastructure` paired fixtures (account <operator-test-account>, plugins 1170 v2 + 1180 v1): `findingCount: 21`; CC6.6 → FAIL (8), C1.1 → FAIL (4), CC6.1 → FAIL (2), A1.2 → FAIL (3). Plugin 1180 correctly classifies `redis-secure-cache` (PASS transit + MEDIUM at-rest AWS-owned-default + MEDIUM no-auth + HIGH Multi-AZ disabled + HIGH SnapshotRetention=0 + INFO subnet) + `redis-leaky-cache` (HIGH on transit + at-rest + retention; INFO standalone-not-applicable for Multi-AZ).

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
- **Real-AWS smoke-validated** against `operator's internal test infrastructure` paired fixtures (account `<operator-test-account>`, 4 resources: `sqs-encrypted-queue` + `sqs-cleartext-queue` + `sns-encrypted-topic` + `sns-cleartext-topic`): `findingCount: 0 → 10`; **C1.1 → FAIL (4)**, **CC6.6 → FAIL (4)**, **A1.2 → FAIL (2)**, **CC7.1 → FAIL (2)**. All 10 classifications match ground truth (AWS-managed `alias/aws/sqs` correctly = MEDIUM not PASS; SNS default policy wildcard-Principal-WITH-Condition correctly = HIGH not CRITICAL — institutionally-correct conservative-classifier-discipline emissions).
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
- **Real-AWS smoke-validated** against `operator's internal test infrastructure` paired fixtures (account `<operator-test-account>`): `findingCount: 0 → 6`; A1.2 → FAIL; C1.1 → FAIL.
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
