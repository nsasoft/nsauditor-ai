# NSAuditor AI

**Security Intelligence Without Data Exposure.**

A modular, AI-assisted network security audit platform that scans, understands, prioritizes, and tracks vulnerabilities — without ever requiring your data to leave your infrastructure.

[![npm](https://img.shields.io/npm/v/nsauditor-ai.svg)](https://www.npmjs.com/package/nsauditor-ai)
[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Node.js 20+](https://img.shields.io/badge/node-20%2B-green.svg)](https://nodejs.org)
[![Tests](https://img.shields.io/badge/tests-1308%20passing-brightgreen.svg)](#tests)

---

NSAuditor AI is the open-source core of a privacy-first security intelligence platform built by [Nsasoft US LLC](https://www.nsauditor.com/ai/). It orchestrates 27 specialized scanning plugins against target hosts, fuses their results through an intelligent concluder, and optionally produces AI-powered vulnerability reports — all running entirely on your machine.

**Zero Data Exfiltration by design — and stated precisely.** We never see your scan data: no customer data is collected, transmitted, or stored by Nsasoft US LLC, and the product has no telemetry or phone-home endpoint. Scanning, analysis, license verification and report generation all run on your machine. Two clarifications that matter operationally: AI enrichment is **opt-in** and uses your own API keys (point it at a local Ollama and nothing leaves the host), while **CVE correlation queries NIST's public NVD API by default** — set `NSAUDITOR_OFFLINE_ONLY=1` with a local NVD store to make it fully local, which reports an explicit coverage gap instead of a silent clean.

## What's New

**The 29th Enterprise plugin: Amazon DocumentDB (CE 0.2.48 / Enterprise 0.41.0).** No CE behaviour
change and **the peer floor stays `>=0.2.45`, unraised** — nothing in this cycle needs new Community
Edition code; this bump pairs the npm-frozen page with Enterprise 0.41.0. What Enterprise adds, in
case you run the pair: plugin `1230 AWS DocumentDB Auditor` owns the `docdb` engine on the shared
RDS control plane — storage encryption + KMS custody, TLS enforcement (the `tls` cluster parameter),
audit logging with the CloudWatch export, backup retention, deletion protection, replica/AZ
topology under the CLUSTER lens, and manual-snapshot public/cross-account restorability. It exists
because the seam was measured cutting both ways: DocumentDB clusters were excluded from the RDS
auditor's cluster-config audit (an unencrypted one read CLEAN) while its instances were audited
under RDS semantics with a remediation that cannot succeed on DocumentDB. The RDS auditor now
engine-filters DocumentDB and Neptune off the shared plane, counts the skips, and states in every
report that DocumentDB is delegated to the new plugin and that **a Neptune estate is unaudited** —
a disclosure, not a silence. Plugin count 28 → 29; all eight coverage matrices UNCHANGED.

**Paired release with the Enterprise timestamp-integrity patch (CE 0.2.47 / Enterprise 0.40.3).** No CE
behaviour change and **the peer floor stays `>=0.2.45`, unraised** — nothing in this cycle needs new
Community Edition code. This bump exists because npm freezes a README at publish time, so the page
you are reading can only be corrected by publishing, and it pairs with Enterprise 0.40.3. What
Enterprise fixes, in case you run the pair — all on the **opt-in** RFC 3161 path
(`NSAUDITOR_TSA_URL`; no default authority): a granted timestamp carries the digest it attests, and
nothing compared it to the digest the request carried — so a replay or a caching proxy could return a
valid timestamp **for a different artifact** and it was written as evidence. It is now refused. And the verification instruction printed on every timestamped compliance report could not be
run: it passed `-queryfile` and `-data` together, which openssl rejects outright with no verdict, and
named a `.tsq` file no pack contains. Timestamping remains **opt-in** (`NSAUDITOR_TSA_URL`; no default
authority). ⚠️ **If you have timestamped packs produced before Enterprise 0.40.3, the fix is not
retroactive** — re-verify them with `openssl ts -verify -in <file>.tsr -data <file> -CAfile <bundle>`,
and note that a `.tsr` which fails there was never a valid timestamp for that artifact.

**Paired release with the Enterprise evidence-integrity patch (CE 0.2.46 / Enterprise 0.40.2).** No CE
code change — this publish exists because npm freezes this README at publish time: it delivers the
page corrections made since 0.2.45 (the eighth framework was missing from four places on this page;
the Activation section taught a stale form) and pairs the page with Enterprise 0.40.2. The Enterprise
half of the pair is an evidence-integrity fix to the **opt-in** RFC 3161 timestamping path
(`NSAUDITOR_TSA_URL`, no default authority): a Time-Stamp Authority **rejection** is now refused
rather than mistaken for a valid timestamp, recorded with one of five named reason codes in the
chain-of-custody envelope. The TSA policy-OID option also works on OpenSSL ≥ 3.0 hosts for the first
time (`-tspolicy` attempted, legacy `-policy` fallback), and internal `(Dim N)` dimension codes are
out of customer-facing GCP finding prose. **Peer floor unchanged: Enterprise requires CE ≥ 0.2.45,
which 0.2.46 satisfies.**

**The eighth compliance framework: NIST SP 800-171 Rev 2 (CE 0.2.45 / Enterprise 0.40.0).** Enterprise adds `--compliance nist-800-171`, and CE registers the stem so the MCP `scan_cloud` tool and the CLI accept it. ⚠️ **Requires CE ≥ 0.2.45** — CE 0.2.44 does NOT carry the stem, so an Enterprise 0.40.0 paired with an older CE will reject the framework name. What Enterprise produces is **evidence substrate an assessor reads**, scoped as *NIST SP 800-171 evidence substrate for CMMC Level 2 preparation*: it is **not** a CMMC certification, **not** a FedRAMP authorization, and it emits **no** MET/NOT MET determination and **no** SPRS score — those are a C3PAO's to make, and only a C3PAO's. All 110 Rev 2 requirements are enumerated with a written reason each; Rev 2 is pinned deliberately, because CMMC assesses Rev 2 by rule and Rev 3 is a different 97-requirement universe.

**`scan_cloud` stops naming a provider roster it cannot derive (CE 0.2.44 / Enterprise 0.39.0).** Paired with Enterprise 0.39.0 — **no CE scanning behaviour change, and the peer floor stays `>=0.2.43`, unraised.** The one thing that moves here is model-facing and npm freezes it, which is why it needs its own publish: the MCP `scan_cloud` tool description used to tell an assistant that *only the AWS plugins declare their capability boundaries; Azure and GCP declare none.* Enterprise 0.39.0 falsifies that — its seven GCP and Azure plugins now declare theirs — and a sentence read on every scan cannot be allowed to go stale on a peer's release. It is rewritten to state the invariant that is true in BOTH states and that CE can actually stand behind: **not every plugin declares its capability boundaries, so `deferredScope` bounds only what the DECLARING plugins state and is never a coverage inventory** — an empty or short list is not a claim of full coverage. CE floats over a peer RANGE and cannot derive Enterprise's plugin roster, so any sentence that counted providers was a claim it had no way to check. Also here: the edition-comparison chart gains the Ed25519 evidence-pack signing row, carrying its permanent scope in-sentence — one framework's envelope and the artifacts it enumerates, an operator-held key, never a vendor attestation. **And a second fix, found by trying to USE the previous release's headline:** `compliance sign-pack` and `compliance verify-pack` dispatched correctly but were **absent from `nsauditor-ai help`** for the whole of 0.2.43 — documented in every README, changelog and design record, and missing from the one surface a user actually reads. Both now carry usage blocks, and a guard derives the dispatched verb set from the dispatch site and asserts help/dispatch equality in both directions, so a reachable-but-undiscoverable command fails the build.

**The pack-signing commands land in the CLI — reachable, and not yet proven at that release (CE 0.2.43 / Enterprise 0.38.0).** ⚠️ **Correcting this entry's own words: that gate has since RUN.** On 2026-08-17 it ran against the published EE 0.38.0 registry bytes and passed, so evidence-pack signing is PROVEN for an operator-held key over one framework's envelope and the artifacts it enumerates, never a vendor attestation. `nsauditor-ai compliance sign-pack --manifest <envelope>` signs a chain-of-custody envelope with an operator-held Ed25519 key; `compliance verify-pack` establishes authorship from it — via `--registry` (your identity registry, with revocation and validity checked **as at signing time**) or `--public-key` (which discloses in its own output that those checks did not run). Both are thin forwards: Enterprise owns every decision and refusal, CE contributes the flags and the exit code. **Verify does more than the signature** — it recomputes every `artifacts[].sha256` against disk, so a signed pack whose report was edited returns a failure with the signature still reading VERIFIED. Exit **0** verified · **1** a violation · **2** the run could not measure, and the third is never a failure. Requires the Enterprise package; an auditor can also verify offline with `openssl` and nothing of ours, because the exact signed bytes ship beside the signature. **⚠️ Also a correction affecting 0.2.42/0.37.0:** a **gzipped** KEV/EPSS store — the default shape, since FIRST distributes EPSS only as `.csv.gz` — loaded with ZERO entries, so every finding reported *no store* rather than an exploit band. Misdiagnosis and silent degradation, **not** a false security verdict: findings carried a visible no-store marker throughout. Compression is now decided by file content rather than by filename.

**The `feed` commands: offline CVE data can be hand-carried (CE 0.2.42 / Enterprise 0.37.0).** `nsauditor-ai feed bundle` merges the NVD feed files you downloaded on a connected host into one portable archive; `feed import` reads one into the offline store on an isolated host — delivered as a **restricted** distribution rather than a public `npm install`, and amd64 only. The implementations are Enterprise-side (**requires `@nsasoft/nsauditor-ai-ee` >= 0.37.0**); the commands, flags and usage text are here, because this is the package with the `bin`. Optional `--kev` / `--epss` carry **your own** downloads from CISA and FIRST inside the archive, and `--extras-dir` places them on import and prints the environment lines to set — **no exploit data ships with either package**. `bundle` bundles the FEEDS YOU DOWNLOADED, never "your database": the offline store is a lossy derivation of an NVD feed and cannot be turned back into one. Import now names **why** it skipped records — about a quarter of a real NVD year file is skipped by design (withdrawn CVEs, entries with no CPE data) and a bare `skipped 9353` reads as data loss; malformed records are called out separately because those are **not** expected. ⚠️ **A bundle is integrity-checked, not authenticated** — the recorded SHA-256 detects alteration in transit but cannot establish authorship, because it travels inside the archive it covers. Also here: **`--flag=value` is now refused by name** instead of being parsed as a valueless flag with the value discarded, which made `--severity=high` run a default-severity scan and report success — a wrong answer that looked like a right one; and the **mDNS module-shape fallback was a TDZ self-reference**, so it never once fell back. **The air-gap delivery claims are earned back at this release**, with two conditions that travel with them: the dependency-complete bundle is a **restricted** distribution rather than a public install, and it is **amd64** only — no arm64 image is published.

**The compliance report now verifies the signatures it renders (CE 0.2.41 / Enterprise 0.36.0).** Paired with Enterprise 0.36.0 — **no CE behaviour change; the peer floor stays `>=0.2.40`, unraised, because nothing in this cycle needs new CE code.** Enterprise-side, a registry member may now carry the approver's public key beside its fingerprint, and when it does, every suppression signature in a compliance report is cryptographically checked — the Ed25519 suppression-signing capability this exercises is **proven as of Enterprise 0.36.0**, its verification gate having run against the published bytes and passed with a tamper negative control, and verified for approvers whose registry entry carries **key material**. Verdicts name the exact bytes they verified, a revoked key's bytes are still checked so signing-after-revocation becomes a cryptographic finding, and a MISSING verdict reads "not checked" rather than "failed" — a report must not accuse an operator of forgery for not having migrated. **Ed25519 suppression signing was `not yet proven` when this shipped**: it shipped the code that made the verification gate satisfiable, and that gate then passed at Enterprise 0.36.0.

**The suppression-approval commands land in the CLI (CE 0.2.40 / Enterprise 0.35.0).** `compliance suppress | review | renew | keygen` are new subcommands — thin forwards, the same discipline `compliance attest` established: Enterprise owns validation, defaults, the signing decision and every refusal; CE contributes flags and an exit code. `keygen` writes an approval keypair for a capability that was not yet proven at that release — Ed25519, private half `0600` — and prints an identity-registry member to paste, refusing to overwrite an existing signing key — regenerating one makes every signature it ever produced unverifiable, and nothing reports that until an auditor checks an archived approval. `suppress` signs the approval it writes when `NSAUDITOR_SIGNING_KEY` names a local Ed25519 key, and a malformed key fails at the command with nothing written. `renew` warns that renewing a signed approval invalidates its signature, because the expiry and the renewal record are inside the signed payload. Ed25519 suppression signing was thereby reachable and, **at that release, not yet proven** — its verification gate had not run against published bytes. It passed at Enterprise 0.36.0.

**Exploit intelligence lands in Pro, and a risk-score claim gets corrected here (CE 0.2.39 / Enterprise 0.34.0).** Paired with Enterprise 0.34.0 — **no CE behaviour change.** Enterprise findings that carry CVEs are now joined by CVE-ID against a local **CISA KEV** catalog and a local **FIRST EPSS** scores file, banded and ordered exploit-first, so a KEV-listed MEDIUM outranks an unexploited CRITICAL. Both stores are **operator-populated — no feed data ships** — and fail closed when stale, so an out-of-date catalog never reports "not exploited". The CE-side change is a correction this README owed you: *"a composite risk score (severity × exploitability × impact × exposure)"* described inputs the code never had. It computes **CVSS weighted by verification status, with an uplift for initial-access techniques**, and that is what it now says. `prioritize()` in the documented FindingQueue sorts by **severity rank alone** — the exploit-aware ordering is Enterprise-side. Community Edition scanning, plugins and output are unchanged.

**The opt-in RFC 3161 register stops understating itself (CE 0.2.38 / Enterprise 0.33.1).** Paired with Enterprise 0.33.1 — **no CE behaviour change; wording only, and it is the wording npm freezes.** Trusted timestamping is opt-in, became operator-configurable in 0.33.0, and has since been proven end to end against a real Time-Stamp Authority twice over: on the npm path, and separately from inside the published Marketplace container image. Six places in this README still told you the container leg was unverified. They now state what is true — **RFC 3161 timestamping is opt-in via `NSAUDITOR_TSA_URL`, with no default ever and an outbound call to the authority you name** — and keep the one caveat that survives: retained images at `:0.32.11` and earlier carry no `openssl` at all, so nothing here speaks for them. **Ed25519 suppression signing was unchanged at that release and still not reachable then** — it became reachable in EE 0.35.0 via `compliance suppress` and is **proven as of EE 0.36.0**, verified for approvers whose registry entry carries **key material**.

See **[CHANGELOG.md](./CHANGELOG.md)** for the full per-release history.

→ See a sample EE scan output: **[walk-through with synthetic Acme Corp AWS account](https://www.nsauditor.com/ai/docs/sample-scan/)** (no signup required)

---


## What It Does

```
Scan → Analyze → Prioritize → Track → Act
```

- **27 scanner plugins** probe networks across ICMP, TCP, UDP, HTTP, TLS, SNMP, DNS, SMB, RPC, mDNS, UPnP, WS-Discovery, MCP (Model Context Protocol), and more
- **Smart result fusion** — the Result Concluder merges all plugin outputs into a normalized view with OS detection, service fingerprinting, and evidence linking
- **Structured finding format** — all findings use a common schema with category, severity, evidence, and remediation — enabling consistent SARIF export and MCP integration
- **AI-powered analysis** — send redacted scan results to OpenAI or Claude (your keys, your choice) for vulnerability assessments and remediation guidance
- **Risk-scored prioritization (Pro)** — findings carry a composite risk score (CVSS weighted by verification status, with an uplift for initial-access techniques) and a status field, and an operator suppression workflow (accepted-risk / false-positive with expiry) keeps triaged findings out of the report until they expire
- **Continuous monitoring (CTEM)** — watch mode rescans on a schedule, diffs against previous results, and fires webhook alerts on changes
- **MCP integration** — expose scanning tools to AI assistants like Claude Code via Model Context Protocol
- **CI/CD ready** — SARIF output with `--fail-on` severity gating for pipeline integration

## Editions

NSAuditor AI is available in three editions: Community (free, MIT-licensed, no restrictions), Pro ($49/mo), and Enterprise ($2k+/yr).

### Why upgrade to Enterprise?

If you're heading into a **SOC 2, HIPAA, NIST CSF 2.0, PCI DSS, ISO 27001, CIS Controls v8, GDPR Article 32, or NIST SP 800-171 / CMMC Level 2 audit** — or need to satisfy customer security questionnaires citing those frameworks, or an IG1 attestation for cyber-insurance renewal — Enterprise turns scan output into **auditor-ready evidence packs** that pass institutional scrutiny:

- ☁️ **29 enterprise plugins — 28 cloud auditors across AWS / Azure / GCP, plus **`1023 Zero Trust Assessment`**, which scores zero-trust posture (segmentation, encryption-in-transit, identity, lateral-movement risk) from a **network-host** scan** — find the configuration risks an auditor will flag, before they do (CloudTrail integrity, KMS custody, S3 Object Lock, IAM shadow-admin paths, GCP IAM impersonation chains, Azure RBAC sprawl, and more)
- 📋 **8 compliance frameworks shipped** — generate any combination from a single scan:
  - **SOC 2** (AICPA TSC 2017) — 10 fully-covered + 4 partial controls
  - **HIPAA Security Rule §164.312** — 7 covered + 3 partial Technical Safeguards; **Zero BAA required** (ePHI never leaves your infrastructure)
  - **NIST CSF 2.0 Core** (NIST CSWP 29, Feb 2024) — 13 covered + 10 partial Subcategories across 106 of CSF 2.0's 107 Subcategories; Subcategory-level mapping (auditor-canonical, not high-level Function/Category claims)
  - **PCI DSS v4.0.1** (PCI SSC, June 2024 errata; v3.2.1 retired March 31, 2024) — **19 covered + 9 partial + 39 OOS sub-requirements across 67 of ~250 (MVP-67)**; sub-requirement-level mapping for QSA Report on Compliance workflow; Defined-vs-Customized Approach discipline per Appendix E (15 Defined-only sub-requirements enforced at schema layer); CHD Scope operator-attested via CDE Data Flow Diagram per Req 1.2.4; Card-brand AOC enforcement priority view (Visa CISP / Mastercard SDP / Amex DSOP / Discover DISC)
  - **ISO/IEC 27001:2022** (ISO + IEC, Oct 2022; 2013 edition retired Oct 31, 2025) — **17 covered + 14 partial + 62 OOS across 93 Annex A controls** (the complete Annex A universe); per-Annex-A-code mapping auditor-canonical for ISO/IEC 17021-1 certification body assessors; Statement of Applicability per Clause 6.1.3.d discipline + ISMS Clauses 4-10 OOS-by-design with 7 Major Nonconformity classes
  - **CIS Critical Security Controls v8** (CIS, May 2021; v8.1 errata June 2024) — **17 covered + 23 partial + 113 OOS across 153 Safeguards / 18 Controls**; per-Safeguard mapping with the **Implementation Group cumulative discipline** (IG1=56 cyber-insurance baseline / IG2 cumulative=130 / IG3 cumulative=153); no-certification-body attestation discipline (INPUT to your CSAT / CIS-CAT Pro self-attestation, never "CIS certified"); Cloud Companion Guide v8 shared-responsibility + CIS-Hardened-Image substrate-evidence credit (4.1/4.2/4.6)
  - **GDPR Article 32 (Security of Processing)** (Regulation (EU) 2016/679) — **4 covered + 5 partial + 2 OOS across 11 Art. 32 sub-measure units**; **GDPR Article 32 infrastructure substrate only — NOT GDPR compliance** (GDPR is a 99-article legal regime; Art. 32 security-of-processing is the only article an infrastructure scanner can substrate-evidence; the rest is operator-side, out of scope by design). Four-factor proportionality (substrate *for* your "appropriate to the risk" determination, never an absolute pass/fail); personal-data-scope attestation (pair with your Art. 30 records of processing); **Art. 83(4) lower fine tier** (€10M/2%, not the €20M/4% headline tier); Art. 32(3)/Art. 42 cloud-provider certification-inheritance
  - **NIST SP 800-171 Rev 2** (NIST, Feb 2020; the baseline CMMC assesses by rule) — **2 covered + 49 partial + 59 OOS across all 110 requirements**, claimed at the SP 800-171A determination-statement level. ⚠️ This is EXAMINE-method evidence substrate for **CMMC Level 2 preparation** — not a CMMC certification, not a FedRAMP authorization, and it emits no MET/NOT MET determination and no SPRS score; each of those is a C3PAO's to make.
- 🔐 **Evidence with a verifiable chain of custody** — SHA-256 sidecars on every artifact, verifiable offline. RFC 3161 trusted timestamps are **opt-in since EE 0.33.0** via `NSAUDITOR_TSA_URL`, require an outbound call to the authority you name plus the `openssl` binary, and were exercised against a live Time-Stamp Authority on the npm path on 2026-08-07: the auditor procedure `openssl ts -verify` returned OK, with a one-byte-mutated copy returning FAILED as the control. The `:0.33.0` Marketplace image is proven too: on 2026-08-08 the same round-trip was driven from inside the pushed image against a real authority, verified with the image’s own `openssl`. **Retained images at `:0.32.11` and earlier carry no `openssl` at all**, so nothing here speaks for them. **Ed25519 suppression signing became reachable in EE 0.35.0 via `compliance suppress`** and is **proven as of EE 0.36.0 for approvers whose registry entry carries key material** — a shipped entry point signs, and a one-character length-preserving tamper makes the report render `signature FAILED verification`. A fingerprint-only registry entry reads `not checked by this report`, which records that no check ran and never that one failed.
- 🏛️ **Zero Data Exfiltration architecture** — no scan data is collected, transmitted, or stored by Nsasoft; reports are written to your local disk. Air-gapped operation once configured for it (`NSAUDITOR_OFFLINE_ONLY=1` plus a local NVD store; a default run queries NIST's public CVE API). AI analysis happens locally (Ollama) or via your own API keys. Important for PCI DSS CDE-isolation threat models.
- 🔗 **GRC connectors — Vanta + Drata + Secureframe (Enterprise)** — map compliance findings to your GRC platform's evidence/test records and push them at **scan time** (opt-in). Suppression-aware outcome mapping (Vanta) / structured records (Drata + Secureframe), idempotent retries, rate-limit handling, token redaction, and Zero-Data-Exfiltration egress redaction. Early-access, single-workspace; live validation against production tenants is in progress. See **[GRC Connectors](#grc-connectors-vanta-drata-secureframe)** below.
- 🗄️ **WORM posture VALIDATION** — we read your bucket's S3 Object Lock configuration per CloudTrail trail bucket and fail the control when it is absent, in GOVERNANCE mode or under-retained. That is substrate FOR a SEC Rule 17a-4(f) / FINRA 4511 retention claim, not the claim itself: the engine WRITING artifacts into the immutable store is built and **not reachable** (no caller), so the retention guarantee stays yours to make about your own archive
- 📊 **SLA / MTTR tracking + recurring-scan attestation** — the **Type II operating-effectiveness evidence** auditors actually demand (not just point-in-time snapshots)
- 🎯 **14 adversarial-audit Claude Code skills** authored per the Per-Framework Adversarial-Audit Skill Pairing institutional pattern — Phase-4 Compliance/GRC chain 9-of-9 COMPLETE for all shipped frameworks (SOC 2 + HIPAA + NIST CSF + PCI DSS + ISO 27001 + CIS Controls v8 + GDPR Article 32 + NIST SP 800-171 + GRC connector)

→ **[See sample EE scan output](https://www.nsauditor.com/ai/docs/sample-scan/)** — full evidence pack against synthetic Acme Corp AWS account (no signup required)
→ **[Buy NSAuditor AI Enterprise Edition](https://www.nsauditor.com/ai/pricing/)** — $2k / $5k / $10k+ per year for 5 / 25 / unlimited seats + custom SLA. Onboarding call included.

### Prefer to buy through AWS Marketplace?

Enterprise Edition is also available as an **[AWS Marketplace container listing](https://aws.amazon.com/marketplace/pp?sku=etar8knc8dx7bshizrrnnjbzi)** — same product, same local ES256 license key, billed through your AWS account (consolidated billing / EDP drawdown, procurement-friendly; custom Enterprise terms via AWS Private Offers). *The listing is public. If it doesn't resolve in your AWS region or account, [contact us](https://www.nsauditor.com/support.html) and we'll extend a Private Offer directly.*

How Marketplace fulfillment works (ZDE and air-gap preserved — no runtime AWS dependency at scan time):

1. **Subscribe** on the listing (tiers `base` / `growth` / `scale` mirror the 5 / 25 / unlimited-seat plans).
2. **Register** your email + AWS account ID at the URL shown in the listing's usage instructions — your **ES256 license key arrives by email**.
3. **Pull and run** the Docker image from the Marketplace registry (commands in the listing's usage instructions and your license email) with `NSAUDITOR_LICENSE_KEY=<your key>`. One tier-agnostic image — upgrades are just a new license key, never a new image. The container runs fully offline after that; billing lives in AWS, enforcement is your local key.

### Feature comparison

| | Community (Free) | Pro ($49/mo) | Enterprise ($2k+/yr) |
|---|:---:|:---:|:---:|
| **Network scanning** | | | |
| 27 scanner plugins (SSH, HTTP, TLS, DNS, SMB, RPC, mDNS, etc.) | ✅ | ✅ | ✅ |
| AI analysis (OpenAI, Claude, Ollama — your keys) | ✅ basic | ✅ enriched | ✅ enriched |
| Structured findings + SARIF + CSV export | ✅ | ✅ | ✅ |
| CTEM watch mode | ✅ basic | ✅ advanced | ✅ advanced |
| **Pro features (vulnerability assessment)** | | | |
| CVE matching + MITRE ATT&CK mapping | — | ✅ | ✅ |
| Risk scoring + prioritization | — | ✅ | ✅ |
| Exploit intelligence — **CISA KEV** + **FIRST EPSS** joined onto the CVE matches, exploit-first ordering (a KEV-listed MEDIUM outranks an unexploited CRITICAL); stores are operator-populated — no feed data ships | — | ✅ | ✅ |
| Parallel analysis agents | — | ✅ | ✅ |
| **Enterprise — cloud scanning** | | | |
| 29 enterprise plugins — 28 cloud (AWS / Azure / GCP) + 1 network-scan zero-trust check | — | — | ✅ |
| Zero Trust assessment | — | — | ✅ |
| **Enterprise — compliance (8 frameworks)** | | | |
| SOC 2 (AICPA TSC 2017) — 10 covered + 4 partial controls | — | — | ✅ |
| HIPAA Security Rule §164.312 — Zero BAA required | — | — | ✅ |
| NIST CSF 2.0 Core — Subcategory-level mapping (106 of 107 Subcategories) | — | — | ✅ |
| PCI DSS v4.0.1 — Sub-requirement-level mapping for QSA RoC (MVP-67) | — | — | ✅ |
| ISO/IEC 27001:2022 — per-Annex-A-code mapping + SoA discipline (93 Annex A controls) | — | — | ✅ |
| CIS Critical Security Controls v8 — per-Safeguard mapping + IG-cumulative discipline (153 Safeguards / 18 Controls) | — | — | ✅ |
| **GDPR Article 32 (Security of Processing)** — Art. 32 infrastructure substrate (4 covered + 5 partial + 2 OOS / 11 sub-measure units); **not GDPR compliance** · Art. 83(4) lower fine tier | — | — | ✅ |
| **NIST SP 800-171 Rev 2** — evidence substrate for **CMMC Level 2 preparation**; all 110 Rev 2 requirements enumerated (2 covered + 49 partial + 59 OOS). **Not a certification, not a FedRAMP authorization, no MET/NOT MET verdict, no SPRS score** | — | — | ✅ |
| Multi-framework `--compliance soc2,hipaa,nist-csf,pci-dss,iso-27001,cis-v8,gdpr,nist-800-171` from one scan | — | — | ✅ |
| **Enterprise — auditor-grade evidence** | | | |
| Evidence packs with SHA-256 chain-of-custody (RFC 3161 timestamps opt-in via `NSAUDITOR_TSA_URL`, exercised against a live TSA on both the npm path and the `:0.33.0` container image; retained images `:0.32.11` and earlier carry no `openssl`) | — | — | ✅ |
| Suppression workflow with approver identity verification (Ed25519 SIGNING reachable 0.35.0, proven 0.36.0, verified per approver holding **key material**) | — | — | ✅ |
| **Ed25519 evidence-pack signing** — `compliance sign-pack` signs the chain-of-custody envelope at an approval station with an **operator-held** key, so the scanning fleet stays keyless and authorship is relative to your own key custody, never a vendor attestation. `compliance verify-pack` establishes authorship from that operator-held key and re-hashes every artifact the envelope names, covering one framework envelope and the artifacts it enumerates — not the pack, not the directory. Verifiable offline with `openssl` alone. | — | — | ✅ |
| Chain-of-custody manifests | — | — | ✅ |
| SLA / MTTR tracking + compensating controls | — | — | ✅ |
| Recurring-scan attestation (Type II operating-effectiveness) | — | — | ✅ |
| WORM POSTURE VALIDATION on your own buckets (S3 Object Lock — SEC 17a-4 / FINRA 4511 substrate). The engine WRITING into the immutable store is built, **not reachable** | — | — | ✅ |
| **Enterprise — integration + deployment** | | | |
| GRC connectors — Vanta + Drata + Secureframe push (scan-time, opt-in) | — | — | ✅ |
| Tabletop simulation + SIEM correlation — built, **not reachable** (no caller) | — | — | 🚧 |
| Air-gapped **operation** once installed — offline licence validation (local ES256, no callback, every tier) and offline CVE matching under `NSAUDITOR_OFFLINE_ONLY=1`, which is the **Pro** intelligence engine. The `feed bundle` / `feed import` hand-carry pipeline (EE 0.37.0) moves the NVD feeds **you downloaded**; it needs the Enterprise **package** installed but is not licence-gated, so a Pro licensee can run it. | — | ✅ | ✅ |
| Air-gapped **DELIVERY** — the dependency-complete offline installation tarball, install script and checksums (EE 0.37.0), distributed **restricted**, amd64 only. No container image bundle ships and arm64 images remain WITHDRAWN. | — | — | ✅ |

**This repository is the Community Edition** — fully functional, MIT-licensed, no restrictions, no telemetry. Pro and Enterprise features ship via the [`@nsasoft/nsauditor-ai-ee`](https://www.nsauditor.com/ai/pricing) package and install alongside the CE binary once licensed.

→ **[Get Pro or Enterprise →](https://www.nsauditor.com/ai/pricing/)**

---

## GRC Connectors (Vanta, Drata, Secureframe)

*Enterprise feature. Requires `@nsasoft/nsauditor-ai-ee`.*

Every compliance scan already produces a GRC-ready JSON evidence artifact. The **GRC connectors** take the next step: they map each NSAuditor compliance finding to your GRC platform's own evidence/test records and **push them at scan time** — so your Vanta, Drata, or Secureframe workspace reflects the latest cloud posture without a manual export/import round-trip.

**Opt-in, and Zero-Data-Exfiltration by default.** The push is off unless you set the environment variables below. When it runs, egress is redaction-gated: resource identifiers can be hashed or removed, the persisted audit log stores a body **fingerprint** (never the raw payload), and your API token is never written to any artifact. Nothing leaves your infrastructure that you didn't opt into.

```bash
# Enable the scan-time push (Enterprise)
COMPLIANCE_GRC_PROVIDER=vanta        # or: drata | secureframe
COMPLIANCE_GRC_TOKEN=<your API key>  # never serialized to artifacts
# Optional:
# COMPLIANCE_GRC_REDACTION=hash      # off | hash | remove  (egress identifier redaction)
# COMPLIANCE_GRC_CONTROL_MAP=/path/to/config.json  # provider config: Vanta control→test map, Drata connection ({connectionId, resourceId, schemaMap}), or Secureframe ({workspaceId, collectionId, schemaMap})
```

| Platform | Status | Model |
|---|---|---|
| **Vanta** | Connector + scan-time activation shipped | Maps findings to Vanta test results; suppression-aware outcome mapping (pass / fail / passed-with-compensating-control), framework-dimensioned idempotency keys, retry with rate-limit backoff, circuit breaker |
| **Drata** | Connector library shipped | Pushes structured records via Drata **Custom Connections**; your Drata **Test Builder** rules (Advanced/Enterprise plans) evaluate them — the connector delivers evidence, your rules do the evaluation |
| **Secureframe** | Connector library shipped (early-access) | Pushes structured records to a workspace evidence collection; **your** Secureframe rules evaluate them — the connector carries the control `status` verbatim, it does not compute pass/fail. API shape published-assumed; live-tenant validation deferred (partner intake) |

**Reliability + audit-integrity built in:** idempotent retries (a network-timed-out push won't create duplicate records), per-attempt + total-duration timeout caps, a consecutive-failure circuit breaker, token redaction across every log and error path, and a durable per-control push audit log written next to your scan artifacts.

> **Honest status.** The Vanta, Drata, and Secureframe connectors are shipped, opt-in, and covered by an extensive test suite. **Live validation against production Vanta / Drata / Secureframe tenants is in progress** as partner onboarding proceeds — until it completes, treat production use as early-access and validate against your own tenant first. This is a single-workspace, operator-configured connector; it is not a multi-tenant managed sync. (Secureframe's API shape is published-assumed pending partner intake; its idempotency keys are SENT but vendor-side dedup is unverified.)

---

## Quick Start

```bash
# Install globally
npm install -g nsauditor-ai

# See all flags, subcommands, and worked examples
nsauditor-ai --help

# Configure (optional — scans work fully offline without AI)
cat > .env << 'EOF'
AI_ENABLED=true
AI_PROVIDER=ollama              # openai | claude | ollama
OLLAMA_MODEL=llama3             # For local AI (no API key needed)
# OPENAI_API_KEY=sk-...         # Or use OpenAI
# ANTHROPIC_API_KEY=sk-ant-...  # Or use Claude
OPENAI_REDACT=true
EOF

# Scan a host with all plugins
nsauditor-ai scan --host 192.168.1.1 --plugins all

# Scan a subnet in parallel
nsauditor-ai scan --host 192.168.1.0/24 --plugins all --parallel 10

# Start the MCP server for AI assistants
nsauditor-ai-mcp
```

Or run without installing:

```bash
npx nsauditor-ai scan --host 192.168.1.1 --plugins all
```

Or clone and run from source:

```bash
git clone https://github.com/nsasoft/nsauditor-ai.git
cd nsauditor-ai
npm install
node --env-file=.env cli.mjs scan --host 192.168.1.1 --plugins all
```

Results land in `./out/<host>_<timestamp>/`:

| File | Contents |
|---|---|
| `scan_conclusion_raw.json` | Full unredacted conclusion (admin reference) |
| `scan_conclusion_raw.html` | Admin RAW HTML with filters and full detail |
| `scan_response_ai_payload.json` | Redacted payload sent to AI |
| `scan_response_ai.json` | Raw AI API response |
| `scan_response_ai.txt` | AI conclusion (markdown) |
| `scan_response_ai.html` | Styled HTML report with CVE links and badges |
| `scan_results.sarif.json` | SARIF 2.1 — only with `--output-format sarif` (renamed `scan_<host>.sarif.json` for multi-host runs) |
| `scan_results.csv` | CSV — only with `--output-format csv` |
| `scan_report.md` | GitHub-flavored Markdown report — only with `--output-format md` (or `markdown`) |

> Works on Node 20+ (tested on Node 22).

---

## Plugins

### Core Scanners

| ID | Name | Protocols | Purpose |
|---|---|---|---|
| 001 | Ping Checker | ICMP/ARP | Reachability + TTL-based OS hints |
| 002 | SSH Scanner | TCP:22 | Banner, version fingerprinting, timeout policy |
| 003 | Port Scanner | TCP/UDP | Bulk open port detection (populates context for downstream plugins) |
| 004 | FTP Banner Check | TCP:21 | FTP daemon version detection |
| 005 | Host Up Check | TCP/UDP | Quick multi-probe reachability confirmation |
| 006 | HTTP Probe | TCP:80/443 | Headers, server token, vendor hints |
| 007 | SNMP Scanner | UDP:161 | sysDescr, OIDs, serial/hardware/firmware extraction |
| 008 | Result Concluder | Meta | Fuses all plugin outputs (always runs last) |
| 009 | DNS Scanner | TCP/UDP:53 | `version.bind` CHAOS/TXT + A record lookup |
| 010 | Webapp Detector | HTTP | Technology stack fingerprinting via wappalyzer |
| 011 | TLS Scanner | TCP:443+ | TLS version + cipher enumeration per port |
| 012 | OpenSearch Scanner | HTTP:9200+ | OpenSearch/Dashboards version + Linux/Node.js hints |
| 013 | OS Detector | Meta | Derives distro/OS from all prior banners with TTL fallback |
| 014 | NetBIOS Scanner | UDP:137/TCP:445 | NetBIOS/SMB enumeration + SMB2 null session probe |
| 015 | SUN RPC Scanner | TCP/UDP:111 | RPC portmapper service discovery (NFS, mountd) |
| 016 | WS-Discovery | UDP:3702 | Multicast device discovery with XML metadata |
| 024 | TCP SYN Scanner | TCP (Nmap) | SYN half-open scan via Nmap wrapper (optional) |
| 040 | TLS Certificate & Cipher Auditor | TCP:443+ | Cert expiry, chain integrity, hostname mismatch, weak ciphers, deprecated protocols, key strength |
| 050 | TRIBE v2 Neural API Security Probe | TCP/HTTP:8080 | Debug leak detection, stack traces in errors, header security, CORS misconfiguration, unauthenticated routes |
| 060 | DNS Security Auditor | DNS/UDP:53 | SPF/DKIM/DMARC, dangling CNAMEs, DNSSEC, NS delegation, zone transfer exposure, MX security, CAA records |
| 070 | MCP Scanner | TCP/HTTP+SSE | Detects MCP (Model Context Protocol) servers on candidate ports (1967, 3000, 3005, 5173, 6274, 6277, 8000, 8090). Audits for cleartext transport (HTTP not HTTPS), missing/anonymous auth, anonymous tool enumeration, deprecated protocol versions, and Inspector exposure on non-loopback. Maps findings to CWE/OWASP/MITRE per the FindingSchema. STDIO-transport MCP servers are out of scope (no network port). |

### Discovery Plugins

| Name | Purpose |
|---|---|
| ARP Scanner | MAC resolution + OUI vendor lookup + OS hints |
| mDNS/Bonjour Scanner | Local service discovery + friendly names from TXT records |
| UPnP/SSDP Scanner | Device discovery + description XML parsing |
| DNS-SD Scanner | DNS Service Discovery announcements |
| LLMNR Scanner | Link-local multicast name resolution |
| DB Scanner | Database service detection (MySQL, PostgreSQL, Redis, etc.) |

### Pro/Enterprise Plugins (via @nsasoft/nsauditor-ai-ee)

**29 enterprise plugins: 28 cloud auditors across AWS, GCP and Azure substrate, plus **`1023 Zero Trust Assessment`**, which scores zero-trust posture (segmentation, encryption-in-transit, identity, lateral-movement risk) from a **network-host** scan** — all mapped to AICPA Trust Services Criteria 2017 (10 covered + 4 partial controls). EE plugins live in the disjoint 1000+ ID range; CE reserves 001-099. Once licensed, the EE package installs alongside the CE binary and discovers automatically. A cloud `--host` pass auto-scopes on `cloudProvider`, which only the 28 declare, so `1023` never runs on a cloud pass. It runs on a network-host scan with the full plugin set — measured on the shipped CLI, selecting it by id on its own does not work, because it requires the host to be confirmed up by a discovery plugin.

→ **[Watch a sample scan run end-to-end](https://www.nsauditor.com/ai/docs/sample-scan/)** — synthetic Acme Corp AWS account + home-office router. Real real scan output, no signup required. See the transitive SG chain reachability finding, the multi-region GuardDuty audit, the dnsmasq CVE detection, and what the evidence pack actually looks like.

→ **[Buy NSAuditor AI Enterprise Edition](https://www.nsauditor.com/ai/enterprise/)** · $2k / $5k / $10k+ per year · 5 / 25 / unlimited seats · onboarding call included.

**All EE plugins follow the same institutional plumbing pattern:**

- **Thread H `_instrumentSdkClient` wrap** — per-API AccessDenied counter + ZDE structural guard (verb-prefix denylist regex blocks `Get*` / `Retrieve*` / `Read*` value-reading APIs at SDK boundary) + idempotency sentinel
- **Throttle-retry** — exponential-backoff retry on `Throttling*` / `RequestLimitExceeded` / `TooManyRequestsException` with per-command wall-clock budget
- **Thread F `conclude()` field-selection allowlist** — structured-data ZDE: only AWS-public-namespace identifiers + integer counts flow through to findings; customer policy content / key material / encrypted payloads NEVER propagate
- **`conservative_classifier_principle`** — emit INFO+evidenceGap with verification prompt when ARN-shape disambiguation needs a follow-up API call; vacuous PASS on partial substrate evidence is treated as the worst SOC 2 reporting outcome
- **`aws_string_case_normalization`** — trim + lowercase AWS-returned strings at SDK-helper boundary; protects against the 7+ recurrent classes of case-sensitivity fail-open (IAM Condition keys, Lambda runtimes, KMS aliases, Effect/Action discriminators, FULL_ADMIN sentinel, S3 region)

| ID | Name | Tier | What it audits |
|---|---|---|---|
| 1020 | AWS S3 Security | Enterprise | Bucket hardening: public-access block, encryption at rest, versioning, Object Lock COMPLIANCE-mode, MFA Delete, access logging. **CC6.1 / C1.1 / C1.2** |
| 1021 | GCP Cloud Scanner | Enterprise | Firewall rules + IAM bindings + Storage bucket public-access. **CC6.1 / CC6.6 / C1.1** |
| 1022 | Azure Cloud Scanner | Enterprise | NSG rules + RBAC role assignments + Storage account hardening. **CC6.1 / CC6.6 / C1.1** |
| 1023 | Zero Trust Checker | Enterprise | Segmentation, encryption, identity, lateral-movement scoring across the network surface. **CC6.1 / CC6.6** |
| 1024 | GCP Cloud Storage Auditor | Enterprise | Multi-cloud parity sister of plugin 1020 AWS S3. 6 dimensions: bucket-level IAM public bindings (allUsers = CRITICAL, allAuthenticatedUsers = HIGH), Uniform Bucket-Level Access (closes legacy bucket-ACL false-PASS class), Object Versioning, Bucket Lock retention policy (SEC 17a-4 / FINRA 4511 WORM-alignment), CMEK via Cloud KMS (four-tier custody ladder), bucket-level access logging. **CC6.1 / CC6.6 / CC7.1 / C1.1 / C1.2 / A1.2** |
| 1025 | GCP IAM Project-Level Auditor (v2 — EE 0.7.1) | Enterprise | First plugin in the v0.7.x GCP-IAM-deep-audit cohort. Mirrors plugin 1030 AWS IAM Deep Auditor's shadow-admin discipline adapted to the GCP IAM data model. **7 dimensions (EE 0.7.1 v2 expansion):** project-scope public-member bindings (allUsers = CRITICAL, allAuthenticatedUsers = HIGH at the project root), admin-equivalent role inventory across 12 predefined sensitive roles, IAM Conditions classifier on sensitive-role bindings (restrictive CEL = PASS, absent on sensitive = MEDIUM, vacuous = LOW + evidenceGap), **custom-role permission audit** (`*` wildcard = CRITICAL; admin-equivalent permission intersection across 16-entry allowlist = HIGH), **SA key custody** (user-managed long-lived keys = HIGH; 90-day rotation threshold uplift), **SA impersonation graph BFS** (transitive `serviceAccountTokenCreator`/`User`/`OpenIdTokenCreator` chains — 2-hop = HIGH, 3+ hop = CRITICAL; project-scope grants surface independently as CRITICAL), **Organization Policy constraint enumeration** (4 sensitive constraints incl. `iam.disableServiceAccountKeyCreation`). Honors `GOOGLE_IMPERSONATE_SERVICE_ACCOUNT` via `utils/gcp_auth.mjs`. **CC6.1 / CC6.6 / C1.1** |
| 1030 | AWS IAM Deep Auditor | Enterprise | Shadow-admin path detection via BFS over PassRole / AssumeRole / federated trust. Restrictive-Condition allowlist for Auth0 / Okta / Cognito OIDC patterns. **CC6.1** |
| 1040 | AWS CloudTrail Operational Integrity | Enterprise | Trail health + CloudWatch alarm coverage against CIS AWS Benchmark §3.1–3.14 + AWS Config + cross-account S3 trail-destination WORM verification (SEC 17a-4 / FINRA 4511). **CC7.2 / CC7.3** |
| 1050 | AWS API Gateway Assurance | Enterprise | Per-route authz classifier (`NONE`=CRITICAL), custom-domain TLS policy, stage-level access logging + WAF, public-endpoint exposure. Entry-point evidence for serverless deployments. **CC6.1 / CC6.6 / CC6.7 / CC7.1 / A1.2** |
| 1060 | AWS DynamoDB Audit Integrity | Enterprise | First "audit-the-auditor" plugin. PITR + deletion protection + KMS-CMK custody + resource-policy presence + CloudTrail data-event cross-reference. **CC6.6 / CC7.1 / C1.1 / PI1.5** |
| 1070 | AWS KMS Auditor | Enterprise | Per-key rotation + wildcard-Principal classifier across 5 severity tiers (covers `Principal.AWS` / Federated / Service / CanonicalUser + NotPrincipal-Allow + NotAction-Allow + glob actions). **CC6.3 / C1.1** |
| 1080 | AWS Lambda Security | Enterprise | Runtime EOL detection (CRITICAL on `nodejs16.x` / `python3.7` etc.), public function URLs, resource-policy wildcards, env-var secret-name detection (ZDE-safe), VPC config, KMS custody, DLQ. **CC6.1 / CC6.6 / CC7.1 / C1.1** |
| 1090 | AWS Secrets Manager + SSM Parameter Store | Enterprise | Rotation cadence + KMS-CMK custody + SecureString classification + secret-name detection. **ZDE-critical**: never calls `GetSecretValue` / `GetParameter` — metadata only. Verb-prefix denylist blocks `Get*` / `Retrieve*` / `Read*` at the SDK boundary. **CC6.1 / CC6.6 / C1.1** |
| 1100 | AWS CodePipeline + CodeBuild | Enterprise | Source-stage encryption, `privilegedMode` detection, buildspec drift, secrets-via-env vs Secrets-Manager, IAM wildcard-Action, artifact-store encryption, stale-execution detection. **CC6.1 / CC7.1 / CC8.1 / C1.1** |
| 1110 | IAM Effective Decrypt-Path Auditor | Enterprise | Cross-plugin reconciler — walks IAM policies for `kms:Decrypt` / `ReEncrypt*` / `GenerateDataKey` grants and cross-references against KMS key policies to compute the effective decrypt path. Closes the NotAction-implicit-decrypt false-PASS class. **CC6.1 / CC6.6 / C1.1 / C1.2** |
| 1120 | AWS S3 Lifecycle + Cross-Region Replication | Enterprise | Lifecycle policy enumeration + cross-region replication topology. Cross-region destination-bucket reachability check closes silent-PASS where replication FAILED but emitted clean. **C1.1 / C1.2 / A1.2** |
| 1130 | AWS Backup Auditor | Enterprise | The flagship plugin — 12-dimension air-gapped vault attestation arc for `LogicallyAirGappedBackupVault` resources. Audits Plans + Vaults + Recovery Points + Frameworks + Restore Testing + Legal Holds + vault Access Policy. SEC 17a-4 / FINRA 4511 ransomware-defense substrate. **CC6.3 / CC6.6 / CC7.1 / CC8.1 / C1.1 / C1.2 / A1.2** |
| 1140 | AWS RDS Auditor | Enterprise | 10 dimensions: Multi-AZ, storage encryption + KMS custody, parameter-group SSL, backup retention, public accessibility, IAM database auth, snapshot encryption, **pgAudit + SPL cross-check**, CloudWatch Logs exports (engine-dispatched), log retention. **A1.2 / CC6.1 / CC6.6 / C1.1 / CC7.2 / CC7.3** |
| 1150 | AWS SQS/SNS Auditor | Enterprise | 7 dimensions across both services: encryption at rest + KMS custody, transit-encryption policy, topic-policy wildcards (CRITICAL on unconditional + NotPrincipal-Allow), DLQ presence, CloudWatch alarm coverage on `ApproximateAgeOfOldestMessage` + `NumberOfNotificationsFailed`. **C1.1 / CC6.6 / A1.2 / CC7.1 / CC7.2** |
| 1160 | AWS VPC Endpoints / PrivateLink | Enterprise | Endpoint-policy wildcards (CRITICAL on PrivateLink-breaking unconditional), PrivateDNS enabled (silent-bypass class), endpoint state (`failed` = silent failure), type substrate disclosure. **CC6.6 / A1.2 / CC7.2** |
| 1170 | AWS EC2 SG Perimeter | Enterprise | RESTRICTED_PORTS (23 ports per CIS AWS Foundations v3.0) wildcard ingress + IPv6 ::/0 + all-protocol-from-wildcard + orphan SG detection. **SG→SG transitive chain reachability**: BFS from public-CIDR roots through `UserIdGroupPairs` — 2-hop = HIGH, 3+ hop = CRITICAL. Catches the ALB → app → database exposure that per-SG audits silently miss. **CC6.6 / CC6.2** |
| 1180 | AWS ElastiCache Redis | Enterprise | 6 dimensions: transit encryption, at-rest + KMS custody (four-tier ladder), Redis AUTH / IAM user groups (Redis 7+ ACL), Multi-AZ, snapshot retention cadence, subnet placement. Cross-plugin sister to plugin 1170 for cache-tier perimeter. **CC6.1 / CC6.2 / CC6.6 / A1.2 / C1.1** |
| 1190 | AWS SES Email Integrity | Enterprise | 6 dimensions: DKIM enablement + CNAME DNS resolution + key-fingerprint pin, DMARC TXT parsing + alignment classifier, custom MailFrom alignment, config-set TLS enforcement, sending-auth policy wildcards, dedicated IP pool, suppression list (count-only — ZDE invariant: never reads addresses). **CC6.1 / CC6.6 / C1.1 / CC7.1 / Privacy** |
| 1200 | AWS Inspector2 / GuardDuty Enablement | Enterprise | 4 dimensions across all opted-in regions (17+ incl. GovCloud / ISO): GuardDuty Detector + protection features (S3 / EKS / EBS-malware / RDS-login / Lambda / RuntimeMonitoring), Inspector2 enablement, scan-target coverage. Plus alerting-destination dim (EventBridge or SecurityHub) and per-target liveness probes for Lambda / SNS / SQS / IAM / API destination / CloudWatch Logs. **CC7.1 / CC7.2** |
| 1210 | AWS EC2 Instance (**EE 0.13.1**) | Enterprise | Multi-region (DescribeRegions; single-region fallback emits an evidence-gap) EC2 instance audit: IMDSv1 enabled (IMDSv2-only enforcement; hop-limit > 1 container-escape) + EBS volume + account-default encryption + public-IP exposure (incl. IPv6 GUA + secondary-ENI/EIP) + instance-store evidence-gap. **AMI inventory → CIS-Hardened-Image detection** on CIS Safeguards 4.1/4.2/4.6 — the AWS producer; Azure (1022) + GCP (1021) feed the same `cisImageInventory` contract. **CC6.1 / C1.1 / CC6.6** |
| 1220 | Azure Storage Account Data-Protection (**EE 0.13.2**) | Enterprise | Dedicated Azure Storage Account encryption / transit / authorization auditor — orthogonal to the 1022 scanner's network-exposure dims (no double-emission; mirrors the AWS 1020 + 1120 two-plugin S3 split). HTTPS-only transit (`enableHttpsTrafficOnly`) + minimum TLS version + Shared Key authorization (`allowSharedKeyAccess` — bypasses Azure AD; absent = enabled, never silent-PASS) + infrastructure (double) encryption + encryption key source incl. **customer-managed-key reachability + rotation** (`keyVaultProperties` — a disabled/revoked/version-pinned CMK degrades, not silent-PASS). Conservative classifier: indeterminate field / AccessDenied → evidence-gap; single-subscription scope surfaced explicitly. **CC6.7 / CC6.1 / C1.1** |
| 1221 | Azure NSG Perimeter (**EE 0.14.0**; UDP lane **EE 0.14.1**) | Enterprise | The Azure analog of AWS 1170 — a CC6.6 network-segmentation perimeter auditor for Azure Network Security Groups. Evaluates each NSG's inbound rules in Azure priority order (first match wins; DenyAllInbound default): all-protocol public Allow + public-source (`*`/`0.0.0.0/0`/`Internet`) to a restricted **TCP** management/data-tier port (SSH/RDP/MSSQL/MySQL/Postgres/Redis/Mongo/SMB/WinRM/etc.) + `::/0` IPv6-wildcard to a restricted port (the dimension 1022's flat lint misses) + **public-source / `::/0` to a restricted UDP service** (SNMP/CLDAP/NTP/rpcbind/IPMI/IKE/Memcached etc. — Dim 2u/3u, EE 0.14.1) + public→non-restricted INFO + PASS substrate. **Attachment-aware** (attached → CRITICAL effective; orphaned → MEDIUM latent) + effective priority/deny-override resolution + `0.0.0.0/1` split-range coverage. Non-overlapping-by-depth with 1022's coarse per-rule NSG lint. Conservative classifier: denied/indeterminate → evidence-gap; one malformed NSG degrades per-resource. **CC6.6** |
| 1222 | Azure Key Vault Deep Auditor (**EE 0.15.0**) | Enterprise | The third dedicated Azure auditor (after 1220 storage + 1221 NSG) — the KV analog of how 1221 deepens 1022's flat NSG dim. Enumerates each vault's keys, role assignments, and diagnostic settings across 4 dims: (1) key **auto-rotation policy** + (2) key **expiry** (epoch-s/ms/Date/string coerced) + (3) **diagnostic logging → Log Analytics** (`@azure/arm-monitor`) + (4) **privileged-access depth** (RBAC `roleAssignments` admin/data-plane/scope-aware + legacy `accessPolicies` export/wide-crypto breadth). Orthogonal to 1022's vault-property dims (purge/soft-delete/network-ACL/RBAC-mode) — no double-emission. Secret/cert expiry is a deliberate data-plane scope boundary. Conservative classifier: indeterminate field / AccessDenied / arm-monitor absent → evidence-gap; one malformed vault degrades per-resource. **CC6.3 / C1.1 / CC6.1 / CC7.2** |
| 1230 | AWS DocumentDB Auditor (**EE 0.41.0**) | Enterprise | Amazon DocumentDB (MongoDB-compatible) cluster security — owns the `docdb` engine on the shared RDS control plane (plugin 1140 delegates it and discloses Neptune as unaudited). Seven dimensions: storage encryption at rest + KMS custody classification (customer-alias PASS / AWS-managed / foreign-account + key-UUID custody-unverifiable evidence gaps — encryption is fixed at cluster creation, so the emission gives a migration remediation, never an unrunnable in-place one) + `tls` cluster parameter (disabled = HIGH) + `audit_logs` + CloudWatch `audit` export (generating-but-unexported = MEDIUM) + backup retention vs the 7-day floor + deletion protection + replica/AZ availability topology under the CLUSTER lens (the per-instance Multi-AZ flag is RDS semantics and never consulted) + manual-snapshot public/cross-account restorability (`all` = CRITICAL). Non-docdb engines counted and skipped; DocumentDB Elastic clusters declared deferred; per-dimension fail-closed evidence gaps. **C1.1 / CC6.1 / CC6.6 / CC7.2 / A1.2** |
| — | SOC 2 Compliance Engine | Enterprise | AICPA TSC 2017 mapping (10 covered + 4 partial controls), SHA-256 chain-of-custody, opt-in RFC 3161 timestamps, exercised against a live TSA on both the npm path and the `:0.33.0` container image, and the suppression workflow. (Ed25519 SIGNING of suppressions is reachable from EE 0.35.0 and PROVEN at EE 0.36.0, verified per approver holding **key material**.) |
| — | **HIPAA Compliance Engine (EE 0.9.0)** | Enterprise | HIPAA Security Rule §164.312 Technical Safeguards mapping (7 covered + 3 partial + 45 OOS within §164.312 + entire §164.308 + entire §164.310). HHS Required/Addressable discipline per control. Same evidence infrastructure as SOC 2 (SHA-256 chain-of-custody; opt-in RFC 3161 timestamps; suppression signing reachable from EE 0.35.0, proven at EE 0.36.0 and verified per approver holding **key material**). Use `--compliance hipaa` or `--compliance soc2,hipaa` for dual-framework reports from a single scan. **Zero BAA required** — Zero Data Exfiltration architecture means ePHI never leaves customer infrastructure. |
| — | **NIST CSF 2.0 Compliance Engine (EE 0.10.0)** | Enterprise | NIST Cybersecurity Framework 2.0 Core mapping at the auditor-canonical Subcategory level — 13 covered + 10 partial + 83 OOS across 106 of CSF 2.0's 107 Subcategories. Govern function OOS-by-design (GV.SC-04 partial as substrate exception); Respond function OOS-entirely; Implementation Tiers 1-4 OOS as organizational-maturity claims. NIST SP 800-53 Rev. 5 + CIS Critical Security Controls v8 cross-references baked into `informativeReferences`. Use `--compliance nist-csf` or `--compliance soc2,hipaa,nist-csf` for triple-framework reports from a single scan. |
| — | **PCI DSS v4.0.1 Compliance Engine (EE 0.11.0)** | Enterprise | PCI DSS v4.0.1 (PCI SSC, June 2024 errata; supersedes v4.0 March 2022; v3.2.1 retired March 31, 2024) mapping at the auditor-canonical sub-requirement level for QSA Report on Compliance workflow — **19 covered + 9 partial + 39 OOS across 67 of ~250 sub-requirements (MVP-67 density)** (Req 7.2.2 down-rated covered→partial in EE 0.19.4 — access-by-job-classification is process/HR-gated). Req 12 Information Security Program OOS-by-design entirely. Req 5 anti-malware + Req 9 physical OOS-entirely. **Defined-vs-Customized Approach discipline per Appendix E** — 15 Defined-only sub-requirements enforced at schema layer. **Cardholder Data Environment (CDE) scope operator-attested** via CDE Data Flow Diagram per Req 1.2.4 + Req 12.5.1. **Card-brand AOC enforcement priority view** (Visa CISP / Mastercard SDP / Amex DSOP / Discover DISC). **4 load-bearing schema enrichments** per control: `controlType` + `approachEligibility` + `cloudProviderAttestation` (AWS / Azure / GCP currently-named AOCs) + `cdeScope`. CAO MVP-deferred to EE 0.11.1. Use `--compliance pci-dss` or `--compliance soc2,hipaa,nist-csf,pci-dss` for quad-framework reports from a single scan. |
| — | **ISO/IEC 27001:2022 Compliance Engine (EE 0.12.0)** | Enterprise | ISO/IEC 27001:2022 (ISO + IEC, October 2022; 2013 edition retired October 31, 2025) Annex A mapping at the auditor-canonical per-Annex-A-code level for ISO/IEC 17021-1 certification body assessors — **17 covered + 14 partial + 62 OOS across 93 Annex A controls** (the complete Annex A universe across 4 themes: A.5 Organizational 37 + A.6 People 8 + A.7 Physical 14 + A.8 Technological 34). **Statement of Applicability per Clause 6.1.3.d discipline** — engine produces substrate for INCLUDED controls; SoA inclusion/exclusion is operator-side. **ISMS Clauses 4-10 OOS-by-design** with 7 Major Nonconformity classes (absence of internal audit per Clause 9.2 OR management review per Clause 9.3 = auto-fail Stage 2). 11 NEW 2022 controls + 5-attribute taxonomy (cybersecurityConcepts 5 categories, NOT 6 like NIST CSF) + 2013-to-2022 transition discipline + Cloud-Provider Certificate Inheritance Matrix. Use `--compliance iso-27001` or any combination for multi-framework reports from a single scan. |
| — | **CIS Critical Security Controls v8 Compliance Engine (EE 0.13.0)** | Enterprise | CIS Controls v8 (Center for Internet Security, May 2021; v8.1 errata June 2024) mapping at the per-Safeguard level (the atomic, attestable unit; coverage claimed at the SAFEGUARD level, never the Control level) — **17 covered + 23 partial + 113 OOS across 153 Safeguards / 18 Controls**. **Implementation Group cumulative discipline** — IG1=56 (cyber-insurance baseline; ~50-70% of mid-market policies require IG1 attestation), IG2 cumulative=130, IG3 cumulative=153; smallest-IG-membership tagging (NEVER report IG2 as 74-of-74 in isolation). **No-certification-body attestation discipline** — engine output is INPUT to CSAT / CIS-CAT Pro self-attestation OR a SOC 2 auditor cross-validating CIS scope, never "CIS certified." Cloud Companion Guide v8 shared-responsibility-model boundary + CIS-Hardened-Image substrate-evidence credit (Safeguards 4.1/4.2/4.6) + 5 Security Functions (NOT 6 — no Govern) + 6 Asset Types + MS-ISAC/EI-ISAC/H-ISAC sector baselines + v7.1-to-v8 cross-reference. Use `--compliance cis-v8` or `--compliance soc2,hipaa,nist-csf,pci-dss,iso-27001,cis-v8,gdpr` for hepta-framework reports from a single scan. |
| — | **GDPR Article 32 Compliance Engine (EE 0.20.0)** | Enterprise | **GDPR Article 32 (Security of Processing)** infrastructure substrate (Regulation (EU) 2016/679) — **4 covered + 5 partial + 2 OOS across 11 Art. 32 sub-measure units** (the 7th framework). **This is GDPR Article 32 infrastructure substrate ONLY — NOT GDPR compliance.** GDPR is a 99-article legal regime; Art. 32 security-of-processing is the only article whose evidence is technical infrastructure state, so the rest of GDPR (lawful basis, consent, DSARs, records of processing, DPIAs, transfers) is operator-side and out of scope by design. **Four-factor proportionality** — Art. 32 measures are "appropriate to the risk" taking into account state-of-the-art / cost / nature-scope-context-purposes / risk; nothing is an absolute pass/fail, the engine produces substrate *for* the operator's determination. **Personal-data-scope attestation** — the scanner reads configuration, not data classification; a finding is an Art. 32 concern only if the resource processes personal data (pair with your Art. 30 records of processing). Controller-vs-processor role applicability + Art. 28 processor agreements. **Art. 83(4) lower fine tier** — Art. 32 infringements cap at €10M or 2% of turnover, NOT the €20M / 4% Art. 83(5) headline tier (which is for the basic principles + data-subject rights). Art. 32(3)/Art. 42 cloud-provider certification-inheritance (ISO 27001 / SOC 2 / C5 / EU Cloud CoC adherence as an element of demonstrable compliance, not a substitute). Use `--compliance gdpr` or any combination for multi-framework reports from a single scan. |
| — | SLA & MTTR Tracking | Enterprise | Per-severity SLA targets, compensating-control flow, finding lifecycle, Type II rolling-quarter cadence. |
| — | Recurring-Scan Attestation | Enterprise | Multi-scan chronological matrix, cadence gap detection, scope-drift surface (CC8.1). |
| — | GRC Platform Connector | Enterprise | Vanta + Drata + Secureframe connectors — scan-time push (opt-in), retry/backoff, deterministic idempotency, rate-limit handling, circuit breaker, foreign-token detection, ZDE egress redaction. See [GRC Connectors](#grc-connectors-vanta-drata-secureframe). |
| — | WORM Posture Validation | Enterprise | Reads S3 Object Lock configuration on your trail buckets + resource redaction + SHA-256 manifest — substrate for a SEC 17a-4 / FINRA 4511 claim. The archive WRITER (`prepareArchive`) is built and **not reachable**: no caller, so no first-party run writes into an immutable store. |
| — | Tabletop Simulation | Enterprise | Probe-event manifest + SIEM detection correlation, configurable coverage bands (Type II / High-Assurance presets). |

**Running EE plugins** (after `nsauditor-ai license install <key>`):

```bash
# Run a single EE plugin
nsauditor-ai scan --host aws --plugins 1130 --compliance soc2 --out evidence.json

# Run multiple EE plugins
nsauditor-ai scan --host aws --plugins 1030,1040,1070,1130 --compliance soc2

# Run all EE plugins (auto-discovered via plugin manager)
nsauditor-ai scan --host aws --plugins all --compliance soc2

# Run a single Enterprise plugin by id
nsauditor-ai scan --host aws --plugins 1130 --compliance soc2
```

### Scoping the AWS audit to regions — `--aws-region`

By default an AWS audit runs against a single region (`AWS_REGION`, else `us-east-1`). The `--aws-region <one|csv|all>` flag controls which regions the **regional** plugins (security groups, EC2, RDS, KMS, Lambda, Secrets Manager, DynamoDB, CodePipeline/CodeBuild, Backup, SQS/SNS, VPC endpoints, ElastiCache, SES, Inspector/GuardDuty, CloudTrail) audit — each now audits *every in-scope region*, not just the configured one:

```bash
# A single region
nsauditor-ai scan --host aws --plugins all --compliance soc2 --aws-region us-east-1

# A comma-separated list of regions
nsauditor-ai scan --host aws --plugins all --compliance soc2 --aws-region us-east-1,eu-west-1,ap-southeast-2

# Every region enabled on the account (via DescribeRegions; static-list fallback on AccessDenied)
nsauditor-ai scan --host aws --plugins all --compliance soc2 --aws-region all
```

- **Precedence:** `--aws-region` flag › `AWS_REGION` (shell / `--env` file) › single-region default.
- **Default (no flag, no `AWS_REGION`):** scans one region and adds an informational *"incomplete region coverage"* note listing the enabled regions that were **not** scanned. It maps to no compliance control (a disclosure, not a finding — your posture is unchanged); pass `--aws-region all` for full coverage.
- **Unknown region:** the explicit flag **fails fast** on an unrecognized region code (set `NSA_AWS_REGION_ALLOW_UNKNOWN=1` to permit a brand-new region); an `AWS_REGION`-derived value warns and proceeds.
- **Global services** (IAM, account-level S3 enumeration) are audited once regardless of `--aws-region`; the S3 auditors resolve **each bucket's own region** and skip + disclose buckets outside the scoped set (closing latent cross-region false-cleans).
- **MCP `scan_cloud` (Claude Desktop / Claude Code):** the same scoping is a `regions` argument — *omit* it to scan the server-configured `AWS_REGION`, or pass `["all"]` (or a region-code list like `["us-east-1","eu-west-1"]`) to fan out. Omitting does **not** fan out, so a single tool-call stays within Desktop's timeout.

The auditor evidence pack is emitted under `out/` — cover-page Scope Attestation, SHA-256 chain-of-custody sidecars, the suppression workflow and approver identity verification, plus opt-in RFC 3161 trusted-timestamps (`NSAUDITOR_TSA_URL`), exercised against a live TSA on both the npm path and the `:0.33.0` container image. Ed25519 suppression SIGNING is reachable from EE 0.35.0 and PROVEN at EE 0.36.0, verified per approver holding **key material**. EE is available at [`www.nsauditor.com/ai/pricing`](https://www.nsauditor.com/ai/pricing).

---

## How Results Are Fused

The Result Concluder (plugin 008) merges all plugin outputs into a normalized structure:

1. **Imports** each plugin's `conclude()` adapter to get normalized `ServiceRecord` objects
2. **Merges** services by `(protocol, port)`, preferring authoritative records
3. **Selects OS** — OS Detector result first, then high-signal hints (Windows services, HTTP tokens), finally TTL fallback
4. **Produces** a unified `{ summary, host, services, evidence }` output
5. **Enriches** host details with names from mDNS, UPnP, NetBIOS; MAC + vendor from ARP

---

## AI Analysis

NSAuditor AI supports three AI providers for vulnerability analysis. **All providers work in all tiers** — CE, Pro, and Enterprise. AI is optional; the platform is fully functional without it.

**Providers:** OpenAI (GPT-4o), Anthropic Claude (Sonnet/Opus), Ollama (fully local)

**What changes by tier is the prompt content, not the provider:**

- **CE** — basic scan-summary prompts (services, ports, versions detected). Local MITRE ATT&CK mapping via `utils/attack_map.mjs`: service-context-aware CVE→technique mapping (`mapCveToAttack`, `mapServiceToAttack`), plus a CWE→technique fallback (`cweToMitre`, `cwesToMitre`) covering ~30 common CWEs (auth, crypto, injection, memory safety, info disclosure, privilege escalation, web). The CWE fallback fires only when CVE-derived mapping returns no techniques — useful for findings annotated with `evidence.cwe[]` (per FindingSchema v0.1.13+) but no CVE context, such as agent-detected misconfigurations and compliance-flagged weaknesses
- **Pro** — intelligence-enriched prompts (CVE matches, MITRE ATT&CK technique annotations, composite risk scores injected into the prompt). Same API call, better-grounded output
- **Enterprise** — Pro prompts + compliance context

**Redaction:** Before any data reaches an AI API, the redaction pipeline masks IP addresses, MAC addresses, serial numbers, and configurable confidential keywords. Admin RAW reports retain full detail for internal review.

```ini
# .env
AI_PROVIDER=claude
ANTHROPIC_API_KEY=sk-ant-...        # Your key — never sent to Nsasoft
ANTHROPIC_MODEL=claude-sonnet-4-6
OPENAI_PROMPT_MODE=optimized
OPENAI_REDACT=true
```

For fully local AI (no external API calls), use [Ollama](https://ollama.ai):

```ini
AI_PROVIDER=ollama
OLLAMA_MODEL=llama3
```

---

## Continuous Monitoring (CTEM)

Watch mode enables periodic rescanning with delta detection and webhook alerts:

```bash
nsauditor-ai scan --host 192.168.1.0/24 --plugins all \
  --watch --interval 15 \
  --webhook-url https://hooks.example.com/security \
  --alert-severity high
```

- **Scheduling** with configurable intervals and concurrency control
- **Delta detection** — new, removed, and changed services highlighted between cycles
- **Webhook alerts** — JSON POST with retry (exponential backoff, no retry on 4xx)
- **SSRF protection** — private, loopback, and cloud metadata addresses blocked at the scan entry point and inside `sendWebhook()`. Set `NSA_ALLOW_ALL_HOSTS=1` to scan RFC 1918 ranges (local network auditing)
- **Scan history** stored in `.scan_history/` (JSONL format, 7-day retention in CE)

---

## MCP Server

> **Heads-up on AI-client fabrication.** Some MCP clients (notably Claude Desktop) can silently substitute AI-generated responses if a `tools/call` times out, instead of surfacing the failure. Every response from this server now ends with a `── Verified MCP call ──` footer and a UUID. Run `nsauditor-ai mcp verify-call <id>` to confirm a response is genuine before acting on it. Full background and workflow: [docs/mcp-verification.md](./docs/mcp-verification.md). When in doubt, generate compliance evidence via the CLI (`nsauditor-ai scan ...`), which has no MCP client in the path.

Expose scanning capabilities to AI assistants via [Model Context Protocol](https://modelcontextprotocol.io):

```bash
nsauditor-ai-mcp
# or
npx nsauditor-ai-mcp
```

The server registers **seven** tools and lists all seven to every client. The licence is
checked when a tool is CALLED, not when the list is served — so an unlicensed call returns
an explicit 🔒 refusal naming the tier it needs, never an empty result that reads as "nothing
found". A higher tier does not add tools; it unlocks the ones already in the list.

**Available on every tier:**

| Tool | Purpose |
|---|---|
| `scan_host` | Run a full plugin scan against a host — service detection, OS fingerprint, structured findings |
| `list_plugins` | List available scanner plugins with their IDs, priorities and requirements |
| `compliance_matrix` | Return the shipped coverage matrix for a framework — Covered / Partial / Out of scope, with the per-group out-of-scope reasons. **Needs the Enterprise pack installed**: the matrices are its data, so on a Community-only install this fails closed with an install instruction rather than returning an empty matrix (an empty matrix is what gets filled in with a guess) |

**Unlocked by Pro** (licence key + `@nsasoft/nsauditor-ai-ee`):

| Tool | Purpose |
|---|---|
| `probe_service` | Run one specific plugin against a single `host:port` |
| `get_vulnerabilities` | Look up known CVEs for a CPE (Common Platform Enumeration) string via the NVD API |

**Unlocked by Enterprise:**

| Tool | Purpose |
|---|---|
| `scan_cloud` | Audit one or more cloud accounts (AWS / GCP / Azure) using server-configured credentials; no network host. "Audit my AWS account" / "Audit my AWS and Azure accounts". |
| `get_findings` | Drill into the findings of the most recent `scan_cloud` run (per-provider session cache — not live state) |

> `scan_cloud` runs the requested clouds' plugins **concurrently** (default up to 20 at once, 25s per-plugin
> timeout) so a full multi-service cloud audit completes within Claude Desktop's ~60s tool-call limit. Tune with
> `CLOUD_SCAN_CONCURRENCY` (default 20) and `CLOUD_PLUGIN_TIMEOUT_MS` (default 25000) in the server env. The
> network `PLUGIN_TIMEOUT_MS` still governs `scan_host` / network scans. Read the result's **`findingsSummary`**
> (per-provider severity counts + a CRITICAL/HIGH list) for the findings; `audited:false` / `notes` / `pluginsRan:0`
> still mean a cloud was NOT audited (never a clean pass). Pass `providers:["aws"]` to audit only the cloud named.

> **Full all-region AWS coverage fits Desktop's limit automatically.** When you ask for "all regions" / "full
> coverage", the agent scans the enabled regions in small **region-group batches** (each within the ~60s window)
> rather than one long `regions:["all"]` call — so it completes without timing out, and you do **not** raise any
> timeout for it. Keep `CLOUD_PLUGIN_TIMEOUT_MS` **under** Desktop's ~60s tool-call cap (default `25000`; raise to
> ~`45000` only for very large accounts — a higher per-plugin cap can let one plugin run past Desktop's wall and
> cause a hard timeout). For unbounded multi-region scans use the **CLI** (`nsauditor-ai scan … --aws-region all`),
> which has no MCP tool-call cap — there you can raise `PLUGIN_TIMEOUT_MS` (e.g. `90000`) freely.

Security: SSRF protection on all host inputs (blocks RFC 1918, loopback, fc00::/7, cloud metadata), port validation (1–65535), CPE format enforcement, dependency injection for test isolation. **Server-startup authentication is required** — see next section.

### Authentication (required)

The MCP server uses stdio transport, which means it runs as a child process of whatever client launches it. Without authentication, **any process running as your user could spawn the server and use its tools** — including the Pro/Enterprise tools that talk to AWS, generate compliance reports, and access your scan history. A per-operator shared-secret check at server startup closes this gap.

**One-time setup** (run once per machine after `npm install -g nsauditor-ai`):

```bash
nsauditor-ai mcp install-key
```

This generates a 256-bit auth key, stores it in the macOS Keychain (or `~/.nsauditor/.env` mode 0600 on Linux/Windows), and prints the Claude Desktop config snippet for you to paste. **The MCP server refuses to start unless the env-presented key matches the stored key** (constant-time compare; mismatch produces an actionable error pointing at this command).

**Inspect / verify**:

```bash
nsauditor-ai mcp status                  # shows storage source WITHOUT printing the key
nsauditor-ai mcp print-key --confirm     # reveals the key (use sparingly; refuses non-TTY output)
nsauditor-ai mcp rotate-key --confirm    # generates a new key (invalidates old one immediately)
```

**Why the Claude Desktop config snippet uses `keychain:` indirection on macOS**: the printed snippet looks like `"NSA_MCP_AUTH_KEY": "keychain:NSA_MCP_AUTH_KEY"` rather than the literal key value. The MCP server resolves the placeholder from your Keychain at startup. Net effect: **the secret never lands in `~/Library/Application Support/Claude/claude_desktop_config.json`** (which is mode 0644 by default — readable by other local users and any macOS app with Documents/Application Support entitlement). On Linux/Windows where there's no Keychain equivalent, the snippet uses the literal key with an explicit `chmod 600` warning.

**Threat model — what this defends, what it doesn't**:

| Threat | Defended? |
|---|---|
| Malicious npm post-install / browser extension running as you spawning the server | ✅ — attacker cannot read your Keychain without GUI prompt |
| Other users on a shared dev box / CI runner | ✅ — key is per-operator |
| Future HTTP/SSE transport network exposure | ✅ — key gates server startup, not network |
| Attacker with full operator code-exec AND can suppress macOS Keychain prompts | ⚠ partial — recent macOS versions log Keychain-access denial events |
| Debugger-attach memory snooping | ⚠ out of scope (any shared-secret auth has this limit) |
| Linux env-var visibility in `/proc/<pid>/environ` | ⚠ partial — see Linux note below |

**Linux note (`/proc/<pid>/environ`)**: on modern Linux, `/proc/<pid>/environ` is readable only by the process owner (the same user that spawned the MCP server). Other users on a multi-user system **cannot** read your MCP auth key from `/proc` under default kernel settings. The realistic remaining risks are:

- Container scenarios where multiple "users" share the same kernel UID (e.g., a Docker container running as root, with multiple processes inside) — the secret is visible to any process in the same UID namespace. Mitigation: run the MCP server in its own container / user.
- Audit/SIEM agents with broad read access (e.g., `auditd` configured to log child-process env). Mitigation: review your `auditd` rules; modern setups exclude env from logs by default.
- The legacy `ps eww` command on older POSIX systems (modern `ps` respects `/proc` permissions).

A shell-wrapper indirection script (read key from `~/.nsauditor/.env` at exec time, pass to child) was considered for v1 but does NOT solve the underlying issue: the spawned MCP server still needs the key in its env to perform the auth check, so it appears in `/proc/<server-pid>/environ` regardless of how the parent process obtained it. v2 may add libsecret integration on Linux to mirror the macOS Keychain indirection model.

**Rotation cadence**: keys older than 90 days emit a soft warning at every server startup AND in `nsauditor-ai mcp status` output. SOC 2 CC6.1 / CC6.7 reviewers expect a credential-rotation cadence; rotate with `nsauditor-ai mcp rotate-key --confirm` and update Claude Desktop config with the new key.

**Escape hatch for CI / dev** (operator-acknowledged risk; emits a stderr warning every startup):

```bash
NSA_MCP_AUTH_DISABLE=1 nsauditor-ai-mcp
```

### Claude Desktop Setup

First install the package globally:

```bash
npm install -g nsauditor-ai
nsauditor-ai mcp install-key   # required before MCP server will start
```

Then add this to your `claude_desktop_config.json` (Settings → Developer → Edit Config):

```json
{
  "mcpServers": {
    "nsauditor-ai": {
      "command": "nsauditor-ai-mcp",
      "env": {
        "NSA_MCP_AUTH_KEY": "keychain:NSA_MCP_AUTH_KEY",
        "NSA_ENV_FILE": "~/envs/prod-aws.env",
        "AI_PROVIDER": "claude",
        "ANTHROPIC_API_KEY": "keychain:ANTHROPIC_API_KEY"
      }
    }
  }
}
```

The exact `NSA_MCP_AUTH_KEY` value to paste is printed by `nsauditor-ai mcp install-key` — on macOS it's the `keychain:NSA_MCP_AUTH_KEY` placeholder shown above; on Linux/Windows it's the literal key value (and you should `chmod 600` your config file).

- `NSA_MCP_AUTH_KEY` — **required** (see Authentication section above)
- `NSA_ALLOW_ALL_HOSTS=1` — required to scan private/RFC 1918 addresses (e.g., `192.168.x.x`)
- `PLUGIN_TIMEOUT_MS=5000` — reduces per-plugin timeout to 5s so the full scan completes within Claude Desktop's 60s MCP limit
- `CLOUD_SCAN_CONCURRENCY` — max cloud plugins run at once by `scan_cloud` (default 20).
- `CLOUD_PLUGIN_TIMEOUT_MS` — per-plugin timeout for `scan_cloud` (default 25000; independent of the network `PLUGIN_TIMEOUT_MS`). Keep it **under** Desktop's ~60s tool-call cap (raise to ~`45000` only for very large accounts); full all-region coverage is delivered by automatic region-batching, so it needs **no** timeout increase.
- `AI_PROVIDER` and API key — optional, enables AI-powered analysis of scan results

#### `NSA_ENV_FILE` — point the MCP server at an environment file

Instead of inlining every scan variable in the config above, set **`NSA_ENV_FILE`** to a
dotenv file and keep the cloud credentials, `CLOUD_PROVIDER`, and scan tuning there. To scan
a different account or cloud, change the one path (or swap the file) and restart Claude Desktop —
no JSON editing.

```bash
# ~/envs/prod-aws.env   (chmod 600 — this holds credentials)
CLOUD_PROVIDER=aws
AWS_ACCESS_KEY_ID=AKIA...
AWS_SECRET_ACCESS_KEY=...
NSA_ALLOW_ALL_HOSTS=1
PLUGIN_TIMEOUT_MS=5000
```

- The file is loaded at server startup; values in it **override** the same keys in the config `env` block.
- **Fail-fast:** if the path is missing or points at an AWS credentials/INI file, the server refuses
  to start (it will not silently fall back to ambient credentials and scan the wrong account). The
  error is written to the MCP server's stderr log.
- **The file is the authoritative scan target:** ambient provider credentials (e.g. an old account's
  `AWS_*` keys still in the config `env` block) that the file does **not** set are cleared, so a partial
  file can't silently scan a leftover account. Instance-role / ADC identity is untouched.
- `NSA_MCP_AUTH_KEY` and `NSAUDITOR_LICENSE_KEY` are resolved **before** the file and must stay
  inline (or in `~/.nsauditor/.env`); if present in `NSA_ENV_FILE` they are ignored.

### Claude Code Setup

```bash
nsauditor-ai mcp install-key   # required before MCP server will start
claude mcp add nsauditor-ai \
  --env NSA_MCP_AUTH_KEY=keychain:NSA_MCP_AUTH_KEY \
  -- npx nsauditor-ai-mcp
```

To target an environment via the file, add it as an env value:

```bash
claude mcp add nsauditor-ai \
  --env NSA_MCP_AUTH_KEY=keychain:NSA_MCP_AUTH_KEY \
  --env NSA_ENV_FILE=~/envs/prod-aws.env \
  -- npx nsauditor-ai-mcp
```

(On Linux/Windows, replace the `keychain:NSA_MCP_AUTH_KEY` placeholder with the literal key printed by `install-key`.)

### Troubleshooting MCP authentication

**"MCP authentication is not configured"** at server startup → run `nsauditor-ai mcp install-key`. If you set `NSA_MCP_AUTH_DISABLE=1` in CI by intent, that's fine — but check that you didn't forget it in your shell rc.

**"NSA_MCP_AUTH_KEY env var is not set, but a key is configured in storage"** → the server found a key in your Keychain (or `~/.nsauditor/.env`) but the spawning client didn't pass `NSA_MCP_AUTH_KEY` in the env block. Update your Claude Desktop / Claude Code config to include the env value (use `nsauditor-ai mcp install-key` output as a reference snippet).

**"NSA_MCP_AUTH_KEY env var does not match the key configured in storage"** → most often means you ran `nsauditor-ai mcp rotate-key --confirm` but didn't update Claude Desktop config with the new key. Run `nsauditor-ai mcp status` to confirm storage source, then either re-paste the new key or use `keychain:NSA_MCP_AUTH_KEY` indirection (macOS only) so future rotations don't require a config change.

**"MCP_AUTH uses keychain: indirection but the referenced Keychain entry could not be read"** → typically a headless macOS / SSH-only CI runner where there's no GUI session to approve Keychain access. Replace the `keychain:` placeholder with the literal key value (or move auth to `~/.nsauditor/.env` with mode 0600).

**`mcp status` reports `keychain-locked`** → distinct from `unconfigured`: the Keychain entry exists but the security daemon refused to unlock without a GUI prompt. Same workarounds as the previous error: approve a Keychain GUI prompt, replace `keychain:` indirection with the literal key, or move auth to `~/.nsauditor/.env`.

**`mcp status` shows `⚠ Created: ... — > 90d threshold`** → key is older than the 90-day rotation cadence. Run `nsauditor-ai mcp rotate-key --confirm` and update Claude Desktop config with the new key. Server emits the same warning to stderr at every startup.

**Claude Desktop reports "Current tier: CE" despite `nsauditor-ai license --status` showing Enterprise** → first run `nsauditor-ai mcp tier` to get the ground-truth tier the MCP server actually resolves at startup. If `mcp tier` reports `enterprise` but Claude Desktop's `list_plugins` says CE, the AI client is synthesizing the response without actually calling the tool — see [docs/mcp-verification.md](./docs/mcp-verification.md) and verify any suspicious response with `nsauditor-ai mcp verify-call <id>`.

If `mcp tier` itself reports CE → genuine resolution failure. Inspect the license storage:

```bash
nsauditor-ai license --status
security find-generic-password -s nsauditor-ai -a NSAUDITOR_LICENSE_KEY -w 2>&1 | head -c 30
```

If license is in `~/.nsauditor/.env` but not in Keychain on macOS, re-run `nsauditor-ai mcp install-key` — the auto-mirror writes the license to Keychain so Claude Desktop's child process can read it via the `keychain:` indirection.

---

## Secure Credential Storage

Store API keys in the macOS Keychain instead of plaintext `.env` files:

```bash
# Store keys
nsauditor-ai security set ANTHROPIC_API_KEY
nsauditor-ai security set OPENAI_API_KEY

# List stored keys (masked)
nsauditor-ai security list

# Delete a key
nsauditor-ai security delete OPENAI_API_KEY
```

Then reference them with the `keychain:` prefix in `.env` or Claude Desktop config:

```env
ANTHROPIC_API_KEY=keychain:ANTHROPIC_API_KEY
```

```json
"env": {
  "ANTHROPIC_API_KEY": "keychain:ANTHROPIC_API_KEY"
}
```

The `keychain:` prefix works anywhere an API key is read — CLI, MCP server, or programmatic API.

---

## CLI Reference

```
nsauditor-ai scan [options]
nsauditor-ai license install <KEY>
nsauditor-ai license <--status | --capabilities | --plugins>
nsauditor-ai security <set|delete|list|get> <KEY>
nsauditor-ai validate
nsauditor-ai feed bundle --from <dir-of-NVD-feeds> --out <bundle.json.gz> [--kev <f>] [--epss <f>]
nsauditor-ai feed import --file <feed-or-bundle> [--cache-dir <d>] [--extras-dir <d>] [--append]   # the feeds you downloaded
nsauditor-ai compliance <attest|suppress|review|renew|keygen|sign-pack|verify-pack>   (Enterprise)
nsauditor-ai mcp
nsauditor-ai --help        (or -h, or `help`)
nsauditor-ai --version     (or -v, or `version`)
```

> Run `nsauditor-ai --help` (or `-h`, or just `nsauditor-ai help`) for a quick reference of subcommands, flags, env vars, and worked examples — works without a license key configured. `--version` / `-v` prints `nsauditor-ai <version>` and exits 0.

| Flag | Description | Default |
|---|---|---|
| `--host <target>` | Target: IP, hostname, CIDR, dash range. Aliases: `--ip`, `--target` | *required*\* |
| `--host-file <path>` | File with one host per line (`#` comments, blank lines OK) | — |
| `--plugins <list>` | Comma-separated plugin IDs or `all` | `all` |
| `--ports <list>` | **Additional** ports to scan, merged into the default config-derived list. Comma-separated. Optional `/tcp` or `/udp` suffix per entry (default: `tcp`). Examples: `8090` · `8090,9090` · `8090/tcp,5353/udp`. Use this to scan custom services on non-standard ports (e.g. MCP servers on `8090`, dev servers on `3000–9000`) | — |
| `--out <dir>` | Custom output directory — applies to the per-scan folder *and* to alternate-format files (SARIF/CSV/Markdown) | `out/` |
| `--parallel <n>` | Concurrent host scans | `1` |
| `--output-format <fmt>` | Additional output format: `sarif` (CI/CD) · `csv` (spreadsheet) · `md` or `markdown` (chat/PR/Slack quotable) | — |
| `--fail-on <sev>` | Exit code 2 if findings ≥ severity: `critical\|high\|medium\|low\|info` | — |
| `--insecure-https` | Accept self-signed TLS certificates | `false` |
| `--watch` | CTEM continuous **alerting** loop — re-scan on `--interval`, diff, webhook on `--alert-severity`. Not an evidence cadence: no retention, no cross-run aggregation, skips SARIF/CSV/Markdown + `--fail-on`, dies with the process. Use a scheduler for SOC 2 Type II history. | `false` |
| `--interval <min>` | Rescan interval in minutes (requires `--watch`) | `60` |
| `--webhook-url <url>` | Webhook URL for delta alerts | — |
| `--alert-severity <sev>` | Minimum severity for webhook alerts | `high` |
| `--compliance <fw>` | Compliance framework to map findings into. Accepts CSV for multi-framework runs (e.g. `soc2`, `hipaa`, `nist-csf`, `pci-dss`, `iso-27001`, `cis-v8`, `gdpr`, `nist-800-171`, or any combination like `soc2,hipaa,nist-csf,pci-dss,iso-27001,cis-v8,gdpr,nist-800-171` — `all` expands to the same eight). **Enterprise license required.** Supported frameworks as of EE 0.40.0 — **eight**: `soc2` (AICPA TSC 2017) + `hipaa` (HIPAA Security Rule §164.312 Technical Safeguards) + `nist-csf` (NIST Cybersecurity Framework 2.0 Core, CSWP 29 Feb 2024) + `pci-dss` (PCI DSS v4.0.1, PCI SSC June 2024 errata) + `iso-27001` (ISO/IEC 27001:2022, ISO + IEC October 2022) + `cis-v8` (CIS Critical Security Controls v8, CIS May 2021 / v8.1 errata June 2024) + `gdpr` (GDPR Article 32 / Security of Processing, Regulation (EU) 2016/679 — Art. 32 infrastructure substrate, **not** GDPR compliance) + `nist-800-171` (NIST SP 800-171 Rev 2 — evidence substrate for **CMMC Level 2 preparation**, **not** a CMMC certification, **not** a FedRAMP authorization, and no MET/NOT MET determination or SPRS score). See `@nsasoft/nsauditor-ai-ee` README for per-framework coverage details. | — |
| `--compliance-scope <path>` | Optional JSON file describing the assessment scope (passed to the compliance engine for cover-page attestation) | — |
| `--help`, `-h` | Print usage block (subcommands, flags, env vars, examples) and exit 0 | — |
| `--version`, `-v` | Print `nsauditor-ai <version>` and exit 0 | — |

\* Either `--host` or `--host-file` is required.

### Host Formats

| Format | Example | Description |
|---|---|---|
| Single IP | `192.168.1.1` | Scan one host |
| Hostname | `example.com` | Resolved via DNS |
| CIDR | `192.168.1.0/24` | All usable hosts (min prefix: /16) |
| Dash range (short) | `192.168.1.1-50` | Last-octet range |
| Dash range (full) | `10.0.0.1-10.0.1.254` | IP-to-IP range (max 65534) |
| Host file | `--host-file targets.txt` | One host/CIDR/range per line |

### Examples

```bash
# Full scan with self-signed cert tolerance
nsauditor-ai scan --host 192.168.1.1 --plugins all --insecure-https

# Parallel subnet scan
nsauditor-ai scan --host 192.168.1.0/24 --plugins all --parallel 10

# Targeted scan: TLS + HTTP + DNS + OS detection
nsauditor-ai scan --host 192.168.1.8 --plugins 011,006,009,013,008

# SARIF output for CI/CD, fail on high+ findings
nsauditor-ai scan --host 10.0.0.5 --plugins all --output-format sarif --fail-on high

# Markdown report — paste straight into a GitHub issue, Slack thread, or chat
nsauditor-ai scan --host 10.0.0.5 --plugins all --output-format md

# Scan custom non-standard ports (e.g. an MCP server on 8090, dev service on 5000)
# Uses --ports to add to the default scan list — additive, not replacing
nsauditor-ai scan --host 192.168.1.28 --plugins all --ports 8090,5000/tcp

# Continuous monitoring with webhook alerts
nsauditor-ai scan --host 192.168.1.0/24 --plugins all \
  --watch --interval 30 \
  --webhook-url https://hooks.example.com/alerts \
  --alert-severity high

# Hosts from file with 4 parallel scans
nsauditor-ai scan --host-file targets.txt --plugins all --parallel 4
```

### Pre-flight `validate` command

`nsauditor-ai validate` runs a fast (<2s) environment check without scanning anything. Useful for CI/CD setups, Docker `HEALTHCHECK` probes, and first-time-user diagnosis. Each check returns a status; the overall exit code is 0 (all OK), 1 (warnings), or 2 (errors).

Checks: plugin discovery, license JWT validation (if key set), AI provider configuration, output-directory writability + free space, DNS resolution.

```bash
# Human-readable output
nsauditor-ai validate

# Machine-readable JSON for CI parsing
nsauditor-ai validate --json
```

Docker HEALTHCHECK example:

```dockerfile
HEALTHCHECK --interval=60s --timeout=5s --start-period=10s --retries=3 \
  CMD nsauditor-ai validate --json | grep -q '"overall": "ok"' || exit 1
```

---

## Configuration

### Environment Variables (.env)

**AI configuration:**

```ini
AI_ENABLED=false                     # Set to true to enable AI analysis
AI_PROVIDER=openai                   # openai | claude | ollama
OPENAI_API_KEY=sk-...               # Your OpenAI key
OPENAI_MODEL=gpt-4o-mini
ANTHROPIC_API_KEY=sk-ant-...        # Your Claude key
ANTHROPIC_MODEL=claude-sonnet-4-6
OPENAI_PROMPT_MODE=optimized        # basic | pro | optimized
OPENAI_REDACT=true                  # Redact before sending to AI
CONFIDENTIAL_KEYWORDS=serial,password,token,secret
```

**Plugin-specific:**

```ini
TLS_SCANNER_TIMEOUT_MS=8000
TLS_SCANNER_VERSIONS=TLSv1,TLSv1.1,TLSv1.2,TLSv1.3
TLS_SCANNER_PORTS=443:https,465:smtps,563:nntps,993:imaps,995:pop3s
OPENSEARCH_SCANNER_TIMEOUT_MS=6000
OPENSEARCH_SCANNER_INSECURE_TLS=false
DNS_TIMEOUT_MS=800
HTTP_PROBE_TIMEOUT_MS=6000
WEBAPP_DETECTOR_TIMEOUT_MS=6000
SMB_NULL_SESSION=false
SMB_NULL_SESSION_TIMEOUT=5000
ENABLE_SYN_SCAN=false
SYN_SCAN_PORTS=
SYN_SCAN_TIMEOUT=30000
PING_FALLBACK=true
PING_FALLBACK_TIMEOUT=2000
```

**Licensing (Pro/Enterprise):**

```ini
NSAUDITOR_LICENSE_KEY=pro_eyJhbGci...   # Pro or Enterprise license key
NSAUDITOR_PLUGIN_PATH=                   # Additional plugin directories (colon-separated)
```

**Longitudinal compliance evidence (Enterprise CLI, new alongside the variables below):**

A single scan shows configuration at an instant. A SOC 2 Type II auditor — and the ISO
surveillance cadence, PCI Appendix E sampling, HIPAA §164.312(b) and GDPR Art. 32(1)(d)
equivalents — asks whether controls operated over a *period*. Every scan has always written
a per-framework `scan_attestation_<framework>.json`, so a history you already have is
aggregatable today:

```bash
# Track remediation SLA / MTTR against a directory of prior scans
nsauditor-ai scan --host aws --compliance soc2 \
  --compliance-history ./out --sla-policy ./my-sla.json

# Roll a directory of prior scans up into a multi-period attestation
nsauditor-ai compliance attest --history ./out --framework soc2 --window 12m
```

Three things the roll-up states about itself rather than leaving you to discover:
discovery reads **one** directory level (`<history-root>/<scan-id>/`), scans whose own
attestation is marked `REPORT INVALID FOR AUDIT` are **counted and named** rather than
averaged into a clean verdict, and an empty history exits **3** with status `no_evidence` —
absence of evidence is a finding, not a pass.

**The approval commands (CE 0.2.40 / Enterprise 0.35.0).** Four more `compliance` subcommands, all
forwarding to Enterprise — they need `@nsasoft/nsauditor-ai-ee` installed and exit 2 with an
explanatory message if it is absent. CLI-only; the MCP surface does not reach them.

```bash
# Create an approval keypair — private half 0600, plus an identity-registry member
# (pass --email/--role/--team too, or the member prints REPLACE ME placeholders)
nsauditor-ai compliance keygen --key ~/.nsauditor/approver.pem --approver "Ann Approver"

# Record an approval; SIGNS it when NSAUDITOR_SIGNING_KEY names a local Ed25519 key (verified per approver holding key material)
NSAUDITOR_SIGNING_KEY=~/.nsauditor/approver.pem \
nsauditor-ai compliance suppress --suppressions ./out/suppressions.json \
  --source auth_agent --title-pattern "SSH password authentication enabled" \
  --status accepted_risk --rationale "compensating control at the perimeter" \
  --approver "Ann Approver" --attestation-level approver

# List every approval across a scan history with its expiry status
nsauditor-ai compliance review --history ./out

# Re-approve before expiry (appended to the record's renewals[] chain)
nsauditor-ai compliance renew --suppressions ./out/suppressions.json \
  --id supp-abc123 --rationale "quarterly re-review" --approver "Ann Approver"
```

Three refusals and a warning you will meet rather than a happy path: `keygen` will not overwrite an
existing signing key (every signature it made becomes unverifiable, and nothing says so until an
auditor checks an archived approval); a malformed signing key fails the command and writes
**nothing**; `awskms:` references are refused in this release; and `renew` on a SIGNED approval
**invalidates its signature** — the expiry and the renewal record are inside the signed payload — so
it warns loudly and tells you to re-approve.

⚠️ **`--flag=value` is not supported**, here or on any flag this CLI has: use `--flag value`.
Ed25519 suppression signing is reachable from Enterprise 0.35.0, and **proven at 0.36.0 for approvers whose registry entry carries key material**.
Its verification gate ran against the published bytes and passed, tamper negative control included.
A fingerprint-only registry entry reads `not checked by this report`, which records that no check
ran and never that one failed.
Verification runs for approvers whose registry entry carries key material; a fingerprint-only entry
reads `not checked by this report`, which records that no check ran and never that one failed.

**Compliance evidence (`NSAUDITOR_*` — Enterprise, all opt-in):**

Every variable added from Enterprise 0.33.0 onward carries the `NSAUDITOR_` prefix, so a
deploy can tell at a glance which environment variables belong to this product. The
unprefixed families above (`AI_*`, `OPENAI_*`, `NVD_API_KEY`, `COMPLIANCE_GRC_*`) keep
working exactly as they do today — prefixed aliases arrive in a later minor, and a silent
rename will never happen.

```ini
NSAUDITOR_OFFLINE_ONLY=1          # Exact match on '1'. Forbids outbound: CVE matching reads a local
                                  # NVD store and reports an explicit coverage gap rather than a silent
                                  # clean. Also VETOES the two settings below — configuring an offline
                                  # posture and an outbound destination together is a startup error,
                                  # never a quiet downgrade to weaker evidence.
NSAUDITOR_TSA_URL=                # RFC 3161 Time-Stamp Authority endpoint, opt-in. Proven against a
                                  # live TSA on the npm path AND from inside the :0.33.0 container
                                  # image; :0.32.11 and earlier carry no openssl. NO DEFAULT, EVER —
                                  # unset means the feature is absent, not "use a vendor default".
NSAUDITOR_TSA_CERT_CHAIN=         # Path to the TSA certificate chain (PEM), for offline verification
NSAUDITOR_TSA_POLICY_OID=         # Optional policy OID to request from the TSA
NSAUDITOR_IDENTITY_REGISTRY=      # Path to the approver identity registry JSON. Binds the humans named
                                  # in your suppression file to identities an assessor can check.
                                  # Template ships at data/compliance/identity_registry.json (Enterprise).
NSAUDITOR_SIGNING_KEY=            # A REFERENCE, never key material: keychain:LABEL | /path/to/key.pem
                                  # (mode 0600) | awskms:alias/… — see the honesty note below.
```

Both of these are capabilities now, and each was proven later than it was wired — saying exactly
when, on which delivery vehicle, and for whom is the point:

- **`NSAUDITOR_SIGNING_KEY` is CONSUMED from EE 0.35.0, and the note below used to say otherwise.** EE 0.33.0 stopped parsing it at option-resolution time — a malformed value used to abort the EE stage for a setting nothing read — so it is carried through unparsed; `parseSigningRef` / `resolveSigner` hold the parse and the offline veto at the point a key is used. As of EE 0.35.0 `compliance suppress` signs the approval it writes when this variable names a local Ed25519 key — proven as of EE 0.36.0 and verified per approver holding key material.
  Its verification gate ran against the published bytes and passed, so a produced signature IS
  evidence for those approvers; a fingerprint-only registry entry reads `not checked by this report`. The record's `algorithm` and `backend` fields were frozen *before* the first
  signature could reach a customer archive, because retrofitting that later breaks every
  auditor holding one.
- **`NSAUDITOR_TSA_URL` is wired, and it is proven on both delivery vehicles — the npm path on 2026-08-07, and from inside the `:0.33.0` container image on 2026-08-08.**
  The live check this note used to say was outstanding has been run: through the installed
  binary, against a real Time-Stamp Authority, the auditor procedure `openssl ts -verify`
  returns OK on the compliance report, the scope attestation and the chain of custody; the
  same response file checked against a one-byte-mutated copy of the artifact returns FAILED,
  so the OK is a statement about those exact bytes and not about the command having run.
  ⚠️ The Marketplace container is a second delivery vehicle and was a separate question,
  because the implementation shells out to the `openssl` binary and a distroless runtime
  does not carry one unless it was deliberately put there. **It was deliberately put there
  for `:0.33.0`**: the image now carries the openssl CLI and libs, and a build-blocking gate
  proves it by building a real `openssl ts -query` request through the shipped module INSIDE
  the image before the leg is allowed to push. That check is made by RUNNING the image, never
  by reading the Dockerfile — a negative from a broken probe reads exactly like a negative
  from a missing binary, so the gate exits 2 rather than 1 when its own positive control
  fails. **And the live round-trip has now been run too** (2026-08-08): the shipped signing
  function was driven from inside the pushed `:0.33.0` image against a real authority,
  returning a genuine `.tsr` that the image's own `openssl` verified — with a one-byte-appended
  copy returning FAILED, so the OK is a statement about those bytes rather than about the
  command running. Both delivery vehicles are therefore proven end to end. **The one container
  caveat that survives is version scope:** retained images at `:0.32.11` and earlier do not
  carry the binary at all, so nothing here speaks for them.

**Security overrides:**

```ini
NSA_ALLOW_ALL_HOSTS=1    # Allow scanning private/RFC 1918 ranges (local network auditing)
NSA_AI_TIMEOUT_MS=120000 # AI provider call timeout in ms (default: 120000 = 2 min)
```

**Debug:**

```ini
NSA_VERBOSE=true      # Verbose PluginManager logging
DEBUG_MODE=true       # Plugin-level debug output
```

---

## Developing Plugins

NSAuditor AI uses a plug-and-play plugin system. Plugins are auto-discovered from `./plugins/` — no registration needed.

### Plugin Interface

```javascript
// plugins/0xx_my_scanner.mjs
export default {
  id: "0xx",
  name: "My Scanner",
  description: "What it probes",
  priority: 300,                    // Lower runs first; Concluder is 100000
  protocols: ["tcp"],
  ports: [1234],

  requirements: {                   // All optional
    host: "up",                     //   Skip if host unreachable
    tcp_open: [1234],               //   Skip if port not open
  },

  // requiredCapabilities: ["enterprise"],  // EE plugins only

  async run(host, port, opts = {}) {
    const { context } = opts;       // Shared state + OUI helpers
    return {
      up: true,
      program: "my-service",
      version: "1.0.0",
      data: [{
        probe_protocol: "tcp",
        probe_port: 1234,
        probe_info: "OK",
        response_banner: "my-service/1.0.0"
      }]
    };
  },

  // Adapter for Result Concluder
  conclude({ result, host }) {
    return [{
      port: 1234,
      protocol: "tcp",
      service: "my-service",
      program: result.program,
      version: result.version,
      status: "open",
      info: null,
      banner: result.data?.[0]?.response_banner || null,
      source: "my-scanner",
      evidence: result.data || [],
      authoritative: true
    }];
  },

  authoritativePorts: new Set(["tcp:1234"])
};
```

### Plugin Tips

- Use env-driven timeouts for all network calls
- Always close sockets on all code paths with a small post-banner linger
- Keep `probe_info` and `response_banner` concise — full detail goes in evidence
- Use `authoritativePorts` to take precedence over other plugins for the same port
- Plugins can also be loaded from external npm packages via `NSAUDITOR_PLUGIN_PATH`

---

## Pro & Enterprise Activation

After purchasing at [nsauditor.com/ai/pricing](https://www.nsauditor.com/ai/pricing), you'll receive an email with your license key and an npm install command. Two steps:

```bash
# 1. Install both packages (one-time, token included in email — the base package carries the CLI)
npm install -g nsauditor-ai
npm install -g @nsasoft/nsauditor-ai-ee --//registry.npmjs.org/:_authToken=npm_xxxxx

# 2. Install your license key — identical on macOS, Linux and Windows, no environment variable needed
nsauditor-ai license install "pro_eyJhbGci..."
```

Verify:

```bash
nsauditor-ai license --status
# ✓ Pro license active | Expires: 2027-04-04

nsauditor-ai license --capabilities
# ✓ intelligenceEngine  ✓ riskScoring  ✓ proAI  ✓ advancedCTEM ...
```

License keys are delivered automatically via Stripe webhook — no manual processing. Subscription renewals generate a fresh key and email it to you before the current one expires.

No license key? Everything in this repository works perfectly without one. The CE is not crippled — it's a complete, production-ready security scanner.

→ [Pricing](https://www.nsauditor.com/ai/pricing/) · [Enterprise contact](https://www.nsauditor.com/ai/enterprise)

---

## Tests

Run all 1308 tests:

```bash
npm test
```

Run a specific suite:

```bash
node --test tests/tls_scanner.test.mjs
node --test tests/port_scanner.test.mjs
node --test tests/result_concluder.test.mjs
node --test tests/os_detector.test.mjs
node --test tests/mcp_server.test.mjs
node --test tests/attack_map.test.mjs
```

Tests use Node.js built-in `--test` runner with the `assert` module — no external test framework. Each test is self-contained with inline fixtures and lightweight network stubs.

---

## Troubleshooting

| Issue | Solution |
|---|---|
| No DNS banner | Provider may block CHAOS/TXT (`version.bind`) or UDP/53 |
| OpenSearch over self-signed TLS | Set `OPENSEARCH_SCANNER_INSECURE_TLS=true` |
| TLS shows "closed" | Service may require SNI — set `TLS_SCANNER_SNI=hostname` |
| RPC not detected | Ensure port 111 is accessible and RPC portmapper is running |
| WS-Discovery timeout | Check network config and firewall for multicast on UDP 3702 |
| SYN scan requires root | Run with `sudo` or use TCP connect scanner (plugin 003) instead |
| Webhook URL rejected | Private/loopback/cloud metadata blocked by SSRF guard. Use `NSA_ALLOW_ALL_HOSTS=1` to allow RFC 1918 scan targets |
| EE plugins not loading | Verify `@nsasoft/nsauditor-ai-ee` is installed and license key is set |

---

## Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

**Quick version:**

1. Fork the repo and create a feature branch
2. Add a `Signed-off-by` line to your commits (`git commit -s`)
3. Include tests for any new or changed behavior
4. Submit a PR

**All contributions to this repository are under the MIT license.** For Enterprise Edition contributions, see the [nsauditor-ai-ee](https://www.nsauditor.com/ai/enterprise) repository which requires a signed IP Assignment Agreement.

**What we won't accept:** Code that phones home, transmits scan data externally, or weakens the Zero Data Exfiltration boundary.

### Requesting or Contributing Plugins

Check `./plugins/` first. If a plugin doesn't exist:

- **Request it:** Open an issue with scope, target ports, protocols, and example banners
- **Build it:** Follow the plugin interface above, include tests, and update this README

Commonly requested plugins: RDP, VNC, SMTP/POP3/IMAP, MySQL/PostgreSQL/MSSQL/MongoDB/Redis, LDAP, RabbitMQ/Kafka/MQTT, SIP, NTP, Modbus/S7/DNP3/BACnet, WordPress/Jenkins/GitLab detectors.

---

## Architecture

For the full technical architecture, see [ARCHITECTURE.md](docs/architecture.md).

**Tech stack:** Node.js 20+ · ES Modules (.mjs) · OpenAI + Anthropic SDKs · Node.js built-in test runner · MCP stdio transport

**Design patterns:** Factory (PluginManager.create) · Strategy (orchestrated/legacy execution) · Context (shared state) · Adapter (plugin conclude()) · Guard Clause (requirement gating) · Capability gating (CE/Pro/EE) · Semaphore (concurrency control) · Delta (scan history diff) · Boundary Guard (SSRF/injection protection) · Finding Queue (structured intermediate format) · Parallel Agents (concurrent specialized analysis)

---

## Privacy & Security

NSAuditor AI is built on a **Zero Data Exfiltration (ZDE)** architecture:

- **No telemetry.** No analytics. No usage tracking. No phone-home.
- **No data processing.** Nsasoft US LLC never sees, stores, or processes your scan results.
- **AI is opt-in.** External AI calls use your own API keys. Redaction runs locally first.
- **License validation is offline.** JWT signature verified locally with an embedded public key.
- **Air-gappable, once configured for it.** Scanning, analysis, license verification and evidence-pack generation all run with no outbound network access; Enterprise adds offline CVE matching from a local NVD store under `NSAUDITOR_OFFLINE_ONLY=1`, which emits an explicit coverage gap rather than a silent clean when the store cannot answer. Stated precisely because it matters operationally: a **default** scan still attempts NVD egress unless that variable is set. The other outbound paths — AI enrichment, the GRC push, the continuous-monitoring webhook, the opt-in RFC 3161 timestamping path (`NSAUDITOR_TSA_URL`, no default ever), and the AWS KMS signing path that ships but is not yet wired — are opt-in and off by default; the paths that are *not* optional are the scan target itself, your own cloud provider's APIs during a cloud scan, and DNS resolution of the target. All of them are enumerated with their trigger and default state in the egress register (EE `docs/architecture.md` §14.1.1), which is generated from code and guarded in both directions — deliberately, so this sentence never again has to carry a completeness claim that prose alone cannot keep true. Populating the local NVD store is the operator's; no feed data is delivered with the product. The prior absolute form of this bullet — *"Fully air-gappable. Every feature works without internet access (Enterprise includes offline NVD feeds)"* — is **WITHDRAWN** (CE 0.2.33): quoted here so the withdrawal record stays on this page now that release history lives in the [CHANGELOG](./CHANGELOG.md).

Nsasoft US LLC is not a data processor, data controller, or business associate under any data protection regulation. You own and control all data produced by NSAuditor AI.

---

## License

**MIT** — see [LICENSE](LICENSE) for the full text.

© 2024-present Nsasoft US LLC. "NSAuditor" and "NSAuditor AI" are trademarks of Nsasoft US LLC.

The Pro and Enterprise features available via `@nsasoft/nsauditor-ai-ee` are licensed under a separate proprietary license. See [www.nsauditor.com/ai/pricing](https://www.nsauditor.com/ai/pricing) for details.
