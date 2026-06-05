# scan_cloud Evidence-Gap Visibility (R-HIGH)

**Date:** 2026-06-05
**Repo:** `nsauditor-ai` (Community Edition — the MCP cloud-summary layer)
**File:** `utils/cloud_finding_summary.mjs` (+ `mcp_server.mjs` tool description)
**Origin:** surfaced by the EE 0.18.1 Desktop MCP validation 2026-06-05 (Prompt 3). Root-caused live.

## Problem

`summarizeCloudFindings` (`utils/cloud_finding_summary.mjs:66`) itemizes **only** `CRITICAL`/`HIGH`
findings into `bucket.findings`; `MEDIUM`/`LOW` contribute to `counts` but get no title. The EE cloud
plugins emit their **no-false-clean evidence-gaps** — the heart of the 0.18.x false-negative-hardening
work (1021 firewall/IAM/bucket AccessDenied, 1024 legacy/default-ACL-unreadable, 1025
impersonation-completeness) — as **LOW** findings carrying `details.evidenceGap === true`. Because they
are LOW, they are **invisible via `scan_cloud`**: a Desktop/MCP auditor sees only `LOW: N`, with no
indication that one of those LOWs is *"impersonation posture UNVERIFIED — do not read as clean."*

During the 0.18.1 validation the Desktop agent, unable to see the gap, **backfilled a factually wrong
claim** ("plugin 1025 doesn't enumerate impersonation edges"; it does). The engine fails closed
correctly — but the failure-closed *signal* is swallowed before it reaches the auditor. This is a
**transport-layer false-clean**: exactly the outcome the evidence-gap work exists to prevent, re-introduced
one layer up. The gaps route to real framework controls (SOC 2 CC6.1/CC6.6, HIPAA §164.312(a)(1),
CIS v8 3.3), so their invisibility directly undercuts the institutional audit value.

## Goal

Surface evidence-gap findings (any severity, `details.evidenceGap === true`) in the `scan_cloud`
summary **and** markdown, in a dedicated, clearly-labeled **"Evidence gaps (unverified)"** section, so the
auditor/agent sees the unverified-posture disclosures **regardless of severity**. Additive only —
`counts` and the `CRITICAL/HIGH` findings list are unchanged; existing consumers are unaffected.

## Design

1. **`summarizeCloudFindings`** — add a per-provider `evidenceGaps: [{ severity, plugin, title }]`
   array, collecting every finding where `x?.details?.evidenceGap === true`, **regardless of severity**.
   - `counts` unchanged (the gap still increments its own severity, normally `LOW`).
   - The `CRITICAL/HIGH` `findings` list is unchanged (gaps are LOW → never hit that branch; the two
     collections are independent).
   - Apply the same `cap` independently to `evidenceGaps` with an `evidenceGapsTruncated` boolean (gaps
     are few in practice; the cap is a backstop, not the common path).
2. **`renderCloudFindingsMarkdown`** — after a provider's `CRITICAL/HIGH` list, when
   `b.evidenceGaps?.length`, render:
   ```
   - **[⚠ EVIDENCE GAP — unverified]** <plugin>: <title>
   ```
   one per gap, preceded by the existing finding lines. (When `evidenceGapsTruncated`, append a
   `_…evidence-gap list truncated…_` note, mirroring the `findings` truncation note.)
3. **`mcp_server.mjs`** scan_cloud tool `description` — add one sentence so the agent reads + interprets
   the gaps correctly: *"`findingsSummary[provider].evidenceGaps` lists checks the scan could NOT verify
   (e.g. AccessDenied / truncated enumeration) — treat these as 'unverified posture', NOT as clean."*

## Decisions / rationale

- **Separate `evidenceGaps` array** (not merged into `findings`, not severity-inflated): an evidence-gap
  is conceptually distinct from a violation — it says "we couldn't check," not "we found a problem."
  Keeping it a separate, labeled collection preserves the CRITICAL/HIGH list semantics and lets the agent
  reason about coverage gaps explicitly. Inflating gap severity would be dishonest (it's not a CRITICAL
  finding; it's an unverified one).
- **Counts untouched:** the gap remains a LOW in `counts` (the count is already complete/correct); the new
  array is purely additive visibility.
- **Backward compatible:** new field on the bucket + new optional markdown section. Existing tests for
  counts/findings/markdown-of-CRIT-HIGH stay green.
- **Edge case (documented):** a finding that is BOTH `details.evidenceGap` AND CRITICAL/HIGH would appear
  in both lists — acceptable and correct (it is both a violation and a gap); not expected from current
  plugins (gaps are LOW by design).

## Test plan (TDD, `tests/cloud_finding_summary.test.mjs`)

1. `summarizeCloudFindings` collects a LOW `details.evidenceGap:true` finding into `evidenceGaps` (title preserved, not lost).
2. A LOW finding WITHOUT `evidenceGap` is NOT in `evidenceGaps`.
3. `evidenceGaps` is independent of the CRITICAL/HIGH `cap` — a gap survives even when the findings list is capped/truncated.
4. `counts.LOW` is unchanged (the gap still counts); the CRITICAL/HIGH `findings` list is unchanged by the presence of gaps.
5. `renderCloudFindingsMarkdown` renders an "EVIDENCE GAP — unverified" line with the gap's plugin + title.
6. No gaps → no evidence-gap section (output identical to before — backward-compat).
7. `evidenceGapsTruncated` flag + note when gaps exceed `cap`.

## Invariants

- Additive only; existing `cloud_finding_summary.test.mjs` cases stay green.
- No EE change required (EE already emits `details.evidenceGap`); CE-only.
- No publish in this task (implement + test + review + plan release in TODO).
