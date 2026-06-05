# scan_cloud Evidence-Gap Visibility — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:test-driven-development for each task (RED → verify-fail → GREEN → verify-pass → commit). Steps use checkbox (`- [ ]`) syntax.

**Goal:** Make EE no-false-clean evidence-gaps (LOW findings carrying `details.evidenceGap === true`) visible in the `scan_cloud` MCP summary + markdown, in a dedicated "Evidence gaps (unverified)" section — additive, backward-compatible.

**Architecture:** Two pure functions in `utils/cloud_finding_summary.mjs` (CE repo). `summarizeCloudFindings` gains a per-provider `evidenceGaps` array (independent of the CRITICAL/HIGH `findings` list + its cap). `renderCloudFindingsMarkdown` gains a labeled section. The `scan_cloud` tool description gains one sentence so the agent interprets gaps as "unverified", not clean.

**Tech Stack:** Node.js ESM, `node:test` + `node:assert/strict`, no new deps.

**Spec:** `docs/superpowers/specs/2026-06-05-scan-cloud-evidence-gap-visibility.md`
**Test cmd:** `node --test tests/cloud_finding_summary.test.mjs`

---

### Task 1: `summarizeCloudFindings` collects evidence-gaps (RED → GREEN)

**Files:**
- Modify: `utils/cloud_finding_summary.mjs` (bucket init ~line 62; per-finding loop ~63-69; cap section ~73-78)
- Test: `tests/cloud_finding_summary.test.mjs` (append)

- [ ] **Step 1: Write the failing tests** — append to `tests/cloud_finding_summary.test.mjs`:

```js
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
```

- [ ] **Step 2: Run to verify they fail** — `node --test tests/cloud_finding_summary.test.mjs`
Expected: FAIL — `s.gcp.evidenceGaps` is undefined (`Cannot read properties of undefined (reading 'length')`).

- [ ] **Step 3: Implement** — three edits in `utils/cloud_finding_summary.mjs`:

(a) bucket init (~line 62) — add `evidenceGaps: []`:
```js
    const bucket = (out[prov] ||= { counts: {}, findings: [], evidenceGaps: [], truncated: false });
```

(b) inside the per-finding `for (const x of found)` loop (~after line 68, still inside the loop), add the evidence-gap collection AFTER the existing CRITICAL/HIGH push:
```js
      if (x && typeof x === 'object' && x.details && x.details.evidenceGap === true) {
        bucket.evidenceGaps.push({ severity: sev, plugin: String(r?.id ?? ''), title: describeFinding(x) });
      }
```

(c) in the post-loop per-provider cap section (~after line 77, inside the `for (const prov ...)` loop, after the findings cap), add the evidenceGaps cap:
```js
    if (b.evidenceGaps.length > cap) { b.evidenceGapsTruncated = true; b.evidenceGaps = b.evidenceGaps.slice(0, cap); }
```

- [ ] **Step 4: Run to verify they pass** — `node --test tests/cloud_finding_summary.test.mjs`
Expected: PASS (incl. the original 9).

- [ ] **Step 5: Commit**
```bash
git add utils/cloud_finding_summary.mjs tests/cloud_finding_summary.test.mjs
git commit -m "feat(scan_cloud): collect details.evidenceGap findings into a per-provider evidenceGaps list"
```

---

### Task 2: `renderCloudFindingsMarkdown` evidence-gap section (RED → GREEN)

**Files:**
- Modify: `utils/cloud_finding_summary.mjs` (`renderCloudFindingsMarkdown`, ~lines 116-123)
- Test: `tests/cloud_finding_summary.test.mjs` (append)

- [ ] **Step 1: Write the failing tests** — append:

```js
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
```

- [ ] **Step 2: Run to verify they fail** — `node --test tests/cloud_finding_summary.test.mjs`
Expected: FAIL on the first new test (no `EVIDENCE GAP` text rendered).

- [ ] **Step 3: Implement** — in `renderCloudFindingsMarkdown`, inside the `for (const prov of order)` loop, AFTER the findings loop + the `if (b.truncated)` note and BEFORE `lines.push('')`:
```js
    for (const g of (b.evidenceGaps || [])) lines.push(`- **[⚠ EVIDENCE GAP — unverified]** ${g.plugin}: ${g.title}`);
    if (b.evidenceGapsTruncated) lines.push(`- _…evidence-gap list truncated; see LOW count for totals._`);
```

- [ ] **Step 4: Run to verify they pass** — `node --test tests/cloud_finding_summary.test.mjs`
Expected: PASS (all, incl. original 9 + Task 1's 4).

- [ ] **Step 5: Commit**
```bash
git add utils/cloud_finding_summary.mjs tests/cloud_finding_summary.test.mjs
git commit -m "feat(scan_cloud): render an 'Evidence gaps (unverified)' section in the markdown summary"
```

---

### Task 3: scan_cloud tool description + full regression

**Files:**
- Modify: `mcp_server.mjs` (scan_cloud tool `description`, ~line 219)

- [ ] **Step 1: Update the description** — find the scan_cloud `description` string (it contains `Read findingsSummary (per-provider severity counts + a CRITICAL/HIGH list) for the results.`) and append, inside the same string:
```
 findingsSummary[provider].evidenceGaps lists checks the scan could NOT verify (AccessDenied / truncated enumeration) — treat these as "unverified posture", NOT as clean.
```
So the sentence reads: `…Read findingsSummary (per-provider severity counts + a CRITICAL/HIGH list) for the results. findingsSummary[provider].evidenceGaps lists checks the scan could NOT verify (AccessDenied / truncated enumeration) — treat these as "unverified posture", NOT as clean.`

- [ ] **Step 2: Full CE regression**
Run: `node --test`
Expected: all pass (the `cloud_finding_summary.test.mjs` 9 original + 6 new; `mcp_scan_cloud.test.mjs` unaffected).

- [ ] **Step 3: Commit**
```bash
git add mcp_server.mjs
git commit -m "docs(scan_cloud): tell the agent to read evidenceGaps as unverified-posture, not clean"
```

---

## Self-Review

- **Spec coverage:** evidenceGaps collection (T1) · markdown section (T2) · tool description (T3) — all spec sections covered.
- **Placeholders:** none — full code in every step.
- **Type consistency:** `evidenceGaps: [{severity,plugin,title}]` + `evidenceGapsTruncated` named consistently across summarize/render/tests.
- **Backward-compat:** additive bucket field + optional markdown section; original 9 tests must stay green (asserted by running the full file each task).
- **Residuals (NOT in scope → TODO):** itemize MEDIUM/LOW on request; grantee strings; per-finding remediation / `explain_finding`. CE release pairing decision (don't publish in this task).
