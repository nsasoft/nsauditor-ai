# Changelog

Release notes for **`nsauditor-ai`** (Community Edition). The main [README](./README.md) focuses on features and usage — this file is the per-release history, kept for upgrade triage and audit reference.

For Enterprise Edition release notes, see [`@nsasoft/nsauditor-ai-ee`](https://www.npmjs.com/package/@nsasoft/nsauditor-ai-ee).

---

## 0.2.45 (2026-08-20) — the eighth framework: CE registers the `nist-800-171` stem

**Paired with Enterprise 0.40.0, and this is a REAL peer raise: `>=0.2.45`.** Unlike the last two
cycles, an older CE does not merely miss a nicety — it **rejects the framework outright**. The
framework-name validation lives in CE, so `--compliance nist-800-171` against CE 0.2.44 fails at the
CLI before Enterprise is ever consulted. That is why the floor moved and why EE 0.40.0 declares it.

### What changed here

`FRAMEWORK_STEMS` gains `nist-800-171`, and the alias table resolves `800-171`, `800171`,
`sp800-171`, `sp-800-171`, `cmmc`, `cmmc-l2` and `cmmc2` onto it. **Bare `nist` still resolves to
NIST CSF 2.0 and was deliberately NOT re-pointed** — two NIST publications now ship, and silently
changing what every existing `--compliance nist` invocation produces is a breaking change wearing
the shape of a convenience. 800-171 is reachable by its number, which is unambiguous.

⚠️ **A `cmmc` token is not a CMMC claim.** It resolves because it is what a defense contractor will
actually type; the artifact it produces names itself *"evidence substrate for CMMC Level 2
preparation"* on its own cover page. The engine emits no certification, no MET / NOT MET verdict and
no SPRS score — those are C3PAO determinations.

⚠️ **Requirement ids collide EXACTLY with PCI DSS sub-requirement ids** — `3.5.1` is real in both
standards. Both frameworks abstain from bare-id stripping and qualify their citations in prose
instead, so always write "NIST SP 800-171 3.5.1" or "Req 3.5.1".

### Also in this release

An invalid `--compliance` token still fails fast and writes **no compliance report** — an empty
report for an unknown framework would be indistinguishable from a clean one.

## 0.2.44 (2026-08-19) — `scan_cloud` stops naming a provider roster it cannot derive

**Paired with Enterprise 0.39.0. No CE scanning behaviour change; the peer floor stays `>=0.2.43`,
unraised, because nothing in this cycle needs new CE code.** What moves is one model-facing sentence
— and it needs its own publish for the reason every README correction here needs one: **npm freezes
it at publish time**, and this string is read by an assistant on every `scan_cloud` call until CE
republishes.

### The defect

The `scan_cloud` tool description told the model: *"Today only the AWS plugins declare their
capability boundaries; Azure and GCP declare none."* Enterprise 0.39.0 falsifies it — its seven GCP
and Azure plugins now declare theirs. But the deeper problem is that the sentence was **unsound in
principle, not merely stale**: CE floats over a peer RANGE (`>=0.2.43` in the other direction) and
cannot derive Enterprise's plugin roster at any version, so a description that counted providers was
making a claim CE had no way to check, and would go stale again on the next Enterprise release with
nothing in this repo to notice.

### What ships

The sentence is rewritten to the invariant that is true in **both** states and that CE can stand
behind: not every plugin declares its capability boundaries, so `deferredScope` bounds only what the
**declaring** plugins state and is never a coverage inventory — an empty or short list is not a
claim of full coverage, and the model is told to say so plainly rather than report completeness.
Pinned two-way by `tests/scan_cloud_deferred_scope_wording.test.mjs`, which also carries a PARSE leg:
the first version of that guard read `mcp_server.mjs` as TEXT and passed while an editing slip had
left the module unimportable. A wording guard over a code file cannot tell you the code runs.

The edition-comparison chart also gains the Ed25519 evidence-pack signing row, for an operator-held key over one framework's envelope and the artifacts it enumerates, never a vendor attestation. That scope is permanent and travels with every mention of it.

### And a third, found by Gate 3 — the invariant shipped and did not arrive

**Claude Desktop truncates the `scan_cloud` tool description at exactly 2,048 characters. It was
3,024. The 976 characters that never reached the model were the honesty half** — "a static
capability boundary, NOT an evidence gap and NOT a finding", "AN EMPTY OR SHORT deferredScope IS NOT
A CLAIM OF FULL COVERAGE", the per-plugin sentence 0.2.44 exists to deliver, and the INFO-tier rule.

Found by an operator running the release's own acceptance prompts and reporting that the text cut
off mid-word. ⚠️ **The gate passed anyway, and that is the instructive part:** the model applied the
invariant correctly in every prompt because the agent-skill was ALSO teaching it. Behaviour was
double-sourced, so testing behaviour could not see the missing half. An agent running this server
WITHOUT the skill had nothing.

**The fix is ORDER, not length.** MCP specifies no description limit and client bounds are
heterogeneous — OpenAI-compatible clients cap near 1,024, Claude Desktop at 2,048, Claude Code
delivers well past both intact. Writing to any one measured bound is writing to one client, and the
agent-skill README advertises clients in both families. So the description now **leads with its
hedges**: truncation can cost mechanics, never honesty, under a bound nobody has measured yet. The
service enumeration that bulked the string is duplicated in `SKILL.md` and both READMEs, so it
points rather than repeats.

Rewritten 3,024 → **1,012** characters, with all three reading rules inside the first 750.

`tests/mcp_tool_description_budget.test.mjs` guards both properties, because either alone is a trap:
a BUDGET leg (no description over the tightest advertised client bound, derived across every
registered tool) and an ORDER leg (the coverage invariant appears within the first 600 chars). Without
the order leg, a future edit could shrink a description under budget while moving the hedge to the
tail — staying green while reintroducing exactly this defect. 3 mutants, 3 RED.

⚠️ **The server cannot detect this itself, ever.** `tools/list` is fire-and-forget; MCP gives a server
no channel by which a client reports what it rendered. Emission is the only place it can be defended.

### And a second defect, found by a release seat trying to USE the 0.38.0 headline

`compliance sign-pack` and `compliance verify-pack` — the two commands CE 0.2.43 / EE 0.38.0 was
named after — **dispatched correctly and were absent from `nsauditor-ai help` for the entire
release.** They were documented in both READMEs, both changelogs, the press release, the
architecture record and the contract; the one surface that omitted them was the tool's own help,
which is where a user actually looks. Nothing was red, because every reachability guard this repo
owns asks *can a customer REACH this?* — and the answer was yes. **Nobody asked whether a customer
could FIND it.**

Both now carry a usage block in the same register as their siblings: `sign-pack` with its permanent
scope bound, `verify-pack` with its two trust anchors and what the `--public-key` arm discloses it
skipped. `tests/cli_help_dispatch_parity.test.mjs` derives the dispatched verb set from the dispatch
site itself — never a hand-written list, which would be a second copy going stale in exactly the
case it guards — and asserts equality in BOTH directions: a dispatched verb missing from help, and a
help entry nothing dispatches. The phantom direction is the worse failure and had never occurred, so
it was written first. Its own first run then reported `attest` as a phantom, because that verb is
dispatched by a NEGATIVE test (`sub !== 'attest'`) and the parse modelled only equality — *a
derivation that models one idiom reports on that idiom, not on the code.*

---

## 0.2.43 (2026-08-17) — the pack-signing commands are reachable here, not yet proven: CE is where the sign/verify entry points live

**Paired with Enterprise 0.38.0.** Two new `compliance` subcommands, both thin forwards — Enterprise
owns validation, the signing decision, every refusal and the exit code; CE contributes a flag
surface and decides nothing.

- `compliance sign-pack --manifest <scan_chain_of_custody_<framework>.json>` — signs one
  chain-of-custody envelope with an operator-held Ed25519 key — reachable, **not yet** proven by the
  gate that runs against published bytes. The key comes from `NSAUDITOR_SIGNING_KEY`, forwarded with
  its provenance, so a refusal names the setting you actually touched.
- `compliance verify-pack --manifest <envelope>` with **either** `--registry <path>` (resolve the
  approver through your identity registry; revocation and validity checked as at signing time) **or**
  `--public-key <pem>` (verify against a key you supply; the run discloses that identity, revocation
  and validity checks did not run). Supplying both is refused rather than resolved by precedence.

Exit **0** verified · **1** a violation · **2** the run could not measure. The third is not a
failure — an unsigned pack, an unreadable manifest, an unsupplied key and a registry member with no
key material all report it, and CE never collapses it into 1.

Requires `@nsasoft/nsauditor-ai-ee` >= 0.38.0 for these two verbs; everything else in CE is
unchanged.

## 0.2.42 (2026-08-15) — the `feed` commands: CE is where the air-gap entry points live

**MINOR: two new subcommands, one refusal that used to be a silent wrong answer, one plugin fix.**

**`nsauditor-ai feed bundle | import`** — the hand-carry pipeline for offline CVE data. `bundle`
merges the NVD feed files you downloaded on a connected host into one portable archive; `import`
reads one into the offline store on an isolated host. The implementations are Enterprise-side
(**requires `@nsasoft/nsauditor-ai-ee` >= 0.37.0**); the commands, flags and usage text are here,
because this is the package with the `bin`.

Optional `--kev` / `--epss` on `bundle` carry **your own** downloads from CISA and FIRST inside the
archive, and `--extras-dir` on `import` places them and prints the environment lines to set. No
exploit data ships with either package — these are your files.

`import` now names WHY it skipped records, split by reason. About a quarter of a real NVD year file
is skipped by design (withdrawn CVEs, entries with no CPE data), and a bare `skipped 9353` reads as
data loss; malformed records are called out separately because those are **not** expected.

**`--flag=value` is now refused by name.** It was previously parsed as a valueless flag with the
value discarded, so `--severity=high` ran a scan at the default severity and reported success — a
wrong answer that looked like a right one. The `--flag value` form is unchanged; full `=` support
is its own lane rather than something smuggled in beside a feature.

**mDNS discovery: the module-shape fallback was a TDZ self-reference**, so it never once fell back.

---

## 0.2.41 (2026-08-13) — Paired with EE 0.36.0: the report verifies the signatures it renders

**PATCH: no CE behaviour change. Version pairing only — every capability in this cycle is Enterprise-side.**

Enterprise 0.36.0 makes every compliance report cryptographically verify each suppression signature it renders — the Ed25519 suppression-signing capability this exercises stays **not yet proven**, its verification gate not having run against published bytes, and adds `report.signatureVerification` to the machine-JSON report. CE forwards `compliance suppress | review | renew | keygen` exactly as it did at 0.2.40 and needs no change to do so — the EE peer floor stays `>=0.2.40` for that reason rather than being raised out of habit.

Recorded because a paired no-op release is where a README goes stale: npm freezes this file at publish, so a version that ships without its own entry is a page that keeps describing the previous cycle until the next publish.

## 0.2.40 (2026-08-12) — Paired with EE 0.35.0: the suppression-approval commands reach the CLI

**MINOR: four new `compliance` subcommands; no change to scanning, and no existing flag moves.**

`compliance suppress | review | renew | keygen` are thin forwards to the Enterprise package, in the discipline `compliance attest` established — EE owns validation, defaults, the signing decision and every refusal; CE contributes flags and an exit code and decides nothing. CLI-only by design: the MCP surface does not reach them, the same ruling the GRC push carries.

The flags parse in `parseArgs` alongside every other flag rather than from `process.argv` inside the subcommand. The first cut did the latter and broke on its first real invocation — a second parser is a second set of edge cases, which is the drift shape this product has paid for elsewhere.

⚠️ `--flag=value` is NOT supported, here or anywhere else in this CLI: `--host=10.0.0.1` yields `undefined` today and always has. That limitation is now pinned by a test naming it, rather than left as a surprise for the first operator who types the other shape. Widening it would change the parse of every existing flag and belongs in its own change.

`NSAUDITOR_SIGNING_KEY` is CONSUMED from this release: with EE 0.35.0, `compliance suppress` signs the approval it writes when the variable names a local Ed25519 key — a capability that is **not yet proven**, because its verification gate has not run against published bytes.

---

## 0.2.39 (2026-08-10) — Paired with EE 0.34.0: exploit intelligence lands in Pro, and the risk-score claim is corrected here

**No CE behaviour change.** Scanning, plugins, concluder and output are unchanged.

Enterprise findings that carry CVEs are now joined by CVE-ID against a local **CISA KEV** catalog
and a local **FIRST EPSS** scores file, banded, and ordered exploit-first so a KEV-listed MEDIUM
outranks an unexploited CRITICAL. Both stores are **operator-populated — no feed data ships** —
and fail closed when stale, so an out-of-date catalog never reports "not exploited".

The CE-side change is a correction this package owed its readers. `README.md` and
`docs/architecture.md` described *"a composite risk score (severity x exploitability x impact x
exposure)"*; the engine computes **CVSS weighted by verification status, with an uplift for
initial-access techniques**, and no exploitability input existed at all until EE 0.34.0. The
documented `FindingQueue.prioritize()` sorts by **severity rank alone** — the exploit-aware
ordering is Enterprise-side.

---

## 0.2.38 (2026-08-07) — Paired with EE 0.33.1: the opt-in RFC 3161 register stops understating itself

**No behaviour change. Wording only — and it is the wording npm freezes onto the package page.**

Trusted timestamping is opt-in, became operator-configurable at EE 0.33.0, and has since been
proven end to end against a real Time-Stamp Authority twice over: on the npm path, and separately from inside the
published `:0.33.0` Marketplace container image. Six places in this README still told a reader the
container leg was unverified.

They now state what is true: **RFC 3161 timestamping is opt-in via `NSAUDITOR_TSA_URL`** — no
default ever, an outbound call to the authority you name, and it needs the `openssl` binary. The
one caveat that survives is **version scope**: retained images at `:0.32.11` and earlier carry no
`openssl` at all, so nothing in that section speaks for them.

The paragraph explaining WHY the container was a separate question is kept rather than trimmed,
because the reasoning still holds — a distroless runtime carries no `openssl` unless deliberately
given one, and the check must be made by RUNNING the image, since a negative from a broken probe
reads exactly like a negative from a missing binary. What changed is the answer.

**Ed25519 suppression signing was unchanged at this release and still not reachable then** — the suppression workflow
shipped, the signature did not, and no shipped entry point signed a suppression at that release.

---

## 0.2.37 (2026-08-07) — the Enterprise entry points, and a catch that was deleting the deliverable

**Paired with Enterprise 0.33.0, and REQUIRED by it** — that release's peer floor is
`>=0.2.37`, because the entry points its docs call reachable live here.

- **`compliance attest`** — Type II recurring-scan attestation over a directory of prior
  scans. Exit 3 on an empty history: absence of evidence is the finding this command exists
  to surface, so it must not exit 0.
- **`--sla-policy <file>` and `--compliance-history <dir>`** — reach the SLA/MTTR engine,
  which had been wired inside the compliance phase behind options no flag ever set.
- **Startup posture preflight, exit 2.** `NSAUDITOR_OFFLINE_ONLY=1` together with a
  configured outbound path is a contradiction the operator cannot have meant. It runs at
  every tier and every command: a contradiction between two operator settings is a
  configuration error regardless of what a licence unlocks.
- **⚠️ The bare `catch {}` around the Enterprise stage is SPLIT.** It wrapped the import AND
  the call, so "Enterprise is not installed" — legitimate and silent for every Community
  user — was indistinguishable from "Enterprise ran and threw", which exits 0, writes no
  compliance report and prints nothing. Absence stays silent; failure names the lost stages
  and marks the result.
- **`--help` fix:** the note on plugin 1023 gave `--plugins 023`, which resolves to nothing
  (ids match exactly). Measured by driving the CLI, `--plugins 1023` does not work either —
  1023 requires the host confirmed up by a discovery plugin, so selecting it alone removes
  the plugin that satisfies its own precondition. It runs on a network-host scan.
- **Frozen-page corrections:** the MCP tool tables advertised seven tools that are not
  registered and omitted two that are; WORM evidence storage carried a ✅ though its writer
  has no caller; `compliance_matrix` was listed as available on every tier when it needs the
  Enterprise pack; and the "28 cloud plugins" gloss counted a network-scan check as a cloud
  auditor.

## 0.2.36 (2026-08-05) — Paired with EE 0.32.11: the summary stops hiding its own scope limits, and a new MCP tool removes the reason to invent a matrix

This is a substantive CE release, not a lockstep bump. Every item was driven by the Desktop-MCP Gate-3 battery.

### `scan_cloud`'s summary was dropping a whole tier

`renderCloudFindingsMarkdown` rendered `CRITICAL · HIGH · MEDIUM · LOW · PASS`. **INFO was not a column**, `findings[]` admitted only CRITICAL/HIGH, and the rollup only MEDIUM/LOW — so on a real AWS scan **55 of 62 INFO records appeared in no summary anywhere**. Several were `deferredScope` declarations, the EE contract marker that exists so a customer can tell *not assessed* from *assessed and clean*. The plugins emitted them correctly; this layer dropped them.

- **INFO is a header column and rolls up by category.** Records with their own channel (evidence gaps, scope boundaries) are excluded from the rollup so a cross-cloud roll-up cannot double-count them.
- **`findingsSummary[provider].deferredScope[]` is new** (additive), rendered under `[🔎 SCOPE NOT ASSESSED]` — deliberately NOT the evidence-gap badge, which would re-assert the routing claim EE's contract forbids for a static boundary.
- **`describeFinding` collapses whitespace.** Producers build these declarations as `"…:\n- alpha\n- beta"`, and the renderer emits one list item per line, so an embedded newline terminated the item and dumped the rest as unformatted text — a truncated disclosure reading as a complete one. It also takes an optional `max`, because a 160-character slice of an eight-dimension boundary discloses one dimension and looks like the whole boundary.

### NEW MCP tool: `compliance_matrix`

Asked for the SOC 2 coverage matrix, an assistant with no authoritative surface built one from the plugin inventory and published 5 / 18 / 38 = 61 against a shipped 10 / 4 / 37 = 51. `compliance_matrix` returns any of the seven frameworks (or all seven), **derived from the shipped EE framework JSON at call time, never a constant**, and **fails closed** with an explicit "Enterprise pack not installed" rather than an empty matrix — an empty matrix is the void a synthesised one fills. `outOfScope` is the **flattened** sub-criterion count, not the group count.

### `pdfExport` withdrawn, and every capability now has a description

`pdfExport` was registered and minted while nothing implemented or read it. Gone. More durably: `CAPABILITIES` entries now carry a `desc`, and `license --capabilities` prints it. Bare identifiers are a claim surface with no text to sweep — a reader with nothing to quote expands the NAME, which is how `airGapped` became "air-gapped deployment", a withdrawn phrase.

### `--watch` is described honestly, including the part the first correction got wrong

`--watch` is a CTEM **alerting** loop. But "writes no evidence artifacts" is false: `opts.compliance` is set before the watch branch and each tick runs an ordinary scan, so `--watch --compliance <fw> --out <dir>` writes that tick's artifacts. The register now says what is actually missing — no retention, no cross-run aggregation, no period sampling, and SARIF/CSV/Markdown and `--fail-on` are skipped. The artifacts are not the missing piece; the relation between them is.

### Also

- Two MCP guards that could not fail are now equality pins — one listed five tool names and asserted `includes` while six shipped; the other checked four of six handlers. Both were completeness titles over subset checks.
- `tests/license.test.mjs` no longer asserts a withdrawn capability is present in a frozen fixture JWT. That assertion kept passing after the flag was removed everywhere — a green assertion, inside the suite, asserting a phantom is still minted.

---

## 0.2.35 (2026-08-03) — Paired with EE 0.32.10: a version bump, and the honest reason for it

**No CE behaviour change.** This is the paired half of the Enterprise 0.32.10 cycle, published in lockstep so the two halves of the product never drift apart on the registry.

What moved is on the Enterprise side, and it is worth reading if you evaluate tooling on how it treats its own instruments: the dependency-advisory gate had been auditing the maintainer's working tree while calling it the production closure. It now packs the tarball, installs it the way you would, and audits **that** — and it refuses to report a clean result unless it can first prove an advisory database actually answered. Measured on the corrected subject, the two trees shared 5 of 26 advisory packages and **zero** high-severity ones, so the number that had been reported for weeks described a tree no customer installs.

Also in the paired release: the SOC 2 coverage matrix is enumerated in full (**10 / 4 / 37 = 51** — completeness, not a coverage change; no control moved status and no routing changed), the Type II documentation now says which mechanisms are reachable from a shipped entry point and which are roadmap, and every unhedged mention of a not-yet-shipping capability is off the public pages.

## 0.2.34 (2026-07-29) — Paired with EE 0.32.9: the MCP summary learns both spellings of the evidence-gap prefix

EE 0.32.9 renamed the evidence-gap routing prefix — it renders as the **violation title** in the customer's evidence pack, and it used to be an internal roadmap id no auditor could resolve:

```
before:  EE-RT.1.2 multi-region-enumeration-incomplete:
after:   Evidence gap (multi-region enumeration incomplete):
```

`ROUTING_PREFIX_RE` in `utils/cloud_finding_summary.mjs` strips that prefix at the presentation layer so the 160-character `scan_cloud` summary spends its budget on substance — and it only knew the old spelling. Without this, the summary would have re-printed ~51 characters of a prefix the `[⚠ EVIDENCE GAP]` badge already conveys.

**BOTH spellings are recognised, deliberately.** CE ships independently of EE and an operator can pair any supported EE with this CE, so dropping the legacy alternative would leave the old prefix unstripped on every paired-with-older-EE run.

**Also — `validate` stopped misreporting where plugins came from.** `checkPlugins` returned the AGGREGATE count across all three discovery sources beside a single `basePath`, so `nsauditor-ai validate` could say *"28 plugins loaded / basePath: <dir>"* for a directory containing none of them (the EE package is resolved globally — `pkgRoot` cannot reach it, by design). It now reports per source: `27 plugins at basePath (+ 28 ee)`, with `details.basePathCount` and `details.bySource`. When an injected `discover` returns plugins carrying no source label, the aggregate wording is kept rather than claiming an attribution we do not have.

Found by the release gate: three tests had been passing **vacuously** because `@nsasoft/nsauditor-ai-ee` did not resolve from the CE dev tree, so their assertions were skipped. One of them also expected EE plugin ids in the retired 3-digit range (`020`), years after they moved to 1000+. All three now assert in both worlds.

No other behaviour change. Suite 1236/1236.

## 0.2.33 (2026-07-28) — Paired with EE 0.32.8: capability-claim honesty pass, part 2 (the air-gapped-delivery class)

Paired with **Enterprise 0.32.8**. Mostly a documentation-and-prose release — no detection, routing, or compliance behaviour change — **plus one CLI fix found by the pre-publish smoke gate** (below).

### Fix — `--out <dir>` silently wrote to the parent directory when the directory name contained a dot

Running the documented command with a version-named output directory — `--out .../audit-evidence-samples/ee-0.32.8` — wrote every artifact to `.../audit-evidence-samples/` instead. Exit 0, no warning, evidence in a folder the operator did not ask for.

`resolveBaseOutDir` decided file-vs-directory by asking whether the path had an extension, and `path.parse('ee-0.32.8').ext` is `'.8'`. So it treated the directory as a file and returned its parent. The same shape breaks `v1.2.3` and `release-2026.07` — and it hit the exact naming convention used for this project's own evidence archives, which is how a full three-cloud audit run surfaced it.

An extension is now recognised as file-like only when it **starts with a letter** (`.json`, `.html`, `.csv`, `.sarif`). A trailing `.8` / `.07` / `.28` is a version or date component, not a file type. The documented `--out report.json` affordance is unchanged and is pinned by its own test in the opposite direction, so the fix cannot degrade into "always treat it as a directory".

**Why it matters beyond the inconvenience:** a flag whose entire job is to say where the evidence goes must not put it somewhere else without saying so. Scattering artifacts into a shared parent risks mixing runs, and a silent success is worse than a failure here. 0.32.7 withdrew six phantom capability *flags*; an audit of the air-gapped-delivery claims found the same class one layer down, in prose, across **27 sites** (distinct lines) in the three published packages.

**CE change this cycle — the ZDE section's air-gap claim.** *"Fully air-gappable. Every feature works without internet access (Enterprise includes offline NVD feeds)"* was false in two ways, and both are corrected:

- **The absolute form.** A **default** scan attempts NVD egress unless `NSAUDITOR_OFFLINE_ONLY=1` is set. The claim is now *"Air-gappable, once configured for it"*, with the qualifier stated rather than implied: scanning, analysis, license verification and evidence-pack generation all run with no outbound network access, and the only other outbound paths — AI enrichment and the GRC push — are opt-in and off by default.
- **"Enterprise includes offline NVD feeds."** **Withdrawn** — no feed data is delivered with the product and no pipeline produces a bundle. What Enterprise adds is the offline *query* path: CVE lookups served from a local NVD store, emitting an explicit coverage gap rather than a silent clean when the store cannot answer. Populating that store is the operator's.

**New guard.** `tests/capability_claim_honesty.test.mjs` fails the build both if the absolute claim returns **and** if the honest qualifier is deleted — because withdrawing an overclaim by deletion trades one inaccuracy for another. Each withdrawn pattern carries a hand-written probe it must match, so the pattern list cannot be dead and green at the same time. Mutation-proven before landing.

On the Enterprise side the same sweep found **five wrong rendered runtime strings** — coverage-gap rationales that render verbatim into the assessor-facing evidence pack and instructed the reader to run a CLI command that does not exist. See the Enterprise changelog for that detail and the full 22-site table.

Plugin count UNCHANGED at 28; all seven coverage matrices UNCHANGED.

---

## 0.2.32 (2026-07-21) — Paired with EE 0.32.7: cross-framework routing + capability-claim honesty pass

Paired with **Enterprise 0.32.7**, which does two things: the network-scan analysis agents' findings now route in **all seven compliance frameworks** (they previously reached only SOC 2 off the same scan — a host serving cleartext or exposing SMB failed SOC 2 and read clean in HIPAA / NIST / ISO / CIS / PCI / GDPR), and a **capability-claim honesty pass** withdraws several Pro/Enterprise capabilities that were advertised without a shipping implementation. See the Enterprise package for the full detail.

- **CE code change this cycle** (the honesty pass reaches CE too): the tier-capability map (`utils/capabilities.mjs`) drops six flags — `verificationEngine`, `brandedReports`, `usageMetering`, `dockerIsolation` (no implementation) and `zdePolicyEngine`, `enterpriseCTEM` (real cores ship + are claimed in prose; no distinct engine behind the name) — in lockstep with EE and both licensing repos, so `nsauditor-ai license --capabilities` and every minted license now name only capabilities that ship. `resolveCapabilities(tier)` already derives from tier and ignores the JWT capability array, so **issued licenses are unaffected**. The README drops a "verification status" prompt-injection claim and a "Verification Probes" design-pattern entry — the Verification Engine is **WITHDRAWN** as of this cycle (EE 0.32.7), no verification probes ship, and every finding is emitted `UNVERIFIED`.
- Plugin count UNCHANGED at 28; all seven coverage matrices UNCHANGED (Enterprise 0.32.7 is matrix-neutral — every finding routes to already-covered controls). Paired **EE 0.32.7** + agent-skill 0.2.30 (peer `nsauditor-ai >=0.2.8` unchanged).

## 0.2.31 (2026-07-19) — Paired bump for EE 0.32.6 (network-scan false-negative closures)

**No CE code change this cycle** — a paired content/version bump for the EE 0.32.6 trio. Enterprise 0.32.6 is a **matrix-neutral** false-negative-hardening release on the EE analysis-agent (network-scan) path: **cleartext transport** is now flagged where before only weak-TLS-where-TLS-exists was — a conditional inversion in the crypto agent (a service that should be encrypted but offers no TLS at all used to read clean) → **SOC 2 CC6.7**; **SMB-alone** exposure is now its own **HIGH** finding rather than being silenced by an `SMB && RDP` conjunction — a severity-inverted conjunction in the exposure agent (SMB without RDP is the higher-risk case) → **CC6.6**; and **WinRM 5985/5986 · Elasticsearch 9300 · MSRPC 135 · a new aggregate open-port-count rule** are new exposure signals → **CC6.6**. Routed SOC 2-first with drift-detector coverage; **SOC 2 routing only this cycle — the cross-framework mappings (HIPAA §164.312(e)(1) · CIS 4.x · NIST PR.*) are deferred**. No new plugins, plugin count UNCHANGED at 28, all seven coverage matrices unchanged. See the EE package for the full detail. Paired **EE 0.32.6** + agent-skill 0.2.29.

## 0.2.30 (2026-07-18) — Marketplace registration in CLI help; paired with EE 0.32.5 report-quality release

- **AWS Marketplace license registration surfaced in the CLI.** `--help` and `nsauditor-ai license --status` now name the registration step, so a Marketplace buyer can complete fulfilment without leaving the terminal.
- Paired with **EE 0.32.5** — matrix-neutral report-quality + routing-integrity release: API Gateway mapping repair (routing was never broken; the defect was stale auditor-facing prose), six rationale rewrites, `renderJSON` no longer shipping raw routing regexes, a CI/CD AccessDenied false-negative closed fail-closed, and three mutation-proven compliance-guard hardenings. Plugin count UNCHANGED at 28; all seven coverage matrices UNCHANGED.

## 0.2.29 (2026-07-13) — Paired bump for EE 0.32.4 (RDS false-negative depth pass, part 2)

**No CE code change this cycle** — a paired content/version bump for the EE 0.32.4 trio. Enterprise 0.32.4 is a **matrix-neutral** RDS false-negative-and-report-quality depth pass on plugin 1140: **RDS Proxy client↔proxy TLS** (a proxy with `RequireTLS` off accepts cleartext client connections — a transit leg distinct from the DB-engine SSL parameter — now a HIGH finding, fail-closed on false-or-absent), a new **retained / cross-region-replicated automated-backup at-rest surface** (an unencrypted automated backup that survives instance/cluster deletion, invisible to the live-resource and snapshot scans, is now caught), the **Aurora cluster-member double-audit closure** (a provisioned Aurora cluster's members no longer double-report the cluster-scoped SSL / Multi-AZ settings as instance-level false positives), and a **cross-framework report-quality leak closure** (a renderer backstop strips foreign framework control-ids out of the violation prose that renders into every framework report). No new plugins, all seven coverage matrices unchanged. See **[CHANGELOG.md](./CHANGELOG.md)** and the EE package for the full history. Paired **EE 0.32.4** + agent-skill 0.2.27.

---

## 0.2.28 (2026-07-12) — GRC-push startup preflight (CE code change) + paired bump for EE 0.32.3 (RDS cluster-level SSL enforcement)

**CE code change this cycle:** the CLI now runs a **GRC-push configuration preflight** at scan startup. When a scan requests a compliance framework and `COMPLIANCE_GRC_PROVIDER` is set, `preflightGrcConfig(process.env)` validates the provider / token / control-map **before** the scan runs, so a misconfiguration fails **fast** with a clear message instead of only surfacing at push time after a full multi-region scan — a real per-org UX fix for MSP/MSSP operators pointing `--env clientX.env` at many client tenants. Framework-less recon scans are unaffected (the preflight is gated to scan + framework + provider). GRC push remains a CLI-only surface (not reachable via the MCP `scan_cloud` tool), by design.

**Paired with EE 0.32.3** — a **matrix-neutral** RDS false-negative depth pass: plugin 1140 now audits **cluster-level SSL enforcement** (closing a cleartext false-negative on instance-less Aurora Serverless v1 clusters, whose cluster parameter group was never checked) and applies **staged-parameter (`ParameterApplyStatus`) discipline** so a set-but-not-yet-applied `rds.force_ssl` / `pgaudit` is no longer affirmed as effective. No new framework, plugin count UNCHANGED at 28, all seven coverage matrices UNCHANGED (the new cluster findings route to existing transit-encryption controls via a titlePattern-only anchor edit). Paired **EE 0.32.3** + **agent-skill 0.2.26**.

---

## 0.2.27 (2026-07-10) — Paired content bump for EE 0.32.2 (GRC connector trio complete — Secureframe + cross-framework report-quality leak closure)

Paired version bump for the EE 0.32.2 trio — no CE code change this cycle. EE 0.32.2 is a **matrix-neutral** release with two legs: (1) a new **Secureframe** GRC push connector completes the Vanta · Drata · Secureframe trio at the same early-access opt-in shape (records model — NSAuditor pushes structured control records to a workspace evidence collection and your Secureframe rules evaluate them; outbound, single-workspace, opt-in; API shape published-assumed, live-tenant validation deferred); and (2) the **cross-framework foreign-token leak** in the Enterprise compliance rationales is closed — an internal `Inherits from soc2.json CC6.1` note, bare foreign control-ids, cross-framework routing-maps, and a `real-engine verified ==` QA-note no longer leak a foreign framework's name into a HIPAA / PCI / ISO / NIST / CIS / GDPR Report on Compliance (~300 rationales across all seven frameworks, pure-deletion + class-level guard, routing byte-neutral). No new framework, plugin count UNCHANGED at 28, all seven coverage matrices UNCHANGED. Paired **EE 0.32.2** + **agent-skill 0.2.25**.

---

## 0.2.26 (2026-07-09) — Paired content bump for EE 0.32.1 (compliance report-quality hygiene + deeper positive-substrate curation + GRC-connector DRY refactor)

Paired version bump for the EE 0.32.1 trio — no CE code change this cycle. EE 0.32.1 is a matrix-neutral patch: it cleans internal engineering markers (`[[wiki-links]]`, `EE-RT` work-codes, reviewer-codes, `Rn-SEVERITY` review-round IDs) out of the "Why this violates" rationales that render into every Report on Compliance across all seven frameworks (~900 rationales), fixes a KMS-parse-failure rationale that leaked a reviewer-code + a foreign-framework token into all seven reports, opts more Azure + deeper-AWS PASS-tier findings into the display-only positive-substrate RoC view, and collapses the Vanta + Drata push loops into a shared `_runPushBatch`. No new framework, plugin count UNCHANGED at 28, all seven coverage matrices UNCHANGED. Paired **EE 0.32.1** + **agent-skill 0.2.24**.

---

## 0.2.25 (2026-07-07) — Paired content bump for EE 0.32.0 (Enterprise GRC push activation — Vanta + Drata)

Paired content bump — **no CE engine/CLI/MCP change this cycle**. The README "What's New" is trimmed to a concise headline + CHANGELOG pointer, and a new **GRC Connectors (Vanta & Drata)** section documents the Enterprise scan-time GRC push (opt-in via `COMPLIANCE_GRC_PROVIDER`, ZDE-redaction-gated, per-platform status + honest-status callout). **EE 0.32.0** ships the headline: the Vanta push connector is now wired for scan-time activation and a new Drata connector (Custom Connections) ships alongside it, plus the T1/T2 AWS positive-substrate curation (60 PASS-tier findings; display-only, non-flipping, count-neutral). Live validation against production Vanta/Drata tenants is in progress — early-access, single-workspace, not a multi-tenant sync. **No new plugins (still 28), all seven coverage matrices UNCHANGED.** Paired **EE 0.32.0** + **agent-skill 0.2.23** (peer `nsauditor-ai >=0.2.8` unchanged).

## 0.2.24 (2026-07-05) — Multi-cloud scope-integrity: `--host aws,gcp,azure` / `--host-file` CLOUD_PROVIDER reconcile (false-clean fix) + manifest skip-status

Closes a **false-clean** in the multi-cloud one-liner: `--host aws,gcp,azure` (and a `--host-file` of cloud sentinels) under a stale or tool-implied `CLOUD_PROVIDER` silently skipped the un-covered cloud legs and reported them **"audited-clean" over zero API calls**. CE-side, matrix-neutral, TDD'd + externally reviewed across two rounds (Mythos 🟢 SHIP-CLEAR on both commits).

- **Move 2.7 — `resolveScanEnv` CSV/host-file reconcile (`utils/env_loader.mjs`):** the reconcile previously fired only for a SINGLE sentinel host, so the CSV multi-host form never matched. It now derives the distinct cloud legs from a `--host` string (single **or** CSV) **and** a `--host-file` resolved host list, and either **fail-fasts** (an operator-pinned `CLOUD_PROVIDER` that misses any leg → a hard error, not a silent skip) or **implies the union** of the legs. Throw-vs-imply keys on operator-pinned (captured *before* the `--aws-profile` implication), so the reasonable `--aws-profile prod --host aws,gcp,azure` flow union-merges instead of wrongly throwing. All three panel-found reachability paths closed (stale `.env`, `--aws-profile` self-poison, `--host-file` with `host=undefined`). `sentinelLegs` gives the `--host-file` source precedence over `--host` (mirrors the CLI's host-file-XOR-host dispatch — no over-widening, no false-positive throw). Help text corrected to match.
- **Move 2.8 (cheap half) — manifest skip-status (`plugin_manager.mjs`):** both classifiers now map a gate-skip envelope `{up:false, skipped:true, …}` to status `'skipped'` (only when nothing ran + no timeout/error — timeout/error still win, a skip+real-run mix stays `'ran'`), so a self-skipped cloud drops out of `auditedProviders` → the pre-existing anti-false-clean note surfaces `audited:false` instead of a bare "audited, 0 findings".
- TDD throughout (RED→GREEN, mutation-proven guards + an argv-level `--host-file` end-to-end test); regression **1198 / 1197 pass / 1** pre-existing license-env baseline; no framework/plugin change. Paired **EE 0.31.10** (the in-tree GCP scope-integrity gate for 1024/1025 + T4 positive-substrate) + agent-skill 0.2.22 (peer `>=0.2.8` unchanged). Deferred residuals (`--host <path>` implicit host-file, the strict-gate skip envelope across 5 plugins, the up-front-parse TOCTOU) tracked for the next cycle.

---

## 0.2.23 (2026-07-03) — Operator bug-fix cycle: network-host cloud-scope integrity (BUG2b) + AI-conclusion robustness (BUG1) + bail-message (BUG2a)

A **real Community-Edition fix cycle** (not a paired no-op) addressing three operator-reported bugs from a live test against the test-infra + a router host (`tasks/BUG_REPORT.md` in the paired EE repo). Each fix was TDD'd and externally reviewed across multiple rounds (Mythos: CHANGES REQUESTED → fold → 🟢 PASS) with fable-5 adversarial-review workflows.

- **BUG2b — cloud-scan scope integrity (was MEDIUM-HIGH):** cloud auditor plugins ran during a `--host 192.168.1.1` **network** scan (they self-gated only on `CLOUD_PROVIDER` + credentials in the environment, ignoring the host). New operator-confirmed contract: a cloud auditor runs **if and only if** the host is its own cloud sentinel (`aws`/`gcp`/`azure`) — `--host` is the sole cloud-intent signal; credentials are a capability, never intent; there is no escape hatch. `plugin_manager.run()` now excludes every `cloudProvider`-tagged plugin whose provider ≠ the host's sentinel (a network host strips all cloud plugins; `--host gcp --plugins 1020` strips the foreign AWS auditor), for the implicit `all` **and** an explicit `--plugins` selection, across **every** dispatch route — `run` / `runByName` / `runCloud` / the MCP `probe_service` single-plugin tool. Excluded plugins emit a `skipped` manifest entry (machine-visible), `opts.hostKind` is threaded as a defense-in-depth signal, `findingsCount` now rolls in cloud findings (was service-level only → a false-clean cloud-scan history), and the CLI `--help` documents the network-host inverse.
- **BUG1 — AI-conclusion robustness:** the AI conclusion aborted on cloud-scale payloads (a fixed 120s AbortController). The timeout now **scales with payload size** (120s floor → 600s ceiling; an explicit `NSA_AI_TIMEOUT_MS` wins and is also applied as the SDK request timeout, with `maxRetries: 0` so the abort can't race SDK-internal retries); on failure the pipeline writes a **visible** `scan_response_ai.txt` stub naming the error + the `NSA_AI_TIMEOUT_MS` remedy (was fail-quiet — only a JSON error file + a scrolled-away `console.error`); and a one-line end-of-scan AI status is printed.
- **BUG2a:** the AI bail message no longer prints "AI_ENABLED=false" when AI is enabled and the API **key** failed to resolve — it names the provider env var (e.g. `ANTHROPIC_API_KEY`).

Also hardened during review: the MCP `probe_service` route (M-1) and a follow-up SSRF fold (M1-SSRF — a network plugin is rejected on a cloud-sentinel host, so the sentinel whitelist can't reopen the SSRF boundary). Full CE suite **1175 / 1174 pass / 1 fail** (the 1 = a pre-existing environment-dependent license-tier test). Paired **EE 0.31.9** + agent-skill 0.2.21. **EE 0.31.9 requires CE 0.2.8+** — the cloud-scope fix is CE-side and works with any installed EE.

---

## 0.2.22 (2026-07-01) — Paired content bump for EE 0.31.8 (GAP-1 positive-substrate polish: framework-aware PCI Req 10.5.1 caveat restoration + SOC 2 GRC-push hygiene)

No CE engine behavior change — detection and compliance routing live in the Enterprise engine; this is a paired content bump (README + this changelog). EE 0.31.8 restores per-framework precision to the 0.31.7 positive-substrate caveat: the RDS audit-log-retention substrate finding routes to both PCI DSS 10.5.1 and (via the inheritance anchor) SOC 2 CC7.2, and now carries a per-framework caveat override so the PCI report restores the `Req 10.5.1` citation while SOC 2 keeps the neutral base (no PCI leak). It also hardens the mechanism (framework-neutral category so no `pci` machine substring rides the SOC 2 renderJSON → GRC-connector push, empty-string-safe caveat selection, genuine renderJSON GRC-channel tests). **No new framework, no new plugins (still 28), all seven coverage matrices UNCHANGED.** Paired **EE 0.31.8** + agent-skill 0.2.20. **EE 0.31.8 requires CE 0.2.8+.**

---

## 0.2.21 (2026-06-29) — Paired content bump for EE 0.31.7 (RDS audit-log no-false-clean (generation + retention) + opt-in positive-substrate RoC surfacing)

No CE engine behavior change — detection and compliance routing live in the Enterprise engine; this is a paired content bump (README + this changelog). EE 0.31.7 closes the *zero-audit-log* false-clean: a database producing no audit logs (CloudWatch exports off, or PostgreSQL pgAudit disabled/misconfigured) now fails closed against every framework's audit-log-**generation** control (SOC 2 CC7.2 · HIPAA §164.312(b) · PCI 10.2.1 · CIS 8.2 + 8.5 · NIST PR.PS-04 · ISO A.8.15, + NIST DE.CM-09 for pgAudit) — not the retention controls. It also adds a conservative PCI DSS 10.5.1 ≥12-month retention substrate and surfaces opt-in positive-substrate evidence per-control in the RoC. **No new framework, no new plugins (still 28), all seven coverage matrices UNCHANGED.** Paired **EE 0.31.7** + agent-skill 0.2.19. **EE 0.31.7 requires CE 0.2.8+.**

---

## 0.2.20 (2026-06-27) — Paired content bump for EE 0.31.6 (RDS enumeration-truncation no-false-clean class CLOSED + audit-log retention routing-depth sweep; CIS matrix 17/22/114 → 17/23/113)

No CE engine behavior change — detection and compliance routing live in the Enterprise engine; this is a paired content bump (README + this changelog). EE 0.31.6 closes the RDS *enumeration-truncation* silent-false-clean class across all four plugin-1140 enumerators (snapshots, live DB/cluster lists, audit-log groups now fail closed on page-cap truncation), registers the RDS auditor in the compliance-engine drift detector, and maps RDS audit-log retention to every framework's retention control — flipping **CIS Controls v8 Safeguard 8.10 "Retain Audit Logs" OOS → partial** (CIS matrix **17/22/114 → 17/23/113**; IG1 cyber-insurance baseline UNCHANGED at 23/56). The other six coverage matrices are UNCHANGED; plugin count UNCHANGED at 28. Paired **EE 0.31.6** + agent-skill 0.2.18. **EE 0.31.6 requires CE 0.2.8+.**

---

## 0.2.19 (2026-06-26) — Paired content bump for EE 0.31.5 (RDS Multi-AZ DB cluster REAL snapshot detection + at-rest snapshot routing fleet sweep)

A paired content bump — no CE engine behavior change. The Enterprise engine promotes a non-Aurora RDS Multi-AZ DB cluster snapshot to real detection (public `restore=all` CRITICAL, cross-account / unencrypted HIGH) and closes a cross-framework **single-framework snapshot false-clean** (an unencrypted snapshot now routes to the at-rest control in **all seven** frameworks; a public/cross-account share also routes to access-control — SOC 2 CC6.1 + the Required HIPAA §164.312(a)(1)). **No new framework, no new plugins (still 28), no coverage-matrix changes.** Paired with EE 0.31.5 + agent-skill 0.2.17. **EE 0.31.5 requires CE 0.2.8+.**

## 0.2.18 (2026-06-25) — clearer sentinel-host auto-scope skip message (multi-cloud)

The per-host auto-scope log line no longer implies other clouds are dropped. On a multi-cloud run (`--host aws,gcp,azure`) the AWS pass printed `skipping 35 non-aws plugin(s) (other clouds + non-cloud)` — misleading, because Azure/GCP **are** scanned, just on their own pass. Now reads: `skipping 35 non-aws plugin(s) not applicable to this host (other-cloud plugins run on their own --host pass; non-cloud plugins need a network host/CIDR)`. The `--host` `--help` auto-scope note is reworded to match. Message-only change (no behavior change); CLI-only (CE). Paired EE 0.31.4 + agent-skill 0.2.16.

## 0.2.17 (2026-06-25) — `--host` multi-cloud comma list + clearer help (CLI usability fix)

`--host aws,gcp,azure` now scans **one or more clouds in a single run** (comma-separated; `--host aws` for one cloud). Previously a comma list was treated as a single bogus hostname and rejected by the SSRF guard (`getaddrinfo ENOTFOUND aws,gcp,azure`) — there was no way to audit multiple clouds in one command. `parseHostArg` now splits a comma list and parses each token, so cloud sentinels, CIDRs, ranges, and plain hosts all compose (e.g. `aws,10.0.0.0/30`); the existing multi-host loop scans each. The `--host` `--help` now documents the comma form, shows a `--host aws,gcp,azure` example, and warns that the `aws|gcp|azure` (pipe) form is *notation* — a shell treats `|` as a pipe. **CLI-only change (CE)**; EE 0.31.4 unaffected (peer `nsauditor-ai >=0.2.8` unchanged). TDD: 5 new `parseHostArg` comma tests (RED→GREEN); host_iterator suite 29/29. Paired EE 0.31.4 + agent-skill 0.2.16.

## 0.2.16 (2026-06-25) — `--compliance` --help docs for EE 0.31.4 (cloud-scan presentation false-clean fix + `--compliance all`)

The CE `--help` for `--compliance` now documents **`all`** (= all seven frameworks), the seven valid stems + aliases (`nist`/`pci`/`iso`/`cis`), and the new **fail-fast on an unknown token** behavior — plus a copy-pasteable `--compliance all` example (the full-cloud-audit invocation). Paired content bump for the Enterprise **"Cloud-scan presentation false-clean fix + `--compliance all` / fail-fast validation"** cycle: a `--host aws|azure|gcp` scan with real findings no longer surfaces the network concluder's *"Host is UP — No open services detected"* over real misconfigurations (the conclusion is rewritten in the Enterprise engine, before the tier gate), and a plugin that times out/errors routes to **coverage UNVERIFIED** instead of an affirmative clean verdict. **No CE engine behavior change beyond the `--help` text** (the detection + conclusion-rewrite live in the Enterprise engine). **No new framework, no new plugins (still 28), no coverage-matrix changes.** Paired with EE 0.31.4 + agent-skill 0.2.16. **EE 0.31.4 requires CE 0.2.8+.**

## 0.2.15 (2026-06-24) — Paired content bump for EE 0.31.3 (Enumeration-failure fleet sweep + Aurora DB-cluster snapshot dimension)

Paired content bump (no CE engine behavior change). EE 0.31.3 is a false-negative hardening patch: it closes a fleet-wide class of **enumeration-failure** false-cleans across **12 AWS plugins** — a scanner that cannot enumerate a resource population now fails **CLOSED** with a routed evidence-gap instead of reading CLEAN (covering the uncaught-escape, in-region-catch, and AccessDenied-arm variants) — and adds the Aurora **DB-cluster snapshot** dimension to plugin 1140 (the cluster snapshot surface instance-level scans never see — a public `restore=all` cluster snapshot is CRITICAL, an unencrypted one HIGH), with a Multi-AZ DB cluster fail-close. **No new framework, plugin count UNCHANGED at 28, all seven coverage matrices UNCHANGED** (titlePattern-only anchor loosening). The CE-side `scan_cloud` description (which already names all seven frameworks) is unchanged; this is a README/version content bump for marketing lockstep. Paired with EE 0.31.3 + agent-skill 0.2.15. **EE 0.31.3 requires CE 0.2.8+.**

## 0.2.14 (2026-06-22) — Paired content bump for EE 0.31.2 (At-rest → ISO A.8.24 fleet sweep + cross-cloud KEY-CUSTODY-HOME doctrine + SOC 2 file-lock fix)

Paired content bump (no CE engine behavior change). EE 0.31.2 is a compliance-mapping depth + cross-cloud routing-doctrine release: it completes **every AWS at-rest-encryption source** (RDS · S3 · EC2/EBS · SQS/SNS · ElastiCache) to the canonical 7-control at-rest set {SOC 2 C1.1 / HIPAA 164.312(a)(2)(iv) / NIST PR.DS-01 / PCI 3.5.1 / ISO A.8.24 / CIS 3.11 / GDPR Art.32(1)(a)}, fixes the DynamoDB + EC2-indeterminate class-O false-cleans (an unverifiable/unclassifiable encryption posture now fails-close instead of reading CLEAN), and establishes the **cross-cloud KEY-CUSTODY-HOME doctrine** — a provider-managed key on an always-encrypted service routes to {SOC 2 C1.1 (GCP CC6.1) / HIPAA / ISO A.8.24} (key management), not the encryption-presence set, closing a live PCI 3.5.1 + GDPR Art.32(1)(a) over-claim on always-encrypted Azure storage. It also fixes a SOC 2 "no silent data loss" mutual-exclusion bug in the Enterprise-side suppression/WORM file lock. **No new framework, plugin count UNCHANGED at 28, all seven coverage matrices UNCHANGED.** The CE-side `scan_cloud` description (which already names all seven frameworks) is unchanged; this is a README/version content bump for marketing lockstep. Paired with EE 0.31.2 + agent-skill 0.2.14. **EE 0.31.2 requires CE 0.2.8+.**

## 0.2.13 (2026-06-21) — Paired content bump for EE 0.30.1 (AWS RDS + API Gateway false-negative depth pass + AXIS_MAP graduation)

Paired content bump (no CE engine behavior change). EE 0.30.1 is a detection-depth + mapping-correctness patch closing the last two AWS sources' silent false-cleans: **RDS (1140)** gains a snapshot-sharing dimension (a `restore=all` shared snapshot is CRITICAL public exposure even when encrypted) + a `DescribeDBInstances` evidence-gap + 57 class-O routing anchors; **API Gateway (1050)** closes its WAF deep-audit gap arm (6 evidence-gaps now fail-close the WAF native set == the positives) + unknown-auth + WebSocket-skip + deleted-WebACL + unencrypted-cache routing. Both graduate `KNOWN_UNCOVERED → AXIS_MAP`, so every AWS source now has a dedicated false-negative pass. Cross-framework parity folds route the API Gateway resource-policy public-grant to **PCI 7.2.1 + GDPR Art.32(1)(b)**, the deleted-WebACL to **PCI 6.4.1 / ISO A.8.21**, and the unencrypted cache to **ISO A.8.24**. **No new framework, plugin count UNCHANGED at 28, all seven coverage matrices UNCHANGED.** The CE-side `scan_cloud` description (which already names all seven frameworks) is unchanged; this is a README/version content bump for marketing lockstep. Paired with EE 0.30.1 + agent-skill 0.2.13. **EE 0.30.1 requires CE 0.2.8+.**

## 0.2.12 (2026-06-18) — Paired content bump for EE 0.30.0 (AWS + Azure false-negative depth-pass + cross-source compliance-mapping parity)

Paired content bump (no CE engine behavior change). EE 0.30.0 is a detection-depth + mapping-correctness release: it closes a wave of cloud-misconfiguration false-negatives across AWS (S3 access-point public-exposure · resource-policy effective-exposure on Lambda/DynamoDB/SQS-SNS/VPC-endpoints/Secrets/API-Gateway · EC2-SG public-vs-private-CIDR + split-range · KMS effective-decrypt + cross-account key-policy · IAM ListUsers truncation) and Azure (storage/NSG/Key-Vault/cloud-scanner class-O fail-opens), then makes the compliance verdict consistent across all seven frameworks (architecturally-identical confidentiality / least-privilege exposures route to the same controls — incl. a public application entry-point now on NIST CSF **PR.AA-05**). **No new framework, plugin count UNCHANGED at 28, all seven coverage matrices UNCHANGED.** The CE-side `scan_cloud` description (which already names all seven frameworks) is unchanged; this is a README/version content bump for marketing lockstep. Paired with EE 0.30.0 + agent-skill 0.2.12. **EE 0.30.0 requires CE 0.2.8+.**

## 0.2.11 (2026-06-12) — Paired content bump for EE 0.20.0 (GDPR Article 32 — the 7th compliance framework)

> **Published 2026-06-12 — live on npm.**

Paired content bump (no engine behavior change). EE 0.20.0 adds the **seventh compliance framework**: GDPR **Article 32 (security-of-processing) infrastructure substrate** — mapped against Regulation (EU) 2016/679, an 11-unit sub-measure matrix (4 covered / 5 partial / 2 OOS) — explicitly **GDPR Article 32 infrastructure substrate ONLY, NOT GDPR compliance** (Art. 32 is the only article an infrastructure scanner can substrate-evidence; the rest of GDPR's 99 articles are OOS-by-design). On the CE side: the `scan_cloud` tool description now **lists GDPR Article 32 (security-of-processing substrate)** alongside the existing six frameworks, so Desktop agents surface it; the paired **agent-skill 0.2.11** teaches the 7th framework (scope doctrine, four-factor proportionality, sub-measure discipline, Art. 83(4) lower fine tier). Plugin count UNCHANGED at 28; the six existing coverage matrices UNCHANGED. Paired with EE 0.20.0 + agent-skill 0.2.11.

## 0.2.10 (2026-06-11) — MCP affordance II: actionable-finding visibility (category rollup) + `get_findings` drill-down (paired with EE 0.19.4 + agent-skill 0.2.10)

A **real Community Edition feature** that closes the MEDIUM-invisibility false-clean surfaced by the EE 0.19.4 Claude Desktop validation: the `scan_cloud` summary itemized only CRITICAL/HIGH + evidence-gaps, so actionable MEDIUM/LOW findings (e.g. 4 live SQS/SNS no-alarm MEDIUMs) were count-only and a Desktop agent narrated "the alarm dimension came back clean" while they fired.

- **Category rollup** (`utils/cloud_finding_summary.mjs`): the `scan_cloud` summary now rolls up MEDIUM + LOW findings per provider by `details.category`, count-descending (e.g. `MEDIUM (8) sqs-age-alarm-missing ×2 · sns-failure-alarm-missing ×2 · …`). LOW is counts-only; gap-marked findings stay in the `evidenceGaps` channel (no double-count); a per-plugin `uncategorized(<id>)` fallback keeps the rollup actionable for category-less plugins. No-silent-cap — the line *compacts*, it never *caps*.
- **`get_findings` (NEW MCP tool, Enterprise-gated):** drills the MOST RECENT scan's per-provider cache — filter by provider/plugin/severity/category, paginate (`cursor`/`limit`, server-capped at 20 + disclosed), and get the FULL untruncated finding text. The cache is per-provider (one slot each, last-writer-wins), per-session (cleared on server restart), keyed by a monotonic `scanId` the `scan_cloud` summary footer carries. The Enterprise dispatch gate covers `get_findings` BEFORE any cache read — a CE/Pro caller gets the same 🔒 denial as `scan_cloud`, never cached Enterprise findings.
- **Collector fixes:** the evidence-gap companion now joins ALL actionable clauses (not just the first); `describeFinding` truncates on a word boundary (the full text is reachable via `get_findings`); evidence-gaps carry a `gapKind` (`walkthrough-required` vs `couldnt-read`, fail-close default). The `scan_cloud` description now steers agents to prefer it over raw cloud-provider APIs/MCPs.

Each change TDD'd (RED→GREEN) + reviewed; a committed integration test guards that the rollup line, its `get_findings` suffix, and the `scanId` footer compose in a single render. Paired with **EE 0.19.4** (unchanged — peer `nsauditor-ai >=0.2.8` already satisfied) + **agent-skill 0.2.10** (documents `get_findings`).

## 0.2.9 (2026-06-11) — Paired-release pin for EE 0.19.4 (Routing-Integrity Hardening)

Paired no-op bump (no Community Edition code change; README-refresh only). Enterprise 0.19.4 closes the routing-integrity false-clean class — a real finding (or a visible evidence-gap) that mapped to **zero** compliance controls while the verdict stayed green: a generic build-time routing guard (a complete-partition `nativeFrameworks` allowlist that fails the build on any marked-but-unrouted gap) + GuardDuty (1200) dedupe/class-O routing + a single-source `MULTI_REGION_GAP_PREFIX` routing prefix; a deferred-scope **unmark** across 8 plugins (a capability boundary is not an evidence-gap, so it no longer pollutes the MCP "unverified" list); the 1160 AWS-default VPC-endpoint full-access policy down-rated CRITICAL→MEDIUM with its 3 policy-gap emissions now routed (SOC 2 CC6.6 / HIPAA 164.312(a)(1) + cross-framework PCI 1.4.1 / ISO A.8.22 / CIS 12.2); and 1150 SQS/SNS alarm-independence (alarm posture is now classified even under a `Get*Attributes` deny, and all four `alarm-coverage-unverifiable` causes fail-close soc2{A1.2,CC7.2}+hipaa{164.312(b)}). **PCI DSS coverage matrix shifts 20/8/39 → 19/9/39** (Req 7.2.2 covered→partial — access-by-job-classification is process/HR-gated, a QSA-detectable overclaim — backed by 1030 over-privilege mapping); plugin count UNCHANGED at 28; the other five matrices UNCHANGED. No change to the MCP `scan_cloud` surface or schemas this CE exposes. Paired with EE 0.19.4 + agent-skill 0.2.9.

## 0.2.8 (2026-06-09) — MCP affordance: scan_cloud routing description + actionable gap-list visibility (paired with EE 0.19.3)

A **real Community Edition code change** (the first since 0.2.5), surfaced by the EE 0.19.2 Claude Desktop validation:

- **`scan_cloud` description is now a routing surface** (`mcp/mcp_server.mjs`): it enumerates the real per-service coverage (AWS S3 / IAM / KMS / CloudTrail / CodePipeline-CodeBuild SoD / Lambda / API GW / DynamoDB / RDS / SQS-SNS / Secrets / Backup / VPC endpoints / SG perimeter / ElastiCache / SES / GuardDuty; Azure Key Vault / Storage / NSG / RBAC; GCP firewall / storage / impersonation) plus the 6 compliance frameworks, and directs agents to use the tool for service-specific audit asks. Previously a service-named ask (e.g. "audit my CodePipeline approvals") was not routed to the scanner at all. `TOOLS` is exported for direct testing; 7 pin tests.
- **Badge-coherent, actionable gap lines** (`utils/cloud_finding_summary.mjs`): `describeFinding(x, {prefer})` classifies issue clauses (gap / substrate-PASS / actionable). The CRIT/HIGH findings list leads actionable-first; the `[⚠ EVIDENCE GAP]` list leads GAP-first and carries the first actionable clause as an `· actionable:` companion — a mixed rollup (e.g. a Key Vault over-privilege grant buried behind a key-enumeration gap clause) is no longer invisible via MCP. The new exported `GAP_CLAUSE_RE` is an exact source mirror of the EE evidence-gap anchor, **cross-repo drift-pinned by an EE meta-test**.
- **Review folds (cross-cutting pre-publish batch review):** the internal `EE-RT.x.y <token>:` compliance-routing tag is stripped at the presentation layer (it consumed up to 47 chars of each gap line's 160-char budget, cutting the remediation tail); the actionable companion is computed for all severities and deduped post-cap only when the finding's CRIT/HIGH list entry actually survived eviction; substrate-PASS clauses never lead a line while an alternative exists.

Paired with **EE 0.19.3** ("MCP affordance + class-O truncation sweep" — see the EE changelog) + agent-skill 0.2.8. EE 0.19.3 sets its peer floor to `nsauditor-ai >=0.2.8`.

## 0.2.7 (2026-06-08) — Paired-release pin for EE 0.19.2 (Confirmed false-negative tail)

Paired no-op bump (no Community Edition code change). Enterprise 0.19.2 closes six more gauntlet-confirmed Tier-B false-negatives across the Pro/Enterprise cloud auditors, each TDD'd + independently adversarially reviewed: **1222** Azure Key Vault legacy access-policy per-verb breadth (2-verb decrypt+unwrapKey envelope-decryption grant) + 2 surfaced titlePattern anchor-drifts + drift-detector closure; **1021** GCP broad-but-not-full public firewall ranges → HIGH (RFC1918 discounted); **1070** AWS KMS PendingDeletion keys now policy-audited (reversible deletion); **1100** CodePipeline sticky approval-latch (each prod stage needs its own gate); **1024** GCP Storage bucket-enumeration truncation evidence-gap (class-O); **1040** CloudTrail data-events read-coverage caveat (WriteOnly drops S3 GetObject). Plugin count UNCHANGED at 28; all six coverage matrices UNCHANGED at the count level. Paired with EE 0.19.2 + agent-skill 0.2.7.

## 0.2.6 (2026-06-08) — Paired-release pin for EE 0.19.1 (Confirmed false-negative batch)

Paired no-op bump (no Community Edition code change). Enterprise 0.19.1 closes seven gauntlet-confirmed Tier-B false-negatives across the Pro/Enterprise cloud auditors, each TDD'd (RED→GREEN) and independently adversarially reviewed with every confirmed review finding folded the same session: **1030** AWS IAM — prefix-glob privesc actions (`iam:Create*`/`iam:Put*`/`sts:Assume*`) now match the shadow-admin set + the access-key `Status`-casing dead-code is revived; **1150** AWS SQS/SNS — a wildcard-Principal SQS queue policy is now audited (was SNS-only) + glob-aware sensitive actions + wildcard-ARN resource scoping; **1130** AWS Backup — the air-gapped KMS key-policy verifier catches `kms:CreateGrant`/`kms:GenerateDataKey`; **1120** AWS S3 — versioned-bucket noncurrent-version disposal via a read-only `GetBucketVersioning` fetch; **1080** AWS Lambda — the bare `provided` (AL1) runtime + a no-more-allowlist-fail-open runtime check (unknown runtimes emit a routed currency evidence-gap); **1025** GCP IAM — `getOpenIdToken` + `workloadIdentityPoolProviders.create` admin-equivalence parity; **1160** AWS VPC endpoints — sensitive-action matching by service namespace. Plugin count UNCHANGED at 28; all six coverage matrices UNCHANGED at the count level (additive class-O anchors on already-covered controls). Paired with EE 0.19.1 + agent-skill 0.2.6.

## 0.2.5 (2026-06-07) — Paired-release pin for EE 0.19.0 (No silent false-clean)

Paired no-op bump (no Community Edition code change). Enterprise 0.19.0 is the largest false-clean-class closure since the framework cycles: an un-scanned cloud region, a denied API call, or a logging-but-not-delivering trail can no longer read CLEAN at EITHER the compliance verdict OR the MCP `scan_cloud` transport. The shared `forEachRegion` (used by all 16 regional AWS plugins) now emits a per-region `region-scan-evidence-gap` LOW + `evidenceGap` finding for every errored or access-denied region — pre-fix such a region was recorded in `scanScope` but emitted ZERO findings, so the findings-only compliance engine and the MCP summary both saw it as CLEAN — and class-O routing fail-closes EXACTLY that source's native attested controls across all six frameworks (additive titlePattern anchors; matrices UNCHANGED at the count level). Four per-plugin swallow→gap retrofits land alongside it: 1150 SQS/SNS region `AccessDenied`, 1022 Azure storage enumeration-error (now distinguishes SDK-absent soft-degrade from a real failure), 1200 GuardDuty `ListDetectors` `AccessDenied` (no longer mis-read as a definitive "GuardDuty NOT ENABLED" HIGH), and 1040 CloudTrail (`LatestDeliveryError` → a trail logging but failing to deliver to S3 is now flagged HIGH). EE 0.19.0 also closes two air-gapped/IAM criticals from the Mythos architecture review (the offline CVE matcher now fails-CLOSED on distro/epoch/build-suffixed package versions like `1.1.1i-1ubuntu` / `1:8.0p1` / `1.2.3+deb11u2`; plugin 1110 keeps HIGH on the AWS-default `…:root` root-delegation KMS key policy) and hardens AI-egress privacy (the AI-enrichment prompt no longer leaks the scan target — public IPv4/IPv6/hostname or MAC/email/AWS-key/Bearer/SNMP-community — to the external LLM, anonymizing every target host to a deterministic `[target-N]` label and routing the block through CE's content-scrubber). Plugin count UNCHANGED at 28; all six coverage matrices UNCHANGED at the count level. Paired with EE 0.19.0 + agent-skill 0.2.5.

## 0.2.4 (2026-06-05) — Paired-release pin for EE 0.18.3 (GCP IAM + Azure Key Vault false-negative hardening III)

Paired no-op bump (no Community Edition code change). Enterprise 0.18.3 closes three cloud false-negatives: an Azure Key Vault custom role granting ONLY a narrow data-plane crypto/extraction verb (`decrypt`/`wrap`/`unwrap`/…) is now flagged (plugin 1222); the GCP IAM service-account impersonation BFS now fail-closes on depth-cap truncation instead of reading "zero reachability paths" (plugin 1025 H3); and when the optional `googleapis` IAM Admin SDK is absent, the GCP IAM custom-role / SA-key / impersonation dims now fail-close to compliance-routed evidence-gaps instead of silently vanishing (plugin 1025 M2). Plugin count UNCHANGED at 28; all six coverage matrices UNCHANGED at the count level. Paired with EE 0.18.3 + agent-skill 0.2.4.

## 0.2.3 (2026-06-05) — scan_cloud evidence-gap visibility (the collector) — paired with EE 0.18.2 + agent-skill 0.2.3

The MCP `scan_cloud` summary now **surfaces** the no-false-clean evidence-gaps that the Enterprise cloud plugins emit. Previously `utils/cloud_finding_summary.mjs` itemized only CRITICAL/HIGH findings; evidence-gaps (emitted at LOW/INFO with `details.evidenceGap: true`) contributed only to severity counts, so a Desktop/MCP auditor saw a silent "LOW: N" over a surface the scanner could not actually read — a transport-layer false-clean (surfaced by the EE 0.18.1 Desktop validation, where the agent even misdescribed plugin coverage). `summarizeCloudFindings` now collects every finding carrying `details.evidenceGap === true` into a per-provider **`evidenceGaps`** array (severity-agnostic, independent of the CRITICAL/HIGH cap), `renderCloudFindingsMarkdown` adds an "[⚠ EVIDENCE GAP — unverified]" section, and the `scan_cloud` tool description tells the agent to read them as "unverified posture, NOT clean". **Additive** — counts and the CRITICAL/HIGH list are unchanged; existing consumers are unaffected. Paired with **EE 0.18.2** (which retrofits the AWS S3 / Azure / IAM plugins to carry the marker via a new CI producer-contract) + agent-skill 0.2.3.

---

## 0.2.2 (2026-06-05) — Paired docs release for EE 0.18.1 (GCP false-negative hardening II + read-only enforcement) + agent-skill 0.2.2

Paired CE bump (no CE code change). EE 0.18.1 batches five cycles on already-covered controls: **(1) plugin 1021 — split-range firewall full-IPv4 coverage** — a GCP INGRESS rule whose split `sourceRanges` union to the whole IPv4 internet (e.g. `0.0.0.0/1` + `128.0.0.0/1`) now flags as the `0.0.0.0/0` CRITICAL via a conservative full-coverage helper, instead of dodging the exact-string check; **(2) plugin 1025 — IAM impersonation-graph completeness** — the SA-impersonation BFS now fail-closes with a LOW evidence-gap (suppressing the over-confident `GRAPH_CLEAN`) when any input is degraded (per-SA policy denied, custom-roles unavailable, or either list pagination-truncated); **(3) plugin 1024 — default-object-ACL public exposure** — a bucket whose DEFAULT object ACL grants `allUsers`/`allAuthenticatedUsers` (every future object born public) is now detected, with empty/non-array treated as an evidence-gap not a PASS; **(4) fleet-wide read-only enforcement** — a new CI meta-test makes it impossible to ship a mutating cloud API call across all 28 plugins; **(5) read-only credential requirement** — EULA §5.5 + README/SECURITY guidance requiring read-only/least-privilege credentials. **Plugin count UNCHANGED at 28; all six coverage matrices UNCHANGED** (SOC 2 + HIPAA + NIST CSF 2.0 + PCI DSS v4.0.1 + ISO 27001:2022 + CIS Controls v8) — substrate-depth false-negative fixes on already-covered controls, NOT new controls.

---

## 0.2.1 (2026-06-03) — Paired docs release for EE 0.18.0 (GCP false-negative hardening) + agent-skill 0.2.1

No CE code change — a docs/paired bump that keeps the npm README current and pins the trio in lockstep with EE 0.18.0. The fixes live entirely in the `@nsasoft/nsauditor-ai-ee` package; CE is bumped so the published README tracks the current Enterprise release.

EE 0.18.0 closes five GCP false-negative CRITICAL/HIGH defects — all substrate-depth fixes on **already-covered controls** (no new controls):

- **GCP evidence-gap routing (plugin 1021)** — an `AccessDenied` GCP firewall / IAM / bucket enumeration now routes into the scan findings (single-owner anchors) and **FAILS** its controls instead of false-CLEANing at the compliance layer.
- **GCP project-IAM public-exposure now actually fires (plugin 1021)** — the project-IAM-public check called `getIamPolicy` on the Compute `ProjectsClient`, which has no IAM methods, so it failed on every live scan (`client.getIamPolicy is not a function`) and never detected a publicly-bound project IAM policy; it now reads the project IAM policy via the correct Resource Manager `ProjectsClient` (the client plugin 1025 already uses), so `allUsers` / `allAuthenticatedUsers` project-level bindings are detected instead of perpetually evidence-gapping. Caught by the new pack + global-install + test-infra smoke gate; live-validated under pure ADC.
- **GCP IAM auditor pure-ADC auth (plugin 1025)** — the `googleapis` IAM-admin client that powers Dim 4–6 (custom-role audit, service-account-key custody, and the impersonation BFS where the K1/K2 fixes live) only set auth for the impersonation / key-file modes; under **pure Application Default Credentials** it had no auth, and — unlike the `@google-cloud` gax clients (storage / resource-manager), which auto-detect ADC — the `googleapis` REST library does **not**, so Dim 4–6 returned `AccessDenied` even for a project owner and never ran live. Fixed with an explicit scoped `GoogleAuth` for the pure-ADC path. Pre-existing; same class as the plugin-1021 wrong-client fix above. Caught by the live Task-12 owner-ADC smoke.
- **Legacy-ACL public-exposure detection (GCP Cloud Storage, plugin 1024)** — a bucket made public via a legacy ACL (`allUsers` / `allAuthenticatedUsers`) while Uniform Bucket-Level Access is disabled was reading CLEAN; the auditor now scans the bucket ACL + a sampled object-ACL surface → CRITICAL / HIGH + evidence-gap (routed to SOC 2 CC6.6 / HIPAA 164.312(a)(1) / CIS v8 3.3).
- **GCP IAM impersonation-BFS completeness (plugin 1025)** — project-scope `roles/iam.serviceAccountKeyAdmin` now fires the project-scope impersonation CRITICAL (a long-lived key = offline impersonation of any service account), and a service account privileged via an admin-equivalent custom role (`iam.serviceAccounts.actAs`…) is now marked admin in the impersonation graph so paths terminating there are detected.

**Live validation (pure owner-ADC, test-infra GCP project).** With the pure-ADC fix in place, the impersonation findings were validated end-to-end against a real project: the project-scope `serviceAccountKeyAdmin` CRITICAL (K1) and a custom-role-`actAs` SA reached over a `tokenCreator` edge (K2) both fired live; Dim 4–6 confirmed running (`accessDeniedByApi: {}`); the plugin-1021 project-IAM read works live (no `getIamPolicy is not a function`); and the no-false-clean invariant held under degraded auth (evidence-gaps, never false-clean). The legacy-public-bucket (1024) and `allUsers` project-binding (1021) **findings** could not be created live because the org enforces `publicAccessPrevention` + `allowedPolicyMemberDomains` and the project owner lacks org-level policy-admin — environmental, not a product gap; those two paths remain unit-test + storage-enumeration-live proven. Fixtures were torn down and the project left clean.

Plugin count UNCHANGED at 28; all six coverage matrices (SOC 2 + HIPAA + NIST CSF 2.0 + PCI DSS v4.0.1 + ISO 27001:2022 + CIS Controls v8) UNCHANGED.

## 0.2.0 (2026-06-01) — `--aws-region` scoping + multi-region fan-out (paired with EE 0.17.0 + agent-skill 0.2.0)

**Minor-version feature release — the `--aws-region` flag + the MCP `scan_cloud` `regions` argument live in CE.**

NEW `--aws-region <one|csv|all>` CLI flag: scopes an AWS audit to a single region, a CSV of regions, or every account-enabled region (`all`). Built on a new canonical AWS-region data module (`utils/aws_regions.mjs`, no SDK dependency), a `RegionIntent` builder + validator (`utils/region_intent.mjs` — an unknown region fails fast for the explicit flag, warns-and-proceeds when derived from `AWS_REGION`; `NSA_AWS_REGION_ALLOW_UNKNOWN=1` bypasses for a brand-new region), threaded into the scan as `opts.awsRegionIntent`.

The MCP `scan_cloud` tool gains a `regions` argument with a **divergent default**: omit it to scan the server-configured `AWS_REGION` (single region) — omitting does **not** fan out; pass `["all"]` explicitly to scan every enabled region (so a Claude Desktop tool-call does not blow its ~60s timeout by default). An implicit-only "incomplete region coverage" advisory is emitted when the region scope is implicit (it maps to no compliance control, so posture is unchanged).

Precedence: `--aws-region` › `AWS_REGION` › single-region default. The per-region fan-out + scoping is executed by the EE regional plugins (see EE 0.17.0). Plugin count UNCHANGED at 28; all six coverage matrices UNCHANGED.

## 0.1.98 (2026-05-31) — Paired no-op bump for EE 0.16.7 + agent-skill 0.1.66

No CE code change. Trio-versioning pin for EE 0.16.7 (CloudTrail plugin 1040 multi-region hotfix: per-region client fast-fail timeout + an errored region no longer discards the whole multi-region scan). The fix is in the `@nsasoft/nsauditor-ai-ee` package; CE is bumped to keep the trio in lockstep.

## 0.1.97 (2026-05-31) — Paired no-op bump for EE 0.16.6 + agent-skill 0.1.65

No CE code change. Trio-versioning pin for EE 0.16.6 (CloudTrail soft-budget `min()` regression hotfix + plugin 1110 KMS AWS-managed-key grant-decrypt false-positive fold + compliance-engine PASS-tier-not-a-violation fold). All three fixes are in the `@nsasoft/nsauditor-ai-ee` package; CE is bumped to keep the trio in lockstep.

## 0.1.96 (2026-05-31) — Paired no-op bump for EE 0.16.5 + agent-skill 0.1.64

EE 0.16.5 fixes four compliance-mapping false-cleans (perimeter exposures now route cross-framework to PCI/ISO/NIST; CloudTrail fails-closed on abort; GCP Cloud Storage emits an evidence-gap on enumeration failure; internal review-process markers + repo paths scrubbed from the shipped framework JSONs). These live entirely in EE (`data/compliance/*.json` + plugins 1040/1024) — **no CE code change**. Plugin count UNCHANGED (28); all six coverage matrices UNCHANGED.

## 0.1.95 (2026-05-30) — `scan_cloud` surfaces cloud findings (false-clean fix) — paired with EE 0.16.4 + agent-skill 0.1.63

### Fixed
- **`scan_cloud` now surfaces cloud findings directly from the scan results** (NEW `findingsSummary`: per-provider
  severity counts + the CRITICAL/HIGH list), instead of deriving them from the network-host concluder
  (`result_concluder.mjs`). That concluder is built for port/service scans and does not understand cloud compliance
  findings — it silently **dropped** them, so a scan could report `audited:true` with **0 findings over real
  CRITICALs** (shadow-admin IAM users, public Lambda URLs, internet-exposed security groups…). This is a distinct
  false-clean class from the 0.1.93 fold (which covered *not-audited* reported as clean); here the cloud **was**
  audited but the findings never reached the caller. Every finding in the raw results is now counted, and every
  CRITICAL/HIGH is listed (capped at `CLOUD_FINDINGS_CAP`, default 60, with a `truncated` flag — counts are never
  capped). The misleading host "conclusion" is no longer surfaced for the cloud path. No EE plugin change; the
  network `scan_host` path is unchanged.

### Changed
- **Scoping guidance:** the `scan_cloud` tool description and the agent skill now steer "audit my AWS account" to
  `providers:["aws"]` (audit only the cloud the user names), reducing over-auditing and concurrent load.

## 0.1.94 (2026-05-30) — parallel `scan_cloud` execution (fits the 60s MCP budget) — paired with EE 0.16.3 + agent-skill 0.1.62

### Changed
- **`scan_cloud` now runs cloud plugins concurrently** (default up to 20 at once) with a dedicated per-run
  timeout (`CLOUD_PLUGIN_TIMEOUT_MS`, default 25000ms), instead of sequentially under the network
  `PLUGIN_TIMEOUT_MS`. This lets a full ~20-plugin cloud audit complete within Claude Desktop's ~60s MCP
  tool-call limit — previously the heaviest, most security-critical plugins (IAM, S3, EC2, Inspector/GuardDuty,
  IAM decrypt-path) timed out at the 5s the 60s budget forced under sequential execution. Tunable via
  `CLOUD_SCAN_CONCURRENCY` (default 20). Cloud plugins are independent, so each runs in its own context; the
  network-scan / `scan_host` path is unchanged. The anti-false-clean reporting (a cloud is "audited" only if a
  plugin actually ran) is preserved — a timed-out plugin still surfaces as a coverage gap, never a clean pass.

### Fixed
- **`callPlugin` hardened against synchronously-throwing plugins** (review fold) — a plugin whose `run()` threw
  before its first `await` previously aborted the whole batch (sequential or parallel); `mod.run` is now wrapped
  so the throw becomes a handled per-plugin `error` and the other plugins still complete. A negative
  `CLOUD_PLUGIN_TIMEOUT_MS` is clamped to the default (no instant-timeout-everything).

---

## 0.1.93 (2026-05-30) — MCP `scan_cloud` tool: audit cloud accounts directly (paired with EE 0.16.2 + agent-skill 0.1.60)

### Added
- **MCP `scan_cloud` tool** — audit one or more cloud accounts (AWS / GCP / Azure) directly through the MCP
  server, with no network host: *"Audit my AWS account"* / *"Audit my AWS and Azure accounts"* (omit the
  providers to audit all). The MCP analog of the 0.16.0 CLI `--host aws --plugins all` scoping. Reuses the
  cloud-plugin scoping (new `scopeSelectionForProviders` + new `pluginManager.runCloud`); the handler
  save/sets/restores `CLOUD_PROVIDER` around the run so it never leaks into the next call. **Enterprise-gated**
  (`enterpriseMCP`), advertised to all tiers with an upgrade message — consistent with cloud scanning being the
  enterprise `cloudScanners` capability, with defense-in-depth at the plugin layer. No network host → no SSRF
  surface. No new plugin; no coverage-matrix change.
- **Anti-false-clean reporting** (closed an R-HIGH the `audit-cloud-plugin-false-negatives` review caught) — a
  cloud is reported "audited" only if ≥1 of its plugins actually ran. The response carries `audited` /
  `auditedProviders`; `pluginsRan` counts completed audits (not error envelopes); and any not-effectively-audited
  cloud (no plugins / missing credentials / skipped) is surfaced as an explicit note, never a silent empty "clean".

---

## 0.1.92 (2026-05-30) — MCP `NSA_ENV_FILE`: per-environment `.env` for the MCP server (paired with EE 0.16.1 + agent-skill 0.1.59)

The MCP analog of the 0.16.0 CLI `--env`. **No plugin-count or coverage-matrix change** — this is an MCP-server ergonomics + safety feature.

### Added
- **MCP `NSA_ENV_FILE`** — the MCP server now loads a per-environment dotenv file named by `NSA_ENV_FILE` at startup (reusing the 0.16.0 CLI `--env` loader `utils/env_loader.mjs#resolveScanEnv`, via the new thin `utils/mcp_env_file.mjs#applyScanEnvFile`). Switch scan environments by changing one path in the Claude Desktop / Claude Code config instead of editing every credential inline.
- Loaded in `startStdioServer()` **after** the auth gate + license resolution and **before** `createServer()`, so it carries **scan-target vars only** (cloud creds / `CLOUD_PROVIDER` / scan tuning) and can neither bypass the MCP auth gate nor escalate the license tier; `NSA_MCP_AUTH_KEY` / `NSAUDITOR_LICENSE_KEY` are **ignored** if present in the file.
- **Fail-fast** on a missing file, an INI/`~/.aws/credentials` file, or a set-but-empty `NSA_ENV_FILE` — the server refuses to start rather than silently scanning ambient credentials.
- **The file is the authoritative scan target:** ambient explicit provider credentials (e.g. a previous account's `AWS_*`/GCP/Azure keys left in the config `env` block) that the file does **not** set are cleared, so a partial file can't silently scan a leftover account. Instance-role / ADC identity is untouched. When `NSA_ENV_FILE` is unused, behavior is unchanged.

### Notes
- Built brainstorm → spec → TDD plan → subagent-driven, then reviewed through the `audit-cloud-plugin-false-negatives` lens (SHIP-WITH-FOLDS). The review verified the auth/license boundary, installed-entrypoint execution, fail-fast plumbing, and secret-name-only logging, and caught one **exploitable false-clean** — a partial env-file letting leftover ambient creds scan the wrong account — folded same-session (the authoritative-file clearing above + set-but-empty fail-fast).
- 13 new tests (`tests/mcp_env_file.test.mjs` 11 + `tests/mcp_env_file_shim.test.mjs` 2 — the shim test spawns the **installed** `bin/nsauditor-ai-mcp.mjs`, per the "test the installed entrypoint" lesson). CE regression GREEN (the single failing `license.test.mjs` case is a pre-existing environmental license-fixture artifact). No new dependencies.

---

## 0.1.91 (2026-05-29; paired with EE 0.16.0) — `--env` / `--aws-profile` + sentinel-host plugin scoping

### Added

- **`--env <path>`** — load a per-scan dotenv (`KEY=value`) file for that one scan (override-on: the file's values take precedence over existing shell variables). Fail-fast on a missing file. INI / credentials-format files (multi-section `[profile]`) are detected at load time and redirect with an actionable error to `--aws-profile`.
- **`--aws-profile <name>`** — use a named profile from the OS-default `~/.aws/credentials` (`%USERPROFILE%\.aws\credentials` on Windows). Clears any explicit `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` / `AWS_SESSION_TOKEN` already in the environment, sets `AWS_SDK_LOAD_CONFIG=1` so `~/.aws/config` is also read, and **implies `CLOUD_PROVIDER=aws`** (when unset) so you don't have to export it separately.
- **Sentinel-host plugin scoping** — `--host aws|gcp|azure` combined with `--plugins all` now runs **only that cloud's plugins**; the other clouds' plugins and the non-cloud network plugins are skipped (the skip is logged). Explicit `--plugins` lists (e.g. `--plugins 1020,1021`) are unaffected — scoping applies only to the `all` expansion.
- **Fix: bin wrapper now calls `main()`** — an entrypoint-guard regression was caught during development that would have made the installed CLI a silent no-op; fixed before release.

---

## 0.1.90 (2026-05-29; paired with EE 0.15.9) — Paired no-op for the EE 0.15.9 hotfix (cross-cloud bleed gate moved from preflight() to run() — the load-bearing path). No CE code change.

## 0.1.89 (2026-05-29; paired with EE 0.15.8) — Paired no-op for the EE cloud-plugin scoping fixes (AWS CLOUD_PROVIDER gate + GCP evidence-gap). No CE code change.

## 0.1.88 (2026-05-29; paired with EE 0.15.7) — Paired no-op for the EE GCP SDK refresh

No CE code change. Version bump preserves the trio + `@latest` pin alignment. EE 0.15.7 re-applies the GCP SDK major bump (`@google-cloud/compute` ^6 / `@google-cloud/iam` ^2 / `googleapis` ^173) on the pure-ADC credential path, documents the compute-client impersonation gap, and folds the plugin-1021 project-resolution fix. Plugin count UNCHANGED at 28; all six coverage matrices UNCHANGED.

## 0.1.87 (2026-05-28; paired with EE 0.15.6) — Paired no-op for the EE compliance-mapping correctness patch

No CE code/behavior change. Version bump preserves the trio + `@latest` pin alignment. EE 0.15.6 closes two cross-framework defects in the S3 public-exposure compliance routing: a publicly-accessible bucket now correctly maps to NIST CSF PR.AA-05 + PR.DS-01 and PCI DSS 7.2.1 (previously CLEAN on those two frameworks), and the missing-Public-Access-Block MEDIUM (a guardrail gap, not a confirmed exposure) no longer false-FAILs the confidentiality-exposure controls. Plugin count UNCHANGED at 28; all six coverage matrices UNCHANGED.

## 0.1.86 (2026-05-28; paired with EE 0.15.5) — Dependency-hygiene / institutional-trust patch

Removes npm deprecation warnings + advisories institutional clients see on `npm install`. No feature/behavior change.

- **In-house tech fingerprinter replaces the abandoned `simple-wappalyzer`.** NEW zero-dependency `utils/tech_fingerprint.mjs` (signature matching over HTTP headers / HTML / `<script src>` / cookies / `<meta>`; confidence `min(100, 25+25×matched-surfaces)`; `implies` + version extraction; 13 seed signatures) wired into `plugins/webapp_detector.mjs`, returning the same `{name, categories, confidence, version}` shape. Eliminates the deprecated `wappalyzer-core` transitive (Wappalyzer went commercial / unmaintained).
- **`@anthropic-ai/sdk` `^0.82.0` → `^0.100.0`** — exits the GHSA-p7fg-763f-g4gf (0.79.0–0.91.0) advisory range. CE only calls `messages.create` (the Filesystem Memory Tool the advisory concerns is never used).
- **Direct `uuid` dependency removed** — replaced by the native `crypto.randomUUID()` in `plugins/wsd_scanner.mjs` + `utils/finding_schema.mjs`.
- **NEW `SECURITY.md`** dependency-transparency statement.
- All tests green (1 pre-existing unrelated `license.test.mjs` failure aside).

## 0.1.85 (PUBLISHED 2026-05-28) — Paired with EE 0.15.4 plugin 1020 non-current-version ACL sampling + public WRITE-vs-READ differentiation

**Paired-publish for trio-publish discipline; no CE code changes.** EE 0.15.4 closes the two residuals the 0.15.3 spec §8 carried as deferred. **(R-MEDIUM-2)** NEW step 2c-v samples public ACLs on **non-current** object versions: when `GetBucketVersioning` Status is Enabled or Suspended (Suspended buckets RETAIN old versions), plugin 1020 calls `ListObjectVersions` (first-page, bounded by `AWS_S3_AUDIT_OBJECT_SAMPLE_CAP`), filters to `IsLatest !== true`, skips `DeleteMarkers`, and reads each with `GetObjectAcl({Key, VersionId})` — closing the Class-B miss where a private current object retains a public-ACL overwritten version still served at `?versionId=`. Public `AllUsers`/`AuthenticatedUsers` grant → CRITICAL via the existing `"publicly accessible"` anchor; PAB `IgnorePublicAcls` → LOW; skipped on `BucketOwnerEnforced`. **(R-LOW-1)** NEW `extractPublicWriteGroups` helper flags public WRITE/WRITE_ACP/FULL_CONTROL grants (anyone-can-overwrite) as a distinct enrichment line + counter on the already-CRITICAL finding at bucket/object/non-current-version ACL sites — no severity change, no new anchor. NEW evidence-gaps reuse the `"S3 object-ACL evidence-gap"` anchor: `ListObjectVersions AccessDenied` (distinct `s3:ListBucketVersions` IAM action) + per-version aggregate-failure threshold + version-list truncation + (folded from the `audit-cloud-plugin-false-negatives` review) a `GetBucketVersioning AccessDenied` gap (previously a silent skip of the whole version surface; now a routed LOW, suppressed on BOE). **Plugin count UNCHANGED at 28; all six coverage matrices UNCHANGED; ZERO framework-JSON edits.** No new dependencies; EE regression **6628/6628 GREEN** (+27 tests vs the 6601 baseline). The framework-agnostic CE engine consumes the new findings automatically once the EE package is installed. _(Staged on `main`; awaiting live AWS smoke on extended versioned fixtures + trio publish.)_

---

## 0.1.84 (2026-05-28) — Paired with EE 0.15.3 plugin 1020 object-level ACL enumeration + BucketOwnerEnforced short-circuit

**Paired-publish for trio-publish discipline; no CE code changes.** EE 0.15.3 closes the 4th and final S3 public-exposure vector (object-level ACLs) documented as a residual in the 0.15.2 closure. Plugin 1020 gains NEW step 2c sampled `GetObjectAcl` enumeration over first-page objects (`AWS_S3_AUDIT_OBJECT_SAMPLE_CAP` default 10, clamped `[1, 1000]`; `AWS_S3_AUDIT_OBJECT_RATE_MS` default 50ms throttle BEFORE each call) + NEW step 2a `GetBucketOwnershipControls` upstream short-circuit that skips both 2b (bucket-ACL) and 2c (object-ACL) on `BucketOwnerEnforced` buckets — the default ownership mode on every bucket created after April 2023; saves 11+ API calls per BOE bucket on modern estates AND closes a false-positive class. **INTENTIONAL MATRIX DELTA from 0.15.2**: BOE buckets with legacy stored public bucket-ACL grants previously emitted CRITICAL via 2b; they now emit informational only (downgraded to the BOE informational) because S3 structurally ignores ACL grants under BOE — the prior CRITICAL was a false-positive class. BOE short-circuit is unconditional (no env-var override). NEW shared `extractPublicGroups` helper used by BOTH step 2b (refactored byte-identical) AND step 2c. 4 LOW evidence-gap emissions via NEW `"S3 object-ACL evidence-gap"` substring anchor on SOC 2 CC7.1 + HIPAA §164.312(b) — surfaces ListObjectsV2 AccessDenied, IsTruncated coverage gaps, and per-object GetObjectAcl AccessDenied/other > `AWS_S3_AUDIT_OBJECT_ACL_PARTIAL_THRESHOLD` (default 0.5, strict >). **Plugin count UNCHANGED at 28; all six coverage matrices UNCHANGED**. No new dependencies; EE regression **6601/6601 GREEN** (+33 tests vs the 6568 baseline). Live AWS smoke against acct 522412052794 — all 4 spot-checks PASS (BOE detection; E1 CRITICAL en-dash byte preservation; cap clamping; objectRateMs throttling). The framework-agnostic CE engine consumes the new calibrated findings automatically once the EE package is installed.

---

## 0.1.83 (2026-05-27) — Paired with EE 0.15.2 audit-accuracy calibration + CloudTrail hardening + Azure 1221/1222 folds

**Paired-publish for trio-publish discipline; no CE code changes.** EE 0.15.2 is a patch cycle of four real-production-account-driven folds. **Fold 1** — plugin 1020 (S3) effective-public-exposure calibration: missing/partial Public Access Block downgraded CRITICAL→MEDIUM (a guardrail gap, not a current exposure), plus a NEW `GetBucketAcl` check completing the ACL × bucket-policy × PAB join (a public `AllUsers`/`AuthenticatedUsers` ACL grant → CRITICAL unless neutralized by PAB `IgnorePublicAcls`) — fixes false-CRITICALs AND closes a public-via-ACL false-negative. **Fold 2** — plugin 1040 (CloudTrail) KMS-CMK calibration: trail-level "KmsKeyId not set" downgraded MEDIUM→LOW when the destination bucket has default SSE-KMS (logs already CMK-encrypted at rest). **Fold 3** — plugin 1040 (CloudTrail) multi-region timeout hardening: an `AbortController` tied to the soft-budget deadline lets a hung disabled-region abort so the plugin finalizes PARTIAL evidence instead of being hard-cancelled with zero output. **Fold 4** — plugin 1221 (Azure NSG) +10 restricted UDP ports (RADIUS 1812/1813/1645/1646, L2TP 1701, SIP 5060, mDNS 5353, RIP 520, XDMCP 177, chargen 19) + plugin 1222 (Azure Key Vault) F-2 custom-role resolution (via `roleDefinitions.getById` + KV-privilege inspection) + F-7.2 HSM dim (software-vs-HSM `key.kty` LOW hardening rec). **Plugin count UNCHANGED at 28; all six coverage matrices UNCHANGED.** No new dependencies; EE regression **6568/6568 GREEN** (+42 tests vs the 6526 baseline). The framework-agnostic CE engine consumes the calibrated findings automatically once the EE package is installed.

## 0.1.82 (PUBLISHED 2026-05-27) — Paired with EE 0.15.1 plugin 1222 hotfix (Dim-3 SDK-shape + Dim-4 inherited-admin re-tune)

**Paired-publish for trio-publish discipline; no CE code changes.** EE 0.15.1 is a follow-up hotfix closing two defects in plugin 1222 (`azure-keyvault-deep-auditor`) surfaced by the 0.15.0 published-build live smoke. **H-1** — the Dim-3 diagnostic-logging probe `for await`-ed `@azure/arm-monitor`'s `diagnosticSettings.list()`, which returns a `Promise<{value:[]}>` collection object (NOT a paged async-iterator), so the dim always threw and degraded to a non-functional evidence-gap; fixed to `await` the call and read `.value` (confirmed against live Azure), with the unit-test mock corrected to the real `Promise<{value}>` shape (the mock-vs-real-SDK mismatch that masked the bug). **H-2** — the Dim-4 privileged-access dim flagged inherited subscription/management-group-scope Owner/Contributor as HIGH on every RBAC vault (a ubiquitous Azure control-plane reality); re-tuned so inherited Owner/User-Access-Administrator → MEDIUM, inherited Contributor → LOW, with HIGH reserved for VAULT-scoped control-plane god roles + Key Vault Administrator at any scope. **Plugin count UNCHANGED at 28; all six coverage matrices UNCHANGED.** Additive bug-fix only; EE regression **6526/6526 GREEN**. The framework-agnostic CE engine consumes the corrected findings automatically once the EE package is installed.

## 0.1.81 (PUBLISHED 2026-05-27) — Paired with EE 0.15.0 NEW plugin 1222 (Azure Key Vault Deep Auditor)

**Paired-publish for trio-publish discipline; no CE code changes.** EE 0.15.0 (Move C-2.3) adds NEW **plugin 1222 `azure-keyvault-deep-auditor`** — the third dedicated Azure auditor (after 1220 storage + 1221 NSG), the KV analog of how 1221 deepens 1022's flat NSG dim — taking the EE plugin count **27 → 28** (cloud-audit 26 → 27; ID range now 1020-1222). It enumerates each vault's keys, role assignments, and diagnostic settings across 4 dims: (1) key auto-rotation policy + (2) key expiry (epoch-s/ms/Date/string coerced) + (3) diagnostic logging → Log Analytics (`@azure/arm-monitor`) + (4) privileged-access depth (RBAC `roleAssignments` admin/data-plane/scope-aware + legacy `accessPolicies` export/wide-crypto breadth). Deliberately orthogonal to plugin 1022's vault-property dims (purge/soft-delete/network-ACL/RBAC-mode) — no double-emission. Secret/cert expiry is a deliberate data-plane scope boundary. Findings route across all six frameworks (SOC 2 CC6.3/C1.1/CC6.1/CC7.2 / HIPAA §164.312(a)(2)(iv)/(b)/(a)(1) / NIST CSF PR.DS-01/DE.CM-09/PR.AA-05 / PCI DSS 3.5.1/10.2.1/7.2.1 / ISO 27001 A.8.24/A.8.15/A.5.15+A.8.2 / CIS v8 3.11/8.2/5.4) — **all six coverage matrices UNCHANGED** (substrate-depth uplift on already-covered key-mgmt / logging / access controls). The CE `--compliance` CSV is unchanged; the framework-agnostic engine consumes the new findings automatically once the EE package is installed. README EE plugin catalog updated to the full 28 plugins (1020-1222); cloud-plugin count 26 → 27, enterprise-plugin count 27 → 28.

## 0.1.80 (PUBLISHED 2026-05-27) — Paired with EE 0.14.1 (plugin 1221 UDP restricted-port lane)

**Paired-publish for trio-publish discipline; no CE code changes.** EE 0.14.1 folds a **UDP restricted-port lane** into plugin 1221 (the Azure NSG perimeter auditor), closing the R-MEDIUM-2 false negative where a public-internet UDP management/amplification service (SNMP 161 / CLDAP 389 / NTP 123 / rpcbind 111 / IPMI 623 / IKE 500 / Memcached 11211, etc.) was silently bucketed as benign non-restricted "web tier" INFO. NEW Dim 2u/3u (UDP public-source + `::/0`), attachment-aware (attached → CRITICAL effective; orphaned → MEDIUM latent), per-transport priority/deny-override resolution; Dim-4 made protocol-aware (a UDP/restricted-port rule — or a range covering one — no longer mis-counts as benign INFO). The two per-port 1221 titlePatterns were generalized `permits TCP inbound …` → `permits (?:TCP|UDP) inbound …` across all six framework JSONs so UDP findings route to the same CC6.6/perimeter controls. **Plugin count UNCHANGED at 27; all six coverage matrices UNCHANGED.** EE regression 6495/6495 GREEN (+14). The CE `--compliance` CSV is unchanged; the framework-agnostic engine consumes the new findings automatically once the EE package is installed.

## 0.1.79 (PUBLISHED 2026-05-26) — Paired with EE 0.14.0 NEW plugin 1221 (Azure NSG Perimeter Auditor)

**Paired-publish for trio-publish discipline; no CE code changes.** EE 0.14.0 (Move C-2.2) adds NEW **plugin 1221 `azure-nsg-perimeter-auditor`** — the Azure analog of AWS plugin 1170 — taking the EE plugin count **26 → 27** (cloud-audit 25 → 26). It is a CC6.6 network-segmentation perimeter auditor for Azure Network Security Groups: evaluates each NSG's inbound rules in Azure priority order (first match wins; DenyAllInbound default) across all-protocol public Allow + public-source (`*`/`0.0.0.0/0`/`Internet`) to a restricted management/data-tier port + `::/0` IPv6-wildcard (the dimension the multi-purpose 1022 scanner's flat per-rule NSG lint misses) + public→non-restricted INFO + PASS substrate, with attachment-aware severity (attached → CRITICAL effective; orphaned → MEDIUM latent), effective priority/deny-override resolution, and `0.0.0.0/1` split-range coverage. Deliberately non-overlapping-by-depth with 1022's coarse NSG dim (no double-emission). Findings route across all six frameworks (SOC 2 CC6.6 / HIPAA / NIST CSF / PCI DSS / ISO 27001 / CIS v8) — **all six coverage matrices UNCHANGED** (substrate-depth uplift on already-covered perimeter controls). The CE `--compliance` CSV is unchanged; the framework-agnostic engine consumes the new findings automatically once the EE package is installed. README EE plugin catalog updated to the full 27 plugins (1020-1221); cloud-plugin count 25 → 26, enterprise-plugin count 26 → 27.

## 0.1.78 (PUBLISHED 2026-05-26) — Paired with EE 0.13.3 (plugin 1220 deepening: blob-recoverability + per-container public-access dims)

**Paired-publish for trio-publish discipline; no CE code changes.** EE 0.13.3 (Move C-2.1) deepens plugin 1220 with two new secondary-resource-path data-protection dims — blob recoverability (soft-delete + versioning via `blobServices.getServiceProperties`) + per-container anonymous public access (account-toggle-aware via `blobContainers.list`). Plugin count UNCHANGED at 26 (deepening, not a new plugin); all six coverage matrices UNCHANGED. The framework-agnostic CE engine consumes the new findings automatically once the EE package is installed.

## 0.1.77 (PUBLISHED 2026-05-26) — Paired with EE 0.13.2 NEW plugin 1220 (Azure Storage Account Data-Protection Auditor)

**Paired-publish for trio-publish discipline; no CE code changes.** EE 0.13.2 (Move C-2) adds NEW **plugin 1220 `azure-storage-hardening-auditor`** — the first dedicated Azure auditor beyond the multi-purpose 1022 scanner — taking the EE plugin count **25 → 26** (cloud-audit 24 → 25). It audits the Azure Storage Account encryption-at-rest / in-transit / authorization-mode surface (HTTPS-only `enableHttpsTrafficOnly` + minimum TLS version + Shared Key authorization `allowSharedKeyAccess` + infrastructure double encryption + customer-managed-key reachability + rotation `keyVaultProperties`), deliberately non-overlapping with 1022's network-exposure dims (no double-emission; mirrors the AWS 1020 + 1120 two-plugin S3 split). Findings route across all six frameworks (SOC 2 / HIPAA / NIST CSF / PCI DSS / ISO 27001 / CIS v8) — **all six coverage matrices UNCHANGED** (substrate-depth uplift on already-covered transit/auth/at-rest controls). The CE `--compliance` CSV is unchanged; the framework-agnostic engine consumes the new findings automatically once the EE package is installed. README EE plugin catalog updated to the full 26 plugins (1020-1220); cloud-plugin count 24 → 25, enterprise-plugin count 25 → 26.

## 0.1.76 (PUBLISHED 2026-05-25) — Paired with EE 0.13.1 CIS-Hardened-Image LIVE detection + plugin 1210

**Paired-publish for trio-publish discipline; no CE code changes.** EE 0.13.1 turns CIS-Hardened-Image detection LIVE and adds NEW **plugin 1210 `aws-ec2-instance-auditor`** (the AWS EC2 instance-level auditor + Hardened-Image producer), taking the EE plugin count **24 → 25**. Azure (1022) + GCP (1021) gain `cisImageInventory` capture so multi-cloud Hardened-Image detection fires end-to-end on CIS Safeguards 4.1/4.2/4.6. CIS Controls v8 matrix grows 17/21/115 → **17/22/114** (Safeguard 9.5 Implement DMARC OOS→partial; IG1 cyber-insurance baseline UNCHANGED at 23/56). All four ISO 0.12.1 deferrals closed (Major/Minor NC triage matrix + 93-control SoA template + 93-row 2013→2022 migration table + expectedOperatingCadence backfill). The CE `--compliance` CSV is unchanged; the framework-agnostic engine consumes the new producer feed automatically once the EE package is installed. README EE plugin catalog updated to the full 25 plugins (1020-1210).

## 0.1.75 (PUBLISHED 2026-05-24) — Paired with EE 0.13.0 CIS Critical Security Controls v8 sixth-framework introduction

**Cycle hook**: EE 0.13.0 ships CIS Critical Security Controls v8 (Center for Internet Security, May 2021; v8.1 errata June 2024) as the SIXTH Track 3 framework alongside SOC 2 + HIPAA + NIST CSF 2.0 + PCI DSS v4.0.1 + ISO/IEC 27001:2022. Per-Safeguard mapping (the atomic, attestable unit; coverage claimed at the SAFEGUARD level, never the Control level) — **17 covered + 21 partial + 115 OOS across 153 Safeguards / 18 Controls / 3 cumulative Implementation Groups** (engine substrate IG1 23-of-56 / IG2-cumulative 36-of-130 / IG3-cumulative 38-of-153). **Implementation Group cumulative discipline** (IG1=56 cyber-insurance baseline / IG2 cumulative=130 / IG3 cumulative=153; NEVER report IG2 as 74-of-74 in isolation) + **no-certification-body attestation discipline** (engine output is INPUT to CSAT / CIS-CAT Pro self-attestation OR a SOC 2 auditor cross-validating CIS scope, never "CIS certified") + Cloud Companion Guide v8 shared-responsibility-model boundary + CIS-Hardened-Image substrate-evidence credit (Safeguards 4.1/4.2/4.6) + 5 Security Functions (NOT 6 — no Govern) + 6 Asset Types + MS-ISAC/EI-ISAC/H-ISAC sector baselines + v7.1-to-v8 cross-reference. Skill #19 `audit-cis-controls-v8-implementation-group-perspective` authored 2026-05-24 via /skill-creator (833 lines / 5 files) per the Per-Framework Adversarial-Audit Skill Pairing pattern — surfacing 16 ship-blocker classes pre-author for a clean P5 ship.

**No CE code changes** — paired-publish for trio-publish discipline + customer discoverability. CE's `--compliance` flag accepts the new `cis-v8` value via the framework-agnostic `loadFrameworkMap()` engine; per-framework JSON ships with EE.

**Plugin catalog**: UNCHANGED at 24 plugins; CE plugin set unchanged. **SOC 2 + HIPAA + NIST CSF + PCI DSS + ISO 27001 matrices ALL UNCHANGED**; **CIS Controls v8 matrix NEW at 17/21/115 across 153 Safeguards**.

**THIRTY-SECOND consecutive trio-publish** institutionalized 0.4.5–0.13.0.

---

## 0.1.74 (PUBLISHED 2026-05-24) — Paired with EE 0.12.0 ISO/IEC 27001:2022 fifth-framework introduction

**Cycle hook**: EE 0.12.0 ships ISO/IEC 27001:2022 as the FIFTH Track 3 framework alongside SOC 2 + HIPAA + NIST CSF 2.0 + PCI DSS v4.0.1. Per-Annex-A-code mapping at the auditor-canonical level for ISO/IEC 17021-1 accredited certification body assessors walking Stage 1 (documentation) / Stage 2 (implementation + operating-effectiveness sampling) / annual surveillance / 3-year recertification. 17 covered + 14 partial + 62 OOS across 93 Annex A controls (the complete Annex A universe across 4 themes: A.5 Organizational 37 + A.6 People 8 + A.7 Physical 14 + A.8 Technological 34). 11 NEW 2022 controls explicitly enumerated (3 COVERED + 2 PARTIAL + 6 OOS). Statement of Applicability per Clause 6.1.3.d discipline + ISMS Clauses 4-10 OOS-by-design framing (7 Major Nonconformity classes — absence of internal audit per Clause 9.2 or management review per Clause 9.3 = auto-fail Stage 2) + 5-attribute taxonomy + 2013-to-2022 transition discipline (transition deadline passed October 31, 2025).

**No CE code changes** — paired-publish for trio-publish discipline + customer discoverability. CE's `--compliance` flag accepts the new `iso-27001` value via the framework-agnostic `loadFrameworkMap()` engine; per-framework JSON ships with EE.

**Plugin catalog**: UNCHANGED at 24 plugins; CE plugin set unchanged.

**THIRTY-FIRST consecutive trio-publish** institutionalized 0.4.5–0.12.0.

---

## 0.1.73 (PUBLISHED 2026-05-23 to npm as `latest`) — Paired with EE 0.11.1 PCI DSS v4.0.1 patch cycle (CAO authorship + 4 R-MEDIUM folds + `license --reset` subcommand)

NEW CE-side `nsauditor-ai license --reset` subcommand for the macOS customer license-rotation flow. Atomic dual-channel reset clears BOTH `~/.nsauditor/license-state.json` AND the macOS Keychain `NSAUDITOR_LICENSE_ID` entry — single-surface clearing ("rm ~/.nsauditor/license-state.json") is a HALF-fix on macOS because `_readLicenseState` (`utils/license.mjs:402-434`) also reads from Keychain and Keychain wins on read. The replay-defense check (`license.mjs:664-670`) then compares persisted-vs-payload `licenseId` and returns `license_id_mismatch` with tier downgrade to CE, even though the customer holds a valid EE JWT.

Customer-facing failure mode (discovered during EE 0.11.0 first-install rehearsal on operator machine, 2026-05-23): customer pays for seat expansion / org change → support reissues new JWT with rotated `licenseId` → customer runs `license install <new-JWT>` (Keychain JWT updated) → next `license --status` call returns `license_id_mismatch` and falls back to CE despite valid Enterprise JWT in Keychain. Pre-this-release recipe required customer to run `security delete-generic-password -s nsauditor-ai -a NSAUDITOR_LICENSE_ID` blind from a support email.

Behavior:
- **Default** (`license --reset`): clears state-file + Keychain `NSAUDITOR_LICENSE_ID`; preserves `NSAUDITOR_LICENSE_KEY` (JWT). Next license check re-binds the new `licenseId` cleanly. Customer sees Enterprise active immediately on next `--status` call.
- **`--purge` flag**: additionally clears Keychain `NSAUDITOR_LICENSE_KEY` (JWT). Forces full re-install with `license install <KEY>`. Linux/Windows file-based JWT purge deferred (would require editing `~/.nsauditor/.env` which may contain unrelated env vars).

Verified end-to-end on operator machine: state file (119 bytes) + Keychain `NSAUDITOR_LICENSE_ID` (lic_f7ff29ad-...) cleared; JWT preserved; next `license --status` re-binds cleanly with Enterprise tier active.

**Paired EE 0.11.1 highlights** (full detail in EE CHANGELOG):
- 5 R-MEDIUM authoring folds shipped: CDE-scope badge per-control display, Req 12.8.5 TPSP shared-responsibility matrix renderer, QSA enforcement-priority ranked view, CAO authorship for all 26 customized-eligible sub-requirements per PCI DSS v4.0.1 Appendix D, + comprehensive test suite extensions
- HIGH-IMPACT pre-existing OCR-categorizer bug fix (`v.issue` → `v.text` — HIPAA OCR-priority section had been silently emitting empty buckets since EE 0.9.4 due to co-evolved test/prod schema drift)
- Dual-skill reviewer pass via `audit-pci-dss-qsa-perspective` + `audit-soc2-evidence-sufficiency` — 0 R-CRITICAL + 3 same-session folds (R-HIGH-1 IPv6 ::/0 regex + R-MEDIUM-1 6-direction leak matrix + stale-comment cleanup)
- Regression: 6236/6236 tests across 1015 suites GREEN (+44 net new tests vs EE 0.11.0 baseline) — 76-session 100% green streak preserved + extended
- **Plugin count UNCHANGED at 24** — pure patch cycle. SOC 2 + HIPAA + NIST CSF 2.0 + PCI DSS coverage matrices ALL UNCHANGED.

**THIRTIETH consecutive trio-publish** institutionalized 0.4.5–0.11.1. Auto-memory: `[[macos_license_reset_dual_channel]]` documents the dual-channel persistence trap.

KNOWN PRE-EXISTING TEST FAILURE (not caused by 0.1.73, tracked for next CE cycle): `tests/license.test.mjs:106` ('returns CE tier when no key') fails on dev machines with installed Enterprise license — `resolveLicenseKey()` 3-source chain (env → Keychain → ~/.nsauditor/.env file) only stubs env var in test setup; Keychain + file resolutions still hit the operator's real JWT on dev machines. CI passes because no JWT exists in any source there. Fix requires extending `loadLicense` to pass opts through to `resolveLicenseKey`. Latent since `resolveLicenseKey` was authored.

---

## 0.1.72 (PUBLISHED 2026-05-23) — Paired with EE 0.11.0 PCI DSS v4.0.1 Track 3 fourth-framework cycle

No CE code changes — paired-publish for trio-publish discipline + customer discoverability. CE's `--compliance` flag already accepts CSV (wired since EE 0.3.0); the engine is framework-agnostic per the institutional cycle pattern. Engine paths are EE-side; CE binary surfaces the framework via `--compliance pci-dss` (or `--compliance soc2,hipaa,nist-csf,pci-dss` for the full 4-framework pack from a single scan).

**Paired EE 0.11.0 highlights** (full detail in EE CHANGELOG):
- NEW `data/compliance/pci-dss.json` (auditor-canonical sub-requirement-level mapping per PCI SSC RoC Reporting Template Appendix B; **MVP-67 density: 20 covered + 8 partial + 39 OOS across 67 of ~250 sub-requirements**; 6 OOS groups; `requirement` / `subRequirement` / `requirementText` / `customizedApproachObjective` / `informativeReferences` schema-additive fields PLUS 4 load-bearing schema enrichments: `controlType` / `approachEligibility` / `cloudProviderAttestation` / `cdeScope` defending against 13 ship-blocker classes surfaced by skill-research synthesis)
- **Req 12 Information Security Program OOS-by-design entirely** (Targeted Risk Analysis Req 12.3.1 + Customized Approach Documentation Req 12.3.2 + TPSP Responsibility Matrix Req 12.8.5 + IR personnel training Req 12.10.4 all Defined-only per Appendix E)
- **Req 5 anti-malware + Req 9 physical OOS-entirely** (endpoint EDR + facility-tier substrate that infrastructure scanning cannot produce)
- **Req 3 stored CHD OOS-by-design at technical-control layer** pending operator CDE attestation via CDE Data Flow Diagram per Req 1.2.4 + Req 12.5.1
- **Defined-vs-Customized Approach discipline per PCI DSS v4.0.1 Appendix E** — 15 Defined-only sub-requirements enforced at schema layer; misclassifying as Customized-eligible is PCI analog of HIPAA's "Addressable as Required" overclaim
- **Customized Approach Objective (CAO) text MVP-deferred to EE 0.11.1 patch** (`customizedApproachObjective: null` on every entry; renderer surfaces explicit CAO MVP-deferral disclaimer directing operators to PCI DSS v4.0.1 Appendix D)
- **Card-brand AOC enforcement priority view** (Visa CISP / Mastercard SDP / Amex DSOP / Discover DISC — the actual penalty mechanism for PCI DSS non-compliance)
- **Cloud-provider PCI DSS Service Provider AOC inheritance** (AWS PCI DSS Service Provider AOC v4.0 + Microsoft Azure PCI DSS v4.0 AOC + Google Cloud Platform PCI DSS v4.0 AOC currently-named as of 2026-05-23)
- EXTENDED EE `utils/soc2_renderer.mjs` (`'pci-dss'` slot table in `frameworkControlCitation` with 8 slots incl. NEW PCI-specific `chd-scope` disclaimer slot; `isPciDssReport` flag; CHD Scope OOS disclaimer + CAO MVP-deferral framing + Defined-only invariant exemplars + card-brand AOC enforcement priority view + preventive-control discipline caveat — markdown + HTML render-path parity)
- 88 net new tests across 3 new EE test files (29 anchor-drift incl. R-LOW-3 reviewer-fold positive-defense for full 15-ID Appendix-E Defined-only enumeration + 31 mapping + 28 renderer); 6-direction cross-framework citation-leak defense (4 frameworks → C(4,2)=6 pair-tests)
- 501-line `docs/pci-dss-coverage.md` companion to existing soc2-coverage + hipaa-coverage + nist-csf-coverage docs
- **3 NEW audit skills authored 2026-05-23 via /skill-creator** (1,916 lines / 13 files): `audit-pci-dss-qsa-perspective` (725 lines / 5 files; pairs with EE 0.11.0 PCI cycle) + `audit-grc-connector-idempotency` (601 lines / 4 files; completes Phase-4 SOC 2/HIPAA/PCI/GRC quad) + `audit-nist-csf-2-implementation-tiers` (590 lines / 4 files; retroactive close of EE 0.10.0 NIST CSF pairing gap). **Per-Framework Adversarial-Audit Skill Pairing institutional pattern** NEW 2026-05-23 — Phase-4 Compliance/GRC chain 5-of-5 COMPLETE for shipped frameworks.

**Cross-repo cascade**:
- nsauditor.com: NEW /docs/pci/ 880-line landing page + /docs/index.html + /enterprise/index.html (replaced "npm install EE 0.10.0 →" callout with "PCI DSS v4.0.1 coverage →" link) + root /index.html + /ai/index.html (all updated to quad-framework framing)
- nsasoft.us: meta + OG + Twitter quad-framework framing + RSS feed (EE 0.11.0 + EE 0.10.0 NIST CSF backfill items) + React src cleaned of stale EE 0.4.5 references + sitemap

**Plugin count UNCHANGED at 24**. **SOC 2 + HIPAA + NIST CSF coverage matrices UNCHANGED** (10/4/33 + 7/3/45 + 13/10/83). **EE regression 6192/6192 across 1010 suites** (+88 net new PCI tests vs 0.10.0 baseline); **76-session 100% green streak preserved + extended**. **Twenty-ninth consecutive trio-publish** institutionalized 0.4.5–0.11.0.

---

## 0.1.71 (PUBLISHED 2026-05-22) — Paired with EE 0.10.0 NIST CSF 2.0 Track 3 third-framework cycle

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
