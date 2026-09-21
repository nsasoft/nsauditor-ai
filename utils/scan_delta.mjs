// Cross-run delta — "what changed since the last scan" (Pro/Enterprise).
//
// ⚠️ NOT `utils/delta_reporter.mjs`. That is the FREE CE last-vs-current alerting delta on the
// webhook path and it stays free, untouched and un-gated. This is a second engine, over two
// ARBITRARY run records, at FINDING level.
//
// ⚠️ THE WHOLE DESIGN IS THE REFUSAL, because "RESOLVED" IS THE DANGEROUS VERDICT. A finding
// that disappeared for any reason other than being fixed reads to a buyer, and to an assessor,
// as remediation. Five ways a finding can vanish without being fixed, every one observed in this
// product's own history:
//   1. HOST      — the host was not scanned in the current run.
//   2. PLUGIN    — the plugin that produced it did not run (`--plugins` differed).
//   3. SCOPE     — an evidence gap: AccessDenied, budget exceeded, incomplete region enumeration.
//                  A FINDING THAT DISAPPEARED BECAUSE THE SCANNER LOST PERMISSION IS NOT FIXED.
//   4. FRAMEWORK — the control enumeration moved (PCI went 19/9/39 → 19/9/44 in one cycle), so a
//                  control that "appeared" or "left" is an enumeration change, not a posture change.
//   5. PRODUCT   — the §5.3 semantics boundary, below. This one is written in our own contract.
// A finding may be called RESOLVED only when its host, plugin, scope and framework enumeration
// were in scope in BOTH runs. Otherwise it goes to NOT-COMPARABLE **with its reason** — never
// into `resolved`, and never silently dropped.
// Integrity is a fact about BYTES ON DISK, so the caller measures it with `utils/run_chain.mjs`
// and passes the verdict in. Keeping it out of this module means the comparability rules can be
// driven without a filesystem, and the chain can be driven without the delta.
export const SCAN_DELTA_SCHEMA = 1;

// ⚠️ REASON CODES ARE APPEND-ONLY UNDER `SCAN_DELTA_SCHEMA = 1`. Adding one is additive and needs
// no schema bump; RENAMING or REMOVING one changes what an existing consumer's stored verdicts
// mean, and bumps the schema.
//
// ⚠️ AND THEY ARE DECLARED HERE BECAUSE TWO SURFACES ARE WRITTEN FROM THEM RATHER THAN FROM A
// COUNT SOMEBODY DID BY HAND. The CE CHANGELOG's "N ways a finding can vanish without being
// fixed" sentence and the agent-skill's item (2) have both already shipped a count that disagreed
// with the code — a count with no list beside it is invisible to every gate this product owns.
// `tests/scan_delta.test.mjs` holds these in EQUALITY with the codes derived from this file's own
// source: a new code that forgets the declaration fails, and so does a declaration whose code is
// gone. The ORDER is the order the engine evaluates them, which is the order a reader meets them.
export const NOT_COMPARABLE_REASONS = Object.freeze([
  'host-not-scanned',              // the other run never wrote this host
  'producer-unknown',              // the finding carries no producer identity to adjudicate
  'plugin-not-run',                // the producing plugin was not requested in the other run
  'evidence-gap',                  // a producer DECLARED it could not read the surface
  'plugin-not-measured',           // the plugin was attempted on the host and errored / timed out / was skipped
  'framework-enumeration-changed', // the control left or joined the enumeration between the runs
]);

// Whole-comparison refusals: cases where NO per-finding verdict is trustworthy, so none is offered.
export const REFUSAL_REASONS = Object.freeze([
  'ee-presence-differs',
  'tier-differs',
  'finding-count-semantics-boundary',
  'run-record-schema-differs',
  'baseline-chain-broken',
  'baseline-integrity-unmeasurable',
]);

// ⚠️ SEPARATE, AND DELIBERATELY SO. `tests/scan_delta.test.mjs` holds `REFUSAL_REASONS` in EXACT
// equality with the `refuse('…')` calls in THIS file — a guard that catches both a new code that
// forgets the constant and a code deleted from the constant while still produced. A view-level
// refusal put into that array breaks the equality, and the only way to keep one array would be to
// relax it to a SUBSET check: a superset guard, which this repo's own notes call structurally
// incapable of catching an omission. So the vocabulary is still one thing to a reader
// (`DECLARED_OUTCOMES` unions them) and two things to the two derivations that can each stay
// EXACT. Raised by `scan_delta_view.mjs`, never by `buildScanDelta`: the baseline record exists
// but this build cannot read it — a schema it does not understand, or a corrupt file.
export const VIEW_REFUSAL_REASONS = Object.freeze([
  'baseline-unloadable',
]);

// ⚠️ THE BOUNDARY CONTRACT. Three fields were dropped at ONE seam before this existed —
// `resource` (a new exposure masked), `plugin` (every comparison fell to plugin-not-run) and
// `control` (a finding whose control left the enumeration read as RESOLVED). Each was invisible
// to this module's own tests because each fixture was built by hand with the field present: a fix
// verified only against fixtures the author constructs is verified against the author's idea of
// the input. `tests/delta_boundary_contract.test.mjs` asserts CONSUMED ⊆ EMITTED ∪ DECLARED_ABSENT
// against the REAL loader, so the fourth instance fails by name instead of shipping.
export const CONSUMED_FINDING_FIELDS = ['host', 'plugin', 'pluginName', 'producerKind', 'evidenceGap',
  'contentDigest', 'identityQualifier', 'resource', 'region', 'port', 'title', 'severity', 'control'];

// Fields this module WRITES onto its output records; they are never read from a loaded finding,
// so they must not be demanded of the loader. Declared so the derivation can subtract them.
export const OUTPUT_ONLY_FINDING_FIELDS = ['reason', 'detail', 'direction', 'from', 'to'];

// A consumed field the loader legitimately cannot produce. NOT a bare allowlist: each entry names
// the limit that DISCLOSES its absence, and the guard verifies that limit is actually emitted —
// a carve-out whose premise nobody checks is how an absence becomes a silent pass.
export const DECLARED_ABSENT_FINDING_FIELDS = {
  control: {
    reason: 'Community ships no compliance data (data/compliance is empty) and report_inputs.mjs '
      + 'emits no control id, so a CE run record cannot carry one. Compliance routing is EE\'s.',
    disclosedBy: 'FRAMEWORK_MOVEMENT_NOT_EVALUATED',
  },
};


// ⚠️ DERIVED FROM THE FROZEN CONTRACT, NOT INVENTED HERE. `docs/contract-v1.md` §5.3: the
// `findingCount` key KEPT ITS NAME AND CHANGED ITS VALUE in the first release after EE 0.46.0 —
// every archived pack before that release printed the ISSUE count under it. A delta spanning that
// boundary would report a mass remediation that never happened, so it is REFUSED, not annotated.
export const FINDING_COUNT_BOUNDARY_EE = '0.46.0';

// The honest label, and it rides in the OUTPUT rather than only in the docs: a hash chain on the
// same disk as the records it covers is defeated by anyone who can recompute the successors.
export const CHAIN_ASSURANCE_LABEL =
  'Baseline integrity is tamper-EVIDENT against accidental corruption, partial restore and ' +
  'unsophisticated edits. It is NOT tamper-proof against an attacker with host-level access, ' +
  'and it is not non-repudiation: the chain carries no signature and names no author.';

const cmpVersion = (a, b) => {
  const pa = String(a).split('.').map((n) => parseInt(n, 10) || 0);
  const pb = String(b).split('.').map((n) => parseInt(n, 10) || 0);
  for (let i = 0; i < 3; i += 1) if ((pa[i] ?? 0) !== (pb[i] ?? 0)) return (pa[i] ?? 0) < (pb[i] ?? 0) ? -1 : 1;
  return 0;
};

// ⚠️ IDENTITY MUST CARRY THE RESOURCE, and the first draft of this did not — a HIGH defect an
// independent seat found by reading the FIXTURES rather than the code. Cloud issue strings carry
// the DEFECT, not the resource ("No public access block configured…"), so twelve buckets with one
// misconfiguration share a title; resource identity lives in `finding.resource` (contract-v1 §1.1).
// Under a host+plugin+title key those twelve collapse to ONE, and the failure is in the dangerous
// direction: fix bucket-c, acquire bucket-d with the same defect, and the delta reported
// "unchanged" — A NEW EXPOSURE ABSENT FROM `newFindings` ENTIRELY, measured, not theorised.
//
// ⚠️ `severity` IS DELIBERATELY NOT IN THE KEY. Adding it would render one escalation as a
// resolved finding PLUS a new one — two false verdicts from one true change. Identity first, then
// severity compared between MATCHED findings into `changed`.
//
// ⚠️ `originalIndex` IS NOT A CANDIDATE, though contract-v1 §1.2 freezes it on every record: it is
// the index in the INPUT array and all fan-out records of one cloud finding SHARE it (§1.2:53).
// Positional and non-unique — adopting it as an id would be worse than this composed key.
// ⚠️ NO `?? f.target` FALLBACK, and its removal is the F5 lesson applied to a benign case. The
// boundary guard flagged `target` as consumed-but-never-emitted on its FIRST run: report_inputs
// already folds target INTO resource (`resource: f?.resource ?? f?.target ?? …`), so a finding can
// never reach here carrying a bare target. A fallback that cannot fire through the shipped path is
// not defensive depth — it is dead code that reads as coverage, which is exactly what made the
// framework-enumeration leg look complete while being inert.
// ⚠️ NEVER OVER A TRUNCATED STRING. The title is SYNTHESISED and CUT AT 160 CHARS for producers
// that emit none, and on a live estate three world-open ingress rules on one security group
// differed only past the cut — one identity for three CRITICAL exposures, so a NEW world-open
// database port would have read as UNCHANGED. `contentDigest` covers the untrucated content and
// `identityQualifier` carries the producer's OWN rule discriminators; the title remains the
// fallback for anything emitting neither.
// ⚠️ BOTH `title` AND `contentDigest`, NEVER ONE INSTEAD OF THE OTHER — measured, and the first
// draft got it wrong in the dangerous direction. `contentDigest ?? title` looked equivalent-or-
// better and was STRICTLY COARSER for producers that emit no raw title: 1020 names the bucket only
// in the SYNTHESISED title, while the digest covers `[rawTitle, issues]` where rawTitle is null and
// the issue text carries no bucket. Two different S3 buckets — `aws-config-logs-…` and
// `cloudtrail-violator-logs-…` — hashed identically and collapsed. The fix for one producer's
// masking re-created it at another, which is why this was caught on the REAL record and not by the
// fixtures written from 1170.
//
// Taking both is strictly finer than either: the digest separates content that TRUNCATION hid, the
// title separates naming the digest never saw, and the qualifier separates rules that share both.
//
// ⚠️ `region` IS A COMPONENT SINCE E1, AND REMOVING THE SUFFIX WITHOUT ADDING IT WOULD COLLAPSE
// A POPULATION. Before E1 the region entered this key only as decoration inside `resource`
// (` [us-east-1]`, appended downstream by EE's `_stampRegion`), so a per-region finding that
// names no object — a scope literal like `backup:account`, emitted once per region — was
// separated ONLY by that suffix. De-suffixing alone would have mapped every region's copy onto
// one key and reported N-1 of them as removed. It is taken from the finding's own FIELD, which
// both sides of any comparison recompute identically, so unlike a suffix it fabricates nothing
// across an upgrade.
const keyOf = (f) => [f.host, f.plugin, f.resource ?? '-', f.port ?? '-',
  f.region ?? '-', f.identityQualifier ?? '-', f.title, f.contentDigest ?? '-'].join('|');

// A plugin status that means THE SURFACE WAS NOT READ. `ran` is the only status that licenses a
// comparison; the rest are the machine saying so itself.
const NOT_MEASURED_STATUS = new Set(['error', 'timeout', 'skipped']);

// ⚠️ SCOPE IS WHAT A RUN MEASURED, WHICH IS NARROWER THAN WHAT IT REQUESTED IN THREE WAYS, and
// every one of them was fail-open here until 2026-09-20 — each produced a `resolved` row in a
// CLIENT artifact when driven through `report --since`:
//   HOSTS were `hostsRequested ∪ hostsWritten`, so a host that was asked for and never produced
//     output counted as scanned and its baseline findings read as remediation.
//   PLUGIN STATUS was not consulted at all, though the loader has always carried it, so a plugin
//     that ERRORED or TIMED OUT on a host counted as having measured it.
//   EVIDENCE GAPS were read from `side.evidenceGaps`, which NO shipped caller ever populated —
//     dead since the day it was written, and the fall-through from a dead leg is `resolved`.
// ⚠️ THE `side.evidenceGaps` READ IS DELETED RATHER THAN REPAIRED. It was unreachable AND
// shape-wrong: the only producer of that record shape (`cloud_finding_summary.mjs`) builds
// `plugin: String(r?.id ?? '')` with NO `host` key at all, so even a caller that filled it would
// key `undefined|1170` against a lookup keyed `<host>|<id>`. Leaving a second unreachable path
// beside the repaired one is the F5 mistake this module already records at the framework leg —
// dead code that reads as coverage.
const scopeOf = (side) => {
  const rec = side?.record ?? {};
  const hosts = new Set((rec.hostsWritten ?? []).map((h) => h?.host).filter(Boolean));
  const plugins = new Set(rec.pluginsRequested ?? []);
  const gaps = new Map();
  // Gaps as the PRODUCER records them — on the finding, where they already ride.
  for (const fi of side?.findings ?? []) {
    if (fi?.evidenceGap === true && fi.plugin != null) {
      gaps.set(`${fi.host}|${fi.plugin}`,
        { kind: 'recorded-gap', reason: fi.title ?? fi.detail ?? 'an evidence gap was recorded' });
    }
  }
  // And as the ENGINE records them: a plugin the host never successfully ran.
  for (const h of (Array.isArray(side?.pluginStatus) ? side.pluginStatus : [])) {
    for (const ps of (h?.status ?? [])) {
      if (!NOT_MEASURED_STATUS.has(ps?.status)) continue;
      // ⚠️ A DIFFERENT KIND, AND THE DIFFERENCE IS CLIENT-VISIBLE. Both mean "this surface was not
      // measured", so both belong in the same scope map — but a producer DECLARING a gap
      // (AccessDenied, budget exceeded) and a plugin CRASHING are not the same event, and the
      // first draft of this reported the second with the first's sentence: "the other run
      // recorded an evidence gap … the plugin's status on that host was error". The other run
      // recorded nothing of the sort. That sentence renders into the client's basis cell, which
      // is the surface this whole engine exists to keep honest.
      gaps.set(`${h.host}|${String(ps.id)}`, { kind: 'not-measured',
        reason: `the plugin's status on that host was "${ps.status}"${ps.reason ? `: ${ps.reason}` : ''}` });
    }
  }
  return {
    hosts, plugins, gaps,
    // ⚠️ AN ABSENT ORACLE IS NOT A CLEAN ONE. `[]` means "measured, no gaps"; MISSING means
    // nothing was measured, and the two must not render alike. Declared in `limits`, never
    // absorbed here — gate:cascade's LEG (ii) is this repo's precedent for the distinction.
    // ⚠️ THIS READ `Array.isArray(side?.pluginStatus)` UNTIL THE OUTCOME CENSUS DROVE IT. Through
    // the shipped path `side.pluginStatus` is `model.plugins.byHost`, which the loader ALWAYS
    // builds — so the test was always true, `scope-not-evaluated` was dead, and a run that
    // recorded no per-host plugin status rendered identically to one that recorded a clean
    // status. That is the exact false clean the comment above forbids, living inside the guard
    // written to prevent it. The loader now carries `pluginStatusRecorded` beside the defaulted
    // array, and this asks the question the comment always meant.
    evaluable: Array.isArray(side?.pluginStatus)
      && side.pluginStatus.every((h) => h?.pluginStatusRecorded !== false),
    frameworks: side?.frameworkEnumeration ?? null,
  };
};

export const SCOPE_NOT_EVALUATED =
  'Scope non-evaluation: one of the two runs recorded no per-host plugin status, so evidence gaps '
  + 'and failed plugins could NOT be distinguished from a clean scan on that side. A finding '
  + 'reported as resolved here may instead be one the scanner could not read. Re-run the '
  + 'comparison against a run recorded by this release or later before treating any row as remediation.';

export const AGENT_SCOPE_FROM_TIER =
  'Agent-produced findings: their scope is derived from the run TIER, not from a per-agent run '
  + 'record — this edition persists no per-agent status, and the agent set is a function of the '
  + 'licensed capabilities. The two runs carry the same tier, which is what makes them comparable; '
  + 'a tier difference refuses the comparison outright rather than narrowing it.';

// The producer as a READER should see it. `plugin` is an id because that is the vocabulary the
// run record can be checked against; the id alone is not a sentence, and this string is rendered
// into the client's report. Both are printed when they differ, so the prose is readable AND the
// token matches the baseline scope line, which prints `pluginsRequested` — ids.
const producerLabel = (f) => (f.pluginName && f.pluginName !== f.plugin ? `${f.pluginName} (${f.plugin})` : String(f.plugin));

// Why a finding present in ONE run cannot be compared against the other. Order matters only for
// which reason is reported first; each is independently sufficient.
function incomparabilityReason(f, mine, theirs) {
  if (!theirs.hosts.has(f.host)) return { reason: 'host-not-scanned', detail: `host ${f.host} was not scanned in the other run` };
  // ⚠️ A NULL IDENTITY MAY NEVER SATISFY A SCOPE CHECK, and it may never be DESCRIBED as one
  // either. Before this leg a finding with no producer fell into `plugin-not-run` and reported
  // "plugin null did not run in the other run" — a sentence that is false about the run, about a
  // finding whose comparability was never established. The honest verdict names the thing that is
  // missing. It is checked FIRST because every leg below keys on the producer.
  if (f.plugin == null) {
    return { reason: 'producer-unknown',
      detail: 'this finding carries no producer identity, so whether it was in scope in the other run cannot be established' };
  }
  // ⚠️ THE ORACLE DEPENDS ON THE PRODUCER KIND, and guessing it from the string's SHAPE is what
  // this leg refuses to do. A plugin id is answerable from `pluginsRequested`. An EE analysis
  // agent appears in no such list and never will, so checking it there would bucket every
  // agent-produced finding as `plugin-not-run` for ever — safe, and useless, which is the failure
  // mode this engine was built to avoid on the other axis. Its scope is the run TIER, and the two
  // whole-comparison refusals above (`ee-presence-differs`, `tier-differs`) are what make that
  // sound: by the time control reaches here both sides carry Enterprise and carry the SAME tier,
  // so the agent set is identical on both. No per-finding agent check is written here, because a
  // check that cannot fail through the shipped path is dead code that reads as coverage.
  if (f.producerKind !== 'agent' && !theirs.plugins.has(f.plugin)) {
    return { reason: 'plugin-not-run', detail: `plugin ${producerLabel(f)} did not run in the other run` };
  }
  const gap = theirs.gaps.get(`${f.host}|${f.plugin}`) ?? mine.gaps.get(`${f.host}|${f.plugin}`);
  if (gap) {
    return gap.kind === 'recorded-gap'
      ? { reason: 'evidence-gap',
        detail: `the other run recorded an evidence gap on ${f.host}/${producerLabel(f)}: ${gap.reason}` }
      : { reason: 'plugin-not-measured',
        detail: `${f.host}/${producerLabel(f)} was not measured in the other run — ${gap.reason}` };
  }
  // ⚠️ NO SILENT SHORT-CIRCUIT. This used to read `mine.frameworks && theirs.frameworks &&
  // f.control`, and all three are absent through the shipped path — so the leg returned null and
  // the finding fell through to `resolved`. That is FAIL-OPEN, the opposite of the `plugin` gap:
  // a finding whose control stopped being enumerated read as REMEDIATED in a client artifact.
  // Whether the oracle exists is now decided ONCE, by `frameworkEnumerationEvaluable`, and its
  // absence is DECLARED in `limits` rather than absorbed here.
  if (frameworkEnumerationEvaluable(mine, theirs) && f.control) {
    const inMine = mine.frameworks.includes(f.control);
    const inTheirs = theirs.frameworks.includes(f.control);
    if (inMine !== inTheirs) {
      return { reason: 'framework-enumeration-changed', detail: `control ${f.control} is enumerated in only one of the two runs` };
    }
  }
  return null;
}

// The oracle test, separated from the per-finding check so its ABSENCE has somewhere to be
// declared. gate:cascade's LEG (ii) is the precedent this repo already set: when the oracle is
// missing, print NOT EVALUATED and never pass silently.
export const FRAMEWORK_MOVEMENT_NOT_EVALUATED =
  'Coverage-matrix movement between the two runs was NOT EVALUATED: this edition records no '
  + 'framework enumeration on a run, so if a control stopped being enumerated between the two '
  + 'scans, findings that mapped to it may appear as resolved here. Compare the two runs\' '
  + 'framework coverage separately before treating any row as remediation.';

export const BASELINE_UNCHAINED =
  'The baseline carries no integrity digest (it predates chained run records), so alteration of '
  + 'the baseline could not be ruled out.';

export const EVIDENCE_GAPS_RECORDED =
  'One or more EVIDENCE GAPS were recorded. A gap is a surface the scanner could not read, not a '
  + 'finding: gaps are listed under coverage, and any finding a gap covers is reported as '
  + 'not-comparable rather than as resolved.';

// The stable head of the collision limit; the colliding identities are appended at the call site.
export const IDENTITY_COLLAPSE =
  'Two or more findings collapsed to one identity (same host, plugin, resource, port, rule '
  + 'qualifier and content). Appearance and disappearance of individual instances cannot be '
  + 'distinguished, so A NEW FINDING MAY BE MASKED by a surviving one that shares its identity. '
  + 'Colliding identities: ';

// ⚠️ THESE TWO ARE EMITTED BY `scan_delta_view.mjs`, AND THEY LIVE HERE ANYWAY. The vocabulary is
// one module or it is two copies: the view imports them. Declaring them beside the view that
// pushes them would put half the census's subject outside the export the census reads.
export const CURRENT_UNCHAINED =
  'The current run carries no integrity digest (it predates chained run records), so alteration '
  + 'of the run being reported could not be ruled out.';

export const CURRENT_CHAIN_LINK_BROKEN =
  'The current run record names a predecessor whose bytes no longer exist (the record was deleted '
  + 'or rewritten). The baseline used here was named explicitly, so it is the one that was asked '
  + 'for \u2014 but the run chain covering this comparison is incomplete.';


// ────────────────────────────────────────────────────────────────────────────────────────────
// THE OUTCOME VOCABULARY — ONE EXPORT, READ BY THE CENSUS, COPIED NOWHERE.
//
// ⚠️ WHY THIS EXISTS: a guard can be disarmed by a FIX THAT NARROWS ITS SUBJECT, with nothing
// failing and nobody editing the guard. It happened twice in two commits in this lane. The census
// (`tests/delta_outcome_census.test.mjs`) asserts SET EQUALITY between what is declared here and
// what the SHIPPED entry point actually produces, so a narrowed trigger fails BY NAME. A new
// outcome joins the census by being written here — incompleteness costs NOISE, never silence.
// ⚠️ APPEND-ONLY under `SCAN_DELTA_SCHEMA = 1`, exactly as the reason codes are.
// ────────────────────────────────────────────────────────────────────────────────────────────

// How much of a limit's sentence identifies it. A limit has no short code in its own text, so the
// census probes its HEAD; the self-check refuses two limits whose heads collide.
export const OUTCOME_PROBE_CHARS = 48;

export const DECLARED_LIMITS = Object.freeze({
  'baseline-unchained': BASELINE_UNCHAINED,
  'chain-assurance': CHAIN_ASSURANCE_LABEL,
  'framework-movement-not-evaluated': FRAMEWORK_MOVEMENT_NOT_EVALUATED,
  'scope-not-evaluated': SCOPE_NOT_EVALUATED,
  'evidence-gaps-recorded': EVIDENCE_GAPS_RECORDED,
  'agent-scope-from-tier': AGENT_SCOPE_FROM_TIER,
  'identity-collapse': IDENTITY_COLLAPSE,
  'current-unchained': CURRENT_UNCHAINED,
  'current-chain-link-broken': CURRENT_CHAIN_LINK_BROKEN,
});

const outcome = (species, probe) => Object.freeze({ species, probe });
export const DECLARED_OUTCOMES = Object.freeze({
  ...Object.fromEntries(NOT_COMPARABLE_REASONS.map((c) => [c, outcome('not-comparable', c)])),
  ...Object.fromEntries([...REFUSAL_REASONS, ...VIEW_REFUSAL_REASONS]
    .map((c) => [c, outcome('refusal', c)])),
  ...Object.fromEntries(Object.entries(DECLARED_LIMITS)
    .map(([c, text]) => [c, outcome('limit', text.slice(0, OUTCOME_PROBE_CHARS))])),
});

// ⚠️ NOT A WAIVER, AND NOT A BARE ALLOWLIST. Each member names the limit that DISCLOSES its
// absence, and the census verifies that limit is actually produced — the same premise-checking
// discipline as `DECLARED_ABSENT_FINDING_FIELDS` above, for the same reason: a carve-out whose
// premise nobody re-checks is how an absence becomes a silent pass.
export const DECLARED_UNREACHABLE_OUTCOMES = Object.freeze({
  'run-record-schema-differs': {
    reason: 'An EARLIER layer refuses first and this branch cannot be reached. `loadRun` pins the '
      + 'run-record schema to the one this build understands and refuses any other outright, so two '
      + 'records that both LOAD always agree on schema. The guard stays because it is the library '
      + 'contract for a caller that builds a delta without the loader.',
    instead: 'this build understands schema',
  },
  'framework-enumeration-changed': {
    reason: 'Reaching this needs a framework enumeration on BOTH runs and a `control` on a finding. '
      + 'Community ships no compliance data, `report_inputs.mjs` emits no control id, and '
      + '`scan_delta_view.mjs` passes no frameworkEnumeration to buildScanDelta — so no CE run can '
      + 'produce it. It stays declared because EE routing supplies exactly these inputs, and the '
      + 'engine must refuse rather than report a de-enumerated control as remediated.',
    disclosedBy: 'framework-movement-not-evaluated',
  },
});

function frameworkEnumerationEvaluable(mine, theirs) {
  return Boolean(mine?.frameworks && theirs?.frameworks);
}

const gapList = (scope) => [...scope.gaps.entries()].map(([k, g]) => {
  const i = k.indexOf('|');
  return { host: k.slice(0, i), plugin: k.slice(i + 1), kind: g.kind, reason: g.reason };
});

export function buildScanDelta({ baseline, current }) {
  const limits = [];
  const refuse = (reason, detail) => ({
    schema: SCAN_DELTA_SCHEMA, comparable: false, refusal: { reason, detail },
    newFindings: [], resolved: [], unchanged: [], changed: [], notComparable: [],
    baselineIntegrity: null, currentIntegrity: null, limits: [detail],
  });

  // ── Whole-comparison refusals. Each is a case where NO per-finding verdict is trustworthy.
  const bEE = baseline?.record?.eeVersion ?? null;
  const cEE = current?.record?.eeVersion ?? null;
  if ((bEE === null) !== (cEE === null)) {
    return refuse('ee-presence-differs',
      'one run carries Enterprise findings and the other does not, so the two populations are not the same population');
  }
  if (bEE && cEE) {
    const bPre = cmpVersion(bEE, FINDING_COUNT_BOUNDARY_EE) <= 0;
    const cPre = cmpVersion(cEE, FINDING_COUNT_BOUNDARY_EE) <= 0;
    if (bPre !== cPre) {
      return refuse('finding-count-semantics-boundary',
        `EE ${bEE} and EE ${cEE} sit on opposite sides of the ${FINDING_COUNT_BOUNDARY_EE} findingCount semantics boundary ` +
        '(contract-v1 §5.3): before it the key carried the ISSUE count, so a comparison across it shows a fall that is a ' +
        'correction and not remediation');
    }
  }
  // ⚠️ TIER IS A STATEMENT ABOUT THE PRODUCER POPULATION, not about how much detail a report
  // shows. `agents/agent_runner.mjs` runs the agents the run's CAPABILITIES license, so an
  // enterprise baseline compared against a pro current is missing an entire producer — and every
  // finding that producer found would read as REMEDIATION. This refuses rather than annotating,
  // for the same reason `ee-presence-differs` does: the two populations are not the same
  // population, and no per-finding verdict across them is trustworthy.
  const bTier = baseline?.record?.tier ?? null;
  const cTier = current?.record?.tier ?? null;
  if (bTier !== cTier) {
    return refuse('tier-differs',
      `the baseline ran at tier "${bTier}" and the current run at tier "${cTier}": the licensed `
      + 'producer set differs between them, so findings absent from the narrower run may simply '
      + 'never have been looked for');
  }
  if ((baseline?.record?.schema ?? null) !== (current?.record?.schema ?? null)) {
    return refuse('run-record-schema-differs',
      `run record schema ${baseline?.record?.schema} vs ${current?.record?.schema}: the two records do not describe coverage the same way`);
  }

  // ── Baseline integrity. A broken chain means the baseline on disk is not the baseline that was
  // written, so every verdict derived from it is unsound — refuse rather than annotate.
  const baselineIntegrity = baseline?.integrity ?? 'chain-absent';
  // ⚠️ THE CURRENT RUN IS ALTERABLE TOO, and until T3 nothing could verify it. A basis that names
  // only the baseline describes half the evidence the verdict rests on. Unlike the baseline this
  // one is never a refusal HERE — the view refuses on it before the engine is called, because the
  // engine is deliberately filesystem-free and integrity is a fact about bytes on disk.
  const currentIntegrity = current?.integrity ?? null;
  if (baselineIntegrity === 'chain-broken') {
    return refuse('baseline-chain-broken',
      'the baseline run record does not match its recorded digest: it was altered, truncated or partially restored after the run');
  }
  // ⚠️ COULD-NOT-MEASURE IS NEVER A PASS. `chain-unreadable` is not `chain-absent`: absent means
  // the record predates chaining and we know that; unreadable means the instrument failed and we
  // know nothing. Letting the second one through would be a verdict from a run that measured nothing.
  if (baselineIntegrity === 'chain-unreadable') {
    return refuse('baseline-integrity-unmeasurable',
      'the baseline integrity digest could not be read, so alteration of the baseline could neither be confirmed nor ruled out');
  }
  if (baselineIntegrity === 'chain-absent') {
    limits.push(BASELINE_UNCHAINED);
  }
  limits.push(CHAIN_ASSURANCE_LABEL);
  // Declared once for the whole comparison, not per finding: it is a property of the two RUNS.
  if (!frameworkEnumerationEvaluable(scopeOf(baseline), scopeOf(current))) {
    limits.push(FRAMEWORK_MOVEMENT_NOT_EVALUATED);
  }

  const bScope = scopeOf(baseline);
  const cScope = scopeOf(current);
  if (!bScope.evaluable || !cScope.evaluable) limits.push(SCOPE_NOT_EVALUATED);

  // ⚠️ A GAP RECORD IS SCOPE AND MUST NOT BE BUCKETED AS A FINDING. It has a severity, a title and
  // — since the producer identity landed — a plugin, so it is comparable like anything else and
  // would otherwise arrive in the client's NEW EXPOSURES table as an INFO row reading
  // "Evidence gap (…)". It has already been read INTO `scopeOf` above, which is its whole job:
  // it explains why its neighbours are not comparable. Measured before the exclusion: the
  // `gap-leg` scenario read `1 new · 1 resolved` where the honest answer is `0 new · 0 resolved`.
  const isGap = (f) => f.evidenceGap === true;
  const bFind = (baseline?.findings ?? []).filter((f) => !isGap(f));
  const cFind = (current?.findings ?? []).filter((f) => !isGap(f));
  if ((baseline?.findings ?? []).some(isGap) || (current?.findings ?? []).some(isGap)) {
    // ⚠️ THE WORDING AVOIDS THE LITERAL BUCKET NAME ON PURPOSE. `scripts/board_probe_delta_driver.mjs`
    // harvests reasons by matching that phrase against every output line, so a LIMIT containing it
    // is read back as if it were a per-finding reason — an instrument the next seat reads,
    // reporting a bucket that no finding is in.
    limits.push(EVIDENCE_GAPS_RECORDED);
  }
  if ((baseline?.findings ?? []).some((f) => f.producerKind === 'agent')
    || (current?.findings ?? []).some((f) => f.producerKind === 'agent')) {
    limits.push(AGENT_SCOPE_FROM_TIER);
  }
  const bMap = new Map(bFind.map((f) => [keyOf(f), f]));
  const cMap = new Map(cFind.map((f) => [keyOf(f), f]));
  // ⚠️ THE LIMIT NAMES THE DIRECTION, because the previous wording ("per-instance deltas are not
  // distinguished") read as a granularity note when the real consequence is a missing exposure.
  if (bMap.size !== bFind.length || cMap.size !== cFind.length) {
    // ⚠️ THE LIMIT NAMES EACH COLLIDING IDENTITY. A generic disclosure tells a reader that SOME
    // finding may be masked and gives them nothing to act on; the whole point is that they can go
    // and look at the one that collided.
    const collide = [];
    for (const [side, list] of [['baseline', bFind], ['current', cFind]]) {
      const seen = new Map();
      for (const f of list) {
        const k = keyOf(f);
        seen.set(k, (seen.get(k) ?? 0) + 1);
      }
      for (const f of list) {
        const k = keyOf(f);
        if ((seen.get(k) ?? 0) > 1 && !collide.some((c) => c.k === k)) {
          collide.push({ k, text: `${side}: plugin ${f.plugin} · ${f.resource ?? 'no resource'} · `
            + `"${String(f.title ?? '').slice(0, 80)}" ×${seen.get(k)}` });
        }
      }
    }
    limits.push(IDENTITY_COLLAPSE + collide.map((c) => c.text).join(' | '));
  }

  const resolved = [];
  const newFindings = [];
  const unchanged = [];
  const changed = [];
  const notComparable = [];

  for (const [k, f] of bMap) {
    if (cMap.has(k)) {
      // Matched on identity — so a severity move is the SAME finding getting worse or better,
      // which is the trend report's actual deliverable. Never a resolution plus a new finding.
      const now = cMap.get(k);
      if ((f.severity ?? null) !== (now.severity ?? null)) changed.push({ ...now, from: f.severity ?? null, to: now.severity ?? null });
      else unchanged.push(f);
      continue;
    }
    const why = incomparabilityReason(f, bScope, cScope);
    if (why) notComparable.push({ ...f, direction: 'disappeared', ...why });
    else resolved.push(f);
  }
  for (const [k, f] of cMap) {
    if (bMap.has(k)) continue;
    // The mirror, and it is not symmetric in danger: a finding "new" only because its host or
    // plugin was out of scope last time is NEW COVERAGE, not a new exposure.
    const why = incomparabilityReason(f, cScope, bScope);
    if (why) notComparable.push({ ...f, direction: 'appeared', ...why });
    else newFindings.push(f);
  }

  return {
    schema: SCAN_DELTA_SCHEMA, comparable: true, refusal: null,
    newFindings, resolved, unchanged, changed, notComparable,
    baselineIntegrity, currentIntegrity, limits,
    coverage: {
      hostsOnlyInBaseline: [...bScope.hosts].filter((h) => !cScope.hosts.has(h)),
      hostsOnlyInCurrent: [...cScope.hosts].filter((h) => !bScope.hosts.has(h)),
      pluginsOnlyInBaseline: [...bScope.plugins].filter((p) => !cScope.plugins.has(p)),
      pluginsOnlyInCurrent: [...cScope.plugins].filter((p) => !bScope.plugins.has(p)),
      // The gaps themselves, named. A reader who sees a NOT-COMPARABLE row needs to be able to
      // find out WHICH surface was unreadable without reading the raw envelope.
      gapsInBaseline: gapList(bScope),
      gapsInCurrent: gapList(cScope),
    },
  };
}
