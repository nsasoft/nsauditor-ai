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

// ⚠️ THE BOUNDARY CONTRACT. Three fields were dropped at ONE seam before this existed —
// `resource` (a new exposure masked), `plugin` (every comparison fell to plugin-not-run) and
// `control` (a finding whose control left the enumeration read as RESOLVED). Each was invisible
// to this module's own tests because each fixture was built by hand with the field present: a fix
// verified only against fixtures the author constructs is verified against the author's idea of
// the input. `tests/delta_boundary_contract.test.mjs` asserts CONSUMED ⊆ EMITTED ∪ DECLARED_ABSENT
// against the REAL loader, so the fourth instance fails by name instead of shipping.
export const CONSUMED_FINDING_FIELDS = ['host', 'plugin', 'resource', 'port', 'title', 'severity', 'control'];

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
const keyOf = (f) => [f.host, f.plugin, f.resource ?? '-', f.port ?? '-', f.title].join('|');

const scopeOf = (side) => {
  const rec = side?.record ?? {};
  const hosts = new Set([
    ...(rec.hostsRequested ?? []),
    ...(rec.hostsWritten ?? []).map((h) => h?.host).filter(Boolean),
  ]);
  const plugins = new Set(rec.pluginsRequested ?? []);
  const gaps = new Map();
  for (const g of side?.evidenceGaps ?? []) gaps.set(`${g.host}|${g.plugin}`, g.reason ?? 'unspecified');
  return { hosts, plugins, gaps, frameworks: side?.frameworkEnumeration ?? null };
};

// Why a finding present in ONE run cannot be compared against the other. Order matters only for
// which reason is reported first; each is independently sufficient.
function incomparabilityReason(f, mine, theirs) {
  if (!theirs.hosts.has(f.host)) return { reason: 'host-not-scanned', detail: `host ${f.host} was not scanned in the other run` };
  if (!theirs.plugins.has(f.plugin)) return { reason: 'plugin-not-run', detail: `plugin ${f.plugin} did not run in the other run` };
  const gap = theirs.gaps.get(`${f.host}|${f.plugin}`) ?? mine.gaps.get(`${f.host}|${f.plugin}`);
  if (gap) return { reason: 'evidence-gap', detail: `the other run recorded an evidence gap on ${f.host}/${f.plugin}: ${gap}` };
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

function frameworkEnumerationEvaluable(mine, theirs) {
  return Boolean(mine?.frameworks && theirs?.frameworks);
}

export function buildScanDelta({ baseline, current }) {
  const limits = [];
  const refuse = (reason, detail) => ({
    schema: SCAN_DELTA_SCHEMA, comparable: false, refusal: { reason, detail },
    newFindings: [], resolved: [], unchanged: [], changed: [], notComparable: [],
    baselineIntegrity: null, limits: [detail],
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
  if ((baseline?.record?.schema ?? null) !== (current?.record?.schema ?? null)) {
    return refuse('run-record-schema-differs',
      `run record schema ${baseline?.record?.schema} vs ${current?.record?.schema}: the two records do not describe coverage the same way`);
  }

  // ── Baseline integrity. A broken chain means the baseline on disk is not the baseline that was
  // written, so every verdict derived from it is unsound — refuse rather than annotate.
  const baselineIntegrity = baseline?.integrity ?? 'chain-absent';
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
    limits.push('The baseline carries no integrity digest (it predates chained run records), so alteration of the baseline could not be ruled out.');
  }
  limits.push(CHAIN_ASSURANCE_LABEL);
  // Declared once for the whole comparison, not per finding: it is a property of the two RUNS.
  if (!frameworkEnumerationEvaluable(scopeOf(baseline), scopeOf(current))) {
    limits.push(FRAMEWORK_MOVEMENT_NOT_EVALUATED);
  }

  const bScope = scopeOf(baseline);
  const cScope = scopeOf(current);
  const bFind = baseline?.findings ?? [];
  const cFind = current?.findings ?? [];
  const bMap = new Map(bFind.map((f) => [keyOf(f), f]));
  const cMap = new Map(cFind.map((f) => [keyOf(f), f]));
  // ⚠️ THE LIMIT NAMES THE DIRECTION, because the previous wording ("per-instance deltas are not
  // distinguished") read as a granularity note when the real consequence is a missing exposure.
  if (bMap.size !== bFind.length || cMap.size !== cFind.length) {
    limits.push('Two or more findings collapsed to one identity (same host, plugin, resource, port and title). '
      + 'Appearance and disappearance of individual instances cannot be distinguished, so A NEW FINDING MAY BE '
      + 'MASKED by a surviving one that shares its identity.');
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
    baselineIntegrity, limits,
    coverage: {
      hostsOnlyInBaseline: [...bScope.hosts].filter((h) => !cScope.hosts.has(h)),
      hostsOnlyInCurrent: [...cScope.hosts].filter((h) => !bScope.hosts.has(h)),
      pluginsOnlyInBaseline: [...bScope.plugins].filter((p) => !cScope.plugins.has(p)),
      pluginsOnlyInCurrent: [...cScope.plugins].filter((p) => !bScope.plugins.has(p)),
    },
  };
}
