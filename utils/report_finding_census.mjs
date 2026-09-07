// utils/report_finding_census.mjs
//
// WHICH CONTAINERS IN A SCAN RECORD CAN HOLD A FINDING, AND DOES THE REPORT READ THEM?
//
// Built after Gate 3-B drove the `report` subcommand over a real 192.168.1.1 run and the
// client deliverable said, over sixteen known CVEs:
//
//     "No findings were recorded in this run."
//     CRITICAL 0 · HIGH 0 · MEDIUM 0 · LOW 0 · INFO 0 · PASS 0 · OTHER 0
//
// `shapeHost` read exactly one container — `result.findings[]` as an ARRAY — and on a
// network host that container is EMPTY. Measured on that run: 47 severity-bearing rows
// live in four other places, and none of them was opened.
//
// ⚠️ WHY THIS IS A CENSUS AND NOT FIVE MORE READERS. The defect was never "we forgot the
// queue". It was that nothing in the product could answer "is there a finding we are not
// rendering?" — so each door had to be found by a human reading raw JSON. A census keyed
// on CONTAINERS answers that question by construction: every container carrying a
// severity-bearing object is either READ or explicitly ALLOWLISTED with a written reason,
// and one that is NEITHER fails loudly. Incompleteness costs NOISE, never SILENCE — the
// inverse of the shape that produced the false clean.
//
// ⚠️ AND THE FIXTURE LESSON THAT MADE IT NECESSARY: the fleet fixture written one round
// earlier proves `shapeFinding` over every finding SHAPE, and it could not see this,
// because the network path's failure is a SOURCE the consumer never opens. A fixture
// drawn from a producer's field names cannot catch a producer whose output lives in a
// different artifact.
//
// ⚠️ AND THEN THE ALLOWLIST BECAME THE NEXT INSTANCE OF THE SAME CLASS. Its entries were
// PROSE, and two of them asserted a FACT about one run rather than a property of a shape —
// the cisAlarmCoverage entry closed with its own instruction, "re-derive, do not re-assert",
// and NOTHING RE-DERIVED IT. A carve-out that outlives the fact justifying it excludes real
// findings from a client deliverable while the census still prints `unread: {}`: a false
// clean wearing the exit code of a measurement. So an entry is now `{reason, verify}`, and a
// premise that FAILS or THROWS withdraws the carve-out — the container is counted UNREAD and
// reported in `premiseFailures` with the detail, because "nobody wrote a reader" and "the
// reason we wrote no reader stopped being true" need different repairs.

/** Containers the report READS. Adding a reader means adding its key here. */
export const READ_CONTAINERS = Object.freeze([
  'result.findings[]',                  // array-shaped plugin findings (the cloud shape)
  'result.findings.<category>[]',       // dict-of-categories (060 DNS Security Auditor)
  'result.zeroTrust.<dim>.findings[]',  // 1023 Zero Trust Assessment
  'result.portResults[].issues[]',      // 040 TLS Certificate & Cipher Auditor
  'findingQueue[]',                     // the EE finding queue (intelligence_engine, crypto_agent)
]);

/**
 * THE CENSUS'S SUBJECT, in one place, because a verifier that vouches for a different set of
 * objects than the census counted is vouching for nothing. Both the walk below and every
 * `verify` use this predicate: it is the DEFINITION of what is being carved out, not a
 * second opinion about it.
 */
export function isCensusSubject(node) {
  return !!node && typeof node === 'object' && !Array.isArray(node) && typeof node.severity === 'string';
}

const resultsOf = (raw) => (Array.isArray(raw?.results) ? raw.results : []);
const arrayAt = (o, k) => (Array.isArray(o?.[k]) ? o[k] : []);

/** Key-sorted serialisation, so two rows compare by CONTENT and not by key order. */
function canonical(v) {
  if (Array.isArray(v)) return `[${v.map(canonical).join(',')}]`;
  if (v && typeof v === 'object') {
    return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${canonical(v[k])}`).join(',')}}`;
  }
  return JSON.stringify(v ?? null);
}

// ── The premises, one per carve-out ──────────────────────────────────────────

/**
 * (i) `result.summary.cisAlarmCoverage.uncovered[]` — the mirror is still 1:1.
 *
 * Derived from the real records, never invented: an uncovered entry is
 * `{id:'cis-3.1', title, severity, coverageMode}` and its paired rendered finding carries
 * BOTH `details.cisId` (with `details.category` = 'cis-alarm-coverage-no-filter') AND an
 * `issues[]` string reading "CloudWatch alarm missing: … (CIS AWS Foundations Benchmark
 * cis-3.1)". Measured over the 152 sample records: 48 plugin results carry an alarm-coverage
 * summary, 624 uncovered entries in total, and BOTH channels independently pair 100% of them.
 * Either channel is therefore accepted — a class the reader receives is not a lost finding,
 * whichever field carried it — and the details channel is scoped to alarm-coverage findings
 * so a `cisId` on an unrelated finding cannot stand in for the mirror.
 */
function verifyAlarmCoverageStillMirrorsItsFindings(raw) {
  const broken = [];
  for (const e of resultsOf(raw)) {
    const res = e?.result ?? {};
    const uncovered = arrayAt(res?.summary?.cisAlarmCoverage, 'uncovered').filter(isCensusSubject);
    if (!uncovered.length) continue;

    const rendered = new Set();
    for (const f of arrayAt(res, 'findings')) {
      if (!f || typeof f !== 'object') continue;
      for (const issue of arrayAt(f, 'issues')) {
        if (typeof issue !== 'string' || !/alarms?\s+missing/i.test(issue)) continue;
        for (const m of issue.matchAll(/\bcis-\d+(?:\.\d+)*\b/gi)) rendered.add(m[0].toLowerCase());
      }
      const d = f.details;
      if (d && typeof d.cisId === 'string' && typeof d.category === 'string' && /alarm/i.test(d.category)) {
        rendered.add(d.cisId.toLowerCase());
      }
    }
    for (const u of uncovered) {
      if (typeof u.id !== 'string' || !u.id) {
        broken.push(`plugin ${e?.id ?? '?'}: an uncovered entry with no \`id\` — nothing can pair it`);
      } else if (!rendered.has(u.id.toLowerCase())) {
        broken.push(`plugin ${e?.id ?? '?'}: ${u.id}`);
      }
    }
  }
  return broken.length
    ? { ok: false,
      unreadCount: broken.length,
      detail: `the 1:1 mirror has BROKEN — ${broken.length} uncovered alarm class(es) have no rendered `
        + `"alarm missing" finding, so they reach no reader: ${broken.join(' · ')}` }
    : { ok: true, detail: 'every uncovered alarm class pairs with a rendered finding' };
}

/**
 * (ii) `result.findings[].policyAnalyses[].issues[]` — the parent really is rendered.
 *
 * The carve-out calls the nested issues EVIDENCE FOR a finding that IS rendered. That is
 * true only while the parent carries content of its own: `shapeFinding` titles a finding
 * from its `issues[]` (falling back to `detail`/`description`), and with none of those it
 * renders "(untitled finding)" — utils/report_inputs.mjs:139-151. A parent with no issue of
 * its own is an empty row whose only real content is the nested detail nobody reads, which
 * is the carve-out's own negation. Measured: 104 parents across the sample corpus carry
 * counted policy-analysis issues, and 0 of them lack their own.
 */
function verifyPolicyAnalysisBacksARenderedFinding(raw) {
  const orphans = [];
  for (const e of resultsOf(raw)) {
    const findings = arrayAt(e?.result, 'findings');
    for (let i = 0; i < findings.length; i += 1) {
      const f = findings[i];
      if (!f || typeof f !== 'object') continue;
      const nested = arrayAt(f, 'policyAnalyses')
        .flatMap((pa) => arrayAt(pa, 'issues'))
        .filter(isCensusSubject);
      if (!nested.length) continue;
      // Presence is not content: an `issues: ['']` renders as no text at all.
      const own = arrayAt(f, 'issues')
        .filter((x) => (typeof x === 'string' ? x.trim().length > 0 : !!x));
      if (!own.length) {
        orphans.push(`plugin ${e?.id ?? '?'} findings[${i}] carries ${nested.length} policy-analysis `
          + 'issue(s) and NO issue of its own');
      }
    }
  }
  return orphans.length
    ? { ok: false,
      unreadCount: orphans.length,
      detail: 'the nested detail is no longer EVIDENCE FOR a rendered finding — the parent renders as '
        + `"(untitled finding)" with nothing in it: ${orphans.join(' · ')}` }
    : { ok: true, detail: 'every policy-analysis parent carries its own issue text' };
}

/**
 * (iii) `result.data[]` — on the cloud path it still MIRRORS `findings[]`.
 *
 * ⚠️ THE PREDICATE IS DELIBERATELY SCOPED TO THE CENSUS'S SUBJECT, AND THAT IS WHAT MAKES
 * THE NETWORK SHAPE PASS WITHOUT AN EXEMPTION. A network host legitimately has
 * `findings[] = 0` and `data[] = 85` — measured on the 192.168.1.1 run, 84 of them
 * `{probe_protocol, probe_port, probe_info}`. Not one carries a `severity`, so not one is a
 * census subject and there is nothing to mirror: the acceptance is STRUCTURAL, not a list of
 * telemetry field names that a producer could quietly step outside. The corollary is
 * intended: a telemetry row that GAINS a severity is a severity-bearing object in a container
 * nobody reads, and it fails.
 *
 * Matching is CONTENT-DEEP within one plugin result. Measured across the sample corpus: 86
 * plugin results carry severity-bearing data rows (1150 and 1170 only, 1075 rows), and every
 * row is deep-equal to a row in the same result's findings[]. A laxer key of
 * severity+resource+issues was measured too — also 0 unmatched — and REJECTED: it collapses
 * to a constant on rows that carry neither `resource` nor `issues`, which is a false-clean
 * generator on exactly the network-ish shape this entry has to keep accepting.
 *
 * One stated limit: the mirror is looked for in `findings[]` in its ARRAY form only. A
 * producer that emitted the 060 DICT-of-categories shape AND severity-bearing data[] would
 * FAIL this premise rather than be excused by it. Nothing does today; failing is the
 * noise-costing direction, and a lax read here would be a carve-out granted on a shape
 * nobody has looked at.
 */
function verifyDataMirrorsFindings(raw) {
  const unmirrored = [];
  for (const e of resultsOf(raw)) {
    const res = e?.result ?? {};
    const rows = arrayAt(res, 'data').filter(isCensusSubject);
    if (!rows.length) continue;
    const rendered = new Set(arrayAt(res, 'findings')
      .filter((f) => f && typeof f === 'object').map(canonical));
    for (const r of rows) {
      if (!rendered.has(canonical(r))) {
        // Locate it well enough to act on: `resource` alone is not distinguishing — on some
        // producers it holds the REGION, so a dozen rows share it.
        const excerpt = arrayAt(r, 'issues').map((x) => (typeof x === 'string' ? x : x?.detail ?? ''))
          .find((t) => t && t.trim()) ?? '';
        unmirrored.push(`plugin ${e?.id ?? '?'}: ${r.severity.toUpperCase()} `
          + `${r.resource ?? '(no resource)'}${excerpt ? ` — "${excerpt.slice(0, 80)}"` : ''}`);
      }
    }
  }
  return unmirrored.length
    ? { ok: false,
      unreadCount: unmirrored.length,
      detail: `result.data[] is no longer a mirror — ${unmirrored.length} severity-bearing row(s) have no `
        + `content-equal finding in the same plugin result, so nothing renders them: ${unmirrored.join(' · ')}` }
    : { ok: true, detail: 'every severity-bearing data row is mirrored by a rendered finding' };
}

/**
 * (iv) `result.portResults[]` — the roll-up really is a roll-up.
 *
 * The reason claims the entry's severity "summarises the port's own issues[], which ARE
 * read". That is checkable in both directions, and both directions matter:
 *   · a severity over an EMPTY issues[] summarises nothing — it is a finding nothing renders,
 *     which is the exact hazard the carve-out denies;
 *   · a severity ABSENT from its own issues' severities is a roll-up of something the port
 *     does not hold.
 * The empty case is not simply forbidden, because 040 seeds the roll-up at SEVERITY.PASS and
 * raises it to the max of the port's issues (plugins/040_tls_cert_auditor.mjs:491-496), so a
 * clean port emits exactly `{severity:'pass', issues:[]}`. PASS is the identity element of
 * this roll-up; failing it would flag every healthy HTTPS port and teach an operator to read
 * past the warning. Measured over 232 records (samples + both out/ trees): 7 portResults
 * entries carry a severity, all 7 hold it among their own issue severities, and none has an
 * empty issues[].
 */
const ROLLUP_IDENTITY_SEVERITY = 'pass';

function verifyPortRollUpSummarisesItsOwnIssues(raw) {
  const bad = [];
  for (const e of resultsOf(raw)) {
    const ports = arrayAt(e?.result, 'portResults');
    for (let i = 0; i < ports.length; i += 1) {
      const pr = ports[i];
      if (!isCensusSubject(pr)) continue;
      const where = `plugin ${e?.id ?? '?'} port ${pr.port ?? `[${i}]`}`;
      const issueSeverities = arrayAt(pr, 'issues').filter(isCensusSubject).map((x) => x.severity);
      if (!issueSeverities.length) {
        if (pr.severity !== ROLLUP_IDENTITY_SEVERITY) {
          bad.push(`${where}: severity "${pr.severity}" over an EMPTY issues[] — it summarises nothing, `
            + 'so nothing renders it');
        }
        continue;
      }
      if (!issueSeverities.includes(pr.severity)) {
        bad.push(`${where}: roll-up severity "${pr.severity}" is not among its own issue severities `
          + `(${[...new Set(issueSeverities)].join(', ')})`);
      }
    }
  }
  return bad.length
    ? { ok: false, unreadCount: bad.length, detail: `the roll-up no longer summarises its own issues[]: ${bad.join(' · ')}` }
    : { ok: true, detail: 'every port roll-up is carried by its own issues' };
}

/**
 * Containers that carry a `severity` but are NOT findings. Each needs a written reason AND,
 * where the reason rests on a checkable fact, a `verify(raw, queue) => {ok, detail}` that
 * re-derives it on every run — an allowlist entry with no reason is how a real door gets
 * closed by accident, and one whose reason nothing re-derives is how a closed door stays
 * shut after the reason has gone.
 */
export const ALLOWLISTED_CONTAINERS = Object.freeze({
  'result.portResults[]': Object.freeze({
    reason:
      'A per-port ROLL-UP, not a finding: its severity summarises the port\'s own '
      + '`issues[]`, which ARE read. Rendering both would double-count every TLS issue.',
    verify: verifyPortRollUpSummarisesItsOwnIssues,
  }),
  'result.summary.cisAlarmCoverage.uncovered[]': Object.freeze({
    reason:
      'A 1:1 SUMMARY MIRROR of 1040\'s own alarm-coverage findings, not a second source. '
      + 'Adjudicated on the 0.44.0 cloud run: 13 uncovered classes, 13 "alarm missing" '
      + 'findings, and the set difference of their cis-N.N ids is EMPTY. That was a fact '
      + 'about one run, so `verify` re-derives it on every run rather than re-asserting it.',
    verify: verifyAlarmCoverageStillMirrorsItsFindings,
  }),
  'result.findings[].policyAnalyses[].issues[]': Object.freeze({
    reason:
      'Per-statement EVIDENCE nested inside a finding that IS rendered — e.g. "Full admin '
      + 'grant: Action \'*\' in policy X" backing a parent whose own issues[] already say '
      + '"SHADOW ADMIN: User has full wildcard (*) permissions". Not a missed finding. '
      + 'RESIDUAL, stated rather than hidden: the per-statement detail is not surfaced in the '
      + 'report at all, which is a DEPTH choice nobody has ruled on, not a coverage gap.',
    verify: verifyPolicyAnalysisBacksARenderedFinding,
  }),
  'result.data[]': Object.freeze({
    reason:
      'NOT a findings container, and the report must never read it. On a CLOUD host it '
      + 'MIRRORS result.findings (verified 0.44.0: 1150 16/16, 1170 9/9). On a NETWORK host '
      + 'it is PROBE TELEMETRY — measured on the 192.168.1.1 run, findings[]=0 while '
      + 'data[]=85, 84 of them {probe_protocol, probe_port, probe_info} ("Connect refused '
      + '(ECONNREFUSED)", "No UDP response"). ⚠️ A `findings ?? data` fallback was written '
      + 'here and REVERTED: it put scan telemetry into a client deliverable, hidden because '
      + 'the telemetry rows collided on one content hash and collapsed to two. '
      + 'cloud_finding_summary\'s findingsOf may use that precedence — it only ever sees '
      + 'cloud producers; this consumer sees both paths.',
    verify: verifyDataMirrorsFindings,
  }),
});

const QUEUE_CONTAINER = 'findingQueue[]';

/**
 * Adjudicate ONE allowlist entry against a record.
 *
 * ⚠️ FAILS CLOSED IN EVERY DIRECTION THAT IS NOT AN EXPLICIT `ok: true`. A verifier that
 * throws has not established the premise; neither has one that returns a shape nobody can
 * read. Both are treated as a broken premise, because the alternative — a thrown TypeError
 * silently restoring the carve-out — is the false clean this whole mechanism exists to
 * close, and it would arrive precisely when a producer changed shape.
 *
 * @returns {string|null} null when the carve-out stands (premise held, or none declared);
 *                        otherwise the operator-facing detail of why it does not.
 */
export function adjudicateAllowlistEntry(entry, raw, queue) {
  // An entry that declares no premise keeps its carve-out: a shape nobody can check yet is
  // better carved out loudly, with its reason readable, than checked wrongly. The ratchet
  // that stops "undeclared" becoming the default lives in the tests, not here.
  if (typeof entry?.verify !== 'function') return null;
  let verdict;
  try {
    verdict = entry.verify(raw, queue);
  } catch (err) {
    return { detail: `premise check THREW (${err?.message ?? String(err)}) — a check that cannot `
      + 'run has established nothing, so the carve-out is withdrawn' };
  }
  if (!verdict || typeof verdict !== 'object' || typeof verdict.ok !== 'boolean') {
    return { detail: 'premise check returned no verdict — treated as FAILED, because a check that '
      + 'cannot answer has not established anything' };
  }
  if (verdict.ok) return null;
  // ⚠️ THE COUNT TRAVELS WITH THE DETAIL. This used to return the detail STRING alone, so the
  // caller had a sentence saying "1 row has no mirror" and no number to act on — and fell back to
  // the container's whole population, which is exactly the false quantity the consumer renders.
  // A failure is `{detail, unreadCount}`; `unreadCount` is whatever the verifier claimed and is
  // VALIDATED downstream by resolveUnreadCount, never trusted here.
  return {
    detail: typeof verdict.detail === 'string' && verdict.detail.trim()
      ? verdict.detail
      : 'premise FAILED, with no detail given',
    unreadCount: verdict.unreadCount,
  };
}

/**
 * Classify where a severity-bearing object lives. Path is the dotted walk from `result`.
 * @returns {string} a container key
 */
function containerOf(path) {
  if (/^\.findings\[\d+\]$/.test(path)) return 'result.findings[]';
  if (/^\.findings\.[A-Za-z0-9_]+\[\d+\]$/.test(path)) return 'result.findings.<category>[]';
  if (/zeroTrust\..*\.findings\[\d+\]$/.test(path)) return 'result.zeroTrust.<dim>.findings[]';
  if (/^\.portResults\[\d+\]\.issues\[\d+\]$/.test(path)) return 'result.portResults[].issues[]';
  if (/^\.portResults\[\d+\]$/.test(path)) return 'result.portResults[]';
  if (/^\.summary\.cisAlarmCoverage\.uncovered\[\d+\]$/.test(path)) return 'result.summary.cisAlarmCoverage.uncovered[]';
  if (/^\.findings\[\d+\]\.policyAnalyses\[\d+\]\.issues\[\d+\]$/.test(path)) return 'result.findings[].policyAnalyses[].issues[]';
  if (/^\.data\[\d+\]$/.test(path)) return 'result.data[]';
  // An UNRECOGNISED container is reported under its own generalised path rather than
  // bucketed into "other" — a census that collapses the unknown into one bucket tells you
  // that something is missing without telling you what.
  return `UNCLASSIFIED:${path.replace(/\[\d+\]/g, '[]')}`;
}

function* severityObjects(node, path = '') {
  if (Array.isArray(node)) {
    for (let i = 0; i < node.length; i += 1) yield* severityObjects(node[i], `${path}[${i}]`);
  } else if (node && typeof node === 'object') {
    if (isCensusSubject(node)) yield { path, obj: node };
    for (const [k, v] of Object.entries(node)) yield* severityObjects(v, `${path}.${k}`);
  }
}

/**
 * Census one scan record.
 * @param {object} raw   the parsed scan_conclusion_raw.json
 * @param {Array}  queue the host's finding queue (scan_finding_queue.json, or the
 *                       eeEnrichment fallback) — passed in because it is a SIBLING
 *                       artifact, not part of `raw`, which is the whole reason it was missed.
 * @returns {{byContainer: Object<string, number>, unread: Object<string, number>,
 *            premiseFailures: Object<string, string>, total: number}}
 *   `unread` is the operator's answer to "what does this report not read?" and a container
 *   lands there for one of TWO reasons; `premiseFailures` says which, keyed on the same
 *   container, because the repairs are opposite — an unknown container needs a reader
 *   written, a withdrawn carve-out needs its justification re-argued or removed.
 */
/**
 * HOW MANY OBJECTS A BROKEN PREMISE ACTUALLY LEAVES UNREAD.
 *
 * ⚠️ THE REPAIR FOR ONE FALSE CLEAN INTRODUCED A FALSE QUANTITY, and the number reaches a
 * CUSTOMER. `unread[k]` used to be the container's WHOLE population, and `executive_report.mjs`
 * renders it as "N recorded finding-like object(s) … are NOT included above". For a MIRROR
 * carve-out that breaks PARTIALLY, most of those objects ARE rendered above — plugin 1150 emits
 * `data: findings`, so 16 mirrored rows and one orphan told a client that 17 objects were missing
 * from a report containing 16 of them. **A caveat that contradicts the body of its own document.**
 *
 * ⚠️ AND `unreadCount ?? population` IS NOT ENOUGH — that only catches null/undefined. A verifier
 * returning `0` on a real break, or `"3"`, or a count ABOVE the population, would put a garbage
 * number into a client-facing sentence. Every one of those degrades to the population instead:
 * **over-report, never emit a silent or impossible number.** `0` is deliberately refused rather
 * than trusted — a failure claiming nothing is unread is a verifier bug silencing itself.
 */
export function resolveUnreadCount(failure, population) {
  const n = failure?.unreadCount;
  if (typeof n !== 'number' || !Number.isInteger(n) || n <= 0 || n > population) return population;
  return n;
}

export function censusFindingContainers(raw, queue = []) {
  const byContainer = {};
  const bump = (k) => { byContainer[k] = (byContainer[k] || 0) + 1; };

  for (const e of resultsOf(raw)) {
    for (const { path } of severityObjects(e?.result ?? {}, '')) bump(containerOf(path));
  }
  if (Array.isArray(queue) && queue.length) byContainer[QUEUE_CONTAINER] = queue.length;

  const unread = {};
  const premiseFailures = {};
  for (const [k, n] of Object.entries(byContainer)) {
    if (READ_CONTAINERS.includes(k)) continue;
    if (!Object.prototype.hasOwnProperty.call(ALLOWLISTED_CONTAINERS, k)) { unread[k] = n; continue; }
    // The premise is only adjudicated where something is actually being carved out: running
    // it over a container this record does not carry would report on nothing.
    const failure = adjudicateAllowlistEntry(ALLOWLISTED_CONTAINERS[k], raw, queue);
    if (failure === null) continue;
    // The BREAK, not the container — see resolveUnreadCount for why the count is validated
    // rather than trusted, and why the population stays in `byContainer` where it belongs.
    unread[k] = resolveUnreadCount(failure, n);
    // `premiseFailures` stays a map of container -> DETAIL STRING: it is the operator- and
    // reader-facing half, and the count already lives in `unread`. Putting the verdict OBJECT
    // here would change a published shape for no gain and hand two numbers to a consumer that
    // needs one.
    premiseFailures[k] = failure.detail;
  }
  return { byContainer, unread, premiseFailures, total: Object.values(byContainer).reduce((a, b) => a + b, 0) };
}
