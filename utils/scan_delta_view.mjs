// `report --since` — baseline SELECTION and the operator-facing delta view.
//
// ⚠️ THE BASELINE SELECTION IS ITSELF A CLAIM, which is why this module names it rather than
// silently diffing against it. If the selected run was narrow — a `--plugins` subset, one host,
// an interrupted run — the delta is technically correct and practically a wall of NOT-COMPARABLE,
// and an operator who meets that twice stops reading the feature. So the baseline's id, timestamp
// and scope are printed BEFORE any verdict.
//
// ⚠️ AND REFUSING IS NOT STONEWALLING. When the selected baseline cannot support a verdict, this
// says which earlier records exist and which of them are chain-verified — but it NEVER
// auto-falls-back to one. Falling back silently changes the SUBJECT of the comparison, which is
// the single thing the delta engine exists not to do.
import { listRunRecords, readRunRecord } from './run_record.mjs';
import { verifyRunChain, predecessorOf } from './run_chain.mjs';
import { buildScanDelta, CURRENT_UNCHAINED, CURRENT_CHAIN_LINK_BROKEN } from './scan_delta.mjs';
import { loadRun } from './report_inputs.mjs';

const scopeOf = (rec) => {
  const hosts = (rec?.hostsRequested ?? []).length;
  const plugins = (rec?.pluginsRequested ?? []).join(', ') || 'none recorded';
  return `${hosts} host(s) · plugins ${plugins}`;
};

/** `prior` = the record immediately before the current one; otherwise an explicit runId. */
export async function resolveBaseline(outRoot, currentRunId, since) {
  const all = await listRunRecords(outRoot);              // newest startedAt first
  if (since === 'prior') {
    // ⚠️ THE SAME ORDERING THE CHAIN USES, and previously it was not. `all[i + 1]` is a POSITION
    // in a list whose sort key is `startedAt` — and `localeCompare` returns 0 for two records
    // that share one, so ties fell through to `Array.prototype.sort`'s stability, i.e. to readdir
    // order, i.e. to the filename. The chain picked by filename too, but by a DIFFERENT filename
    // rule, so the two could name different records for the same run. One ordering now, keyed on
    // the record's contents, with ties broken deterministically.
    // ⚠️ AND IT DOES NOT REQUIRE THE PREDECESSOR TO BE SEALED, unlike the chain. Skipping an
    // unsealed record would compare against an OLDER run without saying so — the subject
    // substitution this command refuses — while comparing against an unsealed baseline merely
    // earns the disclosed `baseline-unchained` limit. Disclose, never substitute.
    const cur = all.find((r) => r?.runId === currentRunId);
    return predecessorOf(all, cur?.startedAt ?? all[0]?.startedAt) ?? null;
  }
  return all.find((r) => r?.runId === since) ?? null;
}

export async function buildSinceView({ outRoot, model, since, allowPartial, tier }) {
  const out = [];
  const err = [];
  const baseRec = await resolveBaseline(outRoot, model.runId, since);
  if (!baseRec) {
    err.push(`[report] --since ${since}: no such run record in ${outRoot}. `
      + 'Refusing rather than comparing against an arbitrary run.');
    return { code: 2, out, err };
  }

  // Name it FIRST — before verifying it, before any verdict. A refusal about a named baseline is
  // actionable; a refusal about an unnamed one is not.
  out.push(`[report] baseline: runId ${baseRec.runId} · started ${baseRec.startedAt} · scope ${scopeOf(baseRec)}`);

  const chain = await verifyRunChain(outRoot, baseRec.runId);
  if (chain.status === 'chain-broken' || chain.status === 'chain-unreadable') {
    // ⚠️ THE DECLARED CODE TRAVELS WITH THE PROSE. This refusal used to name only
    // `chain.status`, so the vocabulary an operator could grep for (`baseline-chain-broken`,
    // `baseline-integrity-unmeasurable`) appeared NOWHERE on any surface, while `buildScanDelta`
    // carried both codes in branches this refusal made unreachable. Two names for one event, and
    // the declared one was the unreachable one — found by the outcome census.
    err.push(`[report] REFUSED: ${chain.status === 'chain-broken' ? 'baseline-chain-broken' : 'baseline-integrity-unmeasurable'}`
      + ` — the baseline is ${chain.status}: ${chain.reason}. `
      + 'No finding can be called resolved against a baseline that may have been altered.');
    const others = (await listRunRecords(outRoot))
      .filter((r) => r?.runId && r.runId !== baseRec.runId && r.runId !== model.runId);
    if (others.length) {
      err.push('[report] earlier records you can name explicitly with `--since <runId>`:');
      for (const r of others) {
        const v = await verifyRunChain(outRoot, r.runId);
        err.push(`[report]   ${r.runId} · ${r.startedAt} · ${v.status}`);
      }
      err.push('[report] NOT falling back automatically: choosing a different baseline changes the '
        + 'subject of the comparison, and that is the operator\'s decision to make, not this command\'s.');
    }
    return { code: 2, out, err };
  }

  // ⚠️ THE CURRENT RECORD'S LINK, WHICH WAS COMPUTED AND NEVER READ. `verifyRunChain` works out
  // whether this run's `prevDigest` still names bytes that exist; this view read `status` alone.
  // Delete the middle of three chained records and `prior` quietly resolved to the survivor — the
  // silent substitution this module's own header says it never makes, and the verdict that
  // vanished with the deleted record is the one the operator was relying on.
  //
  // ⚠️ SCOPED TO `prior`, DELIBERATELY, AND NARROWER THAN THE PRESCRIPTION. Under `prior` a broken
  // link CHANGED THE SUBJECT: the command picked a baseline other than the one it names. Under an
  // explicit `--since <runId>` the operator chose the subject, so nothing was substituted, and
  // refusing there would turn ordinary housekeeping — deleting old records — into a blanket
  // refusal. That is the accuse-honest-evidence direction. Refuse the substitution; DISCLOSE the
  // integrity fact.
  const curChain = await verifyRunChain(outRoot, model.runId);
  // ⚠️ THE CURRENT RUN IS JUST AS ALTERABLE AS THE BASELINE, and only the baseline was verified.
  // `report --run <older> --since <even-older>` is a legitimate invocation — both records are
  // historical — and an edited CURRENT findings file produced `new` and `resolved` rows with no
  // mention of it. The refusal NAMES the side, because "the run is chain-broken" sends an operator
  // to whichever file they assume, and the point of naming a subject is that they check the right
  // one. Same two fatal statuses as the baseline: an altered current run cannot support a `new`
  // row any more than an altered baseline supports a `resolved` one.
  if (curChain.status === 'chain-broken' || curChain.status === 'chain-unreadable') {
    err.push(`[report] REFUSED: the CURRENT run ${model.runId} is ${curChain.status} — ${curChain.reason}. `
      + 'No finding can be called new or resolved when the run being REPORTED may have been altered.');
    return { code: 2, out, err };
  }
  // ⚠️ COLLECTED, NOT PRINTED. These are facts about the RUNS that the engine cannot derive — it
  // is deliberately filesystem-free — so the view supplies them. Pushing them to `out` alone would
  // put them on STDOUT ONLY: read by the operator, who knows what the tool does, and absent from
  // the HTML read by the person being billed. That is the stdout-only shape this lane already
  // retired once, for the not-comparable count. They go into `delta.limits`, which renders into
  // the client artifact AND is echoed to stdout by the limits loop below.
  const viewLimits = [];
  if (curChain.status === 'chain-absent') {
    viewLimits.push(CURRENT_UNCHAINED);
  }
  if (curChain.linkBroken) {
    if (since === 'prior') {
      err.push('[report] REFUSED: this run\'s record names a predecessor whose bytes no longer exist, '
        + `so \`--since prior\` would compare against ${baseRec.runId}, which is NOT that predecessor. `
        + 'Silently changing the subject of the comparison is the one thing this command does not do.');
      const others = (await listRunRecords(outRoot))
        .filter((r) => r?.runId && r.runId !== model.runId);
      if (others.length) {
        err.push('[report] records you can name explicitly with `--since <runId>`:');
        for (const r of others) {
          const v = await verifyRunChain(outRoot, r.runId);
          err.push(`[report]   ${r.runId} · ${r.startedAt} · ${v.status}`);
        }
      }
      return { code: 2, out, err };
    }
    viewLimits.push(CURRENT_CHAIN_LINK_BROKEN);
  }

  const loadedBase = await loadRun(outRoot, { runId: baseRec.runId, allowPartial: !!allowPartial }, { tier });
  if (!loadedBase.ok) {
    err.push(`[report] --since ${since}: the baseline run could not be loaded — ${loadedBase.message}`);
    return { code: 2, out, err };
  }

  const currentRec = await readRunRecord(outRoot, model.runId);
  // ⚠️ `pluginStatus` TRAVELS WITH EACH SIDE, and its ABSENCE is a different fact from an empty
  // one. The loader has always carried it (`model.plugins.byHost`); this view passed only
  // `findings`, so the engine could not tell a plugin that RAN from one that ERRORED on the host
  // and could not tell "no gaps" from "no oracle". Both read as clean, which is the fail-open
  // direction: a finding whose plugin crashed read as REMEDIATED in the client's report.
  const delta = buildScanDelta({
    baseline: { record: baseRec, findings: loadedBase.model.findings, integrity: chain.status,
      pluginStatus: loadedBase.model.plugins.byHost },
    current: { record: currentRec, findings: model.findings, pluginStatus: model.plugins.byHost,
      integrity: curChain.status },
  });

  if (!delta.comparable) {
    err.push(`[report] REFUSED: ${delta.refusal.reason} — ${delta.refusal.detail}`);
    return { code: 2, out, err };
  }
  delta.limits.push(...viewLimits);

  out.push(`[report] delta vs ${baseRec.runId}: ${delta.newFindings.length} new · `
    + `${delta.resolved.length} resolved · ${delta.changed.length} changed · `
    + `${delta.notComparable.length} not-comparable · ${delta.unchanged.length} unchanged`);
  for (const f of delta.changed) out.push(`[report]   CHANGED  ${f.title}${f.resource ? ` (${f.resource})` : ''} — ${f.from} → ${f.to}`);
  // ⚠️ NOT-COMPARABLE IS PRINTED WITH ITS REASON, EVERY TIME. A count alone re-creates the defect
  // this engine exists to prevent: the reader assumes the rest were comparable.
  for (const f of delta.notComparable) {
    out.push(`[report]   NOT COMPARABLE (${f.direction})  ${f.title}${f.resource ? ` (${f.resource})` : ''} — ${f.reason}: ${f.detail}`);
  }
  for (const l of delta.limits) out.push(`[report]   LIMIT: ${l}`);
  return { code: 0, out, err, delta };
}
