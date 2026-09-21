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
import { verifyRunChain } from './run_chain.mjs';
import { buildScanDelta } from './scan_delta.mjs';
import { loadRun } from './report_inputs.mjs';

const scopeOf = (rec) => {
  const hosts = (rec?.hostsRequested ?? []).length;
  const plugins = (rec?.pluginsRequested ?? []).join(', ') || 'none recorded';
  return `${hosts} host(s) · plugins ${plugins}`;
};

/** `prior` = the record immediately before the current one; otherwise an explicit runId. */
export async function resolveBaseline(outRoot, currentRunId, since) {
  const all = await listRunRecords(outRoot);              // newest first
  if (since === 'prior') {
    const i = all.findIndex((r) => r?.runId === currentRunId);
    return (i >= 0 ? all[i + 1] : all[1]) ?? null;
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
    err.push(`[report] REFUSED: the baseline is ${chain.status} — ${chain.reason}. `
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
    current: { record: currentRec, findings: model.findings, pluginStatus: model.plugins.byHost },
  });

  if (!delta.comparable) {
    err.push(`[report] REFUSED: ${delta.refusal.reason} — ${delta.refusal.detail}`);
    return { code: 2, out, err };
  }

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
