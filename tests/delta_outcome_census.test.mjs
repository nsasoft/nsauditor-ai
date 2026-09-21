// THE OUTCOME CENSUS WITH AN EQUALITY RATCHET (board item C7).
//
// ⚠️ THE CLASS THIS EXISTS FOR: a guard can be disarmed by a FIX THAT NARROWS ITS SUBJECT, with
// nothing failing and nobody editing the guard. It happened twice in two commits in this lane —
// the collision limit and the NOT-COMPARABLE reasons — and both times the only thing that caught
// it was a human re-running the mutation battery. That is discipline, not mechanism. This is the
// mechanism: every declared outcome must be PRODUCED by something that drives the SHIPPED entry
// point, so when a later fix narrows a trigger until an outcome is unreachable, this file fails
// BY NAME instead of going quietly green.
//
// ⚠️ WHAT IT DOES NOT COVER, stated here because a mechanism sold past its reach is the defect
// this lane has spent the cycle hunting. It makes REACHABILITY loud, not CORRECTNESS: an outcome
// produced by one trivial fixture passes here while still being wrong. It reaches only guards
// expressible as a DISCRETE NAMED OUTCOME — a branch that merely adjusts a number has no code to
// census, and for those the mutation battery is still the only instrument. This SHRINKS the
// surface that depends on discipline. It does not eliminate it.
//
// The obvious objection — a seat could write one throwaway fixture per code just to satisfy the
// census — is not an objection. That fixture PINS the trigger condition, so when the condition
// narrows it fails. The cheat-path is the intended path.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { runReport } from '../cli.mjs';
import { resolveCapabilities } from '../utils/capabilities.mjs';
import { escapeHtml } from '../utils/brand.mjs';
import {
  DECLARED_OUTCOMES, DECLARED_UNREACHABLE_OUTCOMES, DECLARED_LIMITS, OUTCOME_PROBE_CHARS,
} from '../utils/scan_delta.mjs';
import { newRunId, writeRunStart, appendHostWritten, finalizeRunRecord, runRecordPath } from '../utils/run_record.mjs';
import { sealRunRecord, chainDigestPath } from '../utils/run_chain.mjs';

const PRO = () => resolveCapabilities('pro');
const s3 = (resource, severity = 'HIGH', extra = {}) =>
  ({ severity, title: 'No public access block configured', port: 443, resource, ...extra });

// ⚠️ IDS in `pluginsRequested`, because that is what cli.mjs writes. A fixture spelled in the
// DISPLAY-NAME vocabulary is what kept G2 invisible: both sides agreed, so the suite could not
// tell a working comparison from one that can never match on a real record.
function writeHostDir(outRoot, dir, runId, findings, { status = 'ran', omitResult = false,
  queue = null, omitPluginStatus = false, host = '10.0.0.7' } = {}) {
  fs.mkdirSync(path.join(outRoot, dir), { recursive: true });
  const env = { runId, results: omitResult ? [] : [{ id: '010', name: 'aws-s3', result: { up: true, findings } }] };
  if (!omitPluginStatus) env.pluginStatus = [{ id: '010', name: 'aws-s3', status, reason: status === 'ran' ? null : 'credential expired' }];
  fs.writeFileSync(path.join(outRoot, dir, 'scan_conclusion_raw.json'), JSON.stringify(env), 'utf8');
  if (queue) fs.writeFileSync(path.join(outRoot, dir, 'scan_finding_queue.json'), JSON.stringify(queue), 'utf8');
  return host;
}

async function mkRun(outRoot, { startedAt, findings = [], seal = true, tier = 'pro',
  eeVersion = '1.1.0', ceVersion = '0.2.55', plugins = ['010'], host = '10.0.0.7',
  status, omitResult, queue, omitPluginStatus, prevDigest } = {}) {
  const runId = newRunId();
  await writeRunStart(outRoot, { runId, startedAt, hostsRequested: [host],
    pluginsRequested: plugins, portsRequested: '443', tier, ceVersion, eeVersion, prevDigest });
  writeHostDir(outRoot, `d-${runId}`, runId, findings, { status, omitResult, queue, omitPluginStatus, host });
  await appendHostWritten(outRoot, runId, { host, dir: `d-${runId}` });
  await finalizeRunRecord(outRoot, runId, { finishedAt: startedAt });
  if (seal) await sealRunRecord(outRoot, runId);
  return runId;
}

// EVERY production goes through `runReport` — the function the CLI dispatches to. That is the
// board's correction to the v56 spec, and it is the half that matters: an outcome reachable only
// by calling `buildScanDelta` with hand-built inputs is an outcome no customer can ever see.
async function drive(outRoot, current, since, { tier = 'pro' } = {}) {
  const outFile = path.join(outRoot, `r-${current}.html`);
  const r = await runReport({ from: outRoot, format: 'executive', run: current, since, out: outFile },
    resolveCapabilities(tier));
  return {
    code: r.code,
    stdout: `${r.stdout ?? ''}\n${r.stderr ?? ''}`,
    html: fs.existsSync(outFile) ? fs.readFileSync(outFile, 'utf8') : null,
  };
}

const tmp = (tag) => fs.mkdtempSync(path.join(os.tmpdir(), `nsa-census-${tag}-`));

// ⚠️ `seal: false` IS NOT ENOUGH AND THAT COST A FIXTURE. `finalizeRunRecord` seals every record
// it writes, so a "don't seal it" knob produces a SEALED record and the *-unchained outcomes
// could never fire from it. `chain-absent` means "written before chaining shipped", which is a
// record with NO sidecar AND no `prevDigest` key — a missing sidecar ALONE is `chain-unreadable`,
// deliberately, so that deleting a sidecar cannot be laundered into "this predates chaining".
function makeLegacy(outRoot, runId) {
  fs.rmSync(chainDigestPath(outRoot, runId), { force: true });
  const p = runRecordPath(outRoot, runId);
  const rec = JSON.parse(fs.readFileSync(p, 'utf8'));
  delete rec.prevDigest;
  fs.writeFileSync(p, JSON.stringify(rec), 'utf8');
}

// ── ONE PRODUCER PER DECLARED CODE. Each drives the shipped entry point and returns its output.
const PRODUCERS = {
  'host-not-scanned': async () => {
    const outRoot = tmp('hns');
    const baseline = await mkRun(outRoot, { startedAt: '2026-09-01T10:00:00.000Z', findings: [s3('bucket-a')], host: '10.0.0.7' });
    const current = await mkRun(outRoot, { startedAt: '2026-09-08T10:00:00.000Z', findings: [s3('bucket-a')], host: '10.0.0.9' });
    return drive(outRoot, current, baseline);
  },
  'plugin-not-run': async () => {
    const outRoot = tmp('pnr');
    const baseline = await mkRun(outRoot, { startedAt: '2026-09-01T10:00:00.000Z', findings: [s3('bucket-a')], plugins: ['010'] });
    const current = await mkRun(outRoot, { startedAt: '2026-09-08T10:00:00.000Z', findings: [], plugins: ['020'] });
    return drive(outRoot, current, baseline);
  },
  'plugin-not-measured': async () => {
    const outRoot = tmp('pnm');
    const baseline = await mkRun(outRoot, { startedAt: '2026-09-01T10:00:00.000Z', findings: [s3('bucket-a')] });
    const current = await mkRun(outRoot, { startedAt: '2026-09-08T10:00:00.000Z', findings: [], status: 'error', omitResult: true });
    return drive(outRoot, current, baseline);
  },
  'evidence-gap': async () => {
    const outRoot = tmp('gap');
    const baseline = await mkRun(outRoot, { startedAt: '2026-09-01T10:00:00.000Z', findings: [s3('bucket-a')] });
    const current = await mkRun(outRoot, { startedAt: '2026-09-08T10:00:00.000Z',
      findings: [s3('bucket-a', 'INFO', { details: { evidenceGap: true } })] });
    return drive(outRoot, current, baseline);
  },
  'producer-unknown': async () => {
    const outRoot = tmp('unk');
    // A queue entry with no `evidence.source` carries no producer identity at all.
    const q = [{ id: 'F-1', severity: 'HIGH', title: 'Anonymous producer finding', target: { port: 443 }, evidence: {} }];
    const baseline = await mkRun(outRoot, { startedAt: '2026-09-01T10:00:00.000Z', findings: [], queue: q });
    const current = await mkRun(outRoot, { startedAt: '2026-09-08T10:00:00.000Z', findings: [] });
    return drive(outRoot, current, baseline);
  },
  'ee-presence-differs': async () => {
    const outRoot = tmp('eep');
    const baseline = await mkRun(outRoot, { startedAt: '2026-09-01T10:00:00.000Z', findings: [s3('bucket-a')], eeVersion: '1.1.0' });
    const current = await mkRun(outRoot, { startedAt: '2026-09-08T10:00:00.000Z', findings: [s3('bucket-a')], eeVersion: null });
    return drive(outRoot, current, baseline);
  },
  'tier-differs': async () => {
    const outRoot = tmp('tier');
    const baseline = await mkRun(outRoot, { startedAt: '2026-09-01T10:00:00.000Z', findings: [s3('bucket-a')], tier: 'pro' });
    const current = await mkRun(outRoot, { startedAt: '2026-09-08T10:00:00.000Z', findings: [s3('bucket-a')], tier: 'enterprise' });
    return drive(outRoot, current, baseline, { tier: 'enterprise' });
  },
  'finding-count-semantics-boundary': async () => {
    const outRoot = tmp('fcb');
    const baseline = await mkRun(outRoot, { startedAt: '2026-09-01T10:00:00.000Z', findings: [s3('bucket-a')], eeVersion: '0.45.0' });
    const current = await mkRun(outRoot, { startedAt: '2026-09-08T10:00:00.000Z', findings: [s3('bucket-a')], eeVersion: '1.1.0' });
    return drive(outRoot, current, baseline);
  },
  'run-record-schema-differs': async () => {
    const outRoot = tmp('sch');
    const baseline = await mkRun(outRoot, { startedAt: '2026-09-01T10:00:00.000Z', findings: [s3('bucket-a')], seal: false });
    const p = runRecordPath(outRoot, baseline);
    const rec = JSON.parse(fs.readFileSync(p, 'utf8'));
    rec.schema = 99;
    fs.writeFileSync(p, JSON.stringify(rec), 'utf8');
    await sealRunRecord(outRoot, baseline);
    const current = await mkRun(outRoot, { startedAt: '2026-09-08T10:00:00.000Z', findings: [s3('bucket-a')] });
    return drive(outRoot, current, baseline);
  },
  'baseline-chain-broken': async () => {
    const outRoot = tmp('bcb');
    const baseline = await mkRun(outRoot, { startedAt: '2026-09-01T10:00:00.000Z', findings: [s3('bucket-a')] });
    const current = await mkRun(outRoot, { startedAt: '2026-09-08T10:00:00.000Z', findings: [] });
    // Tamper AFTER sealing: the digest no longer describes the bytes.
    const p = runRecordPath(outRoot, baseline);
    const rec = JSON.parse(fs.readFileSync(p, 'utf8'));
    rec.portsRequested = '8443';
    fs.writeFileSync(p, JSON.stringify(rec), 'utf8');
    return drive(outRoot, current, baseline);
  },
  'baseline-integrity-unmeasurable': async () => {
    const outRoot = tmp('biu');
    const baseline = await mkRun(outRoot, { startedAt: '2026-09-01T10:00:00.000Z', findings: [s3('bucket-a')] });
    const current = await mkRun(outRoot, { startedAt: '2026-09-08T10:00:00.000Z', findings: [] });
    fs.writeFileSync(chainDigestPath(outRoot, baseline), '{ this is not json', 'utf8');
    return drive(outRoot, current, baseline);
  },
  'baseline-unchained': async () => {
    const outRoot = tmp('bun');
    const baseline = await mkRun(outRoot, { startedAt: '2026-09-01T10:00:00.000Z', findings: [s3('bucket-a')] });
    const current = await mkRun(outRoot, { startedAt: '2026-09-08T10:00:00.000Z', findings: [s3('bucket-a')] });
    makeLegacy(outRoot, baseline);
    return drive(outRoot, current, baseline);
  },
  'current-unchained': async () => {
    const outRoot = tmp('cun');
    const baseline = await mkRun(outRoot, { startedAt: '2026-09-01T10:00:00.000Z', findings: [s3('bucket-a')] });
    const current = await mkRun(outRoot, { startedAt: '2026-09-08T10:00:00.000Z', findings: [s3('bucket-a')] });
    makeLegacy(outRoot, current);
    return drive(outRoot, current, baseline);
  },
  'current-chain-link-broken': async () => {
    const outRoot = tmp('clb');
    const baseline = await mkRun(outRoot, { startedAt: '2026-09-01T10:00:00.000Z', findings: [s3('bucket-a')] });
    const doomed = await mkRun(outRoot, { startedAt: '2026-09-04T10:00:00.000Z', findings: [s3('bucket-a')] });
    // ⚠️ THE PREDECESSOR IS NAMED EXPLICITLY, AND THE DEFAULT IS WHY. `writeRunStart` falls back to
    // `latestSealedDigest`, which sorts run-record FILENAMES lexically — and `newRunId()` is
    // `<ISO-seconds>-<6 random hex>`, so for records written inside the same second the "latest"
    // is decided by the random suffix. This fixture chained to the baseline on some runs and to
    // `doomed` on others, from identical code. Boarded as a finding in its own right; pinned here
    // so the census measures the outcome and not the coin flip.
    const prevDigest = fs.readFileSync(chainDigestPath(outRoot, doomed), 'utf8').trim();
    const current = await mkRun(outRoot, { startedAt: '2026-09-08T10:00:00.000Z', findings: [s3('bucket-a')], prevDigest });
    fs.rmSync(runRecordPath(outRoot, doomed));
    fs.rmSync(chainDigestPath(outRoot, doomed), { force: true });
    return drive(outRoot, current, baseline);
  },
  'scope-not-evaluated': async () => {
    const outRoot = tmp('sne');
    const baseline = await mkRun(outRoot, { startedAt: '2026-09-01T10:00:00.000Z', findings: [s3('bucket-a')], omitPluginStatus: true });
    const current = await mkRun(outRoot, { startedAt: '2026-09-08T10:00:00.000Z', findings: [s3('bucket-a')] });
    return drive(outRoot, current, baseline);
  },
  'evidence-gaps-recorded': async () => PRODUCERS['evidence-gap'](),
  'agent-scope-from-tier': async () => {
    const outRoot = tmp('agt');
    const q = [{ id: 'F-1', severity: 'HIGH', title: 'Agent-produced finding', target: { port: 443 },
      evidence: { source: 'intelligence_engine' } }];
    const baseline = await mkRun(outRoot, { startedAt: '2026-09-01T10:00:00.000Z', findings: [], queue: q });
    const current = await mkRun(outRoot, { startedAt: '2026-09-08T10:00:00.000Z', findings: [], queue: q });
    return drive(outRoot, current, baseline);
  },
  'identity-collapse': async () => {
    const outRoot = tmp('col');
    // Same host, plugin, resource, port, qualifier AND content — two records, one identity.
    const twin = [s3('bucket-a'), s3('bucket-a')];
    const baseline = await mkRun(outRoot, { startedAt: '2026-09-01T10:00:00.000Z', findings: twin });
    const current = await mkRun(outRoot, { startedAt: '2026-09-08T10:00:00.000Z', findings: twin });
    return drive(outRoot, current, baseline);
  },
  'chain-assurance': async () => {
    const outRoot = tmp('cha');
    const baseline = await mkRun(outRoot, { startedAt: '2026-09-01T10:00:00.000Z', findings: [s3('bucket-a')] });
    const current = await mkRun(outRoot, { startedAt: '2026-09-08T10:00:00.000Z', findings: [s3('bucket-a')] });
    return drive(outRoot, current, baseline);
  },
  'framework-movement-not-evaluated': async () => PRODUCERS['chain-assurance'](),
};

const probeOf = (code) => DECLARED_OUTCOMES[code].probe;

// ── SELF-CHECK. A census whose probes collide reports on the wrong outcome, and it would do so
// silently. Written before the legs that depend on it.
test('CENSUS SELF-CHECK — every declared probe is distinct and non-trivial', () => {
  const probes = Object.keys(DECLARED_OUTCOMES).map(probeOf);
  assert.equal(new Set(probes).size, probes.length,
    'two outcomes share a probe: the census would credit one production to both');
  for (const [code, o] of Object.entries(DECLARED_OUTCOMES)) {
    assert.ok(o.probe.length >= 12, `${code}: a probe this short will match something it does not mean`);
    assert.ok(['not-comparable', 'refusal', 'limit'].includes(o.species), `${code}: unknown species ${o.species}`);
  }
  for (const [code, text] of Object.entries(DECLARED_LIMITS)) {
    assert.ok(text.startsWith(DECLARED_OUTCOMES[code].probe),
      `${code}: the probe must be a PREFIX of the sentinel, or it is a second copy that can drift`);
    assert.ok(text.length >= OUTCOME_PROBE_CHARS, `${code}: sentinel shorter than the probe window`);
  }
});

// ── LEG 1 — PRODUCED. Set EQUALITY, both directions fatal.
test('LEG 1 — every declared outcome is PRODUCED through the SHIPPED entry point, and nothing is produced undeclared', async () => {
  const declared = new Set(Object.keys(DECLARED_OUTCOMES));
  const unreachable = new Set(Object.keys(DECLARED_UNREACHABLE_OUTCOMES));
  const expected = new Set([...declared].filter((c) => !unreachable.has(c)));

  const produced = new Set();
  const noProducer = [];
  for (const code of expected) {
    const make = PRODUCERS[code];
    if (!make) { noProducer.push(code); continue; }
    const r = await make();
    const surfaces = `${r.stdout}\n${r.html ?? ''}`;
    if (surfaces.includes(probeOf(code)) || surfaces.includes(escapeHtml(probeOf(code)))) produced.add(code);
  }

  assert.deepEqual(noProducer, [],
    'DECLARED BUT NO PRODUCER: an outcome nothing drives is a declared behaviour with no evidence it '
    + 'still fires. Write the fixture, or move it to DECLARED_UNREACHABLE_OUTCOMES with the limit that discloses it.');

  const missing = [...expected].filter((c) => !produced.has(c));
  assert.deepEqual(missing, [],
    'DECLARED BUT NEVER PRODUCED — this is the decay. A fix narrowed a trigger until the outcome '
    + 'became unreachable, and nothing else in the suite noticed.');
});

// ── LEG 1c — THE OTHER DIRECTION, and leg 1 is only half an equality without it.
//
// Leg 1 asks "is every declared outcome produced?". This asks "is every produced outcome
// declared?" — the direction that catches a new limit or a new reason added without joining the
// vocabulary, which is how the census would quietly stop covering the thing it was built for.
//
// ⚠️ ANCHORED ON THE ROW PREFIX, NOT ON A BARE PHRASE. `scripts/board_probe_delta_driver.mjs`
// harvested reasons with a bare /NOT COMPARABLE/ and matched a LIMIT sentence containing the
// words, reporting a bucket no finding was in. The anchors here are the emitting line's own
// prefix, for the same reason.
//
// ⚠️ STATED SCOPE: `REFUSED:` lines are NOT harvested. Two of them — the current-run chain
// refusal and the `--since prior` subject-substitution refusal — carry no declared code today,
// and requiring one would turn this leg red over honest output. That is a coverage gap in this
// leg, named here rather than hidden by a filter.
test('LEG 1c — every outcome the engine EMITS is one this module DECLARES', async () => {
  const limitProbes = Object.entries(DECLARED_OUTCOMES)
    .filter(([, o]) => o.species === 'limit').map(([, o]) => o.probe);
  const reasons = new Set(Object.entries(DECLARED_OUTCOMES)
    .filter(([, o]) => o.species === 'not-comparable').map(([c]) => c));

  const undeclared = [];
  for (const code of Object.keys(PRODUCERS)) {
    const r = await PRODUCERS[code]();
    for (const line of r.stdout.split('\n')) {
      const lim = line.match(/^\[report\]\s+LIMIT:\s+(.*)$/);
      if (lim && !limitProbes.some((p) => lim[1].startsWith(p))) {
        undeclared.push(`LIMIT emitted by ${code} matches no declared limit: "${lim[1].slice(0, 70)}…"`);
      }
      const nc = line.match(/^\[report\]\s+NOT COMPARABLE \([^)]*\)\s+.*? — ([a-z][a-z0-9-]*):/);
      if (nc && !reasons.has(nc[1])) {
        undeclared.push(`NOT-COMPARABLE reason emitted by ${code} is undeclared: "${nc[1]}"`);
      }
    }
  }
  assert.deepEqual([...new Set(undeclared)], [],
    'PRODUCED BUT NOT DECLARED — an outcome joined the engine without joining the vocabulary, so '
    + 'the census stopped covering it the moment it was added.');
});

// ── LEG 1b — the UNREACHABLE set is not a waiver. Each member's premise is CHECKED here.
test('LEG 1b — every UNREACHABLE outcome is STILL unreachable, and what speaks INSTEAD is produced', async () => {
  // ⚠️ AN EXEMPTION IS NOT A WAIVER AND IT IS CHECKED IN BOTH DIRECTIONS. Forward: the thing that
  // speaks instead must actually speak, or the outcome is SILENT rather than disclosed. Backward:
  // the code must still be absent — the day someone wires it, this goes RED and says to move it
  // into LEG 1, so the exemption cannot rot into a parking space for a working outcome.
  for (const [code, d] of Object.entries(DECLARED_UNREACHABLE_OUTCOMES)) {
    assert.ok(d.reason && d.reason.length > 40, `${code}: an exemption without a written reason is a bare allowlist`);
    const viaOutcome = d.disclosedBy ? DECLARED_OUTCOMES[d.disclosedBy] : null;
    assert.ok(viaOutcome || d.instead,
      `${code}: names neither a disclosing outcome nor the text that speaks instead`);

    const make = PRODUCERS[d.disclosedBy] ?? PRODUCERS[code];
    assert.ok(make, `${code}: nothing drives it, so its premise is unchecked — write the fixture`);
    const r = await make();
    const surfaces = `${r.stdout}\n${r.html ?? ''}`;

    const spoken = viaOutcome ? probeOf(d.disclosedBy) : d.instead;
    assert.ok(surfaces.includes(spoken) || surfaces.includes(escapeHtml(spoken)),
      `${code}: what was supposed to speak INSTEAD ("${spoken}") was not produced either — `
      + 'the outcome is silent, not disclosed');

    if (PRODUCERS[code]) {
      const own = await PRODUCERS[code]();
      const ownSurfaces = `${own.stdout}\n${own.html ?? ''}`;
      assert.ok(!ownSurfaces.includes(probeOf(code)),
        `${code}: declared UNREACHABLE but its own fixture produced it. It works — move it into `
        + 'LEG 1 and delete the exemption.');
    }
  }
});

// ── LEG 2 — RENDERED, on BOTH surfaces.
//
// ⚠️ BOTH, because leg 1 alone passes a bare count: the code is still produced internally, and a
// fix that solves the problem on stdout while leaving the client artifact silent re-opens it on
// the surface that matters more. The consultant's deliverable is the HTML, not their terminal.
test('LEG 2 — every outcome that must reach a human reaches BOTH stdout and the client artifact', async () => {
  const failures = [];
  for (const [code, o] of Object.entries(DECLARED_OUTCOMES)) {
    if (o.species === 'refusal') continue;          // asserted by its own leg below
    if (DECLARED_UNREACHABLE_OUTCOMES[code]) continue;
    const r = await PRODUCERS[code]();
    const p = probeOf(code);
    if (!r.stdout.includes(p)) failures.push(`${code}: absent from STDOUT`);
    if (r.html === null) failures.push(`${code}: NO client artifact was written at all`);
    else if (!r.html.includes(escapeHtml(p)) && !r.html.includes(p)) failures.push(`${code}: absent from the CLIENT ARTIFACT`);
  }
  assert.deepEqual(failures, [], failures.join('\n'));
});

// ── LEG 2b — the refusal species, and the asymmetry stated rather than scoped away.
test('LEG 2b — a REFUSAL names its reason on stdout, and writes NO client artifact (pinned, not assumed)', async () => {
  for (const [code, o] of Object.entries(DECLARED_OUTCOMES)) {
    if (o.species !== 'refusal') continue;
    if (DECLARED_UNREACHABLE_OUTCOMES[code]) continue;   // LEG 1b owns these, in both directions
    const r = await PRODUCERS[code]();
    assert.equal(r.code, 2, `${code}: a refusal must exit 2`);
    assert.ok(r.stdout.includes(probeOf(code)), `${code}: the refusal must NAME its reason`);
    // ⚠️ PINNED BECAUSE IT IS A DESIGN DECISION, NOT AN ACCIDENT — and because
    // `executive_report.mjs` carries a rendered `delta-refused` block that NO shipped path can
    // reach while this holds. If someone wires it, this assertion goes RED and tells them to move
    // this species into LEG 2 rather than leaving two contradictory truths in the tree.
    assert.equal(r.html, null,
      `${code}: a refused comparison wrote a client artifact. That may be the right change — but the `
      + 'refusal-HTML block in executive_report.mjs was unreachable when this was written, so decide '
      + 'deliberately and move this species into LEG 2.');
  }
});
