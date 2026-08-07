// tests/cli_posture_preflight.test.mjs
//
// THE POSTURE VETO HAD TO LEAVE A BARE `catch {}` BEFORE IT MEANT ANYTHING.
//
// `NSAUDITOR_OFFLINE_ONLY=1` combined with `NSAUDITOR_TSA_URL` is a configuration
// contradiction: the operator has forbidden outbound connections and configured one. EE
// raises it as an `NsauditorConfigError` from `resolveComplianceEnvOpts`, deliberately
// OUTSIDE its own compliance try/catch, and EE ships a test whose comment reads "a
// fail-fast swallowed by a catch is a quiet skip wearing a fail-fast's name".
//
// One layer up, CE did exactly that. `cli.mjs`'s scan path wraps the whole
// `import('@nsasoft/nsauditor-ai-ee')` + `enrichScan(...)` block in `catch { /* EE not
// installed — CE proceeds unchanged */ }`, so the veto did not refuse the scan: the scan
// COMPLETED, silently missing the entire EE stage — intelligence enrichment, the analysis
// agents and the compliance report. That is worse than an abort. It is the false-clean
// shape, produced by a guard designed to prevent one, and EE's own test could not see it
// because the swallow is in the other repo.
//
// ── TWO THINGS THIS PREFLIGHT CHANGES ON PURPOSE, STATED SO NEITHER IS AN ACCIDENT ──
//
// 1. IT RUNS AT EVERY TIER. `enrichScan` returns at EE `index.mjs:131` when
//    `capabilities.intelligenceEngine` is absent, so the contradiction was never even
//    evaluated on a Community-tier run. A startup preflight has no license in hand and
//    should not: a contradiction between two operator settings is a configuration error
//    regardless of what the licence unlocks, and refusing it only for paying customers
//    would be the strangest possible reading.
//
// 2. IT EXITS 2, NOT 1. `compliance attest` already exits 2 for this exact error class
//    (cli.mjs), so the two doors into the same veto now agree. The GRC startup preflight
//    exits 1 for ITS config class; that divergence predates this file and is recorded on
//    the board rather than changed here, because renumbering a shipped exit code is a
//    contract change and not a tidy-up.
//
// EE remains OPTIONAL: no EE, no veto to run, and the preflight says so with a reason
// rather than failing. The `importEE` seam means these cases never need EE installed.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { preflightNsauditorPosture } from '../cli.mjs';

const cfgErr = (code, m) => {
  const e = new Error(m);
  e.name = 'NsauditorConfigError';
  e.code = code;
  return e;
};
const fakeEE = (impl) => ({ resolveComplianceEnvOpts: impl });
/** The contradiction, as EE raises it. */
const CONTRADICTION = { NSAUDITOR_OFFLINE_ONLY: '1', NSAUDITOR_TSA_URL: 'https://tsa.example/tsr' };

test('posture preflight — a contradiction PROPAGATES, so the CLI can fail fast', async () => {
  await assert.rejects(
    () => preflightNsauditorPosture(CONTRADICTION, {
      importEE: async () => fakeEE(() => { throw cfgErr('EOFFLINE_TSA', 'offline forbids outbound, TSA configures one'); }),
    }),
    (err) => err.name === 'NsauditorConfigError' && err.code === 'EOFFLINE_TSA',
    'the error must reach main(). Swallowing it is the defect this preflight exists to end — '
    + 'and the swallow it replaces did not merely drop the veto, it dropped the whole EE stage.');
});

test('posture preflight — a clean environment runs and reports it ran', async () => {
  let seen = null;
  const r = await preflightNsauditorPosture({ NSAUDITOR_OFFLINE_ONLY: '1' }, {
    importEE: async () => fakeEE((env) => { seen = env; return { offlineOnly: true }; }),
  });
  assert.deepEqual(r, { ran: true });
  assert.deepEqual(seen, { NSAUDITOR_OFFLINE_ONLY: '1' },
    'the resolver must be handed the REAL environment — passing a copy of process.env or an '
    + 'empty object would make the veto structurally unable to fire');
});

test('posture preflight — EE absent is not a failure, it is a reason', async () => {
  const r = await preflightNsauditorPosture(CONTRADICTION, {
    importEE: async () => { throw new Error('Cannot find package'); },
  });
  assert.deepEqual(r, { ran: false, reason: 'ee-unavailable' },
    'CE runs standalone; no EE means no egress paths to veto. Hard-failing here would break '
    + 'every Community install the moment the variables happen to be set.');
});

test('posture preflight — an EE too old to export the resolver is named, not crashed on', async () => {
  const r = await preflightNsauditorPosture(CONTRADICTION, { importEE: async () => ({}) });
  assert.deepEqual(r, { ran: false, reason: 'ee-too-old' },
    'calling a missing export would throw a TypeError that reads as a config error to the '
    + 'operator; the mixed-version case gets its own reason');
});

test('posture preflight — it is NOT gated on the command, and NOT on a licence', async () => {
  // The negative control for decision (1) above: if a future edit adds a `cmd !== 'scan'`
  // gate copied from the GRC preflight, this goes RED and the reader is sent to the comment
  // that explains why the two preflights differ.
  let calls = 0;
  const ee = async () => fakeEE(() => { calls++; return {}; });
  for (const cmd of ['scan', 'license', 'mcp', undefined]) {
    await preflightNsauditorPosture({}, { importEE: ee, cmd });
  }
  assert.equal(calls, 4,
    'a posture contradiction is a configuration error under every command. The GRC preflight '
    + 'gates on `cmd === "scan"` because a framework-less run genuinely never pushes; there is '
    + 'no equivalent condition here — the operator has forbidden egress, or has not.');
});
