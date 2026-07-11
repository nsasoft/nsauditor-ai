// tests/cli_grc_preflight.test.mjs
//
// CLI GRC-push startup preflight (fail-fast). preflightGrcConfig lives in EE and
// validates the GRC push config; wiring it at CLI startup means a bad token /
// control-map / provider fails IMMEDIATELY instead of after a full scan (a real
// per-org UX gap for an MSP). The helper gates on the SAME condition the push
// itself runs under — a `scan` that requests a compliance framework (a
// framework-less recon scan / non-scan command never pushes, so it must never be
// hard-failed by a globally-set COMPLIANCE_GRC_PROVIDER) — then: skips silently
// when EE is unavailable (no EE ⇒ no push ⇒ nothing to preflight; mirrors the
// enrichScan EE-optional pattern); but a GrcConfigError PROPAGATES so the CLI can
// fail-fast.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { preflightGrcIfRequested } from '../cli.mjs';

const fakeEE = (impl) => ({ preflightGrcConfig: impl });
const grcErr = (m) => { const e = new Error(m); e.name = 'GrcConfigError'; return e; };
// a canonical "GRC requested" env + a scan/framework context that SHOULD preflight
const REQ = { COMPLIANCE_GRC_PROVIDER: 'drata', COMPLIANCE_GRC_TOKEN: 't' };
const CTX = (importEE) => ({ cmd: 'scan', frameworks: 'soc2', importEE });

test('GRC preflight — gate: a non-scan command never preflights (no EE import) even with GRC env set', async () => {
  let imported = false;
  const r = await preflightGrcIfRequested(REQ, { cmd: 'license', frameworks: 'soc2', importEE: async () => { imported = true; return fakeEE(async () => {}); } });
  assert.deepEqual(r, { ran: false, reason: 'not-scan' });
  assert.equal(imported, false, 'a globally-set COMPLIANCE_GRC_PROVIDER must not gate non-scan commands');
});

test('GRC preflight — gate: a framework-less scan never preflights (the push would no-op) even with GRC env set', async () => {
  let imported = false;
  const r = await preflightGrcIfRequested(REQ, { cmd: 'scan', frameworks: '', importEE: async () => { imported = true; return fakeEE(async () => {}); } });
  assert.deepEqual(r, { ran: false, reason: 'no-frameworks' });
  assert.equal(imported, false, 'a recon scan with no --compliance must not be hard-failed by a global GRC config');
});

test('GRC preflight — no-op + does NOT import EE when COMPLIANCE_GRC_PROVIDER is unset', async () => {
  let imported = false;
  const r = await preflightGrcIfRequested({}, CTX(async () => { imported = true; return fakeEE(async () => {}); }));
  assert.deepEqual(r, { ran: false, reason: 'not-requested' });
  assert.equal(imported, false, 'must not import EE when GRC is not requested');
});

test('GRC preflight — skips silently when EE is unavailable (import throws)', async () => {
  const r = await preflightGrcIfRequested(REQ, CTX(async () => { throw Object.assign(new Error('nope'), { code: 'ERR_MODULE_NOT_FOUND' }); }));
  assert.deepEqual(r, { ran: false, reason: 'ee-unavailable' });
});

test('GRC preflight — runs preflightGrcConfig(env) when scan + framework + provider set + EE present', async () => {
  let seen = null;
  const r = await preflightGrcIfRequested(REQ, CTX(async () => fakeEE(async (env) => { seen = env; })));
  assert.deepEqual(r, { ran: true });
  assert.equal(seen?.COMPLIANCE_GRC_PROVIDER, 'drata', 'the live env is threaded to preflightGrcConfig');
});

test('GRC preflight — re-throws GrcConfigError (fail-fast) on bad config', async () => {
  await assert.rejects(
    () => preflightGrcIfRequested(REQ, CTX(async () => fakeEE(async () => { throw grcErr('COMPLIANCE_GRC_TOKEN unset'); }))),
    (e) => e.name === 'GrcConfigError' && /TOKEN/.test(e.message),
    'a GrcConfigError from preflightGrcConfig must propagate so the CLI can fail-fast',
  );
});

test('GRC preflight — skips gracefully when EE is too old to export preflightGrcConfig', async () => {
  const r = await preflightGrcIfRequested(REQ, CTX(async () => ({})));
  assert.deepEqual(r, { ran: false, reason: 'ee-too-old' });
});
