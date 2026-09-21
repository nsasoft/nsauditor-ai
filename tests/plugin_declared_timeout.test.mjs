// O1(b) — A PLUGIN MAY DECLARE ITS OWN TIME BUDGET, BOUNDED BY A CEILING.
//
// ⚠️ THIS IS A PRODUCT DEFECT A REALISTIC ESTATE EXPOSES, NOT SMOKE NOISE. Measured on the
// Gate-2 artifacts: plugin 1020 (AWS S3 Security Auditor) ran in 18,130 ms and 18,881 ms with 7
// findings over at least 6 distinct buckets — it audits every bucket serially, issuing many
// per-bucket calls, so its cost is LINEAR in bucket count at roughly 3 s per bucket. The O1
// replication fixtures added buckets to the same account and the next run read
// `status=timeout duration_ms=30001 findings=0` against the 30 s global budget. An S3 auditor
// that reports NOT MEASURED by default on a modest account is a defect every customer has.
//
// ⚠️ AND RAISING `PLUGIN_TIMEOUT_MS` FOR THE SMOKE WOULD HAVE HIDDEN IT FROM THE GATE WHILE
// EVERY CUSTOMER KEPT IT — a green battery bought by moving the instrument, which is the shape
// this repo calls cardinal. The budget belongs to the producer that knows its own cost.
//
// THE CEILING IS THE OTHER HALF. A declared budget with no bound lets one plugin hang a scan,
// so `timeoutMs` is clamped and an exceeded DECLARED budget still fails closed to not-measured.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { resolvePluginTimeoutMs, PLUGIN_TIMEOUT_CEILING_MS, PluginManager } from '../plugin_manager.mjs';

const DEFAULT = 30000;

// ── FOURTH QUADRANT FIRST ───────────────────────────────────────────────────────────────────
// The defect is "a declared budget is ignored". The legs that rot once it is honoured are the
// ones that keep everything ELSE bounded — an undeclared plugin must not silently inherit a
// longer budget, and a declared one must not escape the ceiling. Written before the fix leg.

test('a plugin that declares NOTHING keeps the global default — the change grants no one extra time', () => {
  assert.equal(resolvePluginTimeoutMs({ id: '1010' }, undefined), DEFAULT);
  assert.equal(resolvePluginTimeoutMs({ id: '1010', timeoutMs: 0 }, undefined), DEFAULT);
  assert.equal(resolvePluginTimeoutMs({ id: '1010', timeoutMs: -1 }, undefined), DEFAULT);
  assert.equal(resolvePluginTimeoutMs({ id: '1010', timeoutMs: 'soon' }, undefined), DEFAULT);
  assert.equal(resolvePluginTimeoutMs(null, undefined), DEFAULT);
});

test('a CALLER budget still governs a plugin that declares nothing (the cloud-parallel path)', () => {
  // _runCloudPluginsParallel passes 25000; an undeclared plugin must still receive it.
  assert.equal(resolvePluginTimeoutMs({ id: '1010' }, 25000), 25000);
});

test('a declared budget ABOVE the ceiling is CLAMPED, so one plugin cannot hang a scan', () => {
  assert.equal(resolvePluginTimeoutMs({ id: '1020', timeoutMs: 999_999_999 }, undefined),
    PLUGIN_TIMEOUT_CEILING_MS);
  assert.ok(PLUGIN_TIMEOUT_CEILING_MS > DEFAULT && PLUGIN_TIMEOUT_CEILING_MS <= 600_000,
    `the ceiling must be a real bound above the default; got ${PLUGIN_TIMEOUT_CEILING_MS}`);
});

// ── THE FIX ITSELF ──────────────────────────────────────────────────────────────────────────

test('a declared budget is HONOURED, and outranks a shorter caller budget', () => {
  assert.equal(resolvePluginTimeoutMs({ id: '1020', timeoutMs: 90000 }, undefined), 90000);
  // The producer knows its own cost; a system-wide 25 s must not starve it back to not-measured.
  assert.equal(resolvePluginTimeoutMs({ id: '1020', timeoutMs: 90000 }, 25000), 90000);
});

// ── BOTH ENFORCEMENT SITES, because one policy with two call sites is how 1210 stayed broken ──

test('the DECLARED budget is honoured on the _runOne path, not only in the resolver', async () => {
  const slow = {
    id: '9001', name: 'Slow Declared', timeoutMs: 400,
    run: () => new Promise((r) => setTimeout(() => r({ up: true, data: [], findings: [] }), 150)),
  };
  const mgr = await PluginManager.create({ plugins: [slow] });
  const prev = process.env.PLUGIN_TIMEOUT_MS;
  process.env.PLUGIN_TIMEOUT_MS = '50';          // global would kill it at 50ms
  try {
    const out = await mgr._runOne(slow, 'api', 0, {});
    assert.equal(out?.result?.timedOut ?? false, false,
      'a plugin declaring 400ms must survive a 50ms GLOBAL budget');
    assert.equal(out?.result?.up, true);
  } finally {
    if (prev === undefined) delete process.env.PLUGIN_TIMEOUT_MS; else process.env.PLUGIN_TIMEOUT_MS = prev;
  }
});

test('exceeding its OWN declared budget still fails closed to not-measured', async () => {
  // ⚠️ THE LEG THAT KEEPS THE FIX HONEST. A declared budget must buy TIME, never a pass: a
  // plugin that blows its own budget is still `not measured`, which is what the compliance
  // layer reads as an evidence gap rather than as a clean result.
  const tooSlow = {
    id: '9002', name: 'Over Its Own Budget', timeoutMs: 120,
    run: () => new Promise((r) => setTimeout(() => r({ up: true, data: [] }), 3000)),
  };
  const mgr = await PluginManager.create({ plugins: [tooSlow] });
  const out = await mgr._runOne(tooSlow, 'api', 0, {});
  assert.equal(out?.result?.up, false, 'an over-budget plugin must not report up');
  assert.match(String(out?.result?.error || ''), /timed out after 120ms/,
    'the refusal must name the DECLARED budget, not the global one');
});

test('1020 DECLARES a budget, with its arithmetic, and it is within the ceiling', async () => {
  const mod = (await import('../../nsauditor-ai-ee/plugins/1020_aws_s3_auditor.mjs')).default;
  assert.ok(Number.isFinite(mod.timeoutMs) && mod.timeoutMs > 30000,
    `1020 must declare a budget above the 30s default that starved it; got ${mod.timeoutMs}`);
  assert.ok(mod.timeoutMs <= PLUGIN_TIMEOUT_CEILING_MS,
    'a declared budget above the ceiling is clamped — declare one that fits');
});
