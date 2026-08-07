// tests/compliance_matrix_tool.test.mjs
//
// ── WHY THIS TOOL EXISTS ─────────────────────────────────────────────────────────
// Gate-3 prompt 5 (2026-08-05) FAILED: asked for "the exact SOC 2 coverage matrix", the
// assistant BUILT one from the live plugin inventory and published it as a styled HTML
// artifact — 5 Full / 18 Partial / 38 None = 61, against a shipped 10 / 4 / 37 = 51.
// The prompt's own note named the cause: "No MCP tool returns the coverage matrix."
//
// The correction that matters is the one the battery recorded against itself: prompt 6, in a
// fresh chat with the SAME absent surface, stated 10 / 4 / 37 = 51 correctly and unprompted.
// So the knowledge was there and what differed was a methodological CHOICE — asked for an
// exact matrix, it elected to DERIVE rather than RECALL. This tool does not teach the
// assistant the answer; it removes the OPTION to synthesise one.
//
// ── THE TWO SHIP CONDITIONS ──────────────────────────────────────────────────────
//  1. DERIVED AT CALL TIME from the shipped framework JSON, never a constant. A transcribed
//     matrix in a tool response rots exactly like every other transcribed matrix this repo
//     has caught — and it would rot INSIDE the instrument built to stop the rot.
//  2. FAIL CLOSED when EE is absent. An empty matrix is what an assistant synthesises over.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { TOOLS, toolHandlers, handleComplianceMatrix, FRAMEWORK_STEMS as STEMS } from '../mcp_server.mjs';

// ⚠️ `STEMS` USED TO BE A LITERAL HERE — a fourth independent transcription of a set EE owns,
// sitting in the suite whose whole subject is transcription rot. It is now the server's own
// exported constant, so this file exercises the shipped set rather than a copy that could agree
// with nothing. The set's AUTHORITY — two-way equality with EE's `utils/framework_ids.mjs` and
// with the on-disk `data/compliance/*.json` census — lives in tests/framework_stem_parity.test.mjs.

test('the tool is registered and dispatchable', () => {
  const t = TOOLS.find((x) => x.name === 'compliance_matrix');
  assert.ok(t, 'compliance_matrix missing from TOOLS');
  assert.equal(typeof toolHandlers.compliance_matrix, 'function', 'not wired into toolHandlers');
  // The enum-vs-STEMS deepEqual that stood here is now UNFALSIFIABLE: the enum is built as
  // `[...FRAMEWORK_STEMS, 'all']`, so comparing it back to FRAMEWORK_STEMS can never fail while
  // reading exactly like a check that could. What is still worth asserting is the one part the
  // derivation does NOT give for free — that "all" is offered alongside the stems. The
  // discriminating comparison (enum vs the shipped JSON census) is in framework_stem_parity.
  assert.ok(t.inputSchema.properties.framework.enum.includes('all'),
    'the "all" shorthand vanished from the enum — the cross-framework view becomes unaskable');
});

test('every one of the seven frameworks answers, and each triple SUMS to its own universe', async () => {
  const all = await handleComplianceMatrix({ framework: 'all' });
  assert.deepEqual(Object.keys(all.frameworks).sort(), STEMS.slice().sort());
  for (const stem of STEMS) {
    const m = all.frameworks[stem];
    assert.equal(m.covered + m.partial + m.outOfScope, m.total,
      `${stem}: the published triple does not sum to its own total`);
    assert.ok(m.total > 0, `${stem}: an empty matrix is what an assistant synthesises over`);
  }
});

test('outOfScope is the FLATTENED id count, not the GROUP count — the documented miscopy trap', async () => {
  // soc2's `outOfScope` is 11 GROUPS of {ids, title, reason} flattening to 37 ids. Publishing
  // the group count yields 10/4/11 = 25 and reads like a plausible matrix. This is the exact
  // trap Gate-3's FAIL 5 reproduced, and it is the reason the assertion below is per-framework
  // rather than spot-checked: gdpr's group count (2) EQUALS its id count (2), so a gdpr-only
  // smoke test of a broken flatten reads GREEN.
  const soc2 = await handleComplianceMatrix({ framework: 'soc2' });
  assert.equal(soc2.covered, 10);
  assert.equal(soc2.partial, 4);
  assert.equal(soc2.outOfScope, 37, 'the OOS groups were published instead of their flattened ids');
  assert.equal(soc2.total, 51);
});

test('the numbers are DERIVED from the shipped JSON at call time, not transcribed', async () => {
  // The mechanism check, not a value check: re-derive independently from the same file the
  // tool reads and require agreement for all seven. A constant in the handler passes a value
  // assertion and fails this one the moment the data moves.
  const fs = await import('node:fs');
  const path = await import('node:path');
  const { createRequire } = await import('node:module');
  const req = createRequire(import.meta.url);
  const eeRoot = path.dirname(req.resolve('@nsasoft/nsauditor-ai-ee/package.json'));

  const all = await handleComplianceMatrix({ framework: 'all' });
  for (const stem of STEMS) {
    const raw = JSON.parse(fs.readFileSync(path.join(eeRoot, 'data', 'compliance', `${stem}.json`), 'utf8'));
    const cs = raw.coverageSummary;
    const oos = cs.outOfScope.reduce((n, g) => n + g.ids.length, 0);
    assert.equal(all.frameworks[stem].covered, cs.covered.length, `${stem} covered drifted`);
    assert.equal(all.frameworks[stem].partial, cs.partial.length, `${stem} partial drifted`);
    assert.equal(all.frameworks[stem].outOfScope, oos, `${stem} OOS drifted`);
  }
});

test('a single-framework response carries the control IDS, so a reader need not re-derive them', async () => {
  const m = await handleComplianceMatrix({ framework: 'soc2' });
  assert.ok(Array.isArray(m.coveredIds) && m.coveredIds.length === 10);
  assert.ok(m.coveredIds.includes('CC6.1'), 'covered ids must be the real control ids');
  assert.ok(Array.isArray(m.outOfScopeGroups) && m.outOfScopeGroups.length === 11,
    'the OOS GROUPS carry the per-group reason an assessor asks for — keep them alongside the count');
  assert.ok(m.outOfScopeGroups.every((g) => typeof g.reason === 'string' && g.reason.length > 0),
    'an out-of-scope classification without a reason is the thing auditors reject');
});

test('the "all" response stays small enough to be quotable', async () => {
  // Measured: emitting every group `reason` for all seven is ~52 KB, against a ~10 KB
  // per-response norm elsewhere in this server. A response an assistant truncates is a
  // response an assistant partially synthesises — the defect this tool exists to remove.
  const bytes = Buffer.byteLength(JSON.stringify(await handleComplianceMatrix({ framework: 'all' })));
  assert.ok(bytes < 12000, `the all-frameworks response is ${bytes} B — too large to quote intact`);
});

test('FAILS CLOSED when EE is not installed — never an empty matrix', async () => {
  // The precedent in plugin_discovery.mjs swallows the resolve failure into `catch {}` so CE
  // can run standalone. Copying that here reproduces FAIL 5 exactly: a tool that answers
  // "no matrix" to "what is the matrix" is a tool an assistant routes around.
  const err = await handleComplianceMatrix({ framework: 'soc2', _resolveEE: () => { throw new Error('MODULE_NOT_FOUND'); } })
    .then(() => null, (e) => e);
  assert.ok(err, 'the handler resolved instead of throwing when EE was unresolvable');
  assert.match(err.message, /Enterprise/i);
  assert.match(err.message, /not installed|not resolvable/i);
});

test('an unknown framework is rejected by name, not silently defaulted', async () => {
  const err = await handleComplianceMatrix({ framework: 'sox' }).then(() => null, (e) => e);
  assert.ok(err, 'an unknown framework was accepted');
  assert.match(err.message, /sox/);
});

// ── ADDED AT REVIEW — the two legs the first version could not express ────────────
//
// 'the numbers are DERIVED … not transcribed' re-reads the SAME file the handler reads, so a
// hard-coded constant matching today's shipped values passes it. That is a drift detector, not
// a derivation proof. The discriminating leg points the handler at a DIFFERENT root and
// requires it to report THAT root's numbers.
test('a constant cannot pass: the handler reports the numbers of the root it was given', async () => {
  const fs = await import('node:fs');
  const os = await import('node:os');
  const path = await import('node:path');
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ee-fixture-'));
  fs.mkdirSync(path.join(root, 'data', 'compliance'), { recursive: true });
  // Deliberately NOT the shipped triple — 2 / 1 / 3 = 6.
  fs.writeFileSync(path.join(root, 'data', 'compliance', 'soc2.json'), JSON.stringify({
    framework: 'soc2', frameworkLabel: 'FIXTURE', version: '0', controls: {},
    coverageSummary: {
      covered: ['X1', 'X2'], partial: ['Y1'],
      outOfScope: [{ ids: ['Z1', 'Z2'], title: 't', reason: 'r' }, { ids: ['Z3'], title: 't2', reason: 'r2' }],
    },
  }));
  const m = await handleComplianceMatrix({ framework: 'soc2', _resolveEE: () => root });
  assert.equal(m.covered, 2);
  assert.equal(m.partial, 1);
  assert.equal(m.outOfScope, 3, 'the OOS ids of the GIVEN root must be flattened, not the shipped ones');
  assert.equal(m.total, 6, 'a constant matching the shipped 10/4/37=51 would fail here');
});

test('FAILS CLOSED on a framework file that parses but carries no usable coverageSummary', async () => {
  // Every default in the reader degrades to [], so this used to publish 0 / 0 / 0 with the same
  // authority as a real matrix — over a framework whose file was simply unreadable. A tool built
  // to stop an assistant synthesising a matrix must not hand it a zero to synthesise around.
  const fs = await import('node:fs');
  const os = await import('node:os');
  const path = await import('node:path');
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ee-empty-'));
  fs.mkdirSync(path.join(root, 'data', 'compliance'), { recursive: true });
  fs.writeFileSync(path.join(root, 'data', 'compliance', 'soc2.json'), JSON.stringify({ framework: 'soc2' }));
  const err = await handleComplianceMatrix({ framework: 'soc2', _resolveEE: () => root }).then(() => null, (e) => e);
  assert.ok(err, 'the handler returned a 0/0/0 matrix instead of refusing');
  assert.match(err.message, /NOT a framework with zero coverage/);
});
