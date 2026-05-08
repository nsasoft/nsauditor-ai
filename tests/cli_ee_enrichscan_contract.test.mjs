// tests/cli_ee_enrichscan_contract.test.mjs
// ─────────────────────────────────────────────────────────────────────────────
// CE-0.1.30.5 — contract test for the enrichScan() call site.
//
// CE forwards per-plugin output to EE via opts on the dynamic-import call
// at cli.mjs:~649. EE-0.3.2.1's cloud-finding harvester depends on
// receiving the `results` array — without it, EE sees only the concluder
// object (single plugin output) and produces false-clean SOC 2 reports
// against AWS accounts. EE 0.3.2 emits a runtime version-skew warning
// when `opts.results` is undefined; this test pins the contract on the
// CE side so a future refactor cannot silently drop the field and
// reintroduce the false-clean class.
//
// This is a string-grep contract test — it reads cli.mjs and asserts the
// call site contains `results,` in the opts object literal. Brittle to
// drastic refactors of the call site, but the failure message is
// actionable: any reorganization of the EE enrichment hook MUST keep the
// results forwarding intact.
// ─────────────────────────────────────────────────────────────────────────────

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const CLI_PATH = resolve(__dirname, '..', 'cli.mjs');

test('CE-0.1.30.5: enrichScan() call forwards `results` to EE opts (EE-0.3.2.1 hard dep)', async () => {
  const cli = await readFile(CLI_PATH, 'utf8');

  // Find the enrichScan call site by anchoring on its line and reading
  // forward until we hit the closing `)` on its own line. Cannot use a
  // simple `\{[^}]*\}` because the opts include a template literal
  // `\${msg}` inside the onWarn arrow — `}` inside `${...}` would match
  // the closing brace prematurely.
  const startIdx = cli.indexOf('enrichScan(conclusion, {');
  assert.notEqual(startIdx, -1, 'expected exactly one enrichScan(conclusion, { … }) call site in cli.mjs');
  // Read forward until the matching `});` (call closes on its own line
  // by the project's prevailing style — see surrounding code).
  const tail = cli.slice(startIdx);
  const endMatch = tail.match(/\}\);/);
  assert.ok(endMatch, 'enrichScan call site appears unterminated — refactor likely changed its shape');
  const optsBlock = tail.slice(0, endMatch.index);

  // Each of these fields MUST be forwarded for EE to function correctly.
  // `results` is the EE-0.3.2.1 dep; the rest are pre-existing.
  const requiredFields = [
    'host',
    'outDir',
    'compliance',
    'complianceScope',
    'results',         // ← CE-0.1.30.5 / EE-0.3.2.1 hard dep
    'onWarn',
  ];

  for (const field of requiredFields) {
    const fieldRegex = new RegExp(`\\b${field}\\b\\s*:?`);
    assert.ok(
      fieldRegex.test(optsBlock),
      `enrichScan() opts MUST forward '${field}' (missing — see CE-0.1.30.5 / EE-0.3.2.1). ` +
      `Without 'results', EE's cloud-finding harvester sees no plugin output and produces false-clean SOC 2 reports against AWS accounts.`
    );
  }
});

test('CE-0.1.30.5: enrichScan() opts has the EE-0.3.2.1 rationale comment nearby', async () => {
  // Ensures a future contributor reading the code understands WHY
  // results is forwarded — without context, the field looks redundant
  // (it's already in pm.run() return), and someone refactoring the
  // import block could remove it.
  const cli = await readFile(CLI_PATH, 'utf8');
  assert.match(
    cli,
    /CE-0\.1\.30\.5/,
    'cli.mjs should reference CE-0.1.30.5 in a comment near the enrichScan call (rationale for results forwarding)'
  );
  assert.match(
    cli,
    /EE-0\.3\.2\.1/,
    'cli.mjs should reference EE-0.3.2.1 (the EE-side feature this CE change unblocks)'
  );
});
