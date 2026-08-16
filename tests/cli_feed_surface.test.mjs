/*
 * NSAuditor AI — Community Edition
 */
/**
 * `feed bundle` / `feed import` — THE FLAG SURFACE, PARSED BY THE ONE PARSER.
 *
 * ── WHY THIS EXISTS, AND IT IS THE SIBLING'S SCAR ───────────────────────────────────────────
 * The approval surface shipped with its flags read from `process.argv` inside the subcommand
 * rather than parsed alongside every other flag, and the subcommand threw `ReferenceError` on its
 * first real invocation. Its test file records the lesson in one line: **a second parser is a
 * second set of edge cases**, and this product has already paid for that drift. So `feed`'s flags
 * are parsed in `parseArgs` with everything else, and this file pins the flag surface so a future
 * edit cannot quietly introduce parser number two.
 *
 * ⚠️ AND WRITING THAT SENTENCE FOUND A DEFECT IN THE SENTENCE IT WAS COPIED FROM. The sibling's
 * comment claimed the parser owns the `--flag value` / `--flag=value` / boolean shapes. Measured:
 * the `=` shape is NOT supported anywhere in this CLI — `get()` is an exact-token
 * `indexOf('--' + name)`. The comment is corrected in place at its site, and the limit is PINNED
 * below rather than fixed, because `=` support touches every flag in the CLI.
 *
 * ── WHAT `feed` IS ──────────────────────────────────────────────────────────────────────────
 * The air-gap hand-carry pipeline (EE F1): `feed bundle` merges the NVD feed files an operator
 * downloaded on a CONNECTED host into one portable `.json.gz`; `feed import` consumes it on the
 * ISOLATED host through EE's existing, air-gap-hardened `importFeed()`. CE contributes a flag
 * surface and an exit code and decides nothing — the same THIN-FORWARD discipline as `compliance`.
 *
 * ⚠️ NOTHING HERE CLAIMS THE CAPABILITY WORKS. Publishing a surface is not proving it. The
 * `feed-import-cli`, `offline-install-tarball`, `install-script` and `airgap-deployment` claims
 * stay withdrawn until the trio publishes AND the NIC-down gate passes on the BUILT artifacts.
 * If you are reading this while editing marketing copy, the answer is still "not yet".
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { spawnSync } from 'node:child_process';

import { parseArgs } from '../cli.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const parse = async (...argv) => (await parseArgs(['node', 'cli.mjs', ...argv]));

describe('the feed commands\' flag surface', () => {
  test('`feed bundle` flags parse in the `--flag value` shape', async () => {
    const a = await parse('feed', 'bundle', '--from', '/tmp/nvd', '--out', '/tmp/bundle.json.gz');
    assert.equal(a.cmd, 'feed');
    assert.equal(a.feedArgs.from, '/tmp/nvd');
    assert.equal(a.feedArgs.out, '/tmp/bundle.json.gz');
  });

  test('PINNED LIMIT: `--flag=value` is REFUSED LOUDLY, CLI-wide', async () => {
    /**
     * ⚠️ THIS TEST ASSERTS A LIMIT, NOT A FEATURE, AND IT WAS WRITTEN AS A FEATURE FIRST.
     * The approval surface's comment claimed the parser owns the `--flag=value` shape. Measured:
     * it does not and never has — `get()` is an exact-token `indexOf('--' + name)`.
     *
     * FULL `=` SUPPORT IS ITS OWN LANE (it touches every flag and every test that depends on
     * current parsing). But the SILENT half could not wait for that lane: `--plugins=port_scanner`
     * fell through to the `all` default and ran EVERY plugin on whatever the operator was
     * scanning — a wrong scan they cannot see. `--host=1.2.3.4` refused by accident, because a
     * missing host is checked; nothing checked the others.
     *
     * So the parser now REFUSES the shape by name. A loud refusal is strictly better than silent
     * divergence for every operator using `=` today, and it leaves the future support lane a clean
     * starting state. Precondition measured before building: ZERO documented `=` usages in either
     * repo — it never worked, so nothing can depend on it.
     *
     * ⚠️ DELETE THIS TEST WHEN `=` SUPPORT LANDS, and restore the both-shapes assertion it
     * replaced. A refusal test outliving the refusal is a guard that forbids a shipped feature.
     *
     * Driven by SPAWNING the published CLI, not by calling parseArgs in-process: the refusal is a
     * `process.exit(2)`, and this repo's own record is that reachability defects are found by
     * driving the entry point rather than by reading it.
     */
    const r = spawnSync(process.execPath, [path.join(ROOT, 'cli.mjs'), 'feed', 'bundle',
      '--from=/tmp/nvd', '--out=/tmp/b.json.gz'], { encoding: 'utf8', timeout: 60_000 });
    assert.equal(r.status, 2,
      `the \`=\` shape must be refused with exit 2, got ${r.status}. stderr: ${r.stderr?.slice(0, 300)}`);
    assert.match(`${r.stderr}`, /--from=/,
      'the refusal must NAME the offending token, or the operator cannot find it in a long command');
    assert.match(`${r.stderr}`, /--from \/tmp\/nvd|space|spaced/i,
      'the refusal must show the SPACED form that works — a refusal that does not say what to do '
      + 'instead is a worse experience than the silent bug it replaced');
  });

  test('the spaced form is UNAFFECTED by the refusal (both directions)', async () => {
    // The other half. A refusal that also broke the working shape would be a strictly worse
    // outcome than the silent divergence it replaced.
    const a = await parse('feed', 'bundle', '--from', '/tmp/nvd', '--out', '/tmp/b.json.gz');
    assert.equal(a.feedArgs.from, '/tmp/nvd');
    assert.equal(a.feedArgs.out, '/tmp/b.json.gz');
  });

  test('`feed import` flags parse, including the boolean --append', async () => {
    const a = await parse('feed', 'import', '--file', '/tmp/b.json.gz',
      '--cache-dir', '/tmp/store', '--append');
    assert.equal(a.feedArgs.file, '/tmp/b.json.gz');
    assert.equal(a.feedArgs.cacheDir, '/tmp/store');
    assert.equal(a.feedArgs.append, true);
  });

  test('--append is FALSE when absent — an accumulating default would silently grow a store', async () => {
    // Direction matters: defaulting to append means a re-import never REPLACES, so a store an
    // operator believes they refreshed keeps every stale record it ever held.
    const a = await parse('feed', 'import', '--file', '/tmp/b.json.gz');
    assert.notEqual(a.feedArgs.append, true);
  });

  test('the CLI ROUTES `feed` — the subcommand is reachable, not merely parsed', () => {
    // A flag surface that parses into nothing is the `importFeed()` situation one level up:
    // hardened code with zero callers. Assert the dispatcher actually has a `feed` branch that
    // forwards to EE, in the same shape as the `compliance` precedent.
    const src = fs.readFileSync(path.join(ROOT, 'cli.mjs'), 'utf8');
    assert.match(src, /cmd === 'feed'/,
      'cli.mjs has no `feed` command branch — the flags parse and route nowhere');
    const branch = src.slice(src.indexOf("cmd === 'feed'"));
    assert.match(branch.slice(0, 4000), /@nsasoft\/nsauditor-ai-ee/,
      'the feed branch does not forward to the Enterprise package');
    assert.match(branch.slice(0, 4000), /bundleFeedCommand|importFeedCommand/,
      'the feed branch does not call EE\'s feed commands');
  });

  test('`feed` without the Enterprise package exits 2 with a NAMED reason', () => {
    // The precedent's contract: a missing EE is an operator-actionable message, never a stack
    // trace and never a silent no-op.
    const src = fs.readFileSync(path.join(ROOT, 'cli.mjs'), 'utf8');
    const branch = src.slice(src.indexOf("cmd === 'feed'"), src.indexOf("cmd === 'feed'") + 4000);
    assert.match(branch, /requires the Enterprise package/,
      'a missing EE must say so by name, as `compliance` does');
    assert.match(branch, /process\.exit\(2\)/,
      'exit 2 is this CLI\'s "could not do what you asked" code');
  });

  test('the usage text documents both subcommands', () => {
    const src = fs.readFileSync(path.join(ROOT, 'cli.mjs'), 'utf8');
    assert.match(src, /nsauditor-ai feed bundle/, 'usage does not document `feed bundle`');
    assert.match(src, /nsauditor-ai feed import/, 'usage does not document `feed import`');
  });
});
