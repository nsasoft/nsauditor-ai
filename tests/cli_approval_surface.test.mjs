/*
 * NSAuditor AI — Community Edition
 * CLI flag surface for the EE approval commands (EE 0.35.0).
 */
/**
 * WHAT CE OWNS HERE IS THE FLAG SURFACE, AND NOTHING ELSE.
 *
 * `compliance suppress|review|renew|keygen` are THIN FORWARDS, the same discipline
 * `compliance attest` established: EE owns validation, defaults, the signing decision and every
 * refusal; CE contributes flags and an exit code and decides nothing. So the thing worth testing
 * on this side is the parse — because that is the only place a CE bug can exist.
 *
 * ⚠️ PARSED IN `parseArgs` WITH EVERY OTHER FLAG, not read from `process.argv` inside the
 * subcommand. The first cut did the latter and broke immediately: `get()` is local to the parser,
 * so the subcommand threw `ReferenceError` on its first real invocation. Driving the published CLI
 * caught it in one run — a second parser is a second set of edge cases (`--flag value` vs
 * `--flag=value` vs bare boolean), which is the drift shape this product has paid for elsewhere.
 *
 * ⚠️ NOTHING HERE CLAIMS THE CAPABILITY WORKS. Publishing a surface is not proving it: per D6 the
 * three-part gate runs against the published registry bytes and the hedges flip at N+1.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import { parseArgs } from '../cli.mjs';

const parse = async (...argv) => (await parseArgs(['node', 'cli.mjs', ...argv])).approvalArgs;

describe('the approval commands\' flag surface', () => {
  test('suppress flags parse in the `--flag value` shape', async () => {
    const a = await parse('compliance', 'suppress',
      '--suppressions', '/tmp/s.json',
      '--source', 'auth_agent',
      '--title-pattern', 'SSH password',
      '--status', 'accepted_risk',
      '--rationale', 'WAF compensating control',
      '--approver', 'Ann Approver',
      '--attestation-level', 'approver');
    assert.equal(a.suppressions, '/tmp/s.json');
    assert.equal(a.source, 'auth_agent');
    assert.equal(a.titlePattern, 'SSH password');
    assert.equal(a.status, 'accepted_risk');
    assert.equal(a.rationale, 'WAF compensating control');
    assert.equal(a.approver, 'Ann Approver');
    assert.equal(a.attestationLevel, 'approver');
  });

  test('`--flag=value` is NOT supported — pinned as the CLI\'s real contract, not as a wish', () => {
    // ⚠️ THIS TEST ASSERTED THE OPPOSITE UNTIL IT WAS RUN. I wrote it from an assumed convention
    // ("one parser must handle both shapes") rather than from the parser. Measured: `get()` is
    // `indexOf('--name')` then take the NEXT argv element, so `--flag=value` is unsupported for
    // EVERY flag this CLI has ever had — `--host=10.0.0.1` yields `undefined` today, and has
    // always done. The approval flags inherit that, uniformly.
    //
    // Pinned rather than fixed, deliberately: widening `get()` would change the parse of every
    // existing flag, which is a CE arg-handling change with its own blast radius and is not this
    // lane's scope. Recorded on the board as an observation instead. The value of pinning it is
    // that the limitation is now a KNOWN property with a test naming it, rather than a surprise
    // waiting for the first operator who types the other shape.
    // ⚠️ UPDATED 2026-08-15: the limitation is no longer merely PINNED, it is REFUSED. Silence
    // was the dangerous half — `--plugins=port_scanner` fell through to the `all` default and ran
    // every plugin on whatever was being scanned. Full `=` support is still its own lane; what
    // changed is that the unsupported shape now fails loudly instead of diverging quietly.
    return assert.rejects(
      () => parse('compliance', 'suppress', '--suppressions=/tmp/s.json'),
      (e) => e?.code === 'EFLAGSHAPE' && /--suppressions \/tmp\/s\.json/.test(e.message),
      'the `=` shape must be REFUSED by name, showing the spaced form that works. If it now '
      + 'parses instead, `=` support landed — delete this and restore a both-shapes assertion');
  });

  test('a valueless flag becomes NULL, never the boolean `true`', async () => {
    // The shape that would otherwise reach EE as `status: true` and produce a validation error
    // about a type the operator never typed. Absent and present-but-empty must look the same.
    const a = await parse('compliance', 'suppress', '--suppressions');
    assert.equal(a.suppressions, null);
    assert.equal(a.source, null);
    assert.equal(a.rationale, null);
  });

  test('`--force` is the one BOOLEAN, and it is off unless asked for', async () => {
    assert.equal((await parse('compliance', 'keygen', '--key', '/tmp/k.pem')).force, false);
    assert.equal((await parse('compliance', 'keygen', '--key', '/tmp/k.pem', '--force')).force, true);
  });

  test('keygen identity flags reach the registry snippet', async () => {
    const a = await parse('compliance', 'keygen', '--key', '/tmp/k.pem',
      '--approver', 'Ann Approver', '--email', 'ann@example.test', '--role', 'CISO', '--team', 'Security');
    assert.equal(a.keyPath, '/tmp/k.pem');
    assert.equal(a.approver, 'Ann Approver');
    assert.equal(a.email, 'ann@example.test');
    assert.equal(a.role, 'CISO');
    assert.equal(a.team, 'Security');
  });

  test('renew takes the suppression id, and `--title_pattern` is accepted as an alias', async () => {
    assert.equal((await parse('compliance', 'renew', '--id', 'supp-abc')).suppressionId, 'supp-abc');
    assert.equal((await parse('compliance', 'suppress', '--title_pattern', 'x')).titlePattern, 'x');
  });

  test('the approval flags do not disturb a plain scan', async () => {
    // A regression net: these flags were added to the shared parser, so the scan path must be
    // unchanged for every operator who never types them.
    const args = await parseArgs(['node', 'cli.mjs', 'scan', '--host', '10.0.0.1']);
    assert.equal(args.cmd, 'scan');
    assert.equal(args.host, '10.0.0.1');
    assert.equal(args.approvalArgs.suppressions, null);
    assert.equal(args.approvalArgs.force, false);
  });
});
