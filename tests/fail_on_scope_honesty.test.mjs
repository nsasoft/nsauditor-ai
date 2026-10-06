// `--fail-on` SAYS WHICH FLAGS IT READS (1.2.0 build 3 — the architect seat's review of the scan_host scope fold).
//
// MEASURED on build 2's bytes: `--fail-on` is computed by `maxSeverityInConclusion` in cli.mjs, and that function reads
// FOUR service flags — anonymous FTP login and DNS zone transfer (critical), weak SSH algorithms and dangerous HTTP
// methods (medium) — plus a baseline of info for any concluded scan. It does not read the SNMP default community, weak TLS
// protocols / ciphers or the MCP server checks (all three of which the Markdown report counts), nor Enterprise's CVE rows
// or agent findings. The help text said "Exit non-zero if any finding ≥ severity", and the router's real conclusion gives
// exit 0 for every threshold but `info` and exit 1 for `info` — so a pipeline gated on `--fail-on high` passes a host
// that exposes SNMP `public`, and one gated on `info` fails every host it can reach.
//
// Build 3 shipped honest TEXT (operator ruling) and boarded the widening for 1.2.1. 1.2.1 (s1) WIDENS IT: the gate reads
// the shared service-flag table (utils/service_flags.mjs), the same findings the Markdown, SARIF and CSV reports count, so
// the PINNED legs that held the blind spot were inverted (not deleted) and the README and help were re-stated in the same
// commit. The skill's CI section is owed at release prep.
//
// FOURTH QUADRANT FIRST: the flags the gate DOES read still gate.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { maxSeverityInConclusion } from '../cli.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const CLI = fs.readFileSync(path.join(ROOT, 'cli.mjs'), 'utf8');
const README = fs.readFileSync(path.join(ROOT, 'README.md'), 'utf8');

const RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
const maxSev = () => maxSeverityInConclusion;
const gate = (svc) => maxSev()({ result: { services: [{ port: 1, protocol: 'tcp', status: 'open', ...svc }] } });
const failOnRow = () => {
  const row = README.split('\n').find((l) => l.startsWith('| `--fail-on <sev>`'));
  assert.ok(row, 'the README has its --fail-on row');
  return row;
};

// ── FOURTH QUADRANT ──────────────────────────────────────────────────────────────────────────────
test('(q) the gated flags still gate: anonymous FTP / zone transfer are critical, weak SSH / dangerous methods medium', () => {
  assert.equal(gate({ anonymousLogin: true }), RANK.critical);
  assert.equal(gate({ axfrAllowed: true }), RANK.critical);
  assert.equal(gate({ weakAlgorithms: ['ssh-dss'] }), RANK.medium);
  assert.equal(gate({ dangerousMethods: ['PUT'] }), RANK.medium);
});

// ── (s1): THE BLIND SPOT IS CLOSED — inverted from the build-3 PINNED leg ───────────────────────────────────────
test('(s1) the SNMP community, weak TLS, MCP, null-session and certificate flags gate at the table\'s grade', () => {
  for (const [svc, rank] of [[{ community: 'public' }, RANK.high], [{ weakProtocols: ['TLSv1.0'] }, RANK.medium],
    [{ weakCiphers: ['RC4-SHA'] }, RANK.medium], [{ nullSessionAllowed: true }, RANK.high],
    [{ certSelfSigned: true }, RANK.medium], [{ certExpiry: '2001-01-01T00:00:00Z' }, RANK.high],
    // The five flags plugin 070's adapter really spreads onto its service record (plugins/mcp_scanner.mjs).
    [{ mcpAnonymousAccess: true, mcpAnonymousToolList: ['exec'], mcpCleartextTransport: true,
      mcpDeprecatedProtocol: '2024-11-05', mcpInspectorExposed: true }, RANK.critical]]) {
    assert.equal(gate(svc), rank, JSON.stringify(svc));
  }
  assert.equal(gate({ community: 'custom', communityCustom: true }), RANK.info, 'a custom community is not a finding');
});

test('PINNED: any concluded scan is at least info, so --fail-on info fails every host it reaches', () => {
  assert.equal(gate({}), RANK.info);
  assert.equal(maxSev()({ result: { services: [] } }), RANK.info);
});

// ── THE DEFECT ───────────────────────────────────────────────────────────────────────────────────
test('the help text no longer says "any finding"', () => {
  const at = CLI.indexOf('  --fail-on <severity>');
  assert.ok(at >= 0, 'the help block has its --fail-on entry');
  const entry = CLI.slice(at, CLI.indexOf('\n  --', at + 5));
  assert.doesNotMatch(entry, /any finding/);
  assert.match(entry, /Exit 1 /);
  assert.match(entry, /not a clean host/);
});

test('the README row names what --fail-on reads — the reports\' findings — and what it does not', () => {
  const r = failOnRow();
  for (const re of [/anonymous FTP/, /zone transfer/, /critical/, /SSH/, /dangerous HTTP methods/, /medium/,
    /`--fail-on info` fails every/, /SNMP/, /TLS/, /MCP/, /null session/, /self-signed/, /expired certificate/,
    /\(040\)/, /\(050\)/, /\(060\)/, /CVE/, /agent/, /exit 0 is not a clean host/, /exit 2/]) {
    assert.match(r, re);
  }
  assert.match(r, /same findings the Markdown, SARIF and CSV reports count/);
  assert.match(r, /may fail on findings that were always there/, 'the behaviour change is said where the flag is documented');
});

// (s1): a default scan CAN trip --fail-on high now (SNMP `public` alone grades high), so "never exit 1" is gone; what stays
// true is that the three opt-in checks are named with their switches.
test('the README row and --help name each opt-in check\'s switch, and no longer promise a default scan never trips high', () => {
  const r = failOnRow();
  for (const sw of [/FTP_CHECK_ANON/, /DNS_CHECK_AXFR/, /SMB_NULL_SESSION/]) assert.match(r, sw);
  assert.doesNotMatch(r, /never exit 1/);
  const at = CLI.indexOf('  --fail-on <severity>');
  const help = CLI.slice(at, CLI.indexOf('\n  --', at + 5));
  for (const sw of [/FTP_CHECK_ANON/, /DNS_CHECK_AXFR/, /SMB_NULL_SESSION/]) assert.match(help, sw);
});

// 1.2.1 lane 3 (a4): dangerous HTTP methods REACH the conclusion now (the HTTP probe's adapter), so --fail-on gates on them —
// only where an Allow header was read. Not tested (methodsTested false, null) never trips the gate and is said as such.
test('(a4) dangerous methods gate at medium where an Allow header was read; NOT TESTED never trips the gate', () => {
  assert.equal(gate({ methodsTested: true, dangerousMethods: ['PUT'] }), RANK.medium);
  assert.ok(gate({ methodsTested: false, dangerousMethods: null }) < RANK.medium, 'not tested is not a finding');
  const r = failOnRow();
  assert.doesNotMatch(r, /no scan's conclusion carries/, 'they arrive now');
  assert.match(r, /dangerous HTTP methods[^.]*Allow header/);
  assert.match(r, /not tested/);
  const at = CLI.indexOf('  --fail-on <severity>');
  const help = CLI.slice(at, CLI.indexOf('\n  --', at + 5));
  assert.doesNotMatch(help, /never reach the conclusion/);
  assert.match(help.replace(/\s+/g, ' '), /Dangerous HTTP methods \(medium\) only where an Allow header was read/);
});

test('the README CI example does not promise a high+ gate', () => {
  assert.doesNotMatch(README, /fail on high\+ findings/);
});
