import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  _setTier,
  _requireProCapability,
  _requireEnterpriseCapability,
  handleComplianceMatrix,
} from '../mcp_server.mjs';

// B97 and B98 (2026-10-27, from the review of the agent-availability proposal): a tier denial tells the caller which
// tools it CAN use instead, and that line was one constant — "CE tools available: scan_host, list_plugins,
// compliance_matrix" — whatever the caller held and whatever was installed.
//   · B97: a Pro caller denied an Enterprise tool was shown only the Community list, so the agent never learned it holds
//     probe_service and get_vulnerabilities.
//   · B98: compliance_matrix was listed as available on a Community-only install, where it throws — and its error told
//     the user to `npm i -g @nsasoft/nsauditor-ai-ee`, a restricted package a non-buyer cannot install.
// The line is now DERIVED from the same two gates the dispatcher applies and from whether Enterprise resolves; the
// compliance_matrix error names the licence the package needs instead of an install a non-buyer cannot run.
// FOURTH QUADRANT FIRST: each tier still lists its own tools, and compliance_matrix still lists where Enterprise resolves.

const RESOLVES = () => '/fake/ee-root';
const ABSENT = () => { throw Object.assign(new Error("Cannot find module '@nsasoft/nsauditor-ai-ee/package.json'"), { code: 'MODULE_NOT_FOUND' }); };
const lineOf = (denied) => (denied.content[0].text.match(/\*\*Tools available to you now:\*\* (.+)$/m) ?? [])[1] ?? null;
const listed = (denied) => (lineOf(denied) ?? '').split(', ').filter(Boolean);

test('(first) a Community caller denied a Pro tool is shown the Community tools, compliance_matrix among them where Enterprise resolves', () => {
  _setTier('ce');
  try {
    const denied = _requireProCapability('probe_service', { resolveEE: RESOLVES });
    assert.ok(denied?.isError);
    assert.deepEqual(listed(denied), ['scan_host', 'list_plugins', 'compliance_matrix']);
  } finally { _setTier(); }
});

test('B97: a Pro caller denied an Enterprise tool is shown the Pro tools it holds', () => {
  _setTier('pro');
  try {
    const denied = _requireEnterpriseCapability('scan_cloud', { resolveEE: RESOLVES });
    assert.ok(denied?.isError);
    assert.match(denied.content[0].text, /requires an Enterprise license/);
    assert.deepEqual(listed(denied), ['scan_host', 'list_plugins', 'probe_service', 'get_vulnerabilities', 'compliance_matrix']);
  } finally { _setTier(); }
});

test('B97: a Community caller denied an Enterprise tool is NOT shown the Pro tools it does not hold', () => {
  _setTier('ce');
  try {
    const denied = _requireEnterpriseCapability('scan_cloud', { resolveEE: RESOLVES });
    assert.deepEqual(listed(denied), ['scan_host', 'list_plugins', 'compliance_matrix'], 'the line is absent, or lists a tool this caller does not hold');
  } finally { _setTier(); }
});

test('B98: with Enterprise not installed, neither denial lists compliance_matrix as available', () => {
  for (const [tier, deny] of [['ce', () => _requireProCapability('probe_service', { resolveEE: ABSENT })],
    ['pro', () => _requireEnterpriseCapability('scan_cloud', { resolveEE: ABSENT })]]) {
    _setTier(tier);
    try {
      const denied = deny();
      assert.ok(lineOf(denied), `${tier}: the denial carries no tools line`);
      assert.ok(!listed(denied).includes('compliance_matrix'), `${tier}: ${lineOf(denied)}`);
    } finally { _setTier(); }
  }
});

test('B98: compliance_matrix with Enterprise not installed names the licence, never an install a non-buyer cannot run', async () => {
  await assert.rejects(handleComplianceMatrix({ _resolveEE: ABSENT }), (err) => {
    assert.match(err.message, /Enterprise plugin pack/);
    assert.match(err.message, /Pro or Enterprise licen[cs]e/);
    assert.match(err.message, /https:\/\/www\.nsauditor\.com\/ai\/pricing\//);
    assert.doesNotMatch(err.message, /npm i(nstall)? -g @nsasoft\/nsauditor-ai-ee/, 'an install command a non-buyer cannot run');
    assert.match(err.message, /Do NOT reconstruct the matrix/, 'the anti-fabrication instruction was dropped');
    return true;
  });
});
