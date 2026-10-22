import './helpers/no_operator_home.mjs';   // FIRST: the MCP call log is computed from homedir() at load
// A scan_cloud TITLE SAYS WHEN THE FINDING HOLDS MORE THAN IT SHOWS.
//
// A cloud finding carries one or more entries in issues[]; the summary titles it with ONE of them
// (pickClause → describeFinding, 160-character budget), and nothing said there were others. A
// CRITICAL whose second entry was a second exposed rule read like the whole finding. With the
// option the MCP server passes, a CRITICAL/HIGH or evidence-gap title of a finding that holds N more
// non-blank entries ends " (+N more via get_findings)", inside the same budget. The entries are not
// all defects — a finding can carry evidence statements beside its defect — so the marker names no
// noun.
//
// FOURTH QUADRANT FIRST: the report title (an identity component), the summary without the option
// (the EE CLI's call), a single-entry finding and a PASS finding are exactly what they were.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { describeFinding, summarizeCloudFindings, moreMarker } from '../utils/cloud_finding_summary.mjs';
import { shapeFinding } from '../utils/report_inputs.mjs';
import { handleScanCloud, _setPluginManager, _setTier, TOOLS } from '../mcp_server.mjs';

const VIA = 'get_findings';
const providerOf = () => 'azure';
const SSH = "NSG 'nsa-exposed-attached-nsg' permits TCP inbound from a public source (0.0.0.0/0 / * / Internet) to restricted port(s) 22 (SSH) — management/data-tier service reachable from the Internet";
const RDP = "NSG 'nsa-exposed-attached-nsg' permits TCP inbound from ::/0 (IPv6 wildcard) to restricted port(s) 3389 (RDP) — operators often lock IPv4 down but miss IPv6";
const twoEntry = { severity: 'critical', resource: 'nsa-exposed-attached-nsg', issues: [SSH, RDP] };
const gapWithAction = {
  severity: 'medium', resource: 'vault-1',
  issues: ['Key Vault networkAcls block absent from API response — cannot positively observe the default action',
    'Restrict the vault firewall to selected networks'],
  details: { evidenceGap: true },
};
const run = (findings, opts) => summarizeCloudFindings([{ id: '1221', result: { findings } }], providerOf, undefined, opts).azure;

// The oracles in the three "(first)" legs are DECLARED strings, never describeFinding's output: a marker moved INSIDE
// describeFinding would change both sides of a computed comparison and pass. The fixtures are short on purpose, so a
// marker would fit inside the 160 budget and could not be hidden by the cut.
// Measured on the mutant that moves the marker into describeFinding: finding_identity, report_since and
// cloud_finding_summary all stay green under it. Leg 1, with its declared literal, is the only thing in the suite that
// sees a title change ride into the finding id and the delta key — do not "simplify" its oracle back to describeFinding.
const shortTwo = { severity: 'critical', resource: 'nsg-1', region: 'eastus', issues: ['SSH 22 open to the Internet', 'RDP 3389 open to ::/0'] };

test('(first) the REPORT title of a multi-entry finding is unchanged — it is part of the finding id and the delta key', () => {
  const shaped = shapeFinding('cloud:azure', shortTwo, '1221');
  assert.equal(shaped.title, 'nsg-1 — SSH 22 open to the Internet');
  const long = shapeFinding('cloud:azure', { ...twoEntry, region: 'eastus' }, '1221');
  assert.doesNotMatch(long.title, /more via/);
});

test('(first) the summary WITHOUT the option — the EE CLI call — titles exactly as describeFinding does', () => {
  const s = run([shortTwo, gapWithAction]);
  assert.equal(s.findings[0].title, 'nsg-1 — SSH 22 open to the Internet');
  assert.equal(s.evidenceGaps[0].title, 'vault-1 — Key Vault networkAcls block absent from API response — cannot positively observe the default action');
  assert.doesNotMatch(JSON.stringify(run([twoEntry, shortTwo, gapWithAction])), /more via/);
});

test('(first) with the option: a single-entry finding, and a PASS finding with a gap and two entries, are unchanged', () => {
  const one = { severity: 'high', resource: 'sa-1', issues: ['Storage account allows public blob access'] };
  const pass = { severity: 'pass', resource: 'sa-2', issues: ['gap clause could not be read', 'substrate evidence: TLS 1.2 PASS'], details: { evidenceGap: true } };
  const s = run([one, pass], { moreVia: VIA });
  assert.equal(s.findings[0].title, 'sa-1 — Storage account allows public blob access');
  assert.equal(s.evidenceGaps[0].title, 'sa-2 — gap clause could not be read');
});

test('with the option: a two-entry CRITICAL ends " (+1 more via get_findings)"; nine entries read +8', () => {
  assert.equal(moreMarker(1, VIA), ' (+1 more via get_findings)');
  assert.ok(run([twoEntry], { moreVia: VIA }).findings[0].title.endsWith(' (+1 more via get_findings)'));
  const nine = { severity: 'critical', resource: 'bucket-1', issues: Array.from({ length: 9 }, (_, i) => `defect number ${i}`) };
  assert.ok(run([nine], { moreVia: VIA }).findings[0].title.endsWith(' (+8 more via get_findings)'));
});

test('blank and null entries are not counted — the marker counts what get_findings will show', () => {
  const f = { severity: 'high', resource: 'r', issues: ['the one defect', '', '   ', null] };
  assert.equal(run([f], { moreVia: VIA }).findings[0].title, describeFinding(f));
  const g = { severity: 'high', resource: 'r', issues: ['first', null, 'second', ' \n '] };
  assert.ok(run([g], { moreVia: VIA }).findings[0].title.endsWith(' (+1 more via get_findings)'));
});

test('the budget holds: at most 161 characters, one line, and the marker is never cut', () => {
  const longRes = { severity: 'critical', resource: 'r'.repeat(150), issues: ['a defect', 'another'] };
  const exact160 = { severity: 'high', resource: 'kv', issues: ['x'.repeat(155), 'second'] };
  for (const f of [twoEntry, longRes, exact160]) {
    const t = run([f], { moreVia: VIA }).findings[0].title;
    assert.ok(t.length <= 161, `${t.length}: ${t}`);
    assert.doesNotMatch(t, /\n/);
    assert.ok(t.endsWith(' (+1 more via get_findings)'), t);
  }
});

test('an evidence-gap title carries the marker; its actionable companion is unchanged', () => {
  const off = run([gapWithAction]).evidenceGaps[0];
  const on = run([gapWithAction], { moreVia: VIA }).evidenceGaps[0];
  assert.ok(on.title.endsWith(' (+1 more via get_findings)'), on.title);
  assert.equal(on.action, off.action);
});

test('the marker names no word the gate reads as a gap or a verdict, and no " — "', () => {
  const m = moreMarker(3, VIA);
  assert.doesNotMatch(m, / — |PARTIAL|unverified|evidence gap|could not be read|incomplete|issue/i);
});

test('scan_cloud passes the option when get_findings is registered: a multi-entry CRITICAL carries the marker', async () => {
  _setTier('enterprise');
  _setPluginManager({
    plugins: [{ id: '1221', name: 'nsg', cloudProvider: 'azure' }],
    runCloud: async () => ({
      host: 'cloud:azure', results: [{ id: '1221', result: { findings: [twoEntry] } }], conclusion: null,
      manifest: [{ id: '1221', name: 'nsg', status: 'ran' }],
      providerStatus: { azure: { available: 1, ran: 1, skipped: 0, errored: 0 } }, auditedProviders: ['azure'],
    }),
  });
  try {
    const out = await handleScanCloud({ providers: ['azure'] });
    assert.ok(out.findingsSummary.azure.findings[0].title.endsWith(moreMarker(1, VIA)));
  } finally { _setTier(); _setPluginManager(null); }
});

test('the get_findings description quotes the marker exactly as the summary emits it, and says what the entries are', () => {
  const d = TOOLS.find((t) => t.name === 'get_findings').description;
  const template = moreMarker(1, VIA).trim().replace('+1', '+N');
  assert.ok(d.includes(template), `description lacks ${template}`);
  assert.match(d, /evidence statements/);
});
