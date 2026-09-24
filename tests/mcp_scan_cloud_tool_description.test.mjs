import { test } from 'node:test';
import assert from 'node:assert/strict';
import { TOOLS } from '../mcp_server.mjs';
import { parseArgs, scanTargetRefusal } from '../cli.mjs';

// The scan_cloud tool description is a ROUTING surface: a Desktop agent decides
// whether a user request maps to this tool by reading it. The 0.19.2 Desktop MCP
// validation (prompt #4) proved a generic description loses service-named asks —
// "audit my CodePipelines for segregation of duties" never invoked scan_cloud and
// the agent offered a manual bash workaround instead. These tests pin an explicit
// service-coverage enumeration into the description so service-named audit asks
// route to scan_cloud, and pin the pre-existing contract clauses so enrichment
// never regresses them.

function scanCloudTool() {
  const t = (Array.isArray(TOOLS) ? TOOLS : []).find((x) => x && x.name === 'scan_cloud');
  assert.ok(t, 'scan_cloud tool definition exists in TOOLS');
  return t;
}

test('TOOLS is exported and contains the full tool set', () => {
  // ⚠️ THIS WAS A SUBSET CHECK WEARING A COMPLETENESS TITLE (fixed 0.32.11). It listed five
  // names and asserted `includes` — so it omitted `get_findings`, which already shipped, and
  // no addition could ever fail it. The MCP tool list is the customer's whole view of this
  // server; a tool appearing or vanishing unannounced is exactly what a pin is for. Equality,
  // sorted, both directions.
  assert.ok(Array.isArray(TOOLS));
  assert.deepEqual(
    TOOLS.map((t) => t.name).sort(),
    ['compliance_matrix', 'get_findings', 'get_vulnerabilities', 'list_plugins', 'probe_service', 'scan_cloud', 'scan_host'],
    'the exported MCP tool set changed — update this pin deliberately, in the same commit',
  );
});

test('scan_cloud description enumerates AWS service coverage (routing surface)', () => {
  const d = scanCloudTool().description;
  // The prompt-#4 miss: CI/CD segregation-of-duties asks must route here.
  assert.match(d, /CodePipeline/i);
  assert.match(d, /CodeBuild/i);
  assert.match(d, /segregation.of.duties/i);
  // High-value AWS surfaces a service-named ask would mention.
  assert.match(d, /S3/);
  assert.match(d, /\bIAM\b/);
  assert.match(d, /KMS/);
  assert.match(d, /CloudTrail/i);
  assert.match(d, /Lambda/i);
  assert.match(d, /RDS/);
  assert.match(d, /DynamoDB/i);
  assert.match(d, /SQS/);
  assert.match(d, /SNS/);
  assert.match(d, /Secrets Manager/i);
  assert.match(d, /security.group|perimeter/i);
  assert.match(d, /GuardDuty/i);
});

test('scan_cloud description enumerates Azure + GCP service coverage', () => {
  const d = scanCloudTool().description;
  assert.match(d, /Key Vault/i);
  assert.match(d, /NSG|network security group/i);
  assert.match(d, /storage/i);
  assert.match(d, /firewall/i);
  assert.match(d, /impersonation/i);
});

test('scan_cloud description names the seven compliance frameworks (compliance-named asks route too)', () => {
  const d = scanCloudTool().description;
  assert.match(d, /SOC 2/);
  assert.match(d, /HIPAA/);
  assert.match(d, /NIST CSF/);
  assert.match(d, /PCI DSS/);
  assert.match(d, /ISO 27001/);
  assert.match(d, /CIS/);
  assert.match(d, /GDPR Article 32/); // 7th framework — Art. 32 substrate, not GDPR compliance
});

test('scan_cloud description tells the agent to use this tool for service-specific asks', () => {
  const d = scanCloudTool().description;
  // The affirmative routing instruction — not just a list the agent may skim past.
  assert.match(d, /service-specific|service-named|any of these/i);
});

test('scan_cloud description RETAINS the pre-existing contract clauses (no regression)', () => {
  const d = scanCloudTool().description;
  assert.match(d, /Enterprise license/);
  assert.match(d, /providers:\["aws"\]/);
  assert.match(d, /evidenceGaps/);
  assert.match(d, /NOT as clean/);
  assert.match(d, /findingsSummary/);
});

test('scan_cloud input schema is unchanged (providers enum + regions semantics)', () => {
  const t = scanCloudTool();
  const s = t.inputSchema;
  assert.equal(s.type, 'object');
  assert.deepEqual(s.required, []);
  assert.deepEqual(s.properties.providers.items.enum, ['aws', 'gcp', 'azure']);
  assert.match(s.properties.regions.description, /\["all"\]/);
  // ⚠️ THIS PINNED A FALSE SENTENCE UNTIL EE 1.1.0 build 10: `/does NOT fan out/`. Omitting `regions` sets no
  // intent, and the auditors that enumerate their OWN region list (CloudTrail, GuardDuty/Inspector, EC2 instances)
  // still cover every enabled region — measured on a Desktop run, where the assistant relayed the pinned sentence
  // as "only the default region was audited". EE derives that set from the plugins and holds both sentences to it.
  assert.doesNotMatch(s.properties.regions.description, /does NOT fan out/i);
  assert.match(s.properties.regions.description, /server-configured AWS_REGION/);
  assert.match(s.properties.regions.description, /enumerate their own region list/);
  assert.doesNotMatch(t.description, /does NOT fan out|single server-default region/i);
});

// EVERY CLI COMMAND A TOOL DESCRIPTION TEACHES MUST GET PAST THE CLI'S OWN TARGET REFUSAL (EE 1.1.0 build 10).
// The scan_cloud description taught `nsauditor-ai scan --compliance <fw> --out <dir>` — relayed verbatim to the
// operator by the assistant, and exit 2 as written ("Fatal: --host or --host-file is required"). Judged here by
// the REAL parser and the REAL refusal, never by a copy of the condition. EE runs the same census over every
// other surface that documents a command (READMEs, docs, the agent-skill).
const PLACEHOLDER = { '<cloud>': 'aws', '<fw>': 'soc2', '<dir>': 'evidence', '<target>': '192.0.2.10' };
function commandsIn(text) {
  return [...String(text).matchAll(/(?:nsauditor-ai(?:@[^\s`]+)?|cli\.mjs)[ \t]+scan(?:\s+[^\s.`'"]+|\.\S)*/g)].map((m) => m[0].replace(/\.$/, ''));
}
test('FOURTH QUADRANT FIRST — the census extracts, normalises and REFUSES the retired host-less command', async () => {
  const [cmd] = commandsIn('routing is CLI only: nsauditor-ai scan --compliance <fw> --out <dir>. Read findingsSummary');
  assert.equal(cmd, 'nsauditor-ai scan --compliance <fw> --out <dir>');
  const argv = cmd.split(/\s+/).slice(1).map((t) => PLACEHOLDER[t] ?? t);
  const saved = process.env.SCAN_OUT_PATH;
  try {
    assert.deepEqual(scanTargetRefusal(await parseArgs(['node', 'nsauditor-ai', ...argv])),
      { message: 'Fatal: --host or --host-file is required', code: 2 });
  } finally { if (saved === undefined) delete process.env.SCAN_OUT_PATH; else process.env.SCAN_OUT_PATH = saved; }
});
test('every `nsauditor-ai scan` in any tool description gets past the CLI\'s target refusal', async () => {
  const found = TOOLS.flatMap((t) => commandsIn(`${t.description} ${JSON.stringify(t.inputSchema ?? {})}`)
    .map((cmd) => ({ tool: t.name, cmd })));
  assert.ok(found.length >= 1, 'no tool description teaches a scan command — the census read nothing');
  const saved = process.env.SCAN_OUT_PATH;
  try {
    for (const { tool, cmd } of found) {
      const argv = cmd.split(/\s+/).slice(1).map((t) => PLACEHOLDER[t] ?? t);
      const unknown = argv.filter((t) => /^<[^>]+>$/.test(t));
      assert.deepEqual(unknown, [], `${tool}: "${cmd}" carries a placeholder this census has no value for`);
      const a = await parseArgs(['node', 'nsauditor-ai', ...argv]);
      const refusal = scanTargetRefusal(a);
      assert.equal(refusal, null, `${tool} teaches "${cmd}", which the CLI refuses: ${refusal?.message}`);
      assert.ok(typeof a.host === 'string' || typeof a.hostFile === 'string',
        `${tool} teaches "${cmd}", whose target has no value (host: ${JSON.stringify(a.host)}) — main() would crash on it`);
    }
  } finally { if (saved === undefined) delete process.env.SCAN_OUT_PATH; else process.env.SCAN_OUT_PATH = saved; }
});

test('scan_cloud description steers agents away from raw cloud MCPs', () => {
  const tool = TOOLS.find((t) => t.name === 'scan_cloud');
  assert.match(tool.description, /prefer this tool over raw cloud/i);
});
