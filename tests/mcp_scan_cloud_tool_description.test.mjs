import { test } from 'node:test';
import assert from 'node:assert/strict';
import { TOOLS } from '../mcp_server.mjs';

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
  assert.match(s.properties.regions.description, /does NOT fan out/);
});

test('scan_cloud description steers agents away from raw cloud MCPs', () => {
  const tool = TOOLS.find((t) => t.name === 'scan_cloud');
  assert.match(tool.description, /prefer this tool over raw cloud/i);
});
