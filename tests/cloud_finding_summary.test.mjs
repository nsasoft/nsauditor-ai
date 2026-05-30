import { test } from 'node:test';
import assert from 'node:assert/strict';
import { describeFinding, summarizeCloudFindings, renderCloudFindingsMarkdown } from '../utils/cloud_finding_summary.mjs';

test('describeFinding handles AWS IAM shape (userName + issues)', () => {
  const d = describeFinding({ userName: 'iam-violator-user', severity: 'critical', issues: ['SHADOW ADMIN: full wildcard'] });
  assert.match(d, /iam-violator-user/); assert.match(d, /SHADOW ADMIN/);
});

test('describeFinding handles title/message shapes + unknown shape', () => {
  assert.match(describeFinding({ title: 'open firewall', severity: 'high' }), /open firewall/);
  assert.match(describeFinding({ bucketName: 'b1', classification: 'public' }), /b1/);
  assert.ok(describeFinding({ severity: 'low', foo: 'bar' }).length > 0); // never empty
});

test('summarizeCloudFindings groups by provider, counts severities, lists CRIT/HIGH', () => {
  const results = [
    { id: '1030', result: { findings: [
      { severity: 'critical', userName: 'iam-violator-user', issues: ['SHADOW ADMIN'] },
      { severity: 'critical', userName: 'superadmin', issues: ['SHADOW ADMIN'] },
      { severity: 'high', userName: 'x', issues: ['priv'] },
      { severity: 'pass', userName: 'ok' },
    ] } },
    { id: '1021', result: { data: [ { severity: 'critical', title: 'default-allow-ssh' } ] } },
  ];
  const providerOf = (id) => ({ '1030': 'aws', '1021': 'gcp' }[String(id)] || null);
  const s = summarizeCloudFindings(results, providerOf);
  assert.equal(s.aws.counts.CRITICAL, 2);
  assert.equal(s.aws.counts.HIGH, 1);
  assert.equal(s.aws.counts.PASS, 1);
  assert.equal(s.aws.findings.filter((f) => f.severity === 'CRITICAL').length, 2);
  assert.ok(s.aws.findings.some((f) => /iam-violator-user/.test(f.title)));
  assert.equal(s.gcp.counts.CRITICAL, 1);
});

test('summarizeCloudFindings caps the CRIT/HIGH list + flags truncation', () => {
  const findings = Array.from({ length: 5 }, (_, i) => ({ severity: 'high', title: 'f' + i }));
  const results = [{ id: '1030', result: { findings } }];
  const providerOf = () => 'aws';
  const s = summarizeCloudFindings(results, providerOf, 3);
  assert.equal(s.aws.counts.HIGH, 5);       // counts are complete
  assert.equal(s.aws.findings.length, 3);    // displayed list capped
  assert.equal(s.aws.truncated, true);
});

test('renderCloudFindingsMarkdown lists every CRITICAL', () => {
  const s = { aws: { counts: { CRITICAL: 1, HIGH: 0 }, findings: [{ severity: 'CRITICAL', plugin: '1030', title: 'iam-violator-user — SHADOW ADMIN' }], truncated: false } };
  const md = renderCloudFindingsMarkdown(s, ['aws']);
  assert.match(md, /CRITICAL/); assert.match(md, /iam-violator-user/);
});
