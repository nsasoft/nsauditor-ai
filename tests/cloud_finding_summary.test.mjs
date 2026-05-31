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

test('describeFinding surfaces REAL plugin resource keys (bucket/vault/group/table/key/function/pipeline)', () => {
  assert.match(describeFinding({ bucket: 'prod-pii-bucket', severity: 'critical', issues: ['Bucket policy grants public access'] }), /prod-pii-bucket/);
  assert.match(describeFinding({ vault: 'kv-prod', severity: 'high', issues: ['no purge protection'] }), /kv-prod/);
  assert.match(describeFinding({ group: 'sg-123', severity: 'critical', issues: ['0.0.0.0/0 ingress'] }), /sg-123/);
  assert.match(describeFinding({ table: 'ddb-tbl', severity: 'high', issues: ['no PITR'] }), /ddb-tbl/);
  assert.match(describeFinding({ key: 'kms-1', severity: 'high', issues: ['wildcard decrypt'] }), /kms-1/);
  assert.match(describeFinding({ function: 'fn-x', severity: 'critical', issues: ['public URL'] }), /fn-x/);
  assert.match(describeFinding({ pipeline: 'pl-1', severity: 'high', issues: ['no encryption'] }), /pl-1/);
});

test('describeFinding never emits a raw object dump for an indeterminate finding', () => {
  const d = describeFinding({ severity: 'high', foo: 'bar' });
  assert.ok(d.length > 0);
  assert.doesNotMatch(d, /[{}]/); // no JSON.stringify blob on the headline surface
});

test('cap keeps CRITICALs in the displayed list over HIGHs when truncating', () => {
  const findings = [
    ...Array.from({ length: 60 }, (_, i) => ({ severity: 'high', title: 'h' + i })),
    { severity: 'critical', userName: 'late-crit', issues: ['SHADOW ADMIN'] },
  ];
  const s = summarizeCloudFindings([{ id: '1030', result: { findings } }], () => 'aws', 5);
  assert.equal(s.aws.counts.CRITICAL, 1);          // counts complete
  assert.equal(s.aws.counts.HIGH, 60);
  assert.equal(s.aws.findings.length, 5);          // displayed list capped
  assert.equal(s.aws.truncated, true);
  assert.ok(s.aws.findings.some((f) => f.severity === 'CRITICAL' && /late-crit/.test(f.title))); // CRITICAL survives
});

test('a result whose provider cannot be resolved is bucketed under "unknown", never dropped', () => {
  const s = summarizeCloudFindings([{ id: '9999', result: { findings: [{ severity: 'critical', title: 'orphan-finding' }] } }], () => null);
  assert.equal(s.unknown.counts.CRITICAL, 1);
  const md = renderCloudFindingsMarkdown(s, ['aws']); // 'aws' named, but unknown must still render
  assert.match(md, /orphan-finding/);
});
