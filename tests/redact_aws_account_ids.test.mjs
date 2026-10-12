import './helpers/no_operator_dotenv.mjs';
import './helpers/no_operator_keychain.mjs';   // FIRST: this file imports cli.mjs
// tests/redact_aws_account_ids.test.mjs
// ─────────────────────────────────────────────────────────────────────────────
// THE AI PAYLOAD NO LONGER CARRIES AN AWS ACCOUNT ID, AND NO BARE 12-DIGIT ID (EE 2.0.0 — marketing task #204 measured 20
// occurrences of the account ID in one real AWS payload; the operator ruled "State it now, fix in 2.0.0"). The shape, as
// the architect seat ruled — TWO PASSES:
//   1. an ID in a CERTAIN context — an ARN's account field in any partition, an `amazonaws.com/<12 digits>` URL segment —
//      is an account: every literal occurrence of it becomes [ACCOUNT_ID], inside resource names too; the names stay;
//   2. any OTHER bare 12-digit run becomes the NEUTRAL [REDACTED_ID]: masking it is safe, naming it an account is not.
// FOURTH QUADRANT FIRST: what must come through untouched.
// ─────────────────────────────────────────────────────────────────────────────
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { redactSensitiveForAI, awsAccountIdsIn, ACCOUNT_ID_MASK, BARE_ID_MASK } from '../cli.mjs';

const ACCT = '123456789012';
const red = (info, host = '192.168.1.1') => redactSensitiveForAI({ evidence: [{ info }] }, host).evidence[0].info;

test('(first) a payload with no 12-digit run is BYTE-IDENTICAL after the pass — and no other numeric shape is touched', () => {
  const p = { host: 'x', summary: 'ms 1791778446168 · epoch 1791778446 · id 1234567890123 · plugin 1020 (EE-0.3.2.4 fold)',
    services: [{ port: 443, banner: 'nginx 1.27.0' }], evidence: [{ info: 'version 10.0.19045' }] };
  assert.deepEqual(redactSensitiveForAI(p, 'aws'), p);
});

test('the labels are the ruled ones', () => {
  assert.equal(ACCOUNT_ID_MASK, '[ACCOUNT_ID]');
  assert.equal(BARE_ID_MASK, '[REDACTED_ID]');
});

test('pass 1 — an ARN\'s account field is [ACCOUNT_ID] in EVERY partition, on any payload; the resource stays named', () => {
  for (const p of ['aws', 'aws-us-gov', 'aws-cn']) {
    assert.equal(red(`arn:${p}:sns:us-east-1:${ACCT}:sns-cleartext-topic`), `arn:${p}:sns:us-east-1:[ACCOUNT_ID]:sns-cleartext-topic`);
  }
  assert.equal(red(`arn:aws:iam::${ACCT}:user/iam-violator-user`, 'aws'), 'arn:aws:iam::[ACCOUNT_ID]:user/iam-violator-user');
});

test('pass 1 — an AWS URL\'s account segment is [ACCOUNT_ID], the queue named', () => {
  assert.equal(red(`https://sqs.us-east-1.amazonaws.com/${ACCT}/sqs-cleartext-queue`, 'aws'),
    'https://sqs.us-east-1.amazonaws.com/[ACCOUNT_ID]/sqs-cleartext-queue');
  // The China partition's domain is `amazonaws.com.cn` (the architect seat's X2: the regex's `.cn` branch had no fixture,
  // so dropping it left every leg green — a branch nothing exercises is a claim).
  assert.equal(red(`https://sqs.cn-north-1.amazonaws.com.cn/${ACCT}/sqs-cleartext-queue`, 'aws'),
    'https://sqs.cn-north-1.amazonaws.com.cn/[ACCOUNT_ID]/sqs-cleartext-queue');
});

test('pass 1 — an ID learned in context is [ACCOUNT_ID] EVERYWHERE in the payload: bare, dash-suffixed and GLUED', () => {
  const out = redactSensitiveForAI({ summary: `account ${ACCT}`, evidence: [{ info: `arn:aws:sns:us-east-1:${ACCT}:t` },
    { info: `s3-violator-bucket-${ACCT} — partial block` }, { info: `bucket logs${ACCT} has no lock` }] }, 'aws');
  assert.equal(out.summary, 'account [ACCOUNT_ID]');
  assert.equal(out.evidence[0].info, 'arn:aws:sns:us-east-1:[ACCOUNT_ID]:t');
  assert.equal(out.evidence[1].info, 's3-violator-bucket-[ACCOUNT_ID] — partial block');
  assert.equal(out.evidence[2].info, 'bucket logs[ACCOUNT_ID] has no lock');
  assert.ok(!JSON.stringify(out).includes(ACCT));
});

test('pass 2 — a bare 12-digit run never seen in context is [REDACTED_ID] — on a network payload and an AWS one alike', () => {
  assert.equal(red('sysUpTime 123456789012 ticks'), 'sysUpTime [REDACTED_ID] ticks');
  assert.equal(red(`account ${ACCT}`, 'aws'), 'account [REDACTED_ID]', 'no ARN or URL names it, so it is not called an account');
  assert.equal(red(`bucket logs-${ACCT}`, 'aws'), 'bucket logs-[REDACTED_ID]');
});

test('DECLARED LIMIT: a 12-digit run GLUED into a name and never seen in an ARN or AWS URL survives (no word boundary)', () => {
  assert.equal(red(`bucket logs${ACCT}`, 'aws'), `bucket logs${ACCT}`);
});

test('awsAccountIdsIn learns from ARNs and AWS URLs only', () => {
  const input = { a: 'arn:aws:sns:us-east-1:111111111111:t', b: 'amazonaws.com/222222222222/q', c: 'bare 333333333333',
    d: 'sqs.cn-north-1.amazonaws.com.cn/444444444444/q' };
  assert.deepEqual([...awsAccountIdsIn(input)].sort(), ['111111111111', '222222222222', '444444444444']);
});

test('#204 finding 3 — the payload record names the redactor that RAN: "builtin" on the normal path, never "fallback"', async () => {
  const fs = await import('node:fs');
  const src = fs.readFileSync(new URL('../cli.mjs', import.meta.url), 'utf8').replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:])\/\/[^\n]*/g, '$1');
  assert.match(src, /const used = 'builtin';/);
  assert.doesNotMatch(src, /'fallback'/, 'a normal run must not be recorded as a fallback');
});
