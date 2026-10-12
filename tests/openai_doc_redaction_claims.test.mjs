import './helpers/no_operator_dotenv.mjs';
import './helpers/no_operator_keychain.mjs';   // FIRST: this file imports cli.mjs
// tests/openai_doc_redaction_claims.test.mjs
// ─────────────────────────────────────────────────────────────────────────────
// WHAT docs/openai.md AND THE README SAY THE REDACTOR MASKS — AND DOES NOT — IS WHAT IT DOES (EE 2.0.0, task #205).
//
// The draft said public addresses in service strings were not covered (the base redactor masks them as [IP]) and named
// none of the MAC / IPv6 / serial / Set-Cookie masking; #204's real run (tasks/openai-path-e2e-2026-10.md in Enterprise)
// found AWS account IDs and ARNs surviving. A list of what a redactor does is a claim about the code, so each entry is
// driven through the REAL function here. ⚠️ THE "NOT MASKED" LEG IS A RECORD THAT GOES RED ON PURPOSE: the operator ruled
// (2026-10-12) "State it now, fix in 2.0.0" — when the redactor learns to mask account IDs, this leg fails, and the same
// commit must move the sentence in docs/openai.md and the README.
// ─────────────────────────────────────────────────────────────────────────────
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { redactSensitiveForAI } from '../cli.mjs';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const redact = (info) => JSON.stringify(redactSensitiveForAI({ evidence: [{ info }] }, '203.0.113.9'));

test('(first) MASKED, as documented: public IPv4, colon MAC, full IPv6, link-local, serials', () => {
  assert.match(redact('peer 198.51.100.7 answered'), /\[IP\]/);
  assert.doesNotMatch(redact('peer 198.51.100.7 answered'), /198\.51\.100\.7/);
  assert.match(redact('mac 00:11:22:aa:bb:cc'), /\[MAC\]/);
  assert.match(redact('addr 2001:0db8:0000:0000:0000:ff00:0042:8329'), /\[IPv6\]/);
  assert.match(redact('ll fe80::1ff:fe23:4567:890a'), /\[FE80::\/64\]/);
  assert.match(redact('Serial: ABC123XYZ'), /\[REDACTED_HIDDEN\]/);
});

test('NOT MASKED today, as documented — a record that goes red when 2.0.0 masks account IDs (then move the docs with it)', () => {
  const acct = '123456789012';
  for (const s of [`arn:aws:sns:us-east-1:${acct}:topic-a`, `https://sqs.us-east-1.amazonaws.com/${acct}/queue-a`,
    `bucket logs-${acct}`, `account ${acct}`]) {
    assert.ok(redact(s).includes(acct), `the account ID is masked now in "${s}" — move docs/openai.md and the README's "not mask" sentence in this commit`);
  }
  assert.ok(redact('cert subject emailAddress support@example.com').includes('support@example.com'), 'e-mail addresses survive');
  assert.ok(redact('mac 00-11-22-aa-bb-cc').includes('00-11-22-aa-bb-cc'), 'dash-form MACs survive');
});

test('the docs say so: docs/openai.md and the README name both lists, and the payload file is not called the whole request', () => {
  const doc = fs.readFileSync(path.join(ROOT, 'docs', 'openai.md'), 'utf8');
  const readme = fs.readFileSync(path.join(ROOT, 'README.md'), 'utf8');
  assert.match(doc, /\*\*Not masked\*\*[\s\S]{0,200}AWS account IDs and\s+ARNs/);
  assert.match(doc, /public IPv4 addresses anywhere in the payload are replaced with `\[IP\]`/);
  assert.match(doc, /travels in the SYSTEM PROMPT/);
  assert.doesNotMatch(doc, /The exact payload sent to OpenAI/, 'the payload file does not record the system prompt');
  assert.match(readme, /\*\*It does not mask\*\* AWS account IDs or ARNs/);
  assert.doesNotMatch(readme, /masks IP addresses, MAC addresses, serial numbers, and configurable/);
});
