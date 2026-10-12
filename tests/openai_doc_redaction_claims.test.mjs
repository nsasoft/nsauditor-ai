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
import { buildAIPayload } from '../cli.mjs';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
// THROUGH THE REAL PIPELINE (the architect seat's S1): buildAIPayload is the function maybeSendToOpenAI calls, so the payload
// file IS its output. A network payload, no CONFIDENTIAL_KEYWORDS.
const payload = ({ summary = '', services = [], evidence = [], env = {}, redact = true } = {}) =>
  buildAIPayload({ host: '203.0.113.9', summary, results: [], conclusion: { result: { services, evidence } }, env, redact });
const redact = (info) => JSON.stringify(payload({ evidence: [{ info }] }));

test('(first) MASKED, as documented: public IPv4, colon MAC, full IPv6, link-local, serials', () => {
  assert.match(redact('peer 198.51.100.7 answered'), /\[IP\]/);
  assert.doesNotMatch(redact('peer 198.51.100.7 answered'), /198\.51\.100\.7/);
  assert.match(redact('mac 00:11:22:aa:bb:cc'), /\[MAC\]/);
  assert.match(redact('addr 2001:0db8:0000:0000:0000:ff00:0042:8329'), /\[IPv6\]/);
  assert.match(redact('ll fe80::1ff:fe23:4567:890a'), /\[FE80::\/64\]/);
  assert.match(redact('Serial: ABC123XYZ'), /\[REDACTED_HIDDEN\]/);
});

test('MASKED from Community 1.0.0, and what is STILL NOT — each a record that goes red when the redactor changes again', () => {
  const acct = '123456789012';
  for (const s of [`arn:aws:sns:us-east-1:${acct}:topic-a`, `https://sqs.us-east-1.amazonaws.com/${acct}/queue-a`]) {
    assert.ok(!redact(s).includes(acct), `the account ID survives in "${s}" — the docs say it is masked from Community 1.0.0`);
  }
  // A bare 12-digit number is masked NEUTRALLY; only a GLUED one never named in an ARN or AWS URL is still sent.
  assert.ok(redact(`bucket logs-${acct}`).includes('[REDACTED_ID]'), 'a bare 12-digit number is no longer masked — move the docs');
  assert.ok(redact(`bucket logs${acct}`).includes(acct), 'a glued 12-digit run is masked now — move the docs');
  assert.ok(redact('cert subject emailAddress support@example.com').includes('support@example.com'), 'e-mail addresses survive');
  assert.ok(redact('mac 00-11-22-aa-bb-cc').includes('00-11-22-aa-bb-cc'), 'dash-form MACs survive');
  // The architect seat's measured negative: access-key IDs were absent from the sent payload — by ABSENCE (they live in the
  // findings, not the evidence the payload carries), not by masking. Driven: the redactor passes them unchanged.
  for (const key of ['AKIAIOSFODNN7EXAMPLE', 'ASIAIOSFODNN7EXAMPLE']) {
    assert.ok(redact(`access key ${key} is older than 90 days`).includes(key), `${key.slice(0, 4)}… is masked now — move the docs`);
  }
});

test('the docs say so: docs/openai.md and the README name both lists, and the payload file is not called the whole request', () => {
  const doc = fs.readFileSync(path.join(ROOT, 'docs', 'openai.md'), 'utf8');
  const readme = fs.readFileSync(path.join(ROOT, 'README.md'), 'utf8');
  assert.match(doc, /public IPv4 addresses anywhere in the payload are replaced with `\[IP\]`/);
  assert.match(doc, /travels in the SYSTEM PROMPT/);
  assert.doesNotMatch(doc, /The exact payload sent to OpenAI/, 'the payload file does not record the system prompt');
  assert.match(readme, /From Community 1\.0\.0 it also masks AWS account IDs/);
  assert.match(doc, /becomes `\[ACCOUNT_ID\]`/);
  assert.match(doc, /becomes `\[REDACTED_ID\]`, a neutral label/);
  assert.match(doc, /Azure subscription IDs and\s+GCP project IDs and numbers \(not measured/);
  // ONE not-list, read through BOTH surfaces, so the page and the README cannot drift apart (the architect seat's ask).
  const NOT_MASKED = [/cloud resource names/, /AWS access-key IDs/, /hostnames/, /e-mail/, /compressed IPv6/, /dash- and dot-form MAC/];
  const notParagraph = /\*\*Not masked\*\*[\s\S]{0,900}/.exec(doc)?.[0] ?? '';
  const notSentence = /\*\*It does not mask\*\*[^\n]{0,600}/.exec(readme)?.[0] ?? '';
  for (const re of NOT_MASKED) {
    assert.match(notParagraph.replace(/\s+/g, ' '), re, `docs/openai.md's not-list lost ${re}`);
    assert.match(notSentence, re, `the README's not-list lost ${re}`);
  }
  assert.doesNotMatch(readme, /masks IP addresses, MAC addresses, serial numbers, and configurable/);
});

test('the SUMMARY through both passes as cli.mjs applies them: public → [IP], private → [REDACTED_HOST] — and the page says so', () => {
  // The architect seat's refute (second read of 1ca3ffe): the page said EVERY summary address became [REDACTED_HOST]. The
  // base redactor runs first and turns a public one into [IP]; only a private one is left for the summary pass.
  // Driven through buildAIPayload, so a changed POLICY at the call site turns this red — the first cut spelled the policy in
  // the test and proved the rules compose, not that the pipeline applies them (survivor S1).
  assert.equal(payload({ summary: 'peer 198.51.100.7 and 10.0.0.5 answered' }).summary, 'peer [IP] and [REDACTED_HOST] answered');
  const doc = fs.readFileSync(path.join(ROOT, 'docs', 'openai.md'), 'utf8');
  assert.doesNotMatch(doc, /every IPv4 address in the summary with `\[REDACTED_HOST\]`/);
  assert.match(doc, /a private IPv4 address left in the summary also becomes\s+`\[REDACTED_HOST\]` \(a public one is `\[IP\]` there/);
});

test('the intelligence block\'s scrub is stated in docs/openai.md in the enhancedRedaction desc\'s own words (EE 2.0.0)', async () => {
  // The desc is what `license --capabilities` prints; the doc is what a reader is pointed at. One sentence in two places
  // drifts unless one is held to the other. What the sentence says is driven against EE's real block builder in EE's
  // tests/enhanced_redaction_desc_matches_behaviour — Community cannot drive it from here.
  const { CAPABILITIES } = await import('../utils/capabilities.mjs');
  const desc = CAPABILITIES.enhancedRedaction.desc;
  const i = desc.indexOf('the target host on each finding');
  const j = desc.indexOf(' The scan-payload redactor is the same at every tier');
  assert.ok(i > 0 && j > i, `the desc no longer carries the sentence this leg holds the doc to: ${desc}`);
  assert.match(desc, /^Gates no code of its own\./, 'the key gates no code; the desc must say so first');
  const doc = fs.readFileSync(path.join(ROOT, 'docs', 'openai.md'), 'utf8').replace(/`/g, '').replace(/\s+/g, ' ');
  assert.ok(doc.includes(desc.slice(i, j)), `docs/openai.md must carry, verbatim (backticks aside): ${desc.slice(i, j)}`);
});

test('the rest of the page\'s list, through the pipeline: host, private IPv4 in services and evidence, CONFIDENTIAL_KEYWORDS, _meta', () => {
  const p = payload({ services: [{ port: 22, banner: 'ssh on 192.168.4.4' }], evidence: [{ info: 'peer 10.9.9.9', apiToken: 'xyz' }],
    env: { CONFIDENTIAL_KEYWORDS: 'token' } });
  assert.equal(p.host, '[REDACTED_HOST]');
  assert.equal(p.services[0].banner, 'ssh on [REDACTED_IP]');
  assert.equal(p.evidence[0].info, 'peer [REDACTED_IP]');
  assert.equal(p.evidence[0].apiToken, '[REDACTED_HIDDEN]');
  assert.deepEqual([p._meta.wasRedacted, p._meta.redactor], [true, 'builtin']);
  const doc = fs.readFileSync(path.join(ROOT, 'docs', 'openai.md'), 'utf8').replace(/\s+/g, ' ');
  assert.match(doc, /the top-level host is replaced with `\[REDACTED_HOST\]`/);
  assert.match(doc, /private-range IPv4 addresses \(10\/8, 172\.16\/12, 192\.168\/16\) in service and evidence strings are replaced with `\[REDACTED_IP\]`/);
  assert.match(doc, /any field whose key matches `CONFIDENTIAL_KEYWORDS`[^;\n]*is replaced with `\[REDACTED_HIDDEN\]`/);
  // ...and with OPENAI_REDACT=false nothing is masked and the record says so.
  const off = payload({ evidence: [{ info: 'peer 198.51.100.7' }], redact: false });
  assert.deepEqual([off.host, off.evidence[0].info, off._meta.wasRedacted, off._meta.redactor], ['203.0.113.9', 'peer 198.51.100.7', false, undefined]);
});
