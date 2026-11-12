// tests/proxy_secret_redaction.test.mjs
// ─────────────────────────────────────────────────────────────────────────────
// THE BARE PROXY PASSWORD (EE 2.2.0, I3 — the architect's ruling on the dependency-closure measurement, 2026-11-11).
//
// redactUrlCredentials removed a proxy credential only where it was followed by `@`: the variable's exact userinfo
// (`user:password@`) and any URL's userinfo. A child process a cloud SDK runs can print the password ALONE, or
// percent-DECODED, and the SDK carries the child's stderr into the Error it throws (measured:
// @aws-sdk/credential-provider-process with a customer-configured credential_process). Neither pass sees that, so a
// third one replaces each proxy variable's password, as written and decoded, wherever it appears.
//
// The guard: a password shorter than PROXY_SECRET_MIN_LENGTH (8) is never replaced bare, because a short value would
// shred ordinary text; it is still removed inside a URL by the first two passes. A userinfo with no `:` is a token
// carried as the user name, and it is the secret.
//
// FOURTH QUADRANT FIRST: text that names an e-mail, an ARN or an `@` in a URL's path comes through byte-identical,
// with a credential-bearing proxy variable set — a scrub that shreds identifiers moves a finding's sentence.
// ─────────────────────────────────────────────────────────────────────────────
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as W from '../utils/webhook.mjs';

// A namespace import, so each leg goes red by its own name before the pass exists rather than the file failing to load.
const redactUrlCredentials = (...a) => W.redactUrlCredentials(...a);
const proxySecrets = (...a) => W.proxySecrets(...a);
const PROXY_SECRET_MIN_LENGTH = W.PROXY_SECRET_MIN_LENGTH;

const CANARY = 'B164I3SECRETpw';
const PROXY = { HTTPS_PROXY: `http://proxyuser:${CANARY}@127.0.0.1:9` };
const FOURTH_QUADRANT = Object.freeze([
  'user@example.com',
  'scanner@my-project.iam.gserviceaccount.com',
  'arn:aws:iam::123456789012:role/Admin@Path',
  'https://host/path@x',
  's3://bucket/key@v',
]);

test('(q0) fourth quadrant: identifiers with an @ come through byte-identical, with and without a proxy password set', () => {
  for (const env of [{}, PROXY, { HTTPS_PROXY: 'http://u:pa ss@h:1', https_proxy: 'http://tok3nonlyABCDEF@h:2' }]) {
    for (const s of FOURTH_QUADRANT) {
      assert.equal(redactUrlCredentials(s, env), s, `${JSON.stringify(s)} under ${JSON.stringify(env)}`);
      const sentence = `Bucket policy grants ${s} read access`;
      assert.equal(redactUrlCredentials(sentence, env), sentence);
    }
  }
  // The user NAME is not the secret: it stays where it appears alone.
  assert.equal(redactUrlCredentials('auth as proxyuser failed', PROXY), 'auth as proxyuser failed');
});

test('(q1) the password is replaced wherever it appears — bare, decoded, repeated, from any proxy variable', () => {
  // positive control: before this pass existed, the bare canary survived
  assert.ok(CANARY.length >= (PROXY_SECRET_MIN_LENGTH ?? 8), 'the canary must be long enough to be in scope');
  assert.equal(redactUrlCredentials(`stderr: password ${CANARY} rejected`, PROXY), 'stderr: password <credentials> rejected');
  assert.equal(redactUrlCredentials(`${CANARY} / ${CANARY}`, PROXY), '<credentials> / <credentials>');
  assert.equal(redactUrlCredentials(`proxyuser:${CANARY} (no @)`, PROXY), 'proxyuser:<credentials> (no @)');
  // the URL forms the first two passes already covered are unchanged in outcome
  assert.equal(redactUrlCredentials(`via http://proxyuser:${CANARY}@127.0.0.1:9`, PROXY), 'via http://<credentials>@127.0.0.1:9');
  assert.equal(redactUrlCredentials(`Failed to parse: http://proxyuser:${CANARY}@[::1`, PROXY), 'Failed to parse: http://<credentials>@[::1');

  // percent-encoded in the variable, printed DECODED by the child
  const enc = { https_proxy: 'http://u:B164%40I3%20SECRET@127.0.0.1:9' };
  assert.equal(redactUrlCredentials('child said B164@I3 SECRET', enc), 'child said <credentials>');
  assert.equal(redactUrlCredentials('child said B164%40I3%20SECRET', enc), 'child said <credentials>');

  // a user name with no password is NOT a secret replaced bare (review fold: an ordinary user name would be shredded
  // across host names, banners and keys); inside a URL it is still removed by the first two passes
  const tok = { ALL_PROXY: 'http://tok3nonlyABCDEF@h:2' };
  assert.equal(redactUrlCredentials('user tok3nonlyABCDEF connected', tok), 'user tok3nonlyABCDEF connected');
  assert.equal(redactUrlCredentials('via http://tok3nonlyABCDEF@h:2', tok), 'via http://<credentials>@h:2');

  // longest first: one password a prefix of another leaves no tail behind
  const two = { HTTP_PROXY: 'http://a:SECRETpw12345@h:1', HTTPS_PROXY: 'http://b:SECRETpw12345678@h:2' };
  assert.equal(redactUrlCredentials('x SECRETpw12345678 y SECRETpw12345 z', two), 'x <credentials> y <credentials> z');
});

test('(q2) the guard is 8 characters: a shorter password is removed inside a URL only, never bare (stated limit)', () => {
  assert.equal(PROXY_SECRET_MIN_LENGTH, 8, 'the guard is declared here so a change to it is a decision');
  const seven = { HTTPS_PROXY: 'http://u:short7x@h:1' };
  assert.equal(redactUrlCredentials('bare short7x stays', seven), 'bare short7x stays', 'BELOW the guard: not replaced bare');
  assert.equal(redactUrlCredentials('via http://u:short7x@h:1', seven), 'via http://<credentials>@h:1', 'still removed inside a URL');
  const eight = { HTTPS_PROXY: 'http://u:exactly8@h:1' };
  assert.equal(redactUrlCredentials('bare exactly8 goes', eight), 'bare <credentials> goes', 'AT the guard: replaced');
  // the guard reads the DECODED length too: 'ab%20cdef' is 9 written, 7 decoded — only the written form is in scope
  assert.deepEqual(proxySecrets({ HTTPS_PROXY: 'http://u:ab%20cdef@h:1' }), ['ab%20cdef']);
});

test('(q3) proxySecrets reads the variables Node reads, splits at the FIRST colon, and returns longest first', () => {
  assert.deepEqual(proxySecrets({}), []);
  assert.deepEqual(proxySecrets({ HTTPS_PROXY: 'http://127.0.0.1:9' }), [], 'no userinfo, no secret');
  assert.deepEqual(proxySecrets({ HTTPS_PROXY: 'http://user:@h:1' }), [], 'an empty password is no secret');
  assert.deepEqual(proxySecrets({ HTTPS_PROXY: 'http://tok3nonlyABCDEF@h:1' }), [], 'a user name alone is no secret');
  assert.deepEqual(proxySecrets({ HTTPS_PROXY: 'http://u:pass:word123@h:1' }), ['pass:word123'], 'a colon inside the password is kept');
  assert.deepEqual(proxySecrets({ HTTPS_PROXY: `  http://proxyuser:${CANARY}@h:1  ` }), [CANARY], 'padding trimmed, as Node does');
  assert.deepEqual(proxySecrets({ NO_PROXY: `http://u:${CANARY}@h:1`, PROXY: `http://u:${CANARY}@h:1` }), [], 'only the six proxy variables');
  const got = proxySecrets({ http_proxy: 'http://a:SECRETpw12345@h:1', HTTPS_PROXY: 'http://b:SECRETpw12345678@h:2' });
  assert.deepEqual(got, ['SECRETpw12345678', 'SECRETpw12345']);
});

test('(q4) the bare pass never rewrites a placeholder, so redaction is idempotent even when the password is "credentials"', () => {
  const env = { HTTPS_PROXY: 'http://u:credentials@p:1' };
  assert.equal(redactUrlCredentials('http://a:b@h', env), 'http://<credentials>@h');
  assert.equal(redactUrlCredentials('the credentials leaked', env), 'the <credentials> leaked');
  const two = { HTTP_PROXY: 'http://a:credentials@p:1', HTTPS_PROXY: `http://b:${CANARY}@p:2` };
  for (const x of ['http://a:b@h', `${CANARY} and credentials`, 'credentials <credentials>', `via http://b:${CANARY}@p:2`]) {
    for (const e of [env, two, PROXY]) {
      const once = redactUrlCredentials(x, e);
      assert.equal(redactUrlCredentials(once, e), once, `idempotent: ${JSON.stringify(x)}`);
      assert.ok(!once.includes('<<') && !once.includes('>>'), `no mangled placeholder: ${once}`);
    }
  }
});
