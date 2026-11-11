// tests/mcp_env_file_gcp_selectors.test.mjs
//
// THE ENV FILE IS THE SCAN TARGET FOR GCP TOO: AMBIENT GCP SELECTORS THE FILE DOES NOT SET ARE CLEARED — AN EMPTY ONE
// INCLUDED (board B136, the Community release paired with Enterprise 2.1.2; placed by the two seats under the operator's
// delegation of 2026-11-03).
//
// NSA_ENV_FILE is "the AUTHORITATIVE scan-target selector" (utils/mcp_env_file.mjs): an ambient provider variable the file
// does not set is cleared, so a partial file cannot scan a leftover account. The list named the AWS, Azure and GCP
// credential variables and the four Azure cloud selectors — and no GCP selector. Measured against Enterprise's readers
// (the placement re-derivation, audit-evidence-samples/ee-2.2.0/placement-rederive/B136/):
//   - an ambient GCP_PROJECT_ID — which Enterprise reads FIRST, ahead of GOOGLE_CLOUD_PROJECT — scanned the ambient project,
//     not the one the file selected, and recorded the wrong project as the scope;
//   - an ambient GOOGLE_IMPERSONATE_SERVICE_ACCOUNT ran Enterprise's Cloud Storage and IAM auditors as another identity;
//   - an ambient STORAGE_EMULATOR_HOST or GOOGLE_CLOUD_UNIVERSE_DOMAIN survived the file — on Enterprise 2.1.1 a false clean
//     (an unauthenticated bucket list from the emulator; the credential sent to another universe), on 2.1.2 a refusal;
//   - an ambient GCE_METADATA_HOST or GCE_METADATA_IP chose the host that minted the token for a file with no key;
//   - and the clear rule kept an ambient EMPTY value, which those libraries still count.
// Now those six are cleared when the file does not set them, and the clear rule clears an ambient empty value too.
//
// STATED LIMITS, each a leg below so a change to them is a decision: METADATA_SERVER_DETECTION is NOT cleared (clearing an
// ambient `none` would turn the metadata-server probe back on); the lowercase `google_application_credentials` the Google
// auth library also reads is NOT cleared (on Windows `process.env` is case-insensitive, so a naive clear would delete the
// file's own GOOGLE_APPLICATION_CREDENTIALS — the same residual holds for every key in the list, untested here on macOS);
// GOOGLE_API_USE_CLIENT_CERTIFICATE and GOOGLE_API_USE_MTLS_ENDPOINT are deferred to Enterprise 2.2.0's credential-source
// decision. And with no NSA_ENV_FILE nothing is cleared at all — the remedy text Enterprise's plugins print is the only path.
//
// FOURTH QUADRANT FIRST: every selector the FILE sets is honoured, an empty one included; with no file nothing is touched.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { applyScanEnvFile } from '../utils/mcp_env_file.mjs';

const GCP_SELECTORS = ['STORAGE_EMULATOR_HOST', 'GOOGLE_CLOUD_UNIVERSE_DOMAIN', 'GCP_PROJECT_ID', 'GOOGLE_IMPERSONATE_SERVICE_ACCOUNT', 'GCE_METADATA_HOST', 'GCE_METADATA_IP'];
const AMBIENT = { STORAGE_EMULATOR_HOST: 'localhost:9023', GOOGLE_CLOUD_UNIVERSE_DOMAIN: 'b136.invalid.example', GCP_PROJECT_ID: 'ambient-project',
  GOOGLE_IMPERSONATE_SERVICE_ACCOUNT: 'other@ambient.iam.gserviceaccount.com', GCE_METADATA_HOST: '127.0.0.1:8989', GCE_METADATA_IP: '127.0.0.2' };
const apply = (env, file) => applyScanEnvFile({ env, fileExists: () => true, readFile: () => file, log: () => {} });

test('(first) every GCP selector the FILE sets is honoured — the file wins, an EMPTY value it writes included', () => {
  for (const k of GCP_SELECTORS) {
    const env = { NSA_ENV_FILE: '/e.env', [k]: AMBIENT[k] };
    const r = apply(env, `GOOGLE_CLOUD_PROJECT=file-project\n${k}=from-the-file\n`);
    assert.equal(env[k], 'from-the-file', k);
    assert.ok(!r.cleared.includes(k), `${k} was cleared though the file set it`);
  }
  const env = { NSA_ENV_FILE: '/e.env', STORAGE_EMULATOR_HOST: 'localhost:9023' };
  apply(env, 'GOOGLE_CLOUD_PROJECT=file-project\nSTORAGE_EMULATOR_HOST=\n');
  assert.equal(env.STORAGE_EMULATOR_HOST, '', 'a value the file writes, even an empty one, is the file\'s — Enterprise refuses it with its remedy');
});

test('(first) with NO NSA_ENV_FILE nothing is cleared — the clearing is the file\'s, and only the file\'s', () => {
  const env = { ...AMBIENT };
  const r = applyScanEnvFile({ env, fileExists: () => true, readFile: () => '', log: () => {} });
  assert.deepEqual(r, { applied: [], ignored: [], cleared: [] });
  assert.deepEqual(env, AMBIENT);
});

for (const k of GCP_SELECTORS) {
  test(`an ambient ${k} the file does not set is CLEARED and reported, its value never logged`, () => {
    const env = { NSA_ENV_FILE: '/e.env', [k]: AMBIENT[k] };
    const logs = [];
    const r = applyScanEnvFile({ env, fileExists: () => true, readFile: () => 'GOOGLE_CLOUD_PROJECT=file-project\n', log: (m) => logs.push(m) });
    assert.equal(env[k], undefined, `ambient ${k} survived the env-file selection`);
    assert.ok(r.cleared.includes(k));
    assert.ok(logs.some((m) => m.includes(k)) && !logs.join('\n').includes(AMBIENT[k]), 'the breadcrumb names the key and never its value');
  });
}

test('an ambient GCP_PROJECT_ID no longer outranks the project the file selects (Enterprise reads GCP_PROJECT_ID first)', () => {
  const env = { NSA_ENV_FILE: '/e.env', GCP_PROJECT_ID: 'ambient-project' };
  apply(env, 'GOOGLE_CLOUD_PROJECT=file-project\n');
  assert.deepEqual([env.GCP_PROJECT_ID, env.GOOGLE_CLOUD_PROJECT], [undefined, 'file-project']);
});

test('an ambient EMPTY value is cleared too — for the GCP selectors and for every key already on the list', () => {
  for (const k of [...GCP_SELECTORS, 'AWS_ACCESS_KEY_ID', 'GOOGLE_APPLICATION_CREDENTIALS', 'AZURE_ENVIRONMENT']) {
    const env = { NSA_ENV_FILE: '/e.env', [k]: '' };
    const r = apply(env, 'CLOUD_PROVIDER=gcp\n');
    assert.equal(Object.hasOwn(env, k), false, `an ambient empty ${k} survived — the libraries count an empty value`);
    assert.ok(r.cleared.includes(k), k);
  }
});

test('STATED LIMITS: METADATA_SERVER_DETECTION, the lowercase google_application_credentials and the client-certificate switches are NOT cleared', () => {
  const kept = { METADATA_SERVER_DETECTION: 'none', google_application_credentials: '/ambient/key.json', GOOGLE_API_USE_CLIENT_CERTIFICATE: 'true', GOOGLE_API_USE_MTLS_ENDPOINT: 'always' };
  const env = { NSA_ENV_FILE: '/e.env', ...kept };
  const r = apply(env, 'GOOGLE_CLOUD_PROJECT=file-project\n');
  for (const [k, v] of Object.entries(kept)) {
    assert.equal(env[k], v, `${k} changed — a decision this leg records; update the module's comment, the CHANGELOG and this leg together`);
    assert.ok(!r.cleared.includes(k), k);
  }
});
