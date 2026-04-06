import assert from 'node:assert/strict';
import test from 'node:test';
import { scrubByKey, redactPatterns } from '../utils/redact.mjs';

test('scrubByKey replaces values whose keys match keywords', () => {
  const payload = {
    serialNumber: 'ABC1234567',
    password: 'hunter2',
    nested: { apiToken: 'tok_abcdef', keep: 'ok' }
  };
  const out = scrubByKey(payload, ['serial', 'password', 'token']);

  assert.equal(out.serialNumber, '[REDACTED_HIDDEN]');
  assert.equal(out.password, '[REDACTED_HIDDEN]');
  assert.equal(out.nested.apiToken, '[REDACTED_HIDDEN]');
  assert.equal(out.nested.keep, 'ok');
});

// --- redactPatterns tests ---

test('redactPatterns standard level redacts email addresses', () => {
  const result = redactPatterns({ msg: 'Contact admin@example.com for help' });
  assert.equal(result.msg, 'Contact [REDACTED_EMAIL] for help');
});

test('redactPatterns standard level redacts internal hostnames', () => {
  const result = redactPatterns({
    a: 'resolved db-server.internal',
    b: 'host app-01.local is up',
    c: 'connecting to ldap.corp',
  });
  assert.equal(result.a, 'resolved [REDACTED_HOSTNAME]');
  assert.equal(result.b, 'host [REDACTED_HOSTNAME] is up');
  assert.equal(result.c, 'connecting to [REDACTED_HOSTNAME]');
});

test('redactPatterns standard level redacts private/internal URLs', () => {
  const result = redactPatterns({
    url1: 'see http://10.0.1.5/admin/panel',
    url2: 'visit https://192.168.1.1/config',
    url3: 'go to http://172.16.0.1/api/v1',
  });
  assert.equal(result.url1, 'see [REDACTED_URL]');
  assert.equal(result.url2, 'visit [REDACTED_URL]');
  assert.equal(result.url3, 'go to [REDACTED_URL]');
});

test('redactPatterns standard level does NOT redact file paths', () => {
  const result = redactPatterns({ path: 'error in /etc/nginx/nginx.conf' });
  assert.equal(result.path, 'error in /etc/nginx/nginx.conf');
});

test('redactPatterns strict level redacts file paths', () => {
  const result = redactPatterns({
    a: 'error in /etc/nginx/nginx.conf',
    b: 'see /var/log/app.log',
    c: 'key at /home/user/.ssh/id_rsa.pem',
    d: 'cert /etc/ssl/server.key',
  }, 'strict');
  assert.equal(result.a, 'error in [REDACTED_PATH]');
  assert.equal(result.b, 'see [REDACTED_PATH]');
  assert.equal(result.c, 'key at [REDACTED_PATH]');
  assert.equal(result.d, 'cert [REDACTED_PATH]');
});

test('redactPatterns strict level redacts bearer tokens', () => {
  const result = redactPatterns({
    header: 'Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig',
  }, 'strict');
  assert.equal(result.header, '[REDACTED_BEARER]');
});

test('redactPatterns strict level redacts AWS access keys', () => {
  const result = redactPatterns({
    key: 'aws key is AKIAIOSFODNN7EXAMPLE',
  }, 'strict');
  assert.equal(result.key, 'aws key is [REDACTED_AWS_KEY]');
});

test('redactPatterns handles nested objects and arrays', () => {
  const input = {
    level1: {
      level2: { email: 'user@test.org' },
    },
    list: [
      'contact bob@corp.io',
      { host: 'db.internal' },
    ],
  };
  const result = redactPatterns(input);
  assert.equal(result.level1.level2.email, '[REDACTED_EMAIL]');
  assert.equal(result.list[0], 'contact [REDACTED_EMAIL]');
  assert.equal(result.list[1].host, '[REDACTED_HOSTNAME]');
});

test('redactPatterns passes non-string values through unchanged', () => {
  const result = redactPatterns({
    count: 42,
    active: true,
    empty: null,
    ratio: 3.14,
  });
  assert.equal(result.count, 42);
  assert.equal(result.active, true);
  assert.equal(result.empty, null);
  assert.equal(result.ratio, 3.14);
});
