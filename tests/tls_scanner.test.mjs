// tests/tls_scanner.test.mjs
import { test, after } from 'node:test';
import assert from 'node:assert/strict';

import * as tlsStub from './_tls_stub.mjs';

const { default: tlsScanner, conclude, __setTlsModuleForTests } = await import('../plugins/tls_scanner.mjs');
__setTlsModuleForTests(tlsStub);
after(() => __setTlsModuleForTests(null)); // never leave the stub installed for a later file in a shared process
const { default: concluder }   = await import('../plugins/result_concluder.mjs');

test('TLS Scanner: detects supported TLS versions and integrates with concluder', async () => {
  process.env.TLS_SCANNER_PORTS = '4443:https';
  process.env.TLS_SCANNER_VERSIONS = 'TLSv1,TLSv1.1,TLSv1.2,TLSv1.3';
  process.env.TLS_SCANNER_TIMEOUT_MS = '1500';
  process.env.TLS_SCANNER_DEBUG = '1';

  const raw = await tlsScanner.run('127.0.0.1');

  assert.equal(typeof raw.up, 'boolean');
  assert.ok(Array.isArray(raw.data));
  assert.equal(raw.data.length, 1);

  const row = raw.data[0];
  assert.equal(row.probe_port, 4443);
  assert.match(String(row.probe_info || ''), /TLS:\s*TLSv1\.2, TLSv1\.3/);

  const banner = JSON.parse(row.response_banner || '{}');
  assert.equal(banner.ciphers['TLSv1.2'], 'TLS_FAKE_CIPHER');
  assert.equal(banner.ciphers['TLSv1.3'], 'TLS_FAKE_CIPHER');

  const conclusion = await concluder.run({ results: [{ name: 'TLS Scanner', result: raw }] });
  const svc = conclusion.services.find(s => s.port === 4443);
  assert.ok(svc, 'service record should exist');
  assert.equal(svc.service, 'https');
  assert.equal(svc.status, 'open');
});

// No environment variable chooses the TLS module (EE board B217): tests/tls_scanner_env_seam_removed.test.mjs runs the
// plugin in a child with the old variable set. The test that stood here re-implemented the old guard inline and could not fail.

test('TLS Scanner conclude(): evidence contains only its own port data, not all rows', async () => {
  const fakeResult = {
    up: true,
    data: [
      { probe_protocol: 'tcp', probe_port: 443, probe_service: 'https', probe_info: 'TLS: TLSv1.2, TLSv1.3', response_banner: '{}' },
      { probe_protocol: 'tcp', probe_port: 465, probe_service: 'smtps', probe_info: 'TLS: TLSv1.2', response_banner: '{}' }
    ]
  };

  const items = await conclude({ host: '127.0.0.1', result: fakeResult });

  assert.equal(items.length, 2, 'should produce one service record per port');

  for (const item of items) {
    assert.equal(item.evidence.length, 1, `evidence for port ${item.port} should contain exactly 1 entry`);
    assert.equal(item.evidence[0].probe_port, item.port, `evidence[0].probe_port should match the service record port (${item.port})`);
  }

  assert.equal(items[0].port, 443);
  assert.equal(items[0].evidence[0].probe_port, 443);
  assert.equal(items[1].port, 465);
  assert.equal(items[1].evidence[0].probe_port, 465);
});
