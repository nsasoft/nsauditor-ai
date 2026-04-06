// tests/admin_raw_report_html.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildAdminRawHtmlReport } from '../utils/raw_report_html.mjs';

test('buildAdminRawHtmlReport returns HTML and contains Open Services table', async () => {
  const html = await buildAdminRawHtmlReport({
    host: '1.2.3.4',
    whenIso: '2025-08-29T12:00:00Z',
    summary: 'Host is UP. Likely OS: Linux.',
    services: [
      { port: 80,  protocol: 'tcp', service: 'http', status: 'open',    program: 'nginx',   version: '1.21', info: 'ok', banner: 'Server: nginx' },
      { port: 22,  protocol: 'tcp', service: 'ssh',  status: 'closed',  program: 'OpenSSH', version: '9.0',  info: 'refused', banner: null },
      { port: 161, protocol: 'udp', service: 'snmp', status: 'filtered', program: 'Unknown', version: 'Unknown', info: 'timeout', banner: null },
    ],
    evidence: [
      { from: 'Port Scanner', protocol: 'tcp', port: 80,  info: 'TCP connect success', banner: '' },
      { from: 'Port Scanner', protocol: 'tcp', port: 22,  info: 'refused', banner: '' },
      { from: 'SNMP',         protocol: 'udp', port: 161, info: 'timeout', banner: '' },
    ],
  });

  // basic sanity
  assert.ok(typeof html === 'string' && html.length > 0);

  // has the Open Services section and includes the open http row
  assert.ok(html.includes('Open Services'));
  assert.ok(html.toLowerCase().includes('http'));
  assert.ok(html.includes('tcp-80')); // or whatever marker your template uses for 80/tcp

  // evidence table present and shows a Status column
  assert.ok(html.includes('Evidence'));
  assert.ok(/<th[^>]*>Status<\/th>/i.test(html));

  // Closed service (OpenSSH) may appear in Evidence, but not in "Open Services"
  // (adjust the check to match your template’s exact markup)
  const openSection = html.split('Open Services')[1] || '';
  assert.ok(!openSection.includes('OpenSSH'));
});

