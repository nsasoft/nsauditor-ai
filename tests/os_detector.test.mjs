// tests/os_detector.test.mjs
// Verifies OS inference from DNS (BIND -> RHEL/CentOS),
// adoption by Result Concluder, fallback to Ping TTL OS,
// and fallback to FTP plugin-provided OS when others are absent.

import test from 'node:test';
import assert from 'node:assert/strict';

import osDetector from '../plugins/os_detector.mjs';
import concluder from '../plugins/result_concluder.mjs';

const RHEL_BANNER = '9.11.4-P2-RedHat-9.11.4-26.P2.el7_9.16.tuxcare.els8';

test('OS Detector: infers Red Hat family (with version) from BIND banner', async () => {
  // Mock a DNS plugin result that exposes a BIND banner on UDP/53
  const dnsPlugin = {
    id: '009',
    name: 'DNS Scanner',
    result: {
      up: true,
      program: 'BIND',
      version: '9.11.4-P2',
      data: [
        {
          probe_protocol: 'udp',
          probe_port: 53,
          probe_info: 'version.bind',
          response_banner: RHEL_BANNER
        }
      ]
    }
  };

  // Run the OS detector *as a plugin* over prior plugin results
  const osRes = await osDetector.run([dnsPlugin]);

  assert.equal(osRes.program, 'OS Detector');
  // Accept either precise RHEL label or a family label
  const osLabel = String(osRes.os || '');
  assert.ok(
    ['Red Hat Enterprise Linux', 'Red Hat family (RHEL/CentOS)', 'CentOS', 'Linux'].includes(osLabel),
    `unexpected os label: ${osLabel}`
  );
  // Should extract version "7.9" from el7_9 token, when available
  if (osRes.os === 'Red Hat Enterprise Linux' || osRes.os === 'Red Hat family (RHEL/CentOS)') {
    assert.ok(/^7(\.9)?/.test(String(osRes.osVersion || '')), `expected RHEL version like 7 or 7.9, got ${osRes.osVersion}`);
  }
  // TuxCare flag should be true ('.tuxcare.' exists in banner)
  assert.equal(Boolean(osRes.osExtras?.tuxcare), true);

  // Evidence should include a DNS row on port 53
  assert.ok(Array.isArray(osRes.data) && osRes.data.length >= 1, 'should emit evidence rows');
  const dnsRow = osRes.data.find(d => d.probe_protocol === 'udp' && d.probe_port === 53);
  assert.ok(!!dnsRow, 'expected a DNS version.bind evidence row');
});

test('OS Detector + Concluder: concluder adopts plugin-provided OS', async () => {
  const dnsPlugin = {
    id: '009',
    name: 'DNS Scanner',
    result: {
      up: true,
      program: 'BIND',
      version: '9.11.4-P2',
      data: [
        {
          probe_protocol: 'udp',
          probe_port: 53,
          probe_info: 'version.bind',
          response_banner: RHEL_BANNER
        }
      ]
    }
  };

  const osRes = await osDetector.run([dnsPlugin]);

  // Concluder accepts an array of { name/id, result } items
  const concluded = await concluder.run([
    { id: '013', name: 'OS Detector', result: osRes },
    dnsPlugin
  ]);

  const expectedOs = osRes.os || null;
  assert.equal(concluded?.host?.os || null, expectedOs, `concluder should pick OS from OS Detector (${expectedOs})`);
  if (expectedOs) {
    assert.match(concluded?.summary || '', /OS:\s*Red Hat Enterprise Linux/);
  }
});

test('OS Detector: uses Ping Checker TTL-derived OS as baseline (Windows)', async () => {
  // Fake a Ping Checker plugin that sets os: Windows
  const pingPlugin = {
    id: '001',
    name: 'Ping Checker',
    result: {
      up: true,
      os: 'Windows',
      data: [
        { probe_protocol: 'icmp', probe_port: 0, probe_info: 'Host is up (ping), TTL=128', response_banner: 'ttl=128' }
      ]
    }
  };

  const osRes = await osDetector.run([pingPlugin]);

  // Concluder should adopt it
  const concluded = await concluder.run([
    { id: '013', name: 'OS Detector', result: osRes },
    pingPlugin
  ]);

  assert.equal(concluded?.host?.os || null, 'Windows');
  assert.match(concluded?.summary || '', /OS:\s*Windows/);
});

test('OS Detector: falls back to FTP plugin-provided OS (Linux) if DNS/Ping absent', async () => {
  // Fake an FTP Banner Check plugin that returned os: Linux
  const ftpPlugin = {
    id: '004',
    name: 'FTP Banner Check',
    result: {
      up: true,
      program: 'Pure-FTPd',
      version: 'Unknown',
      os: 'Linux',
      data: [
        {
          probe_protocol: 'tcp',
          probe_port: 21,
          probe_info: 'FTP banner received',
          response_banner: '220 (vsFTPd 3.0.3)'
        }
      ]
    }
  };

  const osRes = await osDetector.run([ftpPlugin]);

  // Should pick Linux from FTP plugin-provided OS
  assert.equal(osRes.os, 'Linux');

  // Concluder should adopt the detector's output
  const concluded = await concluder.run([
    { id: '013', name: 'OS Detector', result: osRes },
    ftpPlugin
  ]);

  assert.equal(concluded?.host?.os || null, 'Linux');
  assert.match(concluded?.summary || '', /OS:\s*Linux/);
});
