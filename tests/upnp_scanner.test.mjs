// tests/upnp_scanner.test.mjs
import test from 'node:test';
import assert from 'node:assert/strict';

function makeUpnpFake() {
  const devices = [
    {
      address: '192.168.1.24',
      headers: {
        '$': 'HTTP/1.1 200 OK',
        'CACHE-CONTROL': 'max-age=600',
        'LOCATION': 'http://192.168.1.24:1990/WFADevice.xml',
        'SERVER': 'POSIX UPnP/1.0 UPnP Stack/7.14.170.1708',
        'ST': 'upnp:rootdevice',
        'USN': 'uuid:4394656a-2942-211a-3017-615a2a38c40f::upnp:rootdevice'
      },
      descriptionXML: '<?xml version="1.0"?><root xmlns="urn:schemas-upnp-org:device-1-0"><device><friendlyName>WFADevice</friendlyName></device></root>'
    },
    {
      address: '192.168.1.88', 
      headers: {
        '$': 'HTTP/1.1 200 OK',
        'CACHE-CONTROL': 'max-age=600',
        'LOCATION': 'http://192.168.1.88:5000/Public_UPNP_gatedesc.xml',
        'SERVER': 'Linux/2.6.12, UPnP/1.0, NETGEAR-UPNP/1.0',
        'ST': 'upnp:rootdevice',
        'USN': 'uuid:d1c05e1b-d45c-89c6-3be8-6c218ca74e15::upnp:rootdevice'
      }
    }
  ];

  return {
    discover: async ({ timeout }) => {
      await new Promise(resolve => setTimeout(resolve, Math.min(timeout, 50)));
      return devices;
    }
  };
}

test('UPnP Scanner: non-local target is skipped quickly', async () => {
  const { default: upnpScanner } = await import('../plugins/upnp_scanner.mjs');
  const out = await upnpScanner.run('8.8.8.8', 1900, {});
  
  assert.equal(out.up, false);
  assert.equal(out.program, 'UPnP/SSDP');
  assert.equal(Array.isArray(out.data), true);
  assert.ok(out.data.some(r => /Non-local target/i.test(String(r.probe_info))));
});

test('UPnP Scanner: matches target host IP and records rows', async () => {
  // Set up mock before importing the plugin
  process.env.UPNP_TEST_FAKE = '1';
  process.env.DEBUG_MODE = '1'; 
  process.env.UPNP_INCLUDE_NON_MATCHED = '1';
  globalThis.__upnpFakeFactory = () => makeUpnpFake();

  const { default: upnpScanner } = await import('../plugins/upnp_scanner.mjs');
  const out = await upnpScanner.run('192.168.1.24', 1900, { timeoutMs: 200 });

  // Enhanced debugging output
  console.log('Raw scanner output:', JSON.stringify(out, null, 2));
  
  if (out.data) {
    console.log('\nAnalyzing each row:');
    out.data.forEach((row, i) => {
      console.log(`\nRow ${i + 1}:`, {
        probe_info: row.probe_info,
        os: row.os,
        osVersion: row.osVersion,
        response_banner: row.response_banner ? JSON.parse(row.response_banner) : null
      });
    });
  }

  // Basic scan result assertions
  assert.equal(out.program, 'UPnP/SSDP');
  assert.equal(out.type, 'upnp');
  assert.equal(Array.isArray(out.data), true);
  assert.ok(out.data.length >= 1, 'should record at least one UPnP row');

  // More flexible match verification
  const hasMatch = out.data.some(row => {
    const probeInfo = String(row.probe_info || '');
    const banner = row.response_banner ? JSON.parse(row.response_banner) : {};
    
    const checks = {
      hasTargetIP: probeInfo.includes('192.168.1.24'),
      hasMatchedText: /matched host/i.test(probeInfo),
      hasBannerMatch: banner.address === '192.168.1.24',
      hasLocationMatch: banner.headers?.LOCATION?.includes('192.168.1.24')
    };
    
    console.log('\nMatch criteria for row:', checks);
    
    return checks.hasTargetIP || checks.hasMatchedText || 
           checks.hasBannerMatch || checks.hasLocationMatch;
  });

  assert.ok(hasMatch, 'should find target IP 192.168.1.24 in results');

  // Verify POSIX device detection
  const posixDevice = out.data.find(r => {
    const banner = r.response_banner ? JSON.parse(r.response_banner) : {};
    return r.os === 'POSIX' || banner.headers?.SERVER?.includes('POSIX');
  });
  
  assert.ok(posixDevice, 'should detect POSIX device');

  // Service status check
  assert.equal(out.up, true, 'UPnP service should be detected as up');

  // Clean up test environment
  delete process.env.UPNP_TEST_FAKE;
  delete process.env.DEBUG_MODE;
  delete process.env.UPNP_INCLUDE_NON_MATCHED;
  delete globalThis.__upnpFakeFactory;
});