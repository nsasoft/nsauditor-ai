// tests/os_detector_upnp.test.mjs
import test from 'node:test';
import assert from 'node:assert/strict';

import osDetector from '../plugins/os_detector.mjs';
import concluder from '../plugins/result_concluder.mjs';

const UPNP_BANNER = '{"address":"192.168.1.12","headers":{"USN":"uuid:4d696e69-444c-164e-9d41-506a03a76cbc::upnp:rootdevice","SERVER":"Linux 2.6 DLNADOC/1.50 UPnP/1.0 ReadyDLNA/1.0.25","ST":"upnp:rootdevice","LOCATION":"http://192.168.1.12:8200/rootDesc.xml"},"descriptionXML":null}';

test('OS Detector: infers OS and version from UPnP Scanner data', async () => {
  // Mock a UPnP Scanner plugin result with OS and version
  const upnpPlugin = {
    id: '017',
    name: 'UPnP Scanner',
    result: {
      up: true,
      program: 'UPnP/SSDP',
      version: 'Unknown',
      data: [
        {
          probe_protocol: 'upnp',
          probe_port: 1900,
          probe_info: 'Matched host — type=upnp:rootdevice address=192.168.1.12 location=http://192.168.1.12:8200/rootDesc.xml',
          response_banner: UPNP_BANNER,
          os: 'Linux',
          osVersion: '2.6'
        }
      ]
    }
  };

  // Run the OS Detector with the UPnP plugin result
  const osRes = await osDetector.run([upnpPlugin], null, { results: [upnpPlugin], context: { host: '192.168.1.12' } });

  assert.equal(osRes.program, 'OS Detector');
  assert.equal(osRes.os, 'Linux', 'should infer OS as Linux from UPnP data');
  assert.equal(osRes.osVersion, '2.6', 'should infer osVersion as 2.6 from UPnP data');
  assert.ok(osRes.osExtras?.upnp, 'should set upnp flag in osExtras');
  assert.ok(Array.isArray(osRes.data) && osRes.data.length >= 1, 'should emit evidence rows');
  const upnpRow = osRes.data.find(d => d.probe_protocol === 'upnp' && d.probe_port === 1900);
  assert.ok(!!upnpRow, 'expected a UPnP evidence row');
  assert.ok(upnpRow.probe_info.includes('UPnP evidence'), 'evidence row should indicate UPnP source');
});

test('OS Detector + Concluder: concluder adopts UPnP-derived OS', async () => {
  const upnpPlugin = {
    id: '017',
    name: 'UPnP Scanner',
    result: {
      up: true,
      program: 'UPnP/SSDP',
      version: 'Unknown',
      data: [
        {
          probe_protocol: 'upnp',
          probe_port: 1900,
          probe_info: 'Matched host — type=upnp:rootdevice address=192.168.1.12 location=http://192.168.1.12:8200/rootDesc.xml',
          response_banner: UPNP_BANNER,
          os: 'Linux',
          osVersion: '2.6'
        }
      ]
    }
  };

  const osRes = await osDetector.run([upnpPlugin], null, { results: [upnpPlugin], context: { host: '192.168.1.12' } });

  // Concluder accepts an array of { name/id, result } items
  const concluded = await concluder.run([
    { id: '013', name: 'OS Detector', result: osRes },
    upnpPlugin
  ]);

  assert.equal(concluded?.host?.os, 'Linux', 'concluder should pick OS as Linux from OS Detector');
  assert.equal(concluded?.host?.osVersion, '2.6', 'concluder should pick osVersion as 2.6 from OS Detector');
  assert.match(concluded?.summary || '', /OS:\s*Linux/, 'summary should include Linux OS');
  assert.match(concluded?.summary || '', /Version:\s*2\.6/, 'summary should include version 2.6');
});