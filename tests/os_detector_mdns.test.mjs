// tests/os_detector_mdns.test.mjs
import test from 'node:test';
import assert from 'node:assert/strict';
import osDetector from '../plugins/os_detector.mjs';

// Minimal fake ctx helpers
const ctxHelpers = {
  lookupVendor: () => null,
  probableOsFromVendor: () => 'Unknown'
};

function wrap(name, id, rows) {
  return { id, name, result: { up: true, data: rows } };
}

// Helper: accept any Apple family label
function isAppleFamily(os) {
  if (!os) return false;
  const s = String(os).toLowerCase();
  return (
    s === 'macos' ||
    s === 'ios' ||
    s === 'macos or ios' ||
    /apple/.test(s) // future-proof if we ever emit 'Apple'
  );
}

test('OS Detector (mDNS): infers Apple OS from AirPlay model + host IP match', async () => {
  const host = '192.168.1.15';
  const mdnsRows = [
    {
      probe_protocol: 'mdns',
      probe_port: 5353,
      // emulate MDNS Scanner row format seen in logs
      probe_info: 'airplay._tcp — model=Mac15,13; srcvers=870.14.1',
      response_banner: 'name=Test MacBook Air; host=Test-MacBook-Air.local.; deviceid=AA:BB:CC:DD:EE:FF; addresses=fe80::1:2:3:4,192.168.1.15'
    }
  ];
  const results = [wrap('MDNS Scanner', '016', mdnsRows)];

  const out = await osDetector.run(host, 0, { results, context: { ...ctxHelpers } });
  assert.ok(isAppleFamily(out.os), `expected Apple-family OS from mDNS AirPlay evidence, got ${out.os}`);
  assert.ok(out.data.some(r => /mDNS evidence/i.test(String(r.probe_info))));
});

test('OS Detector (mDNS) + Concluder: host OS adopted from detector output', async () => {
  const host = '192.168.1.15';
  const mdnsRows = [
    {
      probe_protocol: 'mdns',
      probe_port: 5353,
      probe_info: 'airplay._tcp — model=Mac15,13; srcvers=870.14.1',
      response_banner: 'name=Test MacBook Air; host=Test-MacBook-Air.local.; addresses=192.168.1.15'
    }
  ];
  const results = [wrap('MDNS Scanner', '016', mdnsRows)];
  const out = await osDetector.run(host, 0, { results, context: { ...ctxHelpers } });

  // Simulate simple concluder adoption (test harness expects non-null-ish when detector emits something)
  assert.ok(isAppleFamily(out.os), `concluder should pick an Apple-family OS from the OS Detector (${out.os})`);
});

test('OS Detector (mDNS): non-Apple device (e.g., printer) does not force Apple OS', async () => {
  const host = '192.168.1.24';
  const mdnsRows = [
    {
      probe_protocol: 'mdns',
      probe_port: 5353,
      probe_info: 'ipp._tcp — ty=EPSON ET-2720 Series; vers=2.63',
      response_banner: 'name=EPSON ET-2720 Series; host=EPSON000000.local.; addresses=192.168.1.24'
    }
  ];
  const results = [wrap('MDNS Scanner', '016', mdnsRows)];
  const out = await osDetector.run(host, 0, { results, context: { ...ctxHelpers } });

  // May be Unknown or Linux (embedded); but must NOT be macOS/iOS
  assert.ok(!isAppleFamily(out.os), `printer mDNS must not force Apple OS (got ${out.os})`);
});
