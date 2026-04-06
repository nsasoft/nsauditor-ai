import test from 'node:test';
import assert from 'node:assert/strict';
import mdnsScanner from '../plugins/mdns_scanner.mjs';

function makeMdnsFake() {
  const handlers = { response: [] };
  let destroyed = false;

  const api = {
    on(evt, fn) {
      if (!handlers[evt]) handlers[evt] = [];
      handlers[evt].push(fn);
    },
    removeListener(evt, fn) {
      if (!handlers[evt]) return;
      handlers[evt] = handlers[evt].filter(f => f !== fn);
    },
    query(_q) {
      // Emit service registry
      setTimeout(() => {
        const resp1 = {
          answers: [
            { type: 'PTR', name: '_services._dns-sd._udp.local', data: '_http._tcp.local' }
          ]
        };
        handlers.response.forEach(fn => fn(resp1));
      }, 5);

      // Emit one SRV instance + A hit on target
      setTimeout(() => {
        const serviceFqdn = 'EPSON\\032ET-2720\\032Series._http._tcp.local';
        const targetFqdn  = 'EPSONB121D4.local';
        const targetIPHit = '192.168.1.24';
        const targetIPMiss = '192.168.1.88';

        const resp2 = {
          answers: [
            { type: 'SRV', name: serviceFqdn, data: { target: targetFqdn, port: 80 } },
            { type: 'A', name: targetFqdn, data: targetIPMiss },
          ],
          additionals: [
            { type: 'A', name: targetFqdn, data: targetIPHit }, // the match
            { type: 'TXT', name: serviceFqdn, data: ['ty=EPSON ET-2720 Series', 'adminurl=http://printer/'] },
          ],
        };
        handlers.response.forEach(fn => fn(resp2));
      }, 15);
    },
    destroy() { destroyed = true; },
    get _destroyed() { return destroyed; }
  };
  return api;
}

test('MDNS Scanner: non-local target is skipped quickly', async () => {
  const out = await mdnsScanner.run('8.8.8.8', 0, {});
  assert.equal(out.up, false);
  assert.equal(out.program, 'mDNS/Bonjour');
  assert.equal(Array.isArray(out.data), true);
  assert.ok(out.data.some(r => /Non-local target/i.test(String(r.probe_info))));
});

test('MDNS Scanner: multicast-dns fallback matches target host IP and records rows', async () => {
  // Force the plugin to use the multicast-dns path
  process.env.MDNS_FORCE_FALLBACK = '1';

  // Provide a fake multicast-dns implementation
  process.env.MDNS_TEST_FAKE = '1';
  globalThis.__mdnsFakeFactory = () => makeMdnsFake();

  const out = await mdnsScanner.run('192.168.1.24', 0, { timeoutMs: 200 });

  // cleanup env
  delete process.env.MDNS_TEST_FAKE;
  delete process.env.MDNS_FORCE_FALLBACK;
  delete globalThis.__mdnsFakeFactory;

  assert.equal(out.program, 'mDNS/Bonjour');
  assert.equal(out.type, 'mdns');
  assert.equal(Array.isArray(out.data), true);
  assert.ok(out.data.length >= 1, 'should record at least one mDNS row');
  assert.ok(out.data.some(r => /Matched host IP/i.test(String(r.probe_info))));
  assert.equal(out.up, true);
});
