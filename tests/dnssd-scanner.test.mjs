//tests/dnssd-scanner.test.mjs
import test from 'node:test';
import assert from 'node:assert/strict';

// Mock services data
const MOCK_SERVICES = [
  {
    name: 'Example Printer',
    type: '_printer._tcp',
    port: 631,
    addresses: ['192.168.1.24'],
    txt: {
      model: 'LaserJet Pro',
      status: 'idle',
      queue: '0'
    }
  },
  {
    name: 'Media Server',
    type: '_http._tcp',
    port: 8080,
    addresses: ['192.168.1.88'],
    txt: {
      path: '/media',
      version: '1.0'
    }
  }
];

function makeDnssdFake() {
  return {
    createBrowser(type) {
      const handlers = new Map();
      const matchingServices = MOCK_SERVICES.filter(s => s.type === type || type === 'any');
      
      return {
        start() {
          // Emit services on next tick
          process.nextTick(() => {
            matchingServices.forEach(service => {
              const handler = handlers.get('serviceUp');
              if (handler) handler(service);
            });
          });
          return this;
        },
        stop() {
          process.nextTick(() => {
            matchingServices.forEach(service => {
              const handler = handlers.get('serviceDown');
              if (handler) handler({
                name: service.name,
                type: service.type,
                addresses: service.addresses
              });
            });
          });
          return this;
        },
        on(event, callback) {
          handlers.set(event, callback);
          return this;
        }
      };
    }
  };
}

test('DNS-SD Scanner: matches target host IP and records services', async () => {
  // Set up environment and mock
  process.env.DNSSD_TEST_FAKE = '1';
  process.env.DEBUG_MODE = '1';
  
  // Mock the dnssd module
  const mockDnssd = makeDnssdFake();
  globalThis.__dnssdFakeFactory = () => mockDnssd;
  
  const { default: dnssdScanner } = await import('../plugins/dnssd-scanner.mjs?update=' + Date.now());
  const out = await dnssdScanner.run('192.168.1.24', 5353, { timeoutMs: 1000 });

  console.log('Raw scanner output:', JSON.stringify(out, null, 2));

  // Basic assertions
  assert.equal(out.program, 'DNS-SD/mDNS');
  assert.ok(Array.isArray(out.data), 'data should be an array');
  assert.ok(out.data.length >= 1, 'should record at least one service');

  // Verify printer service
  const printerService = out.data.find(row => 
    row.probe_info?.includes('_printer._tcp')
  );
  assert.ok(printerService, 'should detect printer service');

  // Clean up
  delete process.env.DNSSD_TEST_FAKE;
  delete process.env.DEBUG_MODE;
  delete globalThis.__dnssdFakeFactory;
});

test('DNS-SD Scanner: handles service down events', async () => {
  // Set up environment and mock
  process.env.DNSSD_TEST_FAKE = '1';
  
  const mockDnssd = makeDnssdFake();
  globalThis.__dnssdFakeFactory = () => mockDnssd;

  const { default: dnssdScanner } = await import('../plugins/dnssd-scanner.mjs?update=' + Date.now());
  const out = await dnssdScanner.run('192.168.1.24', 5353, { timeoutMs: 500 });
  
  // Verify service detection
  assert.ok(out.data.some(row => 
    row.probe_info?.includes('went offline') ||
    row.probe_info?.includes('service unavailable')
  ), 'should detect offline services');

  // Clean up
  delete process.env.DNSSD_TEST_FAKE;
  delete globalThis.__dnssdFakeFactory;
});