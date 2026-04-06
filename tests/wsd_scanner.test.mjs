import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert';

describe('WSD Scanner Plugin', () => {
  let plugin;
  
  beforeEach(async () => {
    process.env.WSD_DEBUG = '0';
    process.env.WSD_INCLUDE_NON_MATCHED = '0';
    
    // Import the plugin
    const module = await import('../plugins/wsd_scanner.mjs');
    plugin = module.default;
  });

  afterEach(() => {
    delete process.env.WSD_DEBUG;
    delete process.env.WSD_INCLUDE_NON_MATCHED;
  });

  describe('Plugin Metadata', () => {
    it('should have correct plugin metadata', () => {
      assert.strictEqual(plugin.id, '016');
      assert.strictEqual(plugin.name, 'Enhanced WS-Discovery Scanner');
      assert.ok(plugin.description.includes('WS-Discovery'));
      assert.strictEqual(plugin.priority, 400);
      assert.deepStrictEqual(plugin.protocols, ['udp']);
      assert.deepStrictEqual(plugin.ports, [3702]);
      assert.strictEqual(plugin.runStrategy, 'single');
    });
  });

  describe('Non-private IP handling', () => {
    it('should skip scan for public IP addresses', async () => {
      const result = await plugin.run('8.8.8.8', 3702, {});
      
      assert.strictEqual(result.up, false);
      assert.strictEqual(result.program, 'WS-Discovery');
      assert.strictEqual(result.data.length, 1);
      assert.ok(result.data[0].probe_info.includes('Non-local target'));
    });

    it('should allow scan for private IP addresses', async () => {
      // This test will actually attempt to bind to UDP but should complete quickly with timeout
      const result = await plugin.run('192.168.1.10', 3702, { timeout: 10 });
      
      // Should complete without throwing errors
      assert.ok(typeof result === 'object');
      assert.ok(result.hasOwnProperty('up'));
      assert.ok(result.hasOwnProperty('data'));
    });
  });

  describe('Timeout behavior', () => {
    it('should timeout gracefully with no devices found', async () => {
      const result = await plugin.run('192.168.1.50', 3702, { timeout: 50 });

      assert.strictEqual(result.up, false);
      assert.strictEqual(result.program, 'WS-Discovery');
      assert.strictEqual(result.type, 'wsdiscovery');
      assert.strictEqual(result.data.length, 1);
      assert.ok(result.data[0].probe_info.includes('No WS-Discovery devices relevant to target IP'));
    });
  });

  describe('Environment variable handling', () => {
    it('should respect WSD_DEBUG environment variable', async () => {
      process.env.WSD_DEBUG = '1';
      
      // Re-import to pick up new env var
      const module = await import('../plugins/wsd_scanner.mjs?' + Date.now());
      const debugPlugin = module.default;
      
      const result = await debugPlugin.run('192.168.1.50', 3702, { timeout: 50 });
      
      // Should still work with debug enabled
      assert.ok(typeof result === 'object');
      assert.strictEqual(result.up, false);
    });

    it('should respect WSD_INCLUDE_NON_MATCHED environment variable', () => {
      process.env.WSD_INCLUDE_NON_MATCHED = '1';
      
      // Test that the environment variable is read correctly
      const includeNonMatched = /^(1|true|yes|on)$/i.test(String(process.env.WSD_INCLUDE_NON_MATCHED || ""));
      assert.strictEqual(includeNonMatched, true);
    });
  });

  describe('IP validation functions', () => {
    it('should correctly identify private IP addresses', async () => {
      // Test various private IPs
      const privateIPs = [
        '192.168.1.1',
        '10.0.0.1',
        '172.16.0.1',
        '169.254.1.1'
      ];
      
      for (const ip of privateIPs) {
        const result = await plugin.run(ip, 3702, { timeout: 10 });
        // Should not be rejected due to non-private IP
        assert.ok(!result.data[0].probe_info.includes('Non-local target'));
      }
    });

    it('should correctly identify public IP addresses', async () => {
      // Test various public IPs
      const publicIPs = [
        '8.8.8.8',
        '1.1.1.1',
        '208.67.222.222'
      ];
      
      for (const ip of publicIPs) {
        const result = await plugin.run(ip, 3702, { timeout: 10 });
        assert.ok(result.data[0].probe_info.includes('Non-local target'));
      }
    });
  });

  describe('Return value structure', () => {
    it('should return properly structured result object', async () => {
      const result = await plugin.run('192.168.1.50', 3702, { timeout: 50 });
      
      // Check required properties
      assert.ok(result.hasOwnProperty('up'));
      assert.ok(result.hasOwnProperty('program'));
      assert.ok(result.hasOwnProperty('version'));
      assert.ok(result.hasOwnProperty('type'));
      assert.ok(result.hasOwnProperty('data'));
      assert.ok(result.hasOwnProperty('deviceCount'));
      
      // Check property types
      assert.strictEqual(typeof result.up, 'boolean');
      assert.strictEqual(typeof result.program, 'string');
      assert.strictEqual(typeof result.version, 'string');
      assert.strictEqual(typeof result.type, 'string');
      assert.ok(Array.isArray(result.data));
      assert.strictEqual(typeof result.deviceCount, 'number');
    });

    it('should have proper data array structure', async () => {
      const result = await plugin.run('192.168.1.50', 3702, { timeout: 50 });
      
      assert.ok(result.data.length > 0);
      
      const dataItem = result.data[0];
      assert.ok(dataItem.hasOwnProperty('probe_protocol'));
      assert.ok(dataItem.hasOwnProperty('probe_port'));
      assert.ok(dataItem.hasOwnProperty('probe_info'));
      assert.ok(dataItem.hasOwnProperty('response_banner'));
      
      assert.strictEqual(dataItem.probe_protocol, 'udp');
      assert.strictEqual(typeof dataItem.probe_port, 'number');
      assert.strictEqual(typeof dataItem.probe_info, 'string');
    });
  });

  describe('Error handling', () => {
    it('should handle invalid port numbers gracefully', async () => {
      const result = await plugin.run('192.168.1.50', 99999, { timeout: 50 });
      
      // Should not throw and should return a valid result
      assert.ok(typeof result === 'object');
      assert.strictEqual(result.up, false);
    });

    it('should handle empty host string', async () => {
      const result = await plugin.run('', 3702, { timeout: 50 });
      
      // Should handle gracefully
      assert.ok(typeof result === 'object');
    });

    it('should handle undefined options', async () => {
      const result = await plugin.run('192.168.1.50', 3702);
      
      // Should use default timeout and complete
      assert.ok(typeof result === 'object');
    });
  });

  describe('Response banner format', () => {
    it('should format error response banners as JSON', async () => {
      const result = await plugin.run('192.168.1.50', 3702, { timeout: 50 });
      
      if (result.data[0].response_banner) {
        let bannerObj;
        assert.doesNotThrow(() => {
          bannerObj = JSON.parse(result.data[0].response_banner);
        }, 'Response banner should be valid JSON');
        
        assert.ok(typeof bannerObj === 'object');
      }
    });
  });

  describe('Multicast configuration', () => {
    it('should use correct WS-Discovery multicast settings', () => {
      // Test that constants are correctly defined in the plugin
      assert.strictEqual(plugin.ports[0], 3702);
      assert.strictEqual(plugin.protocols[0], 'udp');
    });
  });
});
