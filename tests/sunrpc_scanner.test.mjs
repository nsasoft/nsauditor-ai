//tests/sunrpc_scanner.test.mjs
import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import dgram from 'node:dgram';
import plugin from '../plugins/sunrpc_scanner.mjs';

describe('SUN RPC Scanner Plugin', () => {
  let server;
  let udpServer;
  const TEST_PORT = 51111; // Use high port for testing
  const TEST_UDP_PORT = 51112;
  const TEST_HOST = '127.0.0.1';

  beforeEach(async () => {
    // Create mock TCP RPC server
    server = net.createServer();
    await new Promise((resolve) => {
      server.listen(TEST_PORT, TEST_HOST, resolve);
    });
    
    // Create mock UDP RPC server
    udpServer = dgram.createSocket('udp4');
    await new Promise((resolve) => {
      udpServer.bind(TEST_UDP_PORT, TEST_HOST, resolve);
    });
  });

  afterEach(async () => {
    // Cleanup with proper error handling
    const promises = [];
    
    if (server && server.listening) {
      promises.push(new Promise(resolve => {
        server.close(() => resolve());
      }));
    }
    
    if (udpServer) {
      promises.push(new Promise(resolve => {
        udpServer.close(() => resolve());
      }));
    }
    
    await Promise.all(promises);
    server = null;
    udpServer = null;
  });

  it('should have correct plugin metadata', () => {
    assert.equal(plugin.id, "015");
    assert.equal(plugin.name, "SUN RPC Scanner");
    assert.deepEqual(plugin.protocols, ["tcp", "udp"]);
    assert.deepEqual(plugin.ports, [111]);
  });

  it('should handle connection failures gracefully', async () => {
    const result = await plugin.run('0.0.0.0', 111);
    assert.equal(result.up, false);
    assert.equal(result.program, "Unknown");
    assert.equal(result.type, "sunrpc");
    assert.ok(Array.isArray(result.data));
    assert.ok(result.data.some(d => d.probe_info === 'No RPC services found'));
  });

  it('should detect RPC services when present', async () => {
    let responseCount = 0;
    
    // Setup mock RPC server response before running the test
    server.removeAllListeners('connection');
    server.on('connection', socket => {
      socket.setTimeout(1000); // Prevent hanging
      
      socket.on('data', data => {
        try {
          // Only respond to the first valid RPC request
          if (responseCount > 0) {
            socket.end();
            return;
          }
          
          // Validate incoming RPC request has frame header + RPC call
          if (data.length < 60) {
            socket.end();
            return;
          }
          
          // Extract frame header and transaction ID
          const frameSize = data.readUInt32BE(0) & 0x7FFFFFFF;
          const xid = data.readUInt32BE(4);
          const msgType = data.readUInt32BE(8);
          
          // Verify it's a CALL (0) message
          if (msgType !== 0) {
            socket.end();
            return;
          }
          
          responseCount++;
          
          // Send proper RPC reply with frame header
          const response = Buffer.alloc(32);
          // Frame header: last fragment bit + 28 bytes payload
          response.writeUInt32BE(0x8000001c, 0);
          // RPC reply
          response.writeUInt32BE(xid, 4);      // echo transaction ID
          response.writeUInt32BE(1, 8);        // REPLY
          response.writeUInt32BE(0, 12);       // ACCEPTED
          response.writeUInt32BE(0, 16);       // AUTH_NULL flavor
          response.writeUInt32BE(0, 20);       // verifier length
          response.writeUInt32BE(0, 24);       // SUCCESS
          response.writeUInt32BE(2049, 28);    // NFS port
          
          socket.write(response, () => {
            socket.end();
          });
        } catch (err) {
          socket.destroy();
        }
      });
      
      socket.on('error', () => {
        socket.destroy();
      });
      
      socket.on('timeout', () => {
        socket.destroy();
      });
    });

    // Small delay to ensure server is ready
    await new Promise(resolve => setTimeout(resolve, 10));

    const result = await plugin.run(TEST_HOST, TEST_PORT, { protocol: 'tcp', timeout: 500 });
    
    assert.ok(result.data.length > 0, 'Should have scan results');
    assert.equal(result.up, true);
    assert.equal(result.program, "SUN RPC");
    assert.equal(result.type, "sunrpc");
  });

  it('should handle malformed RPC responses', async () => {
    server.removeAllListeners('connection');
    server.on('connection', socket => {
      socket.setTimeout(500);
      
      socket.on('data', () => {
        try {
          // Send response that looks like a frame but with invalid RPC data
          const response = Buffer.alloc(8);
          response.writeUInt32BE(0x80000004, 0); // 4-byte payload
          response.writeUInt32BE(0xFFFFFFFF, 4); // Invalid data
          
          socket.write(response, () => {
            socket.end();
          });
        } catch (err) {
          socket.destroy();
        }
      });
      
      socket.on('error', () => socket.destroy());
      socket.on('timeout', () => socket.destroy());
    });

    await new Promise(resolve => setTimeout(resolve, 10));

    const result = await plugin.run(TEST_HOST, TEST_PORT, { protocol: 'tcp', timeout: 300 });
    assert.equal(result.up, false);
    assert.ok(result.data.some(d => d.probe_info === 'No RPC services found'));
  });

  it('should handle connection failures gracefully', async () => {
    const result = await plugin.run('0.0.0.0', 111);
    assert.equal(result.up, false);
    assert.equal(result.program, "Unknown");
    assert.equal(result.type, "sunrpc");
    assert.ok(Array.isArray(result.data));
    assert.ok(result.data.some(d => d.probe_info === 'No RPC services found'));
  });

  it('should detect UDP RPC services when present', async () => {
    // Setup mock UDP RPC server response
    udpServer.removeAllListeners('message');
    udpServer.on('message', (msg, rinfo) => {
      try {
        // Validate minimum RPC call size
        if (msg.length < 56) return;
        
        // Extract transaction ID and verify it's a CALL
        const xid = msg.readUInt32BE(0);
        const msgType = msg.readUInt32BE(4);
        
        if (msgType !== 0) return; // Not a CALL
        
        // Send proper RPC reply (no frame header for UDP)
        const response = Buffer.alloc(28);
        response.writeUInt32BE(xid, 0);      // echo transaction ID
        response.writeUInt32BE(1, 4);        // REPLY
        response.writeUInt32BE(0, 8);        // ACCEPTED
        response.writeUInt32BE(0, 12);       // AUTH_NULL flavor
        response.writeUInt32BE(0, 16);       // verifier length
        response.writeUInt32BE(0, 20);       // SUCCESS
        response.writeUInt32BE(2049, 24);    // NFS port
        
        udpServer.send(response, rinfo.port, rinfo.address);
      } catch (err) {
        // Ignore errors in mock server
      }
    });

    await new Promise(resolve => setTimeout(resolve, 10));

    const result = await plugin.run(TEST_HOST, TEST_UDP_PORT, { protocol: 'udp', timeout: 300 });
    
    assert.ok(result.data.length > 0, 'Should have scan results');
    assert.equal(result.up, true);
    assert.equal(result.program, "SUN RPC");
    assert.equal(result.type, "sunrpc");
    assert.ok(result.data.some(d => d.probe_protocol === 'udp'));
  });

  it('should handle UDP connection failures gracefully', async () => {
    const result = await plugin.run('0.0.0.0', 111, { protocol: 'udp' });
    assert.equal(result.up, false);
    assert.equal(result.program, "Unknown");
    assert.equal(result.type, "sunrpc");
    assert.ok(Array.isArray(result.data));
    assert.ok(result.data.some(d => d.probe_info === 'No RPC services found'));
  });

  it('should handle malformed UDP RPC responses', async () => {
    udpServer.removeAllListeners('message');
    udpServer.on('message', (msg, rinfo) => {
      try {
        // Send completely invalid response
        const badResponse = Buffer.from([0xFF, 0xFF, 0xFF, 0xFF]);
        udpServer.send(badResponse, rinfo.port, rinfo.address);
      } catch (err) {
        // Ignore errors in mock server
      }
    });

    await new Promise(resolve => setTimeout(resolve, 10));

    const result = await plugin.run(TEST_HOST, TEST_UDP_PORT, { protocol: 'udp', timeout: 300 });
    assert.equal(result.up, false);
    assert.ok(result.data.some(d => d.probe_info === 'No RPC services found'));
  });

  it('should handle UDP connection timeouts', async () => {
    // Close server to simulate timeout
    if (udpServer) {
      await new Promise(resolve => {
        udpServer.close(resolve);
      });
      udpServer = null; // Set to null so afterEach doesn't try to close it again
    }

    const result = await plugin.run(TEST_HOST, TEST_UDP_PORT, { protocol: 'udp', timeout: 200 });
    assert.equal(result.up, false);
    assert.equal(result.program, "Unknown");
    assert.ok(result.data.some(d => d.probe_info === 'No RPC services found'));
  });
});