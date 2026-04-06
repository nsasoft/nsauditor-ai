// plugins/sunrpc_scanner.mjs
import net from 'node:net';
import dgram from 'node:dgram';

/* ----------------------------- Helpers ----------------------------- */

function xdrEncodeInt(buffer, value, offset) {
    buffer.writeUInt32BE(value >>> 0, offset);
    return offset + 4;
}

function xdrDecodeInt(buffer, offset) {
  const value = buffer.readInt32BE(offset);
  return { value, newOffset: offset + 4 };
}

// Robust parser that handles both simplified replies (no accept_stat) and proper RPC replies (with accept_stat).
function parseRpcPortFromReply(msg) {
  // msg is expected to start at XID (no TCP record marker)
  // Minimum valid RPC reply is 24 bytes
  if (msg.length < 24) {
    return null;
  }

  try {
    // Layout:
    //  0: xid
    //  4: msg_type (should be 1 for REPLY)
    //  8: reply_stat (should be 0 for ACCEPTED)
    // 12: verifier_flavor
    // 16: verifier_length
    // 20: verifier_body (padded to 4) -> accept_stat -> result (port)
    const msgType = msg.readUInt32BE(4);
    const replyState = msg.readUInt32BE(8);
    if (msgType !== 1 || replyState !== 0) return null;

    // Compute offset after opaque_auth verifier (flavor,len,body[padded])
    if (msg.length >= 20) {
      const verflen = msg.readUInt32BE(16) >>> 0;
      const pad = (4 - (verflen % 4)) % 4;
      const acceptOff = 20 + verflen + pad;

      // Proper RPC reply with accept_stat followed by result (port) on success
      if (msg.length >= acceptOff + 8) {
        const acceptStat = msg.readUInt32BE(acceptOff);
        if (acceptStat === 0 /* SUCCESS */) {
          const port = msg.readUInt32BE(acceptOff + 4);
          return port > 0 && port <= 65535 ? port : null;
        }
      }
    }

    // Fallback: treat offset 20 as port directly (simplified responders)
    if (msg.length >= 24) {
      const port = msg.readUInt32BE(20);
      return port > 0 && port <= 65535 ? port : null;
    }
  } catch {
    return null;
  }
  return null;
}

async function getRpcPortTcp(host, program, version, timeout = 1000, rpcPort = 111) {
  return new Promise((resolve, reject) => {
    const socket = new net.Socket();
    socket.setTimeout(timeout);
    let receivedData = Buffer.alloc(0);
    let expectedLength = null;
    let done = false;

    const finalize = (val) => {
      if (done) return;
      done = true;
      clearTimeout(timeoutId);
      socket.removeAllListeners();
      try { 
        socket.end();
        socket.destroy(); 
      } catch {}
      resolve(val);
    };

    let timeoutId = setTimeout(() => {
      finalize(null);
    }, timeout);

    socket.on('error', () => {
      finalize(null);
    });

    socket.on('timeout', () => {
      finalize(null);
    });

    socket.on('close', () => {
      // Connection closed. Try to parse any data we might have received.
      if (expectedLength !== null && receivedData.length >= expectedLength + 4) {
        const rpcMessage = receivedData.slice(4, expectedLength + 4);
        const port = parseRpcPortFromReply(rpcMessage);
        return finalize(port);
      }
      finalize(null);
    });

    socket.on('data', (data) => {
      if (done) return;
      receivedData = Buffer.concat([receivedData, data]);

      // Parse TCP record marker
      if (expectedLength === null && receivedData.length >= 4) {
        const header = receivedData.readUInt32BE(0);
        const lastFragment = (header & 0x80000000) !== 0;
        expectedLength = header & 0x7FFFFFFF;

        // Sanity checks
        if (!lastFragment || expectedLength === 0 || expectedLength > 8192) {
          return finalize(null);
        }
      }

      // Check if we have complete message
      if (expectedLength !== null && receivedData.length >= expectedLength + 4) {
        const rpcMessage = receivedData.slice(4, expectedLength + 4);
        const port = parseRpcPortFromReply(rpcMessage);
        return finalize(port);
      }
    });

    socket.connect(rpcPort, host, () => {
      if (done) return;
      
      const transactionId = Math.floor(Math.random() * 0xFFFFFFFF);
      // Proper RPC CALL with cred/verifier (AUTH_NULL) + PMAP GETPORT args
      const rpcMessage = Buffer.alloc(56); // 14 * 4-byte integers
      let offset = 0;

      // RPC call header
      offset = xdrEncodeInt(rpcMessage, transactionId, offset); // xid
      offset = xdrEncodeInt(rpcMessage, 0, offset); // CALL
      offset = xdrEncodeInt(rpcMessage, 2, offset); // RPC version

      const rpcbindProgram = 100000;
      const rpcbindVersion = 2;
      const getPortProcedure = 3;

      offset = xdrEncodeInt(rpcMessage, rpcbindProgram, offset);
      offset = xdrEncodeInt(rpcMessage, rpcbindVersion, offset);
      offset = xdrEncodeInt(rpcMessage, getPortProcedure, offset);

      // AUTH credentials (AUTH_NULL)
      offset = xdrEncodeInt(rpcMessage, 0, offset); // cred flavor
      offset = xdrEncodeInt(rpcMessage, 0, offset); // cred length

      // AUTH verifier (AUTH_NULL)
      offset = xdrEncodeInt(rpcMessage, 0, offset); // verf flavor
      offset = xdrEncodeInt(rpcMessage, 0, offset); // verf length

      // PMAP_GETPORT args: program, version, protocol, port(0)
      offset = xdrEncodeInt(rpcMessage, program, offset);
      offset = xdrEncodeInt(rpcMessage, version, offset);
      offset = xdrEncodeInt(rpcMessage, 6, offset); // TCP
      offset = xdrEncodeInt(rpcMessage, 0, offset);

      const frameHeader = Buffer.alloc(4);
      frameHeader.writeUInt32BE((rpcMessage.length | 0x80000000) >>> 0, 0);
      const packet = Buffer.concat([frameHeader, rpcMessage]);
      
      socket.write(packet, (err) => {
        if (err && !done) {
          finalize(null);
        }
      });
    });
  });
}

async function getRpcPortUdp(host, program, version, timeout = 1000, rpcPort = 111) {
  return new Promise((resolve, reject) => {
    const client = dgram.createSocket('udp4');
    let done = false;
    const finalize = (val) => {
      if (done) return;
      done = true;
      clearTimeout(timeoutId);
      client.removeAllListeners();
      try { client.close(); } catch {}
      resolve(val);
    };

    let timeoutId = setTimeout(() => {
      finalize(null); // Timeout treated as normal failure case
    }, timeout);

    client.on('error', () => {
      finalize(null); // Network errors treated as normal failure case
    });

    client.on('message', (msg) => {
      if (done) return;
      // UDP reply starts at XID (no record marker)
      const port = parseRpcPortFromReply(msg);
      finalize(port);
    });

    // Construct the rpcbind GETPORT packet with AUTH_NULL cred/verifier
    const transactionId = Math.floor(Math.random() * 0xFFFFFFFF);
    const packet = Buffer.alloc(56); // 14 * 4-byte integers
    let offset = 0;

    // RPC call header
    offset = xdrEncodeInt(packet, transactionId, offset); // xid
    offset = xdrEncodeInt(packet, 0, offset); // CALL
    offset = xdrEncodeInt(packet, 2, offset); // RPC version

    const rpcbindProgram = 100000;
    const rpcbindVersion = 2;
    const getPortProcedure = 3;

    offset = xdrEncodeInt(packet, rpcbindProgram, offset);
    offset = xdrEncodeInt(packet, rpcbindVersion, offset);
    offset = xdrEncodeInt(packet, getPortProcedure, offset);

    // AUTH credentials (AUTH_NULL)
    offset = xdrEncodeInt(packet, 0, offset); // cred flavor
    offset = xdrEncodeInt(packet, 0, offset); // cred length

    // AUTH verifier (AUTH_NULL)
    offset = xdrEncodeInt(packet, 0, offset); // verf flavor
    offset = xdrEncodeInt(packet, 0, offset); // verf length

    // PMAP_GETPORT args: program, version, protocol, port(0)
    offset = xdrEncodeInt(packet, program, offset);
    offset = xdrEncodeInt(packet, version, offset);
    offset = xdrEncodeInt(packet, 17, offset); // UDP
    offset = xdrEncodeInt(packet, 0, offset);

    client.send(packet, rpcPort, host, (err) => {
      if (err) {
        finalize(null);
      }
    });
  });
}

/* ----------------------------- Scanner Plugin ----------------------------- */

// Reduced set for faster scanning
const RPC_PROGRAMS = [
  { num: 100000, name: 'PORTMAPPER', versions: [2] },
  { num: 100003, name: 'NFS', versions: [3] },
  { num: 100005, name: 'MOUNTD', versions: [1] }
];

export default {
  id: "015", 
  name: "SUN RPC Scanner",
  description: "Scans for RPC services via portmapper on TCP/UDP 111 including NFS, mountd and others",
  priority: 350,
  requirements: {},
  protocols: ["tcp", "udp"],
  ports: [111],

  async run(host, port=111, opts={}) {
    const data = [];
    let up = false;
    let program = "Unknown";
    let version = "Unknown";
    
    // Determine which protocols to scan based on opts or default to both
    const protocols = opts.protocol ? [opts.protocol] : ['tcp', 'udp'];
    const timeout = opts.timeout || 1000;

    // Scan each RPC program using provided port and protocols
    for (const protocol of protocols) {
      for (const prog of RPC_PROGRAMS) {
        for (const ver of prog.versions) {
          try {
            const getRpcPort = protocol === 'tcp' ? getRpcPortTcp : getRpcPortUdp;
            const detectedPort = await getRpcPort(host, prog.num, ver, timeout, port);
            
            if (detectedPort) {
              up = true;
              program = "SUN RPC";
              
              data.push({
                // normalized evidence fields (preferred by reports)
                from: 'sunrpc',
                protocol,
                port: detectedPort,
                info: `RPC ${prog.name} v${ver} (${protocol.toUpperCase()})`,
                banner: `Program ${prog.num} Version ${ver} on port ${detectedPort} via ${protocol.toUpperCase()}`,
                status: 'open',
                service: prog.name.toLowerCase(),

                // keep legacy probe_* fields for compatibility
                probe_protocol: protocol,
                probe_port: detectedPort,
                probe_info: `RPC ${prog.name} v${ver} (${protocol.toUpperCase()})`,
                response_banner: `Program ${prog.num} Version ${ver} on port ${detectedPort} via ${protocol.toUpperCase()}`
              });
              
              // Exit early after finding first service to speed up testing
              if (opts.protocol) return { up, program, version, type: 'sunrpc', data };
            }
          } catch {
            // Individual program/version failures are ignored
          }
        }
      }
    }

    if (!up) {
      data.push({
        from: 'sunrpc',
        protocol: protocols[0],
        port,
        info: 'No RPC services found',
        banner: null,
        status: 'filtered',
        service: 'sunrpc',

        // legacy fields
        probe_protocol: protocols[0],
        probe_port: port,
        probe_info: 'No RPC services found',
        response_banner: null
      });
    }

    return {
      up,
      program,
      version,
      type: 'sunrpc',
      data
    };
  }
};