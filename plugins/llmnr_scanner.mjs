// LLMNR Scanner — probes Link-Local Multicast Name Resolution (UDP/5355)
// Discovers hosts/services responding to LLMNR queries on the local network.

import dgram from "node:dgram";
import crypto from "node:crypto";

function buildLlmnrQuery(hostname) {
  // Build a minimal LLMNR query packet for the given hostname (type A)
  // See RFC 4795 for details
  const tid = crypto.randomBytes(2); // Transaction ID
  const flags = Buffer.from([0x00, 0x00]); // Standard query
  const qdcount = Buffer.from([0x00, 0x01]); // One question
  const ancount = Buffer.from([0x00, 0x00]);
  const nscount = Buffer.from([0x00, 0x00]);
  const arcount = Buffer.from([0x00, 0x00]);

  // Encode hostname as DNS name
  const labels = hostname.split('.').map(l => {
    const b = Buffer.from(l, 'utf8');
    return Buffer.concat([Buffer.from([b.length]), b]);
  });
  const qname = Buffer.concat([...labels, Buffer.from([0x00])]);
  const qtype = Buffer.from([0x00, 0x01]); // Type A
  const qclass = Buffer.from([0x00, 0x01]); // IN

  return Buffer.concat([
    tid, flags, qdcount, ancount, nscount, arcount,
    qname, qtype, qclass
  ]);
}

function parseLlmnrResponse(msg) {
  // Parse minimal LLMNR response for A records
  // Returns array of { name, address }
  const results = [];
  try {
    // Skip header (12 bytes)
    let offset = 12;
    // Parse question (skip)
    while (msg[offset] !== 0) offset++;
    offset += 5; // null + type(2) + class(2)
    // Parse answer(s)
    while (offset < msg.length) {
      // Name (pointer or label)
      if ((msg[offset] & 0xc0) === 0xc0) {
        offset += 2;
      } else {
        while (msg[offset] !== 0) offset++;
        offset++;
      }
      const type = msg.readUInt16BE(offset); offset += 2;
      const cls = msg.readUInt16BE(offset); offset += 2;
      const ttl = msg.readUInt32BE(offset); offset += 4;
      const rdlen = msg.readUInt16BE(offset); offset += 2;
      if (type === 1 && cls === 1 && rdlen === 4) { // A record
        const ip = Array.from(msg.slice(offset, offset + 4)).join('.');
        results.push({ address: ip });
      }
      offset += rdlen;
    }
  } catch {}
  return results;
}

export default {
  id: "017",
  name: "LLMNR Scanner",
  description: "Probes Link-Local Multicast Name Resolution (UDP/5355) for host discovery and name resolution.",
  priority: 346,
  protocols: ["llmnr"],
  ports: [5355],
  requirements: {},
  runStrategy: "single",

  async run(host, _port = 0, opts = {}) {
    const timeoutMs = Number(opts.timeoutMs ?? process.env.LLMNR_SCANNER_TIMEOUT_MS ?? 4000);
    const hostname = opts?.hostname || host;
    const query = buildLlmnrQuery(hostname);

    const data = [];
    const responses = new Set();

    const sock = dgram.createSocket("udp4");
    sock.bind();

    // Listen for responses
    sock.on("message", (msg, rinfo) => {
    // Only process responses from the target host
    if (rinfo.address !== host) return;

    const parsed = parseLlmnrResponse(msg);
    for (const rec of parsed) {
        const key = `${rinfo.address}|${rec.address}`;
        if (!responses.has(key)) {
        responses.add(key);
        data.push({
            probe_protocol: "llmnr",
            probe_port: 5355,
            probe_info: `LLMNR response from ${rinfo.address}`,
            response_banner: JSON.stringify(rec)
        });
        }
    }
    });

    // Send query to LLMNR multicast address
    sock.send(query, 5355, "224.0.0.252");

    await new Promise(res => setTimeout(res, timeoutMs));
    try { sock.close(); } catch {}

    if (data.length === 0) {
      data.push({
        probe_protocol: "llmnr",
        probe_port: 5355,
        probe_info: "No LLMNR response observed in timeout window",
        response_banner: null
      });
    }

    return {
      up: data.length > 1,
      program: "LLMNR",
      version: "RFC4795",
      os: null,
      type: "llmnr",
      data
    };
  }
};
