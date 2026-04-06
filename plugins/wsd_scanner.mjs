// plugins/wsd_scanner.mjs
// Enhanced WS-Discovery Scanner — discovers WS-Discovery devices in the subnet with comprehensive analysis
// Filters results to include only devices matching the target host IP by default.
// Set WSD_INCLUDE_NON_MATCHED=1 to keep all discovered devices.

import dgram from 'dgram';
import { parseString } from 'xml2js';
import { v4 as uuidv4 } from 'uuid';
import { isPrivateLike } from '../utils/net_validation.mjs';

const DEBUG = /^(1|true|yes|on)$/i.test(String(process.env.DEBUG_MODE || process.env.WSD_DEBUG || ""));
function dlog(...a) { if (DEBUG) console.log("[wsd-scanner]", ...a); }

function ipMatches(target, address) {
  const t = String(target || "").trim();
  const a = String(address || "").trim();
  return t === a;
}

/**
 * Discovers WS-Discovery devices by sending a multicast Probe message.
 * @param {string} targetHost The target host IP to filter for
 * @param {number} timeout The time in milliseconds to wait for responses.
 * @returns {Promise<Array<Object>>} A promise that resolves with an array of discovered devices.
 */
function discoverWsDiscoveryDevices(targetHost, timeout = 5000) {
  return new Promise((resolve, reject) => {
    const client = dgram.createSocket('udp4');
    const devices = [];
    const knownAddresses = new Set();
    const probeMessageId = `urn:uuid:${uuidv4()}`;
    const includeNonMatched = /^(1|true|yes|on)$/i.test(String(process.env.WSD_INCLUDE_NON_MATCHED || ""));

    // The multicast address and port for WS-Discovery
    const multicastAddress = '239.255.255.250';
    const multicastPort = 3702;

    // XML-based WS-Discovery Probe message
    const probeMessage = `
      <s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
        xmlns:a="http://www.w3.org/2005/08/addressing"
        xmlns:d="http://docs.oasis-open.org/ws-dd/ns/discovery/2009/01">
        <s:Header>
          <a:Action>http://docs.oasis-open.org/ws-dd/ns/discovery/2009/01/Probe</a:Action>
          <a:MessageID>${probeMessageId}</a:MessageID>
          <a:To>${multicastAddress}:${multicastPort}</a:To>
        </s:Header>
        <s:Body>
          <d:Probe/>
        </s:Body>
      </s:Envelope>
    `;

    client.on('message', (msg, rinfo) => {
      // Ignore messages that are not responses to our Probe
      if (rinfo.address === client.address().address) return;
      if (knownAddresses.has(rinfo.address)) return;

      // Filter by target host unless includeNonMatched is set
      const ipHit = ipMatches(targetHost, rinfo.address);
      if (!ipHit && !includeNonMatched) {
        dlog(`Filtering out non-matching device: ${rinfo.address} (target: ${targetHost})`);
        return;
      }

      // Parse the XML response from the device
      parseString(msg.toString(), (err, result) => {
        if (err) {
          dlog(`XML parse error from ${rinfo.address}:`, err.message);
          return; // Silently ignore parsing errors
        }
        
        // Ensure this is a valid ProbeMatch message
        try {
          if (result && result['s:Envelope'] && result['s:Envelope']['s:Body'] && 
              result['s:Envelope']['s:Body'][0]['d:ProbeMatches']) {
            const probeMatch = result['s:Envelope']['s:Body'][0]['d:ProbeMatches'][0]['d:ProbeMatch'][0];
            const xaddrs = probeMatch['d:XAddrs'] ? probeMatch['d:XAddrs'][0].split(' ') : [];
            
            const endpointRef = probeMatch['a:EndpointReference'] && probeMatch['a:EndpointReference'][0]['a:Address'] 
              ? probeMatch['a:EndpointReference'][0]['a:Address'][0] : 'Unknown';
            
            const types = probeMatch['d:Types'] ? probeMatch['d:Types'][0] : 'Unknown';
            const scopes = probeMatch['d:Scopes'] ? probeMatch['d:Scopes'][0] : null;
            const metadataVersion = probeMatch['d:MetadataVersion'] ? probeMatch['d:MetadataVersion'][0] : null;
            
            devices.push({
              address: rinfo.address,
              port: rinfo.port,
              xaddrs: xaddrs,
              endpointUuid: endpointRef,
              types: types,
              scopes: scopes,
              metadataVersion: metadataVersion,
              isMatched: ipHit,
              timestamp: new Date().toISOString()
            });
            knownAddresses.add(rinfo.address);
            
            dlog(`Discovered WS-Discovery device: ${rinfo.address} (matched: ${ipHit}), types: ${types}`);
          }
        } catch (parseErr) {
          dlog(`Parse error processing response from ${rinfo.address}:`, parseErr.message);
        }
      });
    });

    client.on('error', (err) => {
      dlog("WS-Discovery client error:", err.message);
      client.close();
      reject(err);
    });

    client.bind(() => {
      try {
        client.setBroadcast(true);
        client.setMulticastTTL(128);
        
        dlog(`Sending WS-Discovery probe to ${multicastAddress}:${multicastPort}`);
        const buffer = Buffer.from(probeMessage);
        client.send(buffer, multicastPort, multicastAddress, (err) => {
          if (err) {
            dlog("Failed to send WS-Discovery probe:", err.message);
            client.close();
            reject(err);
          }
        });
      } catch (err) {
        dlog("Error setting up WS-Discovery client:", err.message);
        client.close();
        reject(err);
      }
    });

    setTimeout(() => {
      dlog(`WS-Discovery timeout reached, found ${devices.length} devices`);
      client.close();
      resolve(devices);
    }, timeout);
  });
}

export default {
  id: "016",
  name: "Enhanced WS-Discovery Scanner",
  description: "Discovers WS-Discovery enabled devices using multicast probe messages. Returns only devices matching the target host IP by default.",
  priority: 400,
  requirements: {},
  protocols: ["udp"],
  ports: [3702],
  runStrategy: "single",

  async run(host, port = 3702, opts = {}) {
    const data = [];
    let up = false;
    let program = "WS-Discovery"; // Always set to WS-Discovery
    let version = "1.1"; // Always set to 1.1
    
    const timeout = opts.timeout || 5000;

    if (!isPrivateLike(host)) {
      data.push({
        probe_protocol: "udp",
        probe_port: port,
        probe_info: "Non-local target — WS-Discovery not attempted (requires local network)",
        response_banner: null
      });
      return {
        up: false,
        program: "WS-Discovery",
        version: "1.1",
        type: "wsdiscovery",
        data
      };
    }

    try {
      dlog(`Starting WS-Discovery scan for host: ${host}`);
      const devices = await discoverWsDiscoveryDevices(host, timeout);
      
      const matchedDevices = devices.filter(d => d.isMatched);
      const matched = matchedDevices.length > 0;
      
      dlog(`Discovery complete: total=${devices.length}, matched=${matchedDevices.length}`);
      
      if (devices.length > 0) {
        up = matched;
        // program and version already set above
        
        // Sort devices - matched first
        devices.sort((a, b) => {
          if (a.isMatched && !b.isMatched) return -1;
          if (!a.isMatched && b.isMatched) return 1;
          return 0;
        });
        
        devices.forEach((device) => {
          const xaddrsInfo = device.xaddrs.length > 0 ? device.xaddrs.join(', ') : 'No XAddrs';
          
          // Build comprehensive info string
          const infoParts = [];
          if (device.isMatched) {
            infoParts.push("Matched host —");
          } else {
            infoParts.push("Discovered —");
          }
          infoParts.push(`types="${device.types}"`);
          infoParts.push(`address=${device.address}`);
          if (device.scopes) {
            infoParts.push(`scopes="${device.scopes}"`);
          }
          if (device.metadataVersion) {
            infoParts.push(`metadataVersion=${device.metadataVersion}`);
          }

          const bannerObj = {
            address: device.address,
            endpointUuid: device.endpointUuid,
            types: device.types,
            xaddrs: device.xaddrs,
            scopes: device.scopes,
            metadataVersion: device.metadataVersion,
            discoveredAt: device.timestamp,
            isMatched: device.isMatched
          };
          
          data.push({
            probe_protocol: 'udp',
            probe_port: device.port,
            probe_info: infoParts.join(' '),
            response_banner: JSON.stringify(bannerObj),
            device_address: device.address,
            device_types: device.types,
            endpoint_uuid: device.endpointUuid,
            xaddrs: device.xaddrs,
            scopes: device.scopes,
            isMatched: device.isMatched
          });
        });

        // Add summary row for matched devices
        if (matched) {
          const uniqueTypes = [...new Set(matchedDevices.map(d => d.types))];
          const summaryRow = {
            probe_protocol: 'udp',
            probe_port: port,
            probe_info: `Host ${host} confirmed via WS-Discovery - ${matchedDevices.length} device(s) found: ${uniqueTypes.join(', ')}`,
            response_banner: JSON.stringify({
              summary: true,
              matchedDevices: matchedDevices.length,
              deviceTypes: uniqueTypes,
              discoveredAt: new Date().toISOString()
            })
          };
          data.unshift(summaryRow);
        }
      } else {
        data.push({
          probe_protocol: 'udp',
          probe_port: port,
          probe_info: 'No WS-Discovery devices relevant to target IP discovered within timeout window',
          response_banner: JSON.stringify({
            timeout: timeout,
            reason: "No responses received"
          })
        });
      }
    } catch (error) {
      dlog("WS-Discovery scan error:", error.message);
      data.push({
        probe_protocol: 'udp',
        probe_port: port,
        probe_info: 'WS-Discovery scan failed',
        response_banner: JSON.stringify({
          error: error.message,
          timestamp: new Date().toISOString()
        })
      });
    }

    return {
      up,
      program,
      version,
      type: 'wsdiscovery',
      deviceCount: data.length - (up ? 1 : 0), // Exclude summary row from count
      data
    };
  }
};
