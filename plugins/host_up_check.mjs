// plugins/host_up_check.mjs
// Real plugin to check if a host is up or down using ICMP (ping), TCP (common ports), and UDP (high closed port) probes.
// Updated to prioritize ICMP TTL-based OS detection, with TCP probes refining ambiguous TTLs (e.g., TTL 64) using banners and port heuristics.
// Extracts router name and version from port 443 banner (e.g., Netgear R8000) and includes in result.
// Returns { up: boolean, os: string|null, router_info: { name: string|null, version: string|null }|null, data: [{ probe_protocol, probe_port, probe_info, response_banner }] }.

import { promisify } from 'node:util';
import { execFile } from 'node:child_process';
import net from 'node:net';
import dgram from 'node:dgram';

const execFileP = promisify(execFile);

const DEBUG = /^(1|true|yes|on)$/i.test(String(process.env.DEBUG_MODE || process.env.HOST_UP_DEBUG || ''));
function dlog(...a) { if (DEBUG) console.log('[host-up-check]', ...a); }

/** Validate host string to prevent command injection. */
function isValidHost(h) {
  if (!h || typeof h !== "string") return false;
  return /^[a-zA-Z0-9.:_\-\[\]%]+$/.test(h);
}

// TTL to OS mapping based on provided data (filtered for ICMP, removed Netgear FVG318)
const TTL_OS_MAPPING = [
  { Device_OS: "AIX", TTL: 255, Protocol: "ICMP" },
  { Device_OS: "BSDI", TTL: 255, Protocol: "ICMP" },
  { Device_OS: "Compa", TTL: 64, Protocol: "ICMP" },
  { Device_OS: "Cisco", TTL: 254, Protocol: "ICMP" },
  { Device_OS: "Foundry", TTL: 64, Protocol: "ICMP" },
  { Device_OS: "FreeBSD", TTL: 255, Protocol: "ICMP" },
  { Device_OS: "FreeBSD", TTL: 64, Protocol: "ICMP" },
  { Device_OS: "HP-UX", TTL: 255, Protocol: "ICMP" },
  { Device_OS: "Irix", TTL: 255, Protocol: "ICMP" },
  { Device_OS: "juniper", TTL: 64, Protocol: "ICMP" },
  { Device_OS: "MPE/IX (HP)", TTL: 200, Protocol: "ICMP" },
  { Device_OS: "Linux", TTL: 64, Protocol: "ICMP" },
  { Device_OS: "Linux", TTL: 255, Protocol: "ICMP" },
  { Device_OS: "MacOS/MacTCP", TTL: 64, Protocol: "ICMP/TCP/UDP" },
  { Device_OS: "NetBSD", TTL: 255, Protocol: "ICMP" },
  { Device_OS: "OpenBSD", TTL: 255, Protocol: "ICMP" },
  { Device_OS: "OpenVMS", TTL: 255, Protocol: "ICMP" },
  { Device_OS: "Solaris", TTL: 255, Protocol: "ICMP" },
  { Device_OS: "Stratus", TTL: 255, Protocol: "ICMP" },
  { Device_OS: "SunOS", TTL: 255, Protocol: "ICMP" },
  { Device_OS: "Ultrix", TTL: 255, Protocol: "ICMP" },
  { Device_OS: "Windows", TTL: 32, Protocol: "ICMP" },
  { Device_OS: "Windows", TTL: 128, Protocol: "ICMP" },
  { Device_OS: "Android", TTL: 64, Protocol: "TCP and ICMP" }
];

// Prioritize Linux for router-like devices with TTL 64
const OS_SPECIFICITY = {
  "Linux": 10,         // High for servers/routers with FTP/HTTP/HTTPS
  "MacOS/MacTCP": 9,   // High for desktops
  "Android": 8,
  "FreeBSD": 7,
  "juniper": 6,
  "Cisco": 6,
  "Foundry": 5,
  "Windows": 4,
  "AIX": 3,
  "BSDI": 3,
  "Compa": 3,
  "HP-UX": 3,
  "Irix": 3,
  "MPE/IX (HP)": 3,
  "NetBSD": 3,
  "OpenBSD": 3,
  "OpenVMS": 3,
  "Solaris": 3,
  "Stratus": 3,
  "SunOS": 3,
  "Ultrix": 3
};

export default {
  id: '005',
  name: 'Host Up Check',
  description: 'Checks if the host is up or down using ICMP, TCP (common ports), and UDP (high closed port) probes with enhanced OS detection.',
  priority: 20,
  requirements: { host: "down" }, // run when ping hasn't marked it UP (ping blocked/filtered)
  protocols: ['tcp', 'udp', 'icmp'],
  ports: [21, 22, 80, 443, 3389, 54321],
  runStrategy: 'single',
  async run(host) {
    if (!isValidHost(host)) {
      return { up: false, os: null, router_info: null, data: [{ probe_protocol: 'icmp', probe_port: null, probe_info: 'Invalid host', response_banner: null }] };
    }
    dlog(`Running Host Up Check on ${host}`);
    const data = [];
    let up = false;
    let os = null;
    let router_info = null; // { name: string|null, version: string|null }
    let icmpCandidates = []; // Store ICMP candidates for TCP refinement

    // ICMP Probe (using system ping)
    try {
      const isWindows = process.platform === 'win32';
      const pingArgs = isWindows ? ['-n', '1', '-w', '1000', host] : ['-c', '1', '-W', '1', host];
      dlog(`Executing ping command: ping ${pingArgs.join(' ')}`);
      const { stdout } = await execFileP('ping', pingArgs, { windowsHide: true, timeout: 6000 });
      const received = isWindows ? stdout.includes('Reply from') : stdout.includes('1 received');
      let probe_info = received ? 'Ping successful' : 'Ping failed';
      if (received) {
        up = true;
        // Enhanced OS detection from TTL
        const ttlMatch = stdout.match(/ttl=(\d+)/i);
        if (ttlMatch) {
          const ttl = parseInt(ttlMatch[1], 10);
          icmpCandidates = TTL_OS_MAPPING.filter(entry => entry.TTL === ttl && entry.Protocol.includes('ICMP'));
          dlog(`ICMP TTL ${ttl} candidates: ${icmpCandidates.map(c => c.Device_OS).join(', ')}`);
          if (icmpCandidates.length > 0) {
            // Choose the most specific OS based on OS_SPECIFICITY
            os = icmpCandidates.reduce((best, curr) => 
              (OS_SPECIFICITY[curr.Device_OS] || 0) > (OS_SPECIFICITY[best.Device_OS] || 0) ? curr : best
            ).Device_OS;
            probe_info = `Ping successful (TTL: ${ttl}, OS: ${os})`;
          }
        }
      }
      data.push({
        probe_protocol: 'icmp',
        probe_port: null,
        probe_info,
        response_banner: null
      });
    } catch (err) {
      if (DEBUG) console.error('[host-up-check]', `ICMP probe error: ${err.message}`);
      data.push({
        probe_protocol: 'icmp',
        probe_port: null,
        probe_info: `Ping error: ${err.message}`,
        response_banner: null
      });
    }

    // TCP Probes (common ports)
    const tcpPorts = [21, 22, 80, 443, 3389];
    for (const port of tcpPorts) {
      await new Promise((resolve) => {
        dlog(`Attempting TCP probe on ${host}:${port}`);
        const socket = new net.Socket();
        socket.setTimeout(2000);
        let banner = '';

        socket.on('connect', () => {
          up = true;
          const MAX_BANNER = 4096;
          socket.on('data', (d) => { if (banner.length < MAX_BANNER) banner += d.toString(); });
          setTimeout(() => {
            // OS detection from banner or port, only if ICMP is ambiguous
            let newOs = null;
            let newRouterInfo = null;
            if (banner.toLowerCase().includes('unix') || banner.toLowerCase().includes('linux') || banner.toLowerCase().includes('bftpd')) {
              newOs = 'Linux';
              dlog(`TCP probe port ${port}: Detected ${newOs} from banner: ${banner.trim()}`);
            } else if (banner.toLowerCase().includes('windows') || banner.includes('Microsoft')) {
              newOs = 'Windows';
              dlog(`TCP probe port ${port}: Detected ${newOs} from banner: ${banner.trim()}`);
            } else if (banner.toLowerCase().includes('netgear')) {
              newOs = 'Linux'; // Netgear routers typically run Linux
              // Extract router name and version (e.g., Netgear R8000)
              const routerMatch = banner.match(/(netgear)\s+([^\s]+)/i);
              if (routerMatch) {
                newRouterInfo = { name: routerMatch[1], version: routerMatch[2] };
                dlog(`TCP probe port ${port}: Detected router ${newRouterInfo.name} ${newRouterInfo.version} from banner: ${banner.trim()}`);
              } else {
                newRouterInfo = { name: 'Netgear', version: null };
                dlog(`TCP probe port ${port}: Detected generic Netgear router from banner: ${banner.trim()}`);
              }
            } else if (port === 3389) {
              newOs = 'Windows'; // RDP port suggests Windows
            } else if (port === 22) {
              newOs = 'MacOS/MacTCP'; // SSH port suggests MacOS on desktops
            } else if (port === 21 || port === 80 || port === 443) {
              newOs = 'Linux'; // FTP/HTTP/HTTPS ports suggest Linux on routers
              dlog(`TCP probe port ${port}: Detected ${newOs} from open port (router heuristic)`);
            }
            // Refine os if ICMP set an ambiguous TTL (e.g., 64) or newOs is more specific
            if (newOs && (!os || (icmpCandidates.length > 1 && (OS_SPECIFICITY[newOs] || 0) >= (OS_SPECIFICITY[os] || 0)))) {
              dlog(`TCP probe port ${port}: Setting os=${newOs} (ICMP ambiguous or less specific, TTL ${icmpCandidates[0]?.TTL})`);
              os = newOs;
              if (newRouterInfo) {
                router_info = newRouterInfo;
              }
            } else {
              dlog(`TCP probe port ${port}: Keeping os=${os} (newOs=${newOs})`);
            }
            data.push({
              probe_protocol: 'tcp',
              probe_port: port,
              probe_info: 'Connection successful',
              response_banner: banner.trim() || null
            });
            socket.destroy();
            resolve();
          }, 1000);
        });

        socket.on('error', (err) => {
          if (err.code === 'ECONNREFUSED') {
            up = true;
            let newOs = null;
            if (port === 3389) {
              newOs = 'Windows'; // Refused RDP port suggests Windows
            } else if (port === 22) {
              newOs = 'MacOS/MacTCP'; // Refused SSH port suggests MacOS
            }
            // Refine os if ICMP set an ambiguous TTL (e.g., 64) or newOs is more specific
            if (newOs && (!os || (icmpCandidates.length > 1 && (OS_SPECIFICITY[newOs] || 0) >= (OS_SPECIFICITY[os] || 0)))) {
              dlog(`TCP probe port ${port}: Setting os=${newOs} (ICMP ambiguous or less specific, TTL ${icmpCandidates[0]?.TTL})`);
              os = newOs;
            } else {
              dlog(`TCP probe port ${port}: Keeping os=${os} (newOs=${newOs})`);
            }
            data.push({
              probe_protocol: 'tcp',
              probe_port: port,
              probe_info: 'Connection refused - host up',
              response_banner: null
            });
          } else {
            data.push({
              probe_protocol: 'tcp',
              probe_port: port,
              probe_info: `Error: ${err.code} - ${err.message}`,
              response_banner: null
            });
          }
          resolve();
        });

        socket.on('timeout', () => {
          data.push({
            probe_protocol: 'tcp',
            probe_port: port,
            probe_info: 'Timeout',
            response_banner: null
          });
          socket.destroy();
          resolve();
        });

        socket.connect(port, host);
      });
    }

    // UDP Probe (send to likely closed high port)
    const udpPort = 54321;
    await new Promise((resolve) => {
      dlog(`Attempting UDP probe on ${host}:${udpPort}`);
      const socket = dgram.createSocket('udp4');
      const timeoutId = setTimeout(() => {
        data.push({
          probe_protocol: 'udp',
          probe_port: udpPort,
          probe_info: 'Timeout - host possibly down',
          response_banner: null
        });
        socket.close();
        resolve();
      }, 3000);

      socket.on('error', (err) => {
        clearTimeout(timeoutId);
        if (err.code === 'ECONNREFUSED') {
          up = true;
          data.push({
            probe_protocol: 'udp',
            probe_port: udpPort,
            probe_info: 'ICMP Port Unreachable - host up',
            response_banner: null
          });
        } else {
          data.push({
            probe_protocol: 'udp',
            probe_port: udpPort,
            probe_info: `Error: ${err.code} - ${err.message}`,
            response_banner: null
          });
        }
        socket.close();
        resolve();
      });

      socket.connect(udpPort, host, (err) => {
        if (err) {
          clearTimeout(timeoutId);
          data.push({
            probe_protocol: 'udp',
            probe_port: udpPort,
            probe_info: `Connect error: ${err.message}`,
            response_banner: null
          });
          socket.close();
          resolve();
          return;
        }

        socket.send(Buffer.alloc(0), (err) => {
          clearTimeout(timeoutId);
          if (err) {
            if (err.code === 'ECONNREFUSED') {
              up = true;
              data.push({
                probe_protocol: 'udp',
                probe_port: udpPort,
                probe_info: 'ICMP Port Unreachable - host up',
                response_banner: null
              });
            } else {
              data.push({
                probe_protocol: 'udp',
                probe_port: udpPort,
                probe_info: `Send error: ${err.message}`,
                response_banner: null
              });
            }
          } else {
            up = true;
            data.push({
              probe_protocol: 'udp',
              probe_port: udpPort,
              probe_info: 'Send successful, no error - host up (port may be open)',
              response_banner: null
            });
          }
          socket.close();
          resolve();
        });
      });
    });

    dlog(`Host Up Check result: up=${up}, os=${os}, router_info=${JSON.stringify(router_info)}, data=${JSON.stringify(data)}`);
    return { up, os, router_info, data };
  }
};
