// plugins/ftp_banner_check.mjs
// Real plugin to connect to an FTP server (port 21) and parse the banner for program name, version, and OS hints.
// Handles banners like "220 bftpd 1.6.6 at 192.168.1.1 ready." and Pure-FTPd multi-line banners.
// Returns { up: boolean, program: string, version: string, os: string|null, data: [{ probe_protocol, probe_port, probe_info, response_banner }] }.

import net from 'node:net';

export default {
  id: '004',
  name: 'FTP Banner Check',
  description: 'Connects to FTP server on port 21 and retrieves the program name, version, and OS from the banner.',
  priority: 40,
  requirements: { host: "up", tcp_open: [21] },
  protocols: ['tcp'],
  ports: [21],
  async run(host, port = 21) {
    const anonEnabled = /^(1|true|yes|on)$/i.test(String(process.env.FTP_CHECK_ANON || ''));
    console.log(`Running FTP Banner Check on ${host}:${port} (anon=${anonEnabled})`);
    return new Promise((resolve) => {
      const socket = new net.Socket();
      let banner = '';
      let up = false;
      let anonState = 'banner'; // banner | send-user | send-pass | done
      let anonymousLogin = false;
      let bannerCollected = false;
      let resolved = false;
      const safeResolve = (value) => { if (resolved) return; resolved = true; resolve(value); };

      socket.setTimeout(5000); // 5-second timeout

      socket.on('connect', () => {
        up = true; // Host is up if connection succeeds
        console.log(`Connected to ${host}:${port}`);
      });

      function finalizeBanner() {
        const bannerTrimmed = banner.trim();
        let program = 'Unknown';
        let version = 'Unknown';
        let os = null;
        let probe_info = 'No recognizable FTP banner';

        const singleLineMatch = bannerTrimmed.match(/220[- ]?([a-zA-Z0-9]+)\s+([0-9.]+)(?:\s+.*)?$/i) ||
                               bannerTrimmed.match(/220[- ]?\((.*?)\s+([0-9.]+)\)/i);
        const pureFtpdMatch = bannerTrimmed.match(/220[-]+ Welcome to ([a-zA-Z0-9-]+)(?:\s+\[.*?\])?[- ]+/i);

        if (singleLineMatch) {
          program = singleLineMatch[1] || 'Unknown';
          version = singleLineMatch[2] || 'Unknown';
          probe_info = `Detected FTP server: ${program} ${version}`;
          console.log(`Parsed banner: program=${program}, version=${version}`);
        } else if (pureFtpdMatch) {
          program = pureFtpdMatch[1] || 'Unknown';
          probe_info = `Detected FTP server: ${program} (version not specified in banner)`;
          console.log(`Parsed banner: program=${program}, version=Unknown`);
        }

        if (bannerTrimmed.toLowerCase().includes('unix') || program.toLowerCase().includes('pure-ftpd') || program.toLowerCase().includes('vsftpd') || program.toLowerCase().includes('bftpd')) {
          os = 'Linux';
          console.log(`OS detected: ${os} from banner or program`);
        } else if (bannerTrimmed.toLowerCase().includes('windows') || program.toLowerCase().includes('filezilla')) {
          os = 'Windows';
          console.log(`OS detected: ${os} from banner or program`);
        }

        return { bannerTrimmed, program, version, os, probe_info };
      }

      function buildResult(parsed) {
        const evidenceRows = [{
          probe_protocol: 'tcp',
          probe_port: port,
          probe_info: parsed.probe_info,
          response_banner: parsed.bannerTrimmed || null
        }];

        if (anonEnabled && anonymousLogin) {
          evidenceRows.push({
            probe_protocol: 'tcp',
            probe_port: port,
            probe_info: 'SECURITY FINDING: Anonymous FTP login permitted',
            response_banner: parsed.bannerTrimmed || null
          });
        }

        const result = {
          up,
          program: parsed.program,
          version: parsed.version,
          os: parsed.os,
          data: evidenceRows
        };

        if (anonEnabled) {
          result.anonymousLogin = anonymousLogin;
        }

        console.log(`FTP Banner Check result: up=${up}, program=${parsed.program}, version=${parsed.version}, os=${parsed.os}, anonymousLogin=${anonymousLogin}, banner=${parsed.bannerTrimmed || 'none'}`);
        return result;
      }

      const MAX_BANNER = 65536;
      socket.on('data', (data) => {
        const chunk = data.toString();

        if (anonState === 'banner') {
          if (banner.length > MAX_BANNER) { socket.destroy(); return; }
          banner += chunk;
          if (bannerCollected) return; // already scheduled
          bannerCollected = true;
          // Collect banner for up to 1 second to handle multi-line banners like Pure-FTPd
          setTimeout(() => {
            if (anonEnabled && banner.trim().startsWith('220')) {
              anonState = 'send-user';
              console.log('Starting anonymous login check');
              socket.write('USER anonymous\r\n');
              // Set a separate timeout for the anonymous check
              setTimeout(() => {
                if (anonState !== 'done') {
                  console.log('Anonymous login check timed out');
                  anonState = 'done';
                  socket.end();
                }
              }, 3000);
            } else {
              socket.end();
            }
          }, 1000);
        } else if (anonState === 'send-user') {
          const response = chunk.trim();
          console.log(`Anon USER response: ${response}`);
          if (response.startsWith('331')) {
            anonState = 'send-pass';
            socket.write('PASS anonymous@audit.local\r\n');
          } else if (response.startsWith('230')) {
            // Logged in without password
            anonymousLogin = true;
            anonState = 'done';
            socket.end();
          } else {
            // Unexpected response, treat as denied
            anonState = 'done';
            socket.end();
          }
        } else if (anonState === 'send-pass') {
          const response = chunk.trim();
          console.log(`Anon PASS response: ${response}`);
          if (response.startsWith('230')) {
            anonymousLogin = true;
          }
          // 530/421 or anything else = denied
          anonState = 'done';
          socket.end();
        }
      });

      socket.on('end', () => {
        const parsed = finalizeBanner();
        safeResolve(buildResult(parsed));
      });

      socket.on('timeout', () => {
        socket.destroy();
        console.log(`FTP connection to ${host}:${port} timed out`);
        safeResolve({
          up: false,
          program: 'Unknown',
          version: 'Unknown',
          os: null,
          data: [{
            probe_protocol: 'tcp',
            probe_port: port,
            probe_info: 'Connection timed out',
            response_banner: null
          }]
        });
      });

      socket.on('error', (err) => {
        socket.destroy();
        let probe_info = `Connection error: ${err.message}`;
        if (err.code === 'ECONNREFUSED') {
          up = true; // Host is up but port is closed
          probe_info = 'Connection refused - host up, FTP port closed';
          console.log(`FTP connection to ${host}:${port} refused - host up`);
        } else {
          console.log(`FTP connection error to ${host}:${port}: ${err.message}`);
        }
        safeResolve({
          up,
          program: 'Unknown',
          version: 'Unknown',
          os: null,
          data: [{
            probe_protocol: 'tcp',
            probe_port: port,
            probe_info,
            response_banner: null
          }]
        });
      });

      console.log(`Attempting TCP connection to ${host}:${port}`);
      socket.connect(port, host);
    });
  }
};

// Plug-and-play adapter for the concluder
import { statusFrom } from '../utils/conclusion_utils.mjs';

export async function conclude({ host, result }) {
  const rows = Array.isArray(result?.data) ? result.data : [];
  // Prefer first meaningful row
  const r = rows.find(x => x && (x.probe_port != null)) || rows[0] || {};
  const info = r?.probe_info || null;
  const banner = r?.response_banner || null;

  // Derive status: treat ECONNREFUSED/refused as 'closed'; banner '220' as 'open'
  let status = statusFrom({ info, banner });
  if (status === 'unknown' && result?.up === true && banner) status = 'open';

  const record = {
    port: Number(r?.probe_port ?? 21),
    protocol: String(r?.probe_protocol || 'tcp'),
    service: 'ftp',
    program: result?.program || 'Unknown',
    version: result?.version || 'Unknown',
    status,
    info,
    banner,
    source: 'ftp',
    evidence: rows,
    authoritative: true
  };

  if (result?.anonymousLogin != null) {
    record.anonymousLogin = result.anonymousLogin;
  }

  return [record];
}

export const authoritativePorts = new Set(['tcp:21']);
