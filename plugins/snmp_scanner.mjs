// plugins/snmp_scanner.mjs
// Plugin to probe SNMP (UDP port 161) to detect device types (e.g., printers, routers) via sysDescr OID.
// Uses 'snmp-native' npm package, declared in dependencies.
// Returns { up: boolean, program: string, version: string, os: string|null, type: string, data: [{ probe_protocol, probe_port, probe_info, response_banner }], serialNumber: string, hardwareVersion: string, firmwareVersion: string, ip6: string|null, deviceWebPage: string|null, deviceWebPageInstruction: string }.

export const DEFAULT_COMMUNITIES = ['public', 'private'];
export const snmpCommunities = process.env.SNMP_COMMUNITY
  ? String(process.env.SNMP_COMMUNITY).split(',').map(s => s.trim()).filter(Boolean)
  : DEFAULT_COMMUNITIES;
const oidTable = {
  default: [1, 3, 6, 1, 2, 1, 1, 1, 0], // sysDescr 
  epsonShortName: [1, 3, 6, 1, 2, 1, 1, 5, 0], // sysDescr EPSON6768F4 '1.3.6.1.2.1.1.5.0'
  epsonModel: [1, 3, 6, 1, 4, 1, 1248, 1, 1, 3, 1, 29, 3, 1, 45, 0], // Epson model OID
  epsonSerial: [1, 3, 6, 1, 4, 1, 1248, 1, 2, 2, 1, 1, 1, 4, 1], // Epson serial number
  epsonVersions: [1, 3, 6, 1, 2, 1, 2, 2, 1, 2, 1], // Hardware and firmware versions
  epsonIPv6: [1, 3, 6, 1, 4, 1, 1248, 1, 1, 3, 1, 4, 46, 1, 2, 2], // IPv6 address in URL
  epsonName: [1, 3, 6, 1, 4, 1, 1248, 1, 1, 3, 1, 26, 2, 1, 3, 1], // Epson device full name
  epsonVersion: [1, 3, 6, 1, 4, 1, 1248, 1, 1, 3, 1, 21, 1, 1, 2, 5], // Epson device version
  epsonFirmware: null
};

/** Clamp helper: keep first N chars (used for Epson S/N = 10 chars) */
const clampSerial = (sn, n = 10) => (sn && sn.length > n ? sn.slice(0, n) : sn);

/**
 * Parse an SNMP sysDescr for OS/family/version hints.
 */
function fromSysDescr(v) {
  const s = (v || '').toLowerCase();

  if (s.includes('epson')) {
    return { family: 'Epson', os: 'Embedded Linux', version: '' };
  }
  if (s.includes('cisco')) {
    const iosMatch = s.match(/version\s+([0-9.]+)/);
    return { family: 'Cisco', os: 'Cisco IOS', version: iosMatch ? iosMatch[1] : '' };
  }
  if (s.includes('palo alto')) {
    const paMatch = s.match(/pa-([0-9]+)/);
    return { family: 'Palo Alto Networks', os: 'PAN-OS', version: paMatch ? paMatch[1] : '' };
  }
  if (s.includes('synology')) {
    const modelMatch = s.match(/diskstation\s+([a-z0-9+]+)/);
    return { family: 'Synology', os: 'DiskStation Manager (DSM)', version: modelMatch ? modelMatch[1] : '' };
  }
  if (s.includes('windows')) {
    const versionMatch = s.match(/version\s+([0-9.]+)/);
    return { family: 'Microsoft', os: 'Windows', version: versionMatch ? versionMatch[1] : '' };
  }
  if (s.includes('linux')) {
    const versionMatch = s.match(/linux\s+.*?([0-9.]+\S*)/);
    return { family: 'Linux', os: 'Linux/Unix', version: versionMatch ? versionMatch[1] : '' };
  }
  if (s.includes('unix')) {
    return { family: 'Unix', os: 'Linux/Unix', version: '' };
  }
  return { family: null, os: null, version: '' };
}

/** Parse "EEPS2 Hard Ver.1.00 Firm Ver.0.23" */
function parseVersions(versionString) {
  const regex = /hard\s+ver\.(\d+\.\d+)\s+firm\s+ver\.(\d+\.\d+)/i;
  const m = String(versionString || '').match(regex);
  if (m && m.length === 3) {
    return { hardwareVersion: m[1], firmwareVersion: m[2] };
  }
  return { hardwareVersion: null, firmwareVersion: null };
}

/**
 * Extract a printer serial number from an SNMP VarBind.
 */
function parseSerialNumber(snmpResponse) {
  let raw = '';
  if (snmpResponse && Buffer.isBuffer(snmpResponse.valueRaw)) {
    raw = snmpResponse.valueRaw.toString('latin1');
  } else if (snmpResponse && typeof snmpResponse.value === 'string') {
    raw = snmpResponse.value;
  } else {
    return { serialNumber: '' };
  }

  const asciiStr = raw.replace(/[^\x20-\x7E]/g, ' ').replace(/\s+/g, ' ').trim();

  const BLOCKLIST = new Set([ 'UNKNOWN', 'BDC', 'ST2', 'HTTP', 'IPP', 'EPSON', 'ET', 'SERIES', 'PRINT', 'SERVER' ]);

  const candidates = [];
  const re = /\b([A-Z0-9]{10,14})\b/g;
  for (const m of asciiStr.matchAll(re)) {
    const tok = m[1];
    if (BLOCKLIST.has(tok)) continue;
    const letters = (tok.match(/[A-Z]/g) || []).length;
    const digits  = (tok.match(/\d/g)  || []).length;
    if (letters >= 2 && digits >= 2) {
      candidates.push({ tok, idx: m.index });
    }
  }
  if (!candidates.length) return { serialNumber: '' };
  candidates.sort((a, b) => (b.tok.length - a.tok.length) || (b.idx - a.idx));
  return { serialNumber: candidates[0].tok };
}

export default {
  id: '007',
  name: 'SNMP Scanner',
  description: 'Probes SNMP (UDP 161) to detect device types via sysDescr and Epson OIDs.',
  priority: 70,
  requirements: { host: "up", udp_open: [161] },
  protocols: ['udp'],
  ports: [161],
  dependencies: ['snmp-native'],
  async run(host, options = {}) {
    let up = false;
    let program = 'Unknown';
    let version = 'Unknown';
    let os = null;
    let type = 'unknown';
    let serialNumber = '';
    let hardwareVersion = '';
    let firmwareVersion = '';
    let ip6 = null;
    let deviceWebPage = null;
    let deviceWebPageInstruction = '';
    let deviceFullName = null;
    let community = null;
    const communitiesTried = [];
    const data = [];

    try {
      const snmp = await import('snmp-native').catch(() => null);
      if (!snmp?.default?.Session && !snmp?.Session) {
        throw new Error('snmp-native package not properly loaded');
      }
      const Session = snmp.default?.Session || snmp.Session;

      const useOid = options.oid ? options.oid.split('.').map(Number) : oidTable.default;

      for (const comm of snmpCommunities) {
        communitiesTried.push(comm);
        const s = new Session({ host, community: comm, timeouts: [5000] });

        try {
          const vbs = await new Promise((resolve) => {
            let settled = false;
            const timer = setTimeout(() => { if (!settled) resolve([]); }, 2000);
            try {
              s.get({ oid: useOid }, (err, vb) => {
                if (settled) return;
                clearTimeout(timer);
                settled = true;
                resolve(err ? [] : (vb || []));
              });
            } catch { clearTimeout(timer); if (!settled) { settled = true; resolve([]); } }
          });

          const val = String(vbs?.[0]?.value || '');
          if (val) {
            up = true;
            community = comm;
            const parsed = fromSysDescr(val);
            program = parsed.family || 'Unknown';
            version = parsed.version || 'Unknown';
            os = parsed.os;

            if (/cisco|palo alto/i.test(program) || /router|switch/i.test(val)) type = 'router';
            else if (/synology|epson|printer/i.test(program + ' ' + val)) type = 'printer';
            else if (/microsoft|windows|linux|unix/i.test(program)) type = 'server';

            let probeInfo = `SNMP response received: ${program} ${version}${os ? ` (OS: ${os})` : ''} (Type: ${type})`;
            if (comm === 'public' || comm === 'private') {
              probeInfo += ` WARNING: Default SNMP community string '${comm}' accepted — misconfiguration`;
            }

            data.push({
              probe_protocol: 'udp',
              probe_port: 161,
              probe_info: probeInfo,
              response_banner: val || null
            });

            // Epson extras
            const isEpson = /epson/i.test(program + ' ' + val);
            if (isEpson) {
              const get = (oid) => new Promise((resolve) => {
                let settled = false;
                const timer = setTimeout(() => { if (!settled) { settled = true; resolve([]); } }, 2000);
                try {
                  s.get({ oid }, (err, vb) => {
                    clearTimeout(timer);
                    if (!settled) { settled = true; resolve(err ? [] : (vb || [])); }
                  });
                } catch { clearTimeout(timer); if (!settled) { settled = true; resolve([]); } }
              });

              const serialVbs = await get(oidTable.epsonSerial);
              const { serialNumber: sn } = parseSerialNumber(serialVbs?.[0] || '');
              if (sn) serialNumber = clampSerial(sn, 10);

              const versionsVbs = await get(oidTable.epsonVersions);
              const { hardwareVersion: hw, firmwareVersion: fw } = parseVersions(versionsVbs?.[0]?.value || '');
              if (hw) hardwareVersion = hw;
              if (fw) firmwareVersion = fw;

              const nameVbs = await get(oidTable.epsonName);
              const nameVal = String(nameVbs?.[0]?.value || '');
              if (nameVal) {
                program = nameVal;
                deviceFullName = nameVal;
              }

              const versionVbs = await get(oidTable.epsonVersion);
              const versionVal = String(versionVbs?.[0]?.value || '');
              if (versionVal) version = versionVal;
            }

            // Only add 'Serial:' when a real serial exists
            const infoPieces = [`SNMP response received: ${program} ${version}${os ? ` (OS: ${os})` : ''} (Type: ${type}`];
            if (serialNumber) infoPieces.push(`Serial: ${serialNumber}`);
            if (hardwareVersion) infoPieces.push(`HW Ver: ${hardwareVersion}`);
            if (firmwareVersion) infoPieces.push(`FW Ver: ${firmwareVersion}`);
            infoPieces.push(')');
            if (comm === 'public' || comm === 'private') {
              infoPieces.push(` WARNING: Default SNMP community string '${comm}' accepted — misconfiguration`);
            }
            data[0].probe_info = infoPieces.join(', ');

            const bannerExtras = [];
            if (serialNumber) bannerExtras.push(`Serial=${serialNumber}`);
            if (hardwareVersion) bannerExtras.push(`HW=${hardwareVersion}`);
            if (firmwareVersion) bannerExtras.push(`FW=${firmwareVersion}`);
            if (bannerExtras.length) {
              data[0].response_banner = `${val}\nAdditional Info: ${bannerExtras.join(', ')}`;
            } else {
              data[0].response_banner = val;
            }

            break;
          } else {
            data.push({
              probe_protocol: 'udp',
              probe_port: 161,
              probe_info: `No SNMP response for community "${comm}"`,
              response_banner: null
            });
          }
        } finally {
          try { s.close(); } catch {}
        }
      }
    } catch (err) {
      data.push({
        probe_protocol: 'udp',
        probe_port: 161,
        probe_info: `Error: ${err.message}`,
        response_banner: null
      });
    }

    return { up, program, version, os, type, serialNumber, hardwareVersion, firmwareVersion, ip6, deviceWebPage, deviceWebPageInstruction, community, communitiesTried, data };
  }
};

export async function conclude({ host, result }) {
  const rows = Array.isArray(result?.data) ? result.data : [];
  const row = rows[0] || null;
  const isDefault = DEFAULT_COMMUNITIES.includes(result?.community);
  const communityInfo = result?.community ? ` [community=${isDefault ? result.community : 'custom'}]` : '';
  return [{
    port: 161, protocol: 'udp', service: 'snmp',
    program: result?.program || 'Unknown', version: result?.version || 'Unknown',
    status: result?.up ? 'open' : 'no response',
    info: row?.probe_info ? `${row.probe_info}${communityInfo}` : communityInfo || null,
    banner: row?.response_banner ? `${row.response_banner}${communityInfo}` : null,
    community: result?.community || null,
    source: 'snmp', evidence: rows, authoritative: true
  }];
}
