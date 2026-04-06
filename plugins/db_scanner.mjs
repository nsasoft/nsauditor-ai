// plugins/db_scanner.mjs
// Lightweight DB product/version probes (no external deps). Best-effort banner grabs.
//
// Detects: MySQL/MariaDB (3306), Microsoft SQL Server (1433), PostgreSQL (5432),
// Oracle TNS (1521), MongoDB (27017)

import net from 'node:net';

const TIMEOUT = 2500;
const DB_PORTS = [3306, 1433, 5432, 1521, 27017];

function connect(host, port, timeoutMs) {
  return new Promise((resolve, reject) => {
    const s = new net.Socket();
    let done = false;
    const finish = (err, sock) => { if (done) return; done = true; err ? reject(err) : resolve(sock); };
    s.setNoDelay(true);
    s.setTimeout(timeoutMs, () => { try{s.destroy()}catch{}; finish(new Error('timeout')); });
    s.once('error', (e)=>{ try{s.destroy()}catch{}; finish(e); });
    s.connect(port, host, ()=>finish(null, s));
  });
}

const readAll = (sock, ms) => new Promise(res => {
  const chunks = []; let len = 0; const t = setTimeout(() => end(), ms);
  const end = () => { clearTimeout(t); try{sock.destroy()}catch{}; res(Buffer.concat(chunks, len)); };
  sock.on('data', b => { chunks.push(b); len += b.length; if (len > 65536) end(); });
  sock.on('end', end); sock.on('close', end); sock.on('error', end);
});

// --- MySQL / MariaDB (3306) ---
async function probeMySQL(host, port, timeoutMs) {
  const s = await connect(host, port, timeoutMs);
  const buf = await readAll(s, timeoutMs); // server greets first
  if (buf.length >= 6 && buf[4] === 0x0a) {
    let i = 5;
    while (i < buf.length && buf[i] !== 0x00) i++;
    const verStr = buf.slice(5, i).toString('utf8');
    const lower = verStr.toLowerCase();
    const product = lower.includes('mariadb') ? 'MariaDB' : 'MySQL';
    const m = verStr.match(/\d+\.\d+(?:\.\d+)?/);
    return { type: 'mysql', product, version: m ? m[0] : '', banner: `MySQL greeting: ${verStr}` };
  }
  return { type: 'mysql', product: 'MySQL', version: '', banner: 'MySQL (no greeting parsed)' };
}

// --- Microsoft SQL Server / TDS (1433) ---
async function probeMSSQL(host, port, timeoutMs) {
  const s = await connect(host, port, timeoutMs);
  // Minimal PRELOGIN request (TDS 7.x)
  const prelogin = Buffer.from([
    0x12,0x01,0x00,0x14,0x00,0x00,0x00,0x00, // TDS header
    0x00,0x00,0x06,0x00,0x06,               // VERSION token, offset 0x0006, len 6
    0xFF,                                   // terminator
    0x08,0x00,0x01,0x55,0x00,0x00           // arbitrary client version payload
  ]);
  s.write(prelogin);
  const buf = await readAll(s, timeoutMs);
  const hdrLen = 8;
  if (buf.length <= hdrLen) {
    return { type: 'mssql', product: 'Microsoft SQL Server', version: '', banner: 'TDS (no response)' };
  }
  const payload = buf.slice(hdrLen);
  let i = 0, version = '';
  while (i + 4 < payload.length && payload[i] !== 0xFF) {
    const token   = payload[i];
    const offset  = payload.readUInt16BE(i+1);
    const length  = payload.readUInt16BE(i+3);
    if (token === 0x00 && offset + length <= payload.length && length === 6) {
      const v = payload.slice(offset, offset + length);
      const major = v[0], minor = v[1], build = v.readUInt16BE(2), sub = v.readUInt16BE(4);
      version = `${major}.${minor}.${build}.${sub}`;
      break;
    }
    i += 5;
  }
  const map = { 16: 'SQL Server 2022', 15: 'SQL Server 2019', 14: 'SQL Server 2017', 13: 'SQL Server 2016', 12: 'SQL Server 2014', 11: 'SQL Server 2012', 10: 'SQL Server 2008/R2', 9: 'SQL Server 2005', 8: 'SQL Server 2000' };
  const edition = version ? map[Number(version.split('.')[0])] || '' : '';
  return {
    type: 'mssql',
    product: 'Microsoft SQL Server',
    version,
    banner: version ? `MSSQL PRELOGIN: ${version}${edition ? ' ('+edition+')' : ''}` : 'MSSQL (no version parsed)'
  };
}

// --- PostgreSQL (5432) ---
async function probePostgres(host, port, timeoutMs) {
  const s = await connect(host, port, timeoutMs);
  // StartupMessage: len(4) + protocol 3.0 (4) + params (key\0val\0... \0)
  const params = Buffer.from('user\0pgscan\0database\0postgres\0application_name\0audit-scan\0\0','utf8');
  const startup = Buffer.alloc(8 + params.length);
  startup.writeUInt32BE(startup.length, 0);
  startup.writeUInt32BE(196608, 4); // 3.0
  params.copy(startup, 8);
  s.write(startup);
  const buf = await readAll(s, timeoutMs);
  const text = buf.toString('utf8');
  const m = text.match(/PostgreSQL\s+(\d+\.\d+(?:\.\d+)?)/i);
  const version = m ? m[1] : '';
  return { type: 'postgresql', product: 'PostgreSQL', version, banner: version ? `PostgreSQL ${version}` : 'PostgreSQL (version not disclosed)' };
}

// --- Oracle TNS (1521) — heuristic ---
async function probeOracleTNS(host, port, timeoutMs) {
  const s = await connect(host, port, timeoutMs);
  const buf = await readAll(s, timeoutMs);
  const b = buf.toString('utf8');
  const m = b.match(/version\s*=?\s*([\d.]+)/i);
  return { type: 'oracle', product: 'Oracle Database', version: m ? m[1] : '', banner: b || 'TNS (no banner)' };
}

// --- MongoDB (27017) ---
async function probeMongoDB(host, port, timeoutMs) {
  const s = await connect(host, port, timeoutMs);
  // Build OP_QUERY for { buildInfo: 1 } on admin.$cmd
  const coll = Buffer.from('admin.$cmd\0', 'utf8');
  const doc = buildBsonInt32('buildInfo', 1);
  const headerLen = 16, bodyLen = 4 + coll.length + 4 + 4 + doc.length;
  const buf = Buffer.alloc(headerLen + bodyLen);
  let o = 0;
  buf.writeInt32LE(headerLen + bodyLen, o); o+=4;
  buf.writeInt32LE(1, o); o+=4;     // requestID
  buf.writeInt32LE(0, o); o+=4;     // responseTo
  buf.writeInt32LE(2004, o); o+=4;  // OP_QUERY
  buf.writeInt32LE(0, o); o+=4;     // flags
  coll.copy(buf, o); o += coll.length;
  buf.writeInt32LE(0, o); o+=4;     // numberToSkip
  buf.writeInt32LE(-1, o); o+=4;    // numberToReturn
  doc.copy(buf, o); o += doc.length;
  s.write(buf);
  const rsp = await readAll(s, timeoutMs);
  const txt = rsp.toString('utf8');
  const m = txt.match(/"version"\s*:\s*"([^"]+)"/i);
  const version = m ? m[1] : '';
  return { type: 'mongodb', product: 'MongoDB', version, banner: version ? `MongoDB buildInfo: ${version}` : 'MongoDB (version not disclosed)' };
}

function buildBsonInt32(key, value) {
  const k = Buffer.from(key + '\0', 'utf8');
  const len = 4 + 1 + k.length + 4 + 1; // size + type + key + int32 + terminator
  const b = Buffer.alloc(len);
  let o = 0;
  b[o++] = 0; // filled after
  b[o++] = 0;
  b[o++] = 0;
  b[o++] = 0;
  b[o++] = 0x10; // int32
  k.copy(b, o); o += k.length;
  b.writeInt32LE(value, o); o+=4;
  b[o++] = 0x00;
  b.writeInt32LE(len, 0);
  return b;
}

async function probeDb(host, port, timeoutMs) {
  switch (Number(port)) {
    case 3306:  return await probeMySQL(host, port, timeoutMs);
    case 1433:  return await probeMSSQL(host, port, timeoutMs);
    case 5432:  return await probePostgres(host, port, timeoutMs);
    case 1521:  return await probeOracleTNS(host, port, timeoutMs);
    case 27017: return await probeMongoDB(host, port, timeoutMs);
    default:    return null;
  }
}

export default {
  id: '025',
  name: 'DB Scanner',
  description: 'Identifies common databases on well-known ports and extracts product/version banners.',
  priority: 62,
  requirements: { host: 'up', tcp_open: DB_PORTS },
  protocols: ['tcp'],
  ports: DB_PORTS,
  dependencies: [],

  async run(host, port = 0, opts = {}) {
    const timeoutMs = Number(opts.timeoutMs || process.env.DB_SCAN_TIMEOUT_MS || TIMEOUT);
    const result = {
      up: false,
      program: 'Unknown',
      version: 'Unknown',
      os: null,
      type: 'database',
      data: [],
    };

    try {
      const r = await probeDb(host, Number(port), timeoutMs);
      if (!r) {
        result.data.push({
          probe_protocol: 'tcp',
          probe_port: Number(port),
          probe_info: 'Unsupported DB port',
          response_banner: null
        });
        return result;
      }

      const program =
        r.product || (r.type ? String(r.type).toUpperCase() : 'Unknown');

      result.up = true; // a TCP conversation succeeded
      result.program = program;
      result.version = r.version || 'Unknown';

      result.data.push({
        probe_protocol: 'tcp',
        probe_port: Number(port),
        probe_info: `${program}${r.version ? ' ' + r.version : ''}`.trim(),
        response_banner: r.banner || null
      });

      return result;
    } catch (e) {
      result.data.push({
        probe_protocol: 'tcp',
        probe_port: Number(port),
        probe_info: `TCP error: ${e?.message || e}`,
        response_banner: null
      });
      return result;
    }
  }
};

import { statusFrom } from '../utils/conclusion_utils.mjs';

export async function conclude({ host, result }) {
  const rows = Array.isArray(result?.data) ? result.data : [];
  const svcByPort = { 3306:'mysql', 5432:'postgresql', 1433:'mssql', 1521:'oracle', 27017:'mongodb' };
  const items = [];
  for (const r of rows) {
    if (typeof r?.probe_port !== 'number') continue;
    const port = Number(r.probe_port);
    const proto = String(r?.probe_protocol || 'tcp');
    const service = svcByPort[port] || (proto === 'udp' ? `udp-${port}` : `tcp-${port}`);
    const info = r?.probe_info || null;
    const banner = r?.response_banner || null;
    items.push({
      port, protocol: proto, service,
      program: result?.program || 'Unknown', version: result?.version || 'Unknown',
      status: result?.up ? 'open' : statusFrom({ info, banner }),
      info, banner, source: 'db-scanner', evidence: rows, authoritative: true
    });
  }
  return items;
}
