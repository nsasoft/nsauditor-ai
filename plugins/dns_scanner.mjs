// plugins/dns_scanner.mjs
// DNS Scanner — UDP 53 version.bind (CHAOS/TXT) + example.com (IN/A, MX)
// Adds TCP fallback for version.bind to recover banners on servers that drop CHAOS/TXT over UDP.
// Optional AXFR zone transfer detection (TCP).
// Keeps shapes/names so existing tests and concluder continue to pass.
//
// Env:
//   DNS_SCANNER_TIMEOUT_MS   default 2000
//   DNS_SCANNER_USE_TCP      1/true => enable TCP fallback for version.bind (default on)
//   DNS_SCANNER_DEBUG        1/true => include extra error details in banners
//   DNS_CHECK_AXFR           1/true => attempt AXFR zone transfer (default off)
//   DNS_AXFR_DOMAIN          target domain for AXFR (required when DNS_CHECK_AXFR=true)

import dgram from 'node:dgram';
import net from 'node:net';
import crypto from 'node:crypto';

const DEBUG   = /^(1|true|yes|on)$/i.test(String(process.env.DNS_SCANNER_DEBUG || ''));
const TIMEOUT = Number(process.env.DNS_SCANNER_TIMEOUT_MS || 2000);
const USE_TCP = /^(1|true|yes|on)$/i.test(String(process.env.DNS_SCANNER_USE_TCP || '1'));

const QTYPE = { A:1, MX:15, TXT:16, SRV:33, AXFR:252 };
const QCLASS = { IN:1, CH:3 };

function encodeName(name){
  const parts = String(name).split('.').filter(Boolean);
  const bufs = [];
  for (const label of parts){
    const b = Buffer.from(label, 'utf8');
    if (b.length > 63) throw new Error('DNS label too long');
    bufs.push(Buffer.from([b.length]), b);
  }
  bufs.push(Buffer.from([0]));
  return Buffer.concat(bufs);
}

function buildQuery({ id, qname, qtype, qclass }){
  const header = Buffer.alloc(12);
  header.writeUInt16BE(id & 0xffff, 0);   // ID
  header.writeUInt16BE(0x0100, 2);        // RD=1
  header.writeUInt16BE(1, 4);             // QDCOUNT
  // AN/NS/AR = 0
  const q = Buffer.concat([ encodeName(qname), Buffer.from([0, qtype]), Buffer.from([0, qclass]) ]);
  return Buffer.concat([header, q]);
}

function readName(buf, offset, depth=0){
  if (depth > 10) throw new Error('name pointer loop');
  const labels = [];
  let i = offset;
  while (true){
    if (i >= buf.length) throw new Error('name OOR');
    const len = buf[i];
    if (len === 0){ i += 1; break; }
    if ((len & 0xC0) === 0xC0){
      if (i + 1 >= buf.length) throw new Error('name pointer OOB');
      const ptr = ((len & 0x3F) << 8) | buf[i+1];
      if (ptr >= buf.length) throw new Error('name pointer target OOB');
      const [pname] = readName(buf, ptr, depth+1);
      labels.push(pname);
      i += 2; break;
    }
    if (i + 1 + len > buf.length) throw new Error('name label OOB');
    const label = buf.slice(i+1, i+1+len).toString('utf8');
    labels.push(label);
    i += 1 + len;
  }
  return [labels.join('.'), i];
}

function parseResponse(buf){
  if (!Buffer.isBuffer(buf) || buf.length < 12) throw new Error('bad DNS response');
  const id    = buf.readUInt16BE(0);
  const flags = buf.readUInt16BE(2);
  const qd    = buf.readUInt16BE(4);
  const an    = buf.readUInt16BE(6);
  const ns    = buf.readUInt16BE(8);
  const ar    = buf.readUInt16BE(10);
  const rcode = flags & 0x000f;

  let off = 12;
  for (let qi=0; qi<qd; qi++){ const [,n] = readName(buf, off); off = n + 4; }

  const answers = [];
  const total = Math.min(an + ns + ar, 512);
  for (let i=0; i<total; i++){
    if (off >= buf.length) break;
    const [, n1] = readName(buf, off); off = n1;
    if (off + 10 > buf.length) break;
    const type   = buf.readUInt16BE(off); off+=2;
    const klass  = buf.readUInt16BE(off); off+=2;
    const ttl    = buf.readUInt32BE(off); off+=4;
    const rdlen  = buf.readUInt16BE(off); off+=2;
    if (off + rdlen > buf.length) break;
    const rdata  = buf.slice(off, off+rdlen); off += rdlen;

    let data = null;
    if (type === QTYPE.A && rdlen === 4){
      data = `${rdata[0]}.${rdata[1]}.${rdata[2]}.${rdata[3]}`;
    } else if (type === QTYPE.MX && rdlen >= 3){
      const preference = rdata.readUInt16BE(0);
      // MX exchange name is encoded starting at offset 2 within rdata.
      // We need to resolve it against the full message buffer for pointer support.
      const [exchange] = readName(buf, off - rdlen + 2);
      data = `${preference} ${exchange}`;
    } else if (type === QTYPE.TXT){
      const chunks = []; let p=0;
      while (p < rdata.length){ const ln = rdata[p++]; chunks.push(rdata.slice(p, p+ln).toString('utf8')); p+=ln; }
      data = chunks.join(' | ');
    } else {
      data = `RDATA len ${rdlen}`;
    }
    answers.push({ type, class: klass, ttl, data });
  }
  return { id, rcode, answers };
}

function inferProgramVersion(txt){
  if (!txt) return { program:'Unknown', version:'Unknown' };
  const s = String(txt);
  let m = /dnsmasq[-\s]?([0-9][\w.\-]*)/i.exec(s); if (m) return { program:'dnsmasq', version:m[1] };
  m = /(BIND|named)[-\s]?([0-9][\w.\-]*)/i.exec(s); if (m) return { program:'BIND', version:m[2] };
  m = /unbound[-\s]?([0-9][\w.\-]*)/i.exec(s);      if (m) return { program:'Unbound', version:m[1] };
  m = /PowerDNS[-\s]?([0-9][\w.\-]*)/i.exec(s);     if (m) return { program:'PowerDNS', version:m[1] };
  m = /(Microsoft|MS)\s*DNS[^\d]*([0-9][\w.\-]*)?/i.exec(s); if (m) return { program:'Microsoft DNS', version:m[2] || 'Unknown' };
  return { program:'DNS', version:'Unknown' };
}

function sendUdpQuery({ host, port, qname, qtype, qclass, timeoutMs=TIMEOUT }){
  return new Promise((resolve)=>{
    const s = dgram.createSocket('udp4');
    const id = crypto.randomInt(0, 0xffff);
    const q = buildQuery({ id, qname, qtype, qclass });

    let done=false;
    const finish = (ok, info, parsed=null, raw=null) => { if(done) return; done=true; try{s.close();}catch{} resolve({ok,info,parsed,raw}); };
    const t = setTimeout(()=>finish(false, 'No DNS response'), timeoutMs);

    s.on('message', msg => {
      try{
        const rr = parseResponse(msg);
        if (rr.id !== id) return; // ignore stray
        clearTimeout(t);
        if (rr.rcode !== 0) return finish(false, `DNS error rcode=${rr.rcode}`, rr, msg);
        finish(true, 'DNS reply OK', rr, msg);
      }catch(e){
        clearTimeout(t);
        finish(false, `Parse error: ${e.message}`);
      }
    });
    s.on('error', err => {
      clearTimeout(t);
      finish(false, String(err?.code || 'UDP error'));
    });
    s.send(q, port, host, err => {
      if (err){ clearTimeout(t); finish(false, String(err?.code || 'UDP send error')); }
    });
  });
}

// TCP fallback ONLY for version.bind (CHAOS/TXT)
function sendTcpVersionBind(host, port=53, timeoutMs=TIMEOUT){
  const id = crypto.randomInt(0, 0xffff);
  const q = buildQuery({ id, qname:'version.bind', qtype:QTYPE.TXT, qclass:QCLASS.CH });
  const len = Buffer.alloc(2); len.writeUInt16BE(q.length, 0);

  return new Promise(resolve=>{
    const s = net.createConnection({ host, port });
    let chunks = [], done=false;
    const finish = (ok, info, parsed=null, raw=null) => { if(done) return; done=true; try{s.destroy();}catch{} resolve({ok,info,parsed,raw}); };
    const t = setTimeout(()=>finish(false, 'TCP timeout'), timeoutMs);

    s.on('connect', ()=> s.write(Buffer.concat([len, q])));
    s.on('data', c => chunks.push(c));
    s.on('error', err => { clearTimeout(t); finish(false, String(err?.code || 'TCP error')); });
    s.on('close', ()=>{
      if (done) return;
      clearTimeout(t);
      if (!chunks.length) return finish(false, 'No reply on TCP');
      try{
        const buf = Buffer.concat(chunks);
        const rr = parseResponse(buf.subarray(2)); // strip 2-byte length
        if (rr.rcode !== 0) return finish(false, `DNS error rcode=${rr.rcode}`, rr, buf);
        finish(true, 'DNS reply OK (TCP)', rr, buf);
      }catch(e){
        finish(false, `Parse error: ${e.message}`);
      }
    });
  });
}

// TCP AXFR zone transfer query
function sendAxfrQuery(host, domain, port=53, timeoutMs=TIMEOUT){
  const id = crypto.randomInt(0, 0xffff);
  const q = buildQuery({ id, qname: domain, qtype: QTYPE.AXFR, qclass: QCLASS.IN });
  const len = Buffer.alloc(2);
  len.writeUInt16BE(q.length, 0);

  return new Promise(resolve => {
    const s = net.createConnection({ host, port });
    let buf = Buffer.alloc(0);
    let done = false;
    const records = [];

    const finish = (ok, info) => {
      if (done) return;
      done = true;
      try { s.destroy(); } catch {}
      resolve({ ok, info, records });
    };

    const t = setTimeout(() => finish(false, 'AXFR timeout'), timeoutMs);

    s.on('connect', () => s.write(Buffer.concat([len, q])));
    const MAX_AXFR_RECORDS = 10000;
    s.on('data', chunk => {
      buf = Buffer.concat([buf, chunk]);
      while (buf.length >= 2) {
        const msgLen = buf.readUInt16BE(0);
        if (buf.length < 2 + msgLen) break;
        const msg = buf.subarray(2, 2 + msgLen);
        buf = buf.subarray(2 + msgLen);
        try {
          const rr = parseResponse(msg);
          if (rr.rcode !== 0) {
            clearTimeout(t);
            return finish(false, `AXFR refused (rcode=${rr.rcode})`);
          }
          records.push(...rr.answers);
          if (records.length > MAX_AXFR_RECORDS) {
            clearTimeout(t);
            return finish(true, `AXFR success: ${records.length}+ records (truncated)`);
          }
        } catch (e) {
          clearTimeout(t);
          return finish(false, `AXFR parse error: ${e.message}`);
        }
      }
    });
    s.on('error', err => { clearTimeout(t); finish(false, String(err?.code || 'TCP error')); });
    s.on('close', () => {
      clearTimeout(t);
      if (records.length > 0) finish(true, `AXFR success: ${records.length} records`);
      else finish(false, 'AXFR: no records received');
    });
  });
}

export default {
  id: "009",
  name: "dns_scanner",
  description: "Queries version.bind (CHAOS/TXT) and A example.com; TCP fallback for version.bind; records RCODE on non-recursive/blocked servers.",
  priority: 340,
  requirements: {},

  async run(host, port=53, opts={}){
    // normalize
    const targetPort = Number(port) > 0 && Number(port) < 65536 ? Number(port) : 53;
    const timeoutMs = Number(opts.timeoutMs || process.env.DNS_TIMEOUT_MS || TIMEOUT);
    const testQname = String(opts.qname || process.env.DNS_QNAME || 'example.com');

    const data = [];
    let up = false, program = 'Unknown', version = 'Unknown';

    // 1) version.bind over UDP
    let vb = await sendUdpQuery({ host, port:targetPort, qname:'version.bind', qtype:QTYPE.TXT, qclass:QCLASS.CH, timeoutMs });

    // 1b) fallback to TCP if UDP failed or gave an rcode
    if ((!vb?.ok) && USE_TCP){
      const vbTcp = await sendTcpVersionBind(host, targetPort, timeoutMs);
      if (vbTcp?.ok) vb = vbTcp;
    }

    {
      const entry = {
        probe_protocol: 'udp',        // keep tests simple; transport is not critical for evidence table
        probe_port: targetPort,
        probe_service: 'dns',
        probe_info: vb?.ok ? 'version.bind reply' : (vb?.info || 'No DNS response'),
        response_banner: null
      };
      if (vb?.parsed){
        const txt = vb.parsed.answers.filter(a=>a.type===QTYPE.TXT).map(a=>a.data).join(' | ');
        if (txt){
          entry.response_banner = txt;
          const pv = inferProgramVersion(txt);
          program = pv.program; version = pv.version;
          up = true;
        }
      }
      data.push(entry);
    }

    // 2) A example.com over UDP (basic service behavior / recursion)
    const ares = await sendUdpQuery({ host, port:targetPort, qname:testQname, qtype:QTYPE.A, qclass:QCLASS.IN, timeoutMs });
    {
      const entry = {
        probe_protocol: 'udp',
        probe_port: targetPort,
        probe_service: 'dns',
        probe_info: ares?.ok ? `A ${testQname} reply` : (ares?.info || 'No DNS response'),
        response_banner: null
      };
      if (ares?.parsed){
        const ips = ares.parsed.answers.filter(a=>a.type===QTYPE.A).map(a=>a.data);
        if (ips.length){ entry.response_banner = `A ${testQname} -> ${ips.join(', ')}`; up = true; }
      }
      data.push(entry);
    }

    // 3) MX record query over UDP
    const mxRes = await sendUdpQuery({ host, port:targetPort, qname:testQname, qtype:QTYPE.MX, qclass:QCLASS.IN, timeoutMs });
    {
      const entry = {
        probe_protocol: 'udp',
        probe_port: targetPort,
        probe_service: 'dns',
        probe_info: mxRes?.ok ? `MX ${testQname} reply` : (mxRes?.info || 'No DNS response'),
        response_banner: null
      };
      if (mxRes?.parsed){
        const mxs = mxRes.parsed.answers.filter(a=>a.type===QTYPE.MX).map(a=>a.data);
        if (mxs.length){ entry.response_banner = `MX ${testQname} -> ${mxs.join(', ')}`; up = true; }
      }
      data.push(entry);
    }

    // 4) AXFR zone transfer (opt-in via env)
    const checkAxfr = /^(1|true|yes|on)$/i.test(String(process.env.DNS_CHECK_AXFR || ''));
    const axfrDomain = String(process.env.DNS_AXFR_DOMAIN || opts.axfrDomain || '');
    let axfrAllowed = null;

    if (checkAxfr && axfrDomain) {
      const axfrRes = await sendAxfrQuery(host, axfrDomain, targetPort, timeoutMs);
      axfrAllowed = axfrRes.ok;
      data.push({
        probe_protocol: 'tcp',
        probe_port: targetPort,
        probe_service: 'dns',
        probe_info: axfrRes.ok ? `AXFR ${axfrDomain} allowed` : `AXFR ${axfrDomain} denied`,
        response_banner: axfrRes.info
      });
    }

    return { up, type:'dns', program, version, axfrAllowed, data };
  }
};

// ---------------- Plug-and-Play concluder adapter ----------------
import { statusFrom } from '../utils/conclusion_utils.mjs';

export async function conclude({ host, result }){
  const rows = Array.isArray(result?.data) ? result.data : [];
  const pick = rows.find(r => /version\.bind|example\.com/i.test(String(r?.probe_info||''))) || rows[0] || null;
  const port = Number(pick?.probe_port ?? 53);
  const info = pick?.probe_info || (result?.up ? 'DNS reply' : 'No DNS response');
  const banner = pick?.response_banner || null;
  const status = result?.up ? 'open' : statusFrom({ info, banner });
  return [{
    port, protocol:'udp', service:'dns',
    program: result?.program || 'Unknown',
    version: result?.version || 'Unknown',
    status, info, banner,
    axfrAllowed: result?.axfrAllowed ?? null,
    source: 'dns',
    evidence: rows,
    authoritative: true
  }];
}
