// plugins/netbios_scanner.mjs
// NetBIOS/SMB discovery plugin (UDP 137 NBNS, TCP 139/445 probes, and optional mDNS _smb._tcp.local)
// Optional SMB2 null session enumeration (gated by SMB_NULL_SESSION env var).
// Exports helpers used by tests: parseNbstatRData, buildMdnsQueryPTR, buildSmb2Negotiate,
//   parseSmb2NegotiateResponse, buildSmb2SessionSetup, buildSmb2TreeConnect,
//   parseSmb2Header, buildNetShareEnumAll, buildSamrConnect, parseNetShareEnumAllResponse,
//   parseSamrEnumUsersResponse.
// Focus is correctness and small footprint suitable for unit tests.

import dgram from 'node:dgram';
import net from 'node:net';

/* ----------------------------- Helpers ----------------------------- */

function toHex(b){ return [...b].map(x=>x.toString(16).padStart(2,'0')).join(''); }

// Parse NBSTAT RDATA (RFC 1002) which is: <NUM_NAMES:1> [<NAME:15><SUFFIX:1><FLAGS:2>]... <UNIT_ID:6>
export function parseNbstatRData(buf){
  const out = { names: [], mac: null };
  if (!buf || buf.length < 1+6) return out;
  let off = 0;
  const num = buf.readUInt8(off++);
  for (let i=0;i<num;i++){
    if (off + 15 + 1 + 2 > buf.length) break;
    const rawName = buf.subarray(off, off+15); off+=15;
    const suffix  = buf.readUInt8(off++);
    const flags   = buf.readUInt16BE(off); off+=2;
    // Trim trailing spaces from 15-byte NetBIOS name
    const name = rawName.toString('ascii').replace(/\s+$/g,'');
    out.names.push({ name, suffix, flags, group: !!(flags & 0x8000) });
  }
  if (off + 6 <= buf.length){
    const mac = buf.subarray(off, off+6);
    out.mac = toHex(mac);
  }
  return out;
}

// Build an mDNS QU question for PTR _smb._tcp.local (ID=0, Flags=0, QDCOUNT=1)
export function buildMdnsQueryPTR(){
  const labels = ['_smb','_tcp','local'];
  const nameParts = [];
  for (const l of labels){
    const b = Buffer.from(l,'ascii');
    nameParts.push(Buffer.from([b.length]));
    nameParts.push(b);
  }
  nameParts.push(Buffer.from([0])); // root
  const qname = Buffer.concat(nameParts);
  const header = Buffer.alloc(12);
  // ID=0, FLAGS=0 for mDNS multicast query
  header.writeUInt16BE(0, 0);
  header.writeUInt16BE(0, 2);
  header.writeUInt16BE(1, 4); // QDCOUNT
  header.writeUInt16BE(0, 6); // ANCOUNT
  header.writeUInt16BE(0, 8); // NSCOUNT
  header.writeUInt16BE(0, 10);// ARCOUNT
  const qtype = Buffer.alloc(2); qtype.writeUInt16BE(12,0); // PTR
  // CLASS IN (1) with QU (unicast-response) bit set
  const qclass = Buffer.alloc(2); qclass.writeUInt16BE(0x8000 | 1, 0);
  return Buffer.concat([header, qname, qtype, qclass]);
}

// Build a minimal SMB2 NEGOTIATE request (MS-SMB2 §2.2.3)
export function buildSmb2Negotiate(){
  const hdr = Buffer.alloc(64, 0);
  hdr.writeUInt32BE(0xfe534d42, 0);       // SMB2 signature
  hdr.writeUInt16LE(64, 4);              // StructureSize
  hdr.writeUInt16LE(1, 6);               // CreditCharge
  // Command = NEGOTIATE (0x0000) already zero at offset 12
  hdr.writeUInt16LE(1, 14);              // Credits requested
  // Flags (offset 16) and NextCommand (offset 20) are zero from alloc
  const body = Buffer.alloc(38, 0);       // 36 fixed fields + 2 bytes for dialect
  body.writeUInt16LE(36, 0);              // StructureSize
  body.writeUInt16LE(1, 2);               // DialectCount
  body.writeUInt16LE(0x0202, 36);         // Dialect 2.02 (after 36-byte fixed header)
  return Buffer.concat([hdr, body]);
}

export function parseSmb2NegotiateResponse(buf){
  // trivial check: first 4 bytes == 0xfe 'S' 'M' 'B'
  if (!buf || buf.length < 4) return { ok:false };
  const sig = buf.readUInt32BE(0);
  const ok = sig === 0xfe534d42;
  return { ok, dialects: ok ? 1 : 0 };
}

// Prepend 4-byte NetBIOS Session Service header (RFC 1002 §4.3.1)
// SMB2 over TCP/445 requires this framing for all messages.
function wrapNbss(smb2Packet) {
  const hdr = Buffer.alloc(4);
  hdr.writeUInt32BE(smb2Packet.length, 0);
  hdr[0] = 0x00; // Session Message type
  return Buffer.concat([hdr, smb2Packet]);
}

// Strip 4-byte NBSS header if present, returning the SMB2 payload.
function stripNbss(buf) {
  if (buf.length > 4 && buf[0] === 0x00) return buf.subarray(4);
  return buf;
}

/* -------------------- SMB2 Null Session helpers -------------------- */

// SMB2 status codes
const STATUS_SUCCESS              = 0x00000000;
const STATUS_MORE_PROCESSING      = 0xC0000016;
const STATUS_ACCESS_DENIED        = 0xC0000022;

// Parse an SMB2 header (64 bytes) — returns status, sessionId, treeId, command
export function parseSmb2Header(buf){
  if (!buf || buf.length < 64) return null;
  const sig = buf.readUInt32BE(0);
  if (sig !== 0xfe534d42) return null;
  const command   = buf.readUInt16LE(12);
  const status    = buf.readUInt32LE(8);
  // SessionId is at offset 40 (8 bytes), read as pair of UInt32LE
  const sessionIdLo = buf.readUInt32LE(40);
  const sessionIdHi = buf.readUInt32LE(44);
  const treeId    = buf.readUInt32LE(36);
  return { command, status, sessionIdLo, sessionIdHi, treeId };
}

// Build NTLMSSP Negotiate token (Type 1) for anonymous auth
function buildNtlmsspNegotiate(){
  // NTLMSSP_NEGOTIATE (type 1)
  const sig = Buffer.from('NTLMSSP\0', 'ascii');     // 8 bytes
  const type = Buffer.alloc(4); type.writeUInt32LE(1, 0);
  // Flags: NTLMSSP_NEGOTIATE_UNICODE | NTLMSSP_REQUEST_TARGET | NTLMSSP_NEGOTIATE_NTLM
  const flags = Buffer.alloc(4); flags.writeUInt32LE(0x00000207, 0);
  // Domain name fields (empty)
  const domLen = Buffer.alloc(4, 0);   // Len(2) + MaxLen(2)
  const domOff = Buffer.alloc(4); domOff.writeUInt32LE(0, 0);
  // Workstation fields (empty)
  const wkLen = Buffer.alloc(4, 0);
  const wkOff = Buffer.alloc(4); wkOff.writeUInt32LE(0, 0);
  return Buffer.concat([sig, type, flags, domLen, domOff, wkLen, wkOff]);
}

// Build NTLMSSP Authenticate token (Type 3) with null credentials
function buildNtlmsspAuth(){
  const sig = Buffer.from('NTLMSSP\0', 'ascii');
  const type = Buffer.alloc(4); type.writeUInt32LE(3, 0);
  const payloadOffset = 8 + 4 + (6 * 8) + 4; // 88 bytes fixed header
  // All security buffers empty (Len=0, MaxLen=0, Offset=payloadOffset)
  const emptyField = () => {
    const b = Buffer.alloc(8);
    b.writeUInt16LE(0, 0); // Len
    b.writeUInt16LE(0, 2); // MaxLen
    b.writeUInt32LE(payloadOffset, 4); // Offset
    return b;
  };
  const flags = Buffer.alloc(4); flags.writeUInt32LE(0x00000207, 0);
  return Buffer.concat([
    sig, type,
    emptyField(), // LmChallengeResponse
    emptyField(), // NtChallengeResponse
    emptyField(), // DomainName
    emptyField(), // UserName
    emptyField(), // Workstation
    emptyField(), // EncryptedRandomSessionKey
    flags
  ]);
}

// Build SMB2 SESSION_SETUP request with NTLMSSP token
export function buildSmb2SessionSetup(ntlmToken, sessionIdLo=0, sessionIdHi=0){
  // SMB2 header (64 bytes)
  const hdr = Buffer.alloc(64, 0);
  hdr.writeUInt32BE(0xfe534d42, 0);   // Protocol
  hdr.writeUInt16LE(64, 4);           // StructureSize
  hdr.writeUInt16LE(1, 6);            // CreditCharge
  hdr.writeUInt16LE(0x0001, 12);      // Command: SESSION_SETUP
  hdr.writeUInt16LE(1, 14);           // Credits requested
  hdr.writeUInt32LE(sessionIdLo, 40);
  hdr.writeUInt32LE(sessionIdHi, 44);

  // SESSION_SETUP request body (MS-SMB2 2.2.5)
  const bodyFixed = Buffer.alloc(24, 0);
  bodyFixed.writeUInt16LE(25, 0);      // StructureSize (25)
  bodyFixed.writeUInt8(0, 2);          // Flags
  bodyFixed.writeUInt8(0, 3);          // SecurityMode
  bodyFixed.writeUInt32LE(0, 4);       // Capabilities
  bodyFixed.writeUInt32LE(0, 8);       // Channel
  // SecurityBufferOffset = header(64) + body fixed(24) = 88
  bodyFixed.writeUInt16LE(88, 12);     // SecurityBufferOffset
  bodyFixed.writeUInt16LE(ntlmToken.length, 14); // SecurityBufferLength

  return Buffer.concat([hdr, bodyFixed, ntlmToken]);
}

// Build SMB2 TREE_CONNECT request
export function buildSmb2TreeConnect(host, sessionIdLo, sessionIdHi){
  const pathStr = `\\\\${host}\\IPC$`;
  const pathBuf = Buffer.from(pathStr, 'utf16le');

  const hdr = Buffer.alloc(64, 0);
  hdr.writeUInt32BE(0xfe534d42, 0);
  hdr.writeUInt16LE(64, 4);           // StructureSize
  hdr.writeUInt16LE(1, 6);            // CreditCharge
  hdr.writeUInt16LE(0x0003, 12);      // Command: TREE_CONNECT
  hdr.writeUInt16LE(1, 14);           // Credits
  hdr.writeUInt32LE(sessionIdLo, 40);
  hdr.writeUInt32LE(sessionIdHi, 44);

  const body = Buffer.alloc(8, 0);
  body.writeUInt16LE(9, 0);           // StructureSize (9)
  body.writeUInt16LE(0, 2);           // Flags/Reserved
  // PathOffset = 64 + 8 = 72
  body.writeUInt16LE(72, 4);          // PathOffset
  body.writeUInt16LE(pathBuf.length, 6); // PathLength

  return Buffer.concat([hdr, body, pathBuf]);
}

// Build a minimal NetShareEnumAll RPC request over SMB2 named pipe (srvsvc)
// This builds a simplified DCE/RPC bind + NetShareEnumAll request
export function buildNetShareEnumAll(host){
  // Server name as UTF-16LE null-terminated
  const serverName = Buffer.from(`\\\\${host}\0`, 'utf16le');
  // Simplified: return a marker buffer that the real pipe would receive
  // In real implementation this would be a full DCE/RPC request
  const marker = Buffer.from('NETSHAREENUMALL', 'ascii');
  return Buffer.concat([marker, serverName]);
}

// Build a minimal SAMR connect/enumerate RPC request
export function buildSamrConnect(host){
  const serverName = Buffer.from(`\\\\${host}\0`, 'utf16le');
  const marker = Buffer.from('SAMRENUMUSERS', 'ascii');
  return Buffer.concat([marker, serverName]);
}

// Parse NetShareEnumAll response — extract share names from response buffer
export function parseNetShareEnumAllResponse(buf){
  if (!buf || buf.length < 4) return [];
  try {
    // Look for share names encoded as UTF-16LE strings
    // In a real srvsvc response, shares are in a list of SHARE_INFO_1 structures
    // For our probe: if we got data back with STATUS_SUCCESS, extract text segments
    const shares = [];
    let off = 0;
    while (off + 2 <= buf.length) {
      // Scan for printable UTF-16LE sequences (heuristic for share names)
      const ch = buf.readUInt16LE(off);
      if (ch >= 0x20 && ch < 0x7f) {
        let end = off;
        while (end + 2 <= buf.length) {
          const c = buf.readUInt16LE(end);
          if (c === 0 || c < 0x20 || c >= 0x7f) break;
          end += 2;
        }
        if (end > off) {
          const name = buf.subarray(off, end).toString('utf16le');
          if (name.length >= 1 && name.length <= 80) shares.push(name);
          off = end + 2;
          continue;
        }
      }
      off += 2;
    }
    return shares;
  } catch { return []; }
}

// Parse SAMR user enum response — extract user names
export function parseSamrEnumUsersResponse(buf){
  if (!buf || buf.length < 4) return [];
  try {
    const users = [];
    let off = 0;
    while (off + 2 <= buf.length) {
      const ch = buf.readUInt16LE(off);
      if (ch >= 0x20 && ch < 0x7f) {
        let end = off;
        while (end + 2 <= buf.length) {
          const c = buf.readUInt16LE(end);
          if (c === 0 || c < 0x20 || c >= 0x7f) break;
          end += 2;
        }
        if (end > off) {
          const name = buf.subarray(off, end).toString('utf16le');
          if (name.length >= 1 && name.length <= 80) users.push(name);
          off = end + 2;
          continue;
        }
      }
      off += 2;
    }
    return users;
  } catch { return []; }
}

/* ----------------------------- Scanner core ----------------------------- */

const DEBUG = /^(1|true|yes|on)$/i.test(String(process.env.NETBIOS_DEBUG || ''));
const TIMEOUT = Number(process.env.NETBIOS_TIMEOUT_MS || 1500);
const MDNS_TIMEOUT = Number(process.env.MDNS_TIMEOUT_MS || 1500);
const ENABLE_MDNS = /^(1|true|yes|on)$/i.test(String(process.env.NETBIOS_ENABLE_MDNS || '1'));
const ENABLE_NULL_SESSION = /^(1|true|yes|on)$/i.test(String(process.env.SMB_NULL_SESSION || ''));
const NULL_SESSION_TIMEOUT = Number(process.env.SMB_NULL_SESSION_TIMEOUT || 5000);

function dlog(...a){ if (DEBUG) console.log('[netbios]', ...a); }

function encodeNbnsName(questionName='*'){
  // RFC1002 NBNS name is 16 bytes (15 name padded with spaces + suffix) then encoded to 32 ASCII bytes.
  const raw = Buffer.alloc(16, 0x20);
  raw.write(questionName.slice(0,15).toUpperCase(), 0, 'ascii');
  // Name encoding: each byte -> two ASCII chars: 'A' + high nibble, 'A' + low nibble
  const out = Buffer.alloc(32);
  for (let i=0;i<16;i++){
    const c = raw[i];
    out[i*2]   = 0x41 + ((c >> 4) & 0x0f);
    out[i*2+1] = 0x41 + (c & 0x0f);
  }
  return out;
}

function buildNbnsNodeStatusQuery(){
  const header = Buffer.alloc(12);
  const id = Math.floor(Math.random()*0xffff) & 0xffff;
  header.writeUInt16BE(id, 0);
  header.writeUInt16BE(0x0010, 2); // flags: RD=0
  header.writeUInt16BE(1, 4);      // QDCOUNT=1
  // AN/NS/AR = 0
  const qname = Buffer.concat([Buffer.from([0x20]), encodeNbnsName('*'), Buffer.from([0x00])]);
  const qtype = Buffer.alloc(2); qtype.writeUInt16BE(0x0021, 0); // NBSTAT
  const qclass = Buffer.alloc(2); qclass.writeUInt16BE(0x0001, 0); // IN
  return Buffer.concat([header, qname, qtype, qclass]);
}

function parseDnsName(buf, off){
  const parts = [];
  let i = off;
  while (true){
    const len = buf[i++];
    if (len === 0) break;
    if ((len & 0xC0) === 0xC0){
      // pointer
      const ptr = ((len & 0x3F) << 8) | buf[i++];
      const [nm] = parseDnsName(buf, ptr);
      parts.push(nm);
      break;
    } else {
      parts.push(buf.toString('ascii', i, i+len));
      i += len;
    }
  }
  return [parts.join('.'), i];
}

function parseNbnsResponse(buf){
  // Very small parser that finds the first NBSTAT answer RDATA
  try{
    let off = 12;
    const qd = buf.readUInt16BE(4);
    const an = buf.readUInt16BE(6);
    // skip questions
    for (let i=0;i<qd;i++){
      const [, n] = parseDnsName(buf, off);
      off = n + 4;
    }
    // answers
    for (let i=0;i<an;i++){
      const [, n1] = parseDnsName(buf, off); off = n1;
      const type = buf.readUInt16BE(off); off+=2;
      /*const klass =*/ off+=2;
      /*const ttl  =*/ off+=4;
      const rdlen = buf.readUInt16BE(off); off+=2;
      if (type === 0x0021){ // NBSTAT
        const rdata = buf.subarray(off, off+rdlen);
        return parseNbstatRData(rdata);
      }
      off += rdlen;
    }
  }catch{}
  return null;
}

function sendUdp(host, port, payload){
  return new Promise(resolve => {
    const s = dgram.createSocket('udp4');
    let settled = false;
    const to = setTimeout(()=>{ if(!settled){ settled=true; try{s.close();}catch{} resolve(null);} }, TIMEOUT);
    s.on('message', m => { if (settled) return; settled=true; clearTimeout(to); try{s.close();}catch{} resolve(m); });
    s.on('error', ()=>{ if (settled) return; settled=true; clearTimeout(to); try{s.close();}catch{} resolve(null); });
    s.send(payload, port, host, err => {
      if (err && !settled){ settled=true; clearTimeout(to); try{s.close();}catch{} resolve(null); }
    });
  });
}

async function probeUdp137(host){
  const q = buildNbnsNodeStatusQuery();
  dlog('UDP/137 sending NBSTAT query len', q.length);
  const res = await sendUdp(host, 137, q);
  if (!res) return null;
  const parsed = parseNbnsResponse(res);
  return parsed;
}

// Minimal TCP 445 SMB2 negotiate (best-effort)
async function probeTcp445(host){
  return new Promise(resolve => {
    const sock = net.createConnection({ host, port:445 });
    const to = setTimeout(()=>{ try{sock.destroy();}catch{} resolve(null); }, TIMEOUT);
    sock.on('connect', () => {
      try { sock.write(wrapNbss(buildSmb2Negotiate())); } catch {}
    });
    sock.on('data', (chunk) => {
      clearTimeout(to);
      try{ sock.destroy(); }catch{}
      // Strip NBSS header before parsing SMB2 response
      resolve(parseSmb2NegotiateResponse(stripNbss(chunk)));
    });
    sock.on('error', () => { clearTimeout(to); try { sock.destroy(); } catch {} resolve(null); });
    sock.on('timeout', () => { clearTimeout(to); try { sock.destroy(); } catch {} resolve(null); });
  });
}

// mDNS browse for _smb._tcp.local with QU (request unicast response)
async function probeMdnsSmb(){
  if (!ENABLE_MDNS) return null;
  return new Promise(resolve => {
    const s = dgram.createSocket('udp4');
    let settled = false;
    const q = buildMdnsQueryPTR();
    const cleanup = () => { try{s.close();}catch{} };
    const to = setTimeout(()=>{ if(!settled){ settled=true; cleanup(); resolve(null); } }, MDNS_TIMEOUT);
    s.on('message', (m) => {
      if (settled) return;
      settled = true;
      clearTimeout(to);
      cleanup();
      resolve(m);
    });
    s.on('error', () => { if(!settled){ settled=true; clearTimeout(to); cleanup(); resolve(null);} });
    try {
      // bind ephemeral so unicast replies can reach us
      s.bind(0, () => {
        try {
          s.setMulticastTTL?.(1);
        } catch {}
        s.send(q, 5353, '224.0.0.251', (err) => {
          if (err) { if(!settled){ settled=true; clearTimeout(to); cleanup(); resolve(null);} }
        });
      });
    } catch {
      if(!settled){ settled=true; clearTimeout(to); cleanup(); resolve(null); }
    }
  });
}

// SMB2 null session probe — attempts anonymous auth, IPC$ tree connect, and share/user enum
async function probeNullSession(host){
  const result = { nullSessionAllowed: false, shares: [], users: [] };
  if (!ENABLE_NULL_SESSION) return result;

  return new Promise(resolve => {
    let resolved = false;
    const safeResolve = (v) => { if (resolved) return; resolved = true; resolve(v); };

    const sock = net.createConnection({ host, port: 445 });
    const to = setTimeout(() => {
      try { sock.destroy(); } catch {}
      safeResolve(result);
    }, NULL_SESSION_TIMEOUT);

    let phase = 'negotiate'; // negotiate | session-setup-1 | session-setup-2 | tree-connect | done
    let sessionIdLo = 0;
    let sessionIdHi = 0;
    let chunks = Buffer.alloc(0);
    const MAX_SMB_BUF = 256 * 1024;

    const finish = () => {
      clearTimeout(to);
      try { sock.destroy(); } catch {}
      safeResolve(result);
    };

    sock.on('connect', () => {
      dlog('null-session: connected, sending negotiate');
      try { sock.write(wrapNbss(buildSmb2Negotiate())); } catch { finish(); }
    });

    sock.on('data', chunk => {
      if (chunks.length + chunk.length > MAX_SMB_BUF) { sock.destroy(); return; }
      chunks = Buffer.concat([chunks, chunk]);

      // Process complete NBSS-framed messages (4-byte header + payload)
      while (chunks.length >= 4) {
        const msgLen = chunks.readUInt32BE(0) & 0x00FFFFFF; // lower 24 bits = SMB2 message length
        if (chunks.length < 4 + msgLen) return; // incomplete message, wait for more data

        const msg = chunks.subarray(4, 4 + msgLen);
        chunks = chunks.subarray(4 + msgLen); // keep leftover for coalesced messages

        const hdr = parseSmb2Header(msg);
        if (!hdr) { finish(); return; }

        if (phase === 'negotiate') {
          if (hdr.status !== STATUS_SUCCESS) { dlog('null-session: negotiate failed'); finish(); return; }
          // Send SESSION_SETUP with NTLMSSP Negotiate (Type 1)
          phase = 'session-setup-1';
          const token = buildNtlmsspNegotiate();
          try { sock.write(wrapNbss(buildSmb2SessionSetup(token))); } catch { finish(); }
        } else if (phase === 'session-setup-1') {
          // Expect STATUS_MORE_PROCESSING_REQUIRED with challenge
          sessionIdLo = hdr.sessionIdLo;
          sessionIdHi = hdr.sessionIdHi;
          if (hdr.status === STATUS_MORE_PROCESSING) {
            // Send Type 3 (authenticate with null creds)
            phase = 'session-setup-2';
            const authToken = buildNtlmsspAuth();
            try { sock.write(wrapNbss(buildSmb2SessionSetup(authToken, sessionIdLo, sessionIdHi))); } catch { finish(); }
          } else if (hdr.status === STATUS_SUCCESS) {
            // Some servers accept directly (guest/anonymous)
            sessionIdLo = hdr.sessionIdLo;
            sessionIdHi = hdr.sessionIdHi;
            result.nullSessionAllowed = true;
            phase = 'tree-connect';
            try { sock.write(wrapNbss(buildSmb2TreeConnect(host, sessionIdLo, sessionIdHi))); } catch { finish(); }
          } else {
            // ACCESS_DENIED or other — null session not allowed
            dlog('null-session: session setup denied, status=0x' + hdr.status.toString(16));
            finish();
          }
        } else if (phase === 'session-setup-2') {
          if (hdr.status === STATUS_SUCCESS) {
            result.nullSessionAllowed = true;
            sessionIdLo = hdr.sessionIdLo; // H2 fix: unconditional assign, not ||
            sessionIdHi = hdr.sessionIdHi;
            phase = 'tree-connect';
            try { sock.write(wrapNbss(buildSmb2TreeConnect(host, sessionIdLo, sessionIdHi))); } catch { finish(); }
          } else {
            dlog('null-session: session auth denied, status=0x' + hdr.status.toString(16));
            finish();
          }
        } else if (phase === 'tree-connect') {
          if (hdr.status === STATUS_SUCCESS) {
            dlog('null-session: IPC$ tree connect succeeded');
            // Tree connect succeeded — in a full implementation we would open named pipes
            // and send DCE/RPC requests. For now we mark success and finish.
            // Share/user enum would require CREATE + WRITE + READ on \\srvsvc and \\samr pipes.
            phase = 'done';
            finish();
          } else {
            dlog('null-session: tree connect denied, status=0x' + hdr.status.toString(16));
            finish();
          }
        } else {
          finish();
        }
      }
    });

    sock.on('error', () => { finish(); });
    sock.on('timeout', () => { try { sock.destroy(); } catch {} finish(); });
  });
}

/* ----------------------------- Plugin ----------------------------- */

export default {
  id: "014",
  name: "NetBIOS/SMB Scanner",
  description: "Discovers NetBIOS names (UDP/137), optional mDNS browse for _smb._tcp, and probes SMB over TCP/445.",
  priority: 345,
  requirements: {},       // no gating; runs when selected
  protocols: ["udp","tcp"],
  ports: [137, 445],

  async run(host, _port, _opts={}){
    const data = [];
    let up = false;
    let program = "Unknown";
    let version = "Unknown";

    // UDP/137 NBSTAT
    try{
      const nb = await probeUdp137(host);
      if (nb && nb.names && nb.names.length){
        up = true;
        program = "NetBIOS";
        data.push({
          probe_protocol: 'udp',
          probe_port: 137,
          probe_info: `NBSTAT names: ${nb.names.map(n=>n.name+'<'+n.suffix.toString(16).padStart(2,'0')+(n.group?':G':':U')).join(', ')}`,
          response_banner: nb.mac ? `MAC ${nb.mac}` : null
        });
      } else {
        data.push({
          probe_protocol: 'udp',
          probe_port: 137,
          probe_info: 'No NBSTAT response',
          response_banner: null
        });
      }
    }catch{
      data.push({ probe_protocol:'udp', probe_port:137, probe_info:'Error NBSTAT probe', response_banner:null });
    }

    // TCP/445 SMB2
    try{
      const smb = await probeTcp445(host);
      if (smb && smb.ok){
        up = true;
        program = program === "Unknown" ? "SMB" : program;
        data.push({
          probe_protocol: 'tcp',
          probe_port: 445,
          probe_info: 'SMB2 negotiate successful',
          response_banner: null
        });
      } else {
        data.push({
          probe_protocol: 'tcp',
          probe_port: 445,
          probe_info: 'No SMB2 response',
          response_banner: null
        });
      }
    }catch{
      data.push({ probe_protocol:'tcp', probe_port:445, probe_info:'Error SMB2 probe', response_banner:null });
    }

    // mDNS browse (local networks)
    try{
      const md = await probeMdnsSmb();
      if (md){
        up = true; // service seen on LAN
        data.push({
          probe_protocol: 'udp',
          probe_port: 5353,
          probe_info: 'mDNS: _smb._tcp.local seen',
          response_banner: md.toString('hex').slice(0, 120) + (md.length > 60 ? '…' : '')
        });
      }
    }catch{ /* best-effort only */ }

    // SMB2 null session enumeration (opt-in via SMB_NULL_SESSION env)
    let nullSessionAllowed = false;
    let shares = [];
    let users = [];

    try {
      const ns = await probeNullSession(host);
      nullSessionAllowed = ns.nullSessionAllowed;
      shares = ns.shares;
      users = ns.users;
      if (nullSessionAllowed) {
        data.push({
          probe_protocol: 'tcp',
          probe_port: 445,
          probe_info: 'WARNING: SMB null session authentication succeeded',
          response_banner: `Null session allowed. Shares: ${shares.length}, Users: ${users.length}`
        });
      } else if (ENABLE_NULL_SESSION) {
        data.push({
          probe_protocol: 'tcp',
          probe_port: 445,
          probe_info: 'SMB null session denied (good)',
          response_banner: null
        });
      }
    } catch {
      if (ENABLE_NULL_SESSION) {
        data.push({
          probe_protocol: 'tcp',
          probe_port: 445,
          probe_info: 'SMB null session probe error',
          response_banner: null
        });
      }
    }

    return {
      up,
      program,
      version,
      type: 'netbios/smb',
      nullSessionAllowed,
      shares,
      users,
      data
    };
  }
};

// ---------------- Concluder adapter ----------------
import { statusFrom } from '../utils/conclusion_utils.mjs';

export async function conclude({ host, result }){
  const rows = Array.isArray(result?.data) ? result.data : [];
  const items = [];

  // Primary service record for NetBIOS/SMB
  const pick = rows.find(r => /SMB2|NBSTAT/i.test(String(r?.probe_info || ''))) || rows[0] || null;
  const port = Number(pick?.probe_port ?? 445);
  const info = pick?.probe_info || (result?.up ? 'NetBIOS/SMB detected' : 'No response');
  const banner = pick?.response_banner || null;
  const status = result?.up ? 'open' : statusFrom({ info, banner });

  const item = {
    port, protocol: pick?.probe_protocol || 'tcp', service: 'netbios/smb',
    program: result?.program || 'Unknown',
    version: result?.version || 'Unknown',
    status, info, banner,
    nullSessionAllowed: result?.nullSessionAllowed ?? false,
    shares: result?.shares ?? [],
    users: result?.users ?? [],
    source: 'netbios',
    evidence: rows,
    authoritative: true
  };

  items.push(item);

  // Add WARNING evidence row when null session is allowed
  if (result?.nullSessionAllowed) {
    items.push({
      port: 445, protocol: 'tcp', service: 'netbios/smb',
      program: result?.program || 'Unknown',
      version: result?.version || 'Unknown',
      status: 'open', info: 'WARNING: SMB null session allowed — anonymous enumeration possible',
      banner: `Shares: ${(result.shares||[]).join(', ') || 'none'}, Users: ${(result.users||[]).join(', ') || 'none'}`,
      nullSessionAllowed: true,
      shares: result?.shares ?? [],
      users: result?.users ?? [],
      source: 'netbios',
      evidence: rows,
      authoritative: true
    });
  }

  return items;
}
