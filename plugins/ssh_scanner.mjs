// plugins/ssh_scanner.mjs
// SSH Scanner — connects to TCP/22, parses the RFC 4253 identification string,
// and optionally performs SSH_MSG_KEXINIT exchange to extract supported algorithms.

import net from "node:net";
import crypto from "node:crypto";

/** Your parser, kept exactly as provided (minor safety trims) */
export function parseSshBanner(b) {
  const line = (b || "").split(/\r?\n/)[0] || "";
  const m = /^SSH-([0-9.]+)-([^\s]+)(?:\s+(.+))?/.exec(line);
  if (!m) return null;

  const proto = m[1] || "";
  const prodToken = m[2] || "";
  const trail = (m[3] || "").trim();

  let product = prodToken;
  let version = "";
  let pm = /^(OpenSSH)[-_]?(\d[\w.]+)/i.exec(prodToken);
  if (pm) {
    product = pm[1];
    version = pm[2];
  } else {
    pm = /^([A-Za-z]+_?SSH)[-_]?(\d[\w.]+)/.exec(prodToken);
    if (pm) {
      product = pm[1];
      version = pm[2];
    }
  }

  let os = "";
  let osVersion = "";

  // Detect Solaris from Sun_SSH even when there is no trailing comment
  if (/Sun_SSH/i.test(prodToken)) {
    os = "Solaris";
  }

  if (trail) {
    const tok = trail.split(/\s+/)[0];
    const om = /^(Ubuntu|Debian|Raspbian|FreeBSD|OpenBSD|Alpine|Oracle|SUSE|CentOS|RedHat|Arch|Manjaro|Gentoo)-(.+)$/.exec(tok);
    if (om) {
      os = om[1];
      osVersion = om[2];
    }
  }

  return { name: "ssh", product: product || "ssh", version: version || "", proto: proto || "", os, osVersion };
}

/* ---- Weak algorithm definitions ---- */
const WEAK_KEX = ['diffie-hellman-group1-sha1', 'diffie-hellman-group14-sha1', 'diffie-hellman-group-exchange-sha1'];
const WEAK_CIPHERS = ['aes128-cbc', 'aes192-cbc', 'aes256-cbc', '3des-cbc', 'blowfish-cbc', 'arcfour', 'arcfour128', 'arcfour256'];
const WEAK_MACS = ['hmac-sha1', 'hmac-md5', 'hmac-sha1-96', 'hmac-md5-96'];

/* ---- Client KEXINIT offered algorithms ---- */
const CLIENT_KEX = 'curve25519-sha256,ecdh-sha2-nistp256,diffie-hellman-group14-sha256';
const CLIENT_HOST_KEY = 'ssh-ed25519,ecdsa-sha2-nistp256,rsa-sha2-512,rsa-sha2-256';
const CLIENT_ENCRYPTION = 'aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes128-ctr';
const CLIENT_MAC = 'hmac-sha2-256-etm@openssh.com,hmac-sha2-256';
const CLIENT_COMPRESSION = 'none';

/* ---- SSH binary packet helpers ---- */

function encodeNameList(str) {
  const buf = Buffer.from(str, 'utf8');
  const len = Buffer.alloc(4);
  len.writeUInt32BE(buf.length);
  return Buffer.concat([len, buf]);
}

export function buildClientKexinit() {
  const parts = [
    Buffer.from([20]), // SSH_MSG_KEXINIT
    crypto.randomBytes(16), // cookie
    encodeNameList(CLIENT_KEX),
    encodeNameList(CLIENT_HOST_KEY),
    encodeNameList(CLIENT_ENCRYPTION), // c2s
    encodeNameList(CLIENT_ENCRYPTION), // s2c
    encodeNameList(CLIENT_MAC), // c2s
    encodeNameList(CLIENT_MAC), // s2c
    encodeNameList(CLIENT_COMPRESSION), // c2s
    encodeNameList(CLIENT_COMPRESSION), // s2c
    encodeNameList(''), // languages c2s
    encodeNameList(''), // languages s2c
    Buffer.from([0]), // first_kex_packet_follows
    Buffer.alloc(4, 0), // reserved
  ];
  const payload = Buffer.concat(parts);

  // SSH binary packet: [4:packet_length][1:padding_length][payload][padding]
  // padding must be at least 4 bytes and bring total (padding_length + payload + padding) to multiple of 8
  const blockSize = 8;
  const minPadding = 4;
  let paddingLen = blockSize - ((1 + payload.length + minPadding) % blockSize);
  if (paddingLen < minPadding) paddingLen += blockSize;
  // ensure paddingLen stays within a single unsigned byte
  if (paddingLen > 255) paddingLen = minPadding; // defensive

  const packetLength = 1 + payload.length + paddingLen;
  const header = Buffer.alloc(5);
  header.writeUInt32BE(packetLength, 0);
  header[4] = paddingLen;
  const padding = crypto.randomBytes(paddingLen);

  return Buffer.concat([header, payload, padding]);
}

function readNameList(buf, offset) {
  if (offset + 4 > buf.length) return { value: [], next: buf.length };
  const len = buf.readUInt32BE(offset);
  if (offset + 4 + len > buf.length) return { value: [], next: buf.length };
  const str = buf.subarray(offset + 4, offset + 4 + len).toString('utf8');
  return { value: str ? str.split(',') : [], next: offset + 4 + len };
}

export function parseServerKexinit(packetPayload) {
  // packetPayload starts at the SSH_MSG_KEXINIT byte (20)
  if (!packetPayload || packetPayload.length < 17 || packetPayload[0] !== 20) return null;

  let offset = 1 + 16; // skip type + cookie
  const names = [
    'kex', 'hostKey',
    'encryptionC2S', 'encryptionS2C',
    'macC2S', 'macS2C',
    'compressionC2S', 'compressionS2C',
    'languagesC2S', 'languagesS2C',
  ];
  const result = {};
  for (const name of names) {
    const { value, next } = readNameList(packetPayload, offset);
    result[name] = value;
    offset = next;
  }

  return {
    kex: result.kex,
    hostKey: result.hostKey,
    encryption: [...new Set([...result.encryptionC2S, ...result.encryptionS2C])],
    mac: [...new Set([...result.macC2S, ...result.macS2C])],
    compression: [...new Set([...result.compressionC2S, ...result.compressionS2C])],
  };
}

function findWeakAlgorithms(algorithms) {
  if (!algorithms) return [];
  const weak = [];
  for (const a of algorithms.kex || []) { if (WEAK_KEX.includes(a)) weak.push(a); }
  for (const a of algorithms.encryption || []) { if (WEAK_CIPHERS.includes(a)) weak.push(a); }
  for (const a of algorithms.mac || []) { if (WEAK_MACS.includes(a)) weak.push(a); }
  return weak;
}

function extractKexinitPayload(binaryBuf) {
  // Reads an SSH binary packet from the buffer and returns the payload if it's KEXINIT
  if (binaryBuf.length < 5) return null;
  const packetLength = binaryBuf.readUInt32BE(0);
  if (binaryBuf.length < 4 + packetLength) return null;
  const paddingLength = binaryBuf[4];
  const payloadLength = packetLength - 1 - paddingLength;
  if (payloadLength < 1) return null;
  const payload = binaryBuf.subarray(5, 5 + payloadLength);
  if (payload[0] !== 20) return null; // not KEXINIT
  return payload;
}

function shouldCheckAlgorithms() {
  const v = (process.env.SSH_CHECK_ALGORITHMS ?? 'true').toLowerCase();
  return v !== 'false' && v !== '0' && v !== 'no';
}

async function readSshBanner(host, port, timeoutMs) {
  return new Promise((resolve) => {
    const result = {
      up: false,
      program: "Unknown",
      version: "Unknown",
      os: null,
      type: "ssh",
      algorithms: null,
      weakAlgorithms: [],
      data: []
    };

    let done = false;
    let connected = false;
    let rawBuf = Buffer.alloc(0); // always accumulate raw bytes
    let bannerLine = null;
    let phase = 'banner'; // 'banner' | 'kexinit' | 'done'
    let kexTimer = null;

    const finalize = (probe_info, banner = null) => {
      if (done) return;
      done = true;
      phase = 'done';
      if (kexTimer) { clearTimeout(kexTimer); kexTimer = null; }

      // Parse banner if present
      if (banner && typeof banner === "string") {
        const parsed = parseSshBanner(banner);
        if (parsed) {
          result.up = true;
          result.program = parsed.product || "Unknown";
          result.version = parsed.version || "Unknown";
          result.os = parsed.os ? (parsed.osVersion ? `${parsed.os} ${parsed.osVersion}` : parsed.os) : null;
          probe_info = probe_info || `SSH banner parsed (proto ${parsed.proto || "?"})`;
        } else {
          // We got a line but couldn't parse — still useful evidence.
          result.up = connected || !!banner;
          probe_info = probe_info || "SSH banner received (unparsed)";
        }
      }

      // If connection was refused, still mark host up (closed port heuristic)
      if (!banner && !result.up && connected) result.up = true;

      result.data.push({
        probe_protocol: "tcp",
        probe_port: port,
        probe_info,
        response_banner: banner
      });

      resolve(result);
    };

    const tryParseKexinit = (binaryBuf) => {
      const payload = extractKexinitPayload(binaryBuf);
      if (!payload) return false;
      const algorithms = parseServerKexinit(payload);
      if (algorithms) {
        result.algorithms = algorithms;
        result.weakAlgorithms = findWeakAlgorithms(algorithms);
      }
      return true;
    };

    try {
      const sock = net.createConnection({ host, port });

      // Set conservative timeout (env override)
      const to = Number(process.env.SSH_BANNER_TIMEOUT || timeoutMs || 1500);
      sock.setTimeout(Number.isFinite(to) && to > 0 ? to : 1500);
      // Do NOT setEncoding — keep raw Buffers to preserve binary KEXINIT data

      const checkAlgs = shouldCheckAlgorithms();

      sock.on("connect", () => {
        connected = true;
        // For SSH, server sends banner first—no need to send anything
      });

      const MAX_SSH_BUF = 256 * 1024; // 256KB — more than enough for banner + KEXINIT
      sock.on("data", (chunk) => {
        const chunkBuf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
        rawBuf = Buffer.concat([rawBuf, chunkBuf]);
        if (rawBuf.length > MAX_SSH_BUF) {
          try { sock.destroy(); } catch {}
          finalize('SSH data exceeded safe limit', bannerLine);
          return;
        }

        if (phase === 'banner') {
          // Look for newline in the raw buffer (SSH banner is ASCII, terminated by \n)
          const nlIdx = rawBuf.indexOf(0x0a); // \n
          if (nlIdx === -1) return; // need more data

          // Extract the banner line (strip trailing \r if present)
          let lineEnd = nlIdx;
          if (lineEnd > 0 && rawBuf[lineEnd - 1] === 0x0d) lineEnd--; // strip \r
          const line = rawBuf.subarray(0, lineEnd).toString('utf8');

          // Remainder after the banner line (may contain binary KEXINIT)
          const remainder = rawBuf.subarray(nlIdx + 1);

          if (!checkAlgs) {
            // Banner-only mode
            try { sock.end(); } catch {}
            finalize("SSH banner received", line);
            return;
          }

          // Check if server KEXINIT is already in the remainder
          if (remainder.length > 0 && tryParseKexinit(remainder)) {
            try { sock.end(); } catch {}
            finalize("SSH banner received", line);
            return;
          }

          // Switch to KEXINIT phase
          bannerLine = line;
          phase = 'kexinit';
          // Reset rawBuf to only hold the remainder (post-banner binary data)
          rawBuf = remainder;

          // Send our client banner identification string (required before KEXINIT)
          sock.write('SSH-2.0-NSAuditor_1.0\r\n');
          // Send our KEXINIT
          sock.write(buildClientKexinit());

          // Set a separate timeout for KEXINIT exchange
          const kexTimeoutMs = Number(process.env.SSH_KEXINIT_TIMEOUT || 3000);
          kexTimer = setTimeout(() => {
            // KEXINIT timed out — finalize with banner only (graceful fallback)
            try { sock.end(); } catch {}
            finalize("SSH banner received", bannerLine);
          }, kexTimeoutMs);
        } else if (phase === 'kexinit') {
          // Try to extract KEXINIT payload from accumulated binary data
          if (tryParseKexinit(rawBuf)) {
            try { sock.end(); } catch {}
            finalize("SSH banner received", bannerLine);
          }
        }
      });

      sock.on("timeout", () => {
        try { sock.destroy(new Error("Timeout")); } catch {}
      });

      sock.on("error", (err) => {
        if (phase === 'kexinit' && bannerLine) {
          // KEXINIT failed but we have the banner — graceful fallback
          finalize("SSH banner received", bannerLine);
          return;
        }
        // ECONNREFUSED implies host up, port closed (like your FTP plugin)
        if (err?.code === "ECONNREFUSED") {
          finalize("Connection refused - host up, SSH port closed", null);
        } else if (err?.code === "ETIMEDOUT") {
          finalize("Timeout", null);
        } else {
          finalize(`Error: ${err?.code || err?.message || String(err)}`, null);
        }
      });

      sock.on("close", () => {
        if (!done && phase === 'kexinit' && bannerLine) {
          // Connection closed during KEXINIT — graceful fallback with banner
          finalize("SSH banner received", bannerLine);
        } else if (!done) {
          finalize(connected ? "Connection closed before banner" : "No response", null);
        }
      });
    } catch (err) {
      finalize(`Exception: ${err?.message || String(err)}`, null);
    }
  });
}

export default {
  id: "002",
  name: "SSH Scanner",
  description: "Connects to SSH (TCP 22), reads the identification banner, and extracts product, version, and OS hints.",
  priority: 50,
  requirements: { host: "up", tcp_open: [22] },
  protocols: ["tcp"],
  ports: [22],

  /**
   * @param {string} host
   * @param {number} [port=22]
   * @param {object} [options]
   * @returns {Promise<object>} result object (manager wraps with id/name)
   */
  async run(host, port = 22, options = {}) {
    console.log(`Running SSH Scanner on ${host}:${port}`);
    const res = await readSshBanner(host, port, options?.timeoutMs || 1500);
    // Mirror your other plugins’ console style (manager will also print the wrapped result)
    console.log("SSH Scanner Result:", JSON.stringify({
      id: this.id,
      name: this.name,
      result: res
    }, null, 2));
    return res; // manager expects only the "result" object
  }
};

import { statusFrom } from '../utils/conclusion_utils.mjs';

export async function conclude({ host, result }) {
  const rows = Array.isArray(result?.data) ? result.data : [];
  const items = [];
  for (const r of rows) {
    if (String(r?.probe_protocol||'') !== 'tcp') continue;
    const port = Number(r?.probe_port ?? 22);
    const info = r?.probe_info || '';
    const banner = r?.response_banner || '';
    // SSH timeout policy
    let status;
    if (/timeout/i.test(String(info))) {
      const pol = String(process.env.CONCLUDER_SSH_TIMEOUT_AS || 'filtered').toLowerCase();
      status = (pol === 'closed' || pol === 'unknown' || pol === 'filtered') ? pol : 'filtered';
    } else {
      status = statusFrom({ info, banner, fallbackUp: result?.up });
    }
    items.push({
      port, protocol: 'tcp', service: 'ssh',
      program: result?.program || 'Unknown',
      version: result?.version || 'Unknown',
      status, info: info || null, banner: banner || null,
      algorithms: result?.algorithms || null,
      weakAlgorithms: result?.weakAlgorithms || [],
      source: 'ssh', evidence: rows, authoritative: true
    });
  }
  if (!items.length) {
    items.push({
      port: 22, protocol: 'tcp', service: 'ssh',
      program: result?.program || 'Unknown',
      version: result?.version || 'Unknown',
      status: result?.up ? 'open' : 'unknown',
      info: null, banner: null,
      algorithms: result?.algorithms || null,
      weakAlgorithms: result?.weakAlgorithms || [],
      source: 'ssh', evidence: rows, authoritative: true
    });
  }
  return items;
}
