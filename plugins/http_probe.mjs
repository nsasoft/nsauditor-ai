// plugins/http_probe.mjs
// Robust HTTP/HTTPS probe with tolerant parsing and vendor/model/firmware hints.
// Reads INSECURE_HTTPS=true to allow self-signed certs on router/printer UIs.

import http from 'node:http';
import https from 'node:https';
import { promisify } from 'node:util';
import { execFile } from 'node:child_process';

const execFileP = promisify(execFile);

const DEBUG = /^(1|true|yes|on)$/i.test(String(process.env.DEBUG_MODE || process.env.HTTP_DEBUG || ""));
function dlog(...a) { if (DEBUG) console.log("[http-probe]", ...a); }

function buildBanner(status, headers) {
  const lines = [];
  lines.push(`${status.code} ${status.message}`);
  // Capture the most useful fingerprinting headers
  const pick = [
    'www-authenticate',
    'server',
    'x-frame-options',
    'content-type',
    'set-cookie',
    'location', // include redirect target if any
  ];
  for (const k of pick) {
    const v = headers[k];
    if (!v) continue;
    if (Array.isArray(v)) {
      for (const vv of v) lines.push(`${k}: ${vv}`);
    } else {
      lines.push(`${k}: ${v}`);
    }
  }
  return lines.join('\r\n').slice(0, 512); // Limit banner size
}

function parseNetgear(headers) {
  const wa = headers['www-authenticate'];
  if (!wa) return null;
  const s = Array.isArray(wa) ? wa.join(' ') : wa;
  // Examples: Basic realm="NETGEAR R8000"  OR Basic realm="NETGEAR"
  const m = /NETGEAR\s*([A-Za-z0-9\-]+)?/i.exec(s);
  if (!m) return null;
  const model = m[1] ? m[1].toUpperCase() : undefined;
  return { vendor: 'NETGEAR', model };
}

function parseEpson(headers) {
  const server = headers['server'];
  const wa = headers['www-authenticate'];
  const s = [server, wa].flat().filter(Boolean).join(' ');
  if (!s) return null;
  if (/epson/i.test(s)) {
    // We don't usually get the model via HTTP alone; SNMP will fill that.
    return { vendor: 'EPSON' };
  }
  return null;
}

async function probeOptions(host, port, isHttps, allowInsecure, timeoutMs) {
  const mod = isHttps ? https : http;
  const agent = isHttps ? new https.Agent({ rejectUnauthorized: !allowInsecure }) : undefined;

  return new Promise((resolve) => {
    const req = mod.request({
      host, port,
      method: 'OPTIONS',
      path: '/',
      headers: { 'User-Agent': 'nsauditor/0.1 (+http)' },
      agent,
    }, (res) => {
      const allow = res.headers['allow'] || '';
      res.resume();
      resolve({ allow, status: res.statusCode });
    });

    req.setTimeout(timeoutMs, () => {
      req.destroy(new Error('timeout'));
    });
    req.on('error', () => resolve(null));
    req.end();
  });
}

async function probeFirmware(host, vendor) {
  if (!vendor || !vendor.toLowerCase().includes('netgear')) return null;
  const cmd = "curl";
  const args = [
    "-s", "-m", "5",
    `--connect-timeout`, "3",
    `http://${host}/currentsetting.htm`
  ];
  try {
    const { stdout } = await execFileP(cmd, args, { windowsHide: true, timeout: 6000 });
    // Match formats like Firmware=V1.0.5.88_10.1.88 or Firmware Version=V1.0.5.88
    const firmwareMatch = stdout.match(/Firmware(?:\s*Version)?=V?([\d._]+)/i);
    if (firmwareMatch) {
      dlog(`Firmware detected for ${host}: ${firmwareMatch[1]}`);
      return firmwareMatch[1];
    }
    return null;
  } catch (e) {
    dlog(`Firmware probe error for ${host}: ${e.message}`);
    return null;
  }
}

export default {
  id: '006',
  name: 'HTTP Probe',
  description: 'Probes HTTP/HTTPS (80,443) and extracts headers to fingerprint devices (e.g., routers/printers) with firmware detection.',
  priority: 60,
  requirements: { host: "up", tcp_open: [80, 443] },
  protocols: ['tcp'],
  ports: [80, 443],

  async run(host, port = 80, opts = {}) {
    const isHttps = Number(port) === 443;
    const allowInsecure =
      String(opts.insecureHttps ?? process.env.INSECURE_HTTPS ?? '').toLowerCase() === 'true';
    const timeoutMs = Number(process.env.HTTP_TIMEOUT_MS || 6000);

    const agent = isHttps ? new https.Agent({ rejectUnauthorized: !allowInsecure }) : undefined;
    const mod = isHttps ? https : http;

    const reqOpts = {
      host,
      port,
      method: 'GET', // GET for maximal compatibility; we’ll ignore the body
      path: '/',
      headers: {
        'User-Agent': 'nsauditor/0.1 (+http)',
        Accept: '*/*',
        Connection: 'close',
      },
      agent,
    };

    const result = {
      up: false,
      program: null,   // e.g., 'NETGEAR R8000 HTTP Server'
      version: null,   // e.g., 'V1.0.5.88'
      os: null,        // e.g., 'NETGEAR Router OS (Embedded Linux, Firmware V1.0.5.88)'
      type: null,      // e.g., 'router', 'printer'
      data: []
    };

    // Perform the HTTP/HTTPS probe
    const status = await new Promise((resolve) => {
      const req = mod.request(reqOpts, async (res) => {
        const headers = res.headers;
        const status = { code: res.statusCode, message: res.statusMessage };

        // Initial "up" via response
        result.up = true;

        // Vendor/model detection
        const ngear = parseNetgear(headers);
        const epson = parseEpson(headers);

        if (ngear) {
          result.program = `NETGEAR ${ngear.model || ''} HTTP Server`.trim();
          result.type = 'router';
          result.os = 'NETGEAR Router OS (Embedded Linux)';
        } else if (epson) {
          result.program = 'EPSON HTTP Server';
          result.type = 'printer';
          result.os = 'EPSON Printer OS (Embedded)';
        }

        // Probe for firmware if router detected
        if (result.type === 'router' && ngear) {
          const vendor = opts.context?.lookupVendor ? opts.context.lookupVendor(opts.context.arpMac) : ngear.vendor;
          const firmware = await probeFirmware(host, vendor);
          if (firmware) {
            result.version = firmware;
            result.os = `${result.os}, Firmware ${firmware}`;
            result.data.push({
              probe_protocol: isHttps ? 'https' : 'http',
              probe_port: port,
              probe_info: `Firmware detected: ${firmware}`,
              response_banner: null
            });
          }
        }

        // Fallback to Server header if program still unknown
        const server = headers['server'];
        if (!result.program && server) {
          result.program = String(server);
        }

        // If Epson is detected via headers, hint "printer" and stable program label
        if (epson) {
          result.type = 'printer';
          if (!result.program || /unknown/i.test(result.program)) {
            result.program = 'EPSON HTTP Server';
          }
        }

        // Push a condensed "banner" capture for the probe
        result.data.push({
          probe_protocol: isHttps ? 'https' : 'http',
          probe_port: port,
          probe_info: ngear
            ? `Detected router: ${result.program}`
            : epson
            ? `Detected printer: ${result.program}`
            : server
            ? `Server: ${server}`
            : 'HTTP service detected',
          response_banner: buildBanner(status, headers),
        });

        // Drain and finish
        res.resume();
        resolve(status);
      });

      req.setTimeout(timeoutMs, () => {
        req.destroy(new Error('timeout'));
      });

      req.on('error', (err) => {
        // Tolerate parse/TLS quirks by marking as up when we can infer service presence
        const msg = String(err.message).toLowerCase();
        const looksLikeUp =
          msg.includes('certificate') ||
          msg.includes('self-signed') ||
          msg.includes('parse error') ||
          msg.includes('write epipe') ||
          msg.includes('unexpected server response'); // common TLS handshake noise

        result.up = looksLikeUp || result.up;

        // Record a minimal banner/error line so the operator sees context
        result.data.push({
          probe_protocol: isHttps ? 'https' : 'http',
          probe_port: port,
          probe_info: looksLikeUp
            ? 'HTTP(S) reachable with TLS/parse issues (likely admin UI present)'
            : `HTTP(S) error: ${err.message}`,
          response_banner: null,
        });

        resolve({ code: 0, message: err.message });
      });

      req.end();
    });

    // Final heuristics if type is still unknown
    if (!result.type && result.program) {
      const p = result.program.toLowerCase();
      if (p.includes('netgear')) result.type = 'router';
      else if (p.includes('epson')) result.type = 'printer';
    }

    // Keep OS null unless we have a trustworthy hint; HTTP headers rarely reveal OS reliably.

    // HTTP method testing via OPTIONS
    try {
      const optResult = await probeOptions(host, port, isHttps, allowInsecure, timeoutMs);
      if (optResult?.allow) {
        const methods = optResult.allow.split(',').map(m => m.trim().toUpperCase()).filter(Boolean);
        const dangerous = methods.filter(m => ['PUT', 'DELETE', 'TRACE', 'CONNECT'].includes(m));
        result.allowedMethods = methods;
        result.dangerousMethods = dangerous;
        if (dangerous.length > 0) {
          result.data.push({
            probe_protocol: isHttps ? 'https' : 'http',
            probe_port: port,
            probe_info: `WARNING: Dangerous HTTP methods enabled: ${dangerous.join(', ')}`,
            response_banner: `Allow: ${optResult.allow}`
          });
        }
      } else {
        result.allowedMethods = [];
        result.dangerousMethods = [];
      }
    } catch {
      result.allowedMethods = [];
      result.dangerousMethods = [];
    }

    return result;
  },
};