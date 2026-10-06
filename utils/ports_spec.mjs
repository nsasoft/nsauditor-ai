// utils/ports_spec.mjs
// The --ports grammar, in one place (1.3.0 lane 4, item 12): the port scanner and the webapp detector both read it, so a
// form one accepts the other accepts too. Moved here from plugins/port_scanner.mjs, which re-exports parsePortsSpec.

export function uniqInts(arr = []) {
  return [...new Set((arr || []).map((x) => Number(x)).filter(Number.isFinite))];
}

/**
 * Parse a CLI-style ports spec string into TCP/UDP port arrays.
 *
 * Accepted formats (entries comma-separated, whitespace tolerated):
 *   "8090"                   → { tcp: [8090],          udp: [] }
 *   "8090,9090"              → { tcp: [8090, 9090],    udp: [] }
 *   "8090/tcp"               → { tcp: [8090],          udp: [] }
 *   "8090/udp"               → { tcp: [],              udp: [8090] }
 *   "8090,9090/udp"          → { tcp: [8090],          udp: [9090] }
 *   "8090/tcp,9090/udp"      → { tcp: [8090],          udp: [9090] }
 *
 * Default protocol when not specified: TCP.
 *
 * Malformed entries (non-numeric, out-of-range 1–65535, empty, unknown
 * protocol suffix) are silently skipped — defensive for sloppy CLI input.
 *
 * @param {string} spec
 * @returns {{ tcp: number[], udp: number[] }}
 */
export function parsePortsSpec(spec) {
  const out = { tcp: [], udp: [] };
  if (typeof spec !== 'string') return out;
  const entries = spec.split(',').map(s => s.trim()).filter(Boolean);
  for (const entry of entries) {
    // Reject entries with more than one '/' separator (e.g. "8090/tcp/extra")
    const parts = entry.split('/');
    if (parts.length > 2) continue;
    const portStr = parts[0];
    const proto   = (parts[1] || 'tcp').toLowerCase();
    if (proto !== 'tcp' && proto !== 'udp') continue;
    const port = Number(portStr);
    if (!Number.isInteger(port) || port < 1 || port > 65535) continue;
    out[proto].push(port);
  }
  out.tcp = uniqInts(out.tcp);
  out.udp = uniqInts(out.udp);
  return out;
}
