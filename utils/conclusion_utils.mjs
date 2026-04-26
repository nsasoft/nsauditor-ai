// utils/conclusion_utils.mjs
// Shared helpers for normalizing plugin findings into service records.

import { generateCpe } from './cpe.mjs';

export const keyOf = (svc) => `${(svc.protocol || 'tcp').toLowerCase()}:${Number(svc.port)}`;

export const firstDataRow = (res) =>
  Array.isArray(res?.data) ? res.data.find(Boolean) : null;

export function statusFrom({ info, banner, fallbackUp }) {
  const s = `${info || ''} ${banner || ''}`.toLowerCase();
  if (/connection refused|closed/.test(s)) return 'closed';
  if (/filtered|no route|host unreachable/.test(s)) return 'filtered';
  if (/\bopen\b|\bready\b|^220(?:-| )/m.test(s)) return 'open';
  if (typeof fallbackUp === 'boolean') return fallbackUp ? 'open' : 'unknown';
  return 'unknown';
}

export function normalizeService(svc) {
  // Preserve every field on the input record. Plugin authors attach security
  // flags (anonymousLogin, weakAlgorithms, axfrAllowed, mcpCleartextTransport,
  // etc.) directly to the service record so downstream consumers (sarif,
  // export_csv, report_md, AI prompt) can read them. Stripping unknown fields
  // here would silently kill all those readers — verified bug surfaced during
  // Task N.30 implementation.
  //
  // Standard fields are explicitly normalized (type coercion, defaults). Any
  // other field on the input is passed through verbatim via the spread.
  return {
    ...svc,
    port: Number(svc.port),
    protocol: (svc.protocol || 'tcp').toLowerCase(),
    service: String(svc.service || 'unknown').toLowerCase(),
    program: svc.program ?? null,
    version: svc.version ?? null,
    cpe: svc.program ? generateCpe(svc.program, svc.version) : null,
    status: svc.status || 'unknown',
    info: svc.info ?? null,
    banner: svc.banner ?? null,
    source: svc.source || 'unknown',
    // Evidence: accept either an array (legacy — list of probe rows)
    // OR an object (FindingSchema-style { cwe, owasp, mitre } — see N.5/N.14).
    // Both shapes are valid; downstream readers must handle both.
    evidence: (Array.isArray(svc.evidence) || (svc.evidence && typeof svc.evidence === 'object'))
      ? svc.evidence
      : []
  };
}

// Merge by protocol:port with basic authority precedence.
// If 'authoritative' flag is true on a record, it wins over non-authoritative.
export function upsertService(services, next, { authoritative = false } = {}) {
  const key = keyOf(next);
  const i = services.findIndex(s => keyOf(s) === key);
  if (i === -1) {
    services.push({ ...next, __authoritative: !!authoritative });
    return;
  }
  const cur = services[i];
  // Authority precedence
  if (authoritative && !cur.__authoritative) {
    services[i] = { ...cur, ...next, __authoritative: true };
    return;
  }
  if (!authoritative && cur.__authoritative) {
    // keep current authoritative, but allow filling blanks
    services[i] = {
      ...cur,
      program: cur.program || next.program || null,
      version: cur.version || next.version || null,
      info: cur.info || next.info || null,
      banner: cur.banner || next.banner || null,
      evidence: (cur.evidence || []).concat(next.evidence || [])
    };
    return;
  }
  // Same authority level: last-write-wins while preserving non-null fields
  services[i] = {
    ...cur,
    ...next,
    evidence: (cur.evidence || []).concat(next.evidence || []),
    __authoritative: cur.__authoritative || authoritative
  };
}
