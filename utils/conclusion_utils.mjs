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
  return {
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
    evidence: Array.isArray(svc.evidence) ? svc.evidence : []
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
