// utils/export_csv.mjs
// Export scan results as CSV.

import { csvTokens, PAYLOAD_KEYS } from './service_flags.mjs';

/**
 * Escape a CSV field value.
 * - Wrap in double quotes if contains comma, newline, or double quote
 * - Escape double quotes by doubling them
 * @param {*} value
 * @returns {string}
 */
export function escapeCsvField(value) {
  if (value == null) return '';
  let str = String(value);
  // Defend against CSV formula injection in spreadsheets
  if (/^[=+\-@\t\r]/.test(str)) {
    str = "'" + str;
  }
  if (/[",\r\n]/.test(str)) {
    return `"${str.replace(/"/g, '""')}"`;
  }
  return str;
}

const COLUMNS = ['host', 'port', 'protocol', 'service', 'program', 'version', 'status', 'cpe', 'security_findings'];

/**
 * The security_findings cell for a record: the shared service-flag table's tokens (utils/service_flags.mjs, 1.3.0 (s1)),
 * one per key that fired with its items joined by ';'. A custom SNMP community is never a finding and never printed.
 * @param {object} record
 * @returns {string}
 */
function buildFindings(record) {
  return csvTokens(record).join(',');
}

/**
 * Build CSV string from scan conclusion.
 * Columns: host, port, protocol, service, program, version, status, cpe, security_findings
 *
 * @param {{ host: string, conclusion: object }} scanData
 * @returns {string} CSV content with header row
 */
export function buildCsv(scanData) {
  const { host, conclusion } = scanData;
  const services = conclusion?.result?.services ?? [];

  const header = COLUMNS.join(',');
  const rows = services.map((svc) => {
    const findings = buildFindings(svc);
    const fields = [
      host,
      svc.port ?? '',
      svc.protocol ?? '',
      svc.service ?? '',
      svc.program ?? '',
      svc.version ?? '',
      svc.status ?? '',
      svc.cpe ?? '',
      findings,
    ];
    return fields.map(escapeCsvField).join(',');
  });
  // An adapter payload that landed in evidence (no port — a domain's DNS posture when no 53/udp service was found) gets
  // its own row, with no port: its findings must not depend on whether an unrelated port answered.
  for (const e of conclusion?.result?.evidence ?? []) {
    if (!PAYLOAD_KEYS.some((k) => e?.[k] != null)) continue;
    const payload = Object.fromEntries(PAYLOAD_KEYS.filter((k) => e[k] != null).map((k) => [k, e[k]]));
    rows.push([host, '', '', e.from ?? '', '', '', '', '', buildFindings(payload)].map(escapeCsvField).join(','));
  }

  return [header, ...rows].join('\r\n') + '\r\n';
}
