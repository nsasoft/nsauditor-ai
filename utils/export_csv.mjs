// utils/export_csv.mjs
// Export scan results as CSV.

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
 * Build a security_findings string from a service record.
 * @param {object} svc
 * @returns {string}
 */
function buildFindings(svc) {
  const parts = [];

  if (Array.isArray(svc.weakAlgorithms) && svc.weakAlgorithms.length) {
    parts.push(`weak_algorithms:${svc.weakAlgorithms.length}`);
  }
  if (svc.anonymousLogin) {
    parts.push('anonymous_login');
  }
  if (svc.axfrAllowed) {
    parts.push('axfr_allowed');
  }
  if (Array.isArray(svc.dangerousMethods) && svc.dangerousMethods.length) {
    parts.push(`dangerous_methods:${svc.dangerousMethods.join(';')}`);
  }
  if (svc.community) {
    parts.push(`default_community:${svc.community}`);
  }

  return parts.join(',');
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

  return [header, ...rows].join('\r\n') + '\r\n';
}
