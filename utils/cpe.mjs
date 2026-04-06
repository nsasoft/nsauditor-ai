// utils/cpe.mjs
// CPE 2.3 string generator for known service programs.

export const CPE_MAP = {
  'nginx':        { vendor: 'nginx',       product: 'nginx' },
  'openssh':      { vendor: 'openbsd',     product: 'openssh' },
  'apache':       { vendor: 'apache',      product: 'http_server' },
  'proftpd':      { vendor: 'proftpd',     product: 'proftpd' },
  'pure-ftpd':    { vendor: 'pureftpd',    product: 'pure-ftpd' },
  'bftpd':        { vendor: 'bftpd',       product: 'bftpd' },
  'isc bind':     { vendor: 'isc',         product: 'bind' },
  'bind':         { vendor: 'isc',         product: 'bind' },
  'microsoft-iis':{ vendor: 'microsoft',   product: 'internet_information_services' },
  'iis':          { vendor: 'microsoft',   product: 'internet_information_services' },
  'lighttpd':     { vendor: 'lighttpd',    product: 'lighttpd' },
  'tomcat':       { vendor: 'apache',      product: 'tomcat' },
  'mysql':        { vendor: 'oracle',      product: 'mysql' },
  'postgresql':   { vendor: 'postgresql',  product: 'postgresql' },
  'mongodb':      { vendor: 'mongodb',     product: 'mongodb' },
  'redis':        { vendor: 'redis',       product: 'redis' },
  'opensearch':   { vendor: 'amazon',      product: 'opensearch' },
  'elasticsearch':{ vendor: 'elastic',     product: 'elasticsearch' },
  'vsftpd':       { vendor: 'beasts',      product: 'vsftpd' },
  'dropbear':     { vendor: 'dropbear_ssh_project', product: 'dropbear_ssh' },
  'exim':         { vendor: 'exim',        product: 'exim' },
  'postfix':      { vendor: 'postfix',     product: 'postfix' },
  'dovecot':      { vendor: 'dovecot',     product: 'dovecot' },
  'openssl':      { vendor: 'openssl',     product: 'openssl' },
};

/**
 * Escape special characters in a CPE 2.3 component value.
 * Colons, backslashes, asterisks, and question marks must be escaped.
 */
export function escapeCpeComponent(s) {
  return String(s).replace(/([:\\*?])/g, '\\$1');
}

/**
 * Split a version string like "8.2p1" into { version, update }.
 * Handles dash/underscore separators (e.g. "9.0-rc1", "2.4.57-2").
 * If no update suffix is found, update defaults to '*'.
 */
export function parseVersion(versionString) {
  if (!versionString) return { version: '*', update: '*' };

  // Match version (digits and dots) followed by optional separator and update suffix.
  // Supports: "8.2p1", "9.0-rc1", "2.4.57-2", "1.25.0_beta"
  const m = versionString.match(/^(\d[\d.]*)(?:[-_]([a-zA-Z0-9]\w*)|([a-zA-Z]\w*))?$/);
  if (!m) return { version: versionString, update: '*' };

  return {
    version: m[1],
    update: m[2] || m[3] || '*',
  };
}

/**
 * Generate a CPE 2.3 formatted string for a known program/version.
 * Returns null when the program is not in CPE_MAP.
 */
export function generateCpe(program, version) {
  if (!program) return null;

  const key = String(program).toLowerCase();
  const entry = CPE_MAP[key];
  if (!entry) return null;

  const { version: ver, update } = parseVersion(version || null);

  const safeVer = ver === '*' ? '*' : escapeCpeComponent(ver);
  const safeUpd = update === '*' ? '*' : escapeCpeComponent(update);
  return `cpe:2.3:a:${entry.vendor}:${entry.product}:${safeVer}:${safeUpd}:*:*:*:*:*:*`;
}
