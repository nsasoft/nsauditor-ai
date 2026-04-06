// utils/attack_map.mjs
// MITRE ATT&CK mapping for network security audit findings.
// Maps service types, CVEs, and scan findings to ATT&CK technique IDs.

/**
 * Technique definition: { techniqueId, name }
 */
const T = (techniqueId, name) => ({ techniqueId, name });

/**
 * Mapping from finding/service patterns to ATT&CK techniques.
 */
export const SERVICE_TECHNIQUE_MAP = {
  ssh_cve:              [T('T1021.004', 'Remote Services: SSH')],
  smb_cve:              [T('T1021.002', 'Remote Services: SMB/Windows Admin Shares')],
  ftp_anonymous:        [T('T1078', 'Valid Accounts'), T('T1530', 'Data from Cloud Storage Object')],
  dns_zone_transfer:    [T('T1590.002', 'Gather Victim Network Information: DNS')],
  snmp_default:         [T('T1078', 'Valid Accounts'), T('T1040', 'Network Sniffing')],
  http_dangerous:       [T('T1190', 'Exploit Public-Facing Application')],
  privesc_cve:          [T('T1068', 'Exploitation for Privilege Escalation')],
  default_credentials:  [T('T1110', 'Brute Force')],
  tls_weakness:         [T('T1557', 'Adversary-in-the-Middle')],
  rdp_exposure:         [T('T1021.001', 'Remote Services: RDP')],
  mdns_llmnr_exposure:  [T('T1557.001', 'LLMNR/NBT-NS Poisoning')],
};

/**
 * Convert a technique ID to a MITRE ATT&CK URL.
 * Sub-techniques use dot notation (T1021.004) which maps to slash paths (/T1021/004/).
 * @param {string} techniqueId - e.g. "T1021.004" or "T1190"
 * @returns {string} Full URL
 */
export function attackUrl(techniqueId) {
  const path = String(techniqueId).replace(/\./g, '/');
  return `https://attack.mitre.org/techniques/${path}/`;
}

/**
 * Map a service record to matching ATT&CK techniques.
 * Inspects service type and boolean/array fields to identify relevant techniques.
 *
 * @param {object} service - Service record from scan conclusion
 * @returns {Array<{ techniqueId: string, name: string, url: string }>}
 */
export function mapServiceToAttack(service) {
  if (!service || typeof service !== 'object') return [];

  const techniques = [];
  const svcName = String(service.service || '').toLowerCase();

  // FTP anonymous login
  if (service.anonymousLogin === true) {
    techniques.push(...SERVICE_TECHNIQUE_MAP.ftp_anonymous);
  }

  // DNS zone transfer
  if (service.axfrAllowed === true) {
    techniques.push(...SERVICE_TECHNIQUE_MAP.dns_zone_transfer);
  }

  // SNMP default community string
  if (service.community === 'public' || service.community === 'private') {
    techniques.push(...SERVICE_TECHNIQUE_MAP.snmp_default);
  }

  // HTTP dangerous methods
  if (Array.isArray(service.dangerousMethods) && service.dangerousMethods.length > 0) {
    techniques.push(...SERVICE_TECHNIQUE_MAP.http_dangerous);
  }

  // TLS/SSL weaknesses
  if (
    (Array.isArray(service.weakAlgorithms) && service.weakAlgorithms.length > 0) ||
    (Array.isArray(service.weakCiphers) && service.weakCiphers.length > 0) ||
    (Array.isArray(service.weakProtocols) && service.weakProtocols.length > 0)
  ) {
    techniques.push(...SERVICE_TECHNIQUE_MAP.tls_weakness);
  }

  // RDP exposure
  if (svcName === 'rdp' || svcName === 'ms-wbt-server') {
    techniques.push(...SERVICE_TECHNIQUE_MAP.rdp_exposure);
  }

  // mDNS / LLMNR exposure
  if (svcName === 'mdns' || svcName === 'llmnr') {
    techniques.push(...SERVICE_TECHNIQUE_MAP.mdns_llmnr_exposure);
  }

  // Default/weak credentials (generic flag)
  if (service.defaultCredentials === true || service.weakCredentials === true) {
    techniques.push(...SERVICE_TECHNIQUE_MAP.default_credentials);
  }

  // CVE-based mappings
  const cves = service.cves || service.cve || [];
  if (Array.isArray(cves)) {
    for (const cve of cves) {
      const cveId = typeof cve === 'string' ? cve : (cve?.id || cve?.cveId || '');
      if (cveId) {
        techniques.push(...mapCveToAttack(cveId, svcName));
      }
    }
  }

  return dedup(techniques).map(t => ({ ...t, url: attackUrl(t.techniqueId) }));
}

/**
 * Map a CVE + service context to ATT&CK technique(s).
 * Uses the service type to determine the most relevant technique category.
 *
 * @param {string} cveId - e.g. "CVE-2023-12345"
 * @param {string} [serviceType] - e.g. "ssh", "smb", "http"
 * @returns {Array<{ techniqueId: string, name: string }>}
 */
export function mapCveToAttack(cveId, serviceType) {
  if (!cveId) return [];

  const svc = String(serviceType || '').toLowerCase();
  const id = String(cveId).toUpperCase();

  // Service-specific CVE mapping
  if (svc === 'ssh' || svc === 'openssh') {
    return [...SERVICE_TECHNIQUE_MAP.ssh_cve];
  }
  if (svc === 'smb' || svc === 'microsoft-ds' || svc === 'netbios-ssn') {
    return [...SERVICE_TECHNIQUE_MAP.smb_cve];
  }
  if (svc === 'rdp' || svc === 'ms-wbt-server') {
    return [...SERVICE_TECHNIQUE_MAP.rdp_exposure];
  }
  if (svc === 'http' || svc === 'https' || svc === 'http-proxy') {
    return [...SERVICE_TECHNIQUE_MAP.http_dangerous];
  }
  if (svc === 'ftp') {
    return [...SERVICE_TECHNIQUE_MAP.http_dangerous]; // T1190: exploiting a public-facing service
  }
  if (svc === 'dns' || svc === 'domain') {
    return [...SERVICE_TECHNIQUE_MAP.dns_zone_transfer];
  }

  // No service context — cannot reliably map to a specific ATT&CK technique

  return [];
}

/**
 * Collect all ATT&CK techniques across all services in a scan conclusion.
 * Returns deduplicated list.
 *
 * @param {object} conclusion - Full scan conclusion: { result: { services: [...] } }
 * @returns {Array<{ techniqueId: string, name: string, url: string }>}
 */
export function getAllTechniques(conclusion) {
  const services = conclusion?.result?.services ?? [];
  if (!Array.isArray(services) || services.length === 0) return [];

  const all = [];
  for (const svc of services) {
    all.push(...mapServiceToAttack(svc));
  }

  return dedup(all).map(t => t.url ? t : { ...t, url: attackUrl(t.techniqueId) });
}

/**
 * Deduplicate techniques by techniqueId.
 * @param {Array<{ techniqueId: string, name: string }>} techniques
 * @returns {Array<{ techniqueId: string, name: string }>}
 */
function dedup(techniques) {
  const seen = new Map();
  for (const t of techniques) {
    if (!seen.has(t.techniqueId)) {
      seen.set(t.techniqueId, { techniqueId: t.techniqueId, name: t.name });
    }
  }
  return [...seen.values()];
}
