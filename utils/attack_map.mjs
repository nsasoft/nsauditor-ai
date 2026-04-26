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
 * Mapping from CWE identifiers to ATT&CK techniques.
 *
 * Used by `cweToMitre()` and as a fallback path in `mapServiceToAttack()` for findings
 * that have CWE annotations but no service-context-derivable technique (e.g., agent-detected
 * misconfigurations or compliance violations that aren't tied to a specific CVE).
 *
 * Coverage: ~30 CWEs spanning the most common nsauditor finding categories
 * (authentication, crypto, injection, memory safety, info disclosure, path traversal,
 * privilege escalation, web-specific, resource consumption).
 *
 * IDs are uppercased CWE-NNN format. Lookup in `cweToMitre()` is case-insensitive.
 */
export const CWE_TECHNIQUE_MAP = {
  // Authentication / access control
  'CWE-287':  [T('T1078', 'Valid Accounts')],                                                // Improper Authentication
  'CWE-306':  [T('T1078', 'Valid Accounts')],                                                // Missing Authentication
  'CWE-521':  [T('T1110', 'Brute Force')],                                                   // Weak Password Requirements
  'CWE-798':  [T('T1552.001', 'Unsecured Credentials: Credentials In Files')],               // Use of Hard-coded Credentials
  'CWE-256':  [T('T1552', 'Unsecured Credentials')],                                         // Plaintext Storage of a Password
  'CWE-862':  [T('T1078', 'Valid Accounts')],                                                // Missing Authorization
  'CWE-863':  [T('T1078', 'Valid Accounts')],                                                // Incorrect Authorization

  // Cryptography
  'CWE-319':  [T('T1040', 'Network Sniffing')],                                              // Cleartext Transmission of Sensitive Information
  'CWE-326':  [T('T1557', 'Adversary-in-the-Middle')],                                       // Inadequate Encryption Strength
  'CWE-327':  [T('T1557', 'Adversary-in-the-Middle')],                                       // Use of a Broken or Risky Cryptographic Algorithm
  'CWE-328':  [T('T1557', 'Adversary-in-the-Middle')],                                       // Use of Weak Hash
  'CWE-331':  [T('T1557', 'Adversary-in-the-Middle')],                                       // Insufficient Entropy

  // Injection
  'CWE-77':   [T('T1059', 'Command and Scripting Interpreter')],                             // Command Injection (generic)
  'CWE-78':   [T('T1059', 'Command and Scripting Interpreter')],                             // OS Command Injection
  'CWE-79':   [T('T1059.007', 'Command and Scripting Interpreter: JavaScript')],             // XSS
  'CWE-89':   [T('T1190', 'Exploit Public-Facing Application')],                             // SQL Injection
  'CWE-94':   [T('T1059', 'Command and Scripting Interpreter')],                             // Code Injection
  'CWE-1336': [T('T1059', 'Command and Scripting Interpreter')],                             // Template Injection

  // Memory safety / RCE primitives
  'CWE-119':  [T('T1203', 'Exploitation for Client Execution')],                             // Buffer Errors
  'CWE-120':  [T('T1203', 'Exploitation for Client Execution')],                             // Buffer Overflow
  'CWE-125':  [T('T1203', 'Exploitation for Client Execution')],                             // Out-of-bounds Read
  'CWE-416':  [T('T1203', 'Exploitation for Client Execution')],                             // Use After Free
  'CWE-502':  [T('T1190', 'Exploit Public-Facing Application')],                             // Deserialization of Untrusted Data
  'CWE-787':  [T('T1203', 'Exploitation for Client Execution')],                             // Out-of-bounds Write

  // Information disclosure
  'CWE-200':  [T('T1592', 'Gather Victim Host Information')],                                // Information Exposure
  'CWE-209':  [T('T1592', 'Gather Victim Host Information')],                                // Information Exposure Through Error Messages

  // Path traversal / file
  'CWE-22':   [T('T1083', 'File and Directory Discovery')],                                  // Path Traversal
  'CWE-434':  [T('T1190', 'Exploit Public-Facing Application')],                             // Unrestricted Upload of File with Dangerous Type

  // Privilege escalation / permissions
  'CWE-250':  [T('T1068', 'Exploitation for Privilege Escalation')],                         // Execution with Unnecessary Privileges
  'CWE-269':  [T('T1068', 'Exploitation for Privilege Escalation')],                         // Improper Privilege Management
  'CWE-732':  [T('T1574.005', 'Hijack Execution Flow: Executable Installer File Permissions Weakness')], // Incorrect Permission Assignment

  // Web-specific
  'CWE-352':  [T('T1185', 'Browser Session Hijacking')],                                     // CSRF
  'CWE-601':  [T('T1204.001', 'User Execution: Malicious Link')],                            // URL Redirection to Untrusted Site
  'CWE-918':  [T('T1071', 'Application Layer Protocol')],                                    // SSRF

  // Resource consumption / DoS
  'CWE-400':  [T('T1499', 'Endpoint Denial of Service')],                                    // Uncontrolled Resource Consumption
  'CWE-770':  [T('T1499', 'Endpoint Denial of Service')],                                    // Allocation of Resources Without Limits or Throttling
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
 * Map a single CWE identifier to ATT&CK techniques.
 * Lookup is case-insensitive and tolerates surrounding whitespace.
 * Returns a fresh array (callers may push into it without aliasing the static map).
 *
 * @param {string} cwe - e.g. "CWE-326", "cwe-89"
 * @returns {Array<{ techniqueId: string, name: string }>} Empty if unknown or invalid input.
 */
export function cweToMitre(cwe) {
  if (typeof cwe !== 'string') return [];
  const id = cwe.trim().toUpperCase();
  const techs = CWE_TECHNIQUE_MAP[id];
  return techs ? [...techs] : [];
}

/**
 * Map an array (or single string) of CWE identifiers to a deduplicated set of techniques.
 *
 * @param {string[]|string} cwes - Array like ['CWE-326', 'CWE-89'] or single string.
 * @returns {Array<{ techniqueId: string, name: string }>} Deduplicated by techniqueId.
 */
export function cwesToMitre(cwes) {
  if (!cwes) return [];
  const list = Array.isArray(cwes) ? cwes : [cwes];
  const techniques = [];
  for (const cwe of list) {
    techniques.push(...cweToMitre(cwe));
  }
  return dedup(techniques);
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
  let cveDerivedCount = 0;
  const cves = service.cves || service.cve || [];
  if (Array.isArray(cves)) {
    for (const cve of cves) {
      const cveId = typeof cve === 'string' ? cve : (cve?.id || cve?.cveId || '');
      if (cveId) {
        const cveTechs = mapCveToAttack(cveId, svcName);
        cveDerivedCount += cveTechs.length;
        techniques.push(...cveTechs);
      }
    }
  }

  // CWE-based fallback: only applied when CVE mapping produced no techniques.
  // Reads in priority order: service.cwes → service.cwe → service.evidence?.cwe.
  // CVE-derived mappings are service-context-aware and authoritative; CWE mappings
  // are heuristic and provide coverage for findings without CVE context (agent-detected
  // misconfigurations, compliance-flagged weaknesses, etc.).
  if (cveDerivedCount === 0) {
    const cwes = service.cwes || service.cwe || service.evidence?.cwe || [];
    techniques.push(...cwesToMitre(cwes));
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
