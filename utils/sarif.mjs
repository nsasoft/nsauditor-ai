// utils/sarif.mjs
// Generate SARIF 2.1.0 output from nsauditor scan results.

import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const { version: TOOL_VERSION } = require('../package.json');

const SARIF_VERSION = '2.1.0';
const SARIF_SCHEMA = 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json';
const TOOL_NAME = 'nsauditor';
const TOOL_URI = 'https://github.com/nsasoft/nsauditor-ai';

/**
 * Map nsauditor severity to SARIF level.
 * @param {string} severity - 'Critical', 'High', 'Medium', 'Low', 'Info'
 * @returns {'error'|'warning'|'note'}
 */
export function severityToLevel(severity) {
  const s = String(severity || '').toLowerCase();
  if (s === 'critical' || s === 'high') return 'error';
  if (s === 'medium') return 'warning';
  return 'note';
}

/**
 * Build a rule ID from a service record.
 * @param {object} svc
 * @returns {string}
 */
function ruleIdFromService(svc) {
  const program = svc.program && svc.program !== 'Unknown' ? svc.program : svc.service;
  const version = svc.version && svc.version !== 'Unknown' ? svc.version : null;
  const base = String(program || 'unknown').toLowerCase().replace(/\s+/g, '-');
  return version ? `${base}:${version}` : base;
}

/**
 * Infer severity from a service's status and other indicators.
 * @param {object} svc
 * @returns {string}
 */
function inferServiceSeverity(svc) {
  if (svc.status === 'open') return 'Medium';
  return 'Info';
}

/**
 * Build message text from a service record.
 * @param {object} svc
 * @param {string} host
 * @returns {string}
 */
function buildServiceMessage(svc, host) {
  const parts = [];
  parts.push(`Service ${svc.service || 'unknown'} detected on ${host}:${svc.port}/${svc.protocol || 'tcp'}`);
  if (svc.program && svc.program !== 'Unknown') parts.push(`Program: ${svc.program}`);
  if (svc.version && svc.version !== 'Unknown') parts.push(`Version: ${svc.version}`);
  if (svc.status) parts.push(`Status: ${svc.status}`);
  if (svc.info) parts.push(`Info: ${svc.info}`);
  if (svc.banner) parts.push(`Banner: ${svc.banner}`);
  return parts.join('. ');
}

/**
 * Build SARIF result entries for security findings on a service.
 * @param {object} svc
 * @param {string} host
 * @returns {{ results: object[], rules: object[] }}
 */
function securityFindingsFromService(svc, host) {
  const results = [];
  const rules = [];

  const makeResult = (ruleId, level, message) => ({
    ruleId,
    level,
    message: { text: message },
    locations: [{
      physicalLocation: {
        artifactLocation: { uri: host }
      }
    }]
  });

  // anonymousLogin: true
  if (svc.anonymousLogin === true) {
    const ruleId = 'ftp-anonymous-login';
    rules.push({
      id: ruleId,
      shortDescription: { text: 'FTP anonymous login enabled' },
      helpUri: `${TOOL_URI}`,
      properties: { severity: 'Critical' }
    });
    results.push(makeResult(ruleId, 'error',
      `FTP anonymous login is enabled on ${host}:${svc.port}. This allows unauthenticated access to the FTP server.`));
  }

  // axfrAllowed: true
  if (svc.axfrAllowed === true) {
    const ruleId = 'dns-zone-transfer';
    rules.push({
      id: ruleId,
      shortDescription: { text: 'DNS zone transfer (AXFR) allowed' },
      helpUri: `${TOOL_URI}`,
      properties: { severity: 'Critical' }
    });
    results.push(makeResult(ruleId, 'error',
      `DNS zone transfer (AXFR) is allowed on ${host}:${svc.port}. This can expose the entire DNS zone to attackers.`));
  }

  // weakAlgorithms: [...]
  if (Array.isArray(svc.weakAlgorithms) && svc.weakAlgorithms.length > 0) {
    for (const algo of svc.weakAlgorithms) {
      const algoName = typeof algo === 'string' ? algo : (algo?.algorithm || algo?.name || String(algo));
      const ruleId = `weak-algorithm-${algoName.replace(/[^a-zA-Z0-9._-]/g, '-')}`;
      rules.push({
        id: ruleId,
        shortDescription: { text: `Weak algorithm: ${algoName}` },
        helpUri: `${TOOL_URI}`,
        properties: { severity: 'Medium' }
      });
      results.push(makeResult(ruleId, 'warning',
        `Weak algorithm "${algoName}" is supported on ${host}:${svc.port}/${svc.protocol || 'tcp'}.`));
    }
  }

  // dangerousMethods: [...]
  if (Array.isArray(svc.dangerousMethods) && svc.dangerousMethods.length > 0) {
    for (const method of svc.dangerousMethods) {
      const ruleId = `http-dangerous-method-${String(method).toLowerCase()}`;
      rules.push({
        id: ruleId,
        shortDescription: { text: `Dangerous HTTP method: ${method}` },
        helpUri: `${TOOL_URI}`,
        properties: { severity: 'Medium' }
      });
      results.push(makeResult(ruleId, 'warning',
        `Dangerous HTTP method "${method}" is allowed on ${host}:${svc.port}.`));
    }
  }

  // CVE data (if service has cves or cve array)
  const cves = svc.cves || svc.cve || [];
  if (Array.isArray(cves)) {
    for (const cve of cves) {
      const cveId = typeof cve === 'string' ? cve : (cve?.id || cve?.cveId || String(cve));
      const cveSeverity = cve?.severity || 'High';
      const ruleId = cveId;
      rules.push({
        id: ruleId,
        shortDescription: { text: `Known vulnerability: ${cveId}` },
        helpUri: `https://nvd.nist.gov/vuln/detail/${cveId}`,
        properties: { severity: cveSeverity }
      });
      results.push(makeResult(ruleId, severityToLevel(cveSeverity),
        `${cveId} affects ${svc.program || svc.service}${svc.version && svc.version !== 'Unknown' ? ' ' + svc.version : ''} on ${host}:${svc.port}.`));
    }
  }

  return { results, rules };
}

/**
 * Build a SARIF 2.1.0 log from scan conclusion.
 * @param {{ host: string, conclusion: object, results?: object[] }} scanData
 * @returns {object} SARIF log object
 */
export function buildSarifLog(scanData) {
  const { host, conclusion } = scanData;
  const sarifResults = [];
  const rulesMap = new Map();

  const services = conclusion?.result?.services || [];

  for (const svc of services) {
    // Base service result
    const ruleId = ruleIdFromService(svc);
    const severity = inferServiceSeverity(svc);
    const level = severityToLevel(severity);
    const message = buildServiceMessage(svc, host);

    if (!rulesMap.has(ruleId)) {
      rulesMap.set(ruleId, {
        id: ruleId,
        shortDescription: { text: `${svc.service || 'unknown'} service detected` },
        helpUri: TOOL_URI,
        properties: { severity }
      });
    }

    sarifResults.push({
      ruleId,
      level,
      message: { text: message },
      locations: [{
        physicalLocation: {
          artifactLocation: { uri: host }
        }
      }]
    });

    // Security findings
    const { results: secResults, rules: secRules } = securityFindingsFromService(svc, host);
    for (const sr of secResults) sarifResults.push(sr);
    for (const rule of secRules) {
      if (!rulesMap.has(rule.id)) rulesMap.set(rule.id, rule);
    }
  }

  return {
    $schema: SARIF_SCHEMA,
    version: SARIF_VERSION,
    runs: [{
      tool: {
        driver: {
          name: TOOL_NAME,
          version: TOOL_VERSION,
          informationUri: TOOL_URI,
          rules: [...rulesMap.values()]
        }
      },
      results: sarifResults
    }]
  };
}
