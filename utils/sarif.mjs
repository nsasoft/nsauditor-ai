// utils/sarif.mjs
// Generate SARIF 2.1.0 output from nsauditor scan results.

import { createRequire } from 'node:module';
import { flagFindings, conclusionFindings, OPEN_SERVICE_SEVERITY } from './service_flags.mjs';
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
 * The "service detected" result's grade: OPEN_SERVICE_SEVERITY from the shared table (1.2.1 (s2)) — an open port is
 * inventory, never a warning of its own. A service that is not open is never graded above it.
 * @returns {string}
 */
function inferServiceSeverity() {
  return OPEN_SERVICE_SEVERITY;
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
 * SARIF rule + result entries for graded findings. Every grade comes from the shared service-flag table
 * (utils/service_flags.mjs, 1.2.1 (s1)); the rule ids of the four flags SARIF graded before 1.2.1 are unchanged, since a
 * code-scanning alert is keyed on its rule id.
 * @param {object[]} findings - from the table, each with key/severity/title/ruleId/evidence
 * @param {string} host
 * @param {string} where - the location text in the message (host:port/protocol, or the host for an evidence payload)
 * @returns {{ results: object[], rules: object[] }}
 */
function sarifEntries(findings, host, where) {
  const results = [];
  const rules = [];
  for (const f of findings) {
    rules.push({
      id: f.ruleId,
      shortDescription: { text: f.key === 'cves' ? `Known vulnerability: ${f.ruleId}` : f.title },
      helpUri: f.key === 'cves' ? `https://nvd.nist.gov/vuln/detail/${f.ruleId}` : TOOL_URI,
      properties: { severity: f.severity }
    });
    results.push({
      ruleId: f.ruleId,
      level: severityToLevel(f.severity),
      message: { text: `${f.title} on ${where}.${f.evidence ? ` ${f.evidence}` : ''}` },
      locations: [{ physicalLocation: { artifactLocation: { uri: host } } }]
    });
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
    const severity = inferServiceSeverity();
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
    const where = `${host}:${svc.port}/${svc.protocol || 'tcp'}`;
    const { results: secResults, rules: secRules } = sarifEntries(flagFindings(svc, { target: where }), host, where);
    for (const sr of secResults) sarifResults.push(sr);
    for (const rule of secRules) {
      if (!rulesMap.has(rule.id)) rulesMap.set(rule.id, rule);
    }
  }

  // An adapter payload that landed in EVIDENCE (no port — a domain's DNS posture when no 53/udp service was found) is
  // graded too, located at the host: its grade must not depend on whether an unrelated port answered.
  const onEvidence = conclusionFindings({ evidence: conclusion?.result?.evidence ?? [] }, host);
  const { results: evResults, rules: evRules } = sarifEntries(onEvidence, host, String(host));
  for (const sr of evResults) sarifResults.push(sr);
  for (const rule of evRules) {
    if (!rulesMap.has(rule.id)) rulesMap.set(rule.id, rule);
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
