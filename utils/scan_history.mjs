// utils/scan_history.mjs
// Scan history persistence and comparison utilities.
// Uses JSONL (one JSON object per line) for append-friendly storage.

import fsp from 'node:fs/promises';
import path from 'node:path';

const HISTORY_FILE = 'scan_history.jsonl';

/**
 * Build a service key for comparison (port + protocol).
 * @param {object} svc
 * @returns {string}
 */
function serviceKey(svc) {
  return `${svc.port ?? ''}/${svc.protocol ?? 'tcp'}`;
}

/**
 * Append a scan summary as a single JSON line to scan_history.jsonl.
 * @param {string} outputDir - root output directory
 * @param {object} summary  - scan summary object
 * @returns {Promise<string>} path to the history file
 */
export async function recordScan(outputDir, summary) {
  const filePath = path.join(outputDir, HISTORY_FILE);
  const entry = {
    timestamp: summary.timestamp ?? new Date().toISOString(),
    host: summary.host ?? null,
    servicesCount: summary.servicesCount ?? 0,
    openPorts: Array.isArray(summary.openPorts) ? summary.openPorts : [],
    os: summary.os ?? null,
    findingsCount: summary.findingsCount ?? 0,
    services: Array.isArray(summary.services) ? summary.services.map((s) => ({
      port: s.port ?? null,
      protocol: s.protocol ?? 'tcp',
      service: s.service ?? null,
      version: s.version ?? null,
    })) : [],
  };
  const line = JSON.stringify(entry) + '\n';
  await fsp.mkdir(outputDir, { recursive: true });
  await fsp.appendFile(filePath, line, 'utf8');
  return filePath;
}

/**
 * Read scan_history.jsonl and return the most recent entry for the given host.
 * @param {string} outputDir
 * @param {string} host
 * @returns {Promise<object|null>}
 */
export async function getLastScan(outputDir, host) {
  const filePath = path.join(outputDir, HISTORY_FILE);
  let content;
  try {
    content = await fsp.readFile(filePath, 'utf8');
  } catch (err) {
    if (err.code === 'ENOENT') return null;
    throw err;
  }

  const lines = content.trim().split('\n').filter(Boolean);
  let latest = null;

  for (const line of lines) {
    try {
      const entry = JSON.parse(line);
      if (entry.host === host) {
        if (!latest || entry.timestamp > latest.timestamp) {
          latest = entry;
        }
      }
    } catch {
      // skip malformed lines
    }
  }

  return latest;
}

/**
 * Compare two scan summaries and return a structured diff.
 * @param {object} current  - current scan summary
 * @param {object|null} previous - previous scan summary (null for first scan)
 * @returns {object} diff object
 */
export function computeDiff(current, previous) {
  if (!previous) {
    return {
      newServices: [],
      removedServices: [],
      changedServices: [],
      newFindings: current?.findingsCount ?? 0,
      summary: 'No previous scan for comparison.',
    };
  }

  const currentServices = Array.isArray(current?.services) ? current.services : [];
  const previousServices = Array.isArray(previous?.services) ? previous.services : [];

  const prevMap = new Map();
  for (const svc of previousServices) {
    prevMap.set(serviceKey(svc), svc);
  }

  const currMap = new Map();
  for (const svc of currentServices) {
    currMap.set(serviceKey(svc), svc);
  }

  const newServices = [];
  const changedServices = [];

  for (const [key, svc] of currMap) {
    const prev = prevMap.get(key);
    if (!prev) {
      newServices.push(svc);
    } else if (prev.service !== svc.service || prev.version !== svc.version) {
      changedServices.push({
        port: svc.port,
        protocol: svc.protocol,
        previousService: prev.service,
        previousVersion: prev.version,
        currentService: svc.service,
        currentVersion: svc.version,
      });
    }
  }

  const removedServices = [];
  for (const [key, svc] of prevMap) {
    if (!currMap.has(key)) {
      removedServices.push(svc);
    }
  }

  const findingsDelta = (current?.findingsCount ?? 0) - (previous?.findingsCount ?? 0);

  // Build human-readable summary
  const parts = [];
  if (newServices.length) {
    parts.push(`${newServices.length} new service(s) detected`);
  }
  if (removedServices.length) {
    parts.push(`${removedServices.length} service(s) removed`);
  }
  if (changedServices.length) {
    parts.push(`${changedServices.length} service(s) changed`);
  }
  if (findingsDelta !== 0) {
    const sign = findingsDelta > 0 ? '+' : '';
    parts.push(`findings delta: ${sign}${findingsDelta}`);
  }

  const summary = parts.length > 0
    ? parts.join(', ') + '.'
    : 'No changes detected since last scan.';

  return {
    newServices,
    removedServices,
    changedServices,
    newFindings: findingsDelta,
    summary,
  };
}

/**
 * Format a diff object into markdown-like text lines.
 * @param {object} diff - output from computeDiff()
 * @returns {string}
 */
export function formatDiffReport(diff) {
  if (!diff) return '';

  const lines = [];
  lines.push('## Scan Comparison');
  lines.push('');
  lines.push(diff.summary);
  lines.push('');

  if (diff.newServices.length) {
    lines.push('### New Services');
    for (const svc of diff.newServices) {
      lines.push(`- ${svc.port}/${svc.protocol}: ${svc.service ?? 'unknown'} (${svc.version ?? 'unknown'})`);
    }
    lines.push('');
  }

  if (diff.removedServices.length) {
    lines.push('### Removed Services');
    for (const svc of diff.removedServices) {
      lines.push(`- ${svc.port}/${svc.protocol}: ${svc.service ?? 'unknown'} (${svc.version ?? 'unknown'})`);
    }
    lines.push('');
  }

  if (diff.changedServices.length) {
    lines.push('### Changed Services');
    for (const ch of diff.changedServices) {
      lines.push(`- ${ch.port}/${ch.protocol}: ${ch.previousService ?? 'unknown'} ${ch.previousVersion ?? ''} -> ${ch.currentService ?? 'unknown'} ${ch.currentVersion ?? ''}`);
    }
    lines.push('');
  }

  if (diff.newFindings !== 0) {
    const sign = diff.newFindings > 0 ? '+' : '';
    lines.push(`**Findings delta:** ${sign}${diff.newFindings}`);
    lines.push('');
  }

  return lines.join('\n');
}
