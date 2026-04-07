import test from 'node:test';
import assert from 'node:assert/strict';
import fsp from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import fs from 'node:fs';

import {
  recordScan,
  getLastScan,
  computeDiff,
  formatDiffReport,
  pruneForCE,
} from '../utils/scan_history.mjs';

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

async function makeTmpDir() {
  return fsp.mkdtemp(path.join(os.tmpdir(), 'scan-history-test-'));
}

function makeSummary(overrides = {}) {
  return {
    timestamp: new Date().toISOString(),
    host: '192.168.1.1',
    servicesCount: 2,
    openPorts: [22, 80],
    os: 'Linux',
    findingsCount: 1,
    services: [
      { port: 22, protocol: 'tcp', service: 'ssh', version: '8.9' },
      { port: 80, protocol: 'tcp', service: 'http', version: '1.18' },
    ],
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// recordScan
// ---------------------------------------------------------------------------

test('recordScan writes valid JSONL', async () => {
  const dir = await makeTmpDir();
  try {
    const summary = makeSummary();
    await recordScan(dir, summary);

    const content = await fsp.readFile(path.join(dir, 'scan_history.jsonl'), 'utf8');
    const lines = content.trim().split('\n');
    assert.equal(lines.length, 1);

    const parsed = JSON.parse(lines[0]);
    assert.equal(parsed.host, '192.168.1.1');
    assert.equal(parsed.servicesCount, 2);
    assert.deepEqual(parsed.openPorts, [22, 80]);
    assert.equal(parsed.os, 'Linux');
    assert.equal(parsed.findingsCount, 1);
    assert.equal(parsed.services.length, 2);
  } finally {
    await fsp.rm(dir, { recursive: true, force: true });
  }
});

test('recordScan appends multiple entries', async () => {
  const dir = await makeTmpDir();
  try {
    await recordScan(dir, makeSummary({ host: '10.0.0.1', timestamp: '2025-01-01T00:00:00Z' }));
    await recordScan(dir, makeSummary({ host: '10.0.0.2', timestamp: '2025-01-02T00:00:00Z' }));

    const content = await fsp.readFile(path.join(dir, 'scan_history.jsonl'), 'utf8');
    const lines = content.trim().split('\n');
    assert.equal(lines.length, 2);

    assert.equal(JSON.parse(lines[0]).host, '10.0.0.1');
    assert.equal(JSON.parse(lines[1]).host, '10.0.0.2');
  } finally {
    await fsp.rm(dir, { recursive: true, force: true });
  }
});

test('recordScan normalises service entries', async () => {
  const dir = await makeTmpDir();
  try {
    await recordScan(dir, makeSummary({
      services: [{ port: 443, protocol: 'tcp', service: 'https', version: '1.3', extra: 'ignored' }],
    }));

    const content = await fsp.readFile(path.join(dir, 'scan_history.jsonl'), 'utf8');
    const entry = JSON.parse(content.trim());
    const svc = entry.services[0];
    assert.equal(svc.port, 443);
    assert.equal(svc.protocol, 'tcp');
    assert.equal(svc.service, 'https');
    assert.equal(svc.version, '1.3');
    assert.equal(svc.extra, undefined, 'extra fields should be stripped');
  } finally {
    await fsp.rm(dir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// getLastScan
// ---------------------------------------------------------------------------

test('getLastScan returns latest entry for matching host', async () => {
  const dir = await makeTmpDir();
  try {
    await recordScan(dir, makeSummary({ host: '10.0.0.1', timestamp: '2025-01-01T00:00:00Z', findingsCount: 1 }));
    await recordScan(dir, makeSummary({ host: '10.0.0.1', timestamp: '2025-06-15T12:00:00Z', findingsCount: 3 }));
    await recordScan(dir, makeSummary({ host: '10.0.0.2', timestamp: '2025-09-01T00:00:00Z', findingsCount: 5 }));

    const last = await getLastScan(dir, '10.0.0.1');
    assert.ok(last);
    assert.equal(last.host, '10.0.0.1');
    assert.equal(last.timestamp, '2025-06-15T12:00:00Z');
    assert.equal(last.findingsCount, 3);
  } finally {
    await fsp.rm(dir, { recursive: true, force: true });
  }
});

test('getLastScan returns null for unknown host', async () => {
  const dir = await makeTmpDir();
  try {
    await recordScan(dir, makeSummary({ host: '10.0.0.1' }));
    const result = await getLastScan(dir, '10.0.0.99');
    assert.equal(result, null);
  } finally {
    await fsp.rm(dir, { recursive: true, force: true });
  }
});

test('getLastScan returns null when history file does not exist', async () => {
  const dir = await makeTmpDir();
  try {
    const result = await getLastScan(dir, '10.0.0.1');
    assert.equal(result, null);
  } finally {
    await fsp.rm(dir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// computeDiff — new services
// ---------------------------------------------------------------------------

test('computeDiff detects new services', () => {
  const previous = makeSummary({
    services: [{ port: 22, protocol: 'tcp', service: 'ssh', version: '8.9' }],
  });
  const current = makeSummary({
    services: [
      { port: 22, protocol: 'tcp', service: 'ssh', version: '8.9' },
      { port: 443, protocol: 'tcp', service: 'https', version: '1.3' },
    ],
  });

  const diff = computeDiff(current, previous);
  assert.equal(diff.newServices.length, 1);
  assert.equal(diff.newServices[0].port, 443);
  assert.equal(diff.removedServices.length, 0);
  assert.equal(diff.changedServices.length, 0);
  assert.ok(diff.summary.includes('1 new service'));
});

// ---------------------------------------------------------------------------
// computeDiff — removed services
// ---------------------------------------------------------------------------

test('computeDiff detects removed services', () => {
  const previous = makeSummary({
    services: [
      { port: 22, protocol: 'tcp', service: 'ssh', version: '8.9' },
      { port: 80, protocol: 'tcp', service: 'http', version: '1.18' },
    ],
  });
  const current = makeSummary({
    services: [{ port: 22, protocol: 'tcp', service: 'ssh', version: '8.9' }],
  });

  const diff = computeDiff(current, previous);
  assert.equal(diff.removedServices.length, 1);
  assert.equal(diff.removedServices[0].port, 80);
  assert.equal(diff.newServices.length, 0);
  assert.ok(diff.summary.includes('1 service(s) removed'));
});

// ---------------------------------------------------------------------------
// computeDiff — changed services (version change)
// ---------------------------------------------------------------------------

test('computeDiff detects changed services (version change)', () => {
  const previous = makeSummary({
    services: [{ port: 22, protocol: 'tcp', service: 'ssh', version: '7.4' }],
  });
  const current = makeSummary({
    services: [{ port: 22, protocol: 'tcp', service: 'ssh', version: '8.9' }],
  });

  const diff = computeDiff(current, previous);
  assert.equal(diff.changedServices.length, 1);
  assert.equal(diff.changedServices[0].previousVersion, '7.4');
  assert.equal(diff.changedServices[0].currentVersion, '8.9');
  assert.equal(diff.newServices.length, 0);
  assert.equal(diff.removedServices.length, 0);
  assert.ok(diff.summary.includes('1 service(s) changed'));
});

// ---------------------------------------------------------------------------
// computeDiff — no changes
// ---------------------------------------------------------------------------

test('computeDiff reports no changes for identical scans', () => {
  const services = [
    { port: 22, protocol: 'tcp', service: 'ssh', version: '8.9' },
    { port: 80, protocol: 'tcp', service: 'http', version: '1.18' },
  ];
  const previous = makeSummary({ services, findingsCount: 2 });
  const current = makeSummary({ services, findingsCount: 2 });

  const diff = computeDiff(current, previous);
  assert.equal(diff.newServices.length, 0);
  assert.equal(diff.removedServices.length, 0);
  assert.equal(diff.changedServices.length, 0);
  assert.equal(diff.newFindings, 0);
  assert.ok(diff.summary.includes('No changes detected'));
});

// ---------------------------------------------------------------------------
// computeDiff — first scan (no previous)
// ---------------------------------------------------------------------------

test('computeDiff handles first scan (no previous)', () => {
  const current = makeSummary({ findingsCount: 3 });
  const diff = computeDiff(current, null);

  assert.equal(diff.newServices.length, 0);
  assert.equal(diff.removedServices.length, 0);
  assert.equal(diff.changedServices.length, 0);
  assert.equal(diff.newFindings, 3);
  assert.ok(diff.summary.includes('No previous scan'));
});

// ---------------------------------------------------------------------------
// formatDiffReport
// ---------------------------------------------------------------------------

test('formatDiffReport generates readable output with all sections', () => {
  const diff = {
    newServices: [{ port: 443, protocol: 'tcp', service: 'https', version: '1.3' }],
    removedServices: [{ port: 21, protocol: 'tcp', service: 'ftp', version: '3.0.3' }],
    changedServices: [{
      port: 22, protocol: 'tcp',
      previousService: 'ssh', previousVersion: '7.4',
      currentService: 'ssh', currentVersion: '8.9',
    }],
    newFindings: 2,
    summary: '1 new service(s) detected, 1 service(s) removed, 1 service(s) changed, findings delta: +2.',
  };

  const report = formatDiffReport(diff);
  assert.ok(report.includes('## Scan Comparison'));
  assert.ok(report.includes('### New Services'));
  assert.ok(report.includes('443/tcp: https'));
  assert.ok(report.includes('### Removed Services'));
  assert.ok(report.includes('21/tcp: ftp'));
  assert.ok(report.includes('### Changed Services'));
  assert.ok(report.includes('7.4 -> ssh 8.9'));
  assert.ok(report.includes('+2'));
});

test('formatDiffReport handles first-scan diff', () => {
  const diff = computeDiff(makeSummary(), null);
  const report = formatDiffReport(diff);
  assert.ok(report.includes('## Scan Comparison'));
  assert.ok(report.includes('No previous scan'));
  // No sections for new/removed/changed since diff has empty arrays
  assert.ok(!report.includes('### New Services'));
});

// ---------------------------------------------------------------------------
// pruneForCE
// ---------------------------------------------------------------------------

test('pruneForCE removes entries older than 7 days', async () => {
  const tmpDir = os.tmpdir();
  const filePath = path.join(tmpDir, 'nsa_hist_prune_' + Date.now() + '.jsonl');

  const old = new Date(Date.now() - 8 * 24 * 60 * 60 * 1000).toISOString(); // 8 days ago
  const recent = new Date().toISOString();

  fs.writeFileSync(filePath, [
    JSON.stringify({ host: '1.1.1.1', timestamp: old, services: [] }),
    JSON.stringify({ host: '2.2.2.2', timestamp: recent, services: [] }),
  ].join('\n') + '\n');

  await pruneForCE(filePath); // function under test

  const lines = fs.readFileSync(filePath, 'utf8').trim().split('\n').filter(Boolean);
  assert.equal(lines.length, 1, 'Only the recent entry should survive');
  assert.equal(JSON.parse(lines[0]).host, '2.2.2.2');
  fs.unlinkSync(filePath);
});

test('pruneForCE keeps all entries within 7 days', async () => {
  const tmpDir = os.tmpdir();
  const filePath = path.join(tmpDir, 'nsa_hist_keep_' + Date.now() + '.jsonl');

  const sixDaysAgo = new Date(Date.now() - 6 * 24 * 60 * 60 * 1000).toISOString();
  const today = new Date().toISOString();

  fs.writeFileSync(filePath, [
    JSON.stringify({ host: '1.1.1.1', timestamp: sixDaysAgo, services: [] }),
    JSON.stringify({ host: '2.2.2.2', timestamp: today, services: [] }),
  ].join('\n') + '\n');

  await pruneForCE(filePath);

  const lines = fs.readFileSync(filePath, 'utf8').trim().split('\n').filter(Boolean);
  assert.equal(lines.length, 2, 'Both entries within 7 days should survive');
  fs.unlinkSync(filePath);
});

test('pruneForCE handles non-existent file gracefully', async () => {
  await assert.doesNotReject(() => pruneForCE('/nonexistent/path/hist.jsonl'));
});

test('pruneForCE keeps unparseable lines rather than discarding them', async () => {
  const tmpDir = os.tmpdir();
  const filePath = path.join(tmpDir, 'nsa_hist_corrupt_' + Date.now() + '.jsonl');

  fs.writeFileSync(filePath, 'not valid json\n');
  await pruneForCE(filePath);

  const content = fs.readFileSync(filePath, 'utf8');
  assert.ok(content.includes('not valid json'), 'Unparseable lines are preserved');
  fs.unlinkSync(filePath);
});
