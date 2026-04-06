import test from 'node:test';
import assert from 'node:assert/strict';

import {
  buildDeltaReport,
  formatDeltaSummary,
  hasSignificantChanges,
} from '../utils/delta_reporter.mjs';

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

function hostResult(overrides = {}) {
  return {
    host: '10.0.0.1',
    servicesCount: 1,
    findingsCount: 0,
    services: [
      { port: 22, protocol: 'tcp', service: 'ssh', version: '8.9' },
    ],
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// buildDeltaReport — new hosts
// ---------------------------------------------------------------------------

test('buildDeltaReport detects new hosts', () => {
  const current = new Map([
    ['10.0.0.1', hostResult()],
    ['10.0.0.2', hostResult({ host: '10.0.0.2' })],
  ]);
  const previous = new Map([
    ['10.0.0.1', hostResult()],
  ]);

  const delta = buildDeltaReport(current, previous);
  assert.deepEqual(delta.newHosts, ['10.0.0.2']);
  assert.deepEqual(delta.removedHosts, []);
});

// ---------------------------------------------------------------------------
// buildDeltaReport — removed hosts
// ---------------------------------------------------------------------------

test('buildDeltaReport detects removed hosts', () => {
  const current = new Map([
    ['10.0.0.1', hostResult()],
  ]);
  const previous = new Map([
    ['10.0.0.1', hostResult()],
    ['10.0.0.3', hostResult({ host: '10.0.0.3' })],
  ]);

  const delta = buildDeltaReport(current, previous);
  assert.deepEqual(delta.newHosts, []);
  assert.deepEqual(delta.removedHosts, ['10.0.0.3']);
});

// ---------------------------------------------------------------------------
// buildDeltaReport — per-host service diffs
// ---------------------------------------------------------------------------

test('buildDeltaReport includes per-host service diffs', () => {
  const current = new Map([
    ['10.0.0.1', hostResult({
      services: [
        { port: 22, protocol: 'tcp', service: 'ssh', version: '8.9' },
        { port: 443, protocol: 'tcp', service: 'https', version: '1.3' },
      ],
    })],
  ]);
  const previous = new Map([
    ['10.0.0.1', hostResult({
      services: [
        { port: 22, protocol: 'tcp', service: 'ssh', version: '8.9' },
      ],
    })],
  ]);

  const delta = buildDeltaReport(current, previous);
  assert.equal(delta.hostDiffs.size, 1);
  const diff = delta.hostDiffs.get('10.0.0.1');
  assert.equal(diff.newServices.length, 1);
  assert.equal(diff.newServices[0].port, 443);
});

test('buildDeltaReport detects removed services per host', () => {
  const current = new Map([
    ['10.0.0.1', hostResult({
      services: [{ port: 22, protocol: 'tcp', service: 'ssh', version: '8.9' }],
    })],
  ]);
  const previous = new Map([
    ['10.0.0.1', hostResult({
      services: [
        { port: 22, protocol: 'tcp', service: 'ssh', version: '8.9' },
        { port: 80, protocol: 'tcp', service: 'http', version: '1.18' },
      ],
    })],
  ]);

  const delta = buildDeltaReport(current, previous);
  const diff = delta.hostDiffs.get('10.0.0.1');
  assert.equal(diff.removedServices.length, 1);
  assert.equal(diff.removedServices[0].port, 80);
});

test('buildDeltaReport detects changed services per host', () => {
  const current = new Map([
    ['10.0.0.1', hostResult({
      services: [{ port: 22, protocol: 'tcp', service: 'ssh', version: '9.0' }],
    })],
  ]);
  const previous = new Map([
    ['10.0.0.1', hostResult({
      services: [{ port: 22, protocol: 'tcp', service: 'ssh', version: '8.9' }],
    })],
  ]);

  const delta = buildDeltaReport(current, previous);
  const diff = delta.hostDiffs.get('10.0.0.1');
  assert.equal(diff.changedServices.length, 1);
  assert.equal(diff.changedServices[0].previousVersion, '8.9');
  assert.equal(diff.changedServices[0].currentVersion, '9.0');
});

// ---------------------------------------------------------------------------
// buildDeltaReport — plain objects
// ---------------------------------------------------------------------------

test('buildDeltaReport accepts plain objects as input', () => {
  const current = { '10.0.0.1': hostResult(), '10.0.0.2': hostResult({ host: '10.0.0.2' }) };
  const previous = { '10.0.0.1': hostResult() };

  const delta = buildDeltaReport(current, previous);
  assert.deepEqual(delta.newHosts, ['10.0.0.2']);
  assert.equal(delta.hostDiffs.size, 2);
});

// ---------------------------------------------------------------------------
// buildDeltaReport — empty / null inputs
// ---------------------------------------------------------------------------

test('buildDeltaReport handles null previous gracefully', () => {
  const current = new Map([['10.0.0.1', hostResult()]]);
  const delta = buildDeltaReport(current, null);
  assert.deepEqual(delta.newHosts, ['10.0.0.1']);
  assert.deepEqual(delta.removedHosts, []);
  assert.equal(delta.hostDiffs.size, 1);
});

test('buildDeltaReport handles empty current and previous', () => {
  const delta = buildDeltaReport(new Map(), new Map());
  assert.deepEqual(delta.newHosts, []);
  assert.deepEqual(delta.removedHosts, []);
  assert.equal(delta.hostDiffs.size, 0);
});

// ---------------------------------------------------------------------------
// hasSignificantChanges
// ---------------------------------------------------------------------------

test('hasSignificantChanges returns true for new hosts', () => {
  const delta = buildDeltaReport(
    new Map([['10.0.0.1', hostResult()]]),
    new Map(),
  );
  assert.equal(hasSignificantChanges(delta), true);
});

test('hasSignificantChanges returns true for removed hosts', () => {
  const delta = buildDeltaReport(
    new Map(),
    new Map([['10.0.0.1', hostResult()]]),
  );
  assert.equal(hasSignificantChanges(delta), true);
});

test('hasSignificantChanges returns false when nothing changed', () => {
  const sameResult = hostResult();
  const delta = buildDeltaReport(
    new Map([['10.0.0.1', sameResult]]),
    new Map([['10.0.0.1', sameResult]]),
  );
  assert.equal(hasSignificantChanges(delta), false);
});

test('hasSignificantChanges returns true for service changes', () => {
  const current = new Map([
    ['10.0.0.1', hostResult({
      services: [{ port: 22, protocol: 'tcp', service: 'ssh', version: '9.0' }],
    })],
  ]);
  const previous = new Map([
    ['10.0.0.1', hostResult({
      services: [{ port: 22, protocol: 'tcp', service: 'ssh', version: '8.9' }],
    })],
  ]);
  const delta = buildDeltaReport(current, previous);
  assert.equal(hasSignificantChanges(delta), true);
});

test('hasSignificantChanges returns false for null input', () => {
  assert.equal(hasSignificantChanges(null), false);
});

// ---------------------------------------------------------------------------
// formatDeltaSummary
// ---------------------------------------------------------------------------

test('formatDeltaSummary produces readable output with new and removed hosts', () => {
  const delta = buildDeltaReport(
    new Map([['10.0.0.2', hostResult({ host: '10.0.0.2' })]]),
    new Map([['10.0.0.1', hostResult()]]),
  );
  const text = formatDeltaSummary(delta);
  assert.ok(text.includes('Delta Report'));
  assert.ok(text.includes('New hosts'));
  assert.ok(text.includes('10.0.0.2'));
  assert.ok(text.includes('Removed hosts'));
  assert.ok(text.includes('10.0.0.1'));
});

test('formatDeltaSummary shows no changes when nothing changed', () => {
  const same = hostResult();
  const delta = buildDeltaReport(
    new Map([['10.0.0.1', same]]),
    new Map([['10.0.0.1', same]]),
  );
  const text = formatDeltaSummary(delta);
  assert.ok(text.includes('No significant changes'));
});

test('formatDeltaSummary handles null input', () => {
  assert.equal(formatDeltaSummary(null), '');
});
