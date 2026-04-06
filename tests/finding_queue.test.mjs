import { test } from 'node:test';
import assert from 'node:assert/strict';
import { FindingQueue } from '../utils/finding_queue.mjs';

function mkFinding(overrides = {}) {
  return {
    category: 'AUTH',
    status: 'UNVERIFIED',
    title: 'Weak SSH auth',
    severity: 'HIGH',
    target: { host: '10.0.0.1', port: 22, protocol: 'tcp', service: 'ssh' },
    ...overrides,
  };
}

test('add() stores a finding and returns an ID', () => {
  const q = new FindingQueue();
  const id = q.add(mkFinding());
  assert.ok(typeof id === 'string' && id.startsWith('F-'), `Expected F-xxx ID, got ${id}`);
  assert.equal(q.size, 1);
});

test('add() throws on invalid finding', () => {
  const q = new FindingQueue();
  assert.throws(() => q.add({ category: 'INVALID' }), /Invalid finding/);
});

test('getByCategory filters correctly', () => {
  const q = new FindingQueue();
  q.add(mkFinding({ category: 'AUTH' }));
  q.add(mkFinding({ category: 'CRYPTO' }));
  assert.equal(q.getByCategory('AUTH').length, 1);
  assert.equal(q.getByCategory('CRYPTO').length, 1);
  assert.equal(q.getByCategory('CVE').length, 0);
});

test('getByStatus filters correctly', () => {
  const q = new FindingQueue();
  q.add(mkFinding({ status: 'UNVERIFIED' }));
  q.add(mkFinding({ status: 'UNVERIFIED' }));
  assert.equal(q.getByStatus('UNVERIFIED').length, 2);
  assert.equal(q.getByStatus('VERIFIED').length, 0);
});

test('markVerified updates status and attaches verification evidence', () => {
  const q = new FindingQueue();
  const id = q.add(mkFinding());
  const verification = { method: 'ssh-banner', result: 'password auth confirmed', timestamp: '2026-04-06T00:00:00Z', safe: true };
  q.markVerified(id, verification);
  const verified = q.getByStatus('VERIFIED');
  assert.equal(verified.length, 1, 'should have 1 VERIFIED finding');
  assert.deepEqual(verified[0].evidence.verification, verification);
});

test('markFalsePositive updates status and records reason', () => {
  const q = new FindingQueue();
  const id = q.add(mkFinding());
  q.markFalsePositive(id, 'backport patch confirmed');
  const fp = q.getByStatus('FALSE_POSITIVE');
  assert.equal(fp.length, 1);
  assert.equal(fp[0].falsePositiveReason, 'backport patch confirmed');
});

test('prioritize sorts by severity descending', () => {
  const q = new FindingQueue();
  q.add(mkFinding({ severity: 'LOW' }));
  q.add(mkFinding({ severity: 'CRITICAL' }));
  q.add(mkFinding({ severity: 'MEDIUM' }));
  q.prioritize();
  const sevs = q.findings.map(f => f.severity);
  assert.deepEqual(sevs, ['CRITICAL', 'MEDIUM', 'LOW']);
});

test('toJSON returns a deep copy (mutation does not affect queue)', () => {
  const q = new FindingQueue();
  q.add(mkFinding());
  const json = q.toJSON();
  assert.ok(Array.isArray(json));
  assert.ok(json[0].id, 'finding has an ID');
  // Mutate the copy — original should be unaffected
  json[0].title = 'MUTATED';
  assert.notEqual(q.findings[0].title, 'MUTATED', 'toJSON should return a deep copy');
});
