import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  validateFinding,
  generateFindingId,
  FINDING_CATEGORIES,
  FINDING_STATUSES,
  FINDING_SEVERITIES,
} from '../utils/finding_schema.mjs';

const validFinding = {
  category: 'CRYPTO',
  status: 'UNVERIFIED',
  title: 'TLS 1.0 enabled',
  severity: 'MEDIUM',
  target: { host: '10.0.0.1', port: 443, protocol: 'tcp', service: 'https' },
};

test('validateFinding returns empty array for valid finding', () => {
  assert.deepEqual(validateFinding(validFinding), []);
});

test('validateFinding rejects invalid category', () => {
  const errors = validateFinding({ ...validFinding, category: 'INVALID' });
  assert.ok(errors.length > 0, 'should have errors');
  assert.ok(errors.some(e => e.includes('category')), `errors should mention category: ${errors}`);
});

test('validateFinding rejects invalid severity', () => {
  const errors = validateFinding({ ...validFinding, severity: 'ULTRA' });
  assert.ok(errors.length > 0);
  assert.ok(errors.some(e => e.includes('severity')), `errors should mention severity: ${errors}`);
});

test('validateFinding rejects missing title', () => {
  const { title, ...noTitle } = validFinding;
  const errors = validateFinding(noTitle);
  assert.ok(errors.length > 0);
  assert.ok(errors.some(e => e.includes('title')), `errors should mention title: ${errors}`);
});

test('validateFinding rejects missing target.host', () => {
  const errors = validateFinding({ ...validFinding, target: { port: 443 } });
  assert.ok(errors.length > 0);
  assert.ok(errors.some(e => e.includes('target.host')), `errors should mention target.host: ${errors}`);
});

test('generateFindingId returns unique IDs', () => {
  const ids = new Set(Array.from({ length: 10 }, () => generateFindingId()));
  assert.equal(ids.size, 10, 'All 10 IDs should be unique');
});

test('generateFindingId format is F-<uuid>', () => {
  const id = generateFindingId();
  assert.match(id, /^F-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/, `ID format wrong: ${id}`);
});

test('FINDING_CATEGORIES includes all 6 categories', () => {
  assert.equal(FINDING_CATEGORIES.length, 6, `Expected 6 categories, got ${FINDING_CATEGORIES.length}`);
  for (const cat of ['AUTH', 'CRYPTO', 'CONFIG', 'SERVICE', 'EXPOSURE', 'CVE']) {
    assert.ok(FINDING_CATEGORIES.includes(cat), `Missing category: ${cat}`);
  }
});

test('validateFinding: existing finding without cwe/owasp still validates', () => {
  assert.deepEqual(validateFinding(validFinding), []);
});

test('validateFinding: accepts evidence.cwe with valid CWE-NNN entries', () => {
  const finding = { ...validFinding, evidence: { cwe: ['CWE-326', 'CWE-200'] } };
  assert.deepEqual(validateFinding(finding), []);
});

test('validateFinding: accepts empty evidence.cwe array', () => {
  const finding = { ...validFinding, evidence: { cwe: [] } };
  assert.deepEqual(validateFinding(finding), []);
});

test('validateFinding: rejects lowercase cwe id', () => {
  const finding = { ...validFinding, evidence: { cwe: ['cwe-326'] } };
  const errors = validateFinding(finding);
  assert.ok(errors.length > 0);
  assert.ok(errors.some(e => e.includes('cwe')), `errors should mention cwe: ${errors}`);
});

test('validateFinding: rejects evidence.cwe as a string instead of array', () => {
  const finding = { ...validFinding, evidence: { cwe: 'CWE-326' } };
  const errors = validateFinding(finding);
  assert.ok(errors.length > 0);
  assert.ok(errors.some(e => e.includes('cwe')), `errors should mention cwe: ${errors}`);
});

test('validateFinding: rejects malformed cwe id (CWE-abc)', () => {
  const finding = { ...validFinding, evidence: { cwe: ['CWE-abc'] } };
  const errors = validateFinding(finding);
  assert.ok(errors.length > 0);
  assert.ok(errors.some(e => e.includes('cwe')), `errors should mention cwe: ${errors}`);
});

test('validateFinding: rejects cwe id without CWE- prefix', () => {
  const finding = { ...validFinding, evidence: { cwe: ['326'] } };
  const errors = validateFinding(finding);
  assert.ok(errors.length > 0);
});

test('validateFinding: rejects non-string entry in evidence.cwe array', () => {
  const finding = { ...validFinding, evidence: { cwe: [326] } };
  const errors = validateFinding(finding);
  assert.ok(errors.length > 0);
});

test('validateFinding: accepts evidence.owasp with valid entries', () => {
  const finding = { ...validFinding, evidence: { owasp: ['A02:2021-Cryptographic Failures'] } };
  assert.deepEqual(validateFinding(finding), []);
});

test('validateFinding: accepts empty evidence.owasp array', () => {
  const finding = { ...validFinding, evidence: { owasp: [] } };
  assert.deepEqual(validateFinding(finding), []);
});

test('validateFinding: rejects evidence.owasp as a string instead of array', () => {
  const finding = { ...validFinding, evidence: { owasp: 'A02:2021' } };
  const errors = validateFinding(finding);
  assert.ok(errors.length > 0);
  assert.ok(errors.some(e => e.includes('owasp')), `errors should mention owasp: ${errors}`);
});

test('validateFinding: rejects non-string entry in evidence.owasp array', () => {
  const finding = { ...validFinding, evidence: { owasp: [42] } };
  const errors = validateFinding(finding);
  assert.ok(errors.length > 0);
});

test('validateFinding: accepts both cwe and owasp together', () => {
  const finding = {
    ...validFinding,
    evidence: { cwe: ['CWE-326'], owasp: ['A02:2021-Cryptographic Failures'] },
  };
  assert.deepEqual(validateFinding(finding), []);
});

test('validateFinding: invalid cwe does not mask other validation errors', () => {
  const finding = {
    ...validFinding,
    category: 'INVALID',
    evidence: { cwe: ['cwe-326'] },
  };
  const errors = validateFinding(finding);
  assert.ok(errors.some(e => e.includes('category')), `category error should still surface: ${errors}`);
  assert.ok(errors.some(e => e.includes('cwe')), `cwe error should also surface: ${errors}`);
});
