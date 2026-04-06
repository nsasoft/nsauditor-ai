import test from 'node:test';
import assert from 'node:assert/strict';

import { parseCvssVector, calculateBaseScore, severityFromScore } from '../utils/cvss.mjs';

// ---------------------------------------------------------------------------
// parseCvssVector
// ---------------------------------------------------------------------------

test('parseCvssVector: extracts all 8 metric values correctly', () => {
  const m = parseCvssVector('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H');
  assert.deepEqual(m, { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'C', C: 'H', I: 'H', A: 'H' });
});

test('parseCvssVector: throws on invalid vector string', () => {
  assert.throws(() => parseCvssVector('not-a-vector'), /Invalid CVSS/);
  assert.throws(() => parseCvssVector('CVSS:2.0/AV:N/AC:L'), /Invalid CVSS/);
  assert.throws(() => parseCvssVector(''), /Invalid CVSS/);
  assert.throws(() => parseCvssVector(42), /must be a string/);
});

test('parseCvssVector: throws on missing metric', () => {
  // Missing A metric
  assert.throws(
    () => parseCvssVector('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H'),
    /Missing required metric/,
  );
});

test('parseCvssVector: throws on invalid metric value', () => {
  assert.throws(
    () => parseCvssVector('CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'),
    /Invalid value/,
  );
});

// ---------------------------------------------------------------------------
// Known CVE base scores (must match NVD published scores)
// ---------------------------------------------------------------------------

test('CVE-2021-44228 (Log4Shell) → 10.0 Critical', () => {
  const vector = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H';
  const metrics = parseCvssVector(vector);
  const score = calculateBaseScore(metrics);
  assert.equal(score, 10.0);
  assert.equal(severityFromScore(score), 'Critical');
});

test('CVE-2023-44487 (HTTP/2 Rapid Reset) → 7.5 High', () => {
  const vector = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H';
  const metrics = parseCvssVector(vector);
  const score = calculateBaseScore(metrics);
  assert.equal(score, 7.5);
  assert.equal(severityFromScore(score), 'High');
});

test('CVE-2014-0160 (Heartbleed) → 7.5 High', () => {
  const vector = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N';
  const metrics = parseCvssVector(vector);
  const score = calculateBaseScore(metrics);
  assert.equal(score, 7.5);
  assert.equal(severityFromScore(score), 'High');
});

test('Low severity example → Low range (0.1–3.9)', () => {
  const vector = 'CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N';
  const metrics = parseCvssVector(vector);
  const score = calculateBaseScore(metrics);
  assert.ok(score >= 0.1 && score <= 3.9, `Expected Low range, got ${score}`);
  assert.equal(severityFromScore(score), 'Low');
});

test('Medium severity example → Medium range (4.0–6.9)', () => {
  const vector = 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N';
  const metrics = parseCvssVector(vector);
  const score = calculateBaseScore(metrics);
  assert.ok(score >= 4.0 && score <= 6.9, `Expected Medium range, got ${score}`);
  assert.equal(severityFromScore(score), 'Medium');
});

// ---------------------------------------------------------------------------
// severityFromScore boundary tests
// ---------------------------------------------------------------------------

test('severityFromScore: boundary values', () => {
  assert.equal(severityFromScore(0), 'None');
  assert.equal(severityFromScore(0.0), 'None');
  assert.equal(severityFromScore(0.1), 'Low');
  assert.equal(severityFromScore(3.9), 'Low');
  assert.equal(severityFromScore(4.0), 'Medium');
  assert.equal(severityFromScore(6.9), 'Medium');
  assert.equal(severityFromScore(7.0), 'High');
  assert.equal(severityFromScore(8.9), 'High');
  assert.equal(severityFromScore(9.0), 'Critical');
  assert.equal(severityFromScore(10.0), 'Critical');
});
