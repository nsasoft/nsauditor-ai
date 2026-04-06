import assert from 'node:assert/strict';
import test from 'node:test';
import { generateCpe, parseVersion, CPE_MAP } from '../utils/cpe.mjs';

// --- parseVersion ---

test('parseVersion splits version with update suffix', () => {
  const r = parseVersion('8.2p1');
  assert.equal(r.version, '8.2');
  assert.equal(r.update, 'p1');
});

test('parseVersion returns * update when no suffix', () => {
  const r = parseVersion('1.24.0');
  assert.equal(r.version, '1.24.0');
  assert.equal(r.update, '*');
});

test('parseVersion handles null/undefined', () => {
  assert.deepStrictEqual(parseVersion(null), { version: '*', update: '*' });
  assert.deepStrictEqual(parseVersion(undefined), { version: '*', update: '*' });
  assert.deepStrictEqual(parseVersion(''), { version: '*', update: '*' });
});

// --- generateCpe: known programs ---

test('generateCpe OpenSSH 8.2p1', () => {
  const cpe = generateCpe('openssh', '8.2p1');
  assert.equal(cpe, 'cpe:2.3:a:openbsd:openssh:8.2:p1:*:*:*:*:*:*');
});

test('generateCpe nginx 1.24.0', () => {
  const cpe = generateCpe('nginx', '1.24.0');
  assert.equal(cpe, 'cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*');
});

test('generateCpe Apache 2.4.41', () => {
  const cpe = generateCpe('apache', '2.4.41');
  assert.equal(cpe, 'cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*');
});

test('generateCpe ProFTPD 1.3.5', () => {
  const cpe = generateCpe('proftpd', '1.3.5');
  assert.equal(cpe, 'cpe:2.3:a:proftpd:proftpd:1.3.5:*:*:*:*:*:*:*');
});

test('generateCpe MySQL 8.0.32', () => {
  const cpe = generateCpe('mysql', '8.0.32');
  assert.equal(cpe, 'cpe:2.3:a:oracle:mysql:8.0.32:*:*:*:*:*:*:*');
});

// --- case insensitivity ---

test('generateCpe is case-insensitive (NGINX)', () => {
  const cpe = generateCpe('NGINX', '1.0');
  assert.equal(cpe, 'cpe:2.3:a:nginx:nginx:1.0:*:*:*:*:*:*:*');
});

test('generateCpe is case-insensitive (OpenSSH)', () => {
  const cpe = generateCpe('OpenSSH', '9.0');
  assert.equal(cpe, 'cpe:2.3:a:openbsd:openssh:9.0:*:*:*:*:*:*:*');
});

// --- unknown / null / empty ---

test('generateCpe returns null for unknown program', () => {
  assert.equal(generateCpe('unknown-service', '1.0'), null);
});

test('generateCpe returns null for null program', () => {
  assert.equal(generateCpe(null, '1.0'), null);
});

test('generateCpe returns null for empty string program', () => {
  assert.equal(generateCpe('', '1.0'), null);
});

// --- null/empty version ---

test('generateCpe with null version uses wildcards', () => {
  const cpe = generateCpe('nginx', null);
  assert.equal(cpe, 'cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*');
});

test('generateCpe with empty string version uses wildcards', () => {
  const cpe = generateCpe('nginx', '');
  assert.equal(cpe, 'cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*');
});

// --- full CPE format validation ---

test('CPE string matches cpe:2.3:a:vendor:product:version:update:*:*:*:*:*:* format', () => {
  const cpe = generateCpe('openssh', '8.2p1');
  const parts = cpe.split(':');
  assert.equal(parts.length, 13);
  assert.equal(parts[0], 'cpe');
  assert.equal(parts[1], '2.3');
  assert.equal(parts[2], 'a');
  assert.equal(parts[3], 'openbsd');  // vendor
  assert.equal(parts[4], 'openssh');  // product
  assert.equal(parts[5], '8.2');      // version
  assert.equal(parts[6], 'p1');       // update
  for (let i = 7; i < 13; i++) {
    assert.equal(parts[i], '*');
  }
});
