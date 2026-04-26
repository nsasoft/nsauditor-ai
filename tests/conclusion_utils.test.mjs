// tests/conclusion_utils.test.mjs
//
// Tests for utils/conclusion_utils.mjs. Most importantly: the regression test
// for the latent bug surfaced during Task N.30 implementation, where
// normalizeService() was stripping every plugin's custom security flags
// (anonymousLogin, weakAlgorithms, axfrAllowed, mcpCleartextTransport, etc.).
// Downstream readers (sarif, export_csv, report_md, AI prompt) all expect
// these flags on the service record. Pre-fix: silently dead code.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { normalizeService, upsertService, keyOf, statusFrom, firstDataRow } from '../utils/conclusion_utils.mjs';

/* ------------------------------ keyOf ------------------------------ */

test('keyOf: combines protocol:port', () => {
  assert.equal(keyOf({ protocol: 'tcp', port: 80 }), 'tcp:80');
  assert.equal(keyOf({ protocol: 'UDP', port: 53 }), 'udp:53');
  assert.equal(keyOf({ port: 22 }), 'tcp:22'); // default protocol
});

/* ------------------------------ normalizeService — standard fields ------------------------------ */

test('normalizeService: coerces port to Number', () => {
  const r = normalizeService({ port: '8090', protocol: 'tcp', service: 'mcp' });
  assert.equal(r.port, 8090);
  assert.equal(typeof r.port, 'number');
});

test('normalizeService: lowercases protocol and service', () => {
  const r = normalizeService({ port: 80, protocol: 'TCP', service: 'HTTP' });
  assert.equal(r.protocol, 'tcp');
  assert.equal(r.service, 'http');
});

test('normalizeService: defaults missing service to "unknown"', () => {
  const r = normalizeService({ port: 80, protocol: 'tcp' });
  assert.equal(r.service, 'unknown');
});

test('normalizeService: defaults missing protocol to tcp', () => {
  const r = normalizeService({ port: 80, service: 'http' });
  assert.equal(r.protocol, 'tcp');
});

test('normalizeService: program/version/info/banner default to null when missing', () => {
  const r = normalizeService({ port: 80, protocol: 'tcp', service: 'http' });
  assert.equal(r.program, null);
  assert.equal(r.version, null);
  assert.equal(r.info, null);
  assert.equal(r.banner, null);
});

test('normalizeService: generates CPE when program is present', () => {
  const r = normalizeService({ port: 80, service: 'http', program: 'nginx', version: '1.24.0' });
  assert.ok(r.cpe?.includes('nginx'));
});

test('normalizeService: cpe is null when program is missing', () => {
  const r = normalizeService({ port: 80, service: 'http' });
  assert.equal(r.cpe, null);
});

/* ------------------------------ normalizeService — evidence handling ------------------------------ */

test('normalizeService: array evidence passes through', () => {
  const evidence = [{ probe_protocol: 'tcp', probe_port: 80 }];
  const r = normalizeService({ port: 80, service: 'http', evidence });
  assert.deepEqual(r.evidence, evidence);
});

test('normalizeService: object evidence (FindingSchema cwe/owasp/mitre) passes through', () => {
  // N.5/N.14 introduced object-shaped evidence: { cwe, owasp, mitre }
  const evidence = { cwe: ['CWE-319'], owasp: ['A02:2021-Cryptographic Failures'], mitre: ['T1040'] };
  const r = normalizeService({ port: 8090, service: 'mcp', evidence });
  assert.deepEqual(r.evidence, evidence);
});

test('normalizeService: missing evidence defaults to empty array (not null)', () => {
  const r = normalizeService({ port: 80, service: 'http' });
  assert.deepEqual(r.evidence, []);
});

test('normalizeService: invalid evidence (string, number) defaults to empty array', () => {
  assert.deepEqual(normalizeService({ port: 80, service: 'http', evidence: 'string' }).evidence, []);
  assert.deepEqual(normalizeService({ port: 80, service: 'http', evidence: 42 }).evidence, []);
});

/* ------------------------------ normalizeService — N.30 REGRESSION: custom fields ------------------------------ */

test('N.30 REGRESSION: normalizeService preserves anonymousLogin flag', () => {
  // ftp_banner_check sets this. sarif.mjs / export_csv.mjs / report_md.mjs read it.
  // Pre-fix it was silently stripped — sarif/csv/md never saw the flag.
  const r = normalizeService({ port: 21, service: 'ftp', anonymousLogin: true });
  assert.equal(r.anonymousLogin, true, 'anonymousLogin must survive normalization');
});

test('N.30 REGRESSION: normalizeService preserves axfrAllowed flag', () => {
  const r = normalizeService({ port: 53, service: 'dns', axfrAllowed: true });
  assert.equal(r.axfrAllowed, true);
});

test('N.30 REGRESSION: normalizeService preserves weakAlgorithms / weakProtocols / weakCiphers arrays', () => {
  const r = normalizeService({
    port: 443, service: 'https',
    weakAlgorithms: ['DES', 'RC4'],
    weakProtocols: ['TLSv1.0'],
    weakCiphers: ['DES-CBC3-SHA'],
  });
  assert.deepEqual(r.weakAlgorithms, ['DES', 'RC4']);
  assert.deepEqual(r.weakProtocols, ['TLSv1.0']);
  assert.deepEqual(r.weakCiphers, ['DES-CBC3-SHA']);
});

test('N.30 REGRESSION: normalizeService preserves dangerousMethods', () => {
  const r = normalizeService({ port: 80, service: 'http', dangerousMethods: ['PUT', 'DELETE'] });
  assert.deepEqual(r.dangerousMethods, ['PUT', 'DELETE']);
});

test('N.30 REGRESSION: normalizeService preserves SNMP community flag', () => {
  const r = normalizeService({ port: 161, protocol: 'udp', service: 'snmp', community: 'public' });
  assert.equal(r.community, 'public');
});

test('N.30 REGRESSION: normalizeService preserves CVE arrays', () => {
  const r = normalizeService({ port: 22, service: 'ssh', cves: ['CVE-2023-38408'] });
  assert.deepEqual(r.cves, ['CVE-2023-38408']);
});

test('N.30 REGRESSION: normalizeService preserves MCP-specific flags', () => {
  const r = normalizeService({
    port: 8090, service: 'mcp',
    mcpAnonymousAccess: true,
    mcpCleartextTransport: true,
    mcpDeprecatedProtocol: '2024-11-05',
    mcpInspectorExposed: true,
    mcpAnonymousToolList: ['execute_shell', 'read_file'],
  });
  assert.equal(r.mcpAnonymousAccess, true);
  assert.equal(r.mcpCleartextTransport, true);
  assert.equal(r.mcpDeprecatedProtocol, '2024-11-05');
  assert.equal(r.mcpInspectorExposed, true);
  assert.deepEqual(r.mcpAnonymousToolList, ['execute_shell', 'read_file']);
});

test('N.30 REGRESSION: normalizeService preserves authoritative flag', () => {
  // upsertService reads this from item.authoritative — must not be stripped
  const r = normalizeService({ port: 80, service: 'http', authoritative: true });
  assert.equal(r.authoritative, true);
});

test('N.30 REGRESSION: normalized fields override input even when also present', () => {
  // Custom fields preserved, but the standardized normalization (e.g. lowercased
  // protocol, coerced port) wins over the input shape
  const r = normalizeService({
    port: '443',           // string → coerced to number
    protocol: 'TCP',       // uppercase → lowercased
    service: 'HTTPS',      // uppercase → lowercased
    customFlag: 'kept',    // unknown → preserved
  });
  assert.equal(r.port, 443);
  assert.equal(r.protocol, 'tcp');
  assert.equal(r.service, 'https');
  assert.equal(r.customFlag, 'kept');
});

/* ------------------------------ upsertService ------------------------------ */

test('upsertService: inserts new record', () => {
  const services = [];
  upsertService(services, normalizeService({ port: 80, service: 'http' }));
  assert.equal(services.length, 1);
  assert.equal(services[0].port, 80);
});

test('upsertService: deduplicates by protocol:port key', () => {
  const services = [];
  upsertService(services, normalizeService({ port: 80, protocol: 'tcp', service: 'http' }));
  upsertService(services, normalizeService({ port: 80, protocol: 'tcp', service: 'http', program: 'nginx' }));
  assert.equal(services.length, 1);
  assert.equal(services[0].program, 'nginx');
});

test('upsertService: authoritative wins over non-authoritative', () => {
  const services = [];
  upsertService(services, normalizeService({ port: 80, service: 'http', program: 'guess' }), { authoritative: false });
  upsertService(services, normalizeService({ port: 80, service: 'http', program: 'real' }), { authoritative: true });
  assert.equal(services[0].program, 'real');
});

test('upsertService: custom flags survive merge', () => {
  // Critical: the N.30 fix loses value if upsertService strips flags during merge
  const services = [];
  upsertService(services, normalizeService({ port: 21, service: 'ftp', anonymousLogin: true }), { authoritative: true });
  // Add a non-authoritative blank record on top — must not lose anonymousLogin
  upsertService(services, normalizeService({ port: 21, service: 'ftp' }), { authoritative: false });
  assert.equal(services[0].anonymousLogin, true, 'authoritative flag survives non-auth merge');
});
