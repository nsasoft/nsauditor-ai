import assert from 'node:assert/strict';
import test from 'node:test';
import { escapeCsvField, buildCsv } from '../utils/export_csv.mjs';

// --- escapeCsvField tests ---

test('escapeCsvField — plain string returns as-is', () => {
  assert.equal(escapeCsvField('hello'), 'hello');
});

test('escapeCsvField — string with comma gets quoted', () => {
  assert.equal(escapeCsvField('a,b'), '"a,b"');
});

test('escapeCsvField — string with double quotes gets escaped and quoted', () => {
  assert.equal(escapeCsvField('say "hi"'), '"say ""hi"""');
});

test('escapeCsvField — string with newline gets quoted', () => {
  assert.equal(escapeCsvField('line1\nline2'), '"line1\nline2"');
});

test('escapeCsvField — null/undefined returns empty string', () => {
  assert.equal(escapeCsvField(null), '');
  assert.equal(escapeCsvField(undefined), '');
});

// --- buildCsv tests ---

const scanData = {
  host: '192.168.1.1',
  conclusion: {
    result: {
      services: [
        { port: 22, protocol: 'tcp', service: 'ssh', program: 'OpenSSH', version: '9.6', status: 'open', cpe: 'cpe:2.3:a:openbsd:openssh:9.6:*:*:*:*:*:*:*', weakAlgorithms: ['diffie-hellman-group14-sha1'] },
        { port: 80, protocol: 'tcp', service: 'http', program: 'nginx', version: '1.24', status: 'open', cpe: null, dangerousMethods: ['PUT', 'DELETE'] },
        { port: 21, protocol: 'tcp', service: 'ftp', program: 'vsFTPd', version: '3.0.3', status: 'open', anonymousLogin: true },
      ]
    }
  }
};

test('buildCsv — produces header row with correct columns', () => {
  const csv = buildCsv(scanData);
  const header = csv.split('\r\n')[0];
  assert.equal(header, 'host,port,protocol,service,program,version,status,cpe,security_findings');
});

test('buildCsv — maps services to CSV rows correctly', () => {
  const csv = buildCsv(scanData);
  const lines = csv.split('\r\n');
  // header + 3 service rows + trailing empty after final \r\n
  assert.equal(lines.length, 5);
  // first data row
  const cols = lines[1].split(',');
  assert.equal(cols[0], '192.168.1.1');
  assert.equal(cols[1], '22');
  assert.equal(cols[2], 'tcp');
  assert.equal(cols[3], 'ssh');
  assert.equal(cols[4], 'OpenSSH');
  assert.equal(cols[5], '9.6');
  assert.equal(cols[6], 'open');
});

test('buildCsv — handles empty services array (header only)', () => {
  const csv = buildCsv({ host: '10.0.0.1', conclusion: { result: { services: [] } } });
  const lines = csv.split('\r\n');
  // header + trailing empty
  assert.equal(lines.length, 2);
  assert.equal(lines[0], 'host,port,protocol,service,program,version,status,cpe,security_findings');
  assert.equal(lines[1], ''); // trailing after final \r\n
});

test('buildCsv — includes security findings column with correct formatting', () => {
  const csv = buildCsv(scanData);
  const lines = csv.split('\r\n');

  // SSH row: weakAlgorithms — findings contain comma so the field gets quoted
  const sshRow = lines[1];
  assert.ok(sshRow.includes('weak_algorithms:1'));

  // HTTP row: dangerousMethods — findings contain comma so field gets quoted
  const httpRow = lines[2];
  assert.ok(httpRow.includes('dangerous_methods:PUT;DELETE'));

  // FTP row: anonymousLogin
  const ftpRow = lines[3];
  assert.ok(ftpRow.includes('anonymous_login'));
});

test('buildCsv — handles services without CPE (empty field)', () => {
  const csv = buildCsv(scanData);
  const lines = csv.split('\r\n');
  // HTTP row has cpe: null — the cpe column should be empty
  // Split carefully: the http row has dangerousMethods which produces a comma in findings
  // so the findings field will be quoted. Parse accordingly.
  const httpRow = lines[2];
  // Between status "open" and the findings, cpe should be empty: ...open,,
  assert.ok(httpRow.includes('open,,'), 'empty cpe field should produce consecutive commas');
});
