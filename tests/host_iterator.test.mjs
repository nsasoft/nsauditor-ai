import { test } from 'node:test';
import assert from 'node:assert/strict';
import fsp from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { expandCidr, expandRange, parseHostFile, parseHostArg } from '../utils/host_iterator.mjs';

/* ----------------------------- expandCidr ----------------------------- */

test('expandCidr /30 returns 2 usable hosts', () => {
  const hosts = expandCidr('192.168.1.0/30');
  assert.deepStrictEqual(hosts, ['192.168.1.1', '192.168.1.2']);
});

test('expandCidr /32 returns single IP', () => {
  const hosts = expandCidr('10.0.0.0/32');
  assert.deepStrictEqual(hosts, ['10.0.0.0']);
});

test('expandCidr /31 returns both IPs (point-to-point)', () => {
  const hosts = expandCidr('10.0.0.0/31');
  assert.deepStrictEqual(hosts, ['10.0.0.0', '10.0.0.1']);
});

test('expandCidr /24 returns 254 hosts', () => {
  const hosts = expandCidr('192.168.1.0/24');
  assert.equal(hosts.length, 254);
  assert.equal(hosts[0], '192.168.1.1');
  assert.equal(hosts[253], '192.168.1.254');
});

test('expandCidr /28 returns 14 hosts', () => {
  const hosts = expandCidr('10.10.10.0/28');
  assert.equal(hosts.length, 14);
  assert.equal(hosts[0], '10.10.10.1');
  assert.equal(hosts[13], '10.10.10.14');
});

test('expandCidr throws for prefix < 16', () => {
  assert.throws(() => expandCidr('10.0.0.0/15'), /too large|Minimum prefix/);
  assert.throws(() => expandCidr('10.0.0.0/8'), /too large|Minimum prefix/);
  assert.throws(() => expandCidr('0.0.0.0/0'), /too large|Minimum prefix/);
});

test('expandCidr throws for invalid IP', () => {
  assert.throws(() => expandCidr('999.0.0.0/24'), /Invalid IPv4/);
  assert.throws(() => expandCidr('abc/24'), /Invalid IPv4/);
  assert.throws(() => expandCidr('1.2.3/24'), /Invalid IPv4/);
});

test('expandCidr throws for invalid prefix', () => {
  assert.throws(() => expandCidr('10.0.0.0/33'), /Invalid prefix/);
  assert.throws(() => expandCidr('10.0.0.0/-1'), /Invalid prefix/);
  assert.throws(() => expandCidr('10.0.0.0/abc'), /Invalid prefix/);
});

test('expandCidr throws for missing slash notation', () => {
  assert.throws(() => expandCidr('192.168.1.0'), /Invalid CIDR/);
});

/* ----------------------------- expandRange ------------------------------ */

test('expandRange short notation 192.168.1.1-5 returns 5 IPs', () => {
  const hosts = expandRange('192.168.1.1-5');
  assert.deepStrictEqual(hosts, [
    '192.168.1.1', '192.168.1.2', '192.168.1.3', '192.168.1.4', '192.168.1.5'
  ]);
});

test('expandRange short notation single host 10.0.0.5-5', () => {
  const hosts = expandRange('10.0.0.5-5');
  assert.deepStrictEqual(hosts, ['10.0.0.5']);
});

test('expandRange full notation 192.168.1.1-192.168.1.3', () => {
  const hosts = expandRange('192.168.1.1-192.168.1.3');
  assert.deepStrictEqual(hosts, ['192.168.1.1', '192.168.1.2', '192.168.1.3']);
});

test('expandRange full notation across octets 10.0.0.254-10.0.1.2', () => {
  const hosts = expandRange('10.0.0.254-10.0.1.2');
  assert.deepStrictEqual(hosts, ['10.0.0.254', '10.0.0.255', '10.0.1.0', '10.0.1.1', '10.0.1.2']);
});

test('expandRange throws when end < start (short)', () => {
  assert.throws(() => expandRange('192.168.1.50-10'), /end < start/);
});

test('expandRange throws when end < start (full)', () => {
  assert.throws(() => expandRange('10.0.1.1-10.0.0.1'), /end < start/);
});

test('expandRange throws for invalid octet', () => {
  assert.throws(() => expandRange('192.168.1.1-300'), /Invalid octet/);
});

test('expandRange throws for too-large range', () => {
  assert.throws(() => expandRange('10.0.0.0-10.1.0.0'), /too large/);
});

test('parseHostArg with dash range delegates to expandRange', async () => {
  const hosts = await parseHostArg('192.168.1.1-3');
  assert.deepStrictEqual(hosts, ['192.168.1.1', '192.168.1.2', '192.168.1.3']);
});

/* ----------------------------- parseHostFile -------------------------- */

test('parseHostFile reads hosts, ignores comments and blanks', async () => {
  const tmpDir = os.tmpdir();
  const tmpFile = path.join(tmpDir, `hosts_test_${Date.now()}.txt`);
  try {
    await fsp.writeFile(tmpFile, [
      '# Comment line',
      '192.168.1.1',
      '',
      '10.0.0.1',
      '  # Another comment',
      'example.com',
      '  ',
      ''
    ].join('\n'), 'utf8');

    const hosts = await parseHostFile(tmpFile);
    assert.deepStrictEqual(hosts, ['192.168.1.1', '10.0.0.1', 'example.com']);
  } finally {
    await fsp.unlink(tmpFile).catch(() => {});
  }
});

test('parseHostFile handles Windows-style line endings', async () => {
  const tmpDir = os.tmpdir();
  const tmpFile = path.join(tmpDir, `hosts_crlf_${Date.now()}.txt`);
  try {
    await fsp.writeFile(tmpFile, '10.0.0.1\r\n10.0.0.2\r\n', 'utf8');
    const hosts = await parseHostFile(tmpFile);
    assert.deepStrictEqual(hosts, ['10.0.0.1', '10.0.0.2']);
  } finally {
    await fsp.unlink(tmpFile).catch(() => {});
  }
});

/* ----------------------------- parseHostArg --------------------------- */

test('parseHostArg with single IP returns array of one', async () => {
  const hosts = await parseHostArg('1.2.3.4');
  assert.deepStrictEqual(hosts, ['1.2.3.4']);
});

test('parseHostArg with hostname returns array of one', async () => {
  const hosts = await parseHostArg('example.com');
  assert.deepStrictEqual(hosts, ['example.com']);
});

test('parseHostArg with CIDR delegates to expandCidr', async () => {
  const hosts = await parseHostArg('192.168.1.0/30');
  assert.deepStrictEqual(hosts, ['192.168.1.1', '192.168.1.2']);
});

test('parseHostArg with host file reads file', async () => {
  const relName = `hosts_arg_${Date.now()}.txt`;
  const fullPath = path.join(process.cwd(), relName);
  try {
    await fsp.writeFile(fullPath, '10.0.0.1\n10.0.0.2\n', 'utf8');
    const hosts = await parseHostArg(relName);
    assert.deepStrictEqual(hosts, ['10.0.0.1', '10.0.0.2']);
  } finally {
    await fsp.unlink(fullPath).catch(() => {});
  }
});
