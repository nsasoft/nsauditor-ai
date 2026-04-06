// tests/db_scanner.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import dbScanner from '../plugins/db_scanner.mjs';

// ---------- helpers ---------------------------------------------------------

function startServerAt(port, onConn) {
  return new Promise((resolve, reject) => {
    const server = net.createServer(onConn);
    server.once('error', (e) => {
      if (e && e.code === 'EADDRINUSE') resolve({ port, server: null, inUse: true });
      else reject(e);
    });
    server.listen(port, '127.0.0.1', () => resolve({ port, server, inUse: false }));
  });
}

async function closeServer(srv) {
  if (!srv || !srv.server) return;
  await new Promise((res) => srv.server.close(() => res()));
}

function mysqlGreetingPacket(versionStr) {
  // MySQL protocol 10 greeting: header (len LE 3 + seq 1) + payload: 0x0a + version + 0x00
  const ver = Buffer.from(versionStr, 'utf8');
  const payload = Buffer.concat([Buffer.from([0x0a]), ver, Buffer.from([0x00])]);
  const len = payload.length;
  const header = Buffer.from([len & 0xff, (len >> 8) & 0xff, (len >> 16) & 0xff, 0x00]);
  return Buffer.concat([header, payload]);
}

function mssqlPreloginResponse({ major, minor, build, sub }) {
  // Minimal PRELOGIN response tokens inside a TDS 8-byte header.
  const header = Buffer.from([0x04, 0x01, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00]); // arbitrary OK
  // Token: 0x00 (VERSION), offset=0x0008, length=6 ; then 0xFF terminator
  const token = Buffer.from([0x00, 0x00, 0x08, 0x00, 0x06, 0xff]);
  const pad = Buffer.alloc(0x08 - token.length, 0x00); // pad to offset 0x0008
  const ver = Buffer.alloc(6);
  ver[0] = major;
  ver[1] = minor;
  ver.writeUInt16BE(build, 2);
  ver.writeUInt16BE(sub, 4);
  return Buffer.concat([header, token, pad, ver]);
}

// ---------- tests -----------------------------------------------------------

test('DB Scanner: MySQL/MariaDB greeting is parsed (port 3306)', async (t) => {
  const srv = await startServerAt(3306, (sock) => {
    sock.write(mysqlGreetingPacket('5.7.31-mysql-community'));
    sock.end();
  });
  if (srv.inUse) return t.skip('3306 in use (real MySQL running)');

  try {
    const res = await dbScanner.run('127.0.0.1', 3306, {});
    assert.equal(res.up, true);
    assert.equal(res.program, 'MySQL');
    assert.ok(/^5\.7\.31/.test(res.version), `expected version ~ 5.7.31, got ${res.version}`);
    assert.ok((res.data?.[0]?.response_banner || '').includes('MySQL greeting'));
  } finally {
    await closeServer(srv);
  }
});

test('DB Scanner: MSSQL PRELOGIN version decoded (port 1433)', async (t) => {
  const srv = await startServerAt(1433, (sock) => {
    // Send response after any client data arrives
    sock.once('data', () => {
      sock.write(mssqlPreloginResponse({ major: 15, minor: 0, build: 4185, sub: 0 }));
      sock.end();
    });
  });
  if (srv.inUse) return t.skip('1433 in use (real SQL Server running)');

  try {
    const res = await dbScanner.run('127.0.0.1', 1433, {});
    assert.equal(res.up, true);
    assert.equal(res.program, 'Microsoft SQL Server');
    assert.ok(/^15\./.test(res.version), `expected version to start with 15., got ${res.version}`);
    assert.ok((res.data?.[0]?.response_banner || '').includes('MSSQL PRELOGIN'));
  } finally {
    await closeServer(srv);
  }
});

test('DB Scanner: PostgreSQL version from error text (port 5432)', async (t) => {
  const srv = await startServerAt(5432, (sock) => {
    // Reply to StartupMessage with an error text including the version.
    sock.once('data', () => {
      sock.write(Buffer.from('PostgreSQL 14.2 on x86_64-pc-linux-gnu', 'utf8'));
      sock.end();
    });
  });
  if (srv.inUse) return t.skip('5432 in use (real PostgreSQL running)');

  try {
    const res = await dbScanner.run('127.0.0.1', 5432, {});
    assert.equal(res.up, true);
    assert.equal(res.program, 'PostgreSQL');
    assert.equal(res.version, '14.2');
  } finally {
    await closeServer(srv);
  }
});

test('DB Scanner: Oracle TNS banner heuristic (port 1521)', async (t) => {
  const srv = await startServerAt(1521, (sock) => {
    sock.write(Buffer.from('TNS-Listener OK; version=12.1.0.2.0', 'utf8'));
    sock.end();
  });
  if (srv.inUse) return t.skip('1521 in use (real Oracle listener running)');

  try {
    const res = await dbScanner.run('127.0.0.1', 1521, {});
    assert.equal(res.up, true);
    assert.equal(res.program, 'Oracle Database');
    assert.ok(res.version.startsWith('12.1'), `expected 12.1.*, got ${res.version}`);
  } finally {
    await closeServer(srv);
  }
});

test('DB Scanner: MongoDB buildInfo regex (port 27017)', async (t) => {
  const srv = await startServerAt(27017, (sock) => {
    // Respond to OP_QUERY with a minimal JSON blob containing "version"
    sock.once('data', () => {
      sock.write(Buffer.from('{ "ok":1, "version":"6.0.5" }', 'utf8'));
      sock.end();
    });
  });
  if (srv.inUse) return t.skip('27017 in use (real MongoDB running)');

  try {
    const res = await dbScanner.run('127.0.0.1', 27017, {});
    assert.equal(res.up, true);
    assert.equal(res.program, 'MongoDB');
    assert.equal(res.version, '6.0.5');
  } finally {
    await closeServer(srv);
  }
});
