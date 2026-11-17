// tests/port_set_source_line.test.mjs
// WHEN A WORKING-DIRECTORY config/services.json REPLACES THE PORT SET, THE SCAN SAYS SO, every run, on stderr:
// the relative path and the tcp/udp counts, and that the package default was not swept. With no such file there is
// no line and the package set is swept. The line prints ONCE per process for one working directory and one port set,
// not once per host: a /24 would otherwise print it 254 times.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import portScanner from '../plugins/port_scanner.mjs';

function dirWithServices(json) {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-portset-'));
  if (json !== undefined) { fs.mkdirSync(path.join(d, 'config')); fs.writeFileSync(path.join(d, 'config', 'services.json'), json); }
  return d;
}
async function captured(fn) {
  const lines = [];
  const real = { warn: console.warn, error: console.error };
  console.warn = (...a) => { lines.push(a.join(' ')); };
  console.error = (...a) => { lines.push(a.join(' ')); };
  try { await fn(); return lines; } finally { Object.assign(console, real); }
}
const LINE = /^nsauditor-ai: port set taken from config\/services\.json in the working directory: (\d+) tcp, (\d+) udp \(the package default was not swept\)$/;

test('ACCEPT first: no working-directory file → no port-set line', async () => {
  const floor = dirWithServices(JSON.stringify({ tcp: [9] }));
  const cwd = dirWithServices(undefined);
  try {
    const lines = await captured(() => portScanner.run('127.0.0.1', 0, { _servicesFloorRoot: floor, _servicesCwd: cwd, timeoutMs: 200 }));
    assert.ok(!lines.some((l) => LINE.test(l)), lines.join('\n'));
  } finally { for (const d of [floor, cwd]) fs.rmSync(d, { recursive: true, force: true }); }
});

test('a working-directory override is named on stderr with its counts', async () => {
  const floor = dirWithServices(JSON.stringify({ tcp: [9] }));
  const cwd = dirWithServices(JSON.stringify({ tcp: [8080, 8081], udp: [161] }));
  try {
    const lines = await captured(() => portScanner.run('127.0.0.1', 0, { _servicesFloorRoot: floor, _servicesCwd: cwd, timeoutMs: 200 }));
    const hit = lines.map((l) => LINE.exec(l)).filter(Boolean);
    assert.equal(hit.length, 1, lines.join('\n'));
    assert.deepEqual([hit[0][1], hit[0][2]], ['2', '1']);
  } finally { for (const d of [floor, cwd]) fs.rmSync(d, { recursive: true, force: true }); }
});

test('the port-set line prints once for a multi-host run, not once per host', async () => {
  const floor = dirWithServices(JSON.stringify({ tcp: [9] }));
  const cwd = dirWithServices(JSON.stringify({ tcp: [7001, 7002, 7003] }));
  try {
    const lines = await captured(async () => {
      for (const host of ['127.0.0.1', '127.0.0.2']) await portScanner.run(host, 0, { _servicesFloorRoot: floor, _servicesCwd: cwd, timeoutMs: 200 });
    });
    const hit = lines.map((l) => LINE.exec(l)).filter(Boolean);
    assert.equal(hit.length, 1, `expected one line for two hosts:\n${lines.join('\n')}`);
    assert.deepEqual([hit[0][1], hit[0][2]], ['3', '0']);
  } finally { for (const d of [floor, cwd]) fs.rmSync(d, { recursive: true, force: true }); }
});
