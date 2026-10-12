// tests/scan_pin_subprocess.test.mjs
// ─────────────────────────────────────────────────────────────────────────────
// THE SCAN-TARGET PIN AT THE SUBPROCESS LAYER (EE 2.0.0, R1b). curl, ping, nping, hping3 and nmap resolve through the OS,
// never through the pinned node:dns, so each plugin hands its command the address the scan's check resolved. Driven: the
// commands on PATH are recording stand-ins (they append their argv to a log and exit 1), the plugins run for real, and the
// log says what each plugin handed the OS — the NAME when nothing is pinned (the positive control), the ADDRESS when it is.
// A separate leg drives the REAL curl to prove --resolve does what http_probe relies on.
//
// `pin.test` (RFC 6761) never reaches a real resolver: pinned, the plugins' in-process TCP probes go to 127.0.0.1 and are
// refused fast; unpinned, they fail ENOTFOUND fast.
//
// FOURTH QUADRANT FIRST: unpinned, every command is handed the NAME.
// ─────────────────────────────────────────────────────────────────────────────
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import { spawn } from 'node:child_process';
import { runPinned } from '../utils/scan_pin.mjs';
import hostUpCheck from '../plugins/host_up_check.mjs';
import pingChecker from '../plugins/ping_checker.mjs';
import synScanner from '../plugins/syn_scanner.mjs';
import { probeFirmware } from '../plugins/http_probe.mjs';

const NAME = 'pin.test';
const PIN = { [NAME]: [{ address: '::1', family: 6 }, { address: '127.0.0.1', family: 4 }] };   // IPv6 first: the tools take IPv4
let dir; let log; const saved = {};

before(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pin-shims-'));
  log = path.join(dir, 'argv.log');
  for (const cmd of ['ping', 'nping', 'hping3', 'nmap', 'curl']) {
    fs.writeFileSync(path.join(dir, cmd), `#!/bin/sh\necho "${cmd} $*" >> "$SHIM_LOG"\nexit 1\n`, { mode: 0o755 });
  }
  for (const k of ['PATH', 'SHIM_LOG', 'ENABLE_SYN_SCAN']) saved[k] = process.env[k];
  process.env.PATH = `${dir}${path.delimiter}${process.env.PATH}`;
  process.env.SHIM_LOG = log;
  process.env.ENABLE_SYN_SCAN = '1';
});
after(() => {
  for (const [k, v] of Object.entries(saved)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
  fs.rmSync(dir, { recursive: true, force: true });
});

/** Run `fn` and return the argv lines the stand-ins recorded during it. */
async function recorded(fn) {
  fs.writeFileSync(log, '');
  await fn();
  return fs.readFileSync(log, 'utf8').trim().split('\n').filter(Boolean);
}
const lastArgOf = (lines, cmd) => lines.filter((l) => l.startsWith(`${cmd} `)).map((l) => l.split(' ').pop());

test('(sp1, first) UNPINNED, every command is handed the NAME — the stand-ins record what the plugins hand the OS', async () => {
  const lines = await recorded(async () => {
    await hostUpCheck.run(NAME);
    await pingChecker.run(NAME);
    await synScanner.run(NAME);
    await probeFirmware(NAME, 'NETGEAR R7000');
  });
  // Two pings: host_up_check's and ping_checker's own (the census missed the second; this leg found it).
  assert.deepEqual(lastArgOf(lines, 'ping'), [NAME, NAME], JSON.stringify(lines));
  assert.ok(lastArgOf(lines, 'nping').concat(lastArgOf(lines, 'hping3')).every((a) => a === NAME) && lastArgOf(lines, 'nping').length === 1);
  assert.deepEqual(lastArgOf(lines, 'nmap'), [NAME]);
  const curl = lines.find((l) => l.startsWith('curl '));
  assert.ok(curl && !curl.includes('--resolve') && curl.includes(`http://${NAME}/currentsetting.htm`), curl);
});

test('(sp2) PINNED, ping, nping, hping3 and nmap are handed the pinned IPv4 address — never the name', async () => {
  const lines = await recorded(() => runPinned(PIN, async () => {
    await hostUpCheck.run(NAME);
    await pingChecker.run(NAME);
    await synScanner.run(NAME);
  }));
  assert.deepEqual(lastArgOf(lines, 'ping'), ['127.0.0.1', '127.0.0.1'], JSON.stringify(lines));
  assert.deepEqual(lastArgOf(lines, 'nping'), ['127.0.0.1']);
  assert.deepEqual(lastArgOf(lines, 'hping3'), ['127.0.0.1']);
  assert.deepEqual(lastArgOf(lines, 'nmap'), ['127.0.0.1']);
  assert.ok(!lines.some((l) => l.split(' ').slice(1).includes(NAME)), `a command was still handed the name: ${JSON.stringify(lines)}`);
});

test('(sp3) PINNED, curl keeps the NAME in the URL (the Host header) and is told where to connect with --resolve', async () => {
  const lines = await recorded(() => runPinned(PIN, () => probeFirmware(NAME, 'NETGEAR R7000')));
  const curl = lines.find((l) => l.startsWith('curl '));
  assert.ok(curl, JSON.stringify(lines));
  assert.ok(curl.includes(`--resolve ${NAME}:80:127.0.0.1`), curl);
  assert.ok(curl.endsWith(`http://${NAME}/currentsetting.htm`), curl);
});

test('(sp4) the REAL curl honours --resolve: without it the name lands on loopback (positive control); with it, it never does', async () => {
  const real = ['/usr/bin/curl', '/usr/local/bin/curl', '/opt/homebrew/bin/curl'].find((p) => fs.existsSync(p));
  assert.ok(real, 'no real curl on this machine — this leg cannot measure, and a skipped leg is not a pass');
  let hits = 0;
  const server = http.createServer((req, res) => { hits += 1; res.end('ok'); });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const port = server.address().port;
  const run = (args) => new Promise((resolve) => { const p = spawn(real, args); p.on('close', resolve); p.on('error', resolve); });
  try {
    await run(['-s', '-m', '2', `http://localhost:${port}/`]);
    assert.equal(hits, 1, 'positive control: curl by name reached the loopback receiver');
    await run(['-s', '-m', '1', '--resolve', `localhost:${port}:203.0.113.10`, `http://localhost:${port}/`]);
    assert.equal(hits, 1, '--resolve did not govern where curl connected');
  } finally { await new Promise((r) => server.close(r)); }
});
