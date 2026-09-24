// 028's GUARD ON THE UPnP LIBRARY'S PACKET HANDLER — driven on the REAL node-upnp-utils (EE 1.1.0 build 7).
//
// node-upnp-utils 1.0.3 (the latest published) calls its async `_receivePacket` from the socket handler with
// no catch, so a rejection is unhandled and ends the process. Gate 2 build 6's timeout-control run DIED of it:
// an answer's description fetch was still in flight when the next search's `startDiscovery()` reset the device
// table (`SyntaxError: "undefined" is not valid JSON`). One misbehaving device does it too — an answer with no
// LOCATION (`TypeError: Invalid URL`). The plugin guards the module's single instance and COUNTS what it catches,
// and says so. The library lists a device BEFORE it fetches the description, so a caught answer is still in its
// search's result — measured below, not assumed.
//
// No LAN: the answers are crafted SSDP packets handed to the REAL `_receivePacket`, and the description is
// served by a local server that can be told to be slow. The race is the reset the library itself performs.
import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import upnp from 'node-upnp-utils';
import upnpScanner, { guardReceivePacket, droppedResponses } from '../plugins/upnp_scanner.mjs';

const PLUGIN = fileURLToPath(new URL('../plugins/upnp_scanner.mjs', import.meta.url));
const answer = (usn, location) => Buffer.from(`HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=600\r\n${location ? `LOCATION: ${location}\r\n` : ''}ST: upnp:rootdevice\r\nUSN: ${usn}\r\n\r\n`);
const RINFO = { address: '127.0.0.1', port: 1900 };

async function descriptionServer(t, delayMs) {
  const server = http.createServer((q, r) => setTimeout(() => {
    r.writeHead(200, { 'content-type': 'text/xml' });
    r.end('<?xml version="1.0"?><root><device><friendlyName>x</friendlyName></device></root>');
  }, delayMs));
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  t.after(() => server.close());
  return `http://127.0.0.1:${server.address().port}/desc.xml`;
}
const delta = (before) => {
  const now = droppedResponses(upnp); const out = {};
  for (const [k, v] of Object.entries(now)) if (v - (before[k] ?? 0)) out[k] = v - (before[k] ?? 0);
  return out;
};

guardReceivePacket(upnp);

// ── FOURTH QUADRANT FIRST: a well-formed answer that does not race still becomes a device ──────────────
test('an answer that does not race is processed as before — `added` fires and nothing is counted', async (t) => {
  const loc = await descriptionServer(t, 20);
  upnp._devices = {};
  const added = [];
  const onAdded = (d) => added.push(d);
  upnp.on('added', onAdded);
  t.after(() => upnp.removeListener('added', onAdded));
  const before = droppedResponses(upnp);
  await upnp._receivePacket(answer('uuid:calm::upnp:rootdevice', loc), RINFO);
  assert.equal(added.length, 1, 'the device was added');
  assert.deepEqual(delta(before), {}, 'nothing dropped');
});

test('the guard is installed ONCE — a second call leaves the same wrapper in place', () => {
  const wrapper = upnp._receivePacket;
  guardReceivePacket(upnp);
  assert.equal(upnp._receivePacket, wrapper);
});

test('the reset race — a fetch still in flight when the table is reset — resolves through the guard, and is COUNTED', async (t) => {
  const loc = await descriptionServer(t, 300);
  upnp._devices = {};
  const before = droppedResponses(upnp);
  const p = upnp._receivePacket(answer('uuid:race::upnp:rootdevice', loc), RINFO);
  setTimeout(() => { upnp._devices = {}; }, 50); // what the NEXT search's startDiscovery() does
  await p; // resolves: the guard caught the rejection
  assert.deepEqual(delta(before), { SyntaxError: 1 });
});

test('an answer with no usable LOCATION resolves through the guard, and is COUNTED', async () => {
  upnp._devices = {};
  const before = droppedResponses(upnp);
  await upnp._receivePacket(answer('uuid:noloc::upnp:rootdevice', null), RINFO);
  await upnp._receivePacket(answer('uuid:badloc::upnp:rootdevice', 'not a url'), RINFO);
  assert.deepEqual(delta(before), { TypeError: 2 });
});

// ── THE PRODUCTION SHAPE: the library does not await the handler, so an escaped rejection kills the process ──
const child = (withGuard) => spawnSync(process.execPath, ['--input-type=module', '-e', `
  import http from 'node:http';
  import upnp from 'node-upnp-utils';
  import { guardReceivePacket } from ${JSON.stringify(PLUGIN)};
  ${withGuard ? 'guardReceivePacket(upnp);' : ''}
  const server = http.createServer((q, r) => setTimeout(() => { r.writeHead(200); r.end('<root/>'); }, 300));
  server.listen(0, '127.0.0.1', () => {
    const loc = 'http://127.0.0.1:' + server.address().port + '/d.xml';
    upnp._devices = {};
    upnp._receivePacket(Buffer.from('HTTP/1.1 200 OK\\r\\nCACHE-CONTROL: max-age=600\\r\\nLOCATION: ' + loc + '\\r\\nST: upnp:rootdevice\\r\\nUSN: uuid:c::upnp:rootdevice\\r\\n\\r\\n'), { address: '127.0.0.1', port: 1900 });
    setTimeout(() => { upnp._devices = {}; }, 50);
    setTimeout(() => { server.close(); console.log('SURVIVED'); }, 700);
  });
`], { cwd: fileURLToPath(new URL('..', import.meta.url)), encoding: 'utf8', timeout: 20000 });

test('the NEGATIVE control — unguarded and unawaited, as the library calls it, the race KILLS the process', () => {
  const r = child(false);
  assert.equal(r.status, 1, `exit ${r.status}: ${r.stderr.slice(-200)}`);
  assert.match(r.stderr, /"undefined" is not valid JSON/);
  assert.doesNotMatch(r.stdout, /SURVIVED/);
});

test('the same race, GUARDED and unawaited, leaves the process running to its end', () => {
  const r = child(true);
  assert.equal(r.status, 0, `exit ${r.status}: ${r.stderr.slice(-300)}`);
  assert.match(r.stdout, /SURVIVED/);
  assert.doesNotMatch(r.stderr, /unhandled|not valid JSON/i);
});

// ── WHAT A CAUGHT ANSWER COSTS: its device is still listed by the search that received it ─────────────
test('a caught answer is STILL LISTED by its own search — the library lists a device before it fetches the description', async (t) => {
  const loc = await descriptionServer(t, 300);
  const SEAMS = ['startDiscovery', 'wait', 'stopDiscovery'];
  // The real start's only table effect is `this._devices = {}` (lib/upnp-utils.js); the seam does exactly that.
  upnp.startDiscovery = async () => { upnp._devices = {}; };
  upnp.wait = async () => { upnp._receivePacket(answer('uuid:listed::upnp:rootdevice', loc), RINFO); };
  upnp.stopDiscovery = async () => {};
  t.after(() => { for (const k of SEAMS) delete upnp[k]; });
  const before = droppedResponses(upnp);
  const first = await upnp.discover({ wait: 1, st: 'upnp:rootdevice' });
  assert.ok(first.some((d) => d.headers?.USN === 'uuid:listed::upnp:rootdevice'), 'the device is listed by the search that received its answer');
  upnp.wait = async () => {};
  await upnp.discover({ wait: 1, st: 'ssdp:all' }); // the NEXT search's start resets the table under the in-flight fetch
  await new Promise((r) => setTimeout(r, 450));
  assert.deepEqual(delta(before), { SyntaxError: 1 }, 'and the race still happened, and was caught');
});

// ── THE PLUGIN REPORTS WHAT IT CAUGHT, AND SAYS SO ────────────────────────────────────────────────────
test('an answer caught during a run reaches the result as upnpLibraryErrors, with ONE warning naming the count', async (t) => {
  const SEAMS = ['startDiscovery', 'wait', 'stopDiscovery', 'getActiveDeviceList'];
  let injected = false;
  upnp.startDiscovery = async () => {};
  upnp.wait = async () => {
    if (!injected) { injected = true; await upnp._receivePacket(answer('uuid:inrun::upnp:rootdevice', null), RINFO); }
  };
  upnp.stopDiscovery = async () => {};
  upnp.getActiveDeviceList = () => [];
  const warned = [];
  const warn = console.warn;
  console.warn = (...a) => warned.push(a.join(' '));
  t.after(() => { for (const k of SEAMS) delete upnp[k]; console.warn = warn; });
  const out = await upnpScanner.run('192.168.1.1', 1900, {});
  assert.equal(out.upnpLibraryErrors, 1);
  assert.deepEqual(out.upnpLibraryErrorsByName, { TypeError: 1 });
  assert.equal(warned.filter((w) => /upnp-scanner.*1 UPnP answer/.test(w)).length, 1, `one warning naming the count: ${JSON.stringify(warned)}`);
});
