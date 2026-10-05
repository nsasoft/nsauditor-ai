// tests/upnp_location_guard.test.mjs
// 1.2.1 lane 2, item D (operator ruling R2: the per-hop SSRF guard is IN) — plugin 028's LOCATION fetch.
//
// A UPnP device chooses the URL in its SSDP LOCATION header, and 028 fetched it with node-fetch (an
// undeclared dependency), following redirects, checked against nothing — then stored the first 2000
// characters of the answer in the result banner. The UPnP library itself also fetched the LOCATION of any
// ssdp:alive NOTIFY it heard, with no host check at all. Now: a description is fetched only from the
// answering device's own address (http or https), with global fetch and `redirect: 'manual'`; and a
// NOTIFY whose LOCATION names a host other than its sender is dropped — and counted — before the library
// can fetch it. The library's M-SEARCH-answer path already checks the host and is left as it is.
//
// Harness: NO packet leaves the machine, before or after the fix. Every URL that any code path could
// fetch is a loopback server this file starts; a host that must be refused is spelled `localhost` (a
// name, never the answering address) and served by a counting listener, so "refused" is measured as
// zero requests. Metadata and public hosts appear only in the predicate legs, which fetch nothing.

import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import upnp from 'node-upnp-utils';
import * as plugin from '../plugins/upnp_scanner.mjs';

const XML = '<?xml version="1.0"?><root xmlns="urn:schemas-upnp-org:device-1-0"><device><friendlyName>LoopDevice</friendlyName></device></root>';

async function server(t, handler = (q, r) => { r.writeHead(200, { 'content-type': 'text/xml' }); r.end(XML); }) {
  const hits = [];
  const srv = http.createServer((q, r) => { hits.push(q.url); handler(q, r); });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  t.after(() => srv.close());
  return { hits, port: srv.address().port };
}

// The plugin, over a fake library that reports ONE device at `address` (the scan target) advertising `location`.
async function runWithDevice(t, location, address = '127.0.0.1') {
  const prev = { fake: process.env.UPNP_TEST_FAKE, factory: globalThis.__upnpFakeFactory };
  process.env.UPNP_TEST_FAKE = '1';
  globalThis.__upnpFakeFactory = () => ({
    discover: async () => [{ address, headers: { '$': 'HTTP/1.1 200 OK', 'CACHE-CONTROL': 'max-age=600',
      LOCATION: location, SERVER: 'Linux/5.10 UPnP/1.0 Loop/1.0', ST: 'upnp:rootdevice', USN: 'uuid:loop-0001::upnp:rootdevice' } }],
  });
  t.after(() => {
    if (prev.fake === undefined) delete process.env.UPNP_TEST_FAKE; else process.env.UPNP_TEST_FAKE = prev.fake;
    globalThis.__upnpFakeFactory = prev.factory;
  });
  const out = await plugin.default.run(address, 1900, { timeoutMs: 200 });
  const row = out.data.find((d) => d.probe_protocol === 'upnp' && d.probe_info.includes(`address=${address}`));
  assert.ok(row, `no device row: ${JSON.stringify(out.data)}`);
  return { row, banner: JSON.parse(row.response_banner) };
}

const notify = (usn, location) => Buffer.from(`NOTIFY * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nCACHE-CONTROL: max-age=600\r\n` +
  `LOCATION: ${location}\r\nNT: upnp:rootdevice\r\nNTS: ssdp:alive\r\nUSN: ${usn}\r\n\r\n`);
const SENDER = { address: '127.0.0.1', port: 1900 };
plugin.guardReceivePacket(upnp);
async function receiveNotify(t, usn, location, sender = SENDER) {
  const prevParams = upnp._params;
  upnp._params = { st: 'upnp:rootdevice' }; // what discover() sets: the library keeps a NOTIFY only for its search target
  upnp._devices = {};
  const added = [];
  const onAdded = (d) => added.push(d);
  upnp.on('added', onAdded);
  t.after(() => { upnp.removeListener('added', onAdded); upnp._params = prevParams; upnp._devices = {}; });
  await upnp._receivePacket(notify(usn, location), sender);
  return added;
}

// ── the predicate ────────────────────────────────────────────────────────────

test('(fourth quadrant, first) descriptionUrlAllowed admits the answering device\'s own address — http or https, any port, mapped or bracketed', () => {
  assert.equal(typeof plugin.descriptionUrlAllowed, 'function', 'descriptionUrlAllowed is exported');
  assert.equal(plugin.descriptionUrlAllowed('http://192.168.1.24:1990/WFADevice.xml', '192.168.1.24'), true);
  assert.equal(plugin.descriptionUrlAllowed('https://192.168.1.24/desc.xml', '192.168.1.24'), true);
  assert.equal(plugin.descriptionUrlAllowed('http://192.168.1.24:5000/d.xml', '::ffff:192.168.1.24'), true);
  assert.equal(plugin.descriptionUrlAllowed('http://[fe80::1]:49152/d.xml', 'fe80::1'), true);
});

test('descriptionUrlAllowed refuses any other host — metadata, a public address, a name, another scheme, a non-URL', () => {
  assert.equal(typeof plugin.descriptionUrlAllowed, 'function', 'descriptionUrlAllowed is exported');
  for (const loc of ['http://169.254.169.254/latest/meta-data/', 'http://203.0.113.9/d.xml', 'http://router.local:1990/d.xml',
    'http://localhost:1990/d.xml', 'file:///etc/passwd', 'ftp://192.168.1.24/d.xml', 'not a url', '']) {
    assert.equal(plugin.descriptionUrlAllowed(loc, '192.168.1.24'), false, loc);
  }
});

// ── 028's own fetch ──────────────────────────────────────────────────────────

test('(fourth quadrant) 028 fetches the description from the answering device\'s own address and keeps it', async (t) => {
  const A = await server(t);
  const { banner } = await runWithDevice(t, `http://127.0.0.1:${A.port}/desc.xml`);
  assert.equal(A.hits.length, 1);
  assert.match(banner.descriptionXML, /LoopDevice/);
});

test('028 does NOT fetch a LOCATION on another host — a name, or ANOTHER ADDRESS — zero requests, and the row says so', async (t) => {
  // Two shapes, because the predicate refuses them on different branches: a name never canonicalises to
  // an address, and a different address fails the equality. (A battery mutant admitting every ADDRESS
  // survived a name-only fixture.) 127.0.0.2 is the device; 127.0.0.1 is where its LOCATION points.
  for (const [location, address] of [['localhost', '127.0.0.1'], ['127.0.0.1', '127.0.0.2']]) {
    const B = await server(t);
    const { row, banner } = await runWithDevice(t, `http://${location}:${B.port}/desc.xml`, address);
    assert.equal(B.hits.length, 0, `${address} named ${location}, not itself; the scanner must not go there`);
    assert.equal(banner.descriptionXML, null);
    assert.match(row.probe_info, /description refused/i);
  }
});

test('028 does not follow a redirect from the description URL — the second host receives NOTHING', async (t) => {
  const D = await server(t);
  const C = await server(t, (q, r) => { r.writeHead(302, { location: `http://127.0.0.1:${D.port}/elsewhere.xml` }); r.end(); });
  const { banner } = await runWithDevice(t, `http://127.0.0.1:${C.port}/desc.xml`);
  assert.equal(C.hits.length, 1, 'positive control: the advertised URL was asked');
  assert.equal(D.hits.length, 0, 'a redirect from the device must not be followed');
  assert.equal(banner.descriptionXML, null);
});

// ── the UPnP library's NOTIFY path, on the REAL library ─────────────────────

test('(fourth quadrant) a NOTIFY whose LOCATION names its own sender passes through — the library fetches it and lists the device', async (t) => {
  const E = await server(t);
  const before = plugin.refusedAnnouncements?.(upnp) ?? 0;
  const added = await receiveNotify(t, 'uuid:self-notify::upnp:rootdevice', `http://127.0.0.1:${E.port}/desc.xml`);
  assert.equal(E.hits.length, 1);
  assert.equal(added.length, 1);
  assert.equal((plugin.refusedAnnouncements?.(upnp) ?? 0) - before, 0);
});

test('a NOTIFY whose LOCATION names ANOTHER host is dropped before the library fetches it, and counted', async (t) => {
  assert.equal(typeof plugin.refusedAnnouncements, 'function', 'refusedAnnouncements is exported');
  // A name, and another address (the sender is 127.0.0.2; the LOCATION points at 127.0.0.1).
  for (const [host, sender] of [['localhost', SENDER], ['127.0.0.1', { address: '127.0.0.2', port: 1900 }]]) {
    const F = await server(t);
    const before = plugin.refusedAnnouncements(upnp);
    const added = await receiveNotify(t, `uuid:steer-${host}::upnp:rootdevice`, `http://${host}:${F.port}/desc.xml`, sender);
    assert.equal(F.hits.length, 0, `the library fetched a URL its sender (${sender.address}) did not own`);
    assert.equal(added.length, 0);
    assert.equal(plugin.refusedAnnouncements(upnp) - before, 1);
  }
});

// ── the guard reads an announcement exactly as the LIBRARY reads it ──────────
// (Security review of the first guard: it parsed LOCATION with its own regex while the library parses with
// `_parseSdpResponseHeader` — so a second LOCATION line (the library keeps the LAST, the regex read the
// first), a space before the colon (the library accepts it, the regex did not), or a start line the library
// still takes for a NOTIFY (`NOTIFYX`) slipped a LOCATION past the check. The guard now decides on the
// library's own parse. Node's http.request parses the URL string with the WHATWG parser the predicate uses —
// measured on \\@, #@, padded, 0x7f.1, 127.1 and mapped-IPv6 spellings: same host in every case.)
async function receiveRaw(t, text, sender = SENDER) {
  const prevParams = upnp._params;
  upnp._params = { st: 'upnp:rootdevice' };
  upnp._devices = {};
  const added = [];
  const onAdded = (d) => added.push(d);
  upnp.on('added', onAdded);
  t.after(() => { upnp.removeListener('added', onAdded); upnp._params = prevParams; upnp._devices = {}; });
  await upnp._receivePacket(Buffer.from(text), sender);
  return added;
}
const NOTIFY_TAIL = 'NT: upnp:rootdevice\r\nNTS: ssdp:alive\r\nCACHE-CONTROL: max-age=600\r\n';

test('a SECOND LOCATION line naming another host is refused — the library keeps the last one', async (t) => {
  const own = await server(t);
  const other = await server(t);
  const before = plugin.refusedAnnouncements(upnp);
  await receiveRaw(t, `NOTIFY * HTTP/1.1\r\nLOCATION: http://127.0.0.1:${own.port}/d.xml\r\n` +
    `LOCATION: http://localhost:${other.port}/d.xml\r\n${NOTIFY_TAIL}USN: uuid:dup::upnp:rootdevice\r\n\r\n`);
  assert.equal(other.hits.length, 0, 'the library fetched the second LOCATION');
  assert.equal(plugin.refusedAnnouncements(upnp) - before, 1);
});

test('a LOCATION written with a space before the colon is read and refused — the library accepts that spelling', async (t) => {
  const other = await server(t);
  await receiveRaw(t, `NOTIFY * HTTP/1.1\r\nLOCATION : http://localhost:${other.port}/d.xml\r\n${NOTIFY_TAIL}USN: uuid:spaced::upnp:rootdevice\r\n\r\n`);
  assert.equal(other.hits.length, 0);
});

test('a start line the library still takes for a NOTIFY ("NOTIFYX") is checked too', async (t) => {
  const other = await server(t);
  await receiveRaw(t, `NOTIFYX * HTTP/1.1\r\nLOCATION: http://localhost:${other.port}/d.xml\r\n${NOTIFY_TAIL}USN: uuid:notifyx::upnp:rootdevice\r\n\r\n`);
  assert.equal(other.hits.length, 0);
});
