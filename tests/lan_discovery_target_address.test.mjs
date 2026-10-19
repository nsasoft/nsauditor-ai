// tests/lan_discovery_target_address.test.mjs
// ─────────────────────────────────────────────────────────────────────────────
// THE LAN-DISCOVERY PROBES DECIDE "LOCAL" ON THE ADDRESS THE SCAN RESOLVED, AND A PROBE THAT WAS NOT ATTEMPTED SAYS WHY.
//
// UPnP (028), mDNS (027) and WS-Discovery (016) gated on `isPrivateLike(host)` over the target STRING, so a NAME target —
// `gate-router.test`, pinned by the host check to 192.168.1.1 — was "Non-local target — not attempted", and a by-name scan
// of a LAN device lost all three. They also match the devices that answer by ADDRESS, which a name never equals. Each now
// takes the address the scan resolved the target to (an IP literal is its own; a name, the pinned answer, IPv4 first)
// for both the gate and the match. A probe that is not attempted returns `skipped: true` with its reason — so the
// plugin manager records it `skipped`, not `ran` — and the concluder puts a skipped result with no adapter in evidence
// with that reason, never in the service list (UPnP's not-attempted row used to reach it as `1900/upnp`).
//
// DRIVEN, OFFLINE: each library through its own seam (UPnP and mDNS factories, a fake UDP socket for WS-Discovery);
// the pin is the scan's own (`runPinned`).
//
// FOURTH QUADRANT FIRST: a private IP literal is still attempted and still matched — or the change could pass by
// declining everything.
// ─────────────────────────────────────────────────────────────────────────────
import './helpers/no_operator_home.mjs';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { createRequire } from 'node:module';
import { runPinned } from '../utils/scan_pin.mjs';

const require = createRequire(import.meta.url);
const dgram = require('node:dgram');
const DEVICE = '192.168.1.24';
const NAME = 'gate-router.test';

// ── The three libraries, each answered by one device at DEVICE ───────────────────────────────────────────────────────
globalThis.__upnpFakeFactory = () => ({
  discover: async ({ wait }) => {
    assert.ok(Number.isInteger(wait) && wait >= 1, 'the library contract: a whole-second wait');
    return [{ address: DEVICE, headers: { $: 'HTTP/1.1 200 OK', LOCATION: `http://${DEVICE}:1990/desc.xml`, SERVER: 'POSIX UPnP/1.0',
      ST: 'upnp:rootdevice', USN: 'uuid:1::upnp:rootdevice' },
    descriptionXML: '<?xml version="1.0"?><root xmlns="urn:schemas-upnp-org:device-1-0"><device><friendlyName>Gate</friendlyName></device></root>' }];
  },
});
globalThis.__mdnsFakeFactory = () => {
  const handlers = { response: [] };
  return {
    on(evt, fn) { (handlers[evt] ??= []).push(fn); },
    removeListener(evt, fn) { handlers[evt] = (handlers[evt] ?? []).filter((f) => f !== fn); },
    query() {
      setTimeout(() => handlers.response.forEach((fn) => fn({ answers: [
        { type: 'SRV', name: 'Gate._http._tcp.local', data: { target: 'gate.local', port: 80 } },
        { type: 'A', name: 'gate.local', data: DEVICE }] })), 5);
    },
    destroy() {},
  };
};
const PROBE_MATCH = '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://www.w3.org/2005/08/addressing" '
  + 'xmlns:d="http://docs.oasis-open.org/ws-dd/ns/discovery/2009/01"><s:Body><d:ProbeMatches><d:ProbeMatch>'
  + '<a:EndpointReference><a:Address>urn:uuid:1</a:Address></a:EndpointReference><d:Types>dn:NetworkVideoTransmitter</d:Types>'
  + `<d:XAddrs>http://${DEVICE}/onvif</d:XAddrs></d:ProbeMatch></d:ProbeMatches></s:Body></s:Envelope>`;
dgram.createSocket = () => {
  const s = new EventEmitter();
  s.address = () => ({ address: '0.0.0.0', port: 50000 });
  s.bind = (cb) => setImmediate(() => cb?.());
  s.setBroadcast = () => {}; s.setMulticastTTL = () => {}; s.close = () => {};
  s.send = (_buf, _port, _addr, cb) => { cb?.(null); setImmediate(() => s.emit('message', Buffer.from(PROBE_MATCH), { address: DEVICE, port: 3702 })); };
  return s;
};
process.env.UPNP_TEST_FAKE = '1';
process.env.MDNS_TEST_FAKE = '1';
process.env.MDNS_FORCE_FALLBACK = '1';
globalThis.fetch = async () => new Response('<?xml version="1.0"?><root/>', { status: 200 });

const [{ default: upnp }, { default: mdns }, { default: wsd }, { default: concluder }] = await Promise.all([
  import('../plugins/upnp_scanner.mjs'), import('../plugins/mdns_scanner.mjs'), import('../plugins/wsd_scanner.mjs'),
  import('../plugins/result_concluder.mjs')]);
const PROBES = [
  { id: '028', name: 'Enhanced UPnP Scanner', run: (h) => upnp.run(h, 1900, { timeoutMs: 1000 }) },
  // mDNS matches twice — inside its library path, and again over the rows it kept — and the second writes its own row.
  { id: '027', name: 'mDNS Scanner', run: (h) => mdns.run(h, 0, { timeoutMs: 60 }),
    explicit: (out) => out.data.some((r) => r.probe_info === `Matched host IP ${DEVICE} via mDNS`) },
  { id: '016', name: 'Enhanced WS-Discovery Scanner', run: (h) => wsd.run(h, 3702, { timeout: 40 }) },
];
const matched = (out) => out.up === true && out.data.some((r) => /Matched host|confirmed via/i.test(String(r.probe_info)));
const pinnedTo = (address, fn) => runPinned({ [NAME]: [{ address, family: 4 }] }, fn);

// ── FOURTH QUADRANT FIRST ─────────────────────────────────────────────────────────────────────────────────────────────
for (const p of PROBES) {
  test(`(first) ${p.id}: a private IP literal is attempted and its device matched — as before`, async () => {
    const out = await p.run(DEVICE);
    assert.notEqual(out.skipped, true);
    assert.ok(matched(out), JSON.stringify(out.data.map((r) => r.probe_info)));
  });
}

// ── THE DEFECT: a NAME the scan pinned to a LAN address ────────────────────────────────────────────────────────────────
for (const p of PROBES) {
  test(`${p.id}: a NAME pinned to a LAN address is attempted, and the device at that address is matched`, async () => {
    const out = await pinnedTo(DEVICE, () => p.run(NAME));
    assert.notEqual(out.skipped, true, out.reason);
    assert.ok(matched(out), JSON.stringify(out.data.map((r) => r.probe_info)));
    if (p.explicit) assert.ok(p.explicit(out), `${p.id}: the second match names the address`);
  });
}

// ── NOT ATTEMPTED, WITH THE REASON ─────────────────────────────────────────────────────────────────────────────────────
for (const p of PROBES) {
  test(`${p.id}: not attempted — a name pinned to a PUBLIC address, a name with no pin, a public literal — each says why`, async () => {
    const pub = await pinnedTo('8.8.8.8', () => p.run(NAME));
    assert.equal(pub.skipped, true);
    assert.match(pub.reason, /not on a local network/);
    assert.match(pub.reason, new RegExp(`${NAME.replace('.', '\\.')}.*8\\.8\\.8\\.8`));
    const unknown = await p.run(NAME);
    assert.equal(unknown.skipped, true);
    assert.match(unknown.reason, /address .* is not known/);
    const literal = await p.run('8.8.8.8');
    assert.equal(literal.skipped, true);
    assert.equal(literal.up, false);
    assert.ok(literal.data.some((r) => /Non-local target/.test(String(r.probe_info))), 'the not-attempted row is kept');
  });
}

// ── THE CONCLUDER: a skipped result with no adapter is evidence, never a service ───────────────────────────────────────
test('(first) a fallback result that was NOT skipped is a service, as before', async () => {
  const c = await concluder.run([{ id: '028', name: 'Enhanced UPnP Scanner',
    result: { up: false, program: 'UPnP/SSDP', version: 'Unknown', type: 'upnp',
      data: [{ probe_protocol: 'upnp', probe_port: 1900, probe_info: 'No devices answered', response_banner: null }] } }]);
  assert.equal((c.result ?? c).services.filter((s) => s.port === 1900).length, 1);
});
test('a skipped result with no adapter lists no service: its reason is in evidence', async () => {
  for (const p of PROBES) {
    const result = await p.run('8.8.8.8');
    const c = await concluder.run([{ id: p.id, name: p.name, result }]);
    const r = c.result ?? c;
    assert.deepEqual(r.services.filter((s) => s.port === 1900 || s.port === 3702 || s.port === 53 || s.port === 0), [], p.id);
    assert.ok(r.evidence.some((e) => e.reason === result.reason), `${p.id}: ${JSON.stringify(r.evidence)}`);
  }
});
