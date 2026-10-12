// utils/scan_pin.mjs
// ─────────────────────────────────────────────────────────────────────────────
// THE SCAN-TARGET PIN (EE 2.0.0, R1b — the operator's ruling "CLI pins too"; shape B as the architect seat amended it).
//
// A scan's host check resolves the target and checks EVERY answer; the plugins then connected by NAME, so a name that
// answered one thing to the check and another at connect (DNS rebinding) reached whatever the second answer named. Inside
// `runPinned`, `node:dns` `lookup` and `node:dns/promises` `lookup` answer the CHECKED answer set for the checked name, so
// every in-process connect — net, tls, http(s), fetch, dgram — goes where the check looked, and the name still rides as the
// Host header and the TLS server name.
//
// SCOPED TO THE SCAN'S ASYNC CONTEXT (AsyncLocalStorage), never a process-global map: two overlapping MCP scans of one
// name keep their own answer sets, and unrelated in-process work during a scan (GRC push, AI enrichment, the webhook) is
// not pinned by it. Outside a pinned run the resolvers behave exactly as before. A thrown scan leaves nothing behind.
//
// WHAT IT DOES NOT COVER, by construction: `dns.resolve*` (the DNS protocol, never getaddrinfo — used for DNS posture,
// which never connects to the target), and SUBPROCESSES (curl, ping, nping, hping3, arp, nmap resolve through the OS):
// each of those plugins reads `pinnedAddressFor(host)` and passes the address itself. tests/scan_pin_census.test.mjs is
// the deny-by-default census that keeps that list complete.
//
// A STATED LIMIT, measured: fetch (undici) and http.Agent pool keep-alive connections by NAME, and a reused connection
// never resolves. So within one process a scan can send a request over an idle connection opened earlier to the SAME name,
// for the few seconds it idles: by an earlier scan of that name (to an address that scan's check admitted), or by the
// product's own request to it (an AI provider, the NVD feed — names a scan rarely targets). tests/scan_pin.test.mjs holds
// the measurement.
// ─────────────────────────────────────────────────────────────────────────────
import { AsyncLocalStorage } from 'node:async_hooks';
import dns from 'node:dns';
import dnsPromises from 'node:dns/promises';
import { syncBuiltinESMExports } from 'node:module';

const store = new AsyncLocalStorage();
let ours = null;   // the resolvers this module installed, to tell them from anything installed over them since

const keyOf = (host) => String(host ?? '').trim().toLowerCase().replace(/\.$/, '');

/** The pinned answers for `hostname` in the current scan, family-filtered as asked — or null when nothing is pinned. */
function pinnedFor(hostname, options) {
  const pins = store.getStore();
  if (!pins) return null;
  const list = pins.get(keyOf(hostname));
  if (!list || list.length === 0) return null;
  const family = typeof options === 'number' ? options : options?.family;
  return family === 4 || family === 6 ? list.filter((a) => a.family === family) : list;
}

const notFound = (hostname) => Object.assign(new Error(`getaddrinfo ENOTFOUND ${hostname}`), { code: 'ENOTFOUND', hostname });

/** A pinned callback `lookup` over `base`. Each wrapper keeps its own base, so a wrapper installed over it cannot loop. */
function pinnedLookup(base) {
  return function lookup(hostname, options, callback) {
    if (typeof options === 'function') { callback = options; options = {}; }
    const list = pinnedFor(hostname, options);
    if (list === null) return base.call(dns, hostname, options, callback);
    if (list.length === 0) return process.nextTick(callback, notFound(hostname));
    if (options?.all) return process.nextTick(callback, null, list.map((a) => ({ ...a })));
    return process.nextTick(callback, null, list[0].address, list[0].family);
  };
}

/** A pinned `dns/promises` `lookup` over `base`. */
function pinnedPromisesLookup(base) {
  return async function lookup(hostname, options) {
    const list = pinnedFor(hostname, options);
    if (list === null) return base.call(dnsPromises, hostname, options);
    if (list.length === 0) throw notFound(hostname);
    return options?.all ? list.map((a) => ({ ...a })) : { address: list[0].address, family: list[0].family };
  };
}

/**
 * Install the pinned resolvers, or install them AGAIN over anything that replaced them since. Checked on every pinned run
 * by IDENTITY, never by a flag: an "already installed" flag would let a library, an agent or a test that reassigns
 * `dns.lookup` after the first scan turn the pin off for every later scan in a long-lived server, silently. Transparent
 * outside a pinned run.
 */
export function installScanPin() {
  const lookupOurs = ours !== null && dns.lookup === ours.lookup;
  const promisesOurs = ours !== null && dnsPromises.lookup === ours.promisesLookup;
  if (lookupOurs && promisesOurs) return;
  ours = {
    lookup: lookupOurs ? ours.lookup : pinnedLookup(dns.lookup),
    promisesLookup: promisesOurs ? ours.promisesLookup : pinnedPromisesLookup(dnsPromises.lookup),
  };
  dns.lookup = ours.lookup;
  dnsPromises.lookup = ours.promisesLookup;
  // An ESM named `import { lookup } from 'node:dns'` holds its own binding; this refreshes it (measured by the architect
  // seat on Node 24.12 — without it that import BYPASSES the pin).
  syncBuiltinESMExports();
}

/**
 * Run `fn` with `pins` ({ host: [{ address, family }, …] }, the check's whole answer set, order preserved) pinned for its
 * whole async lifetime. `pins` null or empty runs `fn` with whatever is pinned already (nothing, outside a scan). A run
 * NESTED in a scan — a redirect hop to another host — INHERITS the scan's pins and adds its own; a name pinned again takes
 * the inner answers, for the inner run only.
 */
export function runPinned(pins, fn) {
  const entries = Object.entries(pins ?? {}).filter(([, list]) => Array.isArray(list) && list.length > 0);
  if (entries.length === 0) return fn();
  installScanPin();
  const merged = new Map(store.getStore() ?? []);
  for (const [host, list] of entries) merged.set(keyOf(host), list.map((a) => ({ address: a.address, family: a.family })));
  return store.run(merged, fn);
}

/** The pinned answer set for `host` in the current scan, or null. */
export function pinnedAnswersFor(host) {
  return pinnedFor(host, undefined);
}

/**
 * The pinned address for `host` in the current scan, or null — what a subprocess plugin hands its command. `prefer: 4`
 * picks the first IPv4 answer when there is one: the system `ping`, `arp`, `nping`, `hping3` and `nmap` default to IPv4
 * (macOS `ping` refuses an IPv6 literal), so handing them an IPv6 answer would fail a probe the name used to pass.
 * @param {string} host
 * @param {{ prefer?: 4|6 }} [opts]
 */
export function pinnedAddressFor(host, { prefer } = {}) {
  const list = pinnedAnswersFor(host);
  if (!list || list.length === 0) return null;
  return (prefer && list.find((a) => a.family === prefer)?.address) || list[0].address;
}
