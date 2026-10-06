// tests/webapp_detector_ports_reach.test.mjs
// 1.2.1 lane 4, item 12 — how far an added --ports port reaches the webapp detector (010), DRIVEN on loopback.
//
// THE REACH (ruled): 010 runs only when TCP 80 or 443 is open; an added port is tried after https:443 and http:80 and
// only if neither answers — the detector stops at the first URL that answers. So both edges are pinned here, through the
// real PluginManager (its requirement gate included) and the real 010 module, with a REAL HTTP server on loopback standing
// for the added port: (i) when port 80 answers, the added port is never fetched — the limit, measured on the server's own
// connection count; (ii) when both defaults fail, the added port IS fetched, over the wire — the real-but-rare path.
//
// The defaults' answers are simulated in a fetch wrapper (binding 80 and 443 needs privileges, and whether they are free
// on a given machine is not this test's to decide); every other URL goes to the real fetch, on loopback only.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import PluginManager from '../plugin_manager.mjs';
import webapp from '../plugins/webapp_detector.mjs';

const HOST = '127.0.0.1';
const page = '<!doctype html><html><head><meta name="generator" content="WordPress 6.5.2"/></head><body>ok</body></html>';

async function loopbackSite() {
  const counts = { connections: 0, requests: 0 };
  const srv = http.createServer((req, res) => { counts.requests++; res.writeHead(200, { 'content-type': 'text/html' }); res.end(page); });
  srv.on('connection', () => { counts.connections++; });
  await new Promise((r) => srv.listen(0, HOST, r));
  return { counts, port: srv.address().port, close: () => new Promise((r) => srv.close(r)) };
}

/** Drive one scan: a port scanner reporting `open`, the real 010, --ports in the CLI's string form. */
async function drive({ open, ports, defaults }) {
  const realFetch = globalThis.fetch;
  const fetched = [];
  globalThis.fetch = async (url, init) => {
    fetched.push(String(url));
    const sim = defaults[String(url)];
    if (sim === 'answer') return new Response(page, { status: 200, headers: { 'content-type': 'text/html' } });
    if (sim === 'refuse') throw new Error('connect ECONNREFUSED (simulated default port)');
    return realFetch(url, init);
  };
  try {
    const scanner = { id: '003', name: 'Port Scanner', priority: 30, runStrategy: 'single', requirements: {},
      run: async () => ({ up: true, tcpOpen: open, data: [] }) };
    const pm = await PluginManager.create({ plugins: [scanner, webapp] });
    const out = await pm.run(HOST, 'all', { ports });
    const r = out.results.find((x) => String(x.id) === '010');
    return { fetched, manifest: out.manifest, result: r?.result ?? r };
  } finally { globalThis.fetch = realFetch; }
}

test('(i) THE LIMIT: when http:80 answers, an added --ports port is NEVER fetched — the site counts no connection', { timeout: 15000 }, async () => {
  const site = await loopbackSite();
  try {
    const d = await drive({ open: [80], ports: String(site.port),
      defaults: { [`https://${HOST}/`]: 'refuse', [`http://${HOST}/`]: 'answer' } });
    assert.ok(d.manifest.some((m) => m.id === '010' && m.status === 'ran'), 'positive control: the gate let 010 run');
    assert.deepEqual(d.fetched, [`https://${HOST}/`, `http://${HOST}/`]);
    assert.equal(site.counts.connections, 0, 'the added port was never touched');
    const live = await fetch(`http://${HOST}:${site.port}/`);
    assert.equal(live.status, 200, 'positive control: the site was there to be fetched');
  } finally { await site.close(); }
});

test('(ii) THE REACH: when both defaults fail, the added --ports port IS fetched over the wire and its app detected', { timeout: 15000 }, async () => {
  const site = await loopbackSite();
  try {
    const d = await drive({ open: [80], ports: `${site.port},9090/udp`,
      defaults: { [`https://${HOST}/`]: 'refuse', [`http://${HOST}/`]: 'refuse' } });
    assert.deepEqual(d.fetched.slice(0, 2), [`https://${HOST}/`, `http://${HOST}/`], 'the defaults first');
    assert.ok(d.fetched.includes(`http://${HOST}:${site.port}/`), `the added port was tried: ${d.fetched}`);
    assert.equal(d.fetched.some((u) => u.includes(':9090')), false, 'a /udp port adds no URL');
    assert.equal(site.counts.requests, 1, 'one HTTP request reached the site');
    assert.equal(d.result?.up, true);
    assert.equal(d.result.data.at(-1).probe_port, site.port);
    assert.ok(d.result.apps.some((a) => /WordPress/i.test(a.name)), JSON.stringify(d.result.apps));
  } finally { await site.close(); }
});
