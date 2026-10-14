// tests/scan_pin_curl_proxy.test.mjs
// ─────────────────────────────────────────────────────────────────────────────
// THE FIRMWARE PROBE'S curl, PINNED, CONNECTS WHERE THE CHECK RESOLVED — WHATEVER PROXY OR curl CONFIG THE ENVIRONMENT
// CARRIES. curl is a child process: it reads http_proxy / ALL_PROXY from the environment and a .curlrc (proxy, connect-to)
// from its config directory, none of which the scan's pin governs. The pin's stated limits name ONE proxy switch,
// NODE_USE_ENV_PROXY, which governs Node's own clients; so, pinned, curl must take no proxy and no config file at all.
//
// Driven with the REAL curl behind a recording wrapper on PATH (the wrapper runs the real binary, passes its output
// through and logs its exit code and argv). The pinned name is an RFC 6761 `.test` name pinned to 127.0.0.1, whose port
// 80 refuses: curl exit 7 means it went to the pinned address; exit 6 would mean it resolved the name live; a hit on the
// recording proxy or the redirect receiver means it went somewhere else.
//
// FOURTH QUADRANT FIRST: the apparatus legs show each proxy source DOES move an UNPINNED curl — so a zero below is a
// measurement, not a receiver that cannot see.
// ─────────────────────────────────────────────────────────────────────────────
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import net from 'node:net';
import path from 'node:path';
import http from 'node:http';
import { spawn } from 'node:child_process';
import { runPinned } from '../utils/scan_pin.mjs';
import { probeFirmware } from '../plugins/http_probe.mjs';

const NAME = 'firmware.pin.test';
const PIN = { [NAME]: [{ address: '127.0.0.1', family: 4 }] };
const VENDOR = 'NETGEAR R7000';
const PROXY_VARS = ['http_proxy', 'HTTP_PROXY', 'https_proxy', 'HTTPS_PROXY', 'all_proxy', 'ALL_PROXY', 'no_proxy', 'NO_PROXY', 'NODE_USE_ENV_PROXY', 'CURL_HOME'];
const REAL_CURL = ['/usr/bin/curl', '/usr/local/bin/curl', '/opt/homebrew/bin/curl'].find((p) => fs.existsSync(p));

let dir; let home; let log; let proxy; let receiver; let PURL; let RPORT; const saved = {};
const hits = { proxy: [], receiver: [] };

before(async () => {
  assert.ok(REAL_CURL, 'no real curl on this machine — these legs cannot measure, and a skipped leg is not a pass');
  // The pinned address must refuse on 80, or exit 7 below would not mean "went to the pinned address and was refused".
  const refused = await new Promise((resolve) => {
    const s = net.connect(80, '127.0.0.1'); s.on('connect', () => { s.destroy(); resolve(false); }); s.on('error', (e) => resolve(e.code === 'ECONNREFUSED'));
  });
  assert.ok(refused, '127.0.0.1:80 accepts connections on this machine — the pinned-address legs cannot read curl exit 7 as "pinned"');
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pin-curl-'));
  home = path.join(dir, 'curlhome'); fs.mkdirSync(home);
  log = path.join(dir, 'curl.log');
  fs.writeFileSync(path.join(dir, 'curl'), `#!/bin/sh\n"$REAL_CURL" "$@"\nec=$?\nprintf '%s\\t%s\\n' "$ec" "$*" >> "$CURL_LOG"\nexit $ec\n`, { mode: 0o755 });
  const rec = (bucket) => http.createServer((req, res) => { hits[bucket].push(`${req.method} ${req.url} Host:${req.headers.host}`); res.end('Firmware=V9.9.9_7\n'); });   // the probe's own regex keeps digits, dots and underscores: 9.9.9_7
  proxy = rec('proxy'); receiver = rec('receiver');
  await new Promise((r) => proxy.listen(0, '127.0.0.1', r)); await new Promise((r) => receiver.listen(0, '127.0.0.1', r));
  PURL = `http://127.0.0.1:${proxy.address().port}`; RPORT = receiver.address().port;
  for (const k of ['PATH', 'REAL_CURL', 'CURL_LOG', ...PROXY_VARS]) saved[k] = process.env[k];
  process.env.PATH = `${dir}${path.delimiter}${process.env.PATH}`;
  process.env.REAL_CURL = REAL_CURL; process.env.CURL_LOG = log;
});
after(async () => {
  for (const [k, v] of Object.entries(saved)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
  await new Promise((r) => proxy.close(r)); await new Promise((r) => receiver.close(r));
  fs.rmSync(dir, { recursive: true, force: true });
});

/** One probe under `env` (proxy variables cleared first; CURL_HOME always the empty test home) and an optional .curlrc. */
async function probe({ pinned, env = {}, curlrc = null }) {
  for (const k of PROXY_VARS) delete process.env[k];
  Object.assign(process.env, { CURL_HOME: home }, env);
  fs.rmSync(path.join(home, '.curlrc'), { force: true });
  if (curlrc) fs.writeFileSync(path.join(home, '.curlrc'), curlrc);
  fs.writeFileSync(log, ''); hits.proxy.length = 0; hits.receiver.length = 0;
  const value = pinned ? await runPinned(PIN, () => probeFirmware(NAME, VENDOR)) : await probeFirmware(NAME, VENDOR);
  const calls = fs.readFileSync(log, 'utf8').trim().split('\n').filter(Boolean).map((l) => { const [ec, argv] = l.split('\t'); return { ec: Number(ec), argv }; });
  for (const k of PROXY_VARS) delete process.env[k];
  return { value, calls, proxy: [...hits.proxy], receiver: [...hits.receiver] };
}
const connectTo = () => `connect-to = "${NAME}:80:127.0.0.1:${RPORT}"\n`;
const pinnedAtTheAddress = (r, why) => {
  assert.equal(r.calls.length, 1, `${why}: expected one curl call, got ${JSON.stringify(r.calls)}`);
  assert.deepEqual(r.proxy, [], `${why}: the recording proxy was reached — the pinned name left the pin: ${JSON.stringify(r.proxy)}`);
  assert.deepEqual(r.receiver, [], `${why}: a .curlrc connect-to moved the connection: ${JSON.stringify(r.receiver)}`);
  assert.equal(r.calls[0].ec, 7, `${why}: curl exit ${r.calls[0].ec} (7 = refused at the pinned 127.0.0.1:80; 6 = resolved live): ${r.calls[0].argv}`);
  assert.equal(r.value, null, `${why}: the probe read an answer it could only have had from somewhere other than the pinned address`);
};

// ── the apparatus: each source DOES move an UNPINNED curl (so the zeros below are measurements) ─────────────────────
test('(cp0, first) UNPINNED, each proxy source moves the real curl — http_proxy, ALL_PROXY, a .curlrc proxy, a .curlrc connect-to', async () => {
  for (const [label, opts, bucket] of [
    ['http_proxy', { env: { http_proxy: 'PURL' } }, 'proxy'],
    ['ALL_PROXY', { env: { ALL_PROXY: 'PURL' } }, 'proxy'],
    ['.curlrc proxy', { curlrc: 'PROXYRC' }, 'proxy'],
    ['.curlrc connect-to', { curlrc: 'CONNECTTO' }, 'receiver'],
  ]) {
    const env = Object.fromEntries(Object.entries(opts.env ?? {}).map(([k, v]) => [k, v === 'PURL' ? PURL : v]));
    const curlrc = opts.curlrc === 'PROXYRC' ? `proxy = "${PURL}"\n` : opts.curlrc === 'CONNECTTO' ? connectTo() : null;
    const r = await probe({ pinned: false, env, curlrc });
    assert.equal(r[bucket].length, 1, `apparatus: unpinned with ${label}, the ${bucket} saw ${JSON.stringify(r[bucket])} (calls ${JSON.stringify(r.calls)})`);
    assert.equal(r.value, '9.9.9_7', `apparatus: unpinned with ${label}, the probe did not read the recording server`);
  }
});

test('(cp1) control: PINNED, no proxy source — the real curl goes to the pinned address (refused), nothing else is reached', async () => {
  pinnedAtTheAddress(await probe({ pinned: true }), 'no proxy source');
});

test('(cp2) PINNED with http_proxy set — the real curl does not hand the name to the proxy', async () => {
  pinnedAtTheAddress(await probe({ pinned: true, env: { http_proxy: PURL } }), 'http_proxy');
});

test('(cp3) PINNED with ALL_PROXY set — the real curl does not hand the name to the proxy', async () => {
  pinnedAtTheAddress(await probe({ pinned: true, env: { ALL_PROXY: PURL } }), 'ALL_PROXY');
});

test('(cp4) PINNED with a .curlrc proxy — the real curl reads no config file', async () => {
  pinnedAtTheAddress(await probe({ pinned: true, curlrc: `proxy = "${PURL}"\n` }), '.curlrc proxy');
});

test('(cp5) PINNED with a .curlrc connect-to — the real curl reads no config file, so --resolve is not overridden', async () => {
  pinnedAtTheAddress(await probe({ pinned: true, curlrc: connectTo() }), '.curlrc connect-to');
});

test('(cp6) the stated limit\'s own switch: under NODE_USE_ENV_PROXY=1 Node\'s http client IS proxied (the limit holds as stated) while the pinned curl is not', async () => {
  const env = { NODE_USE_ENV_PROXY: '1', http_proxy: PURL };
  pinnedAtTheAddress(await probe({ pinned: true, env }), 'NODE_USE_ENV_PROXY=1 + http_proxy');
  // Node's own client under the same environment, in a child (the switch is read at startup).
  hits.proxy.length = 0;
  const childEnv = { ...Object.fromEntries(Object.entries(process.env).filter(([k]) => !PROXY_VARS.includes(k))), ...env };
  const out = await new Promise((resolve) => {
    const p = spawn(process.execPath, ['-e', `const r=require('http').get('http://${NAME}/currentsetting.htm',(s)=>{let b='';s.on('data',d=>b+=d);s.on('end',()=>console.log('OK '+b.trim()))});r.setTimeout(5000,()=>{console.log('ERR timeout');r.destroy()});r.on('error',e=>console.log('ERR '+e.code))`], { env: childEnv });
    let o = ''; p.stdout.on('data', (d) => { o += d; }); p.on('close', () => resolve(o.trim()));
  });
  assert.equal(hits.proxy.length, 1, `under NODE_USE_ENV_PROXY=1 Node's http client should go through the proxy (the stated limit): ${out} · ${JSON.stringify(hits.proxy)}`);
});

test('(cp7) the argv: PINNED, -q is FIRST and --noproxy * is present beside --resolve and the ASCII name in both places; UNPINNED, none of them', async () => {
  const pinned = (await probe({ pinned: true })).calls[0].argv.split(' ');
  assert.equal(pinned[0], '-q', `-q must be curl's FIRST argument or curl ignores it: ${pinned.join(' ')}`);
  assert.equal(pinned[pinned.indexOf('--noproxy') + 1], '*', `no --noproxy * on the pinned call: ${pinned.join(' ')}`);
  assert.equal(pinned[pinned.indexOf('--resolve') + 1], `${NAME}:80:127.0.0.1`, pinned.join(' '));
  assert.equal(pinned.at(-1), `http://${NAME}/currentsetting.htm`, pinned.join(' '));
  const bare = (await probe({ pinned: false })).calls[0].argv.split(' ');
  for (const a of ['-q', '--noproxy', '--resolve']) assert.ok(!bare.includes(a), `unpinned, ${a} reached curl: ${bare.join(' ')}`);
});
