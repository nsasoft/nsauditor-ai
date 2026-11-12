// tests/tls_scanner_env_seam_removed.test.mjs
// ─────────────────────────────────────────────────────────────────────────────
// No environment variable chooses the module tls_scanner imports (EE board B217).
//
// Until this change the plugin imported whatever module TLS_SCANNER_TLS_MODULE named unless NODE_ENV was `production`.
// A scan's --env file reaches process.env before the plugins load (the CLI applies it whole), so a credentials file
// could choose code to run, and the same file can set NODE_ENV=test — a NODE_ENV gate is satisfied by the file it guards
// against. Measured through the real CLI before the change: EE audit-evidence-samples/ee-2.2.0/node-floor-24.22.3/
// m2-b217-pre/cli-env-drive/RESULT.md. The plugin now imports node:tls statically; a test injects a stub through
// __setTlsModuleForTests, which takes a module OBJECT and refuses a specifier string.
//
// Fourth quadrant first: (b217-1) the marker, imported directly, records its import, so (b217-2) can see one; and
// (b217-3) the setter's ACCEPT leg runs before its refusals, so a setter that throws on everything cannot pass.
// ─────────────────────────────────────────────────────────────────────────────
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';
import { spawnSync } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';
import * as tlsStub from './_tls_stub.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const PLUGIN = pathToFileURL(path.join(ROOT, 'plugins', 'tls_scanner.mjs')).href;

function markerKit() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'b217-'));
  const log = path.join(dir, 'imported.log');
  const marker = path.join(dir, 'marker.mjs');
  fs.writeFileSync(marker, `import fs from 'node:fs';\nfs.appendFileSync(${JSON.stringify(log)}, 'imported\\n');\n`
    + `export function connect() { throw new Error('marker stub'); }\nexport default { connect };\n`);
  return { dir, log, url: pathToFileURL(marker).href };
}
const child = (script, env) => spawnSync(process.execPath, ['--input-type=module', '-e', script],
  { env: { ...process.env, ...env }, encoding: 'utf8', timeout: 30000 });
async function closedPort() {
  const s = net.createServer();
  await new Promise((r) => s.listen(0, '127.0.0.1', r));
  const { port } = s.address();
  await new Promise((r) => s.close(r));
  return port;
}
const rowFor = (raw, port) => raw.data.find((d) => d.probe_port === port);

test('(b217-1, first) positive control: a child that imports the marker by its URL writes the marker', () => {
  const k = markerKit();
  try {
    const r = child(`await import(${JSON.stringify(k.url)});`, {});
    assert.equal(r.status, 0, r.stderr);
    assert.equal(fs.existsSync(k.log), true, 'the marker did not record its import — the leg below could not see one');
  } finally { fs.rmSync(k.dir, { recursive: true, force: true }); }
});

test('(b217-2) a child that RUNS tls_scanner with TLS_SCANNER_TLS_MODULE=<marker> and NODE_ENV=test never imports the marker', async () => {
  const k = markerKit();
  try {
    const port = await closedPort();
    const script = `const { default: s } = await import(${JSON.stringify(PLUGIN)});`
      + `const raw = await s.run('127.0.0.1', ${port}, {});`
      + `console.log('ROW ' + JSON.stringify(raw.data.find((d) => d.probe_port === ${port}) ?? null));`;
    const r = child(script, {
      TLS_SCANNER_TLS_MODULE: k.url, NODE_ENV: 'test', TLS_SCANNER_PORTS: `${port}:https`,
      TLS_SCANNER_VERSIONS: 'TLSv1.2', TLS_SCANNER_TIMEOUT_MS: '2000', TLS_SCANNER_SNI: '127.0.0.1',
    });
    assert.equal(fs.existsSync(k.log), false, 'tls_scanner imported the module an environment variable named');
    assert.equal(r.status, 0, `the plugin run failed: ${r.stderr}`);
    const m = /^ROW (.*)$/m.exec(r.stdout);
    assert.ok(m, `the plugin run did not complete: ${r.stdout}`);
    const row = JSON.parse(m[1]);
    // Liveness: the run reached the TLS connect and the REAL node:tls dialled the closed port.
    assert.ok(row, 'the run produced no row for the probed port');
    assert.match(String(row.probe_info), /ECONNREFUSED/, `the probe did not dial the port with node:tls: ${row.probe_info}`);
  } finally { fs.rmSync(k.dir, { recursive: true, force: true }); }
});

test('(b217-3) the setter takes a module OBJECT and the plugin uses it; null restores node:tls; anything else is refused', async () => {
  const mod = await import(PLUGIN);
  assert.equal(typeof mod.__setTlsModuleForTests, 'function', 'the plugin exports no __setTlsModuleForTests');
  const { default: scanner, __setTlsModuleForTests } = mod;
  const port = await closedPort();
  Object.assign(process.env, { TLS_SCANNER_PORTS: `${port}:https`, TLS_SCANNER_VERSIONS: 'TLSv1.2,TLSv1.3',
    TLS_SCANNER_TIMEOUT_MS: '2000', TLS_SCANNER_SNI: '127.0.0.1' });
  try {
    // ACCEPT first: the stub answers TLSv1.2/1.3 on any port, so its answer on a CLOSED port proves it was used.
    __setTlsModuleForTests(tlsStub);
    assert.match(String(rowFor(await scanner.run('127.0.0.1'), port)?.probe_info), /TLS:\s*TLSv1\.2, TLSv1\.3/,
      'the plugin did not use the module object the setter was given');
    __setTlsModuleForTests(null);
    assert.match(String(rowFor(await scanner.run('127.0.0.1'), port)?.probe_info), /ECONNREFUSED/,
      'null did not restore node:tls');
    // REFUSALS, each with the stub installed first so a refused call that still installs its argument is visible.
    for (const bad of ['node:tls', 'file:///tmp/x.mjs', 42, true, {}, undefined, () => {}]) {
      __setTlsModuleForTests(tlsStub);
      assert.throws(() => __setTlsModuleForTests(bad), TypeError, `${String(bad)} was accepted`);
      assert.match(String(rowFor(await scanner.run('127.0.0.1'), port)?.probe_info), /TLS:\s*TLSv1\.2/,
        `a refused ${String(bad)} still replaced the installed module`);
    }
  } finally { __setTlsModuleForTests(null); }
});

test('(b217-4) census over the shipped files: only the plugin names the setter, and nothing names the old variable', () => {
  const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
  // The walk is the package's own `files` list (what a customer installs) plus the README; derived, never hand-listed.
  const roots = [...pkg.files, 'README.md'];
  const hits = { setter: [], variable: [] };
  let walked = 0;
  const visit = (rel) => {
    const abs = path.join(ROOT, rel);
    if (fs.statSync(abs).isDirectory()) {
      for (const e of fs.readdirSync(abs)) if (e !== '.DS_Store') visit(path.join(rel, e));
      return;
    }
    walked += 1;
    const src = fs.readFileSync(abs, 'utf8');
    if (src.includes('__setTlsModuleForTests')) hits.setter.push(path.normalize(rel));
    if (src.includes('TLS_SCANNER_TLS_MODULE')) hits.variable.push(path.normalize(rel));
  };
  for (const r of roots) visit(r.replace(/\/$/, ''));
  // Liveness: the plugin's own definition must be found, and the walk must have read the package.
  assert.ok(walked >= 50, `the census walked ${walked} files — the walk is broken`);
  assert.deepEqual(hits.setter, [path.join('plugins', 'tls_scanner.mjs')]);
  assert.deepEqual(hits.variable, []);
});
