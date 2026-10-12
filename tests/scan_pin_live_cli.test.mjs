import './helpers/no_operator_dotenv.mjs';
import './helpers/no_operator_keychain.mjs';   // FIRST: the spawned CLI loads a licence
// tests/scan_pin_live_cli.test.mjs
// ─────────────────────────────────────────────────────────────────────────────
// THE PIN IN A REAL SCAN, BY NAME (EE 2.0.0, R1b). Every other pin leg drives a stand-in or a single function; EE's
// network-scan-path gate scans 127.0.0.1, a literal, which pins nothing. Here the REAL CLI scans the NAME `localhost`
// (NSA_ALLOW_ALL_HOSTS admits loopback on the CLI), so its plugins run inside the pin with the whole answer set the
// resolver gave — on this machine an IPv6 and an IPv4 loopback — and must still find a port open on the IPv4 one.
// That is decision 3 of the design: pin the WHOLE set, so a connect still has the pair it was given.
// ─────────────────────────────────────────────────────────────────────────────
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import dnsPromises from 'node:dns/promises';
import { withNoDotenv } from './helpers/no_operator_dotenv.mjs';

const CE = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');

/** A spawned child that inherits NODE_TEST_CONTEXT can exit 0 on failure. */
const withoutTestContext = (env) => { delete env.NODE_TEST_CONTEXT; return env; };

/** Every object in a parsed JSON tree. */
function* walk(v) {
  if (v && typeof v === 'object') { yield v; for (const x of Object.values(v)) yield* walk(x); }
}

test('a real CLI scan of the NAME localhost, pinned to the whole answer set, finds the port open on the IPv4 loopback', async () => {
  const answers = await dnsPromises.lookup('localhost', { all: true, verbatim: true });
  assert.ok(answers.some((a) => a.address === '127.0.0.1'), `this leg needs localhost to answer 127.0.0.1 here: ${JSON.stringify(answers)}`);
  const server = net.createServer((s) => s.destroy());
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const port = server.address().port;
  const out = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-pin-live-'));
  try {
    const child = spawn(process.execPath, [path.join(CE, 'cli.mjs'), 'scan', '--host', 'localhost', '--ports', String(port), '--plugins', '001,003', '--out', out],
      { env: withNoDotenv(withoutTestContext({ ...process.env, NSA_ALLOW_ALL_HOSTS: '1' })) });
    let stderr = '';
    child.stderr.on('data', (d) => { stderr += d; });
    const status = await new Promise((resolve) => { const t = setTimeout(() => child.kill(), 120000); child.on('close', (c) => { clearTimeout(t); resolve(c); }); });
    assert.equal(status, 0, `the scan failed: ${stderr.slice(0, 800)}`);
    const hostDir = fs.readdirSync(out).find((n) => n.startsWith('localhost_'));
    assert.ok(hostDir, `no per-host directory for the name: ${fs.readdirSync(out).join(', ')}`);
    const raw = JSON.parse(fs.readFileSync(path.join(out, hostDir, 'scan_conclusion_raw.json'), 'utf8'));
    const open = [...walk(raw)].filter((o) => Number(o.port) === port && /open/i.test(String(o.status ?? o.state ?? '')));
    assert.ok(open.length >= 1, `port ${port} is not recorded open — the pinned scan did not reach the listener: ${JSON.stringify(raw).slice(0, 600)}`);
  } finally {
    server.close();
    fs.rmSync(out, { recursive: true, force: true });
  }
});
