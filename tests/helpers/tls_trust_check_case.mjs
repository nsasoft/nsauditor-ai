// A CHILD-PROCESS CASE for tests/tls_cert_trust_check_real_tls.test.mjs: starts a real TLS server on an ephemeral loopback
// port with the given key and certificate (chain), runs the REAL TLS Certificate & Cipher Auditor (040) against it, concludes
// it through the REAL concluder, and prints what 040 decided about the chain's trust — the checks, the ca_not_trusted detail,
// the second look (`trustCheck`) on the port result and on the concluded certAudit, and what the server saw: TCP connections,
// sessions, and tlsClientErrors, each read after the server has closed AND every accepted connection has reported its outcome
// (bounded; `settled` says whether all did), plus the session count when the result was taken (B212: reported, never
// asserted — it once read 0 where 1 was expected).
// A child so the test can set NODE_EXTRA_CA_CERTS at process START (the CA store is fixed then). Loopback only.
// With a PIN NAME, the audit runs inside utils/scan_pin.mjs's runPinned with that name pinned to 127.0.0.1 — a name no
// resolver answers, so every connect that reaches the server reached it through the pin.
// A `.mjs` under tests/helpers/, never `*.test.mjs`: the suite glob does not run it.
// MODES (B212-C3), on the same server and the same counters, with NO audit and no concluder: `raw-connect` — one TCP connect
// destroyed before any ClientHello; `refused-hello` — one ClientHello the server refuses (tests/helpers/tls_case_clients.mjs).
// Each shows the tlsClientErrors term the legs add to sessions counting. A mode takes no 040 opts and no pin.
// usage: node tls_trust_check_case.mjs <key.pem> <cert.pem> [<040 opts JSON>] [<pin name>] [raw-connect|refused-hello]
import fs from 'node:fs';
import tls from 'node:tls';
import { rawConnectOnce, refusedHelloOnce } from './tls_case_clients.mjs';

const MODES = { 'raw-connect': rawConnectOnce, 'refused-hello': refusedHelloOnce };
const [keyPath, certPath, optsJson, pinName, mode] = process.argv.slice(2);
if (mode && !MODES[mode]) throw new Error(`unknown mode: ${mode}`);
if (mode && (optsJson || pinName)) throw new Error(`mode ${mode} takes no 040 opts and no pin`);
// The bound on waiting, after close, for every accepted connection to report its outcome (see `outcomes` below).
const SETTLE_MS = 3000;
const { default: auditor } = await import('../../plugins/040_tls_cert_auditor.mjs');
const { default: concluder } = await import('../../plugins/result_concluder.mjs');
const { runPinned } = await import('../../utils/scan_pin.mjs');

// Security level 0 on the SERVER only, so it can load a 1024-bit key or a SHA-1-signed certificate; the client side is 040's.
const server = tls.createServer({ key: fs.readFileSync(keyPath), cert: fs.readFileSync(certPath), ciphers: 'DEFAULT:@SECLEVEL=0' },
  (s) => { s.on('error', () => { socketErrors += 1; }); try { s.end(); } catch { /* ignore */ } });
// socketErrors: an error on an ESTABLISHED server socket (a reset after the handshake), counted rather than crashing the child.
let sessions = 0, connections = 0, tlsClientErrors = 0, socketErrors = 0, onOutcome = () => {};
server.on('connection', () => { connections += 1; });
server.on('secureConnection', () => { sessions += 1; onOutcome(); });
server.on('tlsClientError', () => { tlsClientErrors += 1; onOutcome(); });
// B212-C3, measured on v24.22.3: close() resolves once every connection has ENDED, but a connection that ends before its
// handshake reports its tlsClientError (ECONNRESET) after that — 100 of 100 runs read 0 at close, 0 after a setImmediate, 1 by
// 50 ms. So after close, wait (bounded) until every accepted connection has reported a session or a tlsClientError.
// Resolves true when they have, false at the bound: a connection that never reports leaves the sum short, never hidden.
const outcomes = (ms) => new Promise((resolve) => {
  const t = setTimeout(() => resolve(false), ms);
  onOutcome = () => { if (sessions + tlsClientErrors >= connections) { clearTimeout(t); resolve(true); } };
  onOutcome();
});
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const port = server.address().port;
let out, settled = null;
try {
  if (mode) {
    out = { mode, client: await MODES[mode](server, port), sessionsAtWrite: sessions };
  } else {
    const opts = { timeoutMs: 4000, ...(optsJson ? JSON.parse(optsJson) : {}) };
    const target = pinName || '127.0.0.1';
    const audit = () => auditor.run(target, port, opts);
    const result = pinName ? await runPinned({ [pinName]: [{ address: '127.0.0.1', family: 4 }] }, audit) : await audit();
    const pr = result.portResults?.[0] ?? null;
    const issues = pr?.issues ?? [];
    const conclusion = await concluder.run({ results: [{ id: '040', name: 'TLS Certificate & Cipher Auditor', result }] });
    const certAudit = (conclusion?.services ?? []).find((s) => s.certAudit)?.certAudit ?? null;
    out = {
      up: pr?.up ?? false,
      failed: (result.failedPorts ?? []).map((f) => f.error ?? f.reason ?? f),
      authError: pr?.authError ?? null,
      checks: issues.filter((i) => i.severity !== 'info' && i.severity !== 'pass').map((i) => `${i.severity}:${i.check}`),
      caTrust: issues.filter((i) => i.check === 'ca_not_trusted').map((i) => i.detail),
      trustCheck: pr?.trustCheck ?? null,
      certAuditTrustCheck: certAudit?.details?.trustCheck ?? null,
      sessionsAtWrite: sessions,
    };
  }
  // The snapshot first, so a child that dies or times out waiting in close() still leaves its verdict and counters.
  process.stdout.write('\n@@ATWRITE@@' + JSON.stringify({ ...out, connectionsAtWrite: connections, tlsClientErrorsAtWrite: tlsClientErrors }));
} finally {
  await new Promise((r) => server.close(r));
  settled = await outcomes(SETTLE_MS);
}
// `sessionsAfterClose` keeps its name: read after close, and after the outcomes wait above.
process.stdout.write('\n@@RESULT@@' + JSON.stringify({ ...out, connections, sessionsAfterClose: sessions, tlsClientErrors, socketErrors, settled }));
