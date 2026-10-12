// A CHILD-PROCESS CASE for tests/tls_cert_trust_check_real_tls.test.mjs: starts a real TLS server on an ephemeral loopback
// port with the given key and certificate (chain), runs the REAL TLS Certificate & Cipher Auditor (040) against it, concludes
// it through the REAL concluder, and prints what 040 decided about the chain's trust — the checks, the ca_not_trusted detail,
// the second look (`trustCheck`) on the port result and on the concluded certAudit, and how many TLS sessions the server saw.
// A child so the test can set NODE_EXTRA_CA_CERTS at process START (the CA store is fixed then). Loopback only.
// With a PIN NAME, the audit runs inside utils/scan_pin.mjs's runPinned with that name pinned to 127.0.0.1 — a name no
// resolver answers, so every connect that reaches the server reached it through the pin.
// A `.mjs` under tests/helpers/, never `*.test.mjs`: the suite glob does not run it.
// usage: node tls_trust_check_case.mjs <key.pem> <cert.pem> [<040 opts JSON>] [<pin name>]
import fs from 'node:fs';
import tls from 'node:tls';

const [keyPath, certPath, optsJson, pinName] = process.argv.slice(2);
const { default: auditor } = await import('../../plugins/040_tls_cert_auditor.mjs');
const { default: concluder } = await import('../../plugins/result_concluder.mjs');
const { runPinned } = await import('../../utils/scan_pin.mjs');

// Security level 0 on the SERVER only, so it can load a 1024-bit key or a SHA-1-signed certificate; the client side is 040's.
const server = tls.createServer({ key: fs.readFileSync(keyPath), cert: fs.readFileSync(certPath), ciphers: 'DEFAULT:@SECLEVEL=0' },
  (s) => { try { s.end(); } catch { /* ignore */ } });
let sessions = 0;
server.on('secureConnection', () => { sessions += 1; });
server.on('tlsClientError', () => {});
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const port = server.address().port;
try {
  const opts = { timeoutMs: 4000, ...(optsJson ? JSON.parse(optsJson) : {}) };
  const target = pinName || '127.0.0.1';
  const audit = () => auditor.run(target, port, opts);
  const result = pinName ? await runPinned({ [pinName]: [{ address: '127.0.0.1', family: 4 }] }, audit) : await audit();
  const pr = result.portResults?.[0] ?? null;
  const issues = pr?.issues ?? [];
  const conclusion = await concluder.run({ results: [{ id: '040', name: 'TLS Certificate & Cipher Auditor', result }] });
  const certAudit = (conclusion?.services ?? []).find((s) => s.certAudit)?.certAudit ?? null;
  process.stdout.write('\n@@RESULT@@' + JSON.stringify({
    up: pr?.up ?? false,
    failed: (result.failedPorts ?? []).map((f) => f.error ?? f.reason ?? f),
    authError: pr?.authError ?? null,
    checks: issues.filter((i) => i.severity !== 'info' && i.severity !== 'pass').map((i) => `${i.severity}:${i.check}`),
    caTrust: issues.filter((i) => i.check === 'ca_not_trusted').map((i) => i.detail),
    trustCheck: pr?.trustCheck ?? null,
    certAuditTrustCheck: certAudit?.details?.trustCheck ?? null,
    sessions,
  }));
} finally {
  server.close();
}
