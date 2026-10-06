// A CHILD-PROCESS CASE for tests/tls_cert_ip_target_name_grading.test.mjs: starts a real TLS server on an ephemeral
// loopback port with the given key and certificate, runs the REAL TLS Certificate & Cipher Auditor (040) against the
// given target over that port, concludes it through the REAL concluder, and reports the hostname issue, the graded
// service-check findings and the `--fail-on` gate's rank — as JSON on stdout.
// It is a child so the test can set NODE_EXTRA_CA_CERTS to a throwaway CA at process START, which makes the chain
// trusted and leaves the certificate's NAME as the only thing under test. Loopback only; nothing leaves the machine.
// A `.mjs` under tests/helpers/, never `*.test.mjs`: the suite glob does not run it.
// usage: node tls_cert_case.mjs <key.pem> <cert.pem> <target host>
// FIRST: the CLI is imported below, and it must never read an operator's .env (tests/no_operator_dotenv_census.test.mjs).
import './no_operator_dotenv.mjs';
import fs from 'node:fs';
import tls from 'node:tls';

const [keyPath, certPath, target] = process.argv.slice(2);
const { default: auditor } = await import('../../plugins/040_tls_cert_auditor.mjs');
const { default: concluder } = await import('../../plugins/result_concluder.mjs');
const { conclusionFindings } = await import('../../utils/service_flags.mjs');
const { maxSeverityInConclusion } = await import('../../cli.mjs');

// TLS 1.2 with ECDHE suites only: 040 judges forward secrecy by the cipher NAME, and a TLS 1.3 suite name carries no
// ECDHE, so a TLS 1.3 server would add a no_forward_secrecy finding that is not under test here (recorded separately).
const server = tls.createServer({ key: fs.readFileSync(keyPath), cert: fs.readFileSync(certPath), minVersion: 'TLSv1.2',
  maxVersion: 'TLSv1.2', ciphers: 'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384', honorCipherOrder: true },
  (s) => { try { s.end(); } catch { /* ignore */ } });
server.on('tlsClientError', () => {});
// Listen on the target's own address when it is an IPv6 literal, else on 127.0.0.1 (a name like localhost reaches it).
await new Promise((r) => server.listen(0, target.includes(':') ? target : '127.0.0.1', r));
const port = server.address().port;
try {
  const result = await auditor.run(target, port, { timeoutMs: 4000 });
  const issues = (result.portResults ?? result.ports ?? []).flatMap((p) => p.issues ?? []);
  const conclusion = await concluder.run({ results: [{ id: '040', name: 'TLS Certificate & Cipher Auditor', result }] });
  const graded = conclusionFindings(conclusion, target).map((f) => ({ severity: f.severity, title: f.title }));
  // After a marker line: importing the CLI prints loader lines on stdout before this.
  process.stdout.write('\n@@RESULT@@' + JSON.stringify({
    port,
    hostname: issues.filter((i) => i.check === 'hostname_mismatch'),
    // Graded issues only: `info` and `pass` never reach a reader (service_flags drops them), and the TLS 1.2 pin adds
    // an info `not_tls13` by design.
    otherChecks: issues.filter((i) => i.check !== 'hostname_mismatch' && i.severity !== 'info' && i.severity !== 'pass')
      .map((i) => `${i.severity}:${i.check}`),
    graded,
    failOnRank: maxSeverityInConclusion(conclusion),
  }));
} finally {
  server.close();
}
