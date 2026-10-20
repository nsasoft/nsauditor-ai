// tests/mcp_probe_service_ports.test.mjs
// ─────────────────────────────────────────────────────────────────────────────
// `probe_service` SAYS WHICH PORTS IT PROBED — A PLUGIN WITH ITS OWN PORT SET DOES NOT USE THE ONE ASKED FOR.
//
// The tool is described as running a plugin "against a host:port combination", but the TLS scanner (011) probes its own
// port set (443, 465, 563, 993, 995, or TLS_SCANNER_PORTS) whatever `port` says — measured: 8443 asked for, those five
// probed. The description now says so, and the response carries `probe` — the requested port, the ports the plugin's own
// rows show it probed, whether the requested one was among them, and a note when it was not — so a client asking for
// 8443 can see what came back. (Making 011 honour `port` would change the plugin's contract on the scan path too; boarded.)
//
// DRIVEN: the REAL plugins through the REAL manager's `_runOne`, against 127.0.0.1 (admitted through the validator seam)
// — every connect is to loopback.
//
// FOURTH QUADRANT FIRST: a plugin that probes the port it is given reports exactly that port, and no note.
// ─────────────────────────────────────────────────────────────────────────────
import './helpers/no_operator_dotenv.mjs';
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import PluginManager from '../plugin_manager.mjs';
import tls from '../plugins/tls_scanner.mjs';
import ssh from '../plugins/ssh_scanner.mjs';
import { handleProbeService, TOOLS, _setPluginManager, _setValidateHost } from '../mcp_server.mjs';

const saved = { TLS_SCANNER_TIMEOUT_MS: process.env.TLS_SCANNER_TIMEOUT_MS, TLS_SCANNER_PORTS: process.env.TLS_SCANNER_PORTS };
before(async () => {
  process.env.TLS_SCANNER_TIMEOUT_MS = '500';
  delete process.env.TLS_SCANNER_PORTS;
  _setPluginManager(await PluginManager.create({ plugins: [tls, ssh] }));
  _setValidateHost(async (h) => ({ name: h, answers: null }));
});
after(() => {
  _setPluginManager(null); _setValidateHost(null);
  for (const [k, v] of Object.entries(saved)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
});

test('(first) a plugin that probes the port it is given reports that port as probed — and no note', async () => {
  const out = await handleProbeService({ host: '127.0.0.1', port: 8022, pluginName: ssh.id });
  assert.deepEqual(out.probe, { requestedPort: 8022, probedPorts: [8022], requestedPortProbed: true });
});

test('the TLS scanner asked for 8443 names the five ports it probed, and says 8443 was not one of them', async () => {
  const out = await handleProbeService({ host: '127.0.0.1', port: 8443, pluginName: tls.id });
  assert.deepEqual(out.probe.probedPorts, [443, 465, 563, 993, 995]);
  assert.equal(out.probe.requestedPortProbed, false);
  assert.match(out.probe.note, /probes its own port set — port 8443 was not probed/);
});

test('the description says a plugin with its own port set does not use `port`, and that the response names what it probed', () => {
  const d = TOOLS.find((t) => t.name === 'probe_service').description;
  assert.match(d, /TLS scanner \(011\) probes 443, 465, 563, 993 and 995/);
  assert.match(d, /`probe` names the ports actually probed/);
});
