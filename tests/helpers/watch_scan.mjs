// tests/helpers/watch_scan.mjs
// REAL scanSingleHost outputs for the --watch legs (1.2.1 lane 4, items 4 + 11): Community's PluginManager with stub
// plugins that carry the real SSH and FTP modules (their adapters included), the real concluder, and the real
// scanSingleHost writing into a scratch output root. The target is a documentation-range literal (no DNS), Enterprise is
// held out through the loader's resolver hook, and the dotenv neutraliser runs before cli.mjs is imported.
import './no_operator_dotenv.mjs';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const absent = () => { throw Object.assign(new Error('not installed'), { code: 'MODULE_NOT_FOUND' }); };
const sshResult = (v, weak) => ({ up: true, program: 'OpenSSH', version: v,
  ...(weak ? { algorithms: { kex: ['diffie-hellman-group1-sha1'] }, weakAlgorithms: ['diffie-hellman-group1-sha1'] } : {}),
  data: [{ probe_protocol: 'tcp', probe_port: 22, probe_info: `SSH-2.0-OpenSSH_${v}`, response_banner: `SSH-2.0-OpenSSH_${v}` }] });
const ftpResult = (anonymousLogin) => ({ up: true, program: 'vsftpd', version: '3.0.3', anonymousLogin,
  data: [{ probe_protocol: 'tcp', probe_port: 21, probe_info: '220 vsFTPd', response_banner: '220 (vsFTPd 3.0.3)' }] });

let harness = null;
/** `{ scan(host, { ssh = '8.0', ftp = null, weakSsh = false }) }` — FTP is present when `ftp` is given (true = anonymous
 *  login allowed, a Critical finding); `weakSsh` adds a weak SSH algorithm (a Medium finding). */
export async function watchScan() {
  if (harness) return harness;
  process.env.NSAUDITOR_LICENSE_KEY = 'not-a-licence';
  delete process.env.OPENAI_OUT_PATH;
  process.env.SCAN_OUT_PATH = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-watch-scan-'));
  const { scanSingleHost } = await import('../../cli.mjs');
  const { default: PluginManager } = await import('../../plugin_manager.mjs');
  const { default: concluder } = await import('../../plugins/result_concluder.mjs');
  const sshMod = await import('../../plugins/ssh_scanner.mjs');
  const ftpMod = await import('../../plugins/ftp_banner_check.mjs');
  const stub = (mod, result) => ({ ...mod.default, conclude: mod.conclude, requirements: {}, runStrategy: 'single', run: async () => result });
  harness = {
    async scan(host, { ssh = '8.0', ftp = null, weakSsh = false } = {}) {
      const plugins = [stub(sshMod, sshResult(ssh, weakSsh)), ...(ftp === null ? [] : [stub(ftpMod, ftpResult(ftp))]), concluder];
      const pm = await PluginManager.create({ plugins });
      return scanSingleHost(pm, host, 'all', { resolveEE: absent }, 'basic');
    },
  };
  return harness;
}
