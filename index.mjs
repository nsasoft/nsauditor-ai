// index.mjs — shim (CLI-first)
// This file exists only for programmatic imports. Prefer the CLI: `node cli.mjs ...`
import { fileURLToPath } from 'node:url';
import path from 'node:path';

export { default as PluginManager } from './plugin_manager.mjs';
export { buildHtmlReport } from './utils/report_html.mjs';

// If run directly, forward to CLI with a helpful message.
const isDirect = (fileURLToPath(import.meta.url) === path.resolve(process.argv[1] || ''));
if (isDirect) {
  console.error('[nsauditor] index.mjs is not a runtime entrypoint. Use the CLI instead:');
  console.error('  node cli.mjs scan --host 192.168.1.1 --plugins all');
  process.exit(1);
}
