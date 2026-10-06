// tests/history_line_written.test.mjs
// 1.2.1 (s1) B fold (audit seat) — the history line ON DISK carries the service-check channel, asserted on the ARTIFACT.
//
// THE DEFECT: scanSingleHost built its summary through historyServiceEntry / historyHostEntry, so the object in memory
// carried flagsBasis, hostFlags, hostChecks and each service's flags / checks — and recordScan then rebuilt the line it
// WROTE from a whitelist that dropped every one of them. Each [ScanHistory] line therefore compared against a baseline
// that looked pre-1.2.1 and printed "service checks not compared: the baseline predates 1.2.1 … the next scan compares
// them" on EVERY scan, forever; the second clause was false. The leg that guarded it read cli.mjs SOURCE for the builder
// calls and never opened the file: the builders were called, and the writer discarded their output.
//
// Driven through the real scanSingleHost (tests/helpers/watch_scan.mjs: the real PluginManager and concluder, the real
// SSH module with a weak algorithm so a flag exists, a scratch output root, a documentation-range target).
import { watchScan } from './helpers/watch_scan.mjs';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { HISTORY_FILE, getLastScan, computeDiff } from '../utils/scan_history.mjs';

const { scan } = await watchScan();
const historyLines = () => fs.readFileSync(path.join(process.env.SCAN_OUT_PATH, HISTORY_FILE), 'utf8').trim().split('\n').map((l) => JSON.parse(l));

async function printed(fn) {
  const lines = [];
  const real = console.log;
  console.log = (...a) => { lines.push(a.join(' ')); };
  try { await fn(); } finally { console.log = real; }
  return lines.filter((l) => l.startsWith('[ScanHistory]'));
}

test('the line WRITTEN to scan_history.jsonl carries the summary\'s service-check channel — read back from the file', async () => {
  const h = '203.0.113.90';
  const out = await scan(h, { ssh: '8.0', weakSsh: true, dns: true });
  const s = out.scanSummary;
  assert.ok(s?.flagsBasis && s.services?.[0]?.flags?.length, 'positive control: the summary in memory carries the channel and a flag');
  assert.deepEqual(s.hostFlags, ['dnsSecurity:missing_spf'], 'positive control: a host-level check is in the summary');
  assert.ok(Object.keys(s.hostChecks).length > 0, 'positive control: and its host-level measured state');
  const line = historyLines().filter((l) => l.host === h).at(-1);
  assert.ok(line, 'the scan wrote a history line for the host');
  assert.equal(line.flagsBasis, s.flagsBasis);
  assert.deepEqual(line.hostFlags, s.hostFlags);
  assert.deepEqual(line.hostChecks, s.hostChecks);
  assert.deepEqual(line.services.map((x) => [x.port, x.flags, x.checks]), s.services.map((x) => [x.port, x.flags, x.checks]));
});

test('the NEXT scan of the host compares its service checks against the line on disk — never "the baseline predates 1.2.1"', async () => {
  const h = '203.0.113.91';
  await scan(h, { ssh: '8.0', weakSsh: true });
  let second;
  const lines = await printed(async () => { second = await scan(h, { ssh: '8.0', weakSsh: true }); });
  assert.equal(lines.length, 1, `one [ScanHistory] line: ${lines}`);
  assert.doesNotMatch(lines[0], /baseline predates/);
  assert.match(lines[0], new RegExp(`\\[ScanHistory\\] ${h.replace(/\./g, '\\.')}: No changes detected since last scan\\.`));
  const first = historyLines().filter((l) => l.host === h).at(-2);
  assert.equal(computeDiff(second.scanSummary, first).flagsNotComparable, false, 'the first scan\'s line on disk is comparable');
  assert.equal((await getLastScan(process.env.SCAN_OUT_PATH, h)).flagsBasis, second.scanSummary.flagsBasis, 'and getLastScan returns the stamp');
});
