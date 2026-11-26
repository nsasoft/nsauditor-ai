// tests/run_record_requested_ids_writer.test.mjs
// ─────────────────────────────────────────────────────────────────────────────
// THE WRITER NEVER RECORDS A REQUESTED PLUGIN WITHOUT A MANIFEST ENTRY (G-71, EE Z-1; architect RULINGS-v397 §4 (2)).
//
// The cross-run delta reads a requested plugin with NO entry in a host's manifest as having run (utils/scan_delta.mjs, the
// absence-read-as-ran rule). That reader is not changed here. What keeps it from ever deciding is the WRITER: every id the
// real CLI records in `pluginsRequested` has an entry in the host's manifest — a plugin its requirements gate out is
// recorded `skipped`, an Enterprise plugin with Enterprise present and unlicensed is recorded `skipped` — and an id the CLI
// cannot load (unknown, or an Enterprise id with Enterprise absent) is REFUSED: exit 2, and no run record is written.
// Measured first on the real CLI (Z/g71-measure-v342, F5). If a leg here goes red, a shipped writer now produces
// "requested, manifest recorded, no entry", and the delta's fail-open rule has an occupant (RULINGS-v397 Q4).
//
// DRIVEN: the real `cli.mjs scan` in a child process against 127.0.0.1, dotenv, AI and licence state neutralised.
// FOURTH QUADRANT FIRST: a run whose every requested plugin loads writes its record and an entry for each id — or the two
// refusal legs could pass on a CLI that writes nothing at all.
// ─────────────────────────────────────────────────────────────────────────────
import './helpers/no_operator_dotenv.mjs';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import cp from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { withNoDotenv } from './helpers/no_operator_dotenv.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const EE_ABSENT = path.join(ROOT, 'tests', 'helpers', 'ee_absent_preload.mjs');

function scan(plugins, { preload = null } = {}) {
  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-requested-ids-'));
  const out = path.join(work, 'out');
  const env = { ...process.env, AI_ENABLED: 'false', NSA_ALLOW_ALL_HOSTS: '1', NSAUDITOR_LICENSE_KEY: 'not-a-licence',
    NSAUDITOR_LICENSE_STATE_FILE: path.join(work, 'license-state.json') };
  for (const k of Object.keys(env)) if (/^(TRIBE_API_|SCAN_OUT_PATH|OPENAI_OUT_PATH)/.test(k)) delete env[k];
  const r = cp.spawnSync(process.execPath, [...(preload ? ['--import', preload] : []), path.join(ROOT, 'cli.mjs'),
    'scan', '--host', '127.0.0.1', '--plugins', plugins, '--out', out], { cwd: work, env: withNoDotenv(env), encoding: 'utf8', timeout: 240000 });
  const runs = fs.existsSync(out) ? fs.readdirSync(out).filter((f) => /^scan_run_.*\.json$/.test(f)) : [];
  return { code: r.status, text: `${r.stdout}${r.stderr}`, out, runs };
}
function manifestOf(out, runFile) {
  const run = JSON.parse(fs.readFileSync(path.join(out, runFile), 'utf8'));
  const dir = (run.hostsWritten ?? []).map((h) => h.dir ?? h).find(Boolean);
  assert.ok(dir, `the run record names the host it wrote: ${JSON.stringify(run.hostsWritten)}`);
  const raw = JSON.parse(fs.readFileSync(path.join(out, dir, 'scan_conclusion_raw.json'), 'utf8'));
  return { requested: run.pluginsRequested, manifest: raw.pluginStatus };
}
const eeResolves = (() => { try { createRequire(import.meta.url).resolve('@nsasoft/nsauditor-ai-ee/package.json'); return true; } catch { return false; } })();

test('(w-1, accept first) every requested id loads: exit 0, one run record, and a manifest entry for EVERY requested id — 050 included when its own requirements gate it out', () => {
  const r = scan('005,003,050', { preload: EE_ABSENT });
  assert.equal(r.code, 0, r.text.slice(-600));
  assert.equal(r.runs.length, 1, 'one run record');
  const { requested, manifest } = manifestOf(r.out, r.runs[0]);
  assert.deepEqual(requested, ['005', '003', '050']);
  for (const id of requested) assert.ok(manifest.some((m) => String(m.id) === id), `${id} has a manifest entry: ${JSON.stringify(manifest)}`);
  // 050 requires tcp 8080 open: closed here it is gated out and recorded `skipped` with that reason; open (a developer
  // machine running something on 8080) it runs. Either way it is an ENTRY, which is what the delta reads.
  const e050 = manifest.find((m) => String(m.id) === '050');
  assert.ok(['skipped', 'ran', 'error'].includes(e050.status), JSON.stringify(e050));
  if (e050.status === 'skipped') assert.match(String(e050.reason), /tcp ports not open: 8080/);
});
test('(w-2) Enterprise present and unlicensed: the Enterprise id is requested AND recorded skipped with its missing capability', (t) => {
  if (!eeResolves) { t.skip('@nsasoft/nsauditor-ai-ee is not resolvable from this tree — w-3 holds the absent case'); return; }
  const r = scan('005,003,050,1023');
  assert.equal(r.code, 0, r.text.slice(-600));
  assert.equal(r.runs.length, 1, 'one run record');
  const { requested, manifest } = manifestOf(r.out, r.runs[0]);
  assert.deepEqual(requested, ['005', '003', '050', '1023']);
  for (const id of requested) assert.ok(manifest.some((m) => String(m.id) === id), `${id} has a manifest entry: ${JSON.stringify(manifest)}`);
  const e = manifest.find((m) => String(m.id) === '1023');
  assert.equal(e.status, 'skipped', JSON.stringify(e));
  assert.match(String(e.reason), /missing capabilities/);
});
test('(w-3) an Enterprise id with Enterprise ABSENT is refused: exit 2, the id named, no run record written', () => {
  const r = scan('005,003,050,1023', { preload: EE_ABSENT });
  assert.equal(r.code, 2, r.text.slice(-600));
  assert.match(r.text, /no plugin matches "1023"/);
  assert.equal(r.runs.length, 0, 'no run record');
});
test('(w-4) an unknown id is refused: exit 2, the id named, no run record written', () => {
  const r = scan('005,003,050,999', { preload: EE_ABSENT });
  assert.equal(r.code, 2, r.text.slice(-600));
  assert.match(r.text, /no plugin matches "999"/);
  assert.equal(r.runs.length, 0, 'no run record');
});
