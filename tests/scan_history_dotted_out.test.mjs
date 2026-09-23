// `scan_history.jsonl` FOLLOWS THE SCAN, EVEN WHEN --out HAS A DOT IN IT (board C3).
//
// ⚠️ THE DEFECT: `cli.mjs` located the history file with an inline
// `toCleanPath(...).replace(/\.[^/.]+$/, '')` — strip anything after the last dot — while every
// other writer resolves through `resolveBaseOutDir()`. `--out …/ee-1.1.0` therefore wrote the
// scan's artifacts into `ee-1.1.0/` and its HISTORY into a sibling `ee-1.1/`, silently created
// beside it. Both `ee-1.1/` and `ee-1.0/` exist as live strays in this project's own evidence
// tree, which is how it was found: by looking at the directory, not at the code.
//
// This is the SAME root cause as the EE 0.32.8 evidence-misplacement bug — "has a dot" read as
// "is a file" — surviving in one call site after `resolveBaseOutDir()` was fixed for the others.
// A repair applied to the resolver does not reach a caller that never used it: the version-named
// directory convention this project uses for its own evidence (`ee-1.1.0`, `v1.2.3`,
// `release-2026.07`) is exactly the shape that breaks.
//
// Driven through `main()` — the real entry point, with the real `--out` flag — because the whole
// class is a call site that bypassed the shared helper. A unit test of the helper passes either
// way and would have proven nothing.
import './helpers/no_operator_keychain.mjs';   // FIRST: keeps this file off the operator's real Keychain
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { main } from '../cli.mjs';

const HISTORY = 'scan_history.jsonl';

async function scanInto(outArg) {
  const savedArgv = process.argv;
  const saved = { SCAN_OUT_PATH: process.env.SCAN_OUT_PATH, OPENAI_OUT_PATH: process.env.OPENAI_OUT_PATH,
    NSA_ALLOW_ALL_HOSTS: process.env.NSA_ALLOW_ALL_HOSTS };
  try {
    process.argv = ['node', 'cli', 'scan', '--host', '127.0.0.1', '--plugins', '003',
      '--ports', '1-2', '--out', outArg];
    delete process.env.SCAN_OUT_PATH;
    delete process.env.OPENAI_OUT_PATH;
    process.env.NSA_ALLOW_ALL_HOSTS = '1';
    await main();
  } finally {
    process.argv = savedArgv;
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k]; else process.env[k] = v;
    }
  }
}

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-hist-'));
const has = (p) => fs.existsSync(p);

test('a DOTTED --out keeps its history INSIDE it, and creates no sibling', async () => {
  const root = tmp();
  const out = path.join(root, 'ee-1.1.0');
  await scanInto(out);

  assert.ok(has(path.join(out, HISTORY)),
    'the history belongs beside the artifacts it describes — `--out …/ee-1.1.0` is a DIRECTORY name, '
    + 'and `.0` is a version component, not a file extension');
  assert.ok(!has(path.join(root, 'ee-1.1')),
    'no sibling may be created. `ee-1.1/` is the inline regex stripping `.0`; it is a real stray in '
    + 'this project\'s own evidence tree, which is where this defect was found');
  // Nothing else may appear at the parent level either — a sibling under any name is the same bug.
  const strays = fs.readdirSync(root).filter((n) => n !== 'ee-1.1.0');
  assert.deepEqual(strays, [], `unexpected entries beside the out dir: ${strays.join(', ')}`);
});

test('a MULTI-DOT --out is the same case — the convention this project actually uses', async () => {
  const root = tmp();
  const out = path.join(root, 'release-2026.09.20');
  await scanInto(out);
  assert.ok(has(path.join(out, HISTORY)));
  assert.deepEqual(fs.readdirSync(root).filter((n) => n !== 'release-2026.09.20'), []);
});

test('an UNDOTTED --out is unchanged — the accept case, so the fix cannot be "always use the raw path"', async () => {
  const root = tmp();
  const out = path.join(root, 'plain-dir');
  await scanInto(out);
  assert.ok(has(path.join(out, HISTORY)));
  assert.deepEqual(fs.readdirSync(root).filter((n) => n !== 'plain-dir'), []);
});

test('a REAL file extension still resolves to the PARENT — the documented `--out report.json` affordance', async () => {
  // ⚠️ THE FOURTH QUADRANT, and the leg that stops the fix from being "never strip anything".
  // `resolveBaseOutDir` treats an extension starting with a LETTER as a file and uses its parent.
  // If this leg is ever deleted, a fix that simply passes the raw path through will look correct
  // on every other leg in this file.
  const root = tmp();
  await scanInto(path.join(root, 'report.json'));
  assert.ok(has(path.join(root, HISTORY)),
    '`--out …/report.json` names a FILE, so the history belongs in its directory');
  assert.ok(!has(path.join(root, 'report.json', HISTORY)));
});

test('a history left at the OLD location is NAMED, not silently abandoned', async () => {
  // ⚠️ WITHOUT THIS THE FIX IS A SILENT BEHAVIOUR CHANGE. A user whose earlier scans wrote
  // history into the stray sibling gets a correct-but-misleading result on the next run: no
  // prior scan is found at the new location, so the run reports as a first scan — a true
  // statement about the new path that reads as "nothing changed since last time". Name the file.
  const root = tmp();
  const out = path.join(root, 'ee-1.1.0');
  const legacy = path.join(root, 'ee-1.1');
  fs.mkdirSync(legacy, { recursive: true });
  fs.writeFileSync(path.join(legacy, HISTORY), '{"host":"127.0.0.1","findingsCount":0}\n', 'utf8');

  const warned = [];
  const saved = console.warn;
  console.warn = (...a) => { warned.push(a.join(' ')); };
  try { await scanInto(out); } finally { console.warn = saved; }

  const notice = warned.find((w) => w.includes('scan history now lives in'));
  assert.ok(notice, 'the move must be announced');
  // ⚠️ PREFIX-SAFE, AND THE FIRST DRAFT WAS NOT. `legacy` is `…/ee-1.1` and the new directory is
  // `…/ee-1.1.0`, so a bare `notice.includes(legacy)` is satisfied by the NEW path containing the
  // OLD one as a prefix — the assertion could not tell "names the stray" from "names the new
  // directory", and a mutant that deleted the stray's interpolation entirely stayed GREEN.
  // Anchored on the sentence that introduces it instead, with the trailing comma the template
  // writes, so only the abandoned path can satisfy it.
  assert.ok(notice.includes(`wrote it to ${legacy},`),
    'it must NAME the abandoned file in the clause that introduces it, not merely contain its '
    + 'characters somewhere — the new directory contains the old one as a prefix');
  assert.ok(fs.existsSync(path.join(legacy, HISTORY)), 'the old file is left on disk — nothing is deleted');
  assert.ok(fs.existsSync(path.join(out, HISTORY)), 'and the new history is written where it belongs');
});

test('NO notice when there is nothing left behind — it is about a FILE, not about having a dot', async () => {
  // Fourth quadrant. A notice that prints on every dotted --out teaches an operator to ignore it,
  // and would then be ignored on the one run where it mattered.
  const root = tmp();
  const warned = [];
  const saved = console.warn;
  console.warn = (...a) => { warned.push(a.join(' ')); };
  try { await scanInto(path.join(root, 'ee-2.0.0')); } finally { console.warn = saved; }
  assert.deepEqual(warned.filter((w) => w.includes('scan history now lives in')), []);
});
