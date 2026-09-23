// EVERY FILE IN THE PUBLISHED TARBALL IS READABLE BY THE USER WHO INSTALLS IT — board item 17 (CE 0.2.55).
//
// Every tarball published up to 0.2.55 shipped `config/services.json` mode 0600 (fixed in 4e100a2): after
// a root-owned global install, a non-root user running the scanner could not read the port floor, and
// the scanner's empty-floor path then reported a host with nothing listening (item 18 now refuses that).
// Nothing checked modes, so the defect shipped for every release. This guard reads the modes npm
// itself will pack — `npm pack --dry-run --json` — and requires other-read on every entry.
// ⚠️ FOURTH QUADRANT FIRST, and the negative control is DRIVEN: a sandbox copy of the package with one
// shipped file made 0600 must fail BY PATH, so a guard that reads nothing, or passes everything, is RED.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const OTHER_READ = 0o004;

/** The packed entries a non-owner cannot read. */
function unreadableEntries(files) {
  return files.filter((f) => (f.mode & OTHER_READ) === 0).map((f) => f.path).sort();
}
function packedFiles(dir) {
  const out = execFileSync('npm', ['pack', '--dry-run', '--json', '--ignore-scripts'], { cwd: dir, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] });
  const files = JSON.parse(out)[0]?.files;
  assert.ok(Array.isArray(files) && files.length > 0, 'npm reported no packed files — the guard would read nothing');
  return files;
}

// THE REAL TARBALL — modes live in the tar headers, and the dry-run listing is npm's account of them.
// Built with `npm pack` into a scratch directory and read back with `tar -tvzf`; a regular file's
// permission string is e.g. `-rw-r--r--`, whose 8th character is other-read.
function tarballEntries(dir) {
  const dest = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-tgz-'));
  try {
    const out = execFileSync('npm', ['pack', '--json', '--ignore-scripts', '--pack-destination', dest], { cwd: dir, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] });
    const tgz = path.join(dest, JSON.parse(out)[0].filename);
    const listing = execFileSync('tar', ['-tvzf', tgz], { encoding: 'utf8' });
    const entries = listing.split('\n').filter((l) => l.startsWith('-')).map((l) => {
      const perms = l.split(/\s+/)[0];
      const p = l.slice(l.lastIndexOf(' package/') + 1).replace(/^package\//, '');
      return { path: p, mode: (perms[7] === 'r' ? OTHER_READ : 0) | 0o600 };
    });
    assert.ok(entries.length > 0, 'the tarball listing held no files — the guard would read nothing');
    return entries;
  } finally { fs.rmSync(dest, { recursive: true, force: true }); }
}

test('FOURTH QUADRANT — the check passes readable modes and flags every unreadable one', () => {
  assert.deepEqual(unreadableEntries([
    { path: 'a.mjs', mode: 0o644 }, { path: 'bin/x.mjs', mode: 0o755 },
    { path: 'config/services.json', mode: 0o600 }, { path: 'b.json', mode: 0o640 },
  ]), ['b.json', 'config/services.json']);
});

test('every entry of the tarball npm would publish is readable by others', () => {
  const files = packedFiles(ROOT);
  assert.deepEqual(unreadableEntries(files), [], 'an entry a non-owner cannot read ships broken for every such user');
  assert.ok(files.some((f) => f.path === 'config/services.json'), 'the file that shipped 0600 is in the pack');
});

test('NEGATIVE CONTROL, DRIVEN — a sandbox copy with ONE shipped file at 0600 fails by that path', () => {
  const sandbox = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-packmodes-'));
  try {
    for (const f of packedFiles(ROOT)) {
      const dest = path.join(sandbox, f.path);
      fs.mkdirSync(path.dirname(dest), { recursive: true });
      fs.copyFileSync(path.join(ROOT, f.path), dest);
      fs.chmodSync(dest, f.mode & 0o777);
    }
    fs.chmodSync(path.join(sandbox, 'config', 'services.json'), 0o600);
    assert.deepEqual(unreadableEntries(packedFiles(sandbox)), ['config/services.json']);
  } finally { fs.rmSync(sandbox, { recursive: true, force: true }); }
});

test('THE BUILT TARBALL — every regular file in the tar npm writes is readable by others', () => {
  const entries = tarballEntries(ROOT);
  assert.deepEqual(unreadableEntries(entries), []);
  assert.equal(entries.length, packedFiles(ROOT).length, 'the tar and npm\'s own listing hold the same number of files');
});

test('NEGATIVE CONTROL, DRIVEN ON THE BUILT TARBALL — the 0600 file is unreadable in the tar itself', () => {
  const sandbox = fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-packmodes-tgz-'));
  try {
    for (const f of packedFiles(ROOT)) {
      const dest = path.join(sandbox, f.path);
      fs.mkdirSync(path.dirname(dest), { recursive: true });
      fs.copyFileSync(path.join(ROOT, f.path), dest);
      fs.chmodSync(dest, f.mode & 0o777);
    }
    fs.chmodSync(path.join(sandbox, 'config', 'services.json'), 0o600);
    assert.deepEqual(unreadableEntries(tarballEntries(sandbox)), ['config/services.json']);
  } finally { fs.rmSync(sandbox, { recursive: true, force: true }); }
});
