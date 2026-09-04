// tests/lockfile_root_identity.test.mjs
//
// THE LOCKFILE ROOT MUST AGREE WITH package.json — PORTED FROM EE, BECAUSE THE
// ASYMMETRY IS WHAT LET THIS SHIP.
//
// EE has carried this guard since its own root version went stale. CE never had
// one, and at the EE 0.44.0 / CE 0.2.51 staging that difference had a measured
// cost: EE's version bump was caught by EE's guard within the same session, while
// CE's identical bump left `package-lock.json` at 0.2.50 and NOTHING in this repo
// said so. It surfaced only when the air-gap carrier build refused to run —
// `scripts/build_airgap_package.mjs` compares the pair before vendoring, exits 2,
// and prints "package-lock.json root version 0.2.50 does not match package.json
// 0.2.51". That is a gate in the OTHER repo, run at one step of one battery,
// standing in for a unit test here.
//
// ⚠️ WHY IT MATTERS BEYOND TIDINESS: `npm ci` installs from the lock, and the lock
// root is what a consumer's resolver reads for this package's own identity. A
// published tarball whose lock root names the PREVIOUS version is a package that
// disagrees with itself about what it is.
//
// The comparison is exported so a build-side guard can import it rather than
// reimplement it — one predicate, two callers, no drift.

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const read = (f) => JSON.parse(fs.readFileSync(path.join(ROOT, f), 'utf8'));

/**
 * @returns {string[]} human-readable mismatches, empty when the roots agree.
 */
export function lockRootMismatches(pkgJson, lockJson) {
  const root = lockJson?.packages?.[''] ?? null;
  if (root === null) return ['package-lock.json has no `packages[""]` root entry'];
  const out = [];
  // ⚠️ KEY ORDER IS NOT A DIFFERENCE. A bare JSON.stringify comparison reports a
  // mismatch whose diff a reader cannot see, and a guard whose first finding is a
  // false positive is one that gets disabled. Key order carries no meaning to npm's
  // resolver, so it carries none here.
  const norm = (v) => {
    if (v === undefined || v === null) return null;
    if (typeof v !== 'object' || Array.isArray(v)) return v;
    return Object.fromEntries(Object.keys(v).sort().map((k) => [k, v[k]]));
  };
  const eq = (field) => {
    const a = norm(pkgJson?.[field]);
    const b = norm(root[field]);
    if (JSON.stringify(a) !== JSON.stringify(b)) {
      out.push(`${field}: package.json ${JSON.stringify(a)} vs lock root ${JSON.stringify(b)}`);
    }
  };
  for (const f of ['name', 'version', 'dependencies', 'optionalDependencies', 'peerDependencies']) {
    eq(f);
  }
  return out;
}

describe('the lockfile root agrees with package.json', () => {
  it("this repo's own pair agrees — the state a release must be in", () => {
    assert.deepEqual(lockRootMismatches(read('package.json'), read('package-lock.json')), []);
  });

  it('catches a stale root VERSION — the exact shape that shipped undetected here', () => {
    // CE 0.2.51's package.json beside a 0.2.50 lock root, which is what the airgap
    // build refused. This is the leg whose absence had a cost.
    const pkg = { name: 'nsauditor-ai', version: '0.2.51' };
    const lock = { packages: { '': { name: 'nsauditor-ai', version: '0.2.50' } } };
    const m = lockRootMismatches(pkg, lock);
    assert.equal(m.length, 1);
    assert.match(m[0], /^version: package.json "0\.2\.51" vs lock root "0\.2\.50"$/);
  });

  it('a matching pair with UNRELATED root fields differing still passes', () => {
    // Fourth quadrant: the comparison is scoped to the five fields `npm ci` needs or
    // ignores. A lock root legitimately carries keys package.json does not (`license`,
    // `hasInstallScript`); flagging those would make the guard noisy enough to disable.
    const pkg = { name: 'x', version: '1.0.0', dependencies: { a: '^1' } };
    const lock = { packages: { '': { name: 'x', version: '1.0.0', dependencies: { a: '^1' }, license: 'MIT', hasInstallScript: true } } };
    assert.deepEqual(lockRootMismatches(pkg, lock), []);
  });

  it('treats a REORDERED dependency map as agreement, not as drift', () => {
    const pkg = { name: 'x', version: '1.0.0', dependencies: { b: '^2', a: '^1' } };
    const lock = { packages: { '': { name: 'x', version: '1.0.0', dependencies: { a: '^1', b: '^2' } } } };
    assert.deepEqual(lockRootMismatches(pkg, lock), []);
  });

  it('a lock with no root entry is a finding, not a pass', () => {
    // Fail-closed: a malformed lock must not read as agreement.
    assert.deepEqual(lockRootMismatches({ name: 'x', version: '1' }, {}),
      ['package-lock.json has no `packages[""]` root entry']);
  });

  it('catches a drifted DEPENDENCY RANGE, not only the version', () => {
    const pkg = { name: 'x', version: '1.0.0', dependencies: { a: '^2' } };
    const lock = { packages: { '': { name: 'x', version: '1.0.0', dependencies: { a: '^1' } } } };
    assert.equal(lockRootMismatches(pkg, lock).length, 1);
  });
});
