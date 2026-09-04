import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { escapeHtml, loadBrand } from '../utils/brand.mjs';

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'nsa-brand-'));

// ── Step 1: the fourth-quadrant leg first — a normal brand file loads unchanged ────────────

test('an ordinary brand file loads with its fields intact', async () => {
  const dir = tmp();
  const f = path.join(dir, 'brand.json');
  fs.writeFileSync(f, JSON.stringify({ title: 'Q3 Perimeter Review', companyName: 'Acme GmbH',
    preparedBy: 'J. Rivera', contact: 'security@example.test' }), 'utf8');
  const r = await loadBrand(f);
  assert.equal(r.ok, true);
  assert.equal(r.brand.title, 'Q3 Perimeter Review');
  assert.equal(r.brand.companyName, 'Acme GmbH');
  assert.equal(r.brand.preparedBy, 'J. Rivera');
  assert.equal(r.brand.contact, 'security@example.test');
  assert.equal(r.brand.logoDataUri, null);
});

test('no brand file at all yields the product default title', async () => {
  const r = await loadBrand(null);
  assert.equal(r.ok, true);
  assert.equal(r.brand.title, 'Network Scan Report');
  assert.equal(r.brand.companyName, '');
  assert.equal(r.brand.preparedBy, '');
  assert.equal(r.brand.contact, '');
  assert.equal(r.brand.logoDataUri, null);
});

test('the default title never contains "assessment" — a scan is not a human judgment', async () => {
  const r = await loadBrand(null);
  assert.equal(r.ok, true);
  assert.doesNotMatch(r.brand.title, /assessment/i);
});

// ── Step 3: the hostile legs ────────────────────────────────────────────────────────────────

test('escapeHtml renders markup literally', () => {
  assert.equal(escapeHtml('<script>alert(1)</script> & "Acme"'),
    '&lt;script&gt;alert(1)&lt;/script&gt; &amp; &quot;Acme&quot;');
});

test('escapeHtml also escapes a single quote, closing the attribute-break gap', () => {
  assert.equal(escapeHtml(`Acme'; onmouseover='alert(1)`),
    'Acme&#39;; onmouseover=&#39;alert(1)');
});

test('a company name containing markup renders literally', () => {
  assert.equal(escapeHtml('<script>alert(1)</script> & "Acme"'),
    '&lt;script&gt;alert(1)&lt;/script&gt; &amp; &quot;Acme&quot;');
});

test('loadBrand does NOT escape at load time — Task 6 escapes at render time', async () => {
  const dir = tmp();
  const f = path.join(dir, 'brand.json');
  fs.writeFileSync(f, JSON.stringify({ companyName: '<b>Acme</b> & Co' }), 'utf8');
  const r = await loadBrand(f);
  assert.equal(r.ok, true);
  assert.equal(r.brand.companyName, '<b>Acme</b> & Co');
});

test('an SVG logo is REFUSED, naming the reason', async () => {
  const dir = tmp();
  fs.writeFileSync(path.join(dir, 'logo.svg'), '<svg onload="fetch(1)"></svg>', 'utf8');
  fs.writeFileSync(path.join(dir, 'brand.json'), JSON.stringify({ logoPath: 'logo.svg' }), 'utf8');
  const r = await loadBrand(path.join(dir, 'brand.json'));
  assert.equal(r.ok, false);
  assert.match(r.message, /SVG/i);
});

test('an SVG logo disguised with a .png extension is still REFUSED — sniffed by bytes, not name', async () => {
  const dir = tmp();
  fs.writeFileSync(path.join(dir, 'logo.png'), '<svg onload="fetch(1)"></svg>', 'utf8');
  fs.writeFileSync(path.join(dir, 'brand.json'), JSON.stringify({ logoPath: 'logo.png' }), 'utf8');
  const r = await loadBrand(path.join(dir, 'brand.json'));
  assert.equal(r.ok, false);
});

test('MIME comes from MAGIC BYTES, not from the extension', async () => {
  const dir = tmp();
  const png = Buffer.from('89504e470d0a1a0a0000000d49484452', 'hex');
  fs.writeFileSync(path.join(dir, 'logo.jpg'), png);        // PNG bytes, .jpg name
  fs.writeFileSync(path.join(dir, 'brand.json'), JSON.stringify({ logoPath: 'logo.jpg' }), 'utf8');
  const r = await loadBrand(path.join(dir, 'brand.json'));
  assert.equal(r.ok, true);
  assert.match(r.brand.logoDataUri, /^data:image\/png;base64,/);
});

test('a JPEG logo with a misleading .png extension still loads as JPEG', async () => {
  const dir = tmp();
  const jpg = Buffer.from('ffd8ffe000104a4649460001', 'hex');
  fs.writeFileSync(path.join(dir, 'logo.png'), jpg);        // JPEG bytes, .png name
  fs.writeFileSync(path.join(dir, 'brand.json'), JSON.stringify({ logoPath: 'logo.png' }), 'utf8');
  const r = await loadBrand(path.join(dir, 'brand.json'));
  assert.equal(r.ok, true);
  assert.match(r.brand.logoDataUri, /^data:image\/jpeg;base64,/);
});

// These assert the message names the URL/network-path reason specifically (and is not the
// generic "could not read"/ENOENT fallback) — because a URL-shaped `logoPath` with no leading
// "/" is a RELATIVE path as far as the containment check is concerned, so it also passes
// containment and then fails to open (ENOENT) even with NO dedicated scheme detection at all. A
// bare `ok:false` + "logoPath" assertion cannot tell "we recognised the URL" apart from "we
// tried to open a file literally named `https:/tracker.example.test/logo.png` and it wasn't
// there" — measured by mutating the scheme check away entirely and watching these stay green
// regardless. Two dedicated checks share this discipline: SCHEME_RE (`http:`/`https:`/`data:`/
// `file:`/…) and NETWORK_PATH_RE (a leading "//" or "\\" — protocol-relative and Windows UNC).
// Each fires on the string alone, before any path resolution or filesystem call, so neither
// one's refusal depends on containment or on whether the path happens to resolve on the machine
// running the test.

test('a logo URL is REFUSED, naming the field — never fetched', async () => {
  const dir = tmp();
  fs.writeFileSync(path.join(dir, 'brand.json'),
    JSON.stringify({ logoPath: 'https://tracker.example.test/logo.png' }), 'utf8');
  const r = await loadBrand(path.join(dir, 'brand.json'));
  assert.equal(r.ok, false);
  assert.match(r.message, /logoPath/);
  assert.match(r.message, /URL/);
  assert.doesNotMatch(r.message, /ENOENT/);
});

test('a logo URL is never fetched — no network reaches it even if it resolves', async () => {
  // Regression guard for the refusal above: point at a scheme network code would try to open,
  // and confirm nothing throws an ECONNREFUSED/timeout — the refusal happens before any I/O.
  const dir = tmp();
  fs.writeFileSync(path.join(dir, 'brand.json'),
    JSON.stringify({ logoPath: 'http://127.0.0.1:1/logo.png' }), 'utf8');
  const r = await loadBrand(path.join(dir, 'brand.json'));
  assert.equal(r.ok, false);
  assert.match(r.message, /logoPath/);
  assert.match(r.message, /URL/);
  assert.doesNotMatch(r.message, /ENOENT/);
});

test('a protocol-relative logo URL is REFUSED too', async () => {
  const dir = tmp();
  fs.writeFileSync(path.join(dir, 'brand.json'),
    JSON.stringify({ logoPath: '//tracker.example.test/logo.png' }), 'utf8');
  const r = await loadBrand(path.join(dir, 'brand.json'));
  assert.equal(r.ok, false);
  assert.match(r.message, /logoPath/);
  assert.match(r.message, /URL/);
  assert.doesNotMatch(r.message, /ENOENT/);
});

test('a file:// logo URL is REFUSED, not treated as a local path', async () => {
  const dir = tmp();
  fs.writeFileSync(path.join(dir, 'brand.json'),
    JSON.stringify({ logoPath: 'file:///etc/passwd' }), 'utf8');
  const r = await loadBrand(path.join(dir, 'brand.json'));
  assert.equal(r.ok, false);
  assert.match(r.message, /logoPath/);
  assert.match(r.message, /URL/);
  assert.doesNotMatch(r.message, /ENOENT/);
});

// A leading "\\" is a Windows UNC network-share reference — opening it is a live SMB connection
// (and historically an NTLM-credential-leak vector) the instant the share exists and is
// reachable. On THIS machine such a path simply fails to resolve, so a containment check (or a
// bare ENOENT from fs.readFile) would ALSO refuse it — but that is a refusal for the wrong
// reason: a property that holds only because the path happened not to resolve is not a
// property, and it would stop holding the moment this ran on a host — or with a share mounted —
// where the path DOES resolve. The assertion below is deliberately the same shape as the four
// above and for the same reason: it must name the network/UNC reason specifically, or this test
// cannot tell "refused by its own dedicated, containment-independent check" apart from "refused
// by accident because this machine could not resolve it."
test('a UNC-style (\\\\host\\share) logoPath is REFUSED as a network path, independent of containment or ENOENT', async () => {
  const dir = tmp();
  fs.writeFileSync(path.join(dir, 'brand.json'),
    JSON.stringify({ logoPath: '\\\\attacker.example.com\\share\\logo.png' }), 'utf8');
  const r = await loadBrand(path.join(dir, 'brand.json'));
  assert.equal(r.ok, false);
  assert.match(r.message, /logoPath/);
  assert.match(r.message, /network|UNC/i);
  assert.doesNotMatch(r.message, /ENOENT/);
});

test('an oversized logo is REFUSED', async () => {
  const dir = tmp();
  const png = Buffer.concat([Buffer.from('89504e470d0a1a0a', 'hex'), Buffer.alloc(3 * 1024 * 1024)]);
  fs.writeFileSync(path.join(dir, 'logo.png'), png);
  fs.writeFileSync(path.join(dir, 'brand.json'), JSON.stringify({ logoPath: 'logo.png' }), 'utf8');
  const r = await loadBrand(path.join(dir, 'brand.json'));
  assert.equal(r.ok, false);
  assert.match(r.message, /too large|size/i);
});

// ── Adversarial pass beyond the brief's enumerated list ─────────────────────────────────────

test('a logoPath that escapes the brand directory via ../ is REFUSED', async () => {
  const dir = tmp();
  const outside = tmp();
  fs.writeFileSync(path.join(outside, 'secret.png'),
    Buffer.from('89504e470d0a1a0a0000000d49484452', 'hex'));
  const rel = path.relative(dir, path.join(outside, 'secret.png'));
  fs.writeFileSync(path.join(dir, 'brand.json'), JSON.stringify({ logoPath: rel }), 'utf8');
  const r = await loadBrand(path.join(dir, 'brand.json'));
  assert.equal(r.ok, false);
  assert.match(r.message, /logoPath/);
});

test('a logoPath that is an absolute filesystem path is REFUSED', async () => {
  const dir = tmp();
  const outside = tmp();
  fs.writeFileSync(path.join(outside, 'secret.png'),
    Buffer.from('89504e470d0a1a0a0000000d49484452', 'hex'));
  fs.writeFileSync(path.join(dir, 'brand.json'),
    JSON.stringify({ logoPath: path.join(outside, 'secret.png') }), 'utf8');
  const r = await loadBrand(path.join(dir, 'brand.json'));
  assert.equal(r.ok, false);
  assert.match(r.message, /logoPath/);
});

test('a non-object brand.json (an array) is REFUSED, not silently defaulted', async () => {
  const dir = tmp();
  const f = path.join(dir, 'brand.json');
  fs.writeFileSync(f, JSON.stringify(['not', 'an', 'object']), 'utf8');
  const r = await loadBrand(f);
  assert.equal(r.ok, false);
});

test('malformed JSON is REFUSED with a readable message', async () => {
  const dir = tmp();
  const f = path.join(dir, 'brand.json');
  fs.writeFileSync(f, '{ not valid json', 'utf8');
  const r = await loadBrand(f);
  assert.equal(r.ok, false);
  assert.equal(typeof r.message, 'string');
  assert.ok(r.message.length > 0);
});

test('a non-string field (e.g. title as a number) is coerced to a safe string, not thrown', async () => {
  const dir = tmp();
  const f = path.join(dir, 'brand.json');
  fs.writeFileSync(f, JSON.stringify({ title: 12345 }), 'utf8');
  const r = await loadBrand(f);
  assert.equal(r.ok, true);
  assert.equal(r.brand.title, '12345');
});

// Parameterized across all four safeString()-consuming metadata fields, not just companyName —
// they share one implementation, so one field's fixture protects the other three only by
// reading, not by a test. Cheap to close: same fixture, four names.
for (const field of ['title', 'companyName', 'preparedBy', 'contact']) {
  test(`a poison-toString object in "${field}" cannot be used to smuggle [object Object] semantics unexpectedly`, async () => {
    const dir = tmp();
    const f = path.join(dir, 'brand.json');
    fs.writeFileSync(f, JSON.stringify({ [field]: { toString: 'nope' } }), 'utf8');
    const r = await loadBrand(f);
    // Whatever the policy, it must not throw and must yield a string.
    assert.equal(r.ok, true);
    assert.equal(typeof r.brand[field], 'string');
  });
}

test('a missing brand file path is REFUSED with a readable message, not thrown', async () => {
  const dir = tmp();
  const r = await loadBrand(path.join(dir, 'does-not-exist.json'));
  assert.equal(r.ok, false);
  assert.equal(typeof r.message, 'string');
});

test('logoPath pointing at a directory (not a file) is REFUSED, not thrown', async () => {
  const dir = tmp();
  fs.mkdirSync(path.join(dir, 'a-directory.png'));
  fs.writeFileSync(path.join(dir, 'brand.json'),
    JSON.stringify({ logoPath: 'a-directory.png' }), 'utf8');
  const r = await loadBrand(path.join(dir, 'brand.json'));
  assert.equal(r.ok, false);
});

test('a data: URI logoPath is explicitly refused as a URL, not just coincidentally unreadable', async () => {
  // A `data:` URI has no "//" after its scheme, so it slips past a naive "scheme://" regex.
  // Assert on the URL-specific wording (not merely ok:false + "logoPath" in the message) —
  // otherwise this test cannot tell "we recognised and named the scheme" apart from "we tried
  // to open a file literally named `data:image/png;base64,...` and got ENOENT", which is a
  // no-op-shaped pass that a review found by mutating the scheme regex to require "://".
  const dir = tmp();
  fs.writeFileSync(path.join(dir, 'brand.json'),
    JSON.stringify({ logoPath: 'data:image/png;base64,iVBORw0KGgo=' }), 'utf8');
  const r = await loadBrand(path.join(dir, 'brand.json'));
  assert.equal(r.ok, false);
  assert.match(r.message, /URL/);
  assert.doesNotMatch(r.message, /ENOENT/);
});

test('escapeHtml handles null and undefined without throwing', () => {
  assert.equal(escapeHtml(null), '');
  assert.equal(escapeHtml(undefined), '');
});

// ── Round 3, coordinator review: logoPath type-checked before the filesystem ────────────────
//
// Driven measurement found a non-string logoPath refused by FS ERRNO, not by name — the exact
// "refused, but for the wrong reason" class the UNC fixture above closed one field over:
//   {toString:'nope'} -> "...EISDIR..." (poison toString collapsed to '', which then resolved
//                          to the brand directory itself)
//   ['a']             -> "...ENOENT..." (Array#toString -> 'a', no such file)
//   42                -> "...ENOENT..." (coerced to "42", no such file)
// Each of these five asserts the message names the TYPE problem specifically (or, for the empty
// string, that the deliberate "treat as absent" reading holds) — not merely `ok === false` —
// and that it does NOT read ENOENT/EISDIR, for the same reason the URL/UNC fixtures above
// needed the same tightening: a bare ok:false assertion cannot tell "refused by name" apart
// from "refused by an accident of how the coerced value happened to resolve."

test('a poison-toString OBJECT logoPath is refused BY NAME, not by EISDIR', async () => {
  const dir = tmp();
  fs.writeFileSync(path.join(dir, 'brand.json'),
    JSON.stringify({ logoPath: { toString: 'nope' } }), 'utf8');
  const r = await loadBrand(path.join(dir, 'brand.json'));
  assert.equal(r.ok, false);
  assert.match(r.message, /logoPath/);
  assert.match(r.message, /object/i);
  assert.doesNotMatch(r.message, /ENOENT|EISDIR/);
});

test('an ARRAY logoPath is refused BY NAME, not by ENOENT', async () => {
  const dir = tmp();
  fs.writeFileSync(path.join(dir, 'brand.json'),
    JSON.stringify({ logoPath: ['a'] }), 'utf8');
  const r = await loadBrand(path.join(dir, 'brand.json'));
  assert.equal(r.ok, false);
  assert.match(r.message, /logoPath/);
  assert.match(r.message, /array/i);
  assert.doesNotMatch(r.message, /ENOENT|EISDIR/);
});

test('a NUMBER logoPath is refused BY NAME, not by ENOENT', async () => {
  const dir = tmp();
  fs.writeFileSync(path.join(dir, 'brand.json'),
    JSON.stringify({ logoPath: 42 }), 'utf8');
  const r = await loadBrand(path.join(dir, 'brand.json'));
  assert.equal(r.ok, false);
  assert.match(r.message, /logoPath/);
  assert.match(r.message, /number/i);
  assert.doesNotMatch(r.message, /ENOENT|EISDIR/);
});

test('a BOOLEAN logoPath is refused BY NAME, not by ENOENT', async () => {
  const dir = tmp();
  fs.writeFileSync(path.join(dir, 'brand.json'),
    JSON.stringify({ logoPath: true }), 'utf8');
  const r = await loadBrand(path.join(dir, 'brand.json'));
  assert.equal(r.ok, false);
  assert.match(r.message, /logoPath/);
  assert.match(r.message, /boolean/i);
  assert.doesNotMatch(r.message, /ENOENT|EISDIR/);
});

test('an empty-string logoPath is treated as "no logo" — a deliberate, pinned reading', async () => {
  // The alternative (refuse an explicit "") is equally defensible; this reading was chosen for
  // consistency with how an absent/null logoPath is already handled. See the comment in
  // utils/brand.mjs directly above the `cfg.logoPath !== ''` check.
  const dir = tmp();
  fs.writeFileSync(path.join(dir, 'brand.json'), JSON.stringify({ logoPath: '' }), 'utf8');
  const r = await loadBrand(path.join(dir, 'brand.json'));
  assert.equal(r.ok, true);
  assert.equal(r.brand.logoDataUri, null);
});

// ── Round 3, coordinator review: containment must resolve symlinks ──────────────────────────

test('a symlink inside the brand directory pointing OUTSIDE it is REFUSED — containment resolves symlinks', async () => {
  const dir = tmp();
  const outside = tmp();
  const target = path.join(outside, 'secret.png');
  fs.writeFileSync(target, Buffer.from('89504e470d0a1a0a0000000d49484452', 'hex'));
  const link = path.join(dir, 'logo.png');
  fs.symlinkSync(target, link);
  fs.writeFileSync(path.join(dir, 'brand.json'), JSON.stringify({ logoPath: 'logo.png' }), 'utf8');
  const r = await loadBrand(path.join(dir, 'brand.json'));
  // The LEXICAL containment check alone would pass this (the symlink's own NAME, "logo.png",
  // never leaves `dir`); only resolving it proves the target does. Assert the specific
  // symlink-escape wording (not merely "logoPath" in the message, which nearly every refusal
  // this module emits contains, including the generic ENOENT/EISDIR fallback) and the absence
  // of an errno-flavored fallback — the same bar the type-shape fixtures above already set, and
  // this one had been missing: without it, a future regression that turned this into an
  // accidental errno refusal (still ok:false) would pass unnoticed.
  assert.equal(r.ok, false);
  assert.match(r.message, /logoPath/);
  assert.match(r.message, /resolves.*through a symlink.*outside/i);
  assert.doesNotMatch(r.message, /ENOENT|EISDIR/);
});

// ── Round 3, coordinator review: the size cap must be a STAT gate, not a read-then-check ────

test('an oversized logo is refused by STAT, before the file is read into memory', async (t) => {
  const dir = tmp();
  const png = Buffer.concat([Buffer.from('89504e470d0a1a0a', 'hex'), Buffer.alloc(3 * 1024 * 1024)]);
  fs.writeFileSync(path.join(dir, 'logo.png'), png);
  fs.writeFileSync(path.join(dir, 'brand.json'), JSON.stringify({ logoPath: 'logo.png' }), 'utf8');

  const realReadFile = fsp.readFile;
  let readFileCalledOnLogo = false;
  t.mock.method(fsp, 'readFile', async (...args) => {
    if (String(args[0]).endsWith('logo.png')) readFileCalledOnLogo = true;
    return realReadFile.apply(fsp, args);
  });

  const r = await loadBrand(path.join(dir, 'brand.json'));
  assert.equal(r.ok, false);
  assert.match(r.message, /too large|size/i);
  assert.equal(readFileCalledOnLogo, false,
    'the oversized logo must be refused by stat().size and never opened with fsp.readFile()');
});
