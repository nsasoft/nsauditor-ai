// Loads a consultant's `brand.json` for the client-facing HTML report (Task 6 renders it).
//
// Everything in that file is untrusted text: a title, a company name, a preparer, a contact,
// and an optional logo. The report it feeds has a hard invariant — no <script> element, no
// on* attribute, no external reference except an <a href> with an http/https/mailto scheme —
// and this module's whole job is making sure a brand file cannot defeat that from the inside.
//
// Escaping happens at RENDER time (Task 6), not here: this module stores the operator's text
// as given so it is never double-escaped.

import fsp from 'node:fs/promises';
import path from 'node:path';

const MAX_LOGO_BYTES = 2 * 1024 * 1024;
const PNG = Buffer.from('89504e470d0a1a0a', 'hex');
const JPEG = Buffer.from('ffd8ff', 'hex');

// A URI scheme prefix, e.g. "http:", "https:", "data:", "file:", "javascript:". Deliberately
// requires at least two letters before the colon so a Windows drive letter ("C:\...") does not
// collide with it — that case is instead caught by the directory-containment check below, with
// the correct message for what it actually is (a path, not a URL).
const SCHEME_RE = /^[a-zA-Z]{2,}[a-zA-Z0-9+.-]*:/;

// A leading pair of path-separator characters, in ANY combination of "/" and "\" — a
// protocol-relative URL ("//host/path") on every platform, and a UNC network-share reference
// ("\\host\share\path") on Windows. This check is deliberately INDEPENDENT of the directory-
// containment check and of the eventual fs.readFile: on a host where such a path happens not to
// resolve, containment (or a plain ENOENT) would refuse it too, but that is a refusal for the
// wrong reason — a security property that holds only because a path happened not to resolve is
// not a property. Opening a UNC path is a live SMB connection (and, historically, an
// NTLM-credential-leak vector) the instant the share exists and is reachable, which not every
// host in this product's install base can be assumed not to be. This check fires on the string
// alone, before any path resolution or filesystem call, on every platform.
const NETWORK_PATH_RE = /^[\\/]{2}/;

export function escapeHtml(s) {
  return String(s ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// String(v) throws when v is an object whose own `toString` shadows Object.prototype.toString
// with a non-callable value and whose `valueOf` does not yield a primitive either — and
// JSON.parse can produce exactly that shape, e.g. `{"companyName": {"toString": "nope"}}`.
// A brand file must never be able to crash the loader; coerce defensively. Used for the four
// free-text metadata fields only — `logoPath` is type-checked instead of coerced (below), so it
// never reaches this function at all when it isn't already a string.
function safeString(v) {
  if (v == null) return '';
  if (typeof v === 'string') return v;
  try { return String(v); } catch { return ''; }
}

function isPlainObject(v) {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

// Names what `logoPath` actually was, for a refusal message — never called on a string.
function describeLogoPathType(v) {
  if (Array.isArray(v)) return 'an array';
  if (typeof v === 'number') return 'a number';
  if (typeof v === 'boolean') return 'a boolean';
  return 'an object';
}

function sniff(buf) {
  if (buf.subarray(0, PNG.length).equals(PNG)) return 'image/png';
  if (buf.subarray(0, JPEG.length).equals(JPEG)) return 'image/jpeg';
  return null;
}

// A relative-path escape check, used twice below: once on the lexical (as-typed) path, and
// again on the realpath (symlinks resolved). `rel` is `path.relative(dir, file)`.
function escapesDir(rel) {
  return rel === '..' || rel.startsWith(`..${path.sep}`) || path.isAbsolute(rel);
}

export async function loadBrand(brandPath) {
  const brand = {
    title: 'Network Scan Report', companyName: '', preparedBy: '', contact: '', logoDataUri: null,
  };
  if (!brandPath) return { ok: true, brand };

  let raw;
  try { raw = await fsp.readFile(brandPath, 'utf8'); }
  catch (e) {
    return { ok: false, message: `Could not read the brand file at ${path.basename(brandPath)}: ${e?.message || e}` };
  }

  let cfg;
  try { cfg = JSON.parse(raw); }
  catch (e) {
    return { ok: false, message: `Could not parse the brand file at ${path.basename(brandPath)} as JSON: ${e?.message || e}` };
  }

  if (!isPlainObject(cfg)) {
    return { ok: false, message: `The brand file at ${path.basename(brandPath)} must be a JSON object, not ${Array.isArray(cfg) ? 'an array' : typeof cfg}.` };
  }

  for (const k of ['title', 'companyName', 'preparedBy', 'contact']) {
    if (cfg[k] != null) brand[k] = safeString(cfg[k]); // escaped at RENDER time, not here
  }

  if (cfg.logoPath != null) {
    // Type-checked BEFORE anything touches the filesystem or even converts the value: a
    // non-string logoPath (an object, an array, a number, a boolean) must be refused BY NAME,
    // not by whatever filesystem errno its coerced-to-string form happens to trip. Driven
    // measurement found three shapes refused for the wrong reason under the previous
    // safeString()-based coercion: `{toString:'nope'}` refused via a stray "EISDIR" (the poison
    // toString collapsed to '', which resolved to the brand directory itself), `['a']` and `42`
    // refused via a stray "ENOENT" (coerced to a filename that doesn't exist) — the exact
    // refused-by-accident class the UNC fix above closed one layer up, recurring here one field
    // over. A refusal that only holds because the coerced string happens not to resolve to a
    // real file is not a refusal by design.
    if (typeof cfg.logoPath !== 'string') {
      return {
        ok: false,
        message: `\`logoPath\` must be a string naming a local PNG or JPEG file; it is `
          + `${describeLogoPathType(cfg.logoPath)}, not a string.`,
      };
    }

    // An empty string is read the same as an absent field: "no logo provided." This is a
    // DELIBERATE reading (an operator's generated brand.json may emit "" rather than omitting
    // the key), not a side effect of a truthiness check — pinned by its own fixture
    // (`tests/brand.test.mjs`: "an empty-string logoPath ..."). If a future maintainer wants the
    // opposite reading (refuse an explicit empty string), that is a one-line change here, but it
    // must keep its own fixture too.
    if (cfg.logoPath !== '') {
      const rawLogo = cfg.logoPath;

      if (SCHEME_RE.test(rawLogo)) {
        return {
          ok: false,
          message: '`logoPath` names a URL, which is refused and never fetched. A remote logo is '
            + 'egress at render time and a tracking pixel every time the client opens the file. '
            + 'Point `logoPath` at a local PNG or JPEG next to the brand file.',
        };
      }
      if (NETWORK_PATH_RE.test(rawLogo)) {
        return {
          ok: false,
          message: '`logoPath` names a network path — a UNC share reference (\\\\host\\share\\..., '
            + 'read on Windows as a live SMB connection) or a protocol-relative URL (//host/...) — '
            + 'which is refused and never opened. A network logo is egress at load time, not just at '
            + 'render time. Point `logoPath` at a local PNG or JPEG next to the brand file.',
        };
      }
      if (/\.svgz?$/i.test(rawLogo)) {
        return {
          ok: false,
          message: '`logoPath` names an SVG, which is refused. SVG is markup and can carry a '
            + '<script> element or event attributes, which would let the brand file defeat the '
            + "report's no-script guarantee from inside. Use PNG or JPEG.",
        };
      }

      // Containment below is a WORKFLOW-SCOPING rule (keep a brand file's assets confined to
      // its own directory), not the product's egress defense — that is NETWORK_PATH_RE /
      // SCHEME_RE above, which fire on the string alone and do not depend on this check or on
      // how it resolves. If this containment boundary is ever relaxed (e.g. to support a logo
      // shared across sibling client directories), the NETWORK_PATH_RE / SCHEME_RE checks above
      // must not be relaxed with it.
      const dir = path.dirname(brandPath);
      const file = path.resolve(dir, rawLogo);
      const rel = path.relative(dir, file);
      if (escapesDir(rel)) {
        return {
          ok: false,
          message: `\`logoPath\` must resolve to a file inside ${dir} — the directory containing `
            + 'this brand file — and it does not. Keep the logo next to `brand.json` and reference '
            + 'it by a plain relative name.',
        };
      }

      // The lexical check above proves the requested NAME stays inside the directory; it does
      // not prove a symlink planted there doesn't point outside it (containment compares
      // strings, not the filesystem's actual graph). Re-check on the REALPATH of both sides —
      // resolving both `dir` and `file` keeps this correct even when the directory prefix
      // itself contains a symlink component (e.g. macOS's /var -> /private/var), since both
      // sides then resolve through the same prefix and stay comparable. Needs local write
      // access to the brand directory to exploit (planting the symlink), so it is a narrower
      // threat than the network/traversal checks above, but containment is a security boundary
      // and this is one extra pair of syscalls, not a redesign.
      let realDir;
      let realFile;
      try {
        realDir = await fsp.realpath(dir);
        realFile = await fsp.realpath(file);
      } catch (e) {
        return { ok: false, message: `Could not read the logo at \`logoPath\`: ${e?.message || e}` };
      }
      if (escapesDir(path.relative(realDir, realFile))) {
        return {
          ok: false,
          message: `\`logoPath\` resolves — through a symlink — to a file outside ${dir}, the `
            + 'directory containing this brand file. Keep the logo, and anything it symlinks to, '
            + 'inside that directory.',
        };
      }

      // The size cap is enforced by STAT, before any byte is read into memory — a file inside
      // the brand directory (or a symlink it targets) is not otherwise bounded, and reading an
      // arbitrarily large file fully into a Buffer before checking its length defeats the whole
      // point of having a cap. Keep the post-read length check below too, as a second gate
      // against a TOCTOU grow-after-stat, but the stat is what actually stops the large read.
      let stat;
      try { stat = await fsp.stat(realFile); }
      catch (e) {
        return { ok: false, message: `Could not read the logo at \`logoPath\`: ${e?.message || e}` };
      }
      if (!stat.isFile()) {
        return { ok: false, message: `\`logoPath\` at ${file} is not a regular file.` };
      }
      if (stat.size > MAX_LOGO_BYTES) {
        return {
          ok: false,
          message: `The logo at \`logoPath\` is ${stat.size} bytes, over the ${MAX_LOGO_BYTES}-byte `
            + 'limit — refused by its reported size before being read into memory. It is embedded '
            + 'in every copy of the report, so size is too large to accept.',
        };
      }

      let buf;
      try { buf = await fsp.readFile(realFile); }
      catch (e) {
        return { ok: false, message: `Could not read the logo at \`logoPath\`: ${e?.message || e}` };
      }
      if (buf.length > MAX_LOGO_BYTES) {
        return {
          ok: false,
          message: `The logo at \`logoPath\` is ${buf.length} bytes, over the ${MAX_LOGO_BYTES}-byte `
            + 'limit — it is embedded in every copy of the report, so size is too large to accept.',
        };
      }
      const mime = sniff(buf); // MAGIC BYTES: an extension is a claim, the bytes are the fact
      if (!mime) {
        return {
          ok: false,
          message: '`logoPath` is neither PNG nor JPEG by its own bytes (its extension is not '
            + 'trusted). Use a real PNG or JPEG file.',
        };
      }
      brand.logoDataUri = `data:${mime};base64,${buf.toString('base64')}`;
    }
  }

  return { ok: true, brand };
}
