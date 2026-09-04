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
// A brand file must never be able to crash the loader; coerce defensively.
function safeString(v) {
  if (v == null) return '';
  if (typeof v === 'string') return v;
  try { return String(v); } catch { return ''; }
}

function isPlainObject(v) {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

function sniff(buf) {
  if (buf.subarray(0, PNG.length).equals(PNG)) return 'image/png';
  if (buf.subarray(0, JPEG.length).equals(JPEG)) return 'image/jpeg';
  return null;
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

  if (cfg.logoPath) {
    const rawLogo = safeString(cfg.logoPath);

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

    // Containment below is a WORKFLOW-SCOPING rule (keep a brand file's assets confined to its
    // own directory), not the product's egress defense — that is NETWORK_PATH_RE above, which
    // fires on the string alone and does not depend on this check or on how it resolves. If this
    // containment boundary is ever relaxed (e.g. to support a logo shared across sibling client
    // directories), the NETWORK_PATH_RE / SCHEME_RE checks above must not be relaxed with it.
    const dir = path.dirname(brandPath);
    const file = path.resolve(dir, rawLogo);
    const rel = path.relative(dir, file);
    if (rel === '..' || rel.startsWith(`..${path.sep}`) || path.isAbsolute(rel)) {
      return {
        ok: false,
        message: `\`logoPath\` must resolve to a file inside ${dir} — the directory containing `
          + 'this brand file — and it does not. Keep the logo next to `brand.json` and reference '
          + 'it by a plain relative name.',
      };
    }

    let buf;
    try { buf = await fsp.readFile(file); }
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

  return { ok: true, brand };
}
