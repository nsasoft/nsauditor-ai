/**
 * tech_fingerprint.mjs — zero-dependency web-technology fingerprinter.
 * Replaces the abandoned `simple-wappalyzer` / deprecated `wappalyzer-core`.
 * Returns wappalyzer-shaped results: [{ name, categories, confidence, version }].
 */

// ---------------------------------------------------------------------------
// Signature table
// Each entry defines detection surfaces (OR semantics — any one match detects).
// Surfaces:
//   header    — [headerName, regex]        tested against that header's value
//   altHeader — [headerName, regex]        secondary header (also OR'd in)
//   meta      — [metaName, regex]          tested against <meta name=… content=…>
//   script    — [regex, …]                 tested against each <script src="…"> URL
//   cookie    — [regex, …]                 tested against Set-Cookie header value
// versionFrom — { surface, key?, regex }  → capture group 1 becomes version
// implies    — [name, …]                  → inject those techs at confidence 50
// ---------------------------------------------------------------------------
const SIGS = [
  {
    name: 'Nginx',
    categories: ['Web servers'],
    header: ['server', /nginx/i],
    versionFrom: { surface: 'header', key: 'server', regex: /nginx\/([\d.]+)/i },
  },
  {
    name: 'Apache',
    categories: ['Web servers'],
    header: ['server', /apache/i],
    versionFrom: { surface: 'header', key: 'server', regex: /apache\/([\d.]+)/i },
  },
  {
    name: 'IIS',
    categories: ['Web servers'],
    header: ['server', /(?:microsoft-)?iis/i],
  },
  {
    name: 'PHP',
    categories: ['Programming languages'],
    header: ['x-powered-by', /php/i],
    versionFrom: { surface: 'header', key: 'x-powered-by', regex: /php\/([\d.]+)/i },
  },
  {
    name: 'ASP.NET',
    categories: ['Web frameworks'],
    header: ['x-powered-by', /asp\.net/i],
    altHeader: ['x-aspnet-version', /.+/],
  },
  {
    name: 'Express',
    categories: ['Web frameworks'],
    header: ['x-powered-by', /express/i],
  },
  {
    name: 'WordPress',
    categories: ['CMS'],
    meta: ['generator', /wordpress/i],
    script: [/\/wp-(?:content|includes)\//i],
    versionFrom: { surface: 'meta', key: 'generator', regex: /wordpress\s+([\d.]+)/i },
    implies: ['PHP'],
  },
  {
    name: 'Drupal',
    categories: ['CMS'],
    meta: ['generator', /drupal/i],
    altHeader: ['x-generator', /drupal/i],
  },
  {
    name: 'Joomla',
    categories: ['CMS'],
    meta: ['generator', /joomla/i],
  },
  {
    name: 'jQuery',
    categories: ['JavaScript libraries'],
    script: [/jquery[.-]([\d.]+)(?:\.min)?\.js/i],
    versionFrom: { surface: 'script', regex: /jquery[.-]([\d]+(?:\.[\d]+)*)/i },
  },
  {
    name: 'React',
    categories: ['JavaScript frameworks'],
    script: [/\breact(?:\.production|\.development)?(?:\.min)?\.js/i],
  },
  {
    name: 'Vue.js',
    categories: ['JavaScript frameworks'],
    script: [/\bvue(?:@[\d.]+)?(?:\.global|\.runtime)?(?:\.min)?\.js/i],
  },
  {
    name: 'Cloudflare',
    categories: ['CDN'],
    header: ['server', /cloudflare/i],
    altHeader: ['cf-ray', /.+/],
  },
];

// Build a lookup map from name → sig for implies resolution.
const SIG_BY_NAME = new Map(SIGS.map(s => [s.name, s]));

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Normalise headers: lowercase keys, join array values. */
function normaliseHeaders(raw = {}) {
  const out = {};
  for (const [k, v] of Object.entries(raw)) {
    out[k.toLowerCase()] = Array.isArray(v) ? v.join('; ') : String(v);
  }
  return out;
}

/** Extract all <script src="…"> URLs from HTML (case-insensitive). */
function extractScriptSrcs(html) {
  const srcs = [];
  const re = /<script[^>]+\bsrc\s*=\s*["']([^"']+)["']/gi;
  let m;
  while ((m = re.exec(html)) !== null) srcs.push(m[1]);
  return srcs;
}

/** Extract <meta name="…" content="…"> into a lowercased-name → content map. */
function extractMetas(html) {
  const map = {};
  const re = /<meta[^>]+>/gi;
  let m;
  while ((m = re.exec(html)) !== null) {
    const tag = m[0];
    const nameM = /\bname\s*=\s*["']([^"']+)["']/i.exec(tag);
    const contM = /\bcontent\s*=\s*["']([^"']*)["']/i.exec(tag);
    if (nameM && contM) map[nameM[1].toLowerCase()] = contM[1];
  }
  return map;
}

// ---------------------------------------------------------------------------
// Core export
// ---------------------------------------------------------------------------

/**
 * Fingerprint a web response.
 * @param {{ url?, html?, statusCode?, headers? }} probe
 * @returns {{ name, categories, confidence, version }[]}
 */
export function fingerprint({ url, html = '', statusCode, headers = {} } = {}) {
  const hdrs  = normaliseHeaders(headers);
  const srcs  = extractScriptSrcs(html);
  const metas = extractMetas(html);
  const cookie = hdrs['set-cookie'] ?? '';

  /** Resolve version for a detected sig given the surfaces already parsed. */
  function resolveVersion(sig) {
    const vf = sig.versionFrom;
    if (!vf) return undefined;
    let haystack = '';
    if (vf.surface === 'header') {
      haystack = hdrs[vf.key ?? ''] ?? '';
    } else if (vf.surface === 'meta') {
      haystack = metas[vf.key ?? ''] ?? '';
    } else if (vf.surface === 'script') {
      // Test every src URL; return the first capture.
      for (const src of srcs) {
        const vm = vf.regex.exec(src);
        if (vm) return vm[1];
      }
      return undefined;
    }
    const vm = vf.regex.exec(haystack);
    return vm ? vm[1] : undefined;
  }

  /** Count how many distinct surfaces match for a sig. */
  function countSurfaces(sig) {
    let count = 0;

    // header
    if (sig.header) {
      const [hName, hRe] = sig.header;
      if (hdrs[hName] && hRe.test(hdrs[hName])) count++;
    }

    // altHeader — only counts if it's a different surface from header
    if (sig.altHeader) {
      const [hName, hRe] = sig.altHeader;
      if (hdrs[hName] && hRe.test(hdrs[hName])) count++;
    }

    // meta
    if (sig.meta) {
      const [mName, mRe] = sig.meta;
      const val = metas[mName.toLowerCase()];
      if (val && mRe.test(val)) count++;
    }

    // script — counts as 1 surface if any src URL matches any pattern
    if (sig.script) {
      const scriptHit = sig.script.some(re => srcs.some(src => re.test(src)));
      if (scriptHit) count++;
    }

    // cookie — counts as 1 surface if any pattern matches
    if (sig.cookie) {
      const cookieHit = sig.cookie.some(re => re.test(cookie));
      if (cookieHit) count++;
    }

    return count;
  }

  // --- Detect ---
  const detected = new Map(); // name → result object

  for (const sig of SIGS) {
    const surfaces = countSurfaces(sig);
    if (surfaces < 1) continue;

    const confidence = Math.min(100, 25 + 25 * surfaces);
    const version    = resolveVersion(sig);

    detected.set(sig.name, {
      name: sig.name,
      categories: sig.categories,
      confidence,
      version,
    });
  }

  // --- Resolve implies ---
  for (const sig of SIGS) {
    if (!sig.implies || !detected.has(sig.name)) continue;
    for (const impliedName of sig.implies) {
      if (detected.has(impliedName)) continue;
      const impliedSig = SIG_BY_NAME.get(impliedName);
      if (!impliedSig) continue;
      detected.set(impliedName, {
        name: impliedName,
        categories: impliedSig.categories,
        confidence: 50,
        version: undefined,
      });
    }
  }

  return Array.from(detected.values());
}

export default fingerprint;
