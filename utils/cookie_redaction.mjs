// utils/cookie_redaction.mjs
// A scanned service's Set-Cookie VALUE is that service's secret (a session token); its NAME fingerprints a framework
// (PHPSESSID, JSESSIONID). A Location header's query string can carry an SSO ticket or an OAuth code the same way.
// 1.3.0 (the audit seat's ruling (A), at BOTH seams): the HTTP probe redacts them when it builds its banner, and the AI
// redactor redacts any Set-Cookie value it meets, so the AI path holds even where a producer does not.

export const REDACTED = '<redacted>';

// One Set-Cookie header value may carry several cookies joined with ", " (fetch merges them) — split only where the next
// chunk starts a new `name=`, so a ", " inside an Expires date is not a boundary.
const COOKIES = /,\s*(?=[^=;,\s]+=)/;
// In free text a Set-Cookie line ends at CR, LF, or a literal backslash-r / backslash-n (the webapp detector joins its
// banner lines with those two-character sequences).
const SET_COOKIE_LINE = /(set-cookie:[ \t]*)((?:(?!\r|\n|\\r|\\n).)*)/gi;

/** One Set-Cookie header value: every cookie's VALUE redacted; its name and attributes (Path, HttpOnly, Expires) kept. */
export function redactSetCookie(value) {
  return String(value).split(COOKIES).map((c) => c.replace(/^(\s*[^=;\s]+)=[^;]*/, `$1=${REDACTED}`)).join(', ');
}

/** A Location header without its query string and fragment — the query can carry a credential. */
export function redactLocation(value) {
  const v = String(value);
  const i = v.search(/[?#]/);
  if (i < 0) return v;
  return v[i] === '?' ? `${v.slice(0, i)}?${REDACTED}` : v.slice(0, i);
}

/** Free text (a banner, an evidence row): every `set-cookie:` line's cookie values redacted. */
export function redactSetCookieLines(text) {
  return String(text).replace(SET_COOKIE_LINE, (_, head, value) => head + redactSetCookie(value));
}

/** Every UNREDACTED `name=value` a Set-Cookie line carries anywhere in a structure — the census helper. */
export function setCookieValues(x) {
  const found = [];
  const visit = (v) => {
    if (typeof v === 'string') {
      for (const m of v.matchAll(SET_COOKIE_LINE)) {
        for (const c of m[2].split(COOKIES)) {
          const kv = /^\s*([^=;\s]+)=([^;]*)/.exec(c);
          if (kv && kv[2].trim() !== REDACTED) found.push(`${kv[1]}=${kv[2].trim()}`);
        }
      }
    } else if (Array.isArray(v)) v.forEach(visit);
    else if (v && typeof v === 'object') Object.values(v).forEach(visit);
  };
  visit(x);
  return found;
}
