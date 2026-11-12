// utils/plugin_output_scrub.mjs
// ─────────────────────────────────────────────────────────────────────────────
// Credentials removed from a plugin's return value and from its throw, where the plugin manager receives them
// (EE 2.2.0, I3 — the architect's ruling of 2026-11-11 on the dependency-closure measurement).
//
// The precondition for anything to be removed: a proxy variable carrying userinfo AND a customer-configured child process
// that prints it, run by a cloud SDK that carries the child's stderr into its Error — measured for
// @aws-sdk/credential-provider-process (credential_process); read from code for google-auth-library's pluggable-auth
// handler and @azure/identity's AzureCliCredential (`az` was not measured). A plugin writes a caught error's text into its
// result, and from the plugin manager that text reaches every artifact, so the scrub sits at the receipt and nowhere else.
//
// Strings go through Community's credentialRedactor (utils/webhook.mjs): the proxy userinfo, any URL's userinfo, and each
// proxy password wherever it appears — as written, decoded, re-encoded and JSON-escaped, each form when it is at least
// PROXY_SECRET_MIN_LENGTH characters. NOT covered: a Base64 Proxy-Authorization value, a token in the user-name position
// outside a URL, and any other encoding. Any URL's userinfo is replaced whether or not a proxy is set.
//
// Walked: strings, plain objects (keys and values), arrays, and an Error's message, stack, cause and own enumerable
// fields. NOT walked (stated limit): a string inside a Map, a Set, a typed array or Buffer, a Date, or any other class
// instance — those are passed by reference. NOT covered: what a plugin prints itself (console, stderr) and what it
// writes into the shared scan context; only its return value and its throw pass the receipt. A value with nothing to redact is returned BY REFERENCE; only a value that
// carries a credential is copied, and the plugin's own objects are never mutated.
// ─────────────────────────────────────────────────────────────────────────────
import { credentialRedactor } from './webhook.mjs';

const isPlain = (v) => {
  if (Array.isArray(v)) return true;
  const proto = Object.getPrototypeOf(v);
  return proto === Object.prototype || proto === null;
};
/**
 * An Error's own properties (message, stack, cause, code, …), enumerable or not, READ THROUGH the Error — on Node 24
 * `stack` is an own ACCESSOR whose getter reads the real Error's internal slot, so its descriptor cannot be copied.
 */
const errorEntries = (e) => Object.getOwnPropertyNames(e).flatMap((k) => {
  try { return [[k, e[k], Object.getOwnPropertyDescriptor(e, k).enumerable]]; } catch { return []; }   // a throwing getter is skipped
});

/**
 * @param {unknown} value
 * @param {{ env?: Record<string, string|undefined>, redact?: (s: string) => string }} [opts]
 * @returns {{ value: unknown, replaced: number }} replaced = the number of strings that changed
 */
const errName = (e) => { try { return String(e?.name || 'Error'); } catch { return 'Error'; } };
const WITHHELD = 'could not be checked for proxy credentials and was withheld';

/**
 * A value the walk cannot read (a throwing getter, nesting deeper than the stack) is WITHHELD: replaced by a named
 * failure envelope, never thrown into the plugin manager (where it would abort the batch) and never passed on unchecked.
 */
export function scrubPluginOutput(value, opts = {}) {
  try { return scrubOrThrow(value, opts); }
  catch (e) { return { value: { up: false, data: [], error: `the plugin's result ${WITHHELD} (${errName(e)})` }, replaced: 0, withheld: true }; }
}

function scrubOrThrow(value, { env = process.env, redact = credentialRedactor(env) } = {}) {
  // Pass 1: does anything need redacting? Answered without copying, so the common case keeps every reference.
  const seen = new Set();
  const needs = (v) => {
    if (typeof v === 'string') return redact(v) !== v;
    if (v === null || typeof v !== 'object' || seen.has(v)) return false;
    seen.add(v);
    if (v instanceof Error) return errorEntries(v).some(([, x]) => needs(x)) || needs(v.message);   // own properties, and an INHERITED message
    if (!isPlain(v)) return false;
    if (Array.isArray(v)) return v.some(needs);
    return Object.keys(v).some((k) => needs(k) || needs(v[k]));
  };
  if (!needs(value)) return { value, replaced: 0 };

  // Pass 2: copy what carries a credential. memo maps each original container to its copy (cycles, shared references).
  let replaced = 0;
  const memo = new Map();
  const str = (s) => { const r = redact(s); if (r !== s) replaced++; return r; };
  const walk = (v) => {
    if (typeof v === 'string') return str(v);
    if (v === null || typeof v !== 'object') return v;
    if (memo.has(v)) return memo.get(v);
    if (v instanceof Error) {
      // A REAL Error (it carries the internal error slot that Error.isError and util.inspect read) with the original's
      // prototype, so it keeps its class; every own property becomes a data property holding the scrubbed value.
      const out = new Error();   // NO argument: an own '' message would shadow a message the prototype carries
      Object.setPrototypeOf(out, Object.getPrototypeOf(v));
      memo.set(v, out);
      for (const [k, x, enumerable] of errorEntries(v)) {
        Object.defineProperty(out, k, { value: walk(x), writable: true, configurable: true, enumerable });
      }
      if (!Object.prototype.hasOwnProperty.call(v, 'message') && typeof v.message === 'string') {
        Object.defineProperty(out, 'message', { value: walk(v.message), writable: true, configurable: true, enumerable: false });
      }
      return out;
    }
    if (!isPlain(v)) return v;
    if (Array.isArray(v)) {
      const out = new Array(v.length);
      memo.set(v, out);
      for (let i = 0; i < v.length; i++) out[i] = walk(v[i]);
      return out;
    }
    const out = Object.getPrototypeOf(v) === null ? Object.create(null) : {};
    memo.set(v, out);
    // defineProperty, never `out[k] =`: an own `__proto__` key (JSON.parse makes one from API data) assigned would set
    // the copy's PROTOTYPE, and the key and its text would vanish from every artifact.
    // A REDACTED key that lands on a name already taken takes `#2`, `#3`, …: an original key keeps its name, and no entry
    // is ever overwritten (two URL keys differing only in userinfo would otherwise collapse into one — a lost finding).
    const used = new Set(Object.keys(v));
    for (const k of Object.keys(v)) {
      let key = str(k);
      if (key !== k) { const base = key; for (let n = 2; used.has(key); n++) key = `${base}#${n}`; used.add(key); }
      Object.defineProperty(out, key, { value: walk(v[k]), writable: true, enumerable: true, configurable: true });
    }
    return out;
  };
  return { value: walk(value), replaced };
}

/**
 * A plugin's throw, scrubbed: an Error keeps its class; any other thrown value is walked as a result is.
 * @param {unknown} thrown
 * @param {{ env?: Record<string, string|undefined>, redact?: (s: string) => string }} [opts]
 */
export function scrubThrown(thrown, opts = {}) {
  try { return scrubOrThrow(thrown, opts).value; }
  catch (e) { return new Error(`the plugin's error ${WITHHELD} (${errName(e)})`); }
}
