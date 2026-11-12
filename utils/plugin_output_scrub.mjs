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
// proxy password of at least PROXY_SECRET_MIN_LENGTH characters wherever it appears.
//
// Walked: strings, plain objects (keys and values), arrays, and an Error's message, stack, cause and own enumerable
// fields. NOT walked (stated limit): a string inside a Map, a Set, a typed array or Buffer, a Date, or any other class
// instance — those are passed by reference. A value with nothing to redact is returned BY REFERENCE; only a value that
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
export function scrubPluginOutput(value, { env = process.env, redact = credentialRedactor(env) } = {}) {
  // Pass 1: does anything need redacting? Answered without copying, so the common case keeps every reference.
  const seen = new Set();
  const needs = (v) => {
    if (typeof v === 'string') return redact(v) !== v;
    if (v === null || typeof v !== 'object' || seen.has(v)) return false;
    seen.add(v);
    if (v instanceof Error) return errorEntries(v).some(([, x]) => needs(x));   // the same properties pass 2 copies
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
      const out = new Error('');
      Object.setPrototypeOf(out, Object.getPrototypeOf(v));
      memo.set(v, out);
      for (const [k, x, enumerable] of errorEntries(v)) {
        Object.defineProperty(out, k, { value: walk(x), writable: true, configurable: true, enumerable });
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
    for (const k of Object.keys(v)) out[str(k)] = walk(v[k]);
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
  return scrubPluginOutput(thrown, opts).value;
}
