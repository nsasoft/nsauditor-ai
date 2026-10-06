// THE PROTOCOL-LABEL TABLE IS DERIVED FROM WHAT THE SHIPPED PRODUCERS WRITE (1.1.1 — the audit seat's T1-a ruling).
//
// The delta's UDP rule (`isUdpTransport`) reads a finding's `protocol`, an APPLICATION label (`udp`, `upnp`, `llmnr`,
// `mdns`, `https`, …) that reaches the finding from the concluder's service set. A hand-listed table rots in both
// directions: a label a producer writes that the table lacks falls to "not UDP" and reads RESOLVED; a label no
// producer writes is a table member nothing can reach. So the table's keys are held against a CENSUS of every label
// the shipped code writes — here over Community's plugins and utils; Enterprise's test holds the two-way equality over
// BOTH repos (it can see this one; this one cannot see it).
//
// Deny-by-default: every `protocol:` / `probe_protocol:` write whose right-hand side carries no literal is a COMPUTED
// site, and each one is DECLARED below with the domain it can take — held in equality, so a new computed site fails
// by name and a stale declaration fails too.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import * as SD from '../utils/scan_delta.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const TABLE = SD.TRANSPORT_OF_LABEL ?? {};

// Comments out, so a label named in prose is not a write — read as a TOKENIZER, not a regex (1.2.1): the regex form opened
// a "block comment" at the `/*` inside a STRING (`Accept: '*/*'` in the HTTP probe) and closed it at the next real `*/`,
// so the day that file gained a doc comment the census blanked five label writes between them and called `http` and
// `https` orphans. Strings, templates and regex literals are skipped as units; newlines are kept.
function code(src) {
  const out = src.split('');
  let i = 0;
  let prev = '';
  const blank = (a, b) => { for (let k = a; k < b; k++) if (out[k] !== '\n') out[k] = ' '; };
  while (i < src.length) {
    const c = src[i];
    const d = src[i + 1];
    if (c === '/' && d === '/') { const j = src.indexOf('\n', i); const e = j < 0 ? src.length : j; blank(i, e); i = e; continue; }
    if (c === '/' && d === '*') { const j = src.indexOf('*/', i + 2); const e = j < 0 ? src.length : j + 2; blank(i, e); i = e; continue; }
    if (c === '"' || c === "'" || c === '`') {
      i++;
      while (i < src.length && src[i] !== c) i += src[i] === '\\' ? 2 : 1;
      i++; prev = c; continue;
    }
    if (c === '/' && (prev === '' || '(,=:[!&|?{};+-*%<>~^'.includes(prev))) {
      let inClass = false;
      i++;
      while (i < src.length && src[i] !== '\n' && (inClass || src[i] !== '/')) {
        if (src[i] === '\\') i++;
        else if (src[i] === '[') inClass = true;
        else if (src[i] === ']') inClass = false;
        i++;
      }
      i++; prev = '/'; continue;
    }
    if (!/\s/.test(c)) prev = c;
    i++;
  }
  return out.join('');
}
// A comparison is not a write: `typeof x === 'string'` must not put `string` in the vocabulary.
const noComparisons = (rhs) => rhs.replace(/(?:===|!==|==|!=)\s*(['"])[^'"]*\1/g, '').replace(/(['"])[^'"]*\1\s*(?:===|!==|==|!=)/g, '');

export function censusOf(files) {
  const labels = new Map();
  const computed = new Set();
  for (const rel of files) {
    const src = code(fs.readFileSync(path.join(ROOT, rel), 'utf8'));
    // Both WRITE forms: an object key (`protocol: …`) and an assignment (`x.protocol = …`, not a comparison) — the
    // first draft read only the key form while claiming "every write form" (review, verified; syn_scanner:51 is one).
    for (const m of src.matchAll(/(?:\b(probe_protocol|protocol)\s*:|\.(probe_protocol|protocol)\s*=(?![=>]))\s*([^,;}\n]+)/g)) {
      m[1] = m[1] ?? m[2]; m[2] = m[3];
      const rhs = noComparisons(m[2]);
      const lits = [...rhs.matchAll(/(['"])([A-Za-z0-9_-]+)\1/g)].map((x) => x[2]);
      if (lits.length === 0) { computed.add(`${rel} :: ${m[1]}: ${m[2].trim()}`); continue; }
      for (const l of lits) labels.set(l, [...(labels.get(l) ?? []), rel]);
    }
    // A default parameter is a write too (os_detector's `proto = "os-detector"`).
    for (const m of src.matchAll(/\bproto\s*=\s*(['"])([A-Za-z0-9_-]+)\1/g)) labels.set(m[2], [...(labels.get(m[2]) ?? []), `${rel} (default)`]);
    // So is a literal FALLBACK on a protocol expression, wherever it flows (1.2.1): os_detector passes
    // `r?.probe_protocol || "dns"` into evidenceRow. Until 1.2.1 that `dns` was ALSO written literally by 060's
    // per-finding records, so the census never had to see this form; folding those records away made it the
    // only writer, and a census that cannot see it calls a live label an orphan.
    for (const m of src.matchAll(/\b(?:probe_)?protocol\s*\|\|\s*(['"])([A-Za-z0-9_-]+)\1/g)) labels.set(m[2], [...(labels.get(m[2]) ?? []), `${rel} (fallback)`]);
  }
  return { labels, computed };
}

const SUBJECT = [
  ...fs.readdirSync(path.join(ROOT, 'plugins')).filter((f) => f.endsWith('.mjs')).map((f) => `plugins/${f}`),
  ...fs.readdirSync(path.join(ROOT, 'utils')).filter((f) => f.endsWith('.mjs')).map((f) => `utils/${f}`),
];

// Every computed write, and the domain it can take. Each domain is ⊆ the census or is a passthrough of a value the
// census already covers — which is what keeps an unknown label unreachable through the shipped path.
const COMPUTED_SITES = new Map([
  ['plugins/db_scanner.mjs :: protocol: proto', 'passthrough: String(r?.probe_protocol || \'tcp\') — a data row\'s probe_protocol, itself a census write'],
  ['plugins/os_detector.mjs :: probe_protocol: proto', 'evidenceRow\'s `proto` parameter: default "os-detector", callers pass "mdns" · "upnp" · probe_protocol || "dns" — every one a census literal'],
  ['plugins/result_concluder.mjs :: protocol: proto', 'passthrough: row?.probe_protocol || result?.protocol || \'tcp\' — the service label every producer write feeds'],
  ['plugins/result_concluder.mjs :: protocol: d?.probe_protocol ?? null', 'evidence piece: a data row\'s probe_protocol verbatim, never a service label'],
  ['plugins/result_concluder.mjs :: protocol: m.protocol', 'meta entry moved to evidence: its protocol verbatim (META labels never reach the service set)'],
  ['plugins/sunrpc_scanner.mjs :: probe_protocol: protocol', 'loop over `protocols` = opts.protocol ? [opts.protocol] : [\'tcp\', \'udp\']'],
  ['plugins/sunrpc_scanner.mjs :: protocol: protocols[0]', 'the same `protocols` list — tcp or udp'],
  ['plugins/sunrpc_scanner.mjs :: probe_protocol: protocols[0]', 'the same `protocols` list — tcp or udp'],
  ['plugins/syn_scanner.mjs :: protocol: proto', 'nmap XML `protocol="…"` under `-sS` only (buildNmapArgs) — tcp'],
  ['plugins/webapp_detector.mjs :: probe_protocol: proto', 'url.startsWith(\'https:\') ? \'https\' : \'http\''],
  ['utils/report_inputs.mjs :: protocol: null', 'the PLUGIN path\'s declared null — no transport on a plugin finding'],
  ['utils/service_flags.mjs :: protocol: null', 'a finding graded from an adapter payload that landed in EVIDENCE — no port, so no transport'],
  ['utils/scan_history.mjs :: protocol: null', 'a HOST-level service-check change on a history line (a domain\'s DNS posture) — no port, so no transport'],
  ['utils/report_inputs.mjs :: protocol: typeof q?.target?.protocol === \'string\' ? q.target.protocol : null',
    'the QUEUE path: a queue producer\'s target.protocol verbatim — Enterprise\'s agents and engine, whose writes Enterprise\'s census holds'],
  ['utils/scan_history.mjs :: protocol: svc.protocol', 'passthrough of a service\'s label into the history record'],
  ['utils/report_inputs.mjs :: protocol: String(s.protocol).toLowerCase()',
    'udpServicesOf: a service label already admitted by isUdpTransport — the table\'s own keys, lower-cased'],
]);
// Written by ENTERPRISE only (its cloud plugins write `api` and `assessment`). This repo cannot see them; the
// Enterprise census holds the full two-way equality and fails if either stops being written there.
const ENTERPRISE_ONLY_LABELS = new Set(['api', 'assessment']);

test('the table exists, is frozen, and classifies every key as udp, tcp or other', () => {
  assert.ok(Object.isFrozen(TABLE));
  assert.ok(Object.keys(TABLE).length >= 10, 'non-vacuity');
  for (const [l, t] of Object.entries(TABLE)) {
    assert.ok(['udp', 'tcp', 'other'].includes(t), `${l} → ${t}`);
    assert.equal(l, l.toLowerCase(), `${l} is lower-case`);
  }
});

test('the census reads a real corpus (floor), and its detector catches every write form and no comparison', () => {
  assert.ok(SUBJECT.length >= 60, `subject floor: ${SUBJECT.length} files`);
  const tmp = fs.mkdtempSync(path.join(ROOT, 'tests', '.census-probe-'));
  try {
    fs.writeFileSync(path.join(tmp, 'p.mjs'), [
      "const a = { protocol: 'udp' };",
      'const b = { probe_protocol: isHttps ? "https" : "http" };',
      "const c = { protocol: svc.protocol ?? 'tcp' };",
      'function row(info, proto = "os-detector") {}',
      "const d = { protocol: typeof x === 'string' ? x : null };",
      "// const e = { protocol: 'commented-out' };",
      'const f = { protocol: somewhere.else };',
      "rec.protocol = 'sctp';",
      "if (x.protocol === 'udp') {}",
      'const g = (x) => x.protocol;',
      'portInfo.protocol = m ? m[1] : "tcp";',
      'evidenceRow("x", port, String(r?.probe_protocol || "dccp"), banner);',
      // a `/*` inside a STRING, then a real doc comment later: the label between them is a write
      "const hdr = { Accept: '*/*' };",
      "const q = { protocol: 'quic' };",
      '/** a doc comment that closes with */',
      // a REGEX LITERAL ending in `\\/\\/` with a write on the same line: read as a line comment, it hides the write (the
      // audit seat's mutant — the regex branch off — stayed green until this line; the corpus carries the shape five times)
      String.raw`const u = /^https?:\/\//.test(s); const a2 = { probe_protocol: 'rtp' };`,
    ].join('\n'));
    const rel = path.relative(ROOT, path.join(tmp, 'p.mjs'));
    const { labels, computed } = censusOf([rel]);
    assert.deepEqual([...labels.keys()].sort(), ['dccp', 'http', 'https', 'os-detector', 'quic', 'rtp', 'sctp', 'tcp', 'udp'],
      'the ASSIGNMENT form is a write (`rec.protocol = \'sctp\'`), and so is a literal fallback (`probe_protocol || "dccp"`); `===` is a comparison, not a write');
    assert.ok(!labels.has('string'), 'a comparison is not a write');
    assert.ok(!labels.has('commented-out'), 'a comment is not a write');
    assert.deepEqual([...computed].map((c) => c.split(' :: ')[1]).sort(),
      ['protocol: somewhere.else', 'protocol: typeof x === \'string\' ? x : null'].sort());
  } finally { fs.rmSync(tmp, { recursive: true, force: true }); }
});

test('every label Community writes is classified in the table — none falls to "unknown"', () => {
  const { labels } = censusOf(SUBJECT);
  const missing = [...labels.keys()].filter((l) => !(l.toLowerCase() in TABLE));
  assert.deepEqual(missing, [], `written but unclassified: ${missing.map((l) => `${l} (${labels.get(l).join(', ')})`).join('; ')}`);
});

test('every table key is written somewhere — here, or by Enterprise (declared, and held there)', () => {
  const { labels } = censusOf(SUBJECT);
  const orphan = Object.keys(TABLE).filter((l) => !labels.has(l) && !ENTERPRISE_ONLY_LABELS.has(l));
  assert.deepEqual(orphan, [], 'a table member no producer writes is a hand-list member');
  for (const l of ENTERPRISE_ONLY_LABELS) assert.ok(l in TABLE && !labels.has(l), `${l} is declared Enterprise-only and must not be written here`);
});

test('every COMPUTED write is declared with its domain, in equality — a new one fails by name, a stale one too', () => {
  const { computed } = censusOf(SUBJECT);
  const undeclared = [...computed].filter((c) => !COMPUTED_SITES.has(c));
  const stale = [...COMPUTED_SITES.keys()].filter((c) => !computed.has(c));
  assert.deepEqual(undeclared, [], 'a protocol write with no literal must be declared with the domain it can take');
  assert.deepEqual(stale, [], 'a declared computed site no longer exists — retire the declaration');
});

test('the UDP set is exactly the udp-classified keys, and the real corpus labels land where they must', () => {
  assert.deepEqual([...SD.UDP_TRANSPORT_LABELS].sort(), Object.keys(TABLE).filter((l) => TABLE[l] === 'udp').sort());
  for (const l of ['udp', 'upnp', 'llmnr', 'mdns', 'dnssd']) assert.equal(TABLE[l], 'udp', l);
  for (const l of ['tcp', 'http', 'https']) assert.equal(TABLE[l], 'tcp', l);
});
