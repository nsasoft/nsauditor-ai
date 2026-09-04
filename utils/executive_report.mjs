// utils/executive_report.mjs — the Pro `report --format executive` HTML deliverable.
//
// Renders Task 4's normalised run model and Task 5's brand into ONE self-contained HTML
// document. This file is the LAST UNGATED LAYER in the product: every gate upstream of it
// checks source and published pages; nothing opens the file a consultant sends to their
// customer. What it says here is what the customer believes.
//
// ⚠️ THE INVARIANT (copied verbatim from the design — do not paraphrase):
// "The only external reference the file may carry is an HTML <a href> whose scheme is http,
// https or mailto. Every other attribute or CSS value containing a URL scheme must begin with
// data: or #. No <script> element and no on* attribute exists anywhere in the file."
//
// Stated as a rule rather than a deny-list: an enumerated list misses <iframe src>,
// <object data>, srcset, <base href>, <meta http-equiv="refresh">, <form action>,
// <video poster>. A hyperlink is not egress — <a href> fetches nothing until a human clicks
// it — so a CVE citation to nvd.nist.gov is permitted; a test that grepped output for
// http(s):// would fire on every legitimate citation and be switched off in its first week.
// `egressViolations` below is that rule made executable, and is the single implementation
// this module's own render, its own test file, and any later gate all share.
//
// Everything reaching this renderer is untrusted text: operator brand fields (Task 5 loads
// them unescaped, by design, and documents that Task 6 must escape at render time), and the
// scan model itself — a finding's title/detail/remediation, a host name, a plugin name or
// error reason can all originate from a scanned target's banner text or from a hostile
// `--host-file`. Every one of those is escaped at the point it is interpolated, whether into
// a text node or into an HTML attribute — never assumed to already be one of a fixed
// vocabulary, even where the producer (report_inputs.mjs) is expected to constrain it.

import { escapeHtml } from './brand.mjs';

/* ------------------------------------------------------------------------------------------
 * egressViolations — deny-by-default. Two levels: every TAG, then EVERY attribute of it
 * (double-, single- and UNQUOTED). Entities are decoded and tab/newline/NUL stripped BEFORE
 * testing, because the browser decodes them before acting on a value. Values are refused
 * unless they begin with `data:` or `#`; the sole exemption is an <a href> whose scheme is
 * http, https or mailto. Some elements are refused BY NAME — no value of theirs is ever
 * acceptable here.
 *
 * ⚠️ STATED LIMIT, restored here because this function is EXPORTED and Task 9 reuses it as the
 * shared predicate over the REAL rendered output: this is a regex over SERIALISED HTML, not a
 * parser. A renderer that emitted an unbalanced quote could still hide an attribute from
 * TAG_RE — the quoted-run fix below closes one such gap, found in this task's own adversarial
 * pass, but it does not make this a tokenizer with a real parse tree. The renderer in this file
 * is ours, and every interpolated value passes `escapeHtml` before it ever reaches here; Task 9
 * Step 1 drives the actual rendered document through this predicate, and THAT leg — not this
 * function's own cleverness — is what covers a renderer bug this regex cannot see. Do not read
 * an empty result from this function as "this HTML is safe" in general; read it as "this
 * document did not match any of the shapes this predicate looks for."
 * ------------------------------------------------------------------------------------------ */
const ENT = { lt: '<', gt: '>', amp: '&', quot: '"', colon: ':', tab: '\t', newline: '\n' };
const decode = (s) => s
  .replace(/&#x([0-9a-f]+);?/gi, (_, h) => String.fromCodePoint(parseInt(h, 16)))
  .replace(/&#(\d+);?/g, (_, d) => String.fromCodePoint(Number(d)))
  .replace(/&(lt|gt|amp|quot|colon|tab|newline);/gi, (_, e) => ENT[e.toLowerCase()])
  .replace(/[\t\n\r\0]/g, '');
const FORBIDDEN_TAGS = /^(?:script|iframe|frame|object|embed|base|form|link|applet|template)$/i;
// ⚠️ FOUND IN THIS IMPLEMENTER'S OWN ADVERSARIAL PASS, NOT IN THE BRIEF'S BATTERY.
// The brief's own TAG_RE was `/<([a-zA-Z][\w:-]*)\b([^>]*)>/g` — `[^>]*` stops at the FIRST
// `>` no matter where it sits, including inside a QUOTED attribute value. A real HTML
// tokenizer does not treat `<`/`>` specially while inside a quoted attribute value — only the
// matching closing quote ends it — so `<a href="data:text/html,<b>x</b>">c</a>` is one real
// `<a>` tag whose href is the whole `data:text/html,<b>x</b>` string, but the brief's regex
// truncates the match at the first `>` (inside the nested `<b>`), leaving the actual href
// value NEVER examined and the fixture the brief's own step 4b lists for this exact shape
// (`'data:text/html document'`) silently GREEN. Measured directly: `egressViolations` on
// that fixture returned `[]` before this fix. The repair makes the tag-attrs capture
// consume a fully-quoted run (either quote style) as one unit before a bare `>` is allowed to
// close the tag, matching how attribute-value tokenizing actually works.
const TAG_RE = /<([a-zA-Z][\w:-]*)\b((?:[^>"']|"[^"]*"|'[^']*')*)>/g;
const ATTR_RE = /([^\s"'<>\/=]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+)))?/g;
// ⚠️ TWO TIERS, AND THE SECOND TIER IS AN EXEMPTION THAT WAS ITSELF A WALK-THROUGH.
// A bare `[a-z][a-z0-9+.-]*:` would read ordinary attribute prose as a scheme —
// alt="Note: the logo", title="SSL: weak cipher suite" — and a finding title routinely
// carries a colon, so a naive rule would fire on nearly every real report and get switched
// off in its first week. The obvious repair, `:(?!\s)` ("a scheme is never followed by
// whitespace"), is FALSE for the schemes that matter: `javascript` is not a special scheme,
// so everything after its colon is the script body, and `href="javascript: alert(1)"`
// EXECUTES — leading space included. So: known-dangerous schemes are URL-ish REGARDLESS of
// what follows; only an UNKNOWN `word:` gets the prose exemption (and only when not followed
// by whitespace).
const URLISH = /^\s*(?:(?:javascript|vbscript|data|blob|file|ftp|https?|wss?|about):|[a-z][a-z0-9+.-]*:(?!\s)|\/\/)/i;
const CSS_BAD = /@import|expression\s*\(|url\s*\(\s*(?:["']\s*)?(?!data:|#)/i;

export function egressViolations(html) {
  const out = [];
  let t;
  TAG_RE.lastIndex = 0;
  while ((t = TAG_RE.exec(html))) {
    const tag = t[1].toLowerCase();
    if (FORBIDDEN_TAGS.test(tag)) { out.push(`<${tag}> is not permitted`); continue; }
    if (tag === 'meta' && !/^\s*(?:charset|name)\s*=/i.test(t[2])) {
      out.push('<meta> other than charset/name is not permitted'); continue;
    }
    let a;
    ATTR_RE.lastIndex = 0;
    while ((a = ATTR_RE.exec(t[2]))) {
      const attr = a[1].toLowerCase();
      const val = decode(a[2] ?? a[3] ?? a[4] ?? '');
      if (attr.startsWith('on')) { out.push(`${tag} carries an event attribute ${attr}`); continue; }
      if (attr === 'srcdoc') { out.push(`${tag}[srcdoc] embeds a document`); continue; }
      if (attr === 'style') { if (CSS_BAD.test(val)) out.push(`${tag}[style] carries a CSS reference`); continue; }
      if (attr === 'srcset') { if (/[a-z]+:|\/\//i.test(val) && !/^\s*data:/i.test(val)) out.push(`${tag}[srcset] names an external URL`); continue; }
      if (!URLISH.test(val)) continue;
      // ⚠️ NARROWED TO THE SHAPE WE ACTUALLY EMIT. A blanket `data:` exemption also clears
      // `<a href="data:text/html,<script>…">`, a document that can run script. The only
      // data: URI this renderer produces is the brand logo, so the exemption is exactly
      // that.
      if (/^\s*(?:data:image\/(?:png|jpeg);base64,|#)/i.test(val)) continue;
      if (tag === 'a' && attr === 'href' && /^\s*(?:https?:|mailto:)/i.test(val)) continue;
      out.push(`${tag}[${attr}] names an external URL: ${val.slice(0, 60)}`);
    }
  }
  for (const s of html.match(/<style\b[^>]*>[\s\S]*?<\/style>/gi) ?? []) {
    if (CSS_BAD.test(decode(s))) out.push('a <style> block carries a CSS reference');
  }
  return out;
}

/* ------------------------------------------------------------------------------------------
 * Rendering helpers
 * ------------------------------------------------------------------------------------------ */

// PASS is LAST and is its own tier. Without an entry here (and in SEV_COLORS) `chartSev`
// collapses it to the literal 'OTHER', so a client-facing report labelled every passing
// check "OTHER" — measured at 18 records on a real AWS run.
const SEV_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', 'PASS'];
const SEV_COLORS = {
  CRITICAL: '#7a1220',
  HIGH: '#b3261e',
  MEDIUM: '#b3690a',
  LOW: '#8a7500',
  INFO: '#3b5568',
  PASS: '#2f6f4f',
  OTHER: '#5a5a5a',
};
const SEV_RANK = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4, PASS: 5 };
const TOP_RISKS_LIMIT = 10;
const CVE_RE = /^CVE-\d{4}-\d{4,7}$/i;

// A finding's severity reaches this renderer as free text from report_inputs.mjs, which
// itself only uppercases whatever a plugin supplied — it is not a closed vocabulary this
// module can rely on. `chartSev` collapses ANY value outside the five known severities to a
// fixed literal 'OTHER' so (a) no raw value is ever placed in a data-row-severity attribute
// without going through escapeHtml first regardless, keeping this a belt-and-braces measure
// rather than the only defense, and (b) an out-of-vocabulary severity still counts toward the
// chart total instead of silently vanishing from it — the same "a count must not silently
// drop members" discipline this project applies to its compliance matrices.
function chartSev(sev) {
  return SEV_COLORS[sev] ? sev : 'OTHER';
}

function sevRank(sev) {
  return SEV_RANK[sev] ?? 99;
}

function sevClass(sev) {
  return SEV_COLORS[sev] ? `sev-${sev.toLowerCase()}` : 'sev-other';
}

// TOP RISKS ordering, stated verbatim on the page: known-exploited first, then EPSS
// probability (descending; a finding with no EPSS score ranks behind one that has any score
// at all), then severity.
function compareRisk(a, b) {
  if (Boolean(a.kev) !== Boolean(b.kev)) return a.kev ? -1 : 1;
  const ae = typeof a.epss === 'number' ? a.epss : -1;
  const be = typeof b.epss === 'number' ? b.epss : -1;
  if (ae !== be) return be - ae;
  return sevRank(a.severity) - sevRank(b.severity);
}

// "(untitled finding)" is the ALARM for a non-pass finding whose producer emitted no
// content — it must stay reserved for that, or a real producer defect reads as normal
// output. A PASS record legitimately has nothing to report.
function untitledLabel(f) {
  return chartSev(f?.severity) === 'PASS' ? 'clean — no issues recorded' : '(untitled finding)';
}

function comparePresentation(a, b) {
  const r = sevRank(a.severity) - sevRank(b.severity);
  if (r !== 0) return r;
  return (a.port ?? -1) - (b.port ?? -1);
}

function fmtDate(value) {
  const d = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(d.getTime())) return 'unknown';
  const pad = (n) => String(n).padStart(2, '0');
  return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())} `
    + `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())} UTC`;
}

function fmtPct(epss) {
  return typeof epss === 'number' && Number.isFinite(epss) ? `${(epss * 100).toFixed(1)}%` : '—';
}

// A CVE id is validated by SHAPE before it is ever used to build a link — the model's own
// data reaches this function, and a malformed or hostile "CVE" string (a compromised target's
// banner text, say) must never be trusted enough to become a URL. Anything that does not match
// renders as escaped plain text instead, same as any other untrusted string.
function renderCves(cves) {
  if (!Array.isArray(cves) || cves.length === 0) return '—';
  return cves.map((c) => {
    const s = String(c);
    if (!CVE_RE.test(s)) return escapeHtml(s);
    const safe = s.toUpperCase();
    return `<a href="https://nvd.nist.gov/vuln/detail/${escapeHtml(safe)}" `
      + `rel="noopener noreferrer">${escapeHtml(safe)}</a>`;
  }).join(', ');
}

// `p.ran`/`p.skipped`/`p.errored`/`p.timedOut` interpolate WITHOUT escapeHtml, deliberately —
// they are computed integers (report_inputs.mjs's own plugin-status tally), never a string a
// scanned target or an operator's --host-file could shape. Escaping an integer would be a rule
// with no defect behind it (the standard this cycle held Task 5 to for a parallel non-issue);
// the file's escaping discipline is universal for STRINGS reaching this renderer, not for
// values that were never strings to begin with.
function pluginSummary(plugins) {
  const p = plugins ?? { ran: 0, skipped: 0, errored: 0, timedOut: 0 };
  const parts = [`${p.ran} plugin${p.ran === 1 ? '' : 's'} ran`];
  if (p.skipped) parts.push(`${p.skipped} skipped`);
  if (p.errored) parts.push(`${p.errored} errored`);
  if (p.timedOut) parts.push(`${p.timedOut} timed out`);
  const sentence = parts.length === 1
    ? `${parts[0]}.`
    : `${parts.slice(0, -1).join(', ')} and ${parts[parts.length - 1]}.`;
  return `${sentence} Reasons per host in the appendix.`;
}

// The named-missing list (`coverage.missing`) and the arithmetic gap (`requested - written`)
// can disagree — report_inputs.mjs's model carries only NAMED misses; a host whose `--host`
// input could not even be parsed into a name is counted upstream but never named here. This
// renders what the model actually provides rather than assuming the two always match.
function partialCaveat(coverage) {
  const gap = coverage.requested - coverage.written;
  if (gap <= 0) return null;
  const named = coverage.missing ?? [];
  const list = named.map((h) => escapeHtml(String(h))).join(', ');
  if (named.length && named.length === gap) {
    return `${gap} of ${coverage.requested} requested hosts were not scanned: ${list}.`;
  }
  if (named.length) {
    return `${gap} of ${coverage.requested} requested hosts were not scanned, including: ${list}.`;
  }
  return `${gap} of ${coverage.requested} requested hosts were not scanned.`;
}

// CC-1: `model.kev.loaded`/`model.epss.loaded` are WHOLE-RUN, all-or-nothing aggregates
// (aggregateStoreLoad in cli.mjs: true only if EVERY written host reported a snapshot date).
// A per-finding `f.kev`/`f.epss` is set independently, per host, by EE's enrichment — and the
// two can disagree for two real reasons, neither exotic: (1) an interrupted run reported with
// `--allow-partial`, where finalize never ran so `kevLoaded` still holds `writeRunStart`'s
// pessimistic `false` default while individual findings carry real enrichment from before the
// interruption; (2) a completed multi-host run where the aggregate is honestly `false` because
// ONE host's enrichment failed to report a snapshot date, while every OTHER host's findings were
// genuinely evaluated. Denying the check outright ("NOT evaluated") on this page is FALSE the
// moment any finding below it shows a real result — and Top Risks' own ordering rule ("ordered
// by known-exploited first…") would then be citing a signal this same cover just denied.
//
// The safe direction is never to deny a check whose results are ON THE PAGE. So the cover looks
// at the model's own findings before it is allowed to say NOT evaluated: if the aggregate says
// no but at least one finding carries a real result anyway, the cover states the truth — partial,
// uncertain coverage — rather than a flat denial that the page immediately contradicts. Only
// `kev === true` is a legible per-finding SIGNAL here — `shapeFinding()` collapses "evaluated
// clear" and "never evaluated" to the same `false`, so a false/null value proves nothing and is
// not used to override the aggregate; only an unambiguous `true` (or a real EPSS number) can.
function kevEvaluatedSomewhere(findings) {
  return findings.some((f) => f.kev === true);
}
function epssEvaluatedSomewhere(findings) {
  return findings.some((f) => typeof f.epss === 'number' && Number.isFinite(f.epss));
}

function renderKevEpss(model) {
  const findings = model.findings ?? [];
  const kevSeen = kevEvaluatedSomewhere(findings);
  const epssSeen = epssEvaluatedSomewhere(findings);
  const kevLine = model.kev?.loaded
    ? `Known-exploited status evaluated against the CISA KEV snapshot dated `
      + `${escapeHtml(String(model.kev.snapshot ?? 'unknown'))}.`
    : kevSeen
      ? 'Known-exploited status evaluated for some but not all hosts in this scan — the CISA '
        + 'KEV feed was not confirmed loaded for the whole run. A finding marked "Yes" below was '
        + 'matched against KEV; one not marked "Yes" may be genuinely clear, or simply '
        + 'unconfirmed.'
      : 'Known-exploited status NOT evaluated — no CISA KEV feed was loaded for this scan.';
  const epssLine = model.epss?.loaded
    ? `Exploitation probability from the FIRST EPSS snapshot dated `
      + `${escapeHtml(String(model.epss.snapshot ?? 'unknown'))}.`
    : epssSeen
      ? 'Exploitation probability available for some but not all hosts in this scan — the FIRST '
        + 'EPSS feed was not confirmed loaded for the whole run. A percentage shown below is a '
        + 'real score; a missing one may be genuinely absent, or simply unconfirmed.'
      : 'Exploitation probability NOT evaluated — no FIRST EPSS feed was loaded for this scan.';
  return `<p>${kevLine}</p>\n<p>${epssLine}</p>`;
}

function renderBrandBlock(brand) {
  const parts = [];
  if (brand.companyName) parts.push(`<p class="brand-company">Prepared for ${escapeHtml(brand.companyName)}</p>`);
  // brand.contact renders as TEXT ONLY, never as an href — a `mailto:`/`javascript:` value in
  // this field must never become a live link (Task 5's own module header carries this
  // constraint; this is where it is enforced).
  if (brand.contact) parts.push(`<p class="brand-contact">Contact: ${escapeHtml(brand.contact)}</p>`);
  if (brand.logoDataUri) {
    // brand.mjs only ever produces a data:image/png|jpeg;base64,... URI (magic-byte sniffed,
    // size-capped) — the sole data: shape egressViolations' own exemption is narrowed to.
    // Escaped anyway: a security property that holds only because an upstream module happens
    // to guarantee it is not a property this file should assume without also enforcing it.
    parts.push(`<img class="brand-logo" src="${escapeHtml(brand.logoDataUri)}" `
      + `alt="${escapeHtml(brand.companyName || 'Company logo')}">`);
  }
  return parts.join('\n');
}

function renderCoverageSummary(model) {
  const c = model.coverage;
  // CC-3: derived from WRITTEN, never REQUESTED. "Not reachable" is an AFFIRMATIVE negative
  // result — it tells the client a probe actually ran against that host and failed. A host that
  // was requested but never even WRITTEN (report_inputs.mjs deliberately keeps `requested` /
  // `written` / `reachable` apart — see its own "coverage separates unreachable from
  // not-written" test) was never probed at all; the data does not support calling it "not
  // reachable". That gap is already disclosed, honestly, by partialCaveat() below ("N of M
  // requested hosts were not scanned") — collapsing it into this line as well double-counts the
  // SAME hosts under two incompatible statuses on the same page.
  const notReachable = Math.max(0, c.written - c.reachable);
  const lines = [];
  // c.requested/c.reachable/notReachable are computed integers (report_inputs.mjs's own
  // coverage arithmetic), not scanner- or operator-supplied strings — deliberately unescaped,
  // same reasoning as pluginSummary() above.
  lines.push(`<p>${c.requested} hosts requested · ${c.reachable} reachable · `
    + `${notReachable} not reachable.</p>`);
  lines.push(`<p>${pluginSummary(model.plugins)}</p>`);
  if (c.partial) {
    const caveat = partialCaveat(c);
    if (caveat) lines.push(`<p class="caveat">${caveat}</p>`);
  }
  if (c.incomplete) {
    lines.push('<p class="caveat">This run did not record completion; it may be missing '
      + 'results the scan had not yet written.</p>');
  }
  if (!model.findings.length) {
    lines.push(`<p>No findings were recorded for the ${c.written} hosts scanned in this run.</p>`);
  }
  return lines.join('\n');
}

function renderCover(model, brand, renderedAt) {
  const preparedClause = brand.preparedBy ? `Prepared by ${escapeHtml(brand.preparedBy)} · ` : '';
  const intro = 'This report lists the findings recorded by NSAuditor AI for the hosts and '
    + 'plugins named below. It is a print-ready HTML report.';
  return `<section id="cover">
<h1>${escapeHtml(brand.title || 'Network Scan Report')}</h1>
${renderBrandBlock(brand)}
<p class="run-dates">${preparedClause}Scan of ${model.coverage.requested} hosts started `
    + `${fmtDate(model.startedAt)} · Report rendered ${fmtDate(renderedAt)}.</p>
<p>${intro}</p>
${renderCoverageSummary(model)}
${renderKevEpss(model)}
</section>`;
}

function renderTopRisks(findings) {
  // A passing check is not a risk. PASS only stayed out of this section by ranking below
  // 105 real findings; on a CLEAN scan the section titled "Top Risks" would have listed
  // the passing checks themselves.
  const sorted = findings.filter((f) => chartSev(f.severity) !== 'PASS')
    .slice().sort(compareRisk).slice(0, TOP_RISKS_LIMIT);
  const rule = 'Findings below are ordered by known-exploited first, then EPSS probability, '
    + 'then severity.';
  if (!sorted.length) {
    return `<section id="top-risks">
<h2>Top Risks</h2>
<p>${rule}</p>
<p>No findings were recorded in this run.</p>
</section>`;
  }
  // ⚠️ Deliberately NO data-row-severity attribute here. The chart/table agreement invariant
  // is proven by having exactly ONE place in the document that carries that attribute per
  // finding (the appendix, which lists every finding exactly once) — a second place that also
  // carried it, over an overlapping subset, would inflate the count the invariant checks.
  const rows = sorted.map((f) => `<tr>
<td class="${sevClass(f.severity)}">${escapeHtml(f.severity)}</td>
<td>${escapeHtml(f.host)}${f.port != null ? `:${escapeHtml(String(f.port))}` : ''}</td>
<td>${escapeHtml(f.title ?? untitledLabel(f))}</td>
<td>${f.kev ? 'Yes' : 'No'}</td>
<td>${escapeHtml(fmtPct(f.epss))}</td>
</tr>`).join('\n');
  return `<section id="top-risks">
<h2>Top Risks</h2>
<p>${rule}</p>
<table>
<thead><tr><th>Severity</th><th>Host</th><th>Finding</th><th>Known-exploited</th><th>EPSS</th></tr></thead>
<tbody>
${rows}
</tbody>
</table>
</section>`;
}

function renderChart(findings) {
  const buckets = [...SEV_ORDER, 'OTHER'];
  const counts = buckets.map((sev) => [sev, findings.filter((f) => chartSev(f.severity) === sev).length]);
  const max = Math.max(1, ...counts.map(([, n]) => n));
  const barHeight = 22;
  const gap = 8;
  const chartWidth = 320;
  const leftPad = 90;
  const rowsSvg = counts.map(([sev, n], i) => {
    const y = i * (barHeight + gap);
    const w = Math.max(1, Math.round((n / max) * chartWidth));
    return `<g>
<text x="0" y="${y + barHeight - 6}" font-size="12" fill="#111111">${sev}</text>
<rect x="${leftPad}" y="${y}" width="${w}" height="${barHeight}" fill="${SEV_COLORS[sev]}" `
      + `data-severity="${sev}" data-count="${n}"></rect>
<text x="${leftPad + w + 6}" y="${y + barHeight - 6}" font-size="12" fill="#111111">${n}</text>
</g>`;
  }).join('\n');
  const totalHeight = counts.length * (barHeight + gap);
  return `<svg viewBox="0 0 ${leftPad + chartWidth + 40} ${totalHeight}" width="100%" `
    + `height="${totalHeight}" role="img" aria-label="Severity distribution">
${rowsSvg}
</svg>`;
}

function renderPluginStatus(statusList) {
  if (!Array.isArray(statusList) || !statusList.length) {
    return '<p>No plugin status was recorded for this host.</p>';
  }
  const rows = statusList.map((s) => `<tr>
<td>${escapeHtml(s?.name ?? s?.id ?? 'unknown plugin')}</td>
<td>${escapeHtml(s?.status ?? 'unknown')}</td>
<td>${escapeHtml(s?.reason ?? '')}</td>
</tr>`).join('\n');
  return `<table class="plugin-status">
<thead><tr><th>Plugin</th><th>Status</th><th>Reason</th></tr></thead>
<tbody>
${rows}
</tbody>
</table>`;
}

function renderFindingsTable(findings) {
  if (!findings.length) return '<p>No findings recorded for this host.</p>';
  const rows = findings.slice().sort(comparePresentation).map((f) => `<tr data-row-severity="${chartSev(f.severity)}">
<td class="${sevClass(f.severity)}">${escapeHtml(f.severity)}</td>
<td>${f.port != null ? escapeHtml(String(f.port)) : '—'}</td>
<td>${escapeHtml(f.title ?? untitledLabel(f))}</td>
<td>${renderCves(f.cves)}</td>
<td>${f.kev ? 'Yes' : 'No'}</td>
<td>${escapeHtml(fmtPct(f.epss))}</td>
<td>${escapeHtml(f.detail ?? '')}</td>
<td>${escapeHtml(f.remediation ?? '')}</td>
</tr>`).join('\n');
  return `<table class="findings">
<thead><tr><th>Severity</th><th>Port</th><th>Finding</th><th>CVE</th><th>Known-exploited</th>`
    + `<th>EPSS</th><th>Detail</th><th>Remediation</th></tr></thead>
<tbody>
${rows}
</tbody>
</table>`;
}

// CC-2: `model.hosts` is one entry per scan DIRECTORY (each carrying its own already-scoped
// `findings` array — see report_inputs.mjs's buildModel), and two directories can share a host
// NAME (`--host 10.0.0.7,10.0.0.7`, a repeated --host-file line, an overlapping range — none of
// which utils/host_iterator.mjs de-duplicates). The previous version rebuilt a `byHost` map
// keyed by NAME from the flattened `model.findings`, so every same-named directory's section
// rendered ALL of that name's findings (doubling them across sections), and `pluginByHost`
// — also name-keyed — was last-write-wins, silently dropping every same-named host's plugin
// table but the final one's. The fix uses `h.findings` directly (already correctly scoped per
// directory, never re-derived) and keys the plugin-status lookup by `dir`, which is unique per
// scan attempt by construction (`path.basename(outDir)`, timestamped — cli.mjs).
function renderAppendix(model) {
  const pluginByDir = new Map((model.plugins?.byHost ?? []).map((h) => [h.dir, h.status]));

  const sections = (model.hosts ?? []).map((h) => {
    const findings = h.findings ?? [];
    const reach = h.up ? 'reachable' : 'not reachable';
    return `<section class="host">
<h3>${escapeHtml(h.host)} — ${reach}</h3>
<p class="dir">Evidence directory: ${escapeHtml(h.dir ?? '')}</p>
${renderPluginStatus(pluginByDir.get(h.dir))}
${renderFindingsTable(findings)}
</section>`;
  }).join('\n');

  return `<section id="appendix">
<h2>Appendix — per-host detail</h2>
${sections}
</section>`;
}

const CSS = `
:root { color-scheme: light; }
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  color: #111111; background: #ffffff; margin: 0; padding: 24px 32px 48px; }
h1 { font-size: 26px; margin: 0 0 12px; }
h2 { font-size: 20px; margin: 32px 0 12px; border-bottom: 2px solid #333333; padding-bottom: 6px; }
h3 { font-size: 16px; margin: 24px 0 6px; }
p { line-height: 1.5; margin: 6px 0; }
.caveat { color: #7a1220; font-weight: bold; }
.brand-logo { max-height: 64px; margin: 8px 0; }
table { border-collapse: collapse; width: 100%; margin: 8px 0 16px; font-size: 13px; }
th, td { border: 1px solid #cccccc; padding: 6px 8px; text-align: left; vertical-align: top; }
th { background: #f0f0f0; }
.sev-critical { color: #7a1220; font-weight: bold; }
.sev-high { color: #b3261e; font-weight: bold; }
.sev-medium { color: #b3690a; font-weight: bold; }
.sev-low { color: #8a7500; }
.sev-info { color: #3b5568; }
.sev-other { color: #5a5a5a; }
footer { margin-top: 32px; padding-top: 12px; border-top: 1px solid #cccccc; font-size: 12px; color: #555555; }
@media print { body { padding: 0; } }
`;

/**
 * Render one self-contained executive HTML report.
 * @param {object} model  Task 4's normalised run model (loadRun()'s .model).
 * @param {object} brand  Task 5's brand ({title, companyName, preparedBy, contact, logoDataUri}).
 * @param {{renderedAt?: Date}} [opts]
 * @returns {string} one complete HTML document.
 */
// The footer names the CE version ALWAYS — CE rendered this document, regardless of tier — and
// APPENDS the EE version when the record carries one, because EE's enrichment (KEV/EPSS) shaped
// the findings above. Both come from the RECORD (`ceVersion` / `eeVersion`), never from the
// renderer's own environment, and never from `model.tier`: a version claim derived from a tier
// is derived from a proxy (the same ruling that put KEV/EPSS coverage on `.loaded`, never on
// tier, in R32/R33 of this cycle) — the record is the fact, the tier is not.
function renderFooter(model) {
  const tier = model.tier ?? 'ce';
  const ceVersion = model.ceVersion ?? '0.0.0';
  const eeSuffix = model.eeVersion ? ` + EE ${escapeHtml(String(model.eeVersion))}` : '';
  return `<footer>Generated by NSAuditor AI ${escapeHtml(tier)} ${escapeHtml(String(ceVersion))}${eeSuffix}</footer>`;
}

export function renderExecutiveReport(model, brand, { renderedAt = new Date() } = {}) {
  const title = escapeHtml(brand.title || 'Network Scan Report');

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${title}</title>
<style>${CSS}</style>
</head>
<body>
${renderCover(model, brand, renderedAt)}
${renderTopRisks(model.findings)}
<section id="chart">
<h2>Severity Distribution</h2>
${renderChart(model.findings)}
</section>
${renderAppendix(model)}
${renderFooter(model)}
</body>
</html>`;
}
