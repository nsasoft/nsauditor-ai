// utils/jira_export.mjs — the Jira-importer CSV export.
//
// CSV using the column names of Jira's CSV importer (Summary, Description, Priority, Labels,
// External ID); the import mapping is done in Jira and has not been verified against a live
// Jira instance.
//
// ⚠️ NOTHING HERE MAY CLAIM A WORKING OR VERIFIED JIRA INTEGRATION. `External ID` is stable per
// finding so that an importer WHICH KEYS ON IT can update rather than duplicate — that is a
// statement of intent, unverified against Jira. Earn-back is a Gate-3-shaped operator check:
// import the sample CSV into a free Jira Cloud project once and record PASS with evidence.
//
// ⚠️ The formula-injection apostrophe below is visible in the RAW file, not only in a
// spreadsheet: a title/detail/remediation beginning with `=`, `+`, `-` or `@` carries a
// prefixed `'` so the cell is inert when opened as a spreadsheet, and that same literal leading
// apostrophe is exactly what a consultant sees reading the CSV directly, e.g. in a text editor.
//
// Consumes Task 4's normalised model (utils/report_inputs.mjs's `loadRun()` — the same object
// the executive HTML report renders), specifically `model.startedAt` (never a render-time
// timestamp — the row is a record of what the SCAN found, not of when this file was produced)
// and `model.findings` (the flat array; each entry's shape is `shapeFinding()`'s: host, port,
// severity, title, detail, remediation, cves, kev, epss — every one of which can originate in a
// scanned target's banner text or a hostile `--host-file` and must be treated as untrusted).
//
// A CSV is opened in a spreadsheet or an importer, not a browser, so the risk shape here is
// RFC4180 structural integrity (a stray `,`/`"`/CR/LF must never let one finding's cell bleed
// into the next row or column) and spreadsheet FORMULA INJECTION (a cell beginning with
// `=`/`+`/`-`/`@` is executed as a formula by Excel/Sheets/LibreOffice the moment the file is
// opened) — never HTML/script injection, which does not apply to this output format.

import crypto from 'node:crypto';

export const JIRA_COLUMNS = ['Summary', 'Description', 'Priority', 'Labels', 'External ID'];

// Jira priorities are site-configurable — this mapping is a CLAIM, and an unstated one is a
// claim nobody can check. Pinned by test; do not change without updating the pinned test.
export const PRIORITY_BY_SEVERITY = {
  CRITICAL: 'Highest', HIGH: 'High', MEDIUM: 'Medium', LOW: 'Low', INFO: 'Lowest',
};

// A severity this repo's own `shapeFinding()` never emits (it always uppercases and defaults to
// 'INFO') should not be reachable from a well-formed model — but this module does not control
// its caller, so a null/undefined/unrecognised severity falls back to a stated safe default
// rather than writing the literal string "undefined" into a Jira Priority cell.
const DEFAULT_PRIORITY = 'Medium';

// ── RFC4180 quoting + formula-injection neutralisation ──────────────────────────────────────
//
// A field is wrapped in `"` (doubling any embedded `"`) when it contains a comma, a double
// quote, or either newline convention (`\n` alone, `\r` alone, or `\r\n`) — a LONE `\r` must be
// quoted too, precisely because it is not the row's own separator (rows are joined with `\n`
// only, below) and an unquoted one would otherwise sit mid-row indistinguishable from ordinary
// content only by luck.
//
// Before that: a cell whose first character is `=`, `+`, `-` or `@` is treated as a formula by
// Excel, Google Sheets and LibreOffice when the file is opened directly — a well-known CSV
// hazard, and a real one here, because a finding's title/detail/remediation is scan output from
// someone else's infrastructure, not text this product authored. A leading `'` forces text
// interpretation in all three without altering the visible value once opened.
function csvField(value) {
  let str = value == null ? '' : String(value);
  if (/^[=+\-@]/.test(str)) str = `'${str}`;
  if (/[",\n\r]/.test(str)) str = `"${str.replace(/"/g, '""')}"`;
  return str;
}

function csvRow(fields) {
  return fields.map(csvField).join(',');
}

// ── External ID ──────────────────────────────────────────────────────────────────────────────
//
// Stable (never a counter, never Date.now(), never Math.random()) and unique within one CSV.
// `host + port + title` alone COLLIDES for two findings reported under one title on one port —
// e.g. two distinct weak-cipher findings on the same host:port — and an importer keyed on
// External ID would then treat the second as an UPDATE of the first, silently dropping one
// finding from the client's board. `detail` is folded into the key for exactly that reason.
//
// Two findings can still be identical in all four fields (a genuine duplicate, or a scan that
// legitimately reports the same condition twice). Those are disambiguated by their ORDINAL
// among equal keys, not by anything that varies between renders of the SAME model — the
// ordinal is a pure function of the (model-determined) order of `model.findings`, so re-running
// this over the same model reproduces the same ids in the same order every time.
function externalIds(findings) {
  const seen = new Map();
  return findings.map((f) => {
    const key = JSON.stringify([keyPart(f.host), keyPart(f.port), keyPart(f.title), keyPart(f.detail)]);
    const ordinal = seen.get(key) ?? 0;
    seen.set(key, ordinal + 1);
    const material = ordinal === 0 ? key : `${key} ${ordinal}`;
    return crypto.createHash('sha256').update(material).digest('hex').slice(0, 16);
  });
}

function keyPart(v) {
  return v == null ? '' : String(v);
}

// ── Labels ───────────────────────────────────────────────────────────────────────────────────
//
// Jira's CSV importer takes multiple label VALUES in one cell space-separated (there is only
// one `Labels` column in JIRA_COLUMNS, never one column per label) — so each token here is
// sanitised to contain no whitespace of its own, or hostile data (e.g. a CVE-shaped string that
// happens to contain a space) would silently fragment into more Jira labels than the scan
// actually reported.
function labelToken(raw) {
  return String(raw).trim().toLowerCase().replace(/\s+/g, '-');
}

function buildLabels(f) {
  const labels = ['nsauditor'];
  const severity = keyPart(f.severity);
  if (severity) labels.push(labelToken(`severity-${severity}`));
  if (f.kev) labels.push('kev');
  for (const cve of Array.isArray(f.cves) ? f.cves : []) {
    const token = labelToken(cve);
    if (token) labels.push(token);
  }
  return labels.join(' ');
}

// ── Description ──────────────────────────────────────────────────────────────────────────────
//
// Carries the SCAN's own timestamp (`model.startedAt`) and the finding's host — never a render
// date, so re-running this exporter next week over an old run does not make the ticket look
// like it was just found.
//
// Sections are joined with ` | `, never `\n` — a raw newline is what `csvField` quotes FOR, not
// something this module should manufacture on its own out of otherwise single-line content. The
// only way this field carries an embedded newline is a genuine one already present in the
// finding's own `detail`/`remediation` (untrusted scan output), preserved as-is and quoted per
// RFC4180 — never introduced by this module's own formatting.
function buildDescription(model, f) {
  const where = f.port != null ? `${keyPart(f.host)}:${f.port}` : keyPart(f.host);
  const parts = [`Host: ${where}`, `Scan started: ${keyPart(model?.startedAt)}`];
  if (f.detail) parts.push(String(f.detail));
  if (f.remediation) parts.push(`Remediation: ${f.remediation}`);
  const cves = Array.isArray(f.cves) ? f.cves.filter(Boolean) : [];
  if (cves.length) parts.push(`CVEs: ${cves.join(', ')}`);
  if (f.kev) parts.push('Listed in the CISA Known Exploited Vulnerabilities (KEV) catalog.');
  if (typeof f.epss === 'number' && Number.isFinite(f.epss)) parts.push(`EPSS: ${f.epss}`);
  return parts.join(' | ');
}

function priorityFor(severity) {
  const key = keyPart(severity).toUpperCase();
  return PRIORITY_BY_SEVERITY[key] ?? DEFAULT_PRIORITY;
}

/**
 * Render Task 4's normalised run model as a Jira-CSV-importer-shaped CSV.
 * @param {object} model - the object `utils/report_inputs.mjs`'s `loadRun()` resolves to.
 * @returns {string}
 */
export function renderJiraCsv(model) {
  // A Jira issue is a WORK ITEM, and a passing check is not work. Before this filter a
  // real AWS run emitted all 18 PASS records as issues — 17 of them carrying substrate
  // prose a consultant would have had to close by hand, and one contentless clean-user
  // record that imported as an issue with no Summary at all.
  //
  // ⚠️ THE FILTER IS DELIBERATELY NARROW — `pass` ONLY. Every other tier, INFO included,
  // stays: INFO carries the evidence gaps and the scope boundaries, which are exactly the
  // material a reader needs to tell an incomplete scan from a clean one.
  const all = Array.isArray(model?.findings) ? model.findings : [];
  const findings = all.filter((f) => String(f?.severity ?? '').toUpperCase() !== 'PASS');
  const ids = externalIds(findings);
  const rows = findings.map((f, i) => csvRow([
    f.title ?? '',
    buildDescription(model, f),
    priorityFor(f.severity),
    buildLabels(f),
    ids[i],
  ]));
  return [JIRA_COLUMNS.join(','), ...rows].join('\n') + '\n';
}
