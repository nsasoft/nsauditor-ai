// tests/changelog_deprecation_pointer.test.mjs
// THE 1.1.2 CHANGELOG ENTRY IS A DEPRECATION TARGET, SO IT IS NEVER TRIMMED FROM THIS FILE.
// Every version of nsauditor-ai below 1.1.2 (153 of them, deprecated 2026-11-18) carries the npm notice
// "Security fix — upgrade to nsauditor-ai 1.1.2 or later … Upgrade notes:
// https://github.com/nsasoft/nsauditor-ai/blob/HEAD/CHANGELOG.md (1.1.2 entry)". HEAD is the default branch, so the
// notice resolves only while THIS file, on main, still holds the 1.1.2 entry with its upgrade effect. A trim of old
// entries, a rename of the heading or a cut of its body sends every user of those versions to a page that does not say
// what changed. Move the entry only together with a re-deprecation that points at its new home.
// A released entry that a registry notice points at does not change, so the whole section — heading line through the
// line before the next "## " heading, lines joined with \n — is pinned to a digest. It equals the section on
// release/1.1.x at f2f6815, the published 1.1.2. An intended edit moves SECTION_SHA256 in the same commit, with the
// reason in that commit's message; the named legs say which part went missing when the digest alone would not.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';

const text = fs.readFileSync(new URL('../CHANGELOG.md', import.meta.url), 'utf8');
const HEADING = /^## 1\.1\.2 \(\d{4}-\d{2}-\d{2}\) — security fix: /;
const SECTION_SHA256 = '46d5e6cedcb8e4fac78d18c3c492f5d19a755e1c9053e253ed256d70a1ef5af0';
const lines = text.split(/\r?\n/);

function bounds() {
  const start = lines.findIndex((l) => HEADING.test(l));
  if (start < 0) return null;
  let end = lines.findIndex((l, i) => i > start && l.startsWith('## '));
  if (end < 0) end = lines.length;
  return { start, end };
}
function section() {
  const b = bounds();
  return b && lines.slice(b.start + 1, b.end).join('\n');
}

test('the CHANGELOG holds exactly one dated "## 1.1.2 (…) — security fix" heading', () => {
  const headings = lines.filter((l) => /^## 1\.1\.2\b/.test(l));
  assert.equal(headings.length, 1, `1.1.2 headings found: ${JSON.stringify(headings)}`);
  assert.match(headings[0], HEADING);
});

test('the 1.1.2 entry still says what changed: the upgrade effect and both of its rules', () => {
  const body = section();
  assert.ok(body, 'no 1.1.2 section');
  assert.ok(body.includes('Security fix. Upgrade effect — read this first.'), 'the upgrade-effect lead is gone');
  assert.ok(body.includes('A `.env` in the working directory is no longer read.'), 'the working-directory .env rule is gone');
  assert.ok(body.includes('`NSAUDITOR_PLUGIN_PATH` entries must be absolute directories under your home directory.'),
    'the plugin-directory rule is gone');
  assert.ok(body.includes('`nsauditor-ai scan … --env ./.env` — only for a file you wrote or trust'),
    'the --env ./.env instruction and its trust condition are gone');
  assert.ok(body.includes('**Stated limits**'), 'the Stated limits block is gone');
  assert.ok(body.includes('The two entry points differ on which home is the base: the CLI uses the home it started with, '
    + 'before `--env` is applied; the MCP server uses the home in effect at its first tool call, which is after '
    + '`NSA_ENV_FILE` is applied.'), 'the two-entry-points limit is gone');
});

test('the 1.1.2 entry is byte-for-byte the released one (digest of the whole section)', () => {
  const b = bounds();
  assert.ok(b, 'no 1.1.2 section');
  const digest = crypto.createHash('sha256').update(lines.slice(b.start, b.end).join('\n'), 'utf8').digest('hex');
  assert.equal(digest, SECTION_SHA256, 'the 1.1.2 section changed; if intended, move SECTION_SHA256 in the same commit');
});
