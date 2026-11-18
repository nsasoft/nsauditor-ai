// tests/changelog_deprecation_pointer.test.mjs
// THE 1.1.2 CHANGELOG ENTRY IS A DEPRECATION TARGET, SO IT IS NEVER TRIMMED FROM THIS FILE.
// Every version of nsauditor-ai below 1.1.2 (153 of them, deprecated 2026-11-18) carries the npm notice
// "Security fix — upgrade to nsauditor-ai 1.1.2 or later … Upgrade notes:
// https://github.com/nsasoft/nsauditor-ai/blob/HEAD/CHANGELOG.md (1.1.2 entry)". HEAD is the default branch, so the
// notice resolves only while THIS file, on main, still holds the 1.1.2 entry with its upgrade effect. A trim of old
// entries, a rename of the heading or a cut of its body sends every user of those versions to a page that does not say
// what changed. Move the entry only together with a re-deprecation that points at its new home.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';

const text = fs.readFileSync(new URL('../CHANGELOG.md', import.meta.url), 'utf8');
const HEADING = /^## 1\.1\.2 \(\d{4}-\d{2}-\d{2}\) — security fix: /;
const lines = text.split(/\r?\n/);

function section() {
  const start = lines.findIndex((l) => HEADING.test(l));
  if (start < 0) return null;
  let end = lines.findIndex((l, i) => i > start && l.startsWith('## '));
  if (end < 0) end = lines.length;
  return lines.slice(start + 1, end).join('\n');
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
});
