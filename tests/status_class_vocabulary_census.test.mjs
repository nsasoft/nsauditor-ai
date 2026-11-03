// tests/status_class_vocabulary_census.test.mjs
//
// NOTHING IN COMMUNITY CONSUMES ENTERPRISE'S GRC STATUS-CLASS VOCABULARY (EE board B158's Community half; the release
// paired with Enterprise 2.1.2).
//
// Enterprise 2.1.2 adds a sixth value, '3xx', to the `statusClass` its GRC push writes into each push-audit row
// (nsauditor.grc-push-audit/v1), a change ruled a PATCH because the vocabulary is consumed nowhere but the module that
// defines it. Enterprise's CHANGELOG says "nothing in Enterprise or Community enumerates the values"; Enterprise holds its
// own half by census (EE tests/grc_connector_no_redirect.test.mjs), and this file holds Community's, so the sentence is
// guarded in both repositories rather than measured once. Deny-by-default over the shipped tree (package.json `files`),
// comments and strings blanked: no module names STATUS_CLASSES, classifyStatus or statusClass, and no reference document
// (README.md, docs/*.md) names the field. The CHANGELOG is a release record, outside the census.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { stripCommentsAndStrings } from './support/strip_comments_and_strings.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const NAMES = /(?<![\w$])(?:STATUS_CLASSES|classifyStatus|statusClass)(?![\w$])/;
const names = (src) => NAMES.test(stripCommentsAndStrings(src));

test('(control, first) the census sees a consumer: an import, a switch over the field, a call — and not prose', () => {
  assert.ok(names("import { STATUS_CLASSES } from '@nsasoft/nsauditor-ai-ee';"));
  assert.ok(names("switch (row.statusClass) { case '2xx': break; }"));
  assert.ok(names('const c = classifyStatus(res.status);'));
  assert.ok(!names("// statusClass in a comment\nconst s = 'statusClass in a string';"));
});

test('no shipped module names the status classes', () => {
  const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
  const hits = [];
  const walk = (rel) => {
    const abs = path.join(ROOT, rel);
    if (!fs.existsSync(abs)) return;
    if (fs.statSync(abs).isDirectory()) { for (const e of fs.readdirSync(abs)) walk(path.join(rel, e)); return; }
    if (/\.(?:mjs|js|cjs)$/.test(rel) && names(fs.readFileSync(abs, 'utf8'))) hits.push(rel);
  };
  for (const entry of pkg.files) walk(entry.replace(/\/$/, ''));
  assert.deepEqual(hits, []);
});

test('no reference document names the field', () => {
  const docs = ['README.md', ...fs.readdirSync(path.join(ROOT, 'docs')).filter((f) => f.endsWith('.md')).map((f) => path.join('docs', f))];
  assert.deepEqual(docs.filter((d) => /statusClass|STATUS_CLASSES/.test(fs.readFileSync(path.join(ROOT, d), 'utf8'))), []);
});
