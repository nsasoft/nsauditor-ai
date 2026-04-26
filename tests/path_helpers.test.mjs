import test from 'node:test';
import assert from 'node:assert/strict';

import { toCleanPath } from '../utils/path_helpers.mjs';

// ---------------------------------------------------------------------------
// toCleanPath — generic path normalization helper
//
// History: previously duplicated in cli.mjs:47 (used by AI provider model env
// vars + scan-history outRoot resolution) and utils/output_dir.mjs:21 (used
// by resolveBaseOutDir). Consolidated to utils/path_helpers.mjs in v0.1.20
// (Task N.20).
// ---------------------------------------------------------------------------

test('toCleanPath: nullish input returns empty string', () => {
  assert.equal(toCleanPath(null), '');
  assert.equal(toCleanPath(undefined), '');
});

test('toCleanPath: empty string passes through as empty', () => {
  assert.equal(toCleanPath(''), '');
});

test('toCleanPath: plain path passes through unchanged', () => {
  assert.equal(toCleanPath('/tmp/scan'), '/tmp/scan');
  assert.equal(toCleanPath('out'), 'out');
  assert.equal(toCleanPath('reports/2026'), 'reports/2026');
});

test('toCleanPath: strips surrounding double quotes', () => {
  assert.equal(toCleanPath('"/tmp/scan"'), '/tmp/scan');
});

test('toCleanPath: strips surrounding single quotes', () => {
  assert.equal(toCleanPath("'/tmp/scan'"), '/tmp/scan');
});

test('toCleanPath: strips multiple layers of stacked quotes', () => {
  assert.equal(toCleanPath('""path""'), 'path');
  assert.equal(toCleanPath(`'"mixed"'`), 'mixed');
  assert.equal(toCleanPath(`""""""triple""""""`), 'triple');
});

test('toCleanPath: trims surrounding whitespace', () => {
  assert.equal(toCleanPath('  /tmp/scan  '), '/tmp/scan');
  assert.equal(toCleanPath('\t/tmp/scan\n'), '/tmp/scan');
});

test('toCleanPath: only trims outer whitespace — preserves internal whitespace', () => {
  assert.equal(toCleanPath('  /a b/c  '), '/a b/c');
});

test('toCleanPath: trims whitespace BEFORE stripping quotes (not after)', () => {
  // This documents the intentional ordering: trim() runs first, then quote-strip.
  // So `  "path"  ` → trim → `"path"` → quote-strip → `path`.
  assert.equal(toCleanPath('  "/tmp/scan"  '), '/tmp/scan');
});

test('toCleanPath: number coerces to string then cleans', () => {
  assert.equal(toCleanPath(42), '42');
  assert.equal(toCleanPath(0), '0');
});

test('toCleanPath: object with toString gets coerced', () => {
  assert.equal(toCleanPath({ toString: () => '/tmp/x' }), '/tmp/x');
});

test('toCleanPath: all-quote input becomes empty string', () => {
  assert.equal(toCleanPath('""""'), '');
  assert.equal(toCleanPath("''''"), '');
});

test('toCleanPath: internal quotes are preserved (only ends trimmed)', () => {
  // Embedded quotes in middle of path stay (rare edge case but defined behavior)
  assert.equal(toCleanPath('/a"b/c'), '/a"b/c');
  assert.equal(toCleanPath("/a'b/c"), "/a'b/c");
});
