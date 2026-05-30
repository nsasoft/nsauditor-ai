import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scopeSelectionForProviders } from '../utils/sentinel_scope.mjs';

const sel = [
  { id: '1', cloudProvider: 'aws' },
  { id: '2', cloudProvider: 'gcp' },
  { id: '3', cloudProvider: 'azure' },
  { id: '4' }, // network plugin, no cloudProvider
];

test('single provider selects only that cloud', () => {
  const r = scopeSelectionForProviders(sel, ['aws']);
  assert.deepEqual(r.selected.map((p) => p.id), ['1']);
  assert.deepEqual(r.skipped.map((p) => p.id), ['2', '3', '4']);
});

test('multiple providers select the union', () => {
  const r = scopeSelectionForProviders(sel, ['aws', 'azure']);
  assert.deepEqual(r.selected.map((p) => p.id).sort(), ['1', '3']);
});

test('network plugins (no cloudProvider) are always skipped', () => {
  const r = scopeSelectionForProviders(sel, ['aws', 'gcp', 'azure']);
  assert.deepEqual(r.selected.map((p) => p.id), ['1', '2', '3']);
  assert.deepEqual(r.skipped.map((p) => p.id), ['4']);
});

test('empty providers selects nothing', () => {
  const r = scopeSelectionForProviders(sel, []);
  assert.deepEqual(r.selected, []);
});

test('case/whitespace-insensitive provider matching', () => {
  const r = scopeSelectionForProviders(sel, [' AWS ']);
  assert.deepEqual(r.selected.map((p) => p.id), ['1']);
});
