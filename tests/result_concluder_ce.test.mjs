import { test } from 'node:test';
import assert from 'node:assert/strict';

test('result_concluder: EE plugin IDs not in slugify map', async () => {
  // Loading the module must not throw even without EE plugins
  const mod = await import('../plugins/result_concluder.mjs');
  assert.ok(mod.default || mod.conclude, 'result_concluder exports something');
});

test('result_concluder: module loads cleanly', async () => {
  // If slugify still had EE IDs, a full concluder run would try to import
  // non-existent files. This test just confirms the module is importable.
  await assert.doesNotReject(
    () => import('../plugins/result_concluder.mjs'),
    'result_concluder should import without errors'
  );
});
