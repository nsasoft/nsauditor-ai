import { test } from 'node:test';
import assert from 'node:assert/strict';

test('result_concluder: an Enterprise plugin id that CE does not hold resolves to no adapter, without error', async () => {
  // 1.2.1: adapters resolve by plugin id (the manager's registry, then the concluder's own directory). Without the
  // Enterprise package, 1023 is in neither, so its result takes the fallback record — here a port-0 assessment, which
  // is evidence and never a service.
  const { default: concluder } = await import('../plugins/result_concluder.mjs');
  const c = await concluder.run([{ id: '1023', name: 'Zero Trust Assessment',
    result: { up: true, data: [{ probe_protocol: 'assessment', probe_port: 0, probe_info: 'Score: 72/100' }] } }]);
  assert.deepEqual(c.services, []);
  assert.ok(c.evidence.some((e) => e.protocol === 'assessment'));
});

test('result_concluder: module loads cleanly', async () => {
  // The module builds its adapter registry lazily, on the first run — importing it does nothing else.
  await assert.doesNotReject(
    () => import('../plugins/result_concluder.mjs'),
    'result_concluder should import without errors'
  );
});
