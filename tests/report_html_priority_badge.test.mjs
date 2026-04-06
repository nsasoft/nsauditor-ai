// tests/report_html_priority_badge.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildHtmlReport } from '../utils/report_html.mjs';

test('Priority tokens render as colored badges', async () => {
  const md = `## Plan\n- Priority: High`;
  const html = await buildHtmlReport({
    host: '1.2.3.4',
    whenIso: '2025-01-01T00:00:00Z',
    model: 'test-model',
    md
  });
  assert.ok(html.includes('<span class="badge badge-high">High</span>'));
});
