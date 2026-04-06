import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const CLI = resolve(__dirname, '..', 'cli.mjs');

test('cli.mjs parses (node --check)', (t, done) => {
  execFile(process.execPath, ['--check', CLI], (err) => {
    assert.equal(err, null, `node --check failed for ${CLI}`);
    done?.();
  });
});
