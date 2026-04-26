import test from 'node:test';
import assert from 'node:assert/strict';

import { resolveBaseOutDir } from '../utils/output_dir.mjs';

// Save & restore env across tests so they don't leak state into each other
function withEnv(overrides, fn) {
  const saved = {
    SCAN_OUT_PATH: process.env.SCAN_OUT_PATH,
    OPENAI_OUT_PATH: process.env.OPENAI_OUT_PATH,
  };
  // Clear both first so the test starts from a known base
  delete process.env.SCAN_OUT_PATH;
  delete process.env.OPENAI_OUT_PATH;
  for (const [k, v] of Object.entries(overrides)) {
    if (v == null) delete process.env[k];
    else process.env[k] = v;
  }
  try {
    return fn();
  } finally {
    for (const [k, v] of Object.entries(saved)) {
      if (v == null) delete process.env[k];
      else process.env[k] = v;
    }
  }
}

// ---------------------------------------------------------------------------
// resolveBaseOutDir — env priority and defaults
// ---------------------------------------------------------------------------

test('resolveBaseOutDir: defaults to "out" when no env vars set', () => {
  withEnv({}, () => {
    assert.equal(resolveBaseOutDir(), 'out');
  });
});

test('resolveBaseOutDir: honors SCAN_OUT_PATH', () => {
  withEnv({ SCAN_OUT_PATH: '/tmp/scan' }, () => {
    assert.equal(resolveBaseOutDir(), '/tmp/scan');
  });
});

test('resolveBaseOutDir: honors OPENAI_OUT_PATH (legacy fallback)', () => {
  withEnv({ OPENAI_OUT_PATH: '/tmp/legacy' }, () => {
    assert.equal(resolveBaseOutDir(), '/tmp/legacy');
  });
});

test('resolveBaseOutDir: SCAN_OUT_PATH wins over OPENAI_OUT_PATH when both set', () => {
  withEnv({ SCAN_OUT_PATH: '/tmp/new', OPENAI_OUT_PATH: '/tmp/legacy' }, () => {
    assert.equal(resolveBaseOutDir(), '/tmp/new');
  });
});

test('resolveBaseOutDir: empty SCAN_OUT_PATH falls through to OPENAI_OUT_PATH', () => {
  withEnv({ SCAN_OUT_PATH: '', OPENAI_OUT_PATH: '/tmp/legacy' }, () => {
    assert.equal(resolveBaseOutDir(), '/tmp/legacy');
  });
});

test('resolveBaseOutDir: both env vars empty → default "out"', () => {
  withEnv({ SCAN_OUT_PATH: '', OPENAI_OUT_PATH: '' }, () => {
    assert.equal(resolveBaseOutDir(), 'out');
  });
});

// ---------------------------------------------------------------------------
// resolveBaseOutDir — path normalization
// ---------------------------------------------------------------------------

test('resolveBaseOutDir: strips surrounding double quotes', () => {
  withEnv({ SCAN_OUT_PATH: '"/tmp/quoted"' }, () => {
    assert.equal(resolveBaseOutDir(), '/tmp/quoted');
  });
});

test('resolveBaseOutDir: strips surrounding single quotes', () => {
  withEnv({ SCAN_OUT_PATH: "'/tmp/quoted'" }, () => {
    assert.equal(resolveBaseOutDir(), '/tmp/quoted');
  });
});

test('resolveBaseOutDir: trims surrounding whitespace', () => {
  withEnv({ SCAN_OUT_PATH: '  /tmp/scan  ' }, () => {
    assert.equal(resolveBaseOutDir(), '/tmp/scan');
  });
});

test('resolveBaseOutDir: file path → returns parent directory', () => {
  withEnv({ SCAN_OUT_PATH: '/tmp/scan/report.json' }, () => {
    assert.equal(resolveBaseOutDir(), '/tmp/scan');
  });
});

test('resolveBaseOutDir: bare filename with extension → defaults to "out"', () => {
  // path.parse('report.json') gives { dir: '', ext: '.json' } — falls back to 'out'
  withEnv({ SCAN_OUT_PATH: 'report.json' }, () => {
    assert.equal(resolveBaseOutDir(), 'out');
  });
});

test('resolveBaseOutDir: relative directory passes through unchanged', () => {
  withEnv({ SCAN_OUT_PATH: 'reports/2026' }, () => {
    assert.equal(resolveBaseOutDir(), 'reports/2026');
  });
});

test('resolveBaseOutDir: directory with no extension treated as directory', () => {
  withEnv({ SCAN_OUT_PATH: '/tmp/scan-dir' }, () => {
    assert.equal(resolveBaseOutDir(), '/tmp/scan-dir');
  });
});

test('resolveBaseOutDir: re-reads env on each call (not cached at module load)', () => {
  // Critical: the CLI sets SCAN_OUT_PATH AFTER module load (during arg parsing).
  // The helper must read env on every invocation, not cache the value.
  withEnv({}, () => {
    assert.equal(resolveBaseOutDir(), 'out');
  });
  withEnv({ SCAN_OUT_PATH: '/tmp/dynamic' }, () => {
    assert.equal(resolveBaseOutDir(), '/tmp/dynamic');
  });
  withEnv({}, () => {
    assert.equal(resolveBaseOutDir(), 'out');
  });
});

// toCleanPath tests live in tests/path_helpers.test.mjs as of v0.1.20.
