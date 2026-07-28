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

// ── A VERSION-NAMED OUTPUT DIRECTORY IS A DIRECTORY, NOT A FILE ────────────────
//
// Found by the EE 0.32.8 pre-publish smoke gate, running the exact command an
// operator would: `--out .../audit-evidence-samples/ee-0.32.8`. Every artifact
// silently landed in `audit-evidence-samples/` instead — because `path.parse`
// reports `ext: '.8'` for `ee-0.32.8`, and the file-vs-directory heuristic reads
// any extension as "this is a file, use its parent".
//
// It fails on precisely the naming convention this project uses for its own
// evidence archives (`ee-0.32.7`, `ee-0.32.5`, … all exist in that folder), plus
// `v1.2.3` and `release-2026.07`. It is silent: no warning, exit 0, artifacts
// written somewhere the operator did not ask for — the worst shape for a flag
// whose whole job is to say where the evidence goes.
//
// The rule: an extension is only file-like if it STARTS WITH A LETTER. A numeric
// trailing segment is a version component, never a file type.

test('resolveBaseOutDir: a version-named dir is NOT mistaken for a file', () => {
  for (const dir of [
    '/tmp/evidence/ee-0.32.8',      // this repo's own evidence-archive convention
    '/tmp/evidence/v1.2.3',
    '/tmp/evidence/release-2026.07',
    '/tmp/evidence/2026.07.28',
  ]) {
    withEnv({ SCAN_OUT_PATH: dir }, () => {
      assert.equal(resolveBaseOutDir(), dir,
        `${dir} is a directory; a numeric trailing segment is a version, not a file extension. ` +
        'Returning the parent silently scatters evidence into a shared folder.');
    });
  }
});

// The other direction, so the fix cannot be "always treat it as a directory" —
// that would break the documented `--out report.json` affordance.
test('resolveBaseOutDir: a real file extension still resolves to the parent dir', () => {
  for (const [given, expected] of [
    ['/tmp/evidence/report.json', '/tmp/evidence'],
    ['/tmp/evidence/scan.html',   '/tmp/evidence'],
    ['/tmp/evidence/out.csv',     '/tmp/evidence'],
    ['/tmp/evidence/f.sarif',     '/tmp/evidence'],
  ]) {
    withEnv({ SCAN_OUT_PATH: given }, () => {
      assert.equal(resolveBaseOutDir(), expected,
        `${given} names a file — its parent directory is the output base`);
    });
  }
});
