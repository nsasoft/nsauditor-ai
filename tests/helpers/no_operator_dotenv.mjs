// tests/helpers/no_operator_dotenv.mjs
// IMPORT THIS FIRST in any test that imports cli.mjs (or bin/nsauditor-ai.mjs), and give every CLI child it spawns an
// env built with withNoDotenv() — tests/no_operator_dotenv_census.test.mjs holds both rules.
//
// WHY. cli.mjs line 2 is `import 'dotenv/config'`, which loads `.env` from the process CWD at import time. The operator's
// checkout carries an untracked `.env` that turns AI sending on with real provider keys, so before this helper existed
// every sequential suite run from the checkout sent 39 real AI requests (loopback-fixture scans, the operator's key) —
// and a worktree, which carries no `.env`, ran a different suite. Static imports are evaluated in source order, so this
// module only protects an import that comes AFTER it.
//
// WHY THREE SETTINGS. DOTENV_CONFIG_PATH pointed at a file that cannot exist stops dotenv loading anything. It is not
// enough alone: dotenv never overrides a variable that is already set, so an AI switch exported in the operator's SHELL
// survives it — AI_ENABLED='false' wins over both. The two provider keys are deleted as belt and braces.
import os from 'node:os';
import path from 'node:path';

/** A path that cannot exist: its directory is never created. */
export const ABSENT_DOTENV = path.join(os.tmpdir(), `nsa-no-dotenv-${process.pid}`, 'absent.env');

/** Neutralise `env` in place and return it. */
export function neutraliseDotenv(env) {
  env.DOTENV_CONFIG_PATH = ABSENT_DOTENV;
  env.AI_ENABLED = 'false';
  delete env.OPENAI_API_KEY;
  delete env.ANTHROPIC_API_KEY;
  return env;
}

/** The env to hand a spawned CLI: a COPY of `env` (default: this process's) carrying the neutraliser. */
export function withNoDotenv(env = process.env) {
  return neutraliseDotenv({ ...env });
}

neutraliseDotenv(process.env);
