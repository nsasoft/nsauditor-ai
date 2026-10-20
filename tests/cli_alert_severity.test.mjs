// tests/cli_alert_severity.test.mjs
// ─────────────────────────────────────────────────────────────────────────────
// `--alert-severity` IS VALIDATED — AN UNRECOGNISED VALUE IS REFUSED, NEVER APPLIED AS `high` IN SILENCE (CE #11).
//
// The flag lower-cased any value and an unrecognised one (a typo — `critial`) silently became `high`, the alert path's
// fallback rank, while the alert itself echoed the typo: documented as a limit, and a refusal is what every other value
// flag gives. The accepted values are the alert path's own rank table — critical, high, medium, low, info — in any case;
// absent is `high`, as before; a bare flag or any other value throws EFLAGVALUE (exit 2, one [ERROR] line).
//
// FOURTH QUADRANT FIRST: absent stays `high`, and every accepted value, in any case, is accepted.
// ─────────────────────────────────────────────────────────────────────────────
import './helpers/no_operator_dotenv.mjs';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseArgs } from '../cli.mjs';

const argv = (...a) => ['node', 'cli.mjs', 'scan', '--host', '192.0.2.1', ...a];

test('(first) absent is high; every accepted value, in any case, is accepted lower-cased', async () => {
  assert.equal((await parseArgs(argv())).alertSeverity, 'high');
  for (const [given, want] of [['critical', 'critical'], ['HIGH', 'high'], ['Medium', 'medium'], ['low', 'low'], ['INFO', 'info']]) {
    assert.equal((await parseArgs(argv('--alert-severity', given))).alertSeverity, want, given);
  }
});

test('an unrecognised value, and a bare flag, are refused — never applied as high', async () => {
  for (const args of [argv('--alert-severity', 'critial'), argv('--alert-severity', 'severe'), argv('--alert-severity')]) {
    const err = await parseArgs(args).then(() => null, (e) => e);
    assert.deepEqual([err?.code, err?.message], ['EFLAGVALUE', '--alert-severity must be one of critical | high | medium | low | info'],
      args.slice(5).join(' '));
  }
});
