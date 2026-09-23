// KEEP THE SUITE OFF THE OPERATOR'S REAL macOS KEYCHAIN.
//
// ⚠️ THE DEFECT THIS CLOSES, MEASURED. `loadLicense` calls `_writeLicenseState`, which writes
// `NSAUDITOR_LICENSE_ID` into the operator's login keychain on EVERY verified load
// (`utils/license.mjs`:468). TWELVE CE test files reach it.
// IN-PROCESS (25 writes): run_record_kev_epss ×7 · scan_history_dotted_out ×6 ·
// run_record_producer_contract ×3 · cli_version_flag ×2 · license_resolver ×2 ·
// mcp_env_file_shim ×2 · license_keychain_indirection ×1 · scan_history_finding_definition ×1 ·
// validate ×1. THROUGH A SPAWNED CLI (29 writes): cli_license_plugins ×16 ·
// cli_license_install ×8 · cli_license ×5. Confirmed under a pass-through `security` shim
// (run_record_kev_epss alone: 7).
//
// ⚠️ THE LAST THREE WERE MISSED BY THE FIRST ATTRIBUTION, FOR THE REASON THIS ITEM IS ABOUT.
// They were invisible to a REPLACEMENT shim: one that stands in for `security` and answers every
// read itself. Answering "not found" (or a fake value) starves the spawned CLI of a valid licence,
// so it never reaches `_writeLicenseState` and never writes — and the call site vanishes from the
// measurement along with the write. **A replacement shim measures the code under the keychain it
// invents, not under the operator's.** The nine that WERE seen load the licence by a path that
// shim did not starve. The instrument for "what does this suite do to the operator's keychain" is
// a PASS-THROUGH logger — log, then `exec /usr/bin/security` — which is what found these.
// (An earlier miss in the same lane DID have the env-var cause — a shim whose log path came from
// an env var, dying inside a child with a rebuilt env — and it is a different defect; this comment
// named that one until the reviewing seat corrected it from their own transcript.)
// They were also invisible to running each file ALONE. What FOUND them
// was the acceptance check itself: after folding the nine, `NSAUDITOR_LICENSE_ID`'s modification
// time STILL MOVED across a full suite run (000117Z → 000537Z), and the writers were then
// attributed by logging the GRANDPARENT process of every `add-generic-password`.
// **A fold verified only over the files you set out to fix is verified against your own list.**
//
// All twelve wrote the operator's own id, so nothing broke; the hazard is one fixture away. A test that loads a licence with a
// DIFFERENT `licenseId` writes THAT to the operator's keychain, and their next real load returns
// `license_id_mismatch` — refused BEFORE the state is rewritten, so it does NOT self-heal.
//
// ⚠️ THE MECHANISM ALREADY EXISTED AND NOTHING USED IT. `_writeLicenseState` skips the keychain
// when `NSAUDITOR_LICENSE_STATE_FILE` is set, symmetric with the read-side skip at :419, and the
// comment beside them already says "no test should write to the operator's real Keychain, and no
// test should read from it either". This module is only the nine files finally setting it.
//
// ⚠️ WHY AN ENV AND NOT AN INJECTED SEAM. A seam is an ARGUMENT and cannot cross a process
// boundary; several of these files SPAWN the CLI. An env var is inherited, so one assignment
// covers the in-process loads and the spawned ones together. (`_keychainSet` cannot, which is the
// same lesson the MCP-auth spawn path teaches one directory over.)
//
// ⚠️ IMPORT THIS FIRST. ESM evaluates import declarations in textual order, so as the first import
// of a test file this runs before any other module's top-level code — including any that loads a
// licence while being imported. Placing the assignment in the test file's own body would be too
// late for that case.
//
// `??=` so an outer harness that has already chosen a state file keeps it.
import os from 'node:os';
import path from 'node:path';

process.env.NSAUDITOR_LICENSE_STATE_FILE ??= path.join(
  os.tmpdir(), `nsa-license-state-test-${process.pid}.json`);
