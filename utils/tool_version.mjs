// utils/tool_version.mjs
//
// Single source of truth for the nsauditor-ai package version, resolved at
// module-load time from package.json via createRequire.
//
// Why a dedicated module:
//   - process.env.npm_package_version is ONLY set when invoked via `npm run`.
//     When users invoke through the bin shim (the normal install path) it's
//     undefined, which silently produced empty version fields in rendered
//     reports prior to v0.1.16 (see Task N.15 / N.6 review).
//   - Centralizing the resolution avoids each consumer reinventing the
//     pattern (or inventing a broken version of it).

import { createRequire } from 'node:module';

const _require = createRequire(import.meta.url);
const _pkg = _require('../package.json');

/**
 * The nsauditor-ai package version, e.g. "0.1.16".
 * Resolved from package.json — independent of how the process was invoked.
 * @type {string}
 */
export const TOOL_VERSION = _pkg.version;

/**
 * The nsauditor-ai package name, e.g. "nsauditor-ai".
 * @type {string}
 */
export const TOOL_NAME = _pkg.name;
