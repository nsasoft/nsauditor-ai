// utils/ee_load.mjs — load the Enterprise package, telling "not installed" from "installed and broken" (1.1.1).
//
// ⚠️ PRESENCE IS DECIDED BY RESOLUTION, NEVER BY THE ERROR. The scan path used to import inside a bare `catch {}` read as
// "EE not installed — the ONLY silent case", and every failure landed there: a named import Community does not export
// (Enterprise installed above the Community it runs on — the measured case at EE 174212f), a missing dependency of
// Enterprise's own, a syntax error. The scan then ran with no analysis agents, no CVE mapper and no compliance report,
// said nothing, and the Pro delta read every agent and engine row RESOLVED. An error CODE cannot separate the cases —
// a dependency Enterprise lacks is `ERR_MODULE_NOT_FOUND` too — so the package's MANIFEST is resolved first (see
// `isInstalled`): no manifest is absence, the one silent case; installed-but-the-import-throws is a load failure,
// returned for the caller to report and record.
//
// Seams (tests only): `resolveEE(specifier)` replaces the resolver; `importEE()` replaces the import. An import seam
// with NO resolver means the package is installed — a test that injects a module is describing one that resolves.

export const EE_PACKAGE = '@nsasoft/nsauditor-ai-ee';

// The DEFAULT resolver, as a replaceable dependency: Enterprise resolves from a development checkout, so a test that must
// describe a checkout without it replaces this rather than the environment. Nothing in the product assigns it.
export const resolverDeps = { resolve: (s) => import.meta.resolve(s) };

/**
 * PRESENCE IS THE PACKAGE'S MANIFEST, NEVER ITS ENTRY (the audit seat's T1-c fold 2). Resolving the entry answers "does
 * the entry resolve": a package whose main file is missing (a truncated install) or whose exports map does not serve
 * "." throws at RESOLUTION — measured on node 24 with real packages — and read as absent, which is installed-but-broken
 * one layer down. The manifest resolves for any installed package; an exports map that declines to serve it
 * (ERR_PACKAGE_PATH_NOT_EXPORTED) still proves the package directory is there. Only a manifest that cannot be found at
 * all is absence. (Community's MCP server resolves the same manifest for the compliance matrix.)
 */
function isInstalled(resolve) {
  try { resolve(`${EE_PACKAGE}/package.json`); return true; } catch (err) { return err?.code === 'ERR_PACKAGE_PATH_NOT_EXPORTED'; }
}

/**
 * @param {{ importEE?: () => Promise<object>, resolveEE?: (specifier: string) => string }} [opts]
 * @returns {Promise<{ ee: object|null, loadError: string|null }>}
 */
export async function loadEnterprise({ importEE = null, resolveEE = null } = {}) {
  const resolve = resolveEE ?? (importEE ? null : resolverDeps.resolve);
  if (resolve && !isInstalled(resolve)) return { ee: null, loadError: null };
  try {
    return { ee: await (importEE ?? (() => import(EE_PACKAGE)))(), loadError: null };
  } catch (err) {
    return { ee: null, loadError: String(err?.message ?? err) };
  }
}
