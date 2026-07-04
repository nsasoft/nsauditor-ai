// utils/sentinel_scope.mjs
//
// Sentinel-host plugin scoping. When the scan target is a cloud-sentinel host
// (`aws`/`gcp`/`azure`) and the plugin selection is the IMPLICIT `all`, run only
// the plugins tagged with that provider (`plugin.cloudProvider`), skipping the
// other clouds + the non-cloud network plugins (which would otherwise probe the
// literal string "aws" and emit unreachable-host noise).
//
// scopeSelectionForHost honors an EXPLICIT plugin selection as-is (it only scopes
// the implicit `all`). The CLOUD-INTENT contract itself, however, is NOT waivable
// by explicit selection: excludeMismatchedCloudPlugins (BUG2b) strips any cloud
// auditor whose cloudProvider does not match the host's sentinel — including an
// explicitly-listed foreign-cloud plugin and every cloud plugin on a network host.
// '--host' is the sole cloud-scan trigger; credentials/selection are not intent.

export const CLOUD_SENTINEL_HOSTS = new Set(['aws', 'gcp', 'azure']);

export function isCloudSentinelHost(host) {
  return typeof host === 'string' && CLOUD_SENTINEL_HOSTS.has(host.trim().toLowerCase());
}

// spec is the ORIGINAL plugin spec ('all' | undefined | null → implicit;
// array or CSV string → explicit). Only the implicit case is scoped.
function isImplicitAll(spec) {
  if (spec == null) return true;
  if (typeof spec === 'string') return spec.trim().toLowerCase() === 'all';
  return false; // arrays are always explicit
}

/**
 * @param {Array<object>} selection  resolved plugin objects (each may have .cloudProvider)
 * @param {string} host
 * @param {string|string[]} spec      original selection spec
 * @returns {{selected: object[], skipped: object[], scoped: boolean, provider: string|null}}
 */
export function scopeSelectionForHost(selection, host, spec) {
  if (!isCloudSentinelHost(host) || !isImplicitAll(spec)) {
    return { selected: selection, skipped: [], scoped: false, provider: null };
  }
  const provider = host.trim().toLowerCase();
  const selected = [];
  const skipped = [];
  for (const p of selection) {
    if (p && p.cloudProvider === provider) selected.push(p);
    else skipped.push(p);
  }
  return { selected, skipped, scoped: true, provider };
}

/**
 * BUG2(b) (operator-confirmed contract 2026-07-03): the INVERSE of
 * scopeSelectionForHost — a cloud auditor plugin runs IF AND ONLY IF the host is
 * ITS OWN cloud sentinel. `--host` is the sole cloud-intent signal; credentials
 * in the environment are a capability, never intent; there is NO escape hatch
 * (not the implicit `all`, not an explicit `--plugins 1020` selection).
 *
 * Strips every cloud-tagged plugin whose `cloudProvider` does NOT match the
 * host's sentinel:
 *   - NETWORK host (IP / CIDR / hostname → sentinel === null): ALL cloud plugins
 *     are foreign → all stripped (the reported router-scan bug).
 *   - SENTINEL host P (aws/gcp/azure): a foreign-cloud plugin (e.g. an AWS
 *     auditor explicitly selected on `--host gcp`) is stripped; P's own plugins
 *     and non-cloud plugins are kept. (Complements scopeSelectionForHost, which
 *     only scopes the implicit `all` — this also covers explicit selections.)
 *
 * @param {Array<object>} selection  resolved plugin objects (each may have .cloudProvider)
 * @param {string} host
 * @returns {{selected: object[], skipped: object[], sentinel: string|null, excludedCloud: boolean}}
 */
export function excludeMismatchedCloudPlugins(selection, host) {
  const sentinel = isCloudSentinelHost(host) ? String(host).trim().toLowerCase() : null;
  const selected = [];
  const skipped = [];
  for (const p of selection) {
    // non-cloud plugins (no cloudProvider) always survive; a cloud plugin
    // survives only when the host IS its sentinel.
    if (p && p.cloudProvider && p.cloudProvider !== sentinel) skipped.push(p);
    else selected.push(p);
  }
  return { selected, skipped, sentinel, excludedCloud: skipped.length > 0 };
}

/**
 * Multi-cloud generalization of scopeSelectionForHost: scope a resolved plugin
 * selection to the union of the given providers (by each plugin's cloudProvider
 * field). Used by pluginManager.runCloud() / the MCP scan_cloud tool. Network
 * plugins (no cloudProvider) and non-requested clouds land in `skipped`.
 *
 * @param {Array<object>} selection  resolved plugin objects (each may have .cloudProvider)
 * @param {string[]} providers       e.g. ['aws'] or ['aws','azure']
 * @returns {{selected: object[], skipped: object[], providers: string[]}}
 */
export function scopeSelectionForProviders(selection, providers) {
  const set = new Set((providers || []).map((p) => String(p).trim().toLowerCase()));
  const selected = [];
  const skipped = [];
  for (const p of selection) {
    if (p && p.cloudProvider && set.has(p.cloudProvider)) selected.push(p);
    else skipped.push(p);
  }
  return { selected, skipped, providers: [...set] };
}
