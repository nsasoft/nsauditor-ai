// utils/sentinel_scope.mjs
//
// Sentinel-host plugin scoping. When the scan target is a cloud-sentinel host
// (`aws`/`gcp`/`azure`) and the plugin selection is the IMPLICIT `all`, run only
// the plugins tagged with that provider (`plugin.cloudProvider`), skipping the
// other clouds + the non-cloud network plugins (which would otherwise probe the
// literal string "aws" and emit unreachable-host noise). Explicit plugin
// selections are always honored as-is.

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
