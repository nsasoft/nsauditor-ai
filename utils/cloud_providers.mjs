// THE CLOUD-PROVIDER VOCABULARY, IN ONE PLACE, BECAUSE IT HAS TWO READERS IN TWO REPOSITORIES.
//
// A cloud scan addresses its provider as the HOST — `nsauditor-ai scan --host aws` writes a run
// directory named `aws_<timestamp>` and a run record whose `hostsWritten[].host` is the literal
// string `aws`. That makes the provider name a vocabulary, and a vocabulary with two copies is a
// vocabulary that drifts.
//
// ⚠️ IT LIVED IN `scan_delta.mjs` AS A PRIVATE CONST UNTIL EE NEEDED IT TOO, and the obvious
// alternative was for Enterprise's CPE mapper to import the delta engine for one literal — a
// PRODUCER importing a CONSUMER, to learn a fact that belongs to neither. The other alternative
// was a second list in EE, which is the shape this file exists to prevent.
//
// ⚠️ ONE LIST, NOT TWO. The host set is DERIVED from the unit map's keys rather than written
// beside it, so there is no second place to forget. Adding a provider means adding its coverage
// unit, and the host set follows.

/**
 * The coverage unit each provider resolves. A provider scan's scope is recorded in these terms,
 * and the cross-run delta refuses to call a finding fixed or new when its unit was outside the
 * other run's recorded scope.
 */
export const PROVIDER_SCOPE_UNIT = Object.freeze({
  aws: 'region',
  azure: 'subscription',
  gcp: 'project',
});

/**
 * The hosts that ARE a cloud provider rather than a network target. Derived from the unit map.
 *
 * Used to answer "is this scan addressing an estate or an address?" — a question with different
 * right answers for the same code. Enterprise's CPE mapper asks it because a cloud scan produces
 * no services BY CONSTRUCTION (cloud envelopes carry no port-bearing rows), so on a cloud host an
 * empty service set is not evidence of anything and an upstream that failed there was never an
 * upstream of the mapper at all.
 */
export const CLOUD_PROVIDER_HOSTS = Object.freeze(Object.keys(PROVIDER_SCOPE_UNIT));

/**
 * Is this host a cloud provider?
 *
 * Case- and whitespace-insensitive because it is applied to a value that reaches the record from
 * a command line. Anything that is not a declared provider is a network target — the safe
 * direction: a misspelling reads as a network host, where the mapper's questions all still apply.
 *
 * @param {unknown} host
 * @returns {boolean}
 */
export function isCloudProviderHost(host) {
  return typeof host === 'string'
    && Object.hasOwn(PROVIDER_SCOPE_UNIT, host.trim().toLowerCase());
}
