// THE PROVIDER VOCABULARY — one list, two repositories, and a guard against the second copy.
//
// ⚠️ WHY A FILE FOR THREE EXPORTS. This list had one reader and lived as a private const in
// `scan_delta.mjs`. Enterprise's CPE mapper then needed the same fact — a cloud host has no
// service-feeding upstreams, so an empty service set there is not evidence of anything — and the
// two cheap answers were both the shape this repo keeps paying for: have a PRODUCER import the
// delta engine for one literal, or write the list a second time in EE. The list is now derived in
// one place and imported by both.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { PROVIDER_SCOPE_UNIT, CLOUD_PROVIDER_HOSTS, isCloudProviderHost } from '../utils/cloud_providers.mjs';

test('the host set is DERIVED from the unit map, so there is no second list to forget', () => {
  assert.deepEqual([...CLOUD_PROVIDER_HOSTS].sort(), Object.keys(PROVIDER_SCOPE_UNIT).sort());
  // Every provider must declare a coverage unit: a provider with none would be silently
  // un-scopeable by the delta while still counting as a cloud host here.
  for (const p of CLOUD_PROVIDER_HOSTS) {
    assert.equal(typeof PROVIDER_SCOPE_UNIT[p], 'string');
    assert.ok(PROVIDER_SCOPE_UNIT[p].length > 0, `${p} declares an empty coverage unit`);
  }
});

test('the predicate agrees with membership, for every member', () => {
  for (const p of CLOUD_PROVIDER_HOSTS) assert.equal(isCloudProviderHost(p), true, p);
});

// ⚠️ THE FOURTH QUADRANT, AND IT IS THE LEG THAT MATTERS. A predicate hardwired to `true` passes
// every leg above. These are the hosts that must keep every check a network target gets — and the
// near-misses are deliberate: a scan of a machine NAMED after a provider is still a network scan.
test('FOURTH QUADRANT — a network target is not a provider, however it is spelled', () => {
  for (const host of ['10.0.0.7', 'aws.example.com', 'my-gcp-box', 'azure-vm-1', 'gcpx', 'awsome',
    '', 'localhost', '192.168.1.1', '::1']) {
    assert.equal(isCloudProviderHost(host), false, `${host} must be treated as a network target`);
  }
});

test('a non-string is not a provider, and does not throw', () => {
  for (const v of [null, undefined, 42, {}, [], Symbol.iterator ? undefined : null]) {
    assert.equal(isCloudProviderHost(v), false);
  }
});

// A host reaches this from a command line, so casing and stray whitespace are the normal case,
// not an edge one.
test('provider names are matched case- and whitespace-insensitively', () => {
  for (const v of ['AWS', ' aws', 'aws ', 'Azure', ' GCP ']) {
    assert.equal(isCloudProviderHost(v), true, v);
  }
});

// ⚠️ NOT A PROTOTYPE LOOKUP. `'constructor'`, `'toString'` and friends are inherited on a plain
// object literal, and an `in` or truthiness test would answer TRUE for every one of them — which
// would make a host called `constructor` a cloud provider and silence the mapper on it.
test('an inherited property name is not a provider', () => {
  for (const v of ['constructor', 'toString', 'hasOwnProperty', '__proto__', 'valueOf']) {
    assert.equal(isCloudProviderHost(v), false, v);
  }
});
