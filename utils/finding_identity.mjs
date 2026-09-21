/**
 * ONE canonical `resource`, shared by every channel that identifies a finding across runs.
 *
 * Two such channels ship, and before E1 they derived this noun independently:
 *   · CE's cross-run delta  (`report --since`)      — `utils/scan_delta.mjs`'s `keyOf`
 *   · EE's SLA/MTTR tracker (`--compliance-history`) — `utils/mttr_engine.mjs`'s fingerprint
 * Two channels deriving the same noun two ways is the C10 defect one noun down, and its cost is
 * concrete: an assessor can be shown one report where a finding is "resolved" and another where
 * it is "unchanged", for the same finding on the same estate.
 *
 * ⚠️ THIS CANONICALISES THE NOUN, NOT THE KEY. Each channel keeps its OWN composition, and that
 * is deliberate rather than an omission — they ask different questions. The delta asks *what
 * changed* and needs `contentDigest` in its key; the tracker asks *how long has this been open*
 * and must NOT reset a remediation clock because some prose it does not key on was reworded.
 * Sharing the whole key would import each channel's sensitivities into the other.
 *
 * WHY A CANONICALISER EXISTS AT ALL — the decoration it removes was manufactured downstream of
 * every producer. `utils/aws_region_scan.mjs::_stampRegion` (EE) rewrote `resource` on every
 * finding routed through `forEachRegion`: a finding WITHOUT a resource got the region itself as
 * its object identity, and a finding WITH one got ` [<region>]` appended. E1 stops both, but the
 * published CE 0.2.54 already wrote baselines carrying the decorated values — and
 * `RUN_RECORD_SCHEMA` is 1 on both sides, so those baselines are COMPARABLE by declaration. This
 * function is what makes that declaration true for every producer that already named its object.
 */

/**
 * @param {unknown} resource — the raw `resource` as the producer (or the stamper) left it.
 * @param {unknown} region   — the finding's OWN region, from its own field. Never a default:
 *   without it nothing can be decoration, and guessing one would strip a real name.
 * @returns {string|null} the canonical resource, or null when it is not an object identity.
 */
export function canonicaliseResource(resource, region) {
  if (typeof resource !== 'string') return null;

  // ⚠️ THE REGION-UNKNOWN PATH, and it is not a convenience — without it this function
  // reintroduces the defect it exists to prevent, on the channel that needed it first.
  // EE's MTTR tracker fingerprints PRIOR scans from their stored `scan_compliance_*.json`
  // violations, and that shape has no `region`: measured over the 1.1.0 evidence tree, 3735
  // violations, all with `resource`, ZERO with `region`. So on the prior side the exact rule
  // below can never fire, a decorated prior written by the published build never matches a
  // clean current, every lifecycle restarts and the SLA section reports mass remediation that
  // did not happen.
  //
  // A trailing bracketed token of STRICT REGION SHAPE is therefore treated as decoration when
  // the region is unknowable. The shape is tight because the alphabet was DERIVED from the real
  // records rather than imagined: bracketed suffixes there are `[us-east-1]` ×286, and also
  // `[target-1]` ×32, `[1022]`, `[1021]`, `[1030]`, `[1020]` and `[ERROR]` — none of them
  // decoration, every one of them eaten by a loose "strip any trailing bracket" rule. Two alpha
  // groups and a trailing number are required, which is what separates `us-east-1` from
  // `target-1`.
  //
  // Rule 2 is deliberately NOT applied here: with no region to compare against, a resource of
  // `us-east-1` is indistinguishable from an object legitimately so named, and leaving identity
  // alone is the safe direction where nulling it is not.
  if (typeof region !== 'string' || region.length === 0) {
    const m = /^(.*?) \[[a-z]{2}(?:-gov|-iso[a-z]?)?-[a-z]+-\d{1,2}\]$/.exec(resource);
    return m ? m[1] : resource;
  }

  // Rule 2 — the resource IS the region: `_stampRegion`'s missing-resource branch claimed a
  // region as the thing a finding was about. That is scope, not an object, so it is not an
  // identity. Checked first: it is the stronger statement of the two.
  if (resource === region) return null;

  // Rule 1 — a TRAILING bracketed suffix equal to this finding's own region is decoration.
  // Trailing and bracketed and region-equal, all three: an ARN contains its region, a bucket may
  // be NAMED for one, and a producer may legitimately qualify a scope literal with one. Matching
  // any of those would collapse distinct objects onto one key, which is the masking this lane
  // exists to close — and over-stripping is the worse direction, because it is silent.
  const suffix = ` [${region}]`;
  if (resource.endsWith(suffix)) return resource.slice(0, -suffix.length);

  return resource;
}
