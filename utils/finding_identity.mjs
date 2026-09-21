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
 * The shape of a cloud region token. Two to four leading letters, one to three dash-separated
 * alpha groups, a trailing number: `us-east-1` · `us-gov-west-1` · `ap-southeast-2` ·
 * `cn-north-1` · `eusc-de-east-1` (European Sovereign Cloud).
 *
 * ⚠️ IT IS ONLY EVER USED ANCHORED, and that is the load-bearing part. Applied as a SCAN over a
 * resource string it matches **562 of the 1786** stored violation resources in the 1.1.0
 * evidence tree — `s3:bucket:s3-violator-bucket-522412052794` contains `ator-bucket-52` — and
 * every one of those would attribute a fabricated region to a finding.
 *
 * ⚠️ AND ITS FIRST DRAFT WAS DERIVED FROM A SINGLE-REGION CORPUS, so it missed `eusc-de-east-1`
 * and left that suffix decorating identity forever. A shape derived from a corpus that carries
 * one value is a shape nobody has tested.
 */
const REGION_TOKEN = '[a-z]{2,4}(?:-[a-z]+){1,3}-\\d{1,2}';
const TRAILING_REGION_DECORATION = new RegExp(`^(.*?) \\[(${REGION_TOKEN})\\]$`);

/**
 * The region a finding belongs to — the STAMPED FIELD, and deliberately nothing cleverer.
 *
 * ⚠️ TWO RICHER VERSIONS OF THIS FUNCTION WERE SPECIFIED AND BOTH WERE WITHDRAWN BY
 * MEASUREMENT, which is why this one is three lines. The idea was to recover a region for a
 * STORED violation — from the ` [<region>]` decoration, or by parsing an ARN's region field —
 * so that `region` could join the MTTR composite. Measured over the whole evidence tree, all
 * 69,792 stored violations:
 *   · carrying a `region` field ............................ 0
 *   · whose resource EMBEDS a region token ................. 0   → the ARN parse has no occupant
 *   · carrying a ` [<region>]` suffix ...................... 2,873
 *   · whose resource IS a bare region ...................... 5,950 (the basis-bumped producers)
 *   · with no region recoverable by any means ............. 60,959
 * Sixty thousand priors can yield no region at all — mostly producers with an empty or
 * name-only resource. So ANY composite carrying region on the current side while the prior
 * yields null resets those lifecycles at the upgrade boundary: the repair would have introduced
 * the defect it was written to prevent, on a larger population than the one it fixed.
 *
 * Region enters MTTR identity by COMPOSITION NEGOTIATION instead (see `mttr_engine.mjs`): the
 * composition is chosen by what the PRIOR scan stores, so the two sides are always commensurable
 * by construction rather than by rescuing one of them. Here, region is simply the field — which
 * is all the delta ever needed, because both sides of a delta are loader-shaped runs that carry
 * it.
 *
 * @param {object} v — a finding or a stored violation.
 * @returns {string|null}
 */
export function regionOf(v) {
  return typeof v?.region === 'string' && v.region.length > 0 ? v.region : null;
}

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
    const m = TRAILING_REGION_DECORATION.exec(resource);
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
