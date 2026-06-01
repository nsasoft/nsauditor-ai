// utils/region_intent.mjs
// Pure CE helper: turn the raw --aws-region arg into a RegionIntent, fail-fast
// validating EXPLICIT regions against the canonical list. No SDK. The EE resolver
// expands the intent to concrete regions (DescribeRegions for 'all').
import { isKnownRegion } from './aws_regions.mjs';

export function buildRegionIntent(rawArg) {
  if (rawArg === undefined) return null;        // no flag → env/implicit downstream
  if (rawArg === true) {                         // value-less flag
    throw new Error("--aws-region requires a value (e.g. --aws-region us-east-1 | us-east-1,eu-west-1 | all)");
  }
  const raw = String(rawArg).trim();
  if (raw.toLowerCase() === 'all') return { kind: 'all', explicit: true };
  const regions = raw.split(',').map((s) => s.trim().toLowerCase()).filter(Boolean);
  if (regions.length === 0) {
    throw new Error("--aws-region requires at least one region or 'all'");
  }
  const allowUnknown = process.env.NSA_AWS_REGION_ALLOW_UNKNOWN === '1';
  if (!allowUnknown) {
    for (const r of regions) {
      if (!isKnownRegion(r)) {
        throw new Error(
          `unknown AWS region '${r}'. Valid regions: see the canonical list ` +
          `(set NSA_AWS_REGION_ALLOW_UNKNOWN=1 to bypass for a brand-new region).`,
        );
      }
    }
  }
  return { kind: 'list', regions, explicit: true };
}
