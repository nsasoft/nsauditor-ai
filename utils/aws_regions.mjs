// utils/aws_regions.mjs
// Canonical AWS region list (pure data — NO SDK). Single source of truth for
// CLI validation + the static fallback when DescribeRegions is denied. Relocated
// from plugins/1040 (EE) so the CE base layer can validate --aws-region without
// the AWS SDK. EE imports this from the CE peer dep.
export const CANONICAL_REGIONS_BY_PARTITION = Object.freeze({
  aws: Object.freeze([
    'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2',
    'ca-central-1', 'ca-west-1',
    'eu-west-1', 'eu-west-2', 'eu-west-3',
    'eu-central-1', 'eu-central-2',
    'eu-north-1', 'eu-south-1', 'eu-south-2',
    'ap-northeast-1', 'ap-northeast-2', 'ap-northeast-3',
    'ap-southeast-1', 'ap-southeast-2', 'ap-southeast-3', 'ap-southeast-4',
    'ap-southeast-5', 'ap-southeast-7',
    'ap-south-1', 'ap-south-2',
    'ap-east-1',
    'sa-east-1',
    'me-south-1', 'me-central-1',
    'af-south-1',
    'il-central-1',
    'mx-central-1',
  ]),
  'aws-cn': Object.freeze(['cn-north-1', 'cn-northwest-1']),
  'aws-us-gov': Object.freeze(['us-gov-east-1', 'us-gov-west-1']),
});

export const CANONICAL_REGION_LIST_VERSION = '2026-05';

export function detectPartition(region) {
  if (typeof region !== 'string' || region.length === 0) return 'aws';
  if (region.startsWith('cn-')) return 'aws-cn';
  if (region.startsWith('us-gov-')) return 'aws-us-gov';
  return 'aws';
}

const _ALL = Object.freeze(
  Object.values(CANONICAL_REGIONS_BY_PARTITION).flat()
);

export function isKnownRegion(region) {
  if (typeof region !== 'string') return false;
  return _ALL.includes(region.trim().toLowerCase());
}

const _EMPTY = Object.freeze([]);

export function regionsForPartition(partition) {
  return CANONICAL_REGIONS_BY_PARTITION[partition] ?? _EMPTY;
}
