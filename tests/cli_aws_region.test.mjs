import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseArgs } from '../cli.mjs';

test('--aws-region single value parses to a string', async () => {
  const a = await parseArgs(['node', 'cli', 'scan', '--host', 'aws', '--aws-region', 'us-east-1']);
  assert.equal(a.awsRegion, 'us-east-1');
});
test('--aws-region csv parses verbatim (split later)', async () => {
  const a = await parseArgs(['node', 'cli', 'scan', '--host', 'aws', '--aws-region', 'us-east-1,eu-west-1']);
  assert.equal(a.awsRegion, 'us-east-1,eu-west-1');
});
test('--aws-region all parses to "all"', async () => {
  const a = await parseArgs(['node', 'cli', 'scan', '--host', 'aws', '--aws-region', 'all']);
  assert.equal(a.awsRegion, 'all');
});
test('absent --aws-region is undefined', async () => {
  const a = await parseArgs(['node', 'cli', 'scan', '--host', 'aws']);
  assert.equal(a.awsRegion, undefined);
});
test('value-less --aws-region is true (caught as error in main)', async () => {
  const a = await parseArgs(['node', 'cli', 'scan', '--host', 'aws', '--aws-region']);
  assert.equal(a.awsRegion, true);
});
