import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseArgs } from '../cli.mjs';

test('parseArgs captures --env and --aws-profile values', async () => {
  const args = await parseArgs(['node', 'cli.mjs', 'scan', '--host', 'aws', '--env', '/envs/prod.env', '--aws-profile', 'prod']);
  assert.equal(args.env, '/envs/prod.env');
  assert.equal(args.awsProfile, 'prod');
});

test('parseArgs marks --env with no value as a flag-without-value (true)', async () => {
  const args = await parseArgs(['node', 'cli.mjs', 'scan', '--host', 'aws', '--env']);
  assert.equal(args.env, true);
});

test('parseArgs leaves env/awsProfile undefined when flags absent', async () => {
  const args = await parseArgs(['node', 'cli.mjs', 'scan', '--host', '10.0.0.1']);
  assert.equal(args.env, undefined);
  assert.equal(args.awsProfile, undefined);
});
