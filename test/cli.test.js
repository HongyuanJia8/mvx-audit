import assert from 'node:assert/strict';
import path from 'node:path';
import test from 'node:test';
import { runCli } from '../src/cli.js';
import { captureStreams } from './helpers.js';

const ROOT = path.resolve('corpus/fixtures');

test('CLI audit emits JSON and honors severity threshold', async () => {
  const capture = captureStreams();
  const code = await runCli(['audit', path.join(ROOT, 'cookie-access/mv3'), '--format', 'json', '--fail-on', 'high'], capture.streams);
  const result = JSON.parse(capture.output().stdout);
  assert.equal(code, 1);
  assert.equal(result.target.manifestVersion, 3);
  assert.equal(capture.output().stderr, '');
});

test('CLI returns usage error for an unknown command', async () => {
  const capture = captureStreams();
  const code = await runCli(['unknown'], capture.streams);
  assert.equal(code, 2);
  assert.match(capture.output().stderr, /INVALID_ARGUMENT/);
});

test('CLI validates the complete corpus', async () => {
  const capture = captureStreams();
  const code = await runCli(['corpus', 'validate'], capture.streams);
  assert.equal(code, 0);
  assert.match(capture.output().stdout, /17 scenarios/);
});

test('CLI help documents stable exit codes', async () => {
  const capture = captureStreams();
  const code = await runCli(['--help'], capture.streams);
  assert.equal(code, 0);
  assert.match(capture.output().stdout, /Exit codes:/);
});

