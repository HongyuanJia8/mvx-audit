import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { runCli } from '../src/cli.js';
import { captureStreams } from '../support/helpers.js';

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

test('CLI emits valid SARIF and version output', async () => {
  const versionCapture = captureStreams();
  assert.equal(await runCli(['--version'], versionCapture.streams), 0);
  assert.match(versionCapture.output().stdout, /^2\.0\.0/);

  const sarifCapture = captureStreams();
  assert.equal(await runCli(['audit', path.join(ROOT, 'cookie-access/mv3'), '--format', 'sarif'], sarifCapture.streams), 0);
  assert.equal(JSON.parse(sarifCapture.output().stdout).version, '2.1.0');
});

test('CLI reports malformed catalog as validation failure', async (t) => {
  const temp = await mkdtemp(path.join(os.tmpdir(), 'mvx-cli-catalog-'));
  t.after(() => rm(temp, { recursive: true, force: true }));
  const catalogPath = path.join(temp, 'catalog.json');
  await writeFile(catalogPath, 'null\n', 'utf8');
  const capture = captureStreams();
  const code = await runCli(['corpus', 'validate', '--catalog', catalogPath], capture.streams);
  assert.equal(code, 1);
  assert.match(capture.output().stdout, /catalog must be a JSON object/);
});

test('CLI treats malformed nested catalog values as validation failures, not crashes', async (t) => {
  const temp = await mkdtemp(path.join(os.tmpdir(), 'mvx-cli-nested-catalog-'));
  t.after(() => rm(temp, { recursive: true, force: true }));
  const catalogPath = path.join(temp, 'catalog.json');
  await writeFile(catalogPath, '{"schemaVersion":1,"scenarios":[null]}\n', 'utf8');
  const capture = captureStreams();
  const code = await runCli(['corpus', 'validate', '--catalog', catalogPath], capture.streams);
  assert.equal(code, 1);
  assert.match(capture.output().stdout, /must be a JSON object/);
  assert.equal(capture.output().stderr, '');
});

test('CLI returns input error when a supported source exceeds the hard limit', async (t) => {
  const temp = await mkdtemp(path.join(os.tmpdir(), 'mvx-cli-limit-'));
  t.after(() => rm(temp, { recursive: true, force: true }));
  await writeFile(path.join(temp, 'manifest.json'), '{"manifest_version":3,"name":"Large","version":"1.0.0"}\n', 'utf8');
  await writeFile(path.join(temp, 'large.js'), `eval(payload);\n${'x'.repeat(2_000_000)}`, 'utf8');
  const capture = captureStreams();
  const code = await runCli(['audit', temp], capture.streams);
  assert.equal(code, 2);
  assert.match(capture.output().stderr, /SCAN_LIMIT.*large\.js/);
});

test('CLI reports and validates the real-world intelligence snapshot', async () => {
  const stats = captureStreams();
  assert.equal(await runCli(['intel', 'stats'], stats.streams), 0);
  assert.match(stats.output().stdout, /Unique extension IDs: 4716/);
  const validation = captureStreams();
  assert.equal(await runCli(['intel', 'validate', '--format', 'json'], validation.streams), 0);
  assert.equal(JSON.parse(validation.output().stdout).valid, true);
});

test('CLI looks up threat intelligence by extension ID', async () => {
  const capture = captureStreams();
  const code = await runCli(['intel', 'lookup', 'acmnokigkgihogfbeooklgemindnbine', '--format', 'json'], capture.streams);
  const records = JSON.parse(capture.output().stdout);
  assert.equal(code, 0);
  assert.equal(records[0].extensionId, 'acmnokigkgihogfbeooklgemindnbine');
  assert.ok(records[0].provenance.length > 0);
});

test('CLI refuses CRX extraction without explicit risk acknowledgement', async () => {
  const capture = captureStreams();
  assert.equal(await runCli(['sample', 'unpack', 'missing.crx'], capture.streams), 2);
  assert.match(capture.output().stderr, /RISK_ACK_REQUIRED/);
});
